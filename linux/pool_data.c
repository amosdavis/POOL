/*
 * pool_data.c - POOL data transfer layer
 *
 * Implements:
 *   - Sending data on channels (with fragmentation if needed)
 *   - Receiving data from RX queue
 *   - Fragment reassembly
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/jiffies.h>

#include "pool_internal.h"

/* Maximum payload per DATA packet (after encryption overhead) */
#define POOL_DATA_MTU  (POOL_DEFAULT_MTU - POOL_HEADER_SIZE - POOL_TAG_SIZE)

/* Dynamic data MTU based on session's discovered path MTU */
static inline uint16_t pool_data_mtu(struct pool_session *sess)
{
    uint16_t mtu = pool_mtu_effective(sess);
    if (mtu < POOL_HEADER_SIZE + POOL_TAG_SIZE + 1)
        return 1;
    return mtu - POOL_HEADER_SIZE - POOL_TAG_SIZE;
}

/*
 * Send data, fragmenting if necessary.
 */
int pool_data_send(struct pool_session *sess, uint8_t channel,
                   const void *data, uint32_t len)
{
    if (!sess->active || sess->state != POOL_STATE_ESTABLISHED)
        return -ENOTCONN;

    if (len <= pool_data_mtu(sess)) {
        /* Single packet */
        int ret = pool_net_send_packet(sess, POOL_PKT_DATA,
                                       POOL_FLAG_REQUIRE_ACK,
                                       channel, data, len);
        if (ret == 0)
            pool_telemetry_record_send(sess, len);
        return ret;
    }

    /* Fragment */
    return pool_data_send_fragmented(sess, channel, data, len);
}

/*
 * Send large data as fragmented packets.
 */
int pool_data_send_fragmented(struct pool_session *sess, uint8_t channel,
                              const void *data, uint32_t len)
{
    uint32_t offset = 0;
    uint32_t msg_id = sess->next_msg_id++;
    int ret;

    if (len > 0xFFFF)
        return -EMSGSIZE;

    while (offset < len) {
        uint32_t chunk = len - offset;
        uint16_t flags = POOL_FLAG_FRAGMENT | POOL_FLAG_REQUIRE_ACK;
        struct pool_frag_header fhdr;
        uint8_t *pkt_data;
        uint32_t pkt_len;

        if (chunk > pool_data_mtu(sess) - sizeof(struct pool_frag_header))
            chunk = pool_data_mtu(sess) - sizeof(struct pool_frag_header);

        if (offset + chunk >= len)
            flags |= POOL_FLAG_LAST_FRAG;

        fhdr.msg_id = cpu_to_be32(msg_id);
        fhdr.frag_offset = cpu_to_be16(offset > 0xFFFF ? 0xFFFF : offset);
        fhdr.total_len = cpu_to_be16(len > 0xFFFF ? 0xFFFF : len);

        pkt_len = sizeof(fhdr) + chunk;
        pkt_data = kmalloc(pkt_len, GFP_KERNEL);
        if (!pkt_data)
            return -ENOMEM;

        memcpy(pkt_data, &fhdr, sizeof(fhdr));
        memcpy(pkt_data + sizeof(fhdr), (const char *)data + offset, chunk);

        ret = pool_net_send_packet(sess, POOL_PKT_DATA, flags,
                                   channel, pkt_data, pkt_len);
        kfree(pkt_data);
        if (ret)
            return ret;

        pool_telemetry_record_send(sess, chunk);
        offset += chunk;
    }

    return 0;
}

/*
 * Handle an incoming fragment and attempt reassembly.
 *
 * Returns:
 *   1   if reassembly is complete (assembled data is in *out_data / *out_len)
 *   0   if this fragment was accepted but more are needed
 *  <0   on error (errno)
 */
int pool_data_handle_fragment(struct pool_session *sess,
                              const uint8_t *payload, uint32_t plen,
                              uint16_t flags, uint8_t channel,
                              uint8_t **out_data, uint32_t *out_len,
                              uint8_t *out_channel)
{
    struct pool_frag_header fhdr;
    uint32_t msg_id, frag_offset, total_len, data_len;
    const uint8_t *frag_data;
    struct pool_frag_buf *fb = NULL;
    int i, free_slot = -1;

    if (plen < sizeof(struct pool_frag_header))
        return -EINVAL;

    memcpy(&fhdr, payload, sizeof(fhdr));
    msg_id     = be32_to_cpu(fhdr.msg_id);
    frag_offset = be16_to_cpu(fhdr.frag_offset);
    total_len  = be16_to_cpu(fhdr.total_len);
    frag_data  = payload + sizeof(struct pool_frag_header);
    data_len   = plen - sizeof(struct pool_frag_header);

    if (total_len == 0 || frag_offset + data_len > total_len)
        return -EINVAL;

    /* Find existing reassembly buffer for this msg_id, or a free slot */
    for (i = 0; i < ARRAY_SIZE(sess->frags); i++) {
        if (sess->frags[i].data && sess->frags[i].msg_id == msg_id) {
            fb = &sess->frags[i];
            break;
        }
        if (!sess->frags[i].data && free_slot < 0)
            free_slot = i;
    }

    if (!fb) {
        /* Allocate a new reassembly buffer */
        if (free_slot < 0) {
            /* S04: LRU eviction — evict oldest incomplete fragment */
            unsigned long oldest_time = jiffies;
            int oldest_slot = -1;
            for (i = 0; i < ARRAY_SIZE(sess->frags); i++) {
                if (sess->frags[i].data &&
                    time_before(sess->frags[i].start_jiffies, oldest_time)) {
                    oldest_time = sess->frags[i].start_jiffies;
                    oldest_slot = i;
                }
            }
            if (oldest_slot >= 0) {
                pr_warn("POOL: evicting stale fragment msg_id=%u for new msg_id=%u\n",
                        sess->frags[oldest_slot].msg_id, msg_id);
                kfree(sess->frags[oldest_slot].data);
                memset(&sess->frags[oldest_slot], 0,
                       sizeof(sess->frags[oldest_slot]));
                free_slot = oldest_slot;
            } else {
                pr_warn("POOL: no free fragment reassembly slot for msg_id=%u\n",
                        msg_id);
                return -ENOSPC;
            }
        }
        fb = &sess->frags[free_slot];
        fb->data = kzalloc(total_len, GFP_KERNEL);
        if (!fb->data)
            return -ENOMEM;
        fb->msg_id = msg_id;
        fb->total_len = total_len;
        fb->received = 0;
        fb->complete = 0;
        fb->start_jiffies = jiffies;
    }

    /* Validate consistency: total_len must match across fragments */
    if (fb->total_len != total_len) {
        pr_warn("POOL: fragment total_len mismatch msg_id=%u (%u vs %u)\n",
                msg_id, fb->total_len, total_len);
        return -EINVAL;
    }

    /* S03: Validate fragment bounds against allocated buffer size */
    if (frag_offset + data_len > fb->total_len) {
        pr_warn("POOL: fragment overflow msg_id=%u offset=%u len=%u total=%u\n",
                msg_id, frag_offset, data_len, fb->total_len);
        return -EINVAL;
    }

    /* Copy fragment data into reassembly buffer at the correct offset */
    memcpy(fb->data + frag_offset, frag_data, data_len);
    fb->received += data_len;

    /* Check if this is the last fragment and we have all bytes */
    if ((flags & POOL_FLAG_LAST_FRAG) && fb->received >= fb->total_len) {
        fb->complete = 1;

        /* Return the assembled message to the caller */
        *out_data = fb->data;
        *out_len = fb->total_len;
        *out_channel = channel;

        /* Clear the slot without freeing data (caller owns it now) */
        fb->data = NULL;
        memset(fb, 0, sizeof(*fb));
        return 1;
    }

    return 0;
}

/*
 * Receive data from session RX queue.
 * Blocks up to timeout_ms milliseconds.
 */
int pool_data_recv(struct pool_session *sess, uint8_t channel,
                   void *buf, uint32_t *len, int timeout_ms)
{
    struct pool_rx_entry *entry;
    unsigned long timeout;
    int ret;

    if (!sess->active)
        return -ENOTCONN;

    timeout = msecs_to_jiffies(timeout_ms);

    ret = wait_event_interruptible_timeout(
        sess->rx_wait,
        !list_empty(&sess->rx_queue) || !sess->active ||
            sess->state == POOL_STATE_CLOSING,
        timeout);

    if (!sess->active || sess->state == POOL_STATE_CLOSING)
        return -ECONNRESET;
    if (ret == 0)
        return -ETIMEDOUT;
    if (ret < 0)
        return ret;

    spin_lock(&sess->rx_lock);
    if (list_empty(&sess->rx_queue)) {
        spin_unlock(&sess->rx_lock);
        return -EAGAIN;
    }

    /* Find first entry matching channel (0 = any) */
    entry = NULL;
    {
        struct pool_rx_entry *e;
        list_for_each_entry(e, &sess->rx_queue, list) {
            if (channel == 0 || e->channel == channel) {
                entry = e;
                break;
            }
        }
    }

    if (!entry) {
        spin_unlock(&sess->rx_lock);
        return -EAGAIN;
    }

    if (entry->len > *len) {
        /* Buffer too small — report required size, leave entry in queue */
        *len = entry->len;
        spin_unlock(&sess->rx_lock);
        return -EMSGSIZE;
    }

    list_del(&entry->list);
    spin_unlock(&sess->rx_lock);

    memcpy(buf, entry->data, entry->len);
    *len = entry->len;

    kfree(entry->data);
    kfree(entry);
    return 0;
}
