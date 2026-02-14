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

/*
 * Send data, fragmenting if necessary.
 */
int pool_data_send(struct pool_session *sess, uint8_t channel,
                   const void *data, uint32_t len)
{
    if (!sess->active || sess->state != POOL_STATE_ESTABLISHED)
        return -ENOTCONN;

    if (len <= POOL_DATA_MTU) {
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

    while (offset < len) {
        uint32_t chunk = len - offset;
        uint16_t flags = POOL_FLAG_FRAGMENT | POOL_FLAG_REQUIRE_ACK;
        struct pool_frag_header fhdr;
        uint8_t *pkt_data;
        uint32_t pkt_len;

        if (chunk > POOL_DATA_MTU - sizeof(struct pool_frag_header))
            chunk = POOL_DATA_MTU - sizeof(struct pool_frag_header);

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

    list_del(&entry->list);
    spin_unlock(&sess->rx_lock);

    if (entry->len > *len) {
        /* Truncate */
        memcpy(buf, entry->data, *len);
    } else {
        memcpy(buf, entry->data, entry->len);
        *len = entry->len;
    }

    kfree(entry->data);
    kfree(entry);
    return 0;
}
