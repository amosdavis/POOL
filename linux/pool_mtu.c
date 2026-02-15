/*
 * pool_mtu.c - POOL Path MTU Discovery
 *
 * Implements DISCOVER packet (type 0xA) for active MTU probing
 * using binary search as specified in PROTOCOL.md §6.
 *
 * Probing algorithm:
 *   1. On session establishment, MTU starts at POOL_DEFAULT_MTU
 *   2. Binary search between POOL_MIN_MTU and POOL_DEFAULT_MTU
 *   3. Send DISCOVER packet padded to probe size
 *   4. If ACK received → increase lower bound
 *   5. If timeout (2s) → decrease upper bound, use lower bound as MTU
 *   6. Re-probe every 60 seconds or on loss detection
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "pool_internal.h"

#define POOL_MTU_PROBE_TIMEOUT_NS  (2ULL * 1000000000ULL)  /* 2 seconds */
#define POOL_MTU_REPROBE_NS       (60ULL * 1000000000ULL)  /* 60 seconds */
#define POOL_MTU_CONVERGE_MARGIN   16  /* stop probing when range < 16 bytes */

/* DISCOVER payload: just the probe size as a 16-bit BE value, padded */
struct pool_discover_payload {
    uint16_t probe_mtu;  /* network byte order */
    uint8_t  padding[];  /* padded to probe_mtu - header - tag */
} __attribute__((packed));

void pool_mtu_init_session(struct pool_session *sess)
{
    sess->mtu = POOL_DEFAULT_MTU;
    sess->mtu_probe_lo = POOL_MIN_MTU;
    sess->mtu_probe_hi = POOL_DEFAULT_MTU;
    sess->mtu_probing = 0;
    sess->mtu_last_probe = 0;
    sess->mtu_probe_size = 0;
    sess->telemetry.mtu_current = POOL_DEFAULT_MTU;
}

void pool_mtu_send_probe(struct pool_session *sess)
{
    uint16_t probe_size;
    uint8_t *probe_data;
    uint16_t payload_len;

    if (sess->mtu_probing)
        return;

    /* S06: Handle lo==hi edge case to prevent infinite loop */
    if (sess->mtu_probe_hi <= sess->mtu_probe_lo)
        return;  /* MTU discovery complete — range collapsed */

    if (sess->mtu_probe_hi - sess->mtu_probe_lo < POOL_MTU_CONVERGE_MARGIN)
        return;  /* converged */

    /* Binary search midpoint */
    probe_size = (sess->mtu_probe_lo + sess->mtu_probe_hi) / 2;

    /* Payload size = probe_size minus fixed overhead */
    if (probe_size <= POOL_HEADER_SIZE + POOL_TAG_SIZE + sizeof(uint16_t))
        return;  /* probe too small */

    payload_len = probe_size - POOL_HEADER_SIZE - POOL_TAG_SIZE;

    probe_data = kzalloc(payload_len, GFP_KERNEL);
    if (!probe_data)
        return;

    /* Embed the probe MTU value at the start */
    *(uint16_t *)probe_data = cpu_to_be16(probe_size);

    sess->mtu_probing = 1;
    sess->mtu_probe_size = probe_size;
    sess->mtu_last_probe = ktime_get_ns();

    pool_net_send_packet(sess, POOL_PKT_DISCOVER, 0, 0,
                         probe_data, payload_len);

    kfree(probe_data);
}

void pool_mtu_handle_discover(struct pool_session *sess,
                              const uint8_t *payload, uint32_t plen,
                              uint16_t flags)
{
    uint16_t probe_mtu;

    if (plen < sizeof(uint16_t))
        return;

    probe_mtu = be16_to_cpu(*(const uint16_t *)payload);

    if (flags & POOL_FLAG_REQUIRE_ACK) {
        /* This is a probe request — echo it back as an ACK */
        pool_net_send_packet(sess, POOL_PKT_DISCOVER,
                             0, 0, payload, plen);
        return;
    }

    /* This is a probe response (ACK) — probe succeeded at this size */
    if (sess->mtu_probing && probe_mtu == sess->mtu_probe_size) {
        sess->mtu_probe_lo = probe_mtu;
        sess->mtu = probe_mtu;
        sess->telemetry.mtu_current = probe_mtu;
        sess->mtu_probing = 0;

        /* Continue binary search upward */
        pool_mtu_send_probe(sess);
    }
}

void pool_mtu_probe_timeout(struct pool_session *sess)
{
    uint64_t now;

    if (!sess->mtu_probing)
        return;

    now = ktime_get_ns();
    if (now - sess->mtu_last_probe < POOL_MTU_PROBE_TIMEOUT_NS)
        return;

    /* Probe timed out — the probe size is too large */
    sess->mtu_probe_hi = sess->mtu_probe_size;
    sess->mtu_probing = 0;

    /* Use conservative (lower) MTU */
    sess->mtu = sess->mtu_probe_lo;
    sess->telemetry.mtu_current = sess->mtu_probe_lo;

    pr_info("POOL: MTU probe timeout at %u, using %u\n",
            sess->mtu_probe_size, sess->mtu);

    /* Continue binary search downward */
    pool_mtu_send_probe(sess);
}

uint16_t pool_mtu_effective(struct pool_session *sess)
{
    return sess->mtu;
}
