/*
 * pool_telemetry.c - POOL built-in telemetry and heartbeat
 *
 * Implements:
 *   - Per-session RTT, jitter, loss, throughput tracking
 *   - Periodic HEARTBEAT packets with embedded telemetry
 */

#include <linux/kthread.h>
#include <linux/delay.h>

#include "pool_internal.h"

/* ---- Telemetry update helpers ---- */

void pool_telemetry_update_rtt(struct pool_session *sess, uint64_t rtt_ns)
{
    uint64_t prev_rtt = sess->telemetry.rtt_ns;

    /* EWMA: rtt = 7/8 * old + 1/8 * new */
    if (prev_rtt == 0)
        sess->telemetry.rtt_ns = rtt_ns;
    else
        sess->telemetry.rtt_ns = (prev_rtt * 7 + rtt_ns) / 8;

    /* Jitter = |rtt - avg_rtt| EWMA */
    {
        uint64_t diff = (rtt_ns > sess->telemetry.rtt_ns) ?
                         rtt_ns - sess->telemetry.rtt_ns :
                         sess->telemetry.rtt_ns - rtt_ns;
        if (sess->telemetry.jitter_ns == 0)
            sess->telemetry.jitter_ns = diff;
        else
            sess->telemetry.jitter_ns =
                (sess->telemetry.jitter_ns * 7 + diff) / 8;
    }
}

void pool_telemetry_record_send(struct pool_session *sess, uint32_t bytes)
{
    /* Simple throughput estimate: bytes/sec over last interval */
    sess->bytes_sent += bytes;
    if (sess->connect_time) {
        uint64_t elapsed_ns = ktime_get_ns() - sess->connect_time;
        if (elapsed_ns > 0) {
            /* bytes_sent * 8 * 1e9 / elapsed_ns = bps */
            uint64_t bps = (sess->bytes_sent * 8ULL * 1000000000ULL) /
                           elapsed_ns;
            sess->telemetry.throughput_bps = (uint32_t)(bps > 0xFFFFFFFF ?
                                             0xFFFFFFFF : bps);
        }
    }
}

void pool_telemetry_record_recv(struct pool_session *sess, uint32_t bytes)
{
    /* Just track the receive side */
    (void)bytes; /* Already counted in pool_net_recv_packet */
}

/* ---- Heartbeat thread ---- */

static int pool_heartbeat_fn(void *data)
{
    while (!kthread_should_stop()) {
        int i;
        for (i = 0; i < POOL_MAX_SESSIONS; i++) {
            struct pool_session *s = &pool.sessions[i];
            if (!s->active || s->state != POOL_STATE_ESTABLISHED)
                continue;

            /* Send heartbeat with our telemetry */
            s->telemetry.uptime_ns = ktime_get_ns() - s->connect_time;
            pool_net_send_packet(s, POOL_PKT_HEARTBEAT,
                                 POOL_FLAG_TELEMETRY, 0,
                                 &s->telemetry,
                                 sizeof(struct pool_telemetry));

            /* Check if rekey is needed */
            if (s->crypto.packets_since_rekey >= POOL_REKEY_PACKETS ||
                time_after(jiffies, s->crypto.last_rekey_jiffies +
                           POOL_REKEY_SEC * HZ)) {
                pool_session_rekey(s);
            }
        }
        msleep(POOL_HEARTBEAT_SEC * 1000);
    }
    return 0;
}

int pool_telemetry_init(void)
{
    pool.heartbeat_thread = kthread_run(pool_heartbeat_fn, NULL,
                                        "pool_heartbeat");
    if (IS_ERR(pool.heartbeat_thread)) {
        int ret = PTR_ERR(pool.heartbeat_thread);
        pool.heartbeat_thread = NULL;
        return ret;
    }
    return 0;
}

void pool_telemetry_cleanup(void)
{
    if (pool.heartbeat_thread) {
        kthread_stop(pool.heartbeat_thread);
        pool.heartbeat_thread = NULL;
    }
}
