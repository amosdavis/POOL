/*
 * pool_telemetry.c - POOL built-in telemetry and heartbeat
 *
 * Implements:
 *   - Per-session RTT, jitter, loss, throughput tracking
 *   - Periodic HEARTBEAT packets with embedded telemetry
 */

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/crc32.h>
#include <linux/module.h>
#include <linux/version.h>

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
    /* Update loss rate (parts per million).
     * Total expected = packets_recv + packets_lost.
     * Loss = packets_lost / (packets_recv + packets_lost) * 1,000,000 */
    uint64_t total = sess->packets_recv + sess->packets_lost;

    if (total > 0) {
        sess->telemetry.loss_rate_ppm =
            (uint32_t)((sess->packets_lost * 1000000ULL) / total);
    }
}

/* ---- Heartbeat thread ---- */

static int pool_heartbeat_fn(void *data)
{
    /*
     * M05: Wait for subsystems to be ready. The heartbeat thread may
     * start before session_init completes. Check that session array
     * is initialized by waiting for sessions_lock to be valid.
     */
    while (!kthread_should_stop() && !pool.sessions_ready)
        msleep(100);

    while (!kthread_should_stop()) {
        int i;

        /* T1/T2: Periodic runtime integrity checks (every 12 beats ≈ 60s) */
        pool.heartbeat_count++;
        if (pool.heartbeat_count % 12 == 0 && !pool.integrity_compromised) {
            int rc = pool_crypto_runtime_selftest();
            if (rc) {
                pool.integrity_compromised = 1;
                pr_crit("POOL: runtime self-test failed, module integrity compromised\n");
            }
            rc = pool_crypto_spot_check();
            if (rc) {
                pool.integrity_compromised = 1;
                pr_crit("POOL: crypto spot-check failed, module integrity compromised\n");
            }
            /* T1: Re-verify module .text section CRC32 (RT-C01) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
            if (pool.text_crc32 != 0) {
                struct module *mod = THIS_MODULE;
                uint32_t current_crc = crc32(0, mod->core_layout.base,
                                             mod->core_layout.text_size);
                if (current_crc != pool.text_crc32) {
                    pool.integrity_compromised = 1;
                    pr_crit("POOL: .text CRC32 mismatch (expected=0x%08x, "
                            "current=0x%08x) — module code modified!\n",
                            pool.text_crc32, current_crc);
                }
            }
#endif
            pool.last_integrity_check = ktime_get_ns();
        }

        for (i = 0; i < POOL_MAX_SESSIONS; i++) {
            struct pool_session *s = &pool.sessions[i];
            if (!s->active || s->state != POOL_STATE_ESTABLISHED)
                continue;

            /* Send heartbeat with our telemetry */
            s->telemetry.uptime_ns = ktime_get_ns() - s->connect_time;

            /* T4: Compute state digest for cross-peer verification (RT-S01, RT-S03) */
            {
                uint32_t crc = crc32(0, (const uint8_t *)&s->crypto.local_seq,
                                     sizeof(s->crypto.local_seq));
                crc = crc32(crc, (const uint8_t *)&s->crypto.remote_seq,
                            sizeof(s->crypto.remote_seq));
                crc = crc32(crc, (const uint8_t *)&s->crypto.packets_since_rekey,
                            sizeof(s->crypto.packets_since_rekey));
                crc = crc32(crc, (const uint8_t *)&s->state,
                            sizeof(s->state));
                s->telemetry.state_digest = crc;
            }

            /* T2/T4: Send periodic integrity challenge to peer (every 12 beats) */
            if (pool.heartbeat_count % 12 == 0 &&
                !s->integrity_challenge_pending) {
                get_random_bytes(s->integrity_challenge, 16);
                s->integrity_challenge_pending = 1;
                s->last_integrity_challenge = ktime_get_ns();
                pool_net_send_packet(s, POOL_PKT_INTEGRITY, 0, 0,
                                     s->integrity_challenge, 16);
            }

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
