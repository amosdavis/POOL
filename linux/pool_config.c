/*
 * pool_config.c - POOL Atomic Configuration & Rollback
 *
 * Implements CONFIG (0x8) and ROLLBACK (0x9) packet handlers as specified
 * in PROTOCOL.md §8. Provides versioned configuration with automatic
 * rollback on deadline expiry.
 *
 * Config state is per-session and includes:
 *   - Puzzle difficulty
 *   - Heartbeat interval
 *   - Rekey interval/threshold
 *   - MTU constraints
 *
 * Changes are tentatively applied and auto-rolled-back if not confirmed.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <crypto/hash.h>

#include "pool_internal.h"

/* Configuration parameters that can be changed at runtime */
struct pool_runtime_config {
    uint32_t version;
    uint32_t prev_version;
    uint8_t  config_hash[POOL_HMAC_SIZE];
    uint8_t  prev_hash[POOL_HMAC_SIZE];
    uint64_t timestamp;
    uint64_t rollback_deadline_ns;
    uint8_t  puzzle_difficulty;
    uint16_t heartbeat_sec;
    uint32_t rekey_packets;
    uint32_t rekey_sec;
    uint16_t mtu_min;
    uint16_t mtu_max;
};

/* On-wire CONFIG payload */
struct pool_config_payload {
    uint32_t version;
    uint32_t prev_version;
    uint8_t  config_hash[POOL_HMAC_SIZE];
    uint8_t  prev_hash[POOL_HMAC_SIZE];
    uint64_t timestamp;
    uint64_t rollback_deadline_ns;
    uint8_t  puzzle_difficulty;
    uint8_t  reserved;
    uint16_t heartbeat_sec;
    uint32_t rekey_packets;
    uint32_t rekey_sec;
    uint16_t mtu_min;
    uint16_t mtu_max;
} __attribute__((packed));

/*
 * S05: Global config is shared across all sessions. Protect with a
 * mutex to prevent concurrent modification races.
 */
static struct pool_runtime_config current_config;
static struct pool_runtime_config prev_config;
static int config_tentative;  /* 1 if a tentative config is active */
static DEFINE_MUTEX(config_lock);

void pool_config_init(void)
{
    memset(&current_config, 0, sizeof(current_config));
    current_config.version = 1;
    current_config.puzzle_difficulty = POOL_PUZZLE_DIFFICULTY;
    current_config.heartbeat_sec = POOL_HEARTBEAT_SEC;
    current_config.rekey_packets = POOL_REKEY_PACKETS;
    current_config.rekey_sec = POOL_REKEY_SEC;
    current_config.mtu_min = POOL_MIN_MTU;
    current_config.mtu_max = POOL_DEFAULT_MTU;
    current_config.timestamp = ktime_get_ns();
    config_tentative = 0;
}

static void config_to_payload(const struct pool_runtime_config *cfg,
                              struct pool_config_payload *pl)
{
    pl->version = cpu_to_be32(cfg->version);
    pl->prev_version = cpu_to_be32(cfg->prev_version);
    memcpy(pl->config_hash, cfg->config_hash, POOL_HMAC_SIZE);
    memcpy(pl->prev_hash, cfg->prev_hash, POOL_HMAC_SIZE);
    pl->timestamp = cpu_to_be64(cfg->timestamp);
    pl->rollback_deadline_ns = cpu_to_be64(cfg->rollback_deadline_ns);
    pl->puzzle_difficulty = cfg->puzzle_difficulty;
    pl->reserved = 0;
    pl->heartbeat_sec = cpu_to_be16(cfg->heartbeat_sec);
    pl->rekey_packets = cpu_to_be32(cfg->rekey_packets);
    pl->rekey_sec = cpu_to_be32(cfg->rekey_sec);
    pl->mtu_min = cpu_to_be16(cfg->mtu_min);
    pl->mtu_max = cpu_to_be16(cfg->mtu_max);
}

static void payload_to_config(const struct pool_config_payload *pl,
                              struct pool_runtime_config *cfg)
{
    cfg->version = be32_to_cpu(pl->version);
    cfg->prev_version = be32_to_cpu(pl->prev_version);
    memcpy(cfg->config_hash, pl->config_hash, POOL_HMAC_SIZE);
    memcpy(cfg->prev_hash, pl->prev_hash, POOL_HMAC_SIZE);
    cfg->timestamp = be64_to_cpu(pl->timestamp);
    cfg->rollback_deadline_ns = be64_to_cpu(pl->rollback_deadline_ns);
    cfg->puzzle_difficulty = pl->puzzle_difficulty;
    cfg->heartbeat_sec = be16_to_cpu(pl->heartbeat_sec);
    cfg->rekey_packets = be32_to_cpu(pl->rekey_packets);
    cfg->rekey_sec = be32_to_cpu(pl->rekey_sec);
    cfg->mtu_min = be16_to_cpu(pl->mtu_min);
    cfg->mtu_max = be16_to_cpu(pl->mtu_max);
}

void pool_config_handle_config(struct pool_session *sess,
                               const uint8_t *payload, uint32_t plen)
{
    struct pool_config_payload pl;
    struct pool_runtime_config proposed;

    if (plen < sizeof(pl)) {
        pr_warn("POOL: CONFIG packet too short (%u < %zu)\n",
                plen, sizeof(pl));
        return;
    }

    memcpy(&pl, payload, sizeof(pl));
    payload_to_config(&pl, &proposed);

    mutex_lock(&config_lock);

    /* Validate: version must be strictly increasing */
    if (proposed.version <= current_config.version) {
        pr_warn("POOL: CONFIG rejected: version %u <= current %u\n",
                proposed.version, current_config.version);
        mutex_unlock(&config_lock);
        return;
    }

    /* Validate: prev_version must match current */
    if (proposed.prev_version != current_config.version) {
        pr_warn("POOL: CONFIG rejected: prev_version %u != current %u\n",
                proposed.prev_version, current_config.version);
        mutex_unlock(&config_lock);
        return;
    }

    /* Save current as previous */
    memcpy(&prev_config, &current_config, sizeof(prev_config));

    /* Apply tentatively */
    memcpy(&current_config, &proposed, sizeof(current_config));
    config_tentative = 1;

    mutex_unlock(&config_lock);

    /* Update the session's telemetry config version */
    sess->telemetry.config_version = proposed.version;

    pr_info("POOL: config v%u applied tentatively (deadline in %llu ns)\n",
            proposed.version, proposed.rollback_deadline_ns);

    /* Record in journal */
    pool_journal_add(POOL_JOURNAL_CONFIG,
                     prev_config.version, proposed.version,
                     "config-apply", 12);

    /* Send ACK to confirm receipt */
    pool_net_send_packet(sess, POOL_PKT_ACK, POOL_FLAG_CONFIG_LOCK,
                         0, NULL, 0);
}

void pool_config_handle_rollback(struct pool_session *sess,
                                 const uint8_t *payload, uint32_t plen)
{
    mutex_lock(&config_lock);

    if (!config_tentative) {
        pr_warn("POOL: ROLLBACK received but no tentative config active\n");
        mutex_unlock(&config_lock);
        return;
    }

    pr_info("POOL: rolling back config v%u → v%u\n",
            current_config.version, prev_config.version);

    /* Restore previous configuration */
    memcpy(&current_config, &prev_config, sizeof(current_config));
    config_tentative = 0;

    mutex_unlock(&config_lock);

    sess->telemetry.config_version = current_config.version;

    pool_journal_add(POOL_JOURNAL_CONFIG,
                     current_config.version + 1, current_config.version,
                     "rollback", 8);

    /* ACK the rollback */
    pool_net_send_packet(sess, POOL_PKT_ACK, POOL_FLAG_ROLLBACK_RDY,
                         0, NULL, 0);
}

void pool_config_check_deadline(struct pool_session *sess)
{
    uint64_t now;

    mutex_lock(&config_lock);
    if (!config_tentative) {
        mutex_unlock(&config_lock);
        return;
    }

    now = ktime_get_ns();
    if (current_config.rollback_deadline_ns > 0 &&
        now >= current_config.rollback_deadline_ns) {
        pr_warn("POOL: config v%u deadline expired, auto-rollback\n",
                current_config.version);
        mutex_unlock(&config_lock);
        pool_config_handle_rollback(sess, NULL, 0);
        return;
    }
    mutex_unlock(&config_lock);
}

void pool_config_confirm(struct pool_session *sess)
{
    mutex_lock(&config_lock);
    if (!config_tentative) {
        pr_debug("POOL: config confirm but no tentative config\n");
        mutex_unlock(&config_lock);
        return;
    }

    config_tentative = 0;
    current_config.rollback_deadline_ns = 0;
    mutex_unlock(&config_lock);

    pr_info("POOL: config v%u confirmed\n", current_config.version);
    pool_journal_add(POOL_JOURNAL_CONFIG,
                     current_config.version, current_config.version,
                     "config-confirm", 14);
}

uint32_t pool_config_version(void)
{
    return current_config.version;
}
