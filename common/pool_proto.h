/*
 * pool_proto.h - POOL Protocol Platform-Independent Definitions
 *
 * This header provides all protocol constants, packet formats, and
 * state machine definitions needed to implement POOL on any platform.
 * It depends only on <stdint.h> and <stddef.h>.
 *
 * Platform-specific code (crypto, networking, memory) is abstracted
 * through the pool_platform.h interface.
 */

#ifndef POOL_PROTO_H
#define POOL_PROTO_H

#include <stdint.h>
#include <stddef.h>

/* ---- Protocol Constants ---- */

#define POOL_VERSION            1
#define POOL_KEY_SIZE           32  /* X25519 / ChaCha20 key */
#define POOL_NONCE_SIZE         12  /* ChaCha20-Poly1305 */
#define POOL_TAG_SIZE           16  /* Poly1305 */
#define POOL_HMAC_SIZE          32  /* HMAC-SHA256 */
#define POOL_SESSION_ID_SIZE    16
#define POOL_ADDR_SIZE          32  /* 256-bit POOL address */
#define POOL_HEADER_SIZE        80
#define POOL_MAX_PAYLOAD        65535
#define POOL_DEFAULT_MTU        1400
#define POOL_MIN_MTU            512
#define POOL_HEARTBEAT_SEC      5
#define POOL_REKEY_PACKETS      ((uint32_t)1 << 28)
#define POOL_REKEY_SEC          3600
#define POOL_MAX_SESSIONS       64
#define POOL_MAX_CHANNELS       256
#define POOL_LISTEN_PORT        9253
#define POOL_PUZZLE_DIFFICULTY   8
#define POOL_MAX_FRAGS          256
#define POOL_FRAG_TIMEOUT_MS    5000

/* ---- Packet Types (4 bits) ---- */

#define POOL_PKT_INIT           0x0
#define POOL_PKT_CHALLENGE      0x1
#define POOL_PKT_RESPONSE       0x2
#define POOL_PKT_DATA           0x3
#define POOL_PKT_ACK            0x4
#define POOL_PKT_HEARTBEAT      0x5
#define POOL_PKT_REKEY          0x6
#define POOL_PKT_CLOSE          0x7
#define POOL_PKT_CONFIG         0x8
#define POOL_PKT_ROLLBACK       0x9
#define POOL_PKT_DISCOVER       0xA
#define POOL_PKT_JOURNAL        0xB

/* ---- Flags (16 bits) ---- */

#define POOL_FLAG_ENCRYPTED     (1 << 0)
#define POOL_FLAG_COMPRESSED    (1 << 1)
#define POOL_FLAG_PRIORITY      (1 << 2)
#define POOL_FLAG_FRAGMENT      (1 << 3)
#define POOL_FLAG_LAST_FRAG     (1 << 4)
#define POOL_FLAG_REQUIRE_ACK   (1 << 5)
#define POOL_FLAG_TELEMETRY     (1 << 6)
#define POOL_FLAG_ROLLBACK_RDY  (1 << 7)
#define POOL_FLAG_CONFIG_LOCK   (1 << 8)
#define POOL_FLAG_JOURNAL_SYNC  (1 << 9)

/* ---- Session States ---- */

#define POOL_STATE_IDLE         0
#define POOL_STATE_INIT_SENT    1
#define POOL_STATE_CHALLENGED   2
#define POOL_STATE_ESTABLISHED  3
#define POOL_STATE_REKEYING     4
#define POOL_STATE_CLOSING      5

/* ---- Error Codes ---- */

#define POOL_ERR_NONE           0x00
#define POOL_ERR_AUTH_FAIL      0x01
#define POOL_ERR_SESSION_FULL   0x02
#define POOL_ERR_PROTOCOL       0x03
#define POOL_ERR_TIMEOUT        0x04
#define POOL_ERR_MTU_EXCEEDED   0x05
#define POOL_ERR_VERSION        0x06

/* ---- On-wire Packet Header (80 bytes, packed) ---- */

#pragma pack(push, 1)

struct pool_header {
    uint8_t  ver_type;          /* upper 4 = version, lower 4 = type */
    uint8_t  reserved0;
    uint16_t flags;
    uint64_t seq;
    uint64_t ack;
    uint8_t  session_id[POOL_SESSION_ID_SIZE];
    uint64_t timestamp;
    uint16_t payload_len;
    uint8_t  channel;
    uint8_t  reserved1;
    uint8_t  hmac[POOL_HMAC_SIZE];
};

/* ---- Telemetry (embedded in HEARTBEAT payload) ---- */

struct pool_telemetry {
    uint64_t rtt_ns;
    uint64_t jitter_ns;
    uint32_t loss_rate_ppm;
    uint32_t throughput_bps;
    uint16_t mtu_current;
    uint16_t queue_depth;
    uint64_t uptime_ns;
    uint32_t rekey_count;
    uint32_t config_version;
};

/* ---- Handshake Payloads ---- */

struct pool_init_payload {
    uint8_t  client_pubkey[POOL_KEY_SIZE];
    uint8_t  client_addr[POOL_ADDR_SIZE];
};

struct pool_challenge_payload {
    uint8_t  server_pubkey[POOL_KEY_SIZE];
    uint8_t  puzzle_seed[POOL_KEY_SIZE];
    uint8_t  difficulty;
    uint8_t  reserved[3];
};

struct pool_response_payload {
    uint64_t puzzle_nonce;
    uint8_t  puzzle_hash[POOL_HMAC_SIZE];
};

/* ---- Fragment Header (8 bytes, prefixed to fragmented DATA) ---- */

struct pool_frag_header {
    uint32_t msg_id;
    uint16_t frag_offset;
    uint16_t total_len;
};

/* ---- Discover Payload ---- */

struct pool_discover_payload {
    uint16_t probe_mtu;
};

#pragma pack(pop)

/* ---- Inline Helpers ---- */

static inline uint8_t pool_pkt_version(const struct pool_header *h)
{
    return (h->ver_type >> 4) & 0x0F;
}

static inline uint8_t pool_pkt_type(const struct pool_header *h)
{
    return h->ver_type & 0x0F;
}

static inline uint8_t pool_make_ver_type(uint8_t version, uint8_t type)
{
    return (uint8_t)((version << 4) | (type & 0x0F));
}

#endif /* POOL_PROTO_H */
