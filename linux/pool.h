/*
 * pool.h - POOL Protocol public API header
 *
 * Protected Orchestrated Overlay Link (POOL) v1.0.0
 * Shared between kernel module and userspace tools.
 */
#ifndef _POOL_H
#define _POOL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

/* ---- Protocol Constants ---- */

#define POOL_VERSION            1
#define POOL_VERSION_PQC        2   /* hybrid X25519 + ML-KEM-768 */
#define POOL_HEADER_SIZE        80
#define POOL_HMAC_SIZE          32  /* SHA-256 */
#define POOL_SESSION_ID_SIZE    16  /* 128-bit */
#define POOL_KEY_SIZE           32  /* X25519 / ChaCha20 */
#define POOL_NONCE_SIZE         12  /* ChaCha20-Poly1305 */
#define POOL_TAG_SIZE           16  /* Poly1305 */
#define POOL_ADDR_SIZE          32  /* 256-bit address */
#define POOL_MAX_PAYLOAD        65535
#define POOL_LISTEN_BACKLOG     128
#define POOL_DEFAULT_MTU        1400
#define POOL_MIN_MTU            512

/* IPv4-mapped IPv6 address helpers: ::ffff:x.x.x.x */
static inline void pool_ipv4_to_mapped(uint32_t ip4, uint8_t addr[16])
{
    __builtin_memset(addr, 0, 10);
    addr[10] = 0xFF;
    addr[11] = 0xFF;
    addr[12] = (ip4 >> 24) & 0xFF;
    addr[13] = (ip4 >> 16) & 0xFF;
    addr[14] = (ip4 >> 8) & 0xFF;
    addr[15] = ip4 & 0xFF;
}

static inline uint32_t pool_mapped_to_ipv4(const uint8_t addr[16])
{
    return ((uint32_t)addr[12] << 24) | ((uint32_t)addr[13] << 16) |
           ((uint32_t)addr[14] << 8) | (uint32_t)addr[15];
}

static inline int pool_addr_is_v4mapped(const uint8_t addr[16])
{
    static const uint8_t prefix[12] = {0,0,0,0, 0,0,0,0, 0,0,0xFF,0xFF};
    return __builtin_memcmp(addr, prefix, 12) == 0;
}
#define POOL_HEARTBEAT_SEC      5
#define POOL_REKEY_PACKETS      ((uint32_t)1 << 28)  /* rekey every 256M pkts */
#define POOL_REKEY_SEC          3600  /* or every hour */
#define POOL_MAX_SESSIONS       64
#define POOL_MAX_CHANNELS       256
#define POOL_LISTEN_PORT        9253  /* default port (253 = experimental IP proto) */
#define POOL_PUZZLE_DIFFICULTY   8  /* bits of leading zeros (low for QEMU) */
#define POOL_MAX_FRAGS          256
#define POOL_FRAG_TIMEOUT_MS    5000
#define POOL_IP_PROTO           253  /* IANA experimental protocol number */

/* Transport modes */
#define POOL_TRANSPORT_TCP      0    /* TCP overlay (default, works everywhere) */
#define POOL_TRANSPORT_RAW      1    /* Raw IP protocol 253 */
#define POOL_TRANSPORT_AUTO     2    /* Try raw first, fall back to TCP */

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

/* ---- On-wire packet header (80 bytes) ---- */

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
} __attribute__((packed));

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
} __attribute__((packed));

/* ---- Handshake payloads ---- */

struct pool_init_payload {
    uint8_t  client_pubkey[POOL_KEY_SIZE];
    uint8_t  client_addr[POOL_ADDR_SIZE];
} __attribute__((packed));

struct pool_challenge_payload {
    uint8_t  server_pubkey[POOL_KEY_SIZE];
    uint8_t  puzzle_seed[32];
    uint16_t puzzle_difficulty;
    uint8_t  server_addr[POOL_ADDR_SIZE];
} __attribute__((packed));

struct pool_response_payload {
    uint8_t  puzzle_solution[32];
    uint8_t  proof[POOL_HMAC_SIZE];   /* HMAC(shared_secret, session_id) */
} __attribute__((packed));

/* ---- POOL 256-bit address ---- */

struct pool_address {
    uint32_t type_version;      /* address type + version */
    uint64_t org_id;            /* organization/network ID */
    uint64_t segment_id;        /* subnet/segment ID */
    uint64_t node_id;           /* derived from public key hash */
    uint32_t checksum;          /* CRC32 */
} __attribute__((packed));

/* ---- Journal entry ---- */

struct pool_journal_entry {
    uint64_t timestamp;
    uint32_t config_ver_before;
    uint32_t config_ver_after;
    uint8_t  change_hash[32];
    uint16_t change_type;
    uint16_t detail_length;
    /* detail[] follows */
} __attribute__((packed));

/* Journal change types */
#define POOL_JOURNAL_CONNECT     1
#define POOL_JOURNAL_DISCONNECT  2
#define POOL_JOURNAL_CONFIG      3
#define POOL_JOURNAL_REKEY       4
#define POOL_JOURNAL_ERROR       5
#define POOL_JOURNAL_DATA        6

/* Error codes */
#define POOL_ERR_AUTH_FAIL       0x01
#define POOL_ERR_DECRYPT_FAIL    0x02
#define POOL_ERR_SEQ_INVALID     0x03
#define POOL_ERR_FRAG_TIMEOUT    0x04
#define POOL_ERR_MTU_EXCEEDED    0x05
#define POOL_ERR_CONFIG_REJECT   0x06
#define POOL_ERR_REKEY_FAIL      0x07
#define POOL_ERR_JOURNAL_FULL    0x08
#define POOL_ERR_OVERLOAD        0x09
#define POOL_ERR_VERSION_MISMATCH 0x0A

/* ---- Ioctl interface ---- */

#define POOL_IOC_MAGIC 'P'

/* Connect to a remote POOL node */
struct pool_connect_req {
    uint8_t  peer_addr[16]; /* IPv4: stored as ::ffff:x.x.x.x (IPv4-mapped) */
    uint16_t peer_port;
    uint8_t  addr_family;   /* AF_INET or AF_INET6 */
    uint8_t  reserved[5];
};

/* Send data on a session */
struct pool_send_req {
    uint32_t session_idx;
    uint8_t  channel;
    uint8_t  flags;
    uint16_t reserved;
    uint32_t len;
    uint64_t data_ptr;  /* userspace pointer */
};

/* Receive data from a session */
struct pool_recv_req {
    uint32_t session_idx;
    uint8_t  channel;
    uint8_t  flags;
    uint16_t reserved;
    uint32_t len;       /* in: buffer size, out: bytes received */
    uint64_t data_ptr;  /* userspace pointer */
};

/* Query session info */
struct pool_session_info {
    uint32_t index;
    uint8_t  peer_addr[16]; /* IPv4: stored as ::ffff:x.x.x.x (IPv4-mapped) */
    uint16_t peer_port;
    uint8_t  addr_family;   /* AF_INET or AF_INET6 */
    uint8_t  state;
    uint8_t  session_id[POOL_SESSION_ID_SIZE];
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint32_t rekey_count;
    struct pool_telemetry telemetry;
};

/* List sessions */
struct pool_session_list {
    uint32_t count;        /* out: number of active sessions */
    uint32_t max_sessions; /* in: size of info array */
    uint64_t info_ptr;     /* userspace pointer to pool_session_info[] */
};

/* Session states */
#define POOL_STATE_IDLE         0
#define POOL_STATE_INIT_SENT    1
#define POOL_STATE_CHALLENGED   2
#define POOL_STATE_ESTABLISHED  3
#define POOL_STATE_REKEYING     4
#define POOL_STATE_CLOSING      5

#define POOL_IOC_LISTEN       _IOW(POOL_IOC_MAGIC, 1, uint16_t)
#define POOL_IOC_CONNECT      _IOW(POOL_IOC_MAGIC, 2, struct pool_connect_req)
#define POOL_IOC_SEND         _IOW(POOL_IOC_MAGIC, 3, struct pool_send_req)
#define POOL_IOC_RECV         _IOWR(POOL_IOC_MAGIC, 4, struct pool_recv_req)
#define POOL_IOC_SESSIONS     _IOWR(POOL_IOC_MAGIC, 5, struct pool_session_list)
#define POOL_IOC_CLOSE_SESS   _IOW(POOL_IOC_MAGIC, 6, uint32_t)
#define POOL_IOC_STOP         _IO(POOL_IOC_MAGIC, 7)
#define POOL_IOC_CHANNEL      _IOWR(POOL_IOC_MAGIC, 8, struct pool_channel_req)

/* Channel management operations */
#define POOL_CHAN_SUBSCRIBE    1  /* Subscribe to receive on this channel */
#define POOL_CHAN_UNSUBSCRIBE  2  /* Unsubscribe from a channel */
#define POOL_CHAN_LIST         3  /* List active channels for a session */

/* Channel management request */
struct pool_channel_req {
    uint32_t session_idx;
    uint8_t  channel;
    uint8_t  operation;   /* POOL_CHAN_* */
    uint16_t reserved;
    uint32_t result;      /* out: result/count */
    uint64_t data_ptr;    /* for LIST: pointer to uint8_t[256] bitmap */
};

/* ---- Fragment reassembly header ---- */
struct pool_frag_header {
    uint32_t msg_id;        /* message ID for reassembly */
    uint16_t frag_offset;   /* byte offset within original message */
    uint16_t total_len;     /* total message length (in LAST_FRAG) */
} __attribute__((packed));

#endif /* _POOL_H */
