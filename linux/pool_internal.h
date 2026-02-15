/*
 * pool_internal.h - POOL kernel module internal state
 *
 * Not shared with userspace.
 */
#ifndef _POOL_INTERNAL_H
#define _POOL_INTERNAL_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>

#include "pool.h"

/* ---- Per-session crypto state ---- */

struct pool_crypto_state {
    uint8_t  local_privkey[POOL_KEY_SIZE];   /* ephemeral X25519 private */
    uint8_t  local_pubkey[POOL_KEY_SIZE];    /* ephemeral X25519 public */
    uint8_t  remote_pubkey[POOL_KEY_SIZE];   /* peer's ephemeral public */
    uint8_t  shared_secret[POOL_KEY_SIZE];   /* ECDH result */
    uint8_t  session_key[POOL_KEY_SIZE];     /* derived data encryption key */
    uint8_t  hmac_key[POOL_KEY_SIZE];        /* derived HMAC key */
    uint8_t  seq_key[POOL_KEY_SIZE];         /* derived sequence encryption key */
    uint64_t local_seq;                      /* our next sequence number */
    uint64_t remote_seq;                     /* highest peer seq we've seen */
    uint32_t packets_since_rekey;
    uint64_t last_rekey_jiffies;
    struct crypto_aead *aead;                /* ChaCha20-Poly1305 */
    struct crypto_shash *hmac;               /* HMAC-SHA256 */
};

/* ---- Fragment reassembly buffer ---- */

struct pool_frag_buf {
    uint32_t msg_id;
    uint32_t total_len;
    uint32_t received;
    uint8_t  *data;
    unsigned long start_jiffies;
    int      complete;
};

/* ---- Receive queue entry ---- */

struct pool_rx_entry {
    struct list_head list;
    uint8_t  channel;
    uint32_t len;
    uint8_t  *data;
};

/* ---- Per-session state ---- */

struct pool_session {
    int      active;
    uint8_t  state;
    uint8_t  transport;   /* POOL_TRANSPORT_TCP or POOL_TRANSPORT_RAW */
    uint8_t  session_id[POOL_SESSION_ID_SIZE];
    uint32_t peer_ip;
    uint16_t peer_port;

    struct socket *sock;

    struct pool_crypto_state crypto;

    /* Handshake state */
    uint8_t  puzzle_seed[32];
    uint64_t server_secret;    /* rotating secret for stateless challenges */

    /* Telemetry */
    struct pool_telemetry telemetry;
    uint64_t connect_time;     /* ktime_get_ns() at session establish */
    uint64_t last_heartbeat;
    uint64_t last_send_ts;     /* for RTT measurement */

    /* Stats */
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t expected_remote_seq; /* next expected remote seq for loss detection */
    uint64_t packets_lost;        /* estimated lost packets (seq gaps) */

    /* Fragment reassembly */
    struct pool_frag_buf frags[16]; /* up to 16 concurrent fragmented msgs */
    uint32_t next_msg_id;

    /* Receive queue */
    struct list_head rx_queue;
    spinlock_t rx_lock;
    wait_queue_head_t rx_wait;

    /* Receiver thread */
    struct task_struct *rx_thread;

    struct mutex send_lock;   /* protects send_packet (seq, HMAC, socket write) */
    struct mutex crypto_lock; /* protects per-session crypto transforms */
    struct mutex lock;

    /* MTU discovery (PMTUD) */
    uint16_t mtu;              /* current effective MTU for this session */
    uint16_t mtu_probe_lo;     /* binary search lower bound */
    uint16_t mtu_probe_hi;     /* binary search upper bound */
    uint8_t  mtu_probing;      /* 1 if probe in flight */
    uint64_t mtu_last_probe;   /* ktime_get_ns() of last probe */
    uint16_t mtu_probe_size;   /* size of current in-flight probe */

    /* Channel subscriptions: bitmap of 256 channels */
    uint8_t  channel_subs[32]; /* 256 bits = 32 bytes */
};

/* ---- Global module state ---- */

struct pool_state {
    /* Char device */
    int major;
    struct class *dev_class;
    struct device *dev_device;

    /* Listener */
    struct socket *listen_sock;       /* TCP listener */
    struct socket *raw_sock;          /* Raw IP proto 253 socket */
    struct task_struct *listen_thread;
    struct task_struct *raw_listen_thread;
    uint16_t listen_port;
    int listening;
    uint8_t transport_mode;           /* POOL_TRANSPORT_* */

    /* Sessions */
    struct pool_session sessions[POOL_MAX_SESSIONS];
    struct mutex sessions_lock;

    /* Procfs */
    struct proc_dir_entry *proc_dir;
    struct proc_dir_entry *proc_status;
    struct proc_dir_entry *proc_sessions;
    struct proc_dir_entry *proc_telemetry;
    struct proc_dir_entry *proc_journal;

    /* Journal */
    struct pool_journal_entry *journal;
    int journal_count;
    int journal_max;
    struct mutex journal_lock;

    /* Module identity */
    uint8_t  node_privkey[POOL_KEY_SIZE];
    uint8_t  node_pubkey[POOL_KEY_SIZE];
    struct pool_address node_addr;

    /* Heartbeat */
    struct task_struct *heartbeat_thread;

    /* Workqueue for async operations */
    struct workqueue_struct *wq;
};

extern struct pool_state pool;

/* ---- Function declarations ---- */

/* pool_crypto.c */
int pool_crypto_init(void);
void pool_crypto_cleanup(void);
int pool_crypto_gen_keypair(uint8_t *privkey, uint8_t *pubkey);
int pool_crypto_ecdh(const uint8_t *privkey, const uint8_t *peer_pubkey,
                     uint8_t *shared_secret);
int pool_crypto_hkdf(const uint8_t *ikm, int ikm_len,
                     const uint8_t *info, int info_len,
                     uint8_t *okm, int okm_len);
int pool_crypto_derive_keys(struct pool_crypto_state *cs);
int pool_crypto_encrypt(struct pool_crypto_state *cs,
                        const uint8_t *plaintext, int plain_len,
                        uint8_t *ciphertext, int *cipher_len,
                        uint64_t seq);
int pool_crypto_decrypt(struct pool_crypto_state *cs,
                        const uint8_t *ciphertext, int cipher_len,
                        uint8_t *plaintext, int *plain_len,
                        uint64_t seq);
int pool_crypto_hmac(struct pool_crypto_state *cs,
                     const void *data, int data_len,
                     uint8_t *out);
int pool_crypto_hmac_verify(struct pool_crypto_state *cs,
                            const void *data, int data_len,
                            const uint8_t *expected);
int pool_crypto_init_session(struct pool_crypto_state *cs);
void pool_crypto_cleanup_session(struct pool_crypto_state *cs);
void pool_crypto_gen_puzzle(uint8_t *seed, uint64_t server_secret,
                            uint32_t client_ip);
int pool_crypto_verify_puzzle(const uint8_t *seed, const uint8_t *solution,
                              uint16_t difficulty);
uint64_t pool_crypto_next_seq(struct pool_crypto_state *cs);

/* pool_net.c */
int pool_net_init(void);
void pool_net_cleanup(void);
int pool_net_listen(uint16_t port);
void pool_net_stop_listen(void);
int pool_net_connect(struct pool_session *sess, uint32_t ip, uint16_t port);
void pool_net_set_sock_rcvtimeo(struct socket *sock, int seconds);
int pool_net_send_raw(struct socket *sock, void *buf, int len);
int pool_net_recv_raw(struct socket *sock, void *buf, int len);
int pool_net_send_packet(struct pool_session *sess, uint8_t type,
                         uint16_t flags, uint8_t channel,
                         const void *payload, int payload_len);
int pool_net_recv_packet(struct pool_session *sess,
                         struct pool_header *hdr,
                         uint8_t *payload, int *payload_len);

/* pool_net_raw.c — Raw IP protocol 253 transport */
int pool_net_raw_init(void);
void pool_net_raw_cleanup(void);
int pool_net_raw_listen(void);
void pool_net_raw_stop_listen(void);
int pool_net_raw_connect(struct pool_session *sess, uint32_t ip);
int pool_net_raw_send(struct pool_session *sess, void *buf, int len);
int pool_net_raw_recv(struct pool_session *sess, void *buf, int len);

/* pool_session.c */
int pool_session_init(void);
void pool_session_cleanup(void);
struct pool_session *pool_session_alloc(void);
void pool_session_free(struct pool_session *sess);
int pool_session_connect(uint32_t ip, uint16_t port);
int pool_session_accept(struct socket *client_sock);
void pool_session_close(struct pool_session *sess);
int pool_session_rekey(struct pool_session *sess);

/* pool_data.c */
int pool_data_send(struct pool_session *sess, uint8_t channel,
                   const void *data, uint32_t len);
int pool_data_recv(struct pool_session *sess, uint8_t channel,
                   void *buf, uint32_t *len, int timeout_ms);
int pool_data_send_fragmented(struct pool_session *sess, uint8_t channel,
                              const void *data, uint32_t len);
int pool_data_handle_fragment(struct pool_session *sess,
                              const uint8_t *payload, uint32_t plen,
                              uint16_t flags, uint8_t channel,
                              uint8_t **out_data, uint32_t *out_len,
                              uint8_t *out_channel);

/* pool_telemetry.c */
int pool_telemetry_init(void);
void pool_telemetry_cleanup(void);
void pool_telemetry_update_rtt(struct pool_session *sess, uint64_t rtt_ns);
void pool_telemetry_record_send(struct pool_session *sess, uint32_t bytes);
void pool_telemetry_record_recv(struct pool_session *sess, uint32_t bytes);

/* pool_mtu.c */
void pool_mtu_init_session(struct pool_session *sess);
void pool_mtu_send_probe(struct pool_session *sess);
void pool_mtu_handle_discover(struct pool_session *sess,
                              const uint8_t *payload, uint32_t plen,
                              uint16_t flags);
void pool_mtu_probe_timeout(struct pool_session *sess);
uint16_t pool_mtu_effective(struct pool_session *sess);

/* pool_sysinfo.c */
int pool_sysinfo_init(void);
void pool_sysinfo_cleanup(void);

/* pool_journal.c */
int pool_journal_init(void);
void pool_journal_cleanup(void);
void pool_journal_add(uint16_t change_type, uint32_t ver_before,
                      uint32_t ver_after, const void *detail, int detail_len);

/* pool_config.c */
void pool_config_init(void);
void pool_config_handle_config(struct pool_session *sess,
                               const uint8_t *payload, uint32_t plen);
void pool_config_handle_rollback(struct pool_session *sess,
                                 const uint8_t *payload, uint32_t plen);
void pool_config_check_deadline(struct pool_session *sess);
void pool_config_confirm(struct pool_session *sess);
uint32_t pool_config_version(void);

/* pool_discover.c */
void pool_discover_init(void);
int pool_discover_start(void);
void pool_discover_stop(void);
void pool_discover_handle_exchange(struct pool_session *sess,
                                   const uint8_t *payload, uint32_t plen);
int pool_discover_build_exchange(uint8_t *buf, int max_len);
int pool_discover_peer_count(void);

/* pool_pqc.c — Post-quantum cryptography (ML-KEM-768 hybrid) */
#define MLKEM_PUBKEY_SIZE   1184
#define MLKEM_SECKEY_SIZE   2400
#define MLKEM_CT_SIZE       1088
#define MLKEM_SS_SIZE       32

int pool_pqc_keygen(uint8_t *pk, uint8_t *sk);
int pool_pqc_encaps(const uint8_t *pk, uint8_t *ct, uint8_t *ss);
int pool_pqc_decaps(const uint8_t *sk, const uint8_t *ct, uint8_t *ss);
int pool_pqc_hybrid_combine(const uint8_t *x25519_ss,
                            const uint8_t *mlkem_ss,
                            uint8_t *combined_ss);
int pool_pqc_enabled(void);
int pool_pqc_get_version(void);
int pool_pqc_negotiate(int peer_version);

#endif /* _POOL_INTERNAL_H */
