/*
 * pool_platform.h - Platform Abstraction Layer for POOL
 *
 * Each platform (Linux kernel, Windows kernel, userspace) must implement
 * these functions to provide the crypto, networking, and memory primitives
 * that the POOL protocol logic depends on.
 */

#ifndef POOL_PLATFORM_H
#define POOL_PLATFORM_H

#include "pool_proto.h"

/* ---- Memory ---- */

void *pool_alloc(size_t size);
void *pool_zalloc(size_t size);
void  pool_free(void *ptr);

/* ---- Crypto: X25519 ---- */

int pool_crypto_x25519_keypair(uint8_t pub[POOL_KEY_SIZE],
                               uint8_t priv[POOL_KEY_SIZE]);
int pool_crypto_x25519_shared(uint8_t shared[POOL_KEY_SIZE],
                              const uint8_t priv[POOL_KEY_SIZE],
                              const uint8_t peer_pub[POOL_KEY_SIZE]);

/* ---- Crypto: ChaCha20-Poly1305 AEAD ---- */

int pool_crypto_aead_encrypt(const uint8_t key[POOL_KEY_SIZE],
                             const uint8_t nonce[POOL_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plain, size_t plain_len,
                             uint8_t *cipher, uint8_t tag[POOL_TAG_SIZE]);

int pool_crypto_aead_decrypt(const uint8_t key[POOL_KEY_SIZE],
                             const uint8_t nonce[POOL_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *cipher, size_t cipher_len,
                             const uint8_t tag[POOL_TAG_SIZE],
                             uint8_t *plain);

/* ---- Crypto: HMAC-SHA256 ---- */

int pool_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t out[POOL_HMAC_SIZE]);

/* ---- Crypto: HKDF-SHA256 ---- */

int pool_crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *okm, size_t okm_len);

/* ---- Crypto: Random ---- */

int pool_crypto_random(uint8_t *buf, size_t len);

/* ---- Crypto: Secure Zeroize ---- */

void pool_crypto_zeroize(void *buf, size_t len);

/* ---- Networking ---- */

typedef void *pool_socket_t;

int pool_net_tcp_connect(pool_socket_t *sock, uint32_t ip, uint16_t port);
int pool_net_tcp_listen(pool_socket_t *sock, uint16_t port, int backlog);
int pool_net_tcp_accept(pool_socket_t listen_sock, pool_socket_t *client_sock);
int pool_net_send(pool_socket_t sock, const void *buf, size_t len);
int pool_net_recv(pool_socket_t sock, void *buf, size_t len);
void pool_net_close(pool_socket_t sock);
int pool_net_set_timeout(pool_socket_t sock, int recv_ms, int send_ms);

/* ---- Threading ---- */

typedef void *pool_thread_t;
typedef void *pool_mutex_t;

int pool_thread_create(pool_thread_t *thread, int (*fn)(void *), void *arg);
int pool_thread_stop(pool_thread_t thread);
int pool_thread_should_stop(void);

int pool_mutex_init(pool_mutex_t *mutex);
void pool_mutex_lock(pool_mutex_t mutex);
void pool_mutex_unlock(pool_mutex_t mutex);
void pool_mutex_destroy(pool_mutex_t mutex);

/* ---- Time ---- */

uint64_t pool_time_ns(void);       /* monotonic nanoseconds */
void     pool_sleep_ms(uint32_t ms);

/* ---- Logging ---- */

void pool_log_info(const char *fmt, ...);
void pool_log_warn(const char *fmt, ...);
void pool_log_error(const char *fmt, ...);
void pool_log_debug(const char *fmt, ...);

#endif /* POOL_PLATFORM_H */
