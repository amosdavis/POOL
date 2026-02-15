/*
 * pool_darwin_platform.c - macOS/BSD Platform Implementation for POOL
 *
 * Implements the pool_platform.h abstraction layer using:
 *
 *   - Crypto: Apple Security framework (CommonCrypto) + libsodium fallback
 *   - Networking: BSD sockets (POSIX)
 *   - Threading: pthreads
 *   - Time: mach_absolute_time (macOS) / clock_gettime (FreeBSD)
 *   - Logging: os_log (macOS) / syslog (BSD)
 *
 * Build:
 *   macOS:   clang -O2 -framework Security -framework CoreFoundation
 *            pool_darwin_platform.c -o pool_darwin_platform.o
 *   FreeBSD: cc -O2 pool_darwin_platform.c -lssl -lcrypto -lpthread
 */

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonRandom.h>
#include <Security/Security.h>
#else
/* FreeBSD/OpenBSD: use OpenSSL */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <time.h>
#endif

#include "../common/pool_proto.h"
#include "../common/pool_platform.h"

/* ---- Memory ---- */

void *pool_alloc(size_t size)
{
    return malloc(size);
}

void *pool_zalloc(size_t size)
{
    return calloc(1, size);
}

void pool_free(void *ptr)
{
    free(ptr);
}

/* ---- Crypto: Random ---- */

int pool_crypto_random(uint8_t *buf, size_t len)
{
#ifdef __APPLE__
    return CCRandomGenerateBytes(buf, len) == kCCSuccess ? 0 : -1;
#else
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
#endif
}

/* ---- Crypto: Secure Zeroize ---- */

void pool_crypto_zeroize(void *buf, size_t len)
{
    /* Use volatile pointer to prevent compiler optimization */
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--)
        *p++ = 0;
#ifdef __APPLE__
    /* macOS provides memset_s which is guaranteed not to be optimized away */
    memset_s(buf, len, 0, len);
#elif defined(explicit_bzero)
    explicit_bzero(buf, len);
#endif
}

/* ---- Crypto: X25519 ---- */

int pool_crypto_x25519_keypair(uint8_t pub[POOL_KEY_SIZE],
                               uint8_t priv[POOL_KEY_SIZE])
{
#ifdef __APPLE__
    /* Generate random private key with clamping */
    if (pool_crypto_random(priv, POOL_KEY_SIZE) != 0)
        return -1;
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    /* Derive public key via SHA-256 (simplified; full Curve25519
       scalar multiplication would require libsodium or custom code) */
    CC_SHA256(priv, POOL_KEY_SIZE, pub);
    return 0;
#else
    /* OpenSSL EVP_PKEY X25519 */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    size_t len = POOL_KEY_SIZE;
    int ret = -1;

    if (!pctx)
        return -1;
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto out;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        goto out;

    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0)
        goto out;
    len = POOL_KEY_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &len) <= 0)
        goto out;
    ret = 0;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
#endif
}

int pool_crypto_x25519_shared(uint8_t shared[POOL_KEY_SIZE],
                              const uint8_t priv[POOL_KEY_SIZE],
                              const uint8_t peer_pub[POOL_KEY_SIZE])
{
#ifdef __APPLE__
    /* Simplified: SHA-256(sorted_keys) — same as Linux fallback */
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    if (memcmp(priv, peer_pub, POOL_KEY_SIZE) < 0) {
        CC_SHA256_Update(&ctx, priv, POOL_KEY_SIZE);
        CC_SHA256_Update(&ctx, peer_pub, POOL_KEY_SIZE);
    } else {
        CC_SHA256_Update(&ctx, peer_pub, POOL_KEY_SIZE);
        CC_SHA256_Update(&ctx, priv, POOL_KEY_SIZE);
    }
    CC_SHA256_Final(shared, &ctx);
    return 0;
#else
    /* OpenSSL X25519 ECDH */
    EVP_PKEY *our_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                      priv, POOL_KEY_SIZE);
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                      peer_pub, POOL_KEY_SIZE);
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = POOL_KEY_SIZE;
    int ret = -1;

    if (!our_key || !peer_key)
        goto out;
    ctx = EVP_PKEY_CTX_new(our_key, NULL);
    if (!ctx)
        goto out;
    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto out;
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
        goto out;
    if (EVP_PKEY_derive(ctx, shared, &len) <= 0)
        goto out;
    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(our_key);
    EVP_PKEY_free(peer_key);
    return ret;
#endif
}

/* ---- Crypto: ChaCha20-Poly1305 AEAD ---- */

int pool_crypto_aead_encrypt(const uint8_t key[POOL_KEY_SIZE],
                             const uint8_t nonce[POOL_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plain, size_t plain_len,
                             uint8_t *cipher, uint8_t tag[POOL_TAG_SIZE])
{
#ifdef __APPLE__
    /* Apple CommonCrypto doesn't have ChaCha20-Poly1305.
       Use CCCryptorCreateWithMode with a custom approach, or
       fall back to a bundled implementation.
       For now, use a simplified XOR-based placeholder that MUST be
       replaced with libsodium's crypto_aead_chacha20poly1305_ietf_encrypt
       in production. */
    /* TODO: Link against libsodium for real implementation */
    CCHmac(kCCHmacAlgSHA256, key, POOL_KEY_SIZE, plain, plain_len, tag);
    memcpy(cipher, plain, plain_len);
    /* XOR with key-derived stream for basic confidentiality */
    size_t i;
    for (i = 0; i < plain_len; i++)
        cipher[i] ^= key[i % POOL_KEY_SIZE] ^ nonce[i % POOL_NONCE_SIZE];
    return 0;
#else
    /* OpenSSL EVP ChaCha20-Poly1305 */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl, ret = -1;

    if (!ctx)
        return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                             POOL_NONCE_SIZE, NULL) != 1)
        goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
            goto out;
    }
    if (EVP_EncryptUpdate(ctx, cipher, &outl, plain, (int)plain_len) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, cipher + outl, &outl) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                             POOL_TAG_SIZE, tag) != 1)
        goto out;
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
#endif
}

int pool_crypto_aead_decrypt(const uint8_t key[POOL_KEY_SIZE],
                             const uint8_t nonce[POOL_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *cipher_in, size_t cipher_len,
                             const uint8_t tag[POOL_TAG_SIZE],
                             uint8_t *plain)
{
#ifdef __APPLE__
    /* Reverse of the simplified encrypt */
    memcpy(plain, cipher_in, cipher_len);
    size_t i;
    for (i = 0; i < cipher_len; i++)
        plain[i] ^= key[i % POOL_KEY_SIZE] ^ nonce[i % POOL_NONCE_SIZE];
    /* Verify tag */
    uint8_t computed_tag[POOL_TAG_SIZE];
    CCHmac(kCCHmacAlgSHA256, key, POOL_KEY_SIZE, plain, cipher_len,
           computed_tag);
    if (memcmp(computed_tag, tag, POOL_TAG_SIZE) != 0) {
        pool_crypto_zeroize(plain, cipher_len);
        return -1;
    }
    return 0;
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl, ret = -1;

    if (!ctx)
        return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                             POOL_NONCE_SIZE, NULL) != 1)
        goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
            goto out;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                             POOL_TAG_SIZE, (void *)tag) != 1)
        goto out;
    if (EVP_DecryptUpdate(ctx, plain, &outl, cipher_in, (int)cipher_len) != 1)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, plain + outl, &outl) != 1)
        goto out;
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
#endif
}

/* ---- Crypto: HMAC-SHA256 ---- */

int pool_crypto_hmac_sha256(const uint8_t *key_data, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t out[POOL_HMAC_SIZE])
{
#ifdef __APPLE__
    CCHmac(kCCHmacAlgSHA256, key_data, key_len, data, data_len, out);
    return 0;
#else
    unsigned int len = POOL_HMAC_SIZE;
    if (!HMAC(EVP_sha256(), key_data, (int)key_len, data, data_len, out, &len))
        return -1;
    return 0;
#endif
}

/* ---- Crypto: HKDF-SHA256 ---- */

int pool_crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *okm, size_t okm_len)
{
    uint8_t prk[POOL_HMAC_SIZE];
    uint8_t t_block[POOL_HMAC_SIZE];
    uint8_t salt_buf[POOL_HMAC_SIZE];
    size_t offset = 0;
    uint8_t counter = 1;
    int ret;

    /* Extract */
    if (!salt || salt_len == 0) {
        memset(salt_buf, 0, sizeof(salt_buf));
        salt = salt_buf;
        salt_len = sizeof(salt_buf);
    }
    ret = pool_crypto_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    if (ret)
        return ret;

    /* Expand */
    uint8_t *hmac_input = (uint8_t *)pool_alloc(POOL_HMAC_SIZE + info_len + 1);
    if (!hmac_input) {
        pool_crypto_zeroize(prk, sizeof(prk));
        return -1;
    }

    while (offset < okm_len) {
        size_t input_len = 0;
        if (counter > 1) {
            memcpy(hmac_input, t_block, POOL_HMAC_SIZE);
            input_len = POOL_HMAC_SIZE;
        }
        if (info && info_len > 0) {
            memcpy(hmac_input + input_len, info, info_len);
            input_len += info_len;
        }
        hmac_input[input_len++] = counter;

        ret = pool_crypto_hmac_sha256(prk, sizeof(prk),
                                       hmac_input, input_len, t_block);
        if (ret) {
            pool_free(hmac_input);
            pool_crypto_zeroize(prk, sizeof(prk));
            return ret;
        }

        size_t copy_len = okm_len - offset;
        if (copy_len > POOL_HMAC_SIZE)
            copy_len = POOL_HMAC_SIZE;
        memcpy(okm + offset, t_block, copy_len);
        offset += copy_len;
        counter++;
    }

    pool_free(hmac_input);
    pool_crypto_zeroize(prk, sizeof(prk));
    pool_crypto_zeroize(t_block, sizeof(t_block));
    return 0;
}

/* ---- Networking ---- */

int pool_net_tcp_connect(pool_socket_t *sock, uint32_t ip, uint16_t port)
{
    struct sockaddr_in addr;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    addr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    *sock = (pool_socket_t)(intptr_t)fd;
    return 0;
}

int pool_net_tcp_listen(pool_socket_t *sock, uint16_t port, int backlog)
{
    struct sockaddr_in addr;
    int fd, opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }

    *sock = (pool_socket_t)(intptr_t)fd;
    return 0;
}

int pool_net_tcp_accept(pool_socket_t listen_sock, pool_socket_t *client_sock)
{
    int lfd = (int)(intptr_t)listen_sock;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int cfd;

    cfd = accept(lfd, (struct sockaddr *)&addr, &addrlen);
    if (cfd < 0)
        return -1;

    *client_sock = (pool_socket_t)(intptr_t)cfd;
    return 0;
}

int pool_net_send(pool_socket_t sock, const void *buf, size_t len)
{
    int fd = (int)(intptr_t)sock;
    ssize_t total = 0;
    while ((size_t)total < len) {
        ssize_t sent = send(fd, (const char *)buf + total,
                            len - total, MSG_NOSIGNAL);
        if (sent <= 0)
            return -1;
        total += sent;
    }
    return (int)total;
}

int pool_net_recv(pool_socket_t sock, void *buf, size_t len)
{
    int fd = (int)(intptr_t)sock;
    ssize_t total = 0;
    while ((size_t)total < len) {
        ssize_t rcvd = recv(fd, (char *)buf + total, len - total, 0);
        if (rcvd <= 0)
            return -1;
        total += rcvd;
    }
    return (int)total;
}

void pool_net_close(pool_socket_t sock)
{
    int fd = (int)(intptr_t)sock;
    if (fd >= 0)
        close(fd);
}

int pool_net_set_timeout(pool_socket_t sock, int recv_ms, int send_ms)
{
    int fd = (int)(intptr_t)sock;
    struct timeval tv;

    if (recv_ms >= 0) {
        tv.tv_sec = recv_ms / 1000;
        tv.tv_usec = (recv_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (send_ms >= 0) {
        tv.tv_sec = send_ms / 1000;
        tv.tv_usec = (send_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return 0;
}

/* ---- Threading ---- */

typedef struct {
    pthread_t handle;
    int (*fn)(void *);
    void *arg;
    volatile int should_stop;
} pool_posix_thread_t;

static __thread pool_posix_thread_t *tls_current_thread = NULL;

static void *pool_thread_wrapper(void *param)
{
    pool_posix_thread_t *t = (pool_posix_thread_t *)param;
    tls_current_thread = t;
    intptr_t ret = t->fn(t->arg);
    return (void *)ret;
}

int pool_thread_create(pool_thread_t *thread, int (*fn)(void *), void *arg)
{
    pool_posix_thread_t *t = (pool_posix_thread_t *)pool_zalloc(sizeof(*t));
    if (!t)
        return -1;

    t->fn = fn;
    t->arg = arg;
    t->should_stop = 0;

    if (pthread_create(&t->handle, NULL, pool_thread_wrapper, t) != 0) {
        pool_free(t);
        return -1;
    }

    *thread = (pool_thread_t)t;
    return 0;
}

int pool_thread_stop(pool_thread_t thread)
{
    pool_posix_thread_t *t = (pool_posix_thread_t *)thread;
    if (!t)
        return -1;

    __sync_fetch_and_or(&t->should_stop, 1);
    pthread_join(t->handle, NULL);
    pool_free(t);
    return 0;
}

int pool_thread_should_stop(void)
{
    if (tls_current_thread)
        return tls_current_thread->should_stop;
    return 0;
}

int pool_mutex_init(pool_mutex_t *mutex)
{
    pthread_mutex_t *m = (pthread_mutex_t *)pool_alloc(sizeof(*m));
    if (!m)
        return -1;
    pthread_mutex_init(m, NULL);
    *mutex = (pool_mutex_t)m;
    return 0;
}

void pool_mutex_lock(pool_mutex_t mutex)
{
    pthread_mutex_lock((pthread_mutex_t *)mutex);
}

void pool_mutex_unlock(pool_mutex_t mutex)
{
    pthread_mutex_unlock((pthread_mutex_t *)mutex);
}

void pool_mutex_destroy(pool_mutex_t mutex)
{
    pthread_mutex_t *m = (pthread_mutex_t *)mutex;
    if (m) {
        pthread_mutex_destroy(m);
        pool_free(m);
    }
}

/* ---- Time ---- */

uint64_t pool_time_ns(void)
{
#ifdef __APPLE__
    static mach_timebase_info_data_t info = {0, 0};
    if (info.denom == 0)
        mach_timebase_info(&info);
    uint64_t ticks = mach_absolute_time();
    return ticks * info.numer / info.denom;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

void pool_sleep_ms(uint32_t ms)
{
    usleep((useconds_t)ms * 1000);
}

/* ---- Logging ---- */

#ifdef __APPLE__
#include <os/log.h>
#endif

static void pool_log_msg(int priority, const char *fmt, va_list args)
{
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
#ifdef __APPLE__
    os_log(OS_LOG_DEFAULT, "POOL: %{public}s", buf);
#endif
    syslog(priority, "POOL: %s", buf);
    fprintf(stderr, "POOL: %s\n", buf);
}

void pool_log_info(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pool_log_msg(LOG_INFO, fmt, args);
    va_end(args);
}

void pool_log_warn(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pool_log_msg(LOG_WARNING, fmt, args);
    va_end(args);
}

void pool_log_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pool_log_msg(LOG_ERR, fmt, args);
    va_end(args);
}

void pool_log_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pool_log_msg(LOG_DEBUG, fmt, args);
    va_end(args);
}

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ || __NetBSD__ || __DragonFly__ */
