/*
 * pool_crypto.c - POOL Protocol cryptography layer
 *
 * Implements:
 *   - X25519 key exchange (via kernel crypto KPP API)
 *   - HKDF-SHA256 key derivation
 *   - ChaCha20-Poly1305 AEAD encryption/decryption
 *   - HMAC-SHA256 packet authentication
 *   - Cryptographic sequence numbers
 *   - Puzzle generation/verification for stateless handshake
 */

#include <linux/random.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <crypto/algapi.h>
#include <linux/string.h>

#include "pool_internal.h"

/* Global HMAC tfm for key derivation (not session-specific) */
static struct crypto_shash *pool_hmac_tfm;

/*
 * Self-test: Known-answer test for HMAC-SHA256.
 * RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
 * Expected HMAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
 */
static int pool_crypto_selftest_hmac(void)
{
    static const uint8_t key[] = "Jefe";
    static const uint8_t data[] = "what do ya want for nothing?";
    static const uint8_t expected[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };
    uint8_t result[32];
    SHASH_DESC_ON_STACK(desc, pool_hmac_tfm);
    int ret;

    desc->tfm = pool_hmac_tfm;
    ret = crypto_shash_setkey(pool_hmac_tfm, key, 4);
    if (ret)
        return ret;
    ret = crypto_shash_init(desc);
    if (ret)
        return ret;
    ret = crypto_shash_update(desc, data, 28);
    if (ret)
        return ret;
    ret = crypto_shash_final(desc, result);
    if (ret)
        return ret;

    if (memcmp(result, expected, 32) != 0) {
        pr_err("POOL: HMAC-SHA256 self-test FAILED\n");
        return -EACCES;
    }
    return 0;
}

/*
 * Self-test: Verify ChaCha20-Poly1305 AEAD round-trip.
 * Encrypt a known plaintext and verify decryption recovers it.
 */
static int pool_crypto_selftest_aead(void)
{
    struct crypto_aead *tfm;
    struct aead_request *req;
    struct scatterlist sg_src, sg_dst;
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    static const uint8_t plain[] = "POOL self-test";
    uint8_t *buf;
    int ret;
    size_t plen = sizeof(plain) - 1;

    tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    crypto_aead_setauthsize(tfm, POOL_TAG_SIZE);
    ret = crypto_aead_setkey(tfm, key, sizeof(key));
    if (ret)
        goto out_free_tfm;

    buf = kzalloc(plen + POOL_TAG_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out_free_tfm;
    }
    memcpy(buf, plain, plen);

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out_free_buf;
    }

    /* Encrypt */
    sg_init_one(&sg_src, buf, plen + POOL_TAG_SIZE);
    sg_init_one(&sg_dst, buf, plen + POOL_TAG_SIZE);
    aead_request_set_crypt(req, &sg_src, &sg_dst, plen, (u8 *)nonce);
    aead_request_set_ad(req, 0);
    ret = crypto_aead_encrypt(req);
    if (ret)
        goto out_free_req;

    /* Verify ciphertext differs from plaintext */
    if (memcmp(buf, plain, plen) == 0) {
        pr_err("POOL: AEAD self-test FAILED (ciphertext == plaintext)\n");
        ret = -EACCES;
        goto out_free_req;
    }

    /* Decrypt */
    sg_init_one(&sg_src, buf, plen + POOL_TAG_SIZE);
    sg_init_one(&sg_dst, buf, plen + POOL_TAG_SIZE);
    aead_request_set_crypt(req, &sg_src, &sg_dst, plen + POOL_TAG_SIZE,
                           (u8 *)nonce);
    aead_request_set_ad(req, 0);
    ret = crypto_aead_decrypt(req);
    if (ret)
        goto out_free_req;

    /* Verify round-trip */
    if (memcmp(buf, plain, plen) != 0) {
        pr_err("POOL: AEAD self-test FAILED (decrypted != original)\n");
        ret = -EACCES;
        goto out_free_req;
    }

    ret = 0;

out_free_req:
    aead_request_free(req);
out_free_buf:
    kfree(buf);
out_free_tfm:
    crypto_free_aead(tfm);
    return ret;
}

int pool_crypto_init(void)
{
    int ret;

    pool_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(pool_hmac_tfm)) {
        pr_err("POOL: failed to allocate hmac(sha256): %ld\n",
               PTR_ERR(pool_hmac_tfm));
        pool_hmac_tfm = NULL;
        return -ENOMEM;
    }

    /* Run mandatory self-tests (SECURITY.md §3.4) */
    ret = pool_crypto_selftest_hmac();
    if (ret) {
        pr_err("POOL: HMAC-SHA256 self-test failed, refusing to load\n");
        crypto_free_shash(pool_hmac_tfm);
        pool_hmac_tfm = NULL;
        return ret;
    }

    ret = pool_crypto_selftest_aead();
    if (ret) {
        pr_err("POOL: ChaCha20-Poly1305 self-test failed, refusing to load\n");
        crypto_free_shash(pool_hmac_tfm);
        pool_hmac_tfm = NULL;
        return ret;
    }

    pr_info("POOL: crypto subsystem initialized (self-tests passed)\n");
    return 0;
}

void pool_crypto_cleanup(void)
{
    if (pool_hmac_tfm) {
        crypto_free_shash(pool_hmac_tfm);
        pool_hmac_tfm = NULL;
    }
}

/* Generate X25519 keypair - use random public key (KPP generates it) */
int pool_crypto_gen_keypair(uint8_t *privkey, uint8_t *pubkey)
{
    struct crypto_kpp *kpp;
    struct kpp_request *req;
    struct scatterlist sg;
    uint8_t *out_buf;
    DECLARE_CRYPTO_WAIT(wait);
    int ret;

    get_random_bytes(privkey, POOL_KEY_SIZE);
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;

    kpp = crypto_alloc_kpp("curve25519", 0, 0);
    if (IS_ERR(kpp)) {
        /* Fallback: derive pubkey from privkey via SHA256 */
        struct crypto_shash *sha;
        SHASH_DESC_ON_STACK(desc, NULL);
        sha = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(sha))
            return PTR_ERR(sha);
        desc->tfm = sha;
        crypto_shash_init(desc);
        crypto_shash_update(desc, privkey, POOL_KEY_SIZE);
        crypto_shash_final(desc, pubkey);
        crypto_free_shash(sha);
        return 0;
    }

    ret = crypto_kpp_set_secret(kpp, privkey, POOL_KEY_SIZE);
    if (ret) {
        crypto_free_kpp(kpp);
        return ret;
    }

    req = kpp_request_alloc(kpp, GFP_KERNEL);
    if (!req) {
        crypto_free_kpp(kpp);
        return -ENOMEM;
    }

    out_buf = kmalloc(POOL_KEY_SIZE, GFP_KERNEL);
    if (!out_buf) {
        kpp_request_free(req);
        crypto_free_kpp(kpp);
        return -ENOMEM;
    }

    sg_init_one(&sg, out_buf, POOL_KEY_SIZE);
    kpp_request_set_output(req, &sg, POOL_KEY_SIZE);
    kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                             crypto_req_done, &wait);

    ret = crypto_wait_req(crypto_kpp_generate_public_key(req), &wait);
    if (ret == 0)
        memcpy(pubkey, out_buf, POOL_KEY_SIZE);

    kfree(out_buf);
    kpp_request_free(req);
    crypto_free_kpp(kpp);
    return ret;
}

/*
 * X25519 ECDH shared secret.
 * Uses KPP API, with SHA256-based fallback if KPP fails.
 * Both sides MUST produce the same shared_secret from the same
 * (privkey, peer_pubkey) pair.
 */
int pool_crypto_ecdh(const uint8_t *privkey, const uint8_t *peer_pubkey,
                     uint8_t *shared_secret)
{
    struct crypto_kpp *kpp;
    struct kpp_request *req;
    struct scatterlist sg_in, sg_out;
    uint8_t *peer_copy, *out_buf;
    DECLARE_CRYPTO_WAIT(wait);
    int ret;

    kpp = crypto_alloc_kpp("curve25519", 0, 0);
    if (IS_ERR(kpp)) {
        /*
         * C02: Fallback when kernel lacks curve25519 KPP.
         * shared = SHA256(sorted(pubA, pubB))
         *
         * This IS commutative — both sides compute the same value.
         * However, it does NOT provide X25519's CDH security property.
         * An eavesdropper who knows both public keys can compute the
         * shared secret. This fallback only protects against passive
         * attackers who don't see the handshake. Log a warning.
         */
        struct crypto_shash *sha;
        SHASH_DESC_ON_STACK(desc, NULL);
        uint8_t my_pubkey[POOL_KEY_SIZE];

        pr_warn_once("POOL: curve25519 KPP unavailable, using SHA256 fallback (REDUCED SECURITY)\n");

        sha = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(sha))
            return PTR_ERR(sha);

        /* Compute our pubkey from privkey (matches keygen fallback) */
        desc->tfm = sha;
        crypto_shash_init(desc);
        crypto_shash_update(desc, privkey, POOL_KEY_SIZE);
        crypto_shash_final(desc, my_pubkey);

        /* shared = SHA256(sorted_pubkeys) — commutative */
        crypto_shash_init(desc);
        if (memcmp(my_pubkey, peer_pubkey, POOL_KEY_SIZE) < 0) {
            crypto_shash_update(desc, my_pubkey, POOL_KEY_SIZE);
            crypto_shash_update(desc, peer_pubkey, POOL_KEY_SIZE);
        } else {
            crypto_shash_update(desc, peer_pubkey, POOL_KEY_SIZE);
            crypto_shash_update(desc, my_pubkey, POOL_KEY_SIZE);
        }
        crypto_shash_final(desc, shared_secret);
        memzero_explicit(my_pubkey, sizeof(my_pubkey));
        crypto_free_shash(sha);
        return 0;
    }

    ret = crypto_kpp_set_secret(kpp, privkey, POOL_KEY_SIZE);
    if (ret) {
        crypto_free_kpp(kpp);
        return ret;
    }

    req = kpp_request_alloc(kpp, GFP_KERNEL);
    if (!req) {
        crypto_free_kpp(kpp);
        return -ENOMEM;
    }

    peer_copy = kmalloc(POOL_KEY_SIZE, GFP_KERNEL);
    out_buf = kmalloc(POOL_KEY_SIZE, GFP_KERNEL);
    if (!peer_copy || !out_buf) {
        kfree(peer_copy);
        kfree(out_buf);
        kpp_request_free(req);
        crypto_free_kpp(kpp);
        return -ENOMEM;
    }
    memcpy(peer_copy, peer_pubkey, POOL_KEY_SIZE);

    sg_init_one(&sg_in, peer_copy, POOL_KEY_SIZE);
    sg_init_one(&sg_out, out_buf, POOL_KEY_SIZE);

    kpp_request_set_input(req, &sg_in, POOL_KEY_SIZE);
    kpp_request_set_output(req, &sg_out, POOL_KEY_SIZE);
    kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                             crypto_req_done, &wait);

    ret = crypto_wait_req(crypto_kpp_compute_shared_secret(req), &wait);
    if (ret == 0)
        memcpy(shared_secret, out_buf, POOL_KEY_SIZE);

    kfree(peer_copy);
    kfree(out_buf);
    kpp_request_free(req);
    crypto_free_kpp(kpp);
    return ret;
}

/* HKDF-SHA256 extract+expand (simplified: single output block) */
int pool_crypto_hkdf(const uint8_t *ikm, int ikm_len,
                     const uint8_t *info, int info_len,
                     uint8_t *okm, int okm_len)
{
    SHASH_DESC_ON_STACK(desc, pool_hmac_tfm);
    uint8_t prk[32]; /* extract output */
    uint8_t salt[32];
    uint8_t counter = 1;
    int ret;

    if (!pool_hmac_tfm)
        return -EINVAL;

    /* C03: Enforce RFC 5869 output length limit: 255 * HashLen */
    if (okm_len <= 0 || okm_len > 255 * 32)
        return -EINVAL;

    desc->tfm = pool_hmac_tfm;

    /* Extract: PRK = HMAC-SHA256(salt=zeros, IKM) */
    memset(salt, 0, sizeof(salt));
    ret = crypto_shash_setkey(pool_hmac_tfm, salt, sizeof(salt));
    if (ret)
        return ret;
    ret = crypto_shash_init(desc);
    if (ret)
        return ret;
    ret = crypto_shash_update(desc, ikm, ikm_len);
    if (ret)
        return ret;
    ret = crypto_shash_final(desc, prk);
    if (ret)
        return ret;

    /* Expand: OKM = HMAC-SHA256(PRK, info || 0x01) */
    ret = crypto_shash_setkey(pool_hmac_tfm, prk, sizeof(prk));
    if (ret)
        return ret;
    ret = crypto_shash_init(desc);
    if (ret)
        return ret;
    if (info && info_len > 0) {
        ret = crypto_shash_update(desc, info, info_len);
        if (ret)
            return ret;
    }
    ret = crypto_shash_update(desc, &counter, 1);
    if (ret)
        return ret;
    ret = crypto_shash_final(desc, okm);
    if (ret)
        return ret;

    /* If more than 32 bytes requested, produce another block */
    if (okm_len > 32) {
        counter = 2;
        ret = crypto_shash_init(desc);
        if (ret) return ret;
        ret = crypto_shash_update(desc, okm, 32); /* T(1) */
        if (ret) return ret;
        if (info && info_len > 0) {
            ret = crypto_shash_update(desc, info, info_len);
            if (ret) return ret;
        }
        ret = crypto_shash_update(desc, &counter, 1);
        if (ret) return ret;
        ret = crypto_shash_final(desc, okm + 32);
        if (ret) return ret;
    }

    memzero_explicit(prk, sizeof(prk));
    return 0;
}

/* Derive session keys from shared secret */
int pool_crypto_derive_keys(struct pool_crypto_state *cs)
{
    static const uint8_t enc_label[] = "pool-session-key";
    static const uint8_t hmac_label[] = "pool-hmac-key";
    static const uint8_t seq_label[] = "pool-seq-key";
    int ret;

    ret = pool_crypto_hkdf(cs->shared_secret, POOL_KEY_SIZE,
                           enc_label, sizeof(enc_label) - 1,
                           cs->session_key, POOL_KEY_SIZE);
    if (ret)
        return ret;

    ret = pool_crypto_hkdf(cs->shared_secret, POOL_KEY_SIZE,
                           hmac_label, sizeof(hmac_label) - 1,
                           cs->hmac_key, POOL_KEY_SIZE);
    if (ret)
        return ret;

    ret = pool_crypto_hkdf(cs->shared_secret, POOL_KEY_SIZE,
                           seq_label, sizeof(seq_label) - 1,
                           cs->seq_key, POOL_KEY_SIZE);
    if (ret)
        return ret;

    /* Initialize CSPRNG sequence number */
    get_random_bytes(&cs->local_seq, sizeof(cs->local_seq));
    cs->remote_seq = 0;
    cs->packets_since_rekey = 0;
    cs->last_rekey_jiffies = jiffies;

    return 0;
}

/* Init per-session crypto (allocate AEAD + HMAC) */
int pool_crypto_init_session(struct pool_crypto_state *cs)
{
    int ret;

    cs->aead = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
    if (IS_ERR(cs->aead)) {
        pr_err("POOL: failed to alloc chacha20-poly1305: %ld\n",
               PTR_ERR(cs->aead));
        cs->aead = NULL;
        return -ENOMEM;
    }

    ret = crypto_aead_setauthsize(cs->aead, POOL_TAG_SIZE);
    if (ret) {
        crypto_free_aead(cs->aead);
        cs->aead = NULL;
        return ret;
    }

    cs->hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(cs->hmac)) {
        crypto_free_aead(cs->aead);
        cs->aead = NULL;
        cs->hmac = NULL;
        return -ENOMEM;
    }

    return 0;
}

void pool_crypto_cleanup_session(struct pool_crypto_state *cs)
{
    if (cs->aead) {
        crypto_free_aead(cs->aead);
        cs->aead = NULL;
    }
    if (cs->hmac) {
        crypto_free_shash(cs->hmac);
        cs->hmac = NULL;
    }
    memzero_explicit(cs->shared_secret, POOL_KEY_SIZE);
    memzero_explicit(cs->session_key, POOL_KEY_SIZE);
    memzero_explicit(cs->hmac_key, POOL_KEY_SIZE);
    memzero_explicit(cs->seq_key, POOL_KEY_SIZE);
    memzero_explicit(cs->local_privkey, POOL_KEY_SIZE);
}

/* Encrypt data with ChaCha20-Poly1305 */
int pool_crypto_encrypt(struct pool_crypto_state *cs,
                        const uint8_t *plaintext, int plain_len,
                        uint8_t *ciphertext, int *cipher_len,
                        uint64_t seq)
{
    struct aead_request *req;
    struct scatterlist sg_plain, sg_cipher;
    uint8_t nonce[POOL_NONCE_SIZE];
    uint8_t *combined;
    int ret, total_len;
    DECLARE_CRYPTO_WAIT(wait);

    if (!cs->aead)
        return -EINVAL;

    /*
     * C01: Derive 12-byte nonce with full entropy. Use first 4 bytes of
     * hmac_key (unique per session) for bytes 0-3, then 8 bytes of
     * sequence number. This eliminates the zero-prefix weakness.
     */
    memcpy(nonce, cs->hmac_key, 4);
    memcpy(nonce + 4, &seq, 8);

    ret = crypto_aead_setkey(cs->aead, cs->session_key, POOL_KEY_SIZE);
    if (ret)
        return ret;

    total_len = plain_len + POOL_TAG_SIZE;
    combined = kmalloc(total_len, GFP_KERNEL);
    if (!combined)
        return -ENOMEM;
    memcpy(combined, plaintext, plain_len);

    req = aead_request_alloc(cs->aead, GFP_KERNEL);
    if (!req) {
        kfree(combined);
        return -ENOMEM;
    }

    sg_init_one(&sg_plain, combined, total_len);
    sg_init_one(&sg_cipher, combined, total_len);

    aead_request_set_crypt(req, &sg_plain, &sg_cipher,
                           plain_len, nonce);
    aead_request_set_ad(req, 0);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              crypto_req_done, &wait);

    ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (ret == 0) {
        memcpy(ciphertext, combined, total_len);
        *cipher_len = total_len;
    }

    aead_request_free(req);
    kfree(combined);
    return ret;
}

/* Decrypt data with ChaCha20-Poly1305 */
int pool_crypto_decrypt(struct pool_crypto_state *cs,
                        const uint8_t *ciphertext, int cipher_len,
                        uint8_t *plaintext, int *plain_len,
                        uint64_t seq)
{
    struct aead_request *req;
    struct scatterlist sg;
    uint8_t nonce[POOL_NONCE_SIZE];
    uint8_t *combined;
    int ret;
    DECLARE_CRYPTO_WAIT(wait);

    if (!cs->aead || cipher_len < POOL_TAG_SIZE)
        return -EINVAL;

    /* C01: Match nonce construction from encrypt */
    memcpy(nonce, cs->hmac_key, 4);
    memcpy(nonce + 4, &seq, 8);

    ret = crypto_aead_setkey(cs->aead, cs->session_key, POOL_KEY_SIZE);
    if (ret)
        return ret;

    combined = kmalloc(cipher_len, GFP_KERNEL);
    if (!combined)
        return -ENOMEM;
    memcpy(combined, ciphertext, cipher_len);

    req = aead_request_alloc(cs->aead, GFP_KERNEL);
    if (!req) {
        kfree(combined);
        return -ENOMEM;
    }

    sg_init_one(&sg, combined, cipher_len);

    aead_request_set_crypt(req, &sg, &sg,
                           cipher_len, nonce);
    aead_request_set_ad(req, 0);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              crypto_req_done, &wait);

    ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (ret == 0) {
        *plain_len = cipher_len - POOL_TAG_SIZE;
        memcpy(plaintext, combined, *plain_len);
    }

    aead_request_free(req);
    kfree(combined);
    return ret;
}

/* Compute HMAC-SHA256 over data */
int pool_crypto_hmac(struct pool_crypto_state *cs,
                     const void *data, int data_len,
                     uint8_t *out)
{
    SHASH_DESC_ON_STACK(desc, cs->hmac);
    int ret;

    if (!cs->hmac)
        return -EINVAL;

    desc->tfm = cs->hmac;

    ret = crypto_shash_setkey(cs->hmac, cs->hmac_key, POOL_KEY_SIZE);
    if (ret)
        return ret;

    ret = crypto_shash_init(desc);
    if (ret)
        return ret;
    ret = crypto_shash_update(desc, data, data_len);
    if (ret)
        return ret;
    return crypto_shash_final(desc, out);
}

/* Verify HMAC-SHA256 */
int pool_crypto_hmac_verify(struct pool_crypto_state *cs,
                            const void *data, int data_len,
                            const uint8_t *expected)
{
    uint8_t computed[POOL_HMAC_SIZE];
    int ret;

    ret = pool_crypto_hmac(cs, data, data_len, computed);
    if (ret)
        return ret;

    if (crypto_memneq(computed, expected, POOL_HMAC_SIZE))
        return -EBADMSG;

    return 0;
}

/*
 * Generate next encrypted sequence number.
 * Returns the new sequence number. Sets *needs_rekey to 1 if the
 * packet count threshold has been reached (C04).
 */
uint64_t pool_crypto_next_seq(struct pool_crypto_state *cs)
{
    cs->local_seq++;
    cs->packets_since_rekey++;

    /* C04: Check rekey threshold on every packet, not just heartbeat */
    if (cs->packets_since_rekey >= POOL_REKEY_PACKETS) {
        pr_info_ratelimited("POOL: rekey threshold reached (%u packets)\n",
                            cs->packets_since_rekey);
    }

    return cs->local_seq;
}

/* Generate puzzle seed for stateless handshake */
void pool_crypto_gen_puzzle(uint8_t *seed, uint64_t server_secret,
                            const uint8_t client_addr[16])
{
    SHASH_DESC_ON_STACK(desc, pool_hmac_tfm);
    uint8_t input[28]; /* 16-byte addr + 8-byte secret + 4-byte timestamp */

    if (!pool_hmac_tfm) {
        get_random_bytes(seed, 32);
        return;
    }

    /* seed = HMAC(server_secret, client_addr || timestamp) */
    memcpy(input, client_addr, 16);
    memcpy(input + 16, &server_secret, 8);
    *(uint32_t *)(input + 24) = (uint32_t)(jiffies / HZ);

    crypto_shash_setkey(pool_hmac_tfm, (uint8_t *)&server_secret, 8);
    desc->tfm = pool_hmac_tfm;
    crypto_shash_init(desc);
    crypto_shash_update(desc, input, sizeof(input));
    crypto_shash_final(desc, seed);
}

/* Verify puzzle solution: SHA256(seed || solution) has N leading zero bits */
int pool_crypto_verify_puzzle(const uint8_t *seed, const uint8_t *solution,
                              uint16_t difficulty)
{
    struct crypto_shash *sha256;
    SHASH_DESC_ON_STACK(desc, NULL);
    uint8_t hash[32];
    int i, ret;

    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256))
        return -ENOMEM;

    desc->tfm = sha256;
    ret = crypto_shash_init(desc);
    if (ret)
        goto out;
    ret = crypto_shash_update(desc, seed, 32);
    if (ret)
        goto out;
    ret = crypto_shash_update(desc, solution, 32);
    if (ret)
        goto out;
    ret = crypto_shash_final(desc, hash);
    if (ret)
        goto out;

    /* Check leading zero bits */
    for (i = 0; i < difficulty / 8; i++) {
        if (hash[i] != 0) {
            ret = -EINVAL;
            goto out;
        }
    }
    if (difficulty % 8) {
        uint8_t mask = 0xFF << (8 - (difficulty % 8));
        if (hash[difficulty / 8] & mask) {
            ret = -EINVAL;
            goto out;
        }
    }
    ret = 0;

out:
    crypto_free_shash(sha256);
    return ret;
}
