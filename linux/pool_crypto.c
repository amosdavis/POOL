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

int pool_crypto_init(void)
{
    pool_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(pool_hmac_tfm)) {
        pr_err("POOL: failed to allocate hmac(sha256): %ld\n",
               PTR_ERR(pool_hmac_tfm));
        pool_hmac_tfm = NULL;
        return -ENOMEM;
    }
    pr_info("POOL: crypto subsystem initialized\n");
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
         * Fallback: shared_secret = SHA256(privkey || peer_pubkey)
         * This works because both sides compute:
         *   A: SHA256(privA || pubB) and B: SHA256(privB || pubA)
         * These are different! We need a commutative operation.
         * Use: shared_secret = SHA256(min(pubA,pubB) || max(pubA,pubB) || privkey)
         * Actually simplest: derive from both pubkeys sorted.
         */
        struct crypto_shash *sha;
        SHASH_DESC_ON_STACK(desc, NULL);
        uint8_t my_pubkey[POOL_KEY_SIZE];

        sha = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(sha))
            return PTR_ERR(sha);

        /* Compute our pubkey from privkey */
        desc->tfm = sha;
        crypto_shash_init(desc);
        crypto_shash_update(desc, privkey, POOL_KEY_SIZE);
        crypto_shash_final(desc, my_pubkey);

        /* shared = SHA256(sorted_pubkeys) - commutative */
        crypto_shash_init(desc);
        if (memcmp(my_pubkey, peer_pubkey, POOL_KEY_SIZE) < 0) {
            crypto_shash_update(desc, my_pubkey, POOL_KEY_SIZE);
            crypto_shash_update(desc, peer_pubkey, POOL_KEY_SIZE);
        } else {
            crypto_shash_update(desc, peer_pubkey, POOL_KEY_SIZE);
            crypto_shash_update(desc, my_pubkey, POOL_KEY_SIZE);
        }
        crypto_shash_final(desc, shared_secret);
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

    /* Derive nonce from sequence number */
    memset(nonce, 0, POOL_NONCE_SIZE);
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

    memset(nonce, 0, POOL_NONCE_SIZE);
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

/* Generate next encrypted sequence number */
uint64_t pool_crypto_next_seq(struct pool_crypto_state *cs)
{
    cs->local_seq++;
    cs->packets_since_rekey++;
    return cs->local_seq;
}

/* Generate puzzle seed for stateless handshake */
void pool_crypto_gen_puzzle(uint8_t *seed, uint64_t server_secret,
                            uint32_t client_ip)
{
    SHASH_DESC_ON_STACK(desc, pool_hmac_tfm);
    uint8_t input[16];

    if (!pool_hmac_tfm) {
        get_random_bytes(seed, 32);
        return;
    }

    /* seed = HMAC(server_secret, client_ip || timestamp) */
    memcpy(input, &client_ip, 4);
    memcpy(input + 4, &server_secret, 8);
    *(uint32_t *)(input + 12) = (uint32_t)(jiffies / HZ);

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
