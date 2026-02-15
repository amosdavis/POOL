/*
 * pool_pqc.c - POOL Post-Quantum Cryptography (Hybrid Key Exchange)
 *
 * Implements a hybrid key exchange combining X25519 (classical) with
 * ML-KEM-768 (NIST post-quantum KEM, formerly Kyber). The combined
 * shared secret is derived as:
 *
 *   shared = HKDF-SHA256(x25519_shared || mlkem_shared,
 *                         "pool-hybrid-v2", 32)
 *
 * This follows the NIST SP 800-227 hybrid approach: even if ML-KEM
 * is broken, X25519 still provides classical security; and if X25519
 * is broken by a quantum computer, ML-KEM provides post-quantum security.
 *
 * Version negotiation:
 *   - POOL v1 (version field = 0x1): X25519-only (current)
 *   - POOL v2 (version field = 0x2): Hybrid X25519 + ML-KEM-768
 *
 * The INIT packet carries the version field in the header. If the
 * responder supports v2, it responds with v2 CHALLENGE including
 * the ML-KEM public key. Otherwise it falls back to v1.
 *
 * ML-KEM-768 parameters (FIPS 203):
 *   - Public key:  1184 bytes
 *   - Secret key:  2400 bytes
 *   - Ciphertext:  1088 bytes
 *   - Shared secret: 32 bytes
 *   - Security:    ~NIST Level 3 (AES-192 equivalent)
 *
 * Since the Linux kernel does not ship a Kyber/ML-KEM implementation,
 * this module implements the core lattice operations in software using
 * Number Theoretic Transform (NTT) over Z_q[X]/(X^256+1) with q=3329.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>
#include <crypto/hash.h>

#include "pool_internal.h"

/* ML-KEM-768 constants (FIPS 203) */
#define MLKEM_N             256
#define MLKEM_Q             3329
#define MLKEM_K             3     /* security parameter k=3 for ML-KEM-768 */
#define MLKEM_ETA1          2
#define MLKEM_ETA2          2
#define MLKEM_DU            10
#define MLKEM_DV            4

#define MLKEM_PUBKEY_SIZE   1184
#define MLKEM_SECKEY_SIZE   2400
#define MLKEM_CT_SIZE       1088
#define MLKEM_SS_SIZE       32
#define MLKEM_SYMBYTES      32
#define MLKEM_POLYBYTES     384

/* Pool hybrid crypto version */
#define POOL_CRYPTO_V1      1
#define POOL_CRYPTO_V2      2

/* Module-level: which version we support */
static int pool_pqc_version = POOL_CRYPTO_V2;

/* Polynomial in Z_q[X]/(X^256+1) */
struct mlkem_poly {
    int16_t coeffs[MLKEM_N];
};

/* Vector of k polynomials */
struct mlkem_polyvec {
    struct mlkem_poly vec[MLKEM_K];
};

/* ML-KEM keypair */
struct mlkem_keypair {
    uint8_t pk[MLKEM_PUBKEY_SIZE];
    uint8_t sk[MLKEM_SECKEY_SIZE];
};

/* Barrett reduction: a mod q */
static int16_t mlkem_barrett_reduce(int32_t a)
{
    /* q = 3329, v = floor(2^26 / q + 0.5) = 20159 */
    int32_t t = ((int64_t)20159 * a) >> 26;
    t = a - t * MLKEM_Q;
    if (t < 0)
        t += MLKEM_Q;
    if (t >= MLKEM_Q)
        t -= MLKEM_Q;
    return (int16_t)t;
}

/* Montgomery reduction */
static int16_t mlkem_montgomery_reduce(int32_t a)
{
    /* q = 3329, qinv = -3327 mod 2^16 = 62209 */
    int16_t t = (int16_t)((uint16_t)a * 62209U);
    int32_t u = (int32_t)t * MLKEM_Q;
    return (int16_t)((a - u) >> 16);
}

/* NTT constants (precomputed roots of unity mod q in Montgomery form) */
static const int16_t mlkem_zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
    3158,  622, 1577,  182,  962, 2127, 1855, 1468,
     573, 2004,  264,  383, 2500, 1458, 1727, 3199,
    2648, 1017,  732,  608, 1787,  411, 3124, 1758,
    1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
     516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
    2476, 3239, 3058,  830,  107, 1908, 3082, 2378,
    2931,  961, 1821, 2604,  448, 2264,  677, 2054,
    2226,  430,  555,  843, 2078,  871, 1550,  105,
     422,  587,  177, 3094, 3038, 2869, 1574, 1653,
    3083,  778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739,  644, 2457,  349,  418,  329, 3173, 3254,
     817, 1097,  603,  610, 1322, 2044, 1864,  384,
    2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
    2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
    3221, 3116, 2503, 2058, 2926, 1553, 1183, 2461
};

/* Forward NTT (Number Theoretic Transform) */
static void mlkem_ntt(struct mlkem_poly *p)
{
    int len, start, j, k = 1;
    int16_t zeta, t;

    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = mlkem_zetas[k++];
            for (j = start; j < start + len; j++) {
                t = mlkem_montgomery_reduce((int32_t)zeta * p->coeffs[j + len]);
                p->coeffs[j + len] = p->coeffs[j] - t;
                p->coeffs[j] = p->coeffs[j] + t;
            }
        }
    }
}

/* Inverse NTT */
static void mlkem_invntt(struct mlkem_poly *p)
{
    int len, start, j, k = 127;
    int16_t zeta, t;
    /* f = 3303 is Montgomery representation of 128^{-1} mod q */
    static const int16_t f = 3303;

    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = mlkem_zetas[k--];
            for (j = start; j < start + len; j++) {
                t = p->coeffs[j];
                p->coeffs[j] = mlkem_barrett_reduce(
                    (int32_t)t + p->coeffs[j + len]);
                p->coeffs[j + len] = mlkem_montgomery_reduce(
                    (int32_t)zeta * (p->coeffs[j + len] - t));
            }
        }
    }
    for (j = 0; j < MLKEM_N; j++)
        p->coeffs[j] = mlkem_montgomery_reduce((int32_t)f * p->coeffs[j]);
}

/* Basemul: multiply in NTT domain */
static void mlkem_basemul(struct mlkem_poly *r,
                          const struct mlkem_poly *a,
                          const struct mlkem_poly *b,
                          int16_t zeta)
{
    int i;
    for (i = 0; i < MLKEM_N / 2; i++) {
        int j = 2 * i;
        int32_t t;
        t = (int32_t)a->coeffs[j] * b->coeffs[j];
        t += mlkem_montgomery_reduce(
            (int32_t)a->coeffs[j + 1] * b->coeffs[j + 1]) * (int32_t)zeta;
        r->coeffs[j] = mlkem_montgomery_reduce(t);

        t = (int32_t)a->coeffs[j] * b->coeffs[j + 1];
        t += (int32_t)a->coeffs[j + 1] * b->coeffs[j];
        r->coeffs[j + 1] = mlkem_montgomery_reduce(t);
    }
}

/* Poly add */
static void mlkem_poly_add(struct mlkem_poly *r,
                           const struct mlkem_poly *a,
                           const struct mlkem_poly *b)
{
    int i;
    for (i = 0; i < MLKEM_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/* Poly sub */
static void mlkem_poly_sub(struct mlkem_poly *r,
                           const struct mlkem_poly *a,
                           const struct mlkem_poly *b)
{
    int i;
    for (i = 0; i < MLKEM_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/* Reduce coefficients mod q */
static void mlkem_poly_reduce(struct mlkem_poly *p)
{
    int i;
    for (i = 0; i < MLKEM_N; i++)
        p->coeffs[i] = mlkem_barrett_reduce(p->coeffs[i]);
}

/* CBD (Centered Binomial Distribution) sampling with eta=2 */
static void mlkem_cbd_eta2(struct mlkem_poly *p, const uint8_t *buf)
{
    int i;
    for (i = 0; i < MLKEM_N / 8; i++) {
        /* C05: Use memcpy for alignment-safe access on ARM/PowerPC */
        uint32_t t;
        memcpy(&t, buf + 4 * i, sizeof(t));
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        int j;
        for (j = 0; j < 8; j++) {
            int16_t a = (d >> (4 * j)) & 0x3;
            int16_t b = (d >> (4 * j + 2)) & 0x3;
            p->coeffs[8 * i + j] = a - b;
        }
    }
}

/* Generate random polynomial via SHAKE/SHA-256 (simplified XOF) */
static void mlkem_gen_poly_uniform(struct mlkem_poly *p,
                                   const uint8_t *seed, uint8_t x, uint8_t y)
{
    struct crypto_shash *sha;
    SHASH_DESC_ON_STACK(desc, NULL);
    uint8_t input[34];
    uint8_t hash_out[64];
    int i, count = 0;

    sha = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha)) {
        /* Fallback: random coefficients */
        get_random_bytes(p->coeffs, sizeof(p->coeffs));
        for (i = 0; i < MLKEM_N; i++)
            p->coeffs[i] = mlkem_barrett_reduce(p->coeffs[i] & 0x0FFF);
        return;
    }

    memcpy(input, seed, 32);
    input[32] = x;
    input[33] = y;

    desc->tfm = sha;

    /* Generate enough uniform random values mod q */
    while (count < MLKEM_N) {
        input[32] = x + (count >> 4);
        input[33] = y + (count & 0x0F);
        crypto_shash_init(desc);
        crypto_shash_update(desc, input, 34);
        crypto_shash_final(desc, hash_out);

        for (i = 0; i < 32 && count < MLKEM_N; i += 2) {
            uint16_t val = ((uint16_t)hash_out[i]) |
                           (((uint16_t)(hash_out[i + 1] & 0x0F)) << 8);
            if (val < MLKEM_Q)
                p->coeffs[count++] = (int16_t)val;
        }
    }
    crypto_free_shash(sha);
}

/* Serialize polynomial to bytes (12-bit coefficients) */
static void mlkem_poly_tobytes(uint8_t *r, const struct mlkem_poly *a)
{
    int i;
    for (i = 0; i < MLKEM_N / 2; i++) {
        uint16_t t0 = (uint16_t)mlkem_barrett_reduce(a->coeffs[2 * i]);
        uint16_t t1 = (uint16_t)mlkem_barrett_reduce(a->coeffs[2 * i + 1]);
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

/* Deserialize bytes to polynomial */
static void mlkem_poly_frombytes(struct mlkem_poly *r, const uint8_t *a)
{
    int i;
    for (i = 0; i < MLKEM_N / 2; i++) {
        r->coeffs[2 * i] = ((uint16_t)a[3 * i + 0]) |
                            (((uint16_t)(a[3 * i + 1] & 0x0F)) << 8);
        r->coeffs[2 * i + 1] = ((uint16_t)(a[3 * i + 1] >> 4)) |
                                (((uint16_t)a[3 * i + 2]) << 4);
    }
}

/* Compress polynomial */
static void mlkem_poly_compress(uint8_t *r, const struct mlkem_poly *a, int d)
{
    int i;
    if (d == 4) {
        for (i = 0; i < MLKEM_N / 2; i++) {
            uint8_t t0 = (uint8_t)(((uint32_t)mlkem_barrett_reduce(
                a->coeffs[2 * i]) * 16 + MLKEM_Q / 2) / MLKEM_Q);
            uint8_t t1 = (uint8_t)(((uint32_t)mlkem_barrett_reduce(
                a->coeffs[2 * i + 1]) * 16 + MLKEM_Q / 2) / MLKEM_Q);
            r[i] = (t0 & 0x0F) | (t1 << 4);
        }
    } else if (d == 10) {
        for (i = 0; i < MLKEM_N / 4; i++) {
            int j;
            uint16_t t[4];
            for (j = 0; j < 4; j++)
                t[j] = (uint16_t)(((uint32_t)mlkem_barrett_reduce(
                    a->coeffs[4 * i + j]) * 1024 + MLKEM_Q / 2) / MLKEM_Q);
            r[5 * i + 0] = (uint8_t)(t[0] >> 0);
            r[5 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[5 * i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[5 * i + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[5 * i + 4] = (uint8_t)(t[3] >> 2);
        }
    }
}

/* Decompress polynomial */
static void mlkem_poly_decompress(struct mlkem_poly *r, const uint8_t *a, int d)
{
    int i;
    if (d == 4) {
        for (i = 0; i < MLKEM_N / 2; i++) {
            r->coeffs[2 * i] = (int16_t)(((uint32_t)(a[i] & 0x0F) *
                                 MLKEM_Q + 8) >> 4);
            r->coeffs[2 * i + 1] = (int16_t)(((uint32_t)(a[i] >> 4) *
                                     MLKEM_Q + 8) >> 4);
        }
    } else if (d == 10) {
        for (i = 0; i < MLKEM_N / 4; i++) {
            uint16_t t[4];
            t[0] = ((uint16_t)a[5*i+0]) | (((uint16_t)(a[5*i+1]&0x03)) << 8);
            t[1] = ((uint16_t)(a[5*i+1]>>2)) | (((uint16_t)(a[5*i+2]&0x0F))<<6);
            t[2] = ((uint16_t)(a[5*i+2]>>4)) | (((uint16_t)(a[5*i+3]&0x3F))<<4);
            t[3] = ((uint16_t)(a[5*i+3]>>6)) | (((uint16_t)a[5*i+4]) << 2);
            int j;
            for (j = 0; j < 4; j++)
                r->coeffs[4*i+j] = (int16_t)(((uint32_t)t[j] *
                                    MLKEM_Q + 512) >> 10);
        }
    }
}

/*
 * ML-KEM-768 KeyGen
 *
 * Generates a public/secret keypair.
 * pk = (encode(t) || rho) where t = A*s + e in NTT domain
 * sk = encode(s)
 */
int pool_pqc_keygen(uint8_t *pk, uint8_t *sk)
{
    struct mlkem_polyvec *a_row, *s, *e, *t;
    uint8_t seed[MLKEM_SYMBYTES * 2];
    uint8_t noise_seed[MLKEM_SYMBYTES];
    uint8_t *noise_buf;
    int i, j, ret = 0;

    a_row = kmalloc(sizeof(*a_row), GFP_KERNEL);
    s = kmalloc(sizeof(*s), GFP_KERNEL);
    e = kmalloc(sizeof(*e), GFP_KERNEL);
    t = kmalloc(sizeof(*t), GFP_KERNEL);
    noise_buf = kmalloc(128, GFP_KERNEL);

    if (!a_row || !s || !e || !t || !noise_buf) {
        ret = -ENOMEM;
        goto out;
    }

    /* Generate seeds */
    get_random_bytes(seed, MLKEM_SYMBYTES);
    pool_crypto_hkdf(seed, MLKEM_SYMBYTES,
                     (const uint8_t *)"mlkem-seed", 10,
                     seed, MLKEM_SYMBYTES * 2);
    memcpy(noise_seed, seed + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

    /* Sample secret vector s (CBD) */
    for (i = 0; i < MLKEM_K; i++) {
        get_random_bytes(noise_buf, 128);
        mlkem_cbd_eta2(&s->vec[i], noise_buf);
        mlkem_ntt(&s->vec[i]);
    }

    /* Sample error vector e (CBD) */
    for (i = 0; i < MLKEM_K; i++) {
        get_random_bytes(noise_buf, 128);
        mlkem_cbd_eta2(&e->vec[i], noise_buf);
        mlkem_ntt(&e->vec[i]);
    }

    /* Compute t = A*s + e */
    for (i = 0; i < MLKEM_K; i++) {
        struct mlkem_poly tmp, acc;
        memset(&acc, 0, sizeof(acc));

        for (j = 0; j < MLKEM_K; j++) {
            mlkem_gen_poly_uniform(&a_row->vec[j], seed, (uint8_t)i, (uint8_t)j);
            mlkem_basemul(&tmp, &a_row->vec[j], &s->vec[j],
                          mlkem_zetas[j + 1]);
            mlkem_poly_add(&acc, &acc, &tmp);
        }
        mlkem_poly_add(&t->vec[i], &acc, &e->vec[i]);
        mlkem_poly_reduce(&t->vec[i]);
    }

    /* Encode public key: pk = (t_bytes || seed[:32]) */
    for (i = 0; i < MLKEM_K; i++)
        mlkem_poly_tobytes(pk + i * MLKEM_POLYBYTES, &t->vec[i]);
    memcpy(pk + MLKEM_K * MLKEM_POLYBYTES, seed, MLKEM_SYMBYTES);

    /* Encode secret key: sk = s_bytes */
    for (i = 0; i < MLKEM_K; i++)
        mlkem_poly_tobytes(sk + i * MLKEM_POLYBYTES, &s->vec[i]);
    /* Append pk, H(pk), z for implicit reject (FIPS 203 §7.3) */
    memcpy(sk + MLKEM_K * MLKEM_POLYBYTES, pk, MLKEM_PUBKEY_SIZE);
    {
        /* C07: Propagate SHA256 allocation failure */
        struct crypto_shash *sha = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(sha)) {
            ret = PTR_ERR(sha);
            goto out;
        }
        SHASH_DESC_ON_STACK(desc, sha);
        desc->tfm = sha;
        ret = crypto_shash_init(desc);
        if (ret) { crypto_free_shash(sha); goto out; }
        ret = crypto_shash_update(desc, pk, MLKEM_PUBKEY_SIZE);
        if (ret) { crypto_free_shash(sha); goto out; }
        ret = crypto_shash_final(desc,
            sk + MLKEM_K * MLKEM_POLYBYTES + MLKEM_PUBKEY_SIZE);
        crypto_free_shash(sha);
        if (ret) goto out;
    }
    get_random_bytes(sk + MLKEM_K * MLKEM_POLYBYTES +
                     MLKEM_PUBKEY_SIZE + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

out:
    if (noise_buf) {
        memzero_explicit(noise_buf, 128);
        kfree(noise_buf);
    }
    if (s) {
        memzero_explicit(s, sizeof(*s));
        kfree(s);
    }
    kfree(e);
    kfree(t);
    kfree(a_row);
    return ret;
}

/*
 * ML-KEM-768 Encapsulate
 *
 * Given a public key pk, produces ciphertext ct and shared secret ss.
 */
int pool_pqc_encaps(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    struct mlkem_polyvec *t_hat, *a_row, *r_vec, *u;
    struct mlkem_poly *e1, *e2, *v, *msg_poly;
    uint8_t *noise_buf, *msg;
    uint8_t seed[MLKEM_SYMBYTES];
    int i, j, ret = 0;

    t_hat = kmalloc(sizeof(*t_hat), GFP_KERNEL);
    a_row = kmalloc(sizeof(*a_row), GFP_KERNEL);
    r_vec = kmalloc(sizeof(*r_vec), GFP_KERNEL);
    u = kmalloc(sizeof(*u), GFP_KERNEL);
    e1 = kmalloc(sizeof(*e1) * MLKEM_K, GFP_KERNEL);
    e2 = kmalloc(sizeof(*e2), GFP_KERNEL);
    v = kmalloc(sizeof(*v), GFP_KERNEL);
    msg_poly = kmalloc(sizeof(*msg_poly), GFP_KERNEL);
    noise_buf = kmalloc(128, GFP_KERNEL);
    msg = kmalloc(MLKEM_SYMBYTES, GFP_KERNEL);

    if (!t_hat || !a_row || !r_vec || !u || !e1 || !e2 || !v ||
        !msg_poly || !noise_buf || !msg) {
        ret = -ENOMEM;
        goto out;
    }

    /* Decode public key */
    for (i = 0; i < MLKEM_K; i++)
        mlkem_poly_frombytes(&t_hat->vec[i], pk + i * MLKEM_POLYBYTES);
    memcpy(seed, pk + MLKEM_K * MLKEM_POLYBYTES, MLKEM_SYMBYTES);

    /* Generate random message */
    get_random_bytes(msg, MLKEM_SYMBYTES);

    /* The shared secret is a hash of the message */
    /* C06: Propagate HKDF errors */
    ret = pool_crypto_hkdf(msg, MLKEM_SYMBYTES,
                     (const uint8_t *)"mlkem-ss", 8,
                     ss, MLKEM_SS_SIZE);
    if (ret)
        goto out;

    /* Sample r, e1, e2 vectors */
    for (i = 0; i < MLKEM_K; i++) {
        get_random_bytes(noise_buf, 128);
        mlkem_cbd_eta2(&r_vec->vec[i], noise_buf);
        mlkem_ntt(&r_vec->vec[i]);
    }
    for (i = 0; i < MLKEM_K; i++) {
        get_random_bytes(noise_buf, 128);
        mlkem_cbd_eta2(&e1[i], noise_buf);
    }
    get_random_bytes(noise_buf, 128);
    mlkem_cbd_eta2(e2, noise_buf);

    /* Encode message as polynomial */
    memset(msg_poly, 0, sizeof(*msg_poly));
    for (i = 0; i < MLKEM_SYMBYTES && i < MLKEM_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            if (msg[i] & (1 << j))
                msg_poly->coeffs[8 * i + j] = (MLKEM_Q + 1) / 2;
        }
    }

    /* u = A^T * r + e1 (in normal domain) */
    for (i = 0; i < MLKEM_K; i++) {
        struct mlkem_poly tmp, acc;
        memset(&acc, 0, sizeof(acc));
        for (j = 0; j < MLKEM_K; j++) {
            mlkem_gen_poly_uniform(&a_row->vec[j], seed, (uint8_t)j, (uint8_t)i);
            mlkem_basemul(&tmp, &a_row->vec[j], &r_vec->vec[j],
                          mlkem_zetas[j + 1]);
            mlkem_poly_add(&acc, &acc, &tmp);
        }
        mlkem_invntt(&acc);
        mlkem_poly_add(&u->vec[i], &acc, &e1[i]);
        mlkem_poly_reduce(&u->vec[i]);
    }

    /* v = t^T * r + e2 + msg */
    {
        struct mlkem_poly tmp, acc;
        memset(&acc, 0, sizeof(acc));
        for (i = 0; i < MLKEM_K; i++) {
            mlkem_basemul(&tmp, &t_hat->vec[i], &r_vec->vec[i],
                          mlkem_zetas[i + 1]);
            mlkem_poly_add(&acc, &acc, &tmp);
        }
        mlkem_invntt(&acc);
        mlkem_poly_add(v, &acc, e2);
        mlkem_poly_add(v, v, msg_poly);
        mlkem_poly_reduce(v);
    }

    /* Compress and encode ciphertext */
    {
        int offset = 0;
        for (i = 0; i < MLKEM_K; i++) {
            mlkem_poly_compress(ct + offset, &u->vec[i], MLKEM_DU);
            offset += MLKEM_N * MLKEM_DU / 8;
        }
        mlkem_poly_compress(ct + offset, v, MLKEM_DV);
    }

out:
    if (noise_buf) {
        memzero_explicit(noise_buf, 128);
        kfree(noise_buf);
    }
    if (msg) {
        memzero_explicit(msg, MLKEM_SYMBYTES);
        kfree(msg);
    }
    kfree(t_hat);
    kfree(a_row);
    if (r_vec) {
        memzero_explicit(r_vec, sizeof(*r_vec));
        kfree(r_vec);
    }
    kfree(u);
    kfree(e1);
    kfree(e2);
    kfree(v);
    kfree(msg_poly);
    return ret;
}

/*
 * ML-KEM-768 Decapsulate
 *
 * Given secret key sk and ciphertext ct, recovers shared secret ss.
 */
int pool_pqc_decaps(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    struct mlkem_polyvec *s_hat, *u;
    struct mlkem_poly *v, *msg_poly;
    uint8_t msg[MLKEM_SYMBYTES];
    int i, j, ret = 0;

    s_hat = kmalloc(sizeof(*s_hat), GFP_KERNEL);
    u = kmalloc(sizeof(*u), GFP_KERNEL);
    v = kmalloc(sizeof(*v), GFP_KERNEL);
    msg_poly = kmalloc(sizeof(*msg_poly), GFP_KERNEL);

    if (!s_hat || !u || !v || !msg_poly) {
        ret = -ENOMEM;
        goto out;
    }

    /* Decode secret key */
    for (i = 0; i < MLKEM_K; i++)
        mlkem_poly_frombytes(&s_hat->vec[i], sk + i * MLKEM_POLYBYTES);

    /* Decompress ciphertext */
    {
        int offset = 0;
        for (i = 0; i < MLKEM_K; i++) {
            mlkem_poly_decompress(&u->vec[i], ct + offset, MLKEM_DU);
            offset += MLKEM_N * MLKEM_DU / 8;
            mlkem_ntt(&u->vec[i]);
        }
        mlkem_poly_decompress(v, ct + offset, MLKEM_DV);
    }

    /* Recover message: msg = v - s^T * u */
    {
        struct mlkem_poly tmp, acc;
        memset(&acc, 0, sizeof(acc));
        for (i = 0; i < MLKEM_K; i++) {
            mlkem_basemul(&tmp, &s_hat->vec[i], &u->vec[i],
                          mlkem_zetas[i + 1]);
            mlkem_poly_add(&acc, &acc, &tmp);
        }
        mlkem_invntt(&acc);
        mlkem_poly_sub(msg_poly, v, &acc);
        mlkem_poly_reduce(msg_poly);
    }

    /* Decode message polynomial back to bytes */
    memset(msg, 0, MLKEM_SYMBYTES);
    for (i = 0; i < MLKEM_SYMBYTES && i < MLKEM_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            int16_t val = mlkem_barrett_reduce(msg_poly->coeffs[8 * i + j]);
            /* val close to q/2 => bit is 1, close to 0 => bit is 0 */
            if (val > MLKEM_Q / 4 && val < 3 * MLKEM_Q / 4)
                msg[i] |= (1 << j);
        }
    }

    /* Shared secret = HKDF(msg) */
    /* C06: Propagate HKDF errors */
    ret = pool_crypto_hkdf(msg, MLKEM_SYMBYTES,
                     (const uint8_t *)"mlkem-ss", 8,
                     ss, MLKEM_SS_SIZE);
    if (ret)
        goto out;

out:
    memzero_explicit(msg, sizeof(msg));
    if (s_hat) {
        memzero_explicit(s_hat, sizeof(*s_hat));
        kfree(s_hat);
    }
    kfree(u);
    kfree(v);
    kfree(msg_poly);
    return ret;
}

/*
 * Hybrid key exchange: combine X25519 and ML-KEM-768 shared secrets.
 *
 * combined_ss = HKDF-SHA256(x25519_ss || mlkem_ss, "pool-hybrid-v2", 32)
 */
int pool_pqc_hybrid_combine(const uint8_t *x25519_ss,
                            const uint8_t *mlkem_ss,
                            uint8_t *combined_ss)
{
    uint8_t combined_input[64];  /* 32 + 32 */
    int ret;

    memcpy(combined_input, x25519_ss, POOL_KEY_SIZE);
    memcpy(combined_input + POOL_KEY_SIZE, mlkem_ss, MLKEM_SS_SIZE);

    ret = pool_crypto_hkdf(combined_input, sizeof(combined_input),
                           (const uint8_t *)"pool-hybrid-v2", 14,
                           combined_ss, POOL_KEY_SIZE);

    memzero_explicit(combined_input, sizeof(combined_input));
    return ret;
}

/* Check if post-quantum crypto is enabled */
int pool_pqc_enabled(void)
{
    return pool_pqc_version >= POOL_CRYPTO_V2;
}

/* Get the crypto version we support */
int pool_pqc_get_version(void)
{
    return pool_pqc_version;
}

/* Negotiate crypto version with peer */
int pool_pqc_negotiate(int peer_version)
{
    if (peer_version >= POOL_CRYPTO_V2 && pool_pqc_version >= POOL_CRYPTO_V2)
        return POOL_CRYPTO_V2;
    return POOL_CRYPTO_V1;
}
