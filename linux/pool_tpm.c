/*
 * pool_tpm.c - POOL software measurement chain (T3 TPM/PCR hook)
 *
 * Implements a software PCR (Platform Configuration Register) that
 * accumulates a rolling SHA-256 measurement of key module events.
 *
 * This is a *software measurement chain*, not a hardware TPM attestation.
 * It satisfies the T3 tenet requirement to "provide TPM/attestation hooks
 * even if hardware is not yet available". The PCR value can be read from
 * /proc/pool/tpm_pcr and compared against externally computed expected
 * values to detect runtime state tampering.
 *
 * Extension algorithm (TPM PCR Extend):
 *   pcr_new = SHA-256(pcr_old || measurement_data)
 *
 * This mirrors the TPM 2.0 PCR_Extend operation. If a real TPM is present,
 * these same measurements can be forwarded to hardware PCR indices.
 */

#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <crypto/hash.h>

#include "pool_internal.h"

static uint8_t pool_pcr[32];          /* Current PCR value (SHA-256 width) */
static uint32_t pool_pcr_extend_count; /* Number of extensions performed */
static DEFINE_MUTEX(pool_pcr_mutex);

int pool_tpm_init(void)
{
    mutex_lock(&pool_pcr_mutex);
    memset(pool_pcr, 0, sizeof(pool_pcr));
    pool_pcr_extend_count = 0;
    mutex_unlock(&pool_pcr_mutex);

    pr_info("POOL: software PCR initialized (T3 TPM hook)\n");
    return 0;
}

void pool_tpm_cleanup(void)
{
    mutex_lock(&pool_pcr_mutex);
    memset(pool_pcr, 0, sizeof(pool_pcr));
    pool_pcr_extend_count = 0;
    mutex_unlock(&pool_pcr_mutex);
}

/*
 * pool_tpm_extend - Extend the software PCR with new measurement data.
 * pcr_new = SHA-256(pcr_old || data)
 *
 * May sleep (allocates crypto transform). Must not be called from atomic
 * or interrupt context.
 */
void pool_tpm_extend(const uint8_t *data, size_t len)
{
    struct crypto_shash *sha256;
    SHASH_DESC_ON_STACK(desc, NULL);
    uint8_t new_pcr[32];
    uint8_t old_pcr[32];
    int ret;

    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256)) {
        pr_warn("POOL: TPM extend: sha256 alloc failed (%ld)\n",
                PTR_ERR(sha256));
        return;
    }

    mutex_lock(&pool_pcr_mutex);
    memcpy(old_pcr, pool_pcr, sizeof(old_pcr));
    mutex_unlock(&pool_pcr_mutex);

    desc->tfm = sha256;
    ret = crypto_shash_init(desc);
    if (ret)
        goto out;
    ret = crypto_shash_update(desc, old_pcr, sizeof(old_pcr));
    if (ret)
        goto out;
    if (data && len > 0) {
        ret = crypto_shash_update(desc, data, len);
        if (ret)
            goto out;
    }
    ret = crypto_shash_final(desc, new_pcr);
    if (ret)
        goto out;

    mutex_lock(&pool_pcr_mutex);
    memcpy(pool_pcr, new_pcr, sizeof(pool_pcr));
    pool_pcr_extend_count++;
    mutex_unlock(&pool_pcr_mutex);

out:
    crypto_free_shash(sha256);
}

/*
 * pool_tpm_get_pcr - Copy the current PCR value (thread-safe).
 * out must point to a 32-byte buffer.
 */
void pool_tpm_get_pcr(uint8_t out[32])
{
    mutex_lock(&pool_pcr_mutex);
    memcpy(out, pool_pcr, 32);
    mutex_unlock(&pool_pcr_mutex);
}

/*
 * pool_tpm_get_extend_count - Return number of PCR extensions performed.
 */
uint32_t pool_tpm_get_extend_count(void)
{
    uint32_t count;

    mutex_lock(&pool_pcr_mutex);
    count = pool_pcr_extend_count;
    mutex_unlock(&pool_pcr_mutex);
    return count;
}
