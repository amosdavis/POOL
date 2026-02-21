/*
 * pool_journal.c - POOL change journal (audit trail)
 *
 * Append-only journal of all state changes for compliance
 * and forensic analysis.
 */

#include <linux/slab.h>
#include <linux/time.h>
#include <crypto/hash.h>

#include "pool_internal.h"

#define POOL_JOURNAL_MAX 1024

int pool_journal_init(void)
{
    pool.journal = kzalloc(sizeof(struct pool_journal_entry) * POOL_JOURNAL_MAX,
                           GFP_KERNEL);
    if (!pool.journal)
        return -ENOMEM;
    pool.journal_count = 0;
    pool.journal_max = POOL_JOURNAL_MAX;
    mutex_init(&pool.journal_lock);
    return 0;
}

void pool_journal_cleanup(void)
{
    kfree(pool.journal);
    pool.journal = NULL;
    pool.journal_count = 0;
}

void pool_journal_add(uint16_t change_type, uint32_t ver_before,
                      uint32_t ver_after, const void *detail, int detail_len)
{
    struct pool_journal_entry *e;
    struct crypto_shash *sha;
    SHASH_DESC_ON_STACK(desc, NULL);

    mutex_lock(&pool.journal_lock);

    if (pool.journal_count >= pool.journal_max) {
        /* Wrap around (overwrite oldest) */
        memmove(pool.journal, pool.journal + 1,
                sizeof(struct pool_journal_entry) * (pool.journal_max - 1));
        pool.journal_count = pool.journal_max - 1;
    }

    e = &pool.journal[pool.journal_count];
    e->timestamp = ktime_get_real_ns();
    e->config_ver_before = ver_before;
    e->config_ver_after = ver_after;
    e->change_type = change_type;
    e->detail_length = (detail_len > 0) ? detail_len : 0;

    /* Compute change hash (T5: Merkle chain — includes previous entry hash) */
    sha = crypto_alloc_shash("sha256", 0, 0);
    if (!IS_ERR(sha)) {
        desc->tfm = sha;
        crypto_shash_init(desc);
        if (pool.journal_count > 0)
            crypto_shash_update(desc,
                pool.journal[pool.journal_count - 1].change_hash, 32);
        crypto_shash_update(desc, (uint8_t *)&e->timestamp, 8);
        crypto_shash_update(desc, (uint8_t *)&change_type, 2);
        if (detail && detail_len > 0)
            crypto_shash_update(desc, detail, detail_len);
        crypto_shash_final(desc, e->change_hash);
        crypto_free_shash(sha);
    } else {
        memset(e->change_hash, 0, 32);
    }

    pool.journal_count++;
    mutex_unlock(&pool.journal_lock);
}
