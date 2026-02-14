/*
 * pool_session.c - POOL session management
 *
 * Implements:
 *   - Stateless handshake (INIT/CHALLENGE/RESPONSE)
 *   - Session lifecycle (connect, accept, close)
 *   - Key rotation (REKEY)
 *   - Receiver thread per session
 */

#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/in.h>
#include <crypto/algapi.h>

#include "pool_internal.h"

/* ---- Init/cleanup ---- */

int pool_session_init(void)
{
    int i;
    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
        struct pool_session *s = &pool.sessions[i];
        memset(s, 0, sizeof(*s));
        mutex_init(&s->lock);
        mutex_init(&s->send_lock);
        mutex_init(&s->crypto_lock);
        spin_lock_init(&s->rx_lock);
        init_waitqueue_head(&s->rx_wait);
        INIT_LIST_HEAD(&s->rx_queue);
    }
    return 0;
}

void pool_session_cleanup(void)
{
    int i;
    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
        if (pool.sessions[i].active)
            pool_session_close(&pool.sessions[i]);
    }
}

/* ---- Session allocation ---- */

struct pool_session *pool_session_alloc(void)
{
    int i;
    mutex_lock(&pool.sessions_lock);
    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
        if (!pool.sessions[i].active) {
            pool.sessions[i].active = 1;
            pool.sessions[i].state = POOL_STATE_IDLE;
            mutex_unlock(&pool.sessions_lock);
            return &pool.sessions[i];
        }
    }
    mutex_unlock(&pool.sessions_lock);
    return NULL;
}

void pool_session_free(struct pool_session *sess)
{
    struct pool_rx_entry *entry, *tmp;

    if (sess->rx_thread) {
        kthread_stop(sess->rx_thread);
        sess->rx_thread = NULL;
    }

    if (sess->sock) {
        kernel_sock_shutdown(sess->sock, SHUT_RDWR);
        sock_release(sess->sock);
        sess->sock = NULL;
    }

    pool_crypto_cleanup_session(&sess->crypto);

    /* Drain RX queue */
    spin_lock(&sess->rx_lock);
    list_for_each_entry_safe(entry, tmp, &sess->rx_queue, list) {
        list_del(&entry->list);
        kfree(entry->data);
        kfree(entry);
    }
    spin_unlock(&sess->rx_lock);

    /* Free fragment buffers */
    {
        int i;
        for (i = 0; i < 4; i++) {
            kfree(sess->frags[i].data);
            sess->frags[i].data = NULL;
        }
    }

    sess->active = 0;
    sess->state = POOL_STATE_IDLE;
    sess->bytes_sent = 0;
    sess->bytes_recv = 0;
    sess->packets_sent = 0;
    sess->packets_recv = 0;
    memset(&sess->telemetry, 0, sizeof(sess->telemetry));
}

/* ---- Receiver thread ---- */

static int pool_rx_thread_fn(void *data)
{
    struct pool_session *sess = data;
    struct pool_header hdr;
    uint8_t *payload;
    int plen;
    int ret;
    uint8_t pkt_type;

    payload = kmalloc(POOL_MAX_PAYLOAD + POOL_TAG_SIZE, GFP_KERNEL);
    if (!payload)
        return -ENOMEM;

    while (!kthread_should_stop() && sess->active) {
        plen = POOL_MAX_PAYLOAD + POOL_TAG_SIZE;
        ret = pool_net_recv_packet(sess, &hdr, payload, &plen);
        if (ret < 0) {
            if (ret == -EAGAIN || ret == -EINTR)
                continue;
            if (kthread_should_stop())
                break;
            pr_warn("POOL: recv error %d, closing session\n", ret);
            break;
        }

        pkt_type = hdr.ver_type & 0x0F;

        switch (pkt_type) {
        case POOL_PKT_DATA: {
            /* Queue data for userspace recv */
            struct pool_rx_entry *entry;
            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
            if (!entry)
                break;
            entry->data = kmalloc(plen, GFP_KERNEL);
            if (!entry->data) {
                kfree(entry);
                break;
            }
            memcpy(entry->data, payload, plen);
            entry->len = plen;
            entry->channel = hdr.channel;

            spin_lock(&sess->rx_lock);
            list_add_tail(&entry->list, &sess->rx_queue);
            spin_unlock(&sess->rx_lock);
            wake_up_interruptible(&sess->rx_wait);
            break;
        }
        case POOL_PKT_ACK:
            /* ACK already processed in recv_packet (RTT update) */
            break;

        case POOL_PKT_HEARTBEAT: {
            /* Update peer telemetry */
            if (plen >= sizeof(struct pool_telemetry)) {
                struct pool_telemetry *t = (struct pool_telemetry *)payload;
                sess->telemetry.rtt_ns = t->rtt_ns;
                sess->telemetry.jitter_ns = t->jitter_ns;
                sess->telemetry.loss_rate_ppm = t->loss_rate_ppm;
            }
            sess->last_heartbeat = ktime_get_ns();
            /* Send ACK back */
            pool_net_send_packet(sess, POOL_PKT_ACK, 0, 0, NULL, 0);
            break;
        }
        case POOL_PKT_REKEY: {
            /* Peer wants to rekey - accept new key material */
            if (plen >= POOL_KEY_SIZE) {
                memcpy(sess->crypto.remote_pubkey, payload, POOL_KEY_SIZE);
                pool_crypto_ecdh(sess->crypto.local_privkey,
                                 sess->crypto.remote_pubkey,
                                 sess->crypto.shared_secret);
                pool_crypto_derive_keys(&sess->crypto);
                /* Set session key on AEAD */
                if (sess->crypto.aead)
                    crypto_aead_setkey(sess->crypto.aead,
                                      sess->crypto.session_key,
                                      POOL_KEY_SIZE);
                pr_info("POOL: rekey completed (initiated by peer)\n");
                pool_journal_add(POOL_JOURNAL_REKEY, 0, 0, "peer", 4);
            }
            break;
        }
        case POOL_PKT_CLOSE:
            pr_info("POOL: peer sent CLOSE\n");
            pool_journal_add(POOL_JOURNAL_DISCONNECT, 0, 0, "peer-close", 10);
            sess->state = POOL_STATE_CLOSING;
            break;

        default:
            pr_debug("POOL: unhandled packet type %d\n", pkt_type);
        }

        if (sess->state == POOL_STATE_CLOSING)
            break;
    }

    kfree(payload);
    return 0;
}

/* ---- Client-initiated handshake (INIT → CHALLENGE → RESPONSE) ---- */

int pool_session_connect(uint32_t ip, uint16_t port)
{
    struct pool_session *sess;
    struct pool_init_payload init_pl;
    struct pool_challenge_payload chal_pl;
    struct pool_response_payload resp_pl;
    struct pool_header hdr;
    uint8_t payload_buf[256];
    int plen, ret;
    int sess_idx;

    sess = pool_session_alloc();
    if (!sess)
        return -ENOMEM;

    sess_idx = sess - pool.sessions;

    ret = pool_crypto_init_session(&sess->crypto);
    if (ret) {
        pool_session_free(sess);
        return ret;
    }

    /* Generate ephemeral keypair */
    pool_crypto_gen_keypair(sess->crypto.local_privkey,
                            sess->crypto.local_pubkey);

    /* TCP connect */
    ret = pool_net_connect(sess, ip, port);
    if (ret) {
        pool_session_free(sess);
        return ret;
    }

    /* Send INIT (plaintext, no encryption yet) */
    memcpy(init_pl.client_pubkey, sess->crypto.local_pubkey, POOL_KEY_SIZE);
    memcpy(init_pl.client_addr, &pool.node_addr, POOL_ADDR_SIZE);
    sess->state = POOL_STATE_INIT_SENT;

    ret = pool_net_send_packet(sess, POOL_PKT_INIT, 0, 0,
                               &init_pl, sizeof(init_pl));
    if (ret) {
        pool_session_free(sess);
        return ret;
    }

    /* Receive CHALLENGE */
    plen = sizeof(payload_buf);
    ret = pool_net_recv_packet(sess, &hdr, payload_buf, &plen);
    if (ret || (hdr.ver_type & 0x0F) != POOL_PKT_CHALLENGE) {
        pr_err("POOL: expected CHALLENGE, got type %d (ret=%d)\n",
               hdr.ver_type & 0x0F, ret);
        pool_session_free(sess);
        return ret ? ret : -EPROTO;
    }

    if (plen < sizeof(chal_pl)) {
        pool_session_free(sess);
        return -EPROTO;
    }
    memcpy(&chal_pl, payload_buf, sizeof(chal_pl));

    /* Save session ID from challenge */
    memcpy(sess->session_id, hdr.session_id, POOL_SESSION_ID_SIZE);
    sess->state = POOL_STATE_CHALLENGED;

    /* Perform ECDH key agreement */
    memcpy(sess->crypto.remote_pubkey, chal_pl.server_pubkey, POOL_KEY_SIZE);
    ret = pool_crypto_ecdh(sess->crypto.local_privkey,
                           sess->crypto.remote_pubkey,
                           sess->crypto.shared_secret);
    if (ret) {
        pool_session_free(sess);
        return ret;
    }

    /* Derive session keys */
    ret = pool_crypto_derive_keys(&sess->crypto);
    if (ret) {
        pool_session_free(sess);
        return ret;
    }

    /* Set keys on crypto transforms */
    if (sess->crypto.aead)
        crypto_aead_setkey(sess->crypto.aead,
                           sess->crypto.session_key, POOL_KEY_SIZE);
    if (sess->crypto.hmac)
        crypto_shash_setkey(sess->crypto.hmac,
                            sess->crypto.hmac_key, POOL_KEY_SIZE);

    /* Solve puzzle (simplified: find solution where SHA256(seed||solution) has
       leading zero bits) */
    {
        uint8_t solution[32];
        uint64_t attempt = 0;
        struct crypto_shash *sha;
        SHASH_DESC_ON_STACK(desc, NULL);
        uint8_t hash[32];
        uint16_t diff;
        int ok, i;
        uint8_t mask;

        sha = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(sha)) {
            pool_session_free(sess);
            return PTR_ERR(sha);
        }

        desc->tfm = sha;
        memset(solution, 0, 32);
        diff = be16_to_cpu(chal_pl.puzzle_difficulty);

        while (attempt < 1000000) {
            memcpy(solution, &attempt, sizeof(attempt));
            crypto_shash_init(desc);
            crypto_shash_update(desc, chal_pl.puzzle_seed, 32);
            crypto_shash_update(desc, solution, 32);
            crypto_shash_final(desc, hash);

            ok = 1;
            for (i = 0; i < diff / 8 && ok; i++)
                if (hash[i] != 0) ok = 0;
            if (ok && (diff % 8)) {
                mask = 0xFF << (8 - (diff % 8));
                if (hash[diff / 8] & mask) ok = 0;
            }
            if (ok)
                break;
            attempt++;
        }
        crypto_free_shash(sha);

        memcpy(resp_pl.puzzle_solution, solution, 32);
    }

    /* Compute proof = HMAC(shared_secret, session_id) */
    {
        SHASH_DESC_ON_STACK(desc, sess->crypto.hmac);
        if (sess->crypto.hmac) {
            crypto_shash_setkey(sess->crypto.hmac,
                                sess->crypto.shared_secret, POOL_KEY_SIZE);
            desc->tfm = sess->crypto.hmac;
            crypto_shash_init(desc);
            crypto_shash_update(desc, sess->session_id, POOL_SESSION_ID_SIZE);
            crypto_shash_final(desc, resp_pl.proof);
            /* Reset HMAC key back to hmac_key */
            crypto_shash_setkey(sess->crypto.hmac,
                                sess->crypto.hmac_key, POOL_KEY_SIZE);
        }
    }

    /* Now we consider ourselves established so RESPONSE will be encrypted+HMAC'd */
    sess->state = POOL_STATE_ESTABLISHED;
    sess->connect_time = ktime_get_ns();
    sess->telemetry.mtu_current = POOL_DEFAULT_MTU;

    ret = pool_net_send_packet(sess, POOL_PKT_RESPONSE,
                               POOL_FLAG_ENCRYPTED | POOL_FLAG_REQUIRE_ACK,
                               0, &resp_pl, sizeof(resp_pl));
    if (ret) {
        pool_session_free(sess);
        return ret;
    }

    /* Wait for ACK or first DATA */
    plen = sizeof(payload_buf);
    ret = pool_net_recv_packet(sess, &hdr, payload_buf, &plen);
    if (ret) {
        pr_err("POOL: handshake completion failed: %d\n", ret);
        pool_session_free(sess);
        return ret;
    }

    /* Start receiver thread */
    sess->rx_thread = kthread_run(pool_rx_thread_fn, sess,
                                  "pool_rx_%d", sess_idx);
    if (IS_ERR(sess->rx_thread)) {
        sess->rx_thread = NULL;
        pool_session_free(sess);
        return -ENOMEM;
    }

    pr_info("POOL: session %d established to %pI4h:%d\n",
            sess_idx, &ip, port);
    pool_journal_add(POOL_JOURNAL_CONNECT, 0, 0, "connect", 7);

    return sess_idx;
}

/* ---- Server-side accept (receives INIT, sends CHALLENGE, verifies RESPONSE) ---- */

int pool_session_accept(struct socket *client_sock)
{
    struct pool_session *sess;
    struct pool_init_payload init_pl;
    struct pool_challenge_payload chal_pl;
    struct pool_response_payload resp_pl;
    struct pool_header hdr;
    uint8_t payload_buf[256];
    int plen, ret;
    int sess_idx;

    sess = pool_session_alloc();
    if (!sess)
        return -ENOMEM;

    sess_idx = sess - pool.sessions;
    sess->sock = client_sock;

    ret = pool_crypto_init_session(&sess->crypto);
    if (ret) {
        sess->sock = NULL;
        pool_session_free(sess);
        return ret;
    }

    /* Generate ephemeral keypair for this session */
    pool_crypto_gen_keypair(sess->crypto.local_privkey,
                            sess->crypto.local_pubkey);

    /* Receive INIT (stateless: we allocate no persistent state until verified) */
    plen = sizeof(payload_buf);
    ret = pool_net_recv_packet(sess, &hdr, payload_buf, &plen);
    if (ret || (hdr.ver_type & 0x0F) != POOL_PKT_INIT) {
        pr_warn("POOL: expected INIT, got %d\n", hdr.ver_type & 0x0F);
        sess->sock = NULL;
        pool_session_free(sess);
        return -EPROTO;
    }

    if (plen < sizeof(init_pl)) {
        sess->sock = NULL;
        pool_session_free(sess);
        return -EPROTO;
    }
    memcpy(&init_pl, payload_buf, sizeof(init_pl));
    memcpy(sess->crypto.remote_pubkey, init_pl.client_pubkey, POOL_KEY_SIZE);

    /* Generate session ID */
    get_random_bytes(sess->session_id, POOL_SESSION_ID_SIZE);

    /* Generate puzzle (stateless: derived from client IP + rotating secret) */
    get_random_bytes(&sess->server_secret, sizeof(sess->server_secret));
    pool_crypto_gen_puzzle(chal_pl.puzzle_seed, sess->server_secret,
                           sess->peer_ip);
    chal_pl.puzzle_difficulty = cpu_to_be16(POOL_PUZZLE_DIFFICULTY);
    memcpy(chal_pl.server_pubkey, sess->crypto.local_pubkey, POOL_KEY_SIZE);
    memcpy(chal_pl.server_addr, &pool.node_addr, POOL_ADDR_SIZE);

    /* Send CHALLENGE */
    ret = pool_net_send_packet(sess, POOL_PKT_CHALLENGE, 0, 0,
                               &chal_pl, sizeof(chal_pl));
    if (ret) {
        sess->sock = NULL;
        pool_session_free(sess);
        return ret;
    }

    /* Perform ECDH */
    ret = pool_crypto_ecdh(sess->crypto.local_privkey,
                           sess->crypto.remote_pubkey,
                           sess->crypto.shared_secret);
    if (ret) {
        sess->sock = NULL;
        pool_session_free(sess);
        return ret;
    }

    /* Derive keys */
    ret = pool_crypto_derive_keys(&sess->crypto);
    if (ret) {
        sess->sock = NULL;
        pool_session_free(sess);
        return ret;
    }

    /* Set keys */
    if (sess->crypto.aead)
        crypto_aead_setkey(sess->crypto.aead,
                           sess->crypto.session_key, POOL_KEY_SIZE);
    if (sess->crypto.hmac)
        crypto_shash_setkey(sess->crypto.hmac,
                            sess->crypto.hmac_key, POOL_KEY_SIZE);

    /* Now mark as established so we can decrypt the RESPONSE */
    sess->state = POOL_STATE_ESTABLISHED;
    sess->connect_time = ktime_get_ns();
    sess->telemetry.mtu_current = POOL_DEFAULT_MTU;

    /* Receive RESPONSE */
    plen = sizeof(payload_buf);
    ret = pool_net_recv_packet(sess, &hdr, payload_buf, &plen);
    if (ret || (hdr.ver_type & 0x0F) != POOL_PKT_RESPONSE) {
        pr_warn("POOL: expected RESPONSE, got %d (ret=%d)\n",
                hdr.ver_type & 0x0F, ret);
        sess->sock = NULL;
        pool_session_free(sess);
        return -EPROTO;
    }

    if (plen < sizeof(resp_pl)) {
        sess->sock = NULL;
        pool_session_free(sess);
        return -EPROTO;
    }
    memcpy(&resp_pl, payload_buf, sizeof(resp_pl));

    /* Verify puzzle solution */
    ret = pool_crypto_verify_puzzle(chal_pl.puzzle_seed,
                                    resp_pl.puzzle_solution,
                                    POOL_PUZZLE_DIFFICULTY);
    if (ret) {
        pr_warn("POOL: puzzle verification failed\n");
        sess->sock = NULL;
        pool_session_free(sess);
        return -EACCES;
    }

    /* Verify proof = HMAC(shared_secret, session_id) */
    {
        uint8_t expected_proof[POOL_HMAC_SIZE];
        SHASH_DESC_ON_STACK(desc, sess->crypto.hmac);
        if (sess->crypto.hmac) {
            crypto_shash_setkey(sess->crypto.hmac,
                                sess->crypto.shared_secret, POOL_KEY_SIZE);
            desc->tfm = sess->crypto.hmac;
            crypto_shash_init(desc);
            crypto_shash_update(desc, sess->session_id, POOL_SESSION_ID_SIZE);
            crypto_shash_final(desc, expected_proof);
            /* Reset key */
            crypto_shash_setkey(sess->crypto.hmac,
                                sess->crypto.hmac_key, POOL_KEY_SIZE);

            if (crypto_memneq(expected_proof, resp_pl.proof, POOL_HMAC_SIZE)) {
                pr_warn("POOL: proof verification failed\n");
                sess->sock = NULL;
                pool_session_free(sess);
                return -EACCES;
            }
        }
    }

    /* Send ACK to complete handshake */
    ret = pool_net_send_packet(sess, POOL_PKT_ACK, 0, 0, NULL, 0);
    if (ret) {
        sess->sock = NULL;
        pool_session_free(sess);
        return ret;
    }

    /* Start receiver thread */
    sess->rx_thread = kthread_run(pool_rx_thread_fn, sess,
                                  "pool_rx_%d", sess_idx);
    if (IS_ERR(sess->rx_thread)) {
        sess->rx_thread = NULL;
        sess->sock = NULL;
        pool_session_free(sess);
        return -ENOMEM;
    }

    /* Determine peer IP from socket */
    {
        struct sockaddr_in peer_addr;
        if (kernel_getpeername(client_sock,
                               (struct sockaddr *)&peer_addr) == 0) {
            sess->peer_ip = ntohl(peer_addr.sin_addr.s_addr);
            sess->peer_port = ntohs(peer_addr.sin_port);
        }
    }

    pr_info("POOL: session %d accepted from %pI4h:%d\n",
            sess_idx, &sess->peer_ip, sess->peer_port);
    pool_journal_add(POOL_JOURNAL_CONNECT, 0, 0, "accept", 6);

    return sess_idx;
}

/* ---- Close ---- */

void pool_session_close(struct pool_session *sess)
{
    if (!sess->active)
        return;

    mutex_lock(&sess->lock);
    if (sess->state == POOL_STATE_ESTABLISHED) {
        /* Send CLOSE packet (best effort) */
        pool_net_send_packet(sess, POOL_PKT_CLOSE, 0, 0, NULL, 0);
        pool_journal_add(POOL_JOURNAL_DISCONNECT, 0, 0, "close", 5);
    }

    pool_session_free(sess);
    mutex_unlock(&sess->lock);
}

/* ---- Rekey ---- */

int pool_session_rekey(struct pool_session *sess)
{
    uint8_t new_priv[POOL_KEY_SIZE], new_pub[POOL_KEY_SIZE];
    int ret;

    if (sess->state != POOL_STATE_ESTABLISHED)
        return -EINVAL;

    /* Generate new ephemeral keypair */
    pool_crypto_gen_keypair(new_priv, new_pub);

    /* Send our new public key */
    ret = pool_net_send_packet(sess, POOL_PKT_REKEY, 0, 0,
                               new_pub, POOL_KEY_SIZE);
    if (ret)
        return ret;

    /* Update local private key */
    memcpy(sess->crypto.local_privkey, new_priv, POOL_KEY_SIZE);
    memcpy(sess->crypto.local_pubkey, new_pub, POOL_KEY_SIZE);

    /* Note: the actual shared secret update happens when peer responds
       with their new key. For now we just mark the rekey as initiated. */
    sess->crypto.packets_since_rekey = 0;
    sess->crypto.last_rekey_jiffies = jiffies;

    pr_info("POOL: rekey initiated\n");
    pool_journal_add(POOL_JOURNAL_REKEY, 0, 0, "initiate", 8);

    return 0;
}
