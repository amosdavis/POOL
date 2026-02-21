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
#include <linux/in6.h>
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
    pool.sessions_ready = 1;
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

    /* T8: Refuse new sessions when integrity is compromised (RT-*) */
    if (pool.integrity_compromised) {
        pr_crit("POOL: refusing new session — integrity compromised\n");
        return NULL;
    }

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
    pr_warn("POOL: session limit reached (%d)\n", POOL_MAX_SESSIONS);
    return NULL;
}

void pool_session_free(struct pool_session *sess)
{
    struct pool_rx_entry *entry, *tmp;

    /* Shut down socket FIRST to unblock any pending kernel_recvmsg
     * in the rx_thread before attempting to stop it. */
    if (sess->sock) {
        kernel_sock_shutdown(sess->sock, SHUT_RDWR);
    }

    if (sess->rx_thread) {
        kthread_stop(sess->rx_thread);
        sess->rx_thread = NULL;
    }

    if (sess->sock) {
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

    /* S02: Free fragment buffers under rx_lock to prevent races
     * with concurrent fragment reassembly in rx_thread */
    spin_lock(&sess->rx_lock);
    {
        int i;
        for (i = 0; i < ARRAY_SIZE(sess->frags); i++) {
            kfree(sess->frags[i].data);
            sess->frags[i].data = NULL;
        }
    }
    spin_unlock(&sess->rx_lock);

    sess->active = 0;
    sess->state = POOL_STATE_IDLE;
    sess->transport = POOL_TRANSPORT_TCP;  /* default, overridden for raw */
    sess->bytes_sent = 0;
    sess->bytes_recv = 0;
    sess->packets_sent = 0;
    sess->packets_recv = 0;
    sess->expected_remote_seq = 0;
    sess->packets_lost = 0;
    memset(&sess->telemetry, 0, sizeof(sess->telemetry));
    pool_mtu_init_session(sess);
    memset(sess->channel_subs, 0, sizeof(sess->channel_subs));
    sess->channel_subs[0] = 0x01;  /* subscribe to channel 0 by default */
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
            uint16_t pkt_flags = be16_to_cpu(hdr.flags);

            if (pkt_flags & POOL_FLAG_FRAGMENT) {
                /* Fragmented packet — accumulate and reassemble */
                uint8_t *assembled_data = NULL;
                uint32_t assembled_len = 0;
                uint8_t assembled_channel = 0;
                int fret;

                fret = pool_data_handle_fragment(sess, payload, plen,
                                                  pkt_flags, hdr.channel,
                                                  &assembled_data,
                                                  &assembled_len,
                                                  &assembled_channel);
                if (fret == 1) {
                    /* Reassembly complete — queue for userspace */
                    struct pool_rx_entry *entry;
                    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
                    if (!entry) {
                        kfree(assembled_data);
                        break;
                    }
                    entry->data = assembled_data;
                    entry->len = assembled_len;
                    entry->channel = assembled_channel;

                    spin_lock(&sess->rx_lock);
                    list_add_tail(&entry->list, &sess->rx_queue);
                    spin_unlock(&sess->rx_lock);
                    wake_up_interruptible(&sess->rx_wait);

                    pool_telemetry_record_recv(sess, assembled_len);
                } else if (fret < 0) {
                    pr_warn("POOL: fragment handling error %d\n", fret);
                }
                /* fret == 0 means more fragments needed, nothing to queue */
            } else {
                /* Non-fragmented packet — queue directly */
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
            }
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

        case POOL_PKT_DISCOVER:
            if (be16_to_cpu(hdr.flags) & POOL_FLAG_TELEMETRY)
                pool_discover_handle_exchange(sess, payload, plen);
            else
                pool_mtu_handle_discover(sess, payload, plen,
                                         be16_to_cpu(hdr.flags));
            break;

        case POOL_PKT_CONFIG:
            pool_config_handle_config(sess, payload, plen);
            break;

        case POOL_PKT_ROLLBACK:
            pool_config_handle_rollback(sess, payload, plen);
            break;

        case POOL_PKT_INTEGRITY: {
            /*
             * T2/T4: Peer crypto challenge-response (RT-C02, RT-C04).
             * If we receive a 16-byte challenge, encrypt it with session
             * key and return it. If we receive a 32-byte response (16
             * nonce + 16 tag), verify against our pending challenge.
             */
            if (plen == 16) {
                /* Incoming challenge: encrypt nonce and return */
                uint8_t response[16 + POOL_TAG_SIZE];
                int resp_len = 0;
                int rc;

                mutex_lock(&sess->crypto_lock);
                rc = pool_crypto_encrypt(&sess->crypto,
                                          payload, 16,
                                          response, &resp_len,
                                          sess->crypto.local_seq);
                mutex_unlock(&sess->crypto_lock);
                if (!rc) {
                    pool_net_send_packet(sess, POOL_PKT_INTEGRITY,
                                         POOL_FLAG_REQUIRE_ACK, 0,
                                         response, resp_len);
                }
            } else if (plen > 16 && sess->integrity_challenge_pending) {
                /* Incoming response: decrypt and verify */
                uint8_t decrypted[16];
                int dec_len = 0;
                int rc;

                mutex_lock(&sess->crypto_lock);
                rc = pool_crypto_decrypt(&sess->crypto,
                                          payload, plen,
                                          decrypted, &dec_len,
                                          sess->crypto.remote_seq);
                mutex_unlock(&sess->crypto_lock);
                sess->integrity_challenge_pending = 0;
                if (rc || dec_len != 16 ||
                    crypto_memneq(decrypted, sess->integrity_challenge, 16)) {
                    pr_crit("POOL: peer integrity challenge failed — "
                            "crypto behavior mismatch\n");
                    pool.integrity_compromised = 1;
                }
            }
            break;
        }

        default:
            pr_debug("POOL: unhandled packet type %d\n", pkt_type);
        }

        if (sess->state == POOL_STATE_CLOSING)
            break;

        /* Expire stale fragment reassembly buffers (5 second timeout) */
        {
            int fi;
            for (fi = 0; fi < ARRAY_SIZE(sess->frags); fi++) {
                struct pool_frag_buf *fb = &sess->frags[fi];
                if (fb->data && !fb->complete &&
                    time_after(jiffies,
                               fb->start_jiffies + msecs_to_jiffies(5000))) {
                    pr_warn("POOL: fragment timeout msg_id=%u slot=%d "
                            "(received %u/%u bytes)\n",
                            fb->msg_id, fi, fb->received, fb->total_len);
                    kfree(fb->data);
                    memset(fb, 0, sizeof(*fb));
                }
            }
        }

        /* MTU probe timeout and periodic re-probing */
        pool_mtu_probe_timeout(sess);
        if (!sess->mtu_probing && sess->mtu_last_probe > 0) {
            uint64_t now = ktime_get_ns();
            if (now - sess->mtu_last_probe > 60ULL * 1000000000ULL)
                pool_mtu_send_probe(sess);
        }

        /* Check config rollback deadlines */
        pool_config_check_deadline(sess);
    }

    kfree(payload);
    return 0;
}

/* ---- Client-initiated handshake (INIT → CHALLENGE → RESPONSE) ---- */

int pool_session_connect(const uint8_t peer_addr[16], uint8_t addr_family,
                         uint16_t port)
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
        return -ENOSPC;

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
    ret = pool_net_connect(sess, peer_addr, addr_family, port);
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

    /* Receive CHALLENGE (with timeout to avoid blocking forever) */
    pool_net_set_sock_rcvtimeo(sess->sock, 10);
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

    /* Wait for ACK or first DATA (with timeout) */
    pool_net_set_sock_rcvtimeo(sess->sock, 30);
    plen = sizeof(payload_buf);
    ret = pool_net_recv_packet(sess, &hdr, payload_buf, &plen);
    /* Clear timeout for normal session operation */
    pool_net_set_sock_rcvtimeo(sess->sock, 0);
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

    pr_info("POOL: session %d established to %pI6c:%d\n",
            sess_idx, sess->peer_addr, port);
    pool_journal_add(POOL_JOURNAL_CONNECT, 0, 0, "connect", 7);

    /* Initiate MTU discovery */
    pool_mtu_send_probe(sess);

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
        return -ENOSPC;

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
    pool_net_set_sock_rcvtimeo(sess->sock, 10);
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
                           sess->peer_addr);
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

    /* Receive RESPONSE (with timeout for puzzle-solving) */
    pool_net_set_sock_rcvtimeo(sess->sock, 30);
    plen = sizeof(payload_buf);
    ret = pool_net_recv_packet(sess, &hdr, payload_buf, &plen);
    /* Clear timeout for normal session operation */
    pool_net_set_sock_rcvtimeo(sess->sock, 0);
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

    /* Determine peer address from socket (dual-stack: may be IPv4-mapped) */
    {
        struct sockaddr_storage peer_storage;
        struct sockaddr_in *sin;
        struct sockaddr_in6 *sin6;

        if (kernel_getpeername(client_sock,
                               (struct sockaddr *)&peer_storage) == 0) {
            if (peer_storage.ss_family == AF_INET6) {
                sin6 = (struct sockaddr_in6 *)&peer_storage;
                memcpy(sess->peer_addr, &sin6->sin6_addr, 16);
                sess->peer_port = ntohs(sin6->sin6_port);
                sess->addr_family = AF_INET6;
                /* Detect IPv4-mapped and downgrade addr_family */
                if (pool_addr_is_v4mapped(sess->peer_addr))
                    sess->addr_family = AF_INET;
            } else {
                sin = (struct sockaddr_in *)&peer_storage;
                pool_ipv4_to_mapped(ntohl(sin->sin_addr.s_addr),
                                    sess->peer_addr);
                sess->peer_port = ntohs(sin->sin_port);
                sess->addr_family = AF_INET;
            }
        }
    }

    pr_info("POOL: session %d accepted from %pI6c:%d\n",
            sess_idx, sess->peer_addr, sess->peer_port);
    pool_journal_add(POOL_JOURNAL_CONNECT, 0, 0, "accept", 6);

    /* Initiate MTU discovery */
    pool_mtu_send_probe(sess);

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
