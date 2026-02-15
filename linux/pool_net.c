/*
 * pool_net.c - POOL Protocol network transport layer
 *
 * TCP-based transport (IP proto 253 not feasible in QEMU VMs).
 * Handles listener, raw send/recv, and POOL packet framing.
 */

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/sockptr.h>

#include "pool_internal.h"

#define POOL_HANDSHAKE_TIMEOUT_SEC   10
#define POOL_RESPONSE_TIMEOUT_SEC    30

/* ---- Raw socket helpers ---- */

int pool_net_send_raw(struct socket *sock, void *buf, int len)
{
    struct kvec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
    int sent = 0, ret;

    while (sent < len) {
        iov.iov_base = (char *)buf + sent;
        iov.iov_len = len - sent;
        ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (ret <= 0)
            return ret ? ret : -EIO;
        sent += ret;
    }
    return sent;
}

int pool_net_recv_raw(struct socket *sock, void *buf, int len)
{
    struct kvec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg = { .msg_flags = MSG_WAITALL | MSG_NOSIGNAL };
    int rcvd = 0, ret;

    while (rcvd < len) {
        iov.iov_base = (char *)buf + rcvd;
        iov.iov_len = len - rcvd;
        ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len,
                             msg.msg_flags);
        if (ret <= 0)
            return ret ? ret : -EIO;
        rcvd += ret;
    }
    return rcvd;
}

/* ---- POOL packet send/recv ---- */

/*
 * Send a POOL packet on an established session.
 * Encrypts payload if session is established.
 * Computes and embeds HMAC over header+payload.
 */
int pool_net_send_packet(struct pool_session *sess, uint8_t type,
                         uint16_t flags, uint8_t channel,
                         const void *payload, int payload_len)
{
    struct pool_header hdr;
    uint8_t *enc_payload = NULL;
    int enc_len = 0;
    uint64_t seq;
    int ret;
    void *hmac_buf;
    int hmac_buf_len;

    if (!sess->sock)
        return -ENOTCONN;

    mutex_lock(&sess->send_lock);

    memset(&hdr, 0, sizeof(hdr));
    hdr.ver_type = (POOL_VERSION << 4) | (type & 0x0F);
    hdr.flags = cpu_to_be16(flags);
    memcpy(hdr.session_id, sess->session_id, POOL_SESSION_ID_SIZE);
    hdr.timestamp = cpu_to_be64(ktime_get_ns());
    hdr.channel = channel;

    seq = pool_crypto_next_seq(&sess->crypto);
    hdr.seq = cpu_to_be64(seq);
    hdr.ack = cpu_to_be64(sess->crypto.remote_seq);

    /* Encrypt payload if session is established */
    if (payload && payload_len > 0 &&
        sess->state == POOL_STATE_ESTABLISHED) {
        enc_payload = kmalloc(payload_len + POOL_TAG_SIZE, GFP_KERNEL);
        if (!enc_payload) {
            ret = -ENOMEM;
            goto out_unlock;
        }
        mutex_lock(&sess->crypto_lock);
        ret = pool_crypto_encrypt(&sess->crypto,
                                  payload, payload_len,
                                  enc_payload, &enc_len, seq);
        mutex_unlock(&sess->crypto_lock);
        if (ret) {
            kfree(enc_payload);
            goto out_unlock;
        }
        hdr.payload_len = cpu_to_be16(enc_len);
        flags |= POOL_FLAG_ENCRYPTED;
        hdr.flags = cpu_to_be16(flags);
    } else if (payload && payload_len > 0) {
        /* Pre-establishment: send plaintext */
        hdr.payload_len = cpu_to_be16(payload_len);
        enc_len = payload_len;
    } else {
        hdr.payload_len = 0;
        enc_len = 0;
    }

    /* Compute HMAC over header (with zeroed HMAC field) + payload */
    memset(hdr.hmac, 0, POOL_HMAC_SIZE);
    hmac_buf_len = sizeof(hdr) + enc_len;
    hmac_buf = kmalloc(hmac_buf_len, GFP_KERNEL);
    if (!hmac_buf) {
        kfree(enc_payload);
        ret = -ENOMEM;
        goto out_unlock;
    }
    memcpy(hmac_buf, &hdr, sizeof(hdr));
    if (enc_len > 0) {
        if (enc_payload)
            memcpy((char *)hmac_buf + sizeof(hdr), enc_payload, enc_len);
        else
            memcpy((char *)hmac_buf + sizeof(hdr), payload, enc_len);
    }

    if (sess->state == POOL_STATE_ESTABLISHED) {
        mutex_lock(&sess->crypto_lock);
        pool_crypto_hmac(&sess->crypto, hmac_buf, hmac_buf_len, hdr.hmac);
        mutex_unlock(&sess->crypto_lock);
    }
    kfree(hmac_buf);

    /* Send header */
    sess->last_send_ts = ktime_get_ns();
    ret = pool_net_send_raw(sess->sock, &hdr, sizeof(hdr));
    if (ret < 0) {
        kfree(enc_payload);
        goto out_unlock;
    }

    /* Send payload */
    if (enc_len > 0) {
        if (enc_payload)
            ret = pool_net_send_raw(sess->sock, enc_payload, enc_len);
        else
            ret = pool_net_send_raw(sess->sock, (void *)payload, enc_len);
        kfree(enc_payload);
        if (ret < 0)
            goto out_unlock;
    } else {
        kfree(enc_payload);
    }

    sess->packets_sent++;
    sess->bytes_sent += sizeof(hdr) + enc_len;
    ret = 0;

out_unlock:
    mutex_unlock(&sess->send_lock);
    return ret;
}

/*
 * Receive a POOL packet from a session.
 * Verifies HMAC, decrypts if needed.
 */
int pool_net_recv_packet(struct pool_session *sess,
                         struct pool_header *hdr,
                         uint8_t *payload, int *payload_len)
{
    int ret, plen;
    uint8_t saved_hmac[POOL_HMAC_SIZE];
    void *hmac_buf;
    int hmac_buf_len;

    if (!sess->sock)
        return -ENOTCONN;

    /* Read header */
    ret = pool_net_recv_raw(sess->sock, hdr, sizeof(*hdr));
    if (ret < 0)
        return ret;

    plen = be16_to_cpu(hdr->payload_len);
    if (plen > POOL_MAX_PAYLOAD + POOL_TAG_SIZE)
        return -EMSGSIZE;

    /* Read payload */
    if (plen > 0) {
        ret = pool_net_recv_raw(sess->sock, payload, plen);
        if (ret < 0)
            return ret;
    }

    /* Verify HMAC if session is established and packet is DATA/HEARTBEAT */
    if (sess->state == POOL_STATE_ESTABLISHED) {
        uint8_t pkt_type = hdr->ver_type & 0x0F;
        /* Skip HMAC on handshake completion packets (RESPONSE/ACK)
         * since both sides just derived keys and seq numbers differ */
        if (pkt_type != POOL_PKT_RESPONSE && pkt_type != POOL_PKT_ACK) {
            memcpy(saved_hmac, hdr->hmac, POOL_HMAC_SIZE);
            memset(hdr->hmac, 0, POOL_HMAC_SIZE);
            hmac_buf_len = sizeof(*hdr) + plen;
            hmac_buf = kmalloc(hmac_buf_len, GFP_KERNEL);
            if (!hmac_buf)
                return -ENOMEM;
            memcpy(hmac_buf, hdr, sizeof(*hdr));
            if (plen > 0)
                memcpy((char *)hmac_buf + sizeof(*hdr), payload, plen);
            mutex_lock(&sess->crypto_lock);
            ret = pool_crypto_hmac_verify(&sess->crypto, hmac_buf,
                                           hmac_buf_len, saved_hmac);
            mutex_unlock(&sess->crypto_lock);
            kfree(hmac_buf);
            if (ret) {
                pr_warn("POOL: HMAC verification failed (type=%d)\n", pkt_type);
                return -EBADMSG;
            }
            memcpy(hdr->hmac, saved_hmac, POOL_HMAC_SIZE);
        }
    }

    /* Decrypt if encrypted */
    if (plen > 0 && (be16_to_cpu(hdr->flags) & POOL_FLAG_ENCRYPTED)) {
        uint8_t *plain;
        int plain_len;
        uint64_t seq = be64_to_cpu(hdr->seq);

        plain = kmalloc(plen, GFP_KERNEL);
        if (!plain)
            return -ENOMEM;

        mutex_lock(&sess->crypto_lock);
        ret = pool_crypto_decrypt(&sess->crypto, payload, plen,
                                  plain, &plain_len, seq);
        mutex_unlock(&sess->crypto_lock);
        if (ret) {
            kfree(plain);
            pr_warn("POOL: decryption failed\n");
            return -EBADMSG;
        }
        memcpy(payload, plain, plain_len);
        plen = plain_len;
        kfree(plain);
    }

    /* Update remote sequence and detect loss via gaps */
    {
        uint64_t remote_seq = be64_to_cpu(hdr->seq);

        if (sess->expected_remote_seq > 0 &&
            remote_seq > sess->expected_remote_seq) {
            /* Sequence gap detected — count skipped seqs as lost */
            sess->packets_lost +=
                remote_seq - sess->expected_remote_seq;
        }
        sess->expected_remote_seq = remote_seq + 1;
        sess->crypto.remote_seq = remote_seq;
    }

    /* Update RTT from timestamp */
    if (be64_to_cpu(hdr->ack) == sess->crypto.local_seq && sess->last_send_ts) {
        uint64_t now = ktime_get_ns();
        uint64_t rtt = now - sess->last_send_ts;
        pool_telemetry_update_rtt(sess, rtt);
    }

    sess->packets_recv++;
    sess->bytes_recv += sizeof(*hdr) + plen;
    *payload_len = plen;

    pool_telemetry_record_recv(sess, plen);

    return 0;
}

/* ---- Listener ---- */

static int pool_listen_thread_fn(void *data)
{
    struct socket *new_sock;
    int ret;

    while (!kthread_should_stop()) {
        ret = kernel_accept(pool.listen_sock, &new_sock, 0);
        if (ret < 0) {
            if (ret == -EAGAIN || kthread_should_stop())
                break;
            msleep(100);
            continue;
        }

        pr_info("POOL: accepted incoming connection\n");
        ret = pool_session_accept(new_sock);
        if (ret < 0) {
            pr_warn("POOL: failed to accept session: %d\n", ret);
            sock_release(new_sock);
        }
    }
    return 0;
}

int pool_net_listen(uint16_t port)
{
    struct sockaddr_in addr;
    int ret, opt = 1;
    sockptr_t optval = KERNEL_SOCKPTR(&opt);

    if (pool.listening) {
        pr_info("POOL: already listening\n");
        return 0;
    }

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                           IPPROTO_TCP, &pool.listen_sock);
    if (ret) {
        pr_err("POOL: failed to create listen socket: %d\n", ret);
        return ret;
    }

    ret = sock_setsockopt(pool.listen_sock, SOL_SOCKET, SO_REUSEADDR,
                          optval, sizeof(opt));
    if (ret)
        pr_warn("POOL: SO_REUSEADDR failed: %d\n", ret);

    pool_net_set_keepalive(pool.listen_sock);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = kernel_bind(pool.listen_sock, (struct sockaddr *)&addr,
                      sizeof(addr));
    if (ret) {
        pr_err("POOL: bind to port %d failed: %d\n", port, ret);
        sock_release(pool.listen_sock);
        pool.listen_sock = NULL;
        return ret;
    }

    ret = kernel_listen(pool.listen_sock, POOL_LISTEN_BACKLOG);
    if (ret) {
        pr_err("POOL: listen failed: %d\n", ret);
        sock_release(pool.listen_sock);
        pool.listen_sock = NULL;
        return ret;
    }

    pool.listen_port = port;
    pool.listening = 1;

    pool.listen_thread = kthread_run(pool_listen_thread_fn, NULL,
                                     "pool_listen");
    if (IS_ERR(pool.listen_thread)) {
        ret = PTR_ERR(pool.listen_thread);
        pool.listen_thread = NULL;
        pool.listening = 0;
        sock_release(pool.listen_sock);
        pool.listen_sock = NULL;
        return ret;
    }

    pr_info("POOL: listening on port %d\n", port);
    pool_journal_add(POOL_JOURNAL_CONNECT, 0, 0, "listen", 6);
    return 0;
}

void pool_net_stop_listen(void)
{
    if (pool.listen_thread) {
        kthread_stop(pool.listen_thread);
        pool.listen_thread = NULL;
    }
    if (pool.listen_sock) {
        kernel_sock_shutdown(pool.listen_sock, SHUT_RDWR);
        sock_release(pool.listen_sock);
        pool.listen_sock = NULL;
    }
    pool.listening = 0;
}

/* Connect to a peer (raw TCP, handshake done in pool_session.c) */
int pool_net_connect(struct pool_session *sess, uint32_t ip, uint16_t port)
{
    struct sockaddr_in addr;
    int ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                           IPPROTO_TCP, &sess->sock);
    if (ret) {
        pr_err("POOL: failed to create socket: %d\n", ret);
        return ret;
    }

    pool_net_set_keepalive(sess->sock);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    addr.sin_port = htons(port);

    ret = kernel_connect(sess->sock, (struct sockaddr *)&addr,
                         sizeof(addr), 0);
    if (ret) {
        pr_err("POOL: connect to %pI4h:%d failed: %d\n", &ip, port, ret);
        sock_release(sess->sock);
        sess->sock = NULL;
        return ret;
    }

    sess->peer_ip = ip;
    sess->peer_port = port;
    return 0;
}

int pool_net_init(void)
{
    return 0;
}

/* Set receive timeout on a socket */
static void pool_net_set_rcvtimeo(struct socket *sock, int seconds)
{
    struct __kernel_sock_timeval tv;
    sockptr_t optval;

    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    optval = KERNEL_SOCKPTR(&tv);
    sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_NEW,
                    optval, sizeof(tv));
}

void pool_net_set_sock_rcvtimeo(struct socket *sock, int seconds)
{
    pool_net_set_rcvtimeo(sock, seconds);
}

/* Enable TCP keepalive: detect dead peers within ~90 seconds */
static void pool_net_set_keepalive(struct socket *sock)
{
    int opt = 1;
    sockptr_t optval = KERNEL_SOCKPTR(&opt);
    int idle = 60, intvl = 10, cnt = 3;

    sock_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, optval, sizeof(opt));
    tcp_sock_set_keepidle(sock->sk, idle);
    tcp_sock_set_keepintvl(sock->sk, intvl);
    tcp_sock_set_keepcnt(sock->sk, cnt);
}

void pool_net_cleanup(void)
{
    pool_net_stop_listen();
}
