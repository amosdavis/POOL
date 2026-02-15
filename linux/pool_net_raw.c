/*
 * pool_net_raw.c - POOL Raw IP Protocol 253 Transport
 *
 * Implements native IP protocol 253 transport as specified in the POOL
 * protocol specification. This provides direct IP-layer communication
 * without TCP overhead.
 *
 * When raw sockets are available (requires CAP_NET_RAW), POOL packets
 * are sent/received as IP protocol 253 datagrams. Each datagram contains
 * exactly one POOL packet (header + encrypted payload + tag).
 *
 * The raw transport is connectionless at the IP layer — session state,
 * reliability, and ordering are handled by the POOL protocol itself
 * (sequence numbers, ACKs, retransmission).
 */

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <net/sock.h>

#include "pool_internal.h"

/* Maximum raw datagram: IP header is added by the kernel */
#define POOL_RAW_MAX_PKT  (POOL_DEFAULT_MTU + POOL_HEADER_SIZE + POOL_TAG_SIZE)

/* ---- Raw socket send/recv ---- */

int pool_net_raw_send(struct pool_session *sess, void *buf, int len)
{
    struct sockaddr_in dst;
    struct msghdr msg;
    struct kvec iov;
    int ret;

    if (!pool.raw_sock)
        return -ENOTCONN;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(pool_mapped_to_ipv4(sess->peer_addr));

    iov.iov_base = buf;
    iov.iov_len = len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dst;
    msg.msg_namelen = sizeof(dst);
    msg.msg_flags = MSG_NOSIGNAL;

    ret = kernel_sendmsg(pool.raw_sock, &msg, &iov, 1, len);
    if (ret < 0)
        return ret;
    return ret;
}

int pool_net_raw_recv(struct pool_session *sess, void *buf, int len)
{
    struct sockaddr_in src;
    struct msghdr msg;
    struct kvec iov;
    int ret;

    if (!pool.raw_sock)
        return -ENOTCONN;

    iov.iov_base = buf;
    iov.iov_len = len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &src;
    msg.msg_namelen = sizeof(src);
    msg.msg_flags = MSG_NOSIGNAL;

    ret = kernel_recvmsg(pool.raw_sock, &msg, &iov, 1, len, msg.msg_flags);
    if (ret < 0)
        return ret;

    /* Capture source IP for session matching */
    if (sess && ret >= (int)sizeof(struct pool_header)) {
        pool_ipv4_to_mapped(ntohl(src.sin_addr.s_addr), sess->peer_addr);
        sess->addr_family = AF_INET;
    }

    return ret;
}

/* ---- Raw listener thread ---- */

static int pool_raw_listen_thread_fn(void *data)
{
    uint8_t *pkt_buf;
    struct sockaddr_in src;
    struct pool_header *hdr;
    int ret;

    pkt_buf = kmalloc(POOL_RAW_MAX_PKT, GFP_KERNEL);
    if (!pkt_buf)
        return -ENOMEM;

    while (!kthread_should_stop()) {
        struct msghdr msg;
        struct kvec iov;

        iov.iov_base = pkt_buf;
        iov.iov_len = POOL_RAW_MAX_PKT;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &src;
        msg.msg_namelen = sizeof(src);

        ret = kernel_recvmsg(pool.raw_sock, &msg, &iov, 1,
                             POOL_RAW_MAX_PKT, 0);
        if (ret < 0) {
            if (ret == -EAGAIN || kthread_should_stop())
                break;
            msleep(10);
            continue;
        }

        if (ret < (int)sizeof(struct pool_header))
            continue;

        hdr = (struct pool_header *)pkt_buf;

        /* Check version */
        if ((hdr->ver_type >> 4) != POOL_VERSION)
            continue;

        /* Route to appropriate session based on session_id */
        {
            int i;
            uint8_t pkt_type = hdr->ver_type & 0x0F;
            uint32_t src_ip = ntohl(src.sin_addr.s_addr);

            if (pkt_type == POOL_PKT_INIT) {
                /* New connection — create session via raw transport */
                struct socket *dummy_sock = NULL;

                /* For raw transport, we create a lightweight "session"
                   without a per-session TCP socket. The raw_sock is
                   shared. We use pool_session_alloc + manual setup. */
                struct pool_session *sess = pool_session_alloc();
                if (!sess) {
                    pr_warn("POOL: raw: no session slots\n");
                    continue;
                }
                sess->transport = POOL_TRANSPORT_RAW;
                pool_ipv4_to_mapped(src_ip, sess->peer_addr);
                sess->addr_family = AF_INET;
                sess->peer_port = 0;  /* raw has no port */
                sess->sock = pool.raw_sock;

                /* Queue the INIT packet for the session's handshake */
                {
                    struct pool_rx_entry *item;
                    item = kmalloc(sizeof(*item), GFP_KERNEL);
                    if (!item)
                        continue;
                    item->data = kmalloc(ret, GFP_KERNEL);
                    if (!item->data) {
                        kfree(item);
                        continue;
                    }
                    memcpy(item->data, pkt_buf, ret);
                    item->len = ret;
                    item->channel = hdr->channel;
                    spin_lock(&sess->rx_lock);
                    list_add_tail(&item->list, &sess->rx_queue);
                    spin_unlock(&sess->rx_lock);
                    wake_up(&sess->rx_wait);
                }
                continue;
            }

            /* N05: Existing session lookup — use sessions_lock for safety */
            mutex_lock(&pool.sessions_lock);
            for (i = 0; i < POOL_MAX_SESSIONS; i++) {
                struct pool_session *s = &pool.sessions[i];
                if (!s->active)
                    continue;
                if (s->transport != POOL_TRANSPORT_RAW)
                    continue;
                if (memcmp(s->session_id, hdr->session_id,
                           POOL_SESSION_ID_SIZE) == 0) {
                    /* N03: Validate source IP matches session peer */
                    uint8_t src_mapped[16];
                    pool_ipv4_to_mapped(src_ip, src_mapped);
                    if (memcmp(s->peer_addr, src_mapped, 16) != 0) {
                        pr_warn_ratelimited("POOL: raw: source IP mismatch for session %d\n", i);
                        break;
                    }

                    /* N04: Limit RX queue depth to prevent memory exhaustion */
                    {
                        int queue_depth = 0;
                        struct pool_rx_entry *tmp;
                        spin_lock(&s->rx_lock);
                        list_for_each_entry(tmp, &s->rx_queue, list)
                            queue_depth++;
                        spin_unlock(&s->rx_lock);
                        if (queue_depth >= 4096) {
                            pr_warn_ratelimited("POOL: raw: RX queue full for session %d\n", i);
                            break;
                        }
                    }

                    /* Deliver to this session's RX queue */
                    struct pool_rx_entry *item;
                    item = kmalloc(sizeof(*item), GFP_KERNEL);
                    if (!item)
                        break;
                    item->data = kmalloc(ret, GFP_KERNEL);
                    if (!item->data) {
                        kfree(item);
                        break;
                    }
                    memcpy(item->data, pkt_buf, ret);
                    item->len = ret;
                    item->channel = hdr->channel;
                    spin_lock(&s->rx_lock);
                    list_add_tail(&item->list, &s->rx_queue);
                    spin_unlock(&s->rx_lock);
                    wake_up(&s->rx_wait);
                    break;
                }
            }
            mutex_unlock(&pool.sessions_lock);
        }
    }

    kfree(pkt_buf);
    return 0;
}

/* ---- Init / Cleanup ---- */

int pool_net_raw_init(void)
{
    int ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_RAW,
                           POOL_IP_PROTO, &pool.raw_sock);
    if (ret) {
        pr_info("POOL: raw IP proto 253 socket unavailable (%d), "
                "using TCP transport only\n", ret);
        pool.raw_sock = NULL;
        return ret;
    }

    /* Set IP_HDRINCL = 0 so kernel adds IP header for us */
    pr_info("POOL: raw IP protocol 253 socket created\n");
    return 0;
}

int pool_net_raw_listen(void)
{
    if (!pool.raw_sock) {
        int ret = pool_net_raw_init();
        if (ret)
            return ret;
    }

    pool.raw_listen_thread = kthread_run(pool_raw_listen_thread_fn, NULL,
                                         "pool_raw_rx");
    if (IS_ERR(pool.raw_listen_thread)) {
        int ret = PTR_ERR(pool.raw_listen_thread);
        pool.raw_listen_thread = NULL;
        return ret;
    }

    pr_info("POOL: raw IP protocol 253 listener started\n");
    return 0;
}

void pool_net_raw_stop_listen(void)
{
    if (pool.raw_listen_thread) {
        kthread_stop(pool.raw_listen_thread);
        pool.raw_listen_thread = NULL;
    }
}

void pool_net_raw_cleanup(void)
{
    pool_net_raw_stop_listen();
    if (pool.raw_sock) {
        sock_release(pool.raw_sock);
        pool.raw_sock = NULL;
    }
}

int pool_net_raw_connect(struct pool_session *sess, uint32_t ip)
{
    if (!pool.raw_sock) {
        int ret = pool_net_raw_init();
        if (ret)
            return ret;
    }

    sess->transport = POOL_TRANSPORT_RAW;
    sess->sock = pool.raw_sock;  /* shared raw socket */
    pool_ipv4_to_mapped(ip, sess->peer_addr);
    sess->addr_family = AF_INET;
    sess->peer_port = 0;

    return 0;
}
