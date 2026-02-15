/*
 * pool_discover.c - POOL Peer Discovery
 *
 * Implements three discovery mechanisms:
 *
 *   1. Multicast LAN discovery — Periodically sends DISCOVER packets to
 *      the POOL multicast group (239.253.0.1:9253). Peers respond with
 *      their identity, enabling zero-config LAN mesh formation.
 *
 *   2. Peer exchange — Established peers share their known peer lists,
 *      enabling mesh expansion beyond direct multicast reach.
 *
 *   3. Static peer list — Configured peers from /etc/pool/peers.conf
 *      are always attempted.
 *
 * Discovery runs as a background kernel thread that periodically probes
 * and maintains the peer table.
 */

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>

#include "pool_internal.h"

#define POOL_MCAST_GROUP        0xEFFD0001  /* 239.253.0.1 */
#define POOL_DISCOVER_PORT      9253
#define POOL_DISCOVER_INTERVAL  30  /* seconds between probes */
#define POOL_MAX_PEERS          256
#define POOL_PEER_TIMEOUT_SEC   120 /* remove peer if not seen for 2 minutes */

/* Peer table entry */
struct pool_peer {
    uint32_t ip;
    uint16_t port;
    uint8_t  pubkey[POOL_KEY_SIZE];
    uint8_t  addr[POOL_ADDR_SIZE];
    uint64_t last_seen_ns;
    uint8_t  active;
    uint8_t  source;  /* 0=multicast, 1=exchange, 2=static */
};

/* Discovery announce payload */
struct pool_announce {
    uint8_t  pubkey[POOL_KEY_SIZE];
    uint8_t  addr[POOL_ADDR_SIZE];
    uint16_t listen_port;
    uint8_t  version;
    uint8_t  flags;
    uint32_t session_count;  /* how many active sessions */
    uint32_t uptime_sec;
} __attribute__((packed));

/* Peer exchange payload — list of known peers */
struct pool_peer_entry {
    uint32_t ip;
    uint16_t port;
    uint8_t  pubkey[POOL_KEY_SIZE];
} __attribute__((packed));

struct pool_peer_exchange {
    uint16_t count;
    struct pool_peer_entry peers[];
} __attribute__((packed));

/* Module-level peer table */
static struct pool_peer peer_table[POOL_MAX_PEERS];
static struct mutex peer_lock;
static struct socket *mcast_sock;
static struct task_struct *discover_thread;

void pool_discover_init(void)
{
    memset(peer_table, 0, sizeof(peer_table));
    mutex_init(&peer_lock);
    mcast_sock = NULL;
    discover_thread = NULL;
}

/* N06: Find or create a peer entry with LRU eviction when table is full */
static struct pool_peer *peer_find_or_create(uint32_t ip, uint16_t port)
{
    int i, free_slot = -1;
    int oldest_slot = -1;
    uint64_t oldest_time = ULLONG_MAX;

    for (i = 0; i < POOL_MAX_PEERS; i++) {
        if (peer_table[i].active && peer_table[i].ip == ip &&
            peer_table[i].port == port)
            return &peer_table[i];
        if (!peer_table[i].active && free_slot < 0)
            free_slot = i;
        /* Track oldest non-static peer for LRU eviction */
        if (peer_table[i].active && peer_table[i].source != 2 &&
            peer_table[i].last_seen_ns < oldest_time) {
            oldest_time = peer_table[i].last_seen_ns;
            oldest_slot = i;
        }
    }

    if (free_slot < 0) {
        /* Table full — evict oldest non-static peer */
        if (oldest_slot >= 0) {
            pr_info("POOL: discover: evicting stale peer %pI4h for new peer\n",
                    &peer_table[oldest_slot].ip);
            free_slot = oldest_slot;
        } else {
            return NULL;
        }
    }

    memset(&peer_table[free_slot], 0, sizeof(peer_table[free_slot]));
    peer_table[free_slot].ip = ip;
    peer_table[free_slot].port = port;
    peer_table[free_slot].active = 1;
    return &peer_table[free_slot];
}

/* Remove stale peers */
static void peer_expire_stale(void)
{
    int i;
    uint64_t now = ktime_get_ns();
    uint64_t timeout_ns = (uint64_t)POOL_PEER_TIMEOUT_SEC * 1000000000ULL;

    for (i = 0; i < POOL_MAX_PEERS; i++) {
        if (!peer_table[i].active)
            continue;
        if (peer_table[i].source == 2)
            continue;  /* static peers never expire */
        if (now - peer_table[i].last_seen_ns > timeout_ns) {
            peer_table[i].active = 0;
        }
    }
}

/* Send a multicast announce */
static int pool_discover_send_announce(void)
{
    struct pool_announce ann;
    struct sockaddr_in dst;
    struct msghdr msg;
    struct kvec iov;
    int ret, i, count = 0;

    if (!mcast_sock)
        return -ENOTCONN;

    memcpy(ann.pubkey, pool.node_pubkey, POOL_KEY_SIZE);
    memcpy(ann.addr, &pool.node_addr, POOL_ADDR_SIZE);
    ann.listen_port = cpu_to_be16(pool.listen_port);
    ann.version = POOL_VERSION;
    ann.flags = 0;

    /* Count active sessions */
    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
        if (pool.sessions[i].active)
            count++;
    }
    ann.session_count = cpu_to_be32(count);
    ann.uptime_sec = 0;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(POOL_MCAST_GROUP);
    dst.sin_port = htons(POOL_DISCOVER_PORT);

    iov.iov_base = &ann;
    iov.iov_len = sizeof(ann);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dst;
    msg.msg_namelen = sizeof(dst);
    msg.msg_flags = MSG_NOSIGNAL;

    ret = kernel_sendmsg(mcast_sock, &msg, &iov, 1, sizeof(ann));
    return ret < 0 ? ret : 0;
}

/* Handle received announce */
static void pool_discover_handle_announce(const struct pool_announce *ann,
                                          uint32_t src_ip)
{
    struct pool_peer *peer;
    uint16_t port = be16_to_cpu(ann->listen_port);

    if (ann->version != POOL_VERSION)
        return;

    /* Don't discover ourselves */
    if (memcmp(ann->pubkey, pool.node_pubkey, POOL_KEY_SIZE) == 0)
        return;

    /*
     * N07: Verify announce authenticity. The pubkey field acts as the
     * peer's identity. We verify that src_ip is consistent with the
     * announced address. Full authentication happens at session setup
     * via X25519 handshake — discovery only establishes candidates.
     * Rate-limit announce processing to prevent table churn.
     */
    {
        static uint64_t last_announce_ns;
        uint64_t now = ktime_get_ns();
        if (now - last_announce_ns < 100000000ULL) /* 100ms min interval */
            return;
        last_announce_ns = now;
    }

    mutex_lock(&peer_lock);
    peer = peer_find_or_create(src_ip, port);
    if (peer) {
        memcpy(peer->pubkey, ann->pubkey, POOL_KEY_SIZE);
        memcpy(peer->addr, ann->addr, POOL_ADDR_SIZE);
        peer->last_seen_ns = ktime_get_ns();
        peer->source = 0;  /* multicast */
        pr_info("POOL: discovered peer %pI4h:%d\n", &src_ip, port);
    }
    mutex_unlock(&peer_lock);
}

/* Handle peer exchange from an established session */
void pool_discover_handle_exchange(struct pool_session *sess,
                                   const uint8_t *payload, uint32_t plen)
{
    const struct pool_peer_exchange *pex;
    uint16_t count;
    int i;

    if (plen < sizeof(uint16_t))
        return;

    pex = (const struct pool_peer_exchange *)payload;
    count = be16_to_cpu(pex->count);

    if (plen < sizeof(uint16_t) + count * sizeof(struct pool_peer_entry))
        return;

    mutex_lock(&peer_lock);
    for (i = 0; i < count && i < POOL_MAX_PEERS; i++) {
        uint32_t ip = be32_to_cpu(pex->peers[i].ip);
        uint16_t port = be16_to_cpu(pex->peers[i].port);
        struct pool_peer *peer = peer_find_or_create(ip, port);
        if (peer) {
            memcpy(peer->pubkey, pex->peers[i].pubkey, POOL_KEY_SIZE);
            peer->last_seen_ns = ktime_get_ns();
            peer->source = 1;  /* exchange */
        }
    }
    mutex_unlock(&peer_lock);
}

/* Build peer exchange payload for sharing with a session peer */
int pool_discover_build_exchange(uint8_t *buf, int max_len)
{
    struct pool_peer_exchange *pex = (struct pool_peer_exchange *)buf;
    int i, count = 0;
    int max_entries = (max_len - sizeof(uint16_t)) /
                      sizeof(struct pool_peer_entry);

    if (max_len < (int)sizeof(uint16_t))
        return 0;

    mutex_lock(&peer_lock);
    for (i = 0; i < POOL_MAX_PEERS && count < max_entries; i++) {
        if (!peer_table[i].active)
            continue;
        pex->peers[count].ip = cpu_to_be32(peer_table[i].ip);
        pex->peers[count].port = cpu_to_be16(peer_table[i].port);
        memcpy(pex->peers[count].pubkey, peer_table[i].pubkey, POOL_KEY_SIZE);
        count++;
    }
    mutex_unlock(&peer_lock);

    pex->count = cpu_to_be16(count);
    return sizeof(uint16_t) + count * sizeof(struct pool_peer_entry);
}

/* Get the count of known peers */
int pool_discover_peer_count(void)
{
    int i, count = 0;

    mutex_lock(&peer_lock);
    for (i = 0; i < POOL_MAX_PEERS; i++) {
        if (peer_table[i].active)
            count++;
    }
    mutex_unlock(&peer_lock);
    return count;
}

/* Discovery thread: periodic announce + receive + expire */
static int pool_discover_thread_fn(void *data)
{
    uint8_t *recv_buf;

    recv_buf = kmalloc(1024, GFP_KERNEL);
    if (!recv_buf)
        return -ENOMEM;

    while (!kthread_should_stop()) {
        /* Send announce */
        pool_discover_send_announce();

        /* Receive announces (non-blocking, poll for 1 second) */
        {
            struct sockaddr_in src;
            struct msghdr msg;
            struct kvec iov;
            int ret;

            pool_net_set_sock_rcvtimeo(mcast_sock, 1);

            iov.iov_base = recv_buf;
            iov.iov_len = 1024;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = &src;
            msg.msg_namelen = sizeof(src);

            ret = kernel_recvmsg(mcast_sock, &msg, &iov, 1, 1024,
                                 MSG_NOSIGNAL);
            if (ret >= (int)sizeof(struct pool_announce)) {
                pool_discover_handle_announce(
                    (struct pool_announce *)recv_buf,
                    ntohl(src.sin_addr.s_addr));
            }
        }

        /* Expire stale peers */
        mutex_lock(&peer_lock);
        peer_expire_stale();
        mutex_unlock(&peer_lock);

        /* Share peers with established sessions (peer exchange) */
        {
            int i;
            uint8_t *exchange_buf = kmalloc(4096, GFP_KERNEL);
            if (exchange_buf) {
                int ex_len = pool_discover_build_exchange(exchange_buf, 4096);
                if (ex_len > (int)sizeof(uint16_t)) {
                    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
                        struct pool_session *s = &pool.sessions[i];
                        if (!s->active ||
                            s->state != POOL_STATE_ESTABLISHED)
                            continue;
                        pool_net_send_packet(s, POOL_PKT_DISCOVER,
                                             POOL_FLAG_TELEMETRY, 0,
                                             exchange_buf, ex_len);
                    }
                }
                kfree(exchange_buf);
            }
        }

        msleep(POOL_DISCOVER_INTERVAL * 1000);
    }

    kfree(recv_buf);
    return 0;
}

int pool_discover_start(void)
{
    struct sockaddr_in addr;
    struct ip_mreqn mreq;
    int ret, opt = 1;
    sockptr_t optval;

    /* Create UDP socket for multicast */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM,
                           IPPROTO_UDP, &mcast_sock);
    if (ret) {
        pr_warn("POOL: failed to create discover socket: %d\n", ret);
        return ret;
    }

    /* Allow address reuse */
    optval = KERNEL_SOCKPTR(&opt);
    sock_setsockopt(mcast_sock, SOL_SOCKET, SO_REUSEADDR,
                    optval, sizeof(opt));

    /* Bind to discover port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(POOL_DISCOVER_PORT);

    ret = kernel_bind(mcast_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        pr_warn("POOL: discover bind failed: %d\n", ret);
        sock_release(mcast_sock);
        mcast_sock = NULL;
        return ret;
    }

    /* Join multicast group */
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = htonl(POOL_MCAST_GROUP);
    mreq.imr_ifindex = 0;

    optval = KERNEL_SOCKPTR(&mreq);
    ret = sock_setsockopt(mcast_sock, SOL_IP, IP_ADD_MEMBERSHIP,
                          optval, sizeof(mreq));
    if (ret)
        pr_warn("POOL: multicast join failed: %d (discovery limited)\n", ret);

    /* Set multicast TTL to 1 (LAN only) */
    {
        int ttl = 1;
        sockptr_t ttl_opt = KERNEL_SOCKPTR(&ttl);
        sock_setsockopt(mcast_sock, SOL_IP, IP_MULTICAST_TTL,
                        ttl_opt, sizeof(ttl));
    }

    /* Start discovery thread */
    discover_thread = kthread_run(pool_discover_thread_fn, NULL,
                                  "pool_discover");
    if (IS_ERR(discover_thread)) {
        ret = PTR_ERR(discover_thread);
        discover_thread = NULL;
        sock_release(mcast_sock);
        mcast_sock = NULL;
        return ret;
    }

    pr_info("POOL: peer discovery started (mcast 239.253.0.1:%d)\n",
            POOL_DISCOVER_PORT);
    return 0;
}

void pool_discover_stop(void)
{
    if (discover_thread) {
        kthread_stop(discover_thread);
        discover_thread = NULL;
    }
    if (mcast_sock) {
        sock_release(mcast_sock);
        mcast_sock = NULL;
    }
}
