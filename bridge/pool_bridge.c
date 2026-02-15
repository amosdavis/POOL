/*
 * pool_bridge.c - TCP ↔ POOL bridge daemon
 *
 * Provides dual-stack operation: accepts TCP connections from legacy clients
 * and forwards them over POOL to the destination. Also accepts POOL sessions
 * and proxies them out as TCP connections.
 *
 * This enables incremental migration: deploy POOL on internal servers first,
 * bridge at the edge for TCP clients that haven't migrated yet.
 *
 * Usage:
 *   pool_bridge --tcp-listen 8080 --pool-dest 10.4.4.101 --pool-port 9253
 *   pool_bridge --pool-listen 9253 --tcp-dest 10.4.4.200 --tcp-port 80
 *   pool_bridge --dual 8080 --pool-port 9253 --dest 10.4.4.101
 *
 * Modes:
 *   TCP→POOL:  Accept TCP, forward over POOL (for migrating clients)
 *   POOL→TCP:  Accept POOL, forward over TCP (for migrating servers)
 *   DUAL:      Both directions (edge bridge)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>

#include "../linux/pool.h"

#define BRIDGE_BUF_SIZE   65536
#define MAX_BRIDGES       256

static volatile int running = 1;

struct bridge_conn {
    int active;
    int tcp_fd;        /* TCP side socket */
    int pool_fd;       /* /dev/pool fd */
    int session_idx;   /* POOL session index */
    pthread_t thread;
    uint64_t bytes_forwarded;
};

static struct bridge_conn bridges[MAX_BRIDGES];
static pthread_mutex_t bridge_lock = PTHREAD_MUTEX_INITIALIZER;

static int pool_fd_global = -1;  /* shared /dev/pool fd for listener */

static void sighandler(int sig)
{
    (void)sig;
    running = 0;
}

/* Forward TCP data → POOL session */
static void *tcp_to_pool_thread(void *arg)
{
    struct bridge_conn *bc = (struct bridge_conn *)arg;
    char buf[BRIDGE_BUF_SIZE];
    ssize_t n;
    struct pool_send_req sreq;
    struct pool_recv_req rreq;

    while (running && bc->active) {
        struct pollfd pfd = { .fd = bc->tcp_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;

        /* TCP → POOL */
        n = read(bc->tcp_fd, buf, sizeof(buf));
        if (n <= 0) break;

        memset(&sreq, 0, sizeof(sreq));
        sreq.session_idx = bc->session_idx;
        sreq.channel = 0;
        sreq.len = (uint32_t)n;
        sreq.data_ptr = (uint64_t)(unsigned long)buf;
        if (ioctl(bc->pool_fd, POOL_IOC_SEND, &sreq) < 0) break;

        bc->bytes_forwarded += n;
    }

    /* Also need a POOL → TCP direction */
    /* In practice this needs two threads or poll on both */
    bc->active = 0;
    close(bc->tcp_fd);
    bc->tcp_fd = -1;
    return NULL;
}

/* Bidirectional forwarding: TCP ↔ POOL */
static void *bidir_thread(void *arg)
{
    struct bridge_conn *bc = (struct bridge_conn *)arg;
    char tcp_buf[BRIDGE_BUF_SIZE];
    char pool_buf[BRIDGE_BUF_SIZE];
    struct pool_send_req sreq;
    struct pool_recv_req rreq;

    while (running && bc->active) {
        struct pollfd pfd = { .fd = bc->tcp_fd, .events = POLLIN };
        int ret;
        ssize_t n;

        /* Check TCP → POOL (non-blocking) */
        ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            n = read(bc->tcp_fd, tcp_buf, sizeof(tcp_buf));
            if (n <= 0) break;

            memset(&sreq, 0, sizeof(sreq));
            sreq.session_idx = bc->session_idx;
            sreq.channel = 0;
            sreq.len = (uint32_t)n;
            sreq.data_ptr = (uint64_t)(unsigned long)tcp_buf;
            if (ioctl(bc->pool_fd, POOL_IOC_SEND, &sreq) < 0) break;
            bc->bytes_forwarded += n;
        }

        /* Check POOL → TCP (non-blocking via short timeout) */
        memset(&rreq, 0, sizeof(rreq));
        rreq.session_idx = bc->session_idx;
        rreq.channel = 0;
        rreq.len = sizeof(pool_buf);
        rreq.data_ptr = (uint64_t)(unsigned long)pool_buf;
        if (ioctl(bc->pool_fd, POOL_IOC_RECV, &rreq) >= 0 && rreq.len > 0) {
            n = write(bc->tcp_fd, pool_buf, rreq.len);
            if (n <= 0) break;
            bc->bytes_forwarded += rreq.len;
        }
    }

    bc->active = 0;
    if (bc->tcp_fd >= 0) {
        close(bc->tcp_fd);
        bc->tcp_fd = -1;
    }
    if (bc->session_idx >= 0) {
        uint32_t idx = bc->session_idx;
        ioctl(bc->pool_fd, POOL_IOC_CLOSE_SESS, &idx);
        bc->session_idx = -1;
    }
    return NULL;
}

static struct bridge_conn *alloc_bridge(void)
{
    int i;
    pthread_mutex_lock(&bridge_lock);
    for (i = 0; i < MAX_BRIDGES; i++) {
        if (!bridges[i].active) {
            memset(&bridges[i], 0, sizeof(bridges[i]));
            bridges[i].active = 1;
            bridges[i].tcp_fd = -1;
            bridges[i].session_idx = -1;
            pthread_mutex_unlock(&bridge_lock);
            return &bridges[i];
        }
    }
    pthread_mutex_unlock(&bridge_lock);
    return NULL;
}

/* TCP→POOL mode: accept TCP, connect POOL, bridge bidirectionally */
static int run_tcp_to_pool(uint16_t tcp_port,
                           const struct sockaddr_storage *pool_dest,
                           uint16_t pool_port)
{
    int listen_fd, client_fd, opt = 1, v6only = 0;
    struct sockaddr_in6 addr6;
    struct sockaddr_storage client_addr;
    socklen_t clen;
    char dest_str[INET6_ADDRSTRLEN];

    /* Format destination for logging */
    if (pool_dest->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)pool_dest;
        inet_ntop(AF_INET6, &s6->sin6_addr, dest_str, sizeof(dest_str));
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)pool_dest;
        inet_ntop(AF_INET, &s4->sin_addr, dest_str, sizeof(dest_str));
    }

    /* Dual-stack TCP listener */
    listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(tcp_port);

    if (bind(listen_fd, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
        perror("bind"); close(listen_fd); return 1;
    }
    if (listen(listen_fd, 64) < 0) {
        perror("listen"); close(listen_fd); return 1;
    }

    printf("pool_bridge: TCP:%d → POOL:%s:%d\n", tcp_port, dest_str, pool_port);

    while (running) {
        struct bridge_conn *bc;
        struct pool_connect_req creq;
        int ret;

        clen = sizeof(client_addr);
        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &clen);
        if (client_fd < 0) continue;

        bc = alloc_bridge();
        if (!bc) {
            fprintf(stderr, "pool_bridge: connection limit reached (%d/%d)\n",
                    MAX_BRIDGES, MAX_BRIDGES);
            close(client_fd);
            continue;
        }

        bc->tcp_fd = client_fd;
        bc->pool_fd = open("/dev/pool", O_RDWR);
        if (bc->pool_fd < 0) {
            fprintf(stderr, "Cannot open /dev/pool\n");
            close(client_fd);
            bc->active = 0;
            continue;
        }

        /* Connect to POOL peer */
        memset(&creq, 0, sizeof(creq));
        if (pool_dest->ss_family == AF_INET6) {
            const struct sockaddr_in6 *s6 =
                (const struct sockaddr_in6 *)pool_dest;
            memcpy(creq.peer_addr, &s6->sin6_addr, 16);
            creq.addr_family = AF_INET6;
        } else {
            const struct sockaddr_in *s4 =
                (const struct sockaddr_in *)pool_dest;
            pool_ipv4_to_mapped(ntohl(s4->sin_addr.s_addr), creq.peer_addr);
            creq.addr_family = AF_INET;
        }
        creq.peer_port = pool_port;

        ret = ioctl(bc->pool_fd, POOL_IOC_CONNECT, &creq);
        if (ret < 0) {
            fprintf(stderr, "POOL connect failed\n");
            close(client_fd);
            close(bc->pool_fd);
            bc->active = 0;
            continue;
        }
        bc->session_idx = ret;

        printf("  bridge: TCP client → POOL session %d\n", ret);
        pthread_create(&bc->thread, NULL, bidir_thread, bc);
    }

    /* Clean shutdown: join all active bridge threads */
    running = 0;
    {
        pthread_t threads_to_join[MAX_BRIDGES];
        int join_count = 0, idx;

        pthread_mutex_lock(&bridge_lock);
        for (idx = 0; idx < MAX_BRIDGES; idx++) {
            if (bridges[idx].active) {
                bridges[idx].active = 0;
                threads_to_join[join_count++] = bridges[idx].thread;
            }
        }
        pthread_mutex_unlock(&bridge_lock);

        for (idx = 0; idx < join_count; idx++)
            pthread_join(threads_to_join[idx], NULL);
    }

    close(listen_fd);
    return 0;
}

/* POOL→TCP mode: accept POOL sessions, forward to TCP destination */
static int run_pool_to_tcp(uint16_t pool_port,
                           const struct sockaddr_storage *tcp_dest,
                           uint16_t tcp_port)
{
    int ret;
    uint16_t port = pool_port;
    char dest_str[INET6_ADDRSTRLEN];

    if (tcp_dest->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)tcp_dest;
        inet_ntop(AF_INET6, &s6->sin6_addr, dest_str, sizeof(dest_str));
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)tcp_dest;
        inet_ntop(AF_INET, &s4->sin_addr, dest_str, sizeof(dest_str));
    }

    pool_fd_global = open("/dev/pool", O_RDWR);
    if (pool_fd_global < 0) { perror("/dev/pool"); return 1; }

    if (ioctl(pool_fd_global, POOL_IOC_LISTEN, &port) < 0) {
        perror("POOL listen"); close(pool_fd_global); return 1;
    }

    printf("pool_bridge: POOL:%d → TCP:%s:%d\n",
           pool_port, dest_str, tcp_port);

    /* Poll for new POOL sessions, bridge to TCP */
    while (running) {
        struct pool_session_list list;
        struct pool_session_info infos[POOL_MAX_SESSIONS];
        uint32_t i;

        memset(&list, 0, sizeof(list));
        list.max_sessions = POOL_MAX_SESSIONS;
        list.info_ptr = (uint64_t)(unsigned long)infos;
        ioctl(pool_fd_global, POOL_IOC_SESSIONS, &list);

        for (i = 0; i < list.count; i++) {
            int found = 0, j;
            struct bridge_conn *bc;

            if (infos[i].state != POOL_STATE_ESTABLISHED) continue;

            /* Hold lock across check + allocate to prevent TOCTOU race */
            pthread_mutex_lock(&bridge_lock);

            /* Check if we already have a bridge for this session */
            for (j = 0; j < MAX_BRIDGES; j++) {
                if (bridges[j].active &&
                    bridges[j].session_idx == (int)infos[i].index) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                pthread_mutex_unlock(&bridge_lock);
                continue;
            }

            /* Allocate a bridge slot while still holding the lock */
            bc = NULL;
            for (j = 0; j < MAX_BRIDGES; j++) {
                if (!bridges[j].active) {
                    memset(&bridges[j], 0, sizeof(bridges[j]));
                    bridges[j].active = 1;
                    bc = &bridges[j];
                    break;
                }
            }
            pthread_mutex_unlock(&bridge_lock);

            if (!bc) {
                fprintf(stderr, "pool_bridge: connection limit reached (%d/%d)\n",
                        MAX_BRIDGES, MAX_BRIDGES);
                continue;
            }

            bc->pool_fd = pool_fd_global;
            bc->session_idx = infos[i].index;

            /* Connect to TCP dest */
            bc->tcp_fd = socket(tcp_dest->ss_family, SOCK_STREAM, 0);
            if (bc->tcp_fd < 0) { bc->active = 0; continue; }

            if (tcp_dest->ss_family == AF_INET6) {
                struct sockaddr_in6 dest6;
                const struct sockaddr_in6 *s6 =
                    (const struct sockaddr_in6 *)tcp_dest;
                memset(&dest6, 0, sizeof(dest6));
                dest6.sin6_family = AF_INET6;
                memcpy(&dest6.sin6_addr, &s6->sin6_addr, 16);
                dest6.sin6_port = htons(tcp_port);
                if (connect(bc->tcp_fd, (struct sockaddr *)&dest6,
                            sizeof(dest6)) < 0) {
                    close(bc->tcp_fd);
                    bc->active = 0;
                    continue;
                }
            } else {
                struct sockaddr_in dest4;
                const struct sockaddr_in *s4 =
                    (const struct sockaddr_in *)tcp_dest;
                memset(&dest4, 0, sizeof(dest4));
                dest4.sin_family = AF_INET;
                dest4.sin_addr = s4->sin_addr;
                dest4.sin_port = htons(tcp_port);
                if (connect(bc->tcp_fd, (struct sockaddr *)&dest4,
                            sizeof(dest4)) < 0) {
                    close(bc->tcp_fd);
                    bc->active = 0;
                    continue;
                }
            }

            printf("  bridge: POOL session %d → TCP %s:%d\n",
                   bc->session_idx, dest_str, tcp_port);
            pthread_create(&bc->thread, NULL, bidir_thread, bc);
        }

        usleep(100000); /* 100ms poll interval */
    }

    /* Clean shutdown: join all active bridge threads */
    {
        pthread_t threads_to_join[MAX_BRIDGES];
        int join_count = 0, idx;

        pthread_mutex_lock(&bridge_lock);
        for (idx = 0; idx < MAX_BRIDGES; idx++) {
            if (bridges[idx].active) {
                bridges[idx].active = 0;
                threads_to_join[join_count++] = bridges[idx].thread;
            }
        }
        pthread_mutex_unlock(&bridge_lock);

        for (idx = 0; idx < join_count; idx++)
            pthread_join(threads_to_join[idx], NULL);
    }

    ioctl(pool_fd_global, POOL_IOC_STOP);
    close(pool_fd_global);
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "pool_bridge - TCP ↔ POOL protocol bridge\n\n"
        "Modes:\n"
        "  pool_bridge tcp2pool <tcp_port> <pool_dest> [pool_port]\n"
        "    Accept TCP on <tcp_port>, forward over POOL to <pool_dest>\n\n"
        "  pool_bridge pool2tcp <pool_port> <tcp_dest> <tcp_port>\n"
        "    Accept POOL on <pool_port>, forward to TCP <tcp_dest>:<tcp_port>\n\n"
        "Addresses can be IPv4 (10.4.4.101) or IPv6 (::1, [2001:db8::1])\n\n"
        "Examples:\n"
        "  pool_bridge tcp2pool 8080 10.4.4.101 9253\n"
        "  pool_bridge tcp2pool 8080 ::1 9253\n"
        "  pool_bridge pool2tcp 9253 127.0.0.1 80\n");
}

/* Resolve an address string (IPv4, IPv6, or hostname) */
static int resolve_addr(const char *host, struct sockaddr_storage *out)
{
    struct addrinfo hints, *res;
    int ret;
    char clean[INET6_ADDRSTRLEN + 1];
    const char *h = host;

    /* Strip brackets from [IPv6] notation */
    if (h[0] == '[') {
        size_t len = strlen(h);
        if (len > 2 && h[len - 1] == ']') {
            memcpy(clean, h + 1, len - 2);
            clean[len - 2] = '\0';
            h = clean;
        }
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    ret = getaddrinfo(h, NULL, &hints, &res);
    if (ret != 0) {
        /* Try without AI_NUMERICHOST for hostname resolution */
        hints.ai_flags = 0;
        ret = getaddrinfo(h, NULL, &hints, &res);
        if (ret != 0) {
            fprintf(stderr, "Cannot resolve '%s': %s\n",
                    host, gai_strerror(ret));
            return -1;
        }
    }

    memcpy(out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char **argv)
{
    struct sockaddr_storage dest_addr;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if (argc < 4) { usage(); return 1; }

    if (strcmp(argv[1], "tcp2pool") == 0) {
        uint16_t tcp_port = (uint16_t)atoi(argv[2]);
        uint16_t pool_port = (argc > 4) ? (uint16_t)atoi(argv[4]) : POOL_LISTEN_PORT;
        if (resolve_addr(argv[3], &dest_addr) < 0) return 1;
        return run_tcp_to_pool(tcp_port, &dest_addr, pool_port);
    }
    else if (strcmp(argv[1], "pool2tcp") == 0) {
        uint16_t pool_port = (uint16_t)atoi(argv[2]);
        uint16_t tcp_port = (uint16_t)atoi(argv[4]);
        if (resolve_addr(argv[3], &dest_addr) < 0) return 1;
        return run_pool_to_tcp(pool_port, &dest_addr, tcp_port);
    }
    else {
        usage();
        return 1;
    }
}
