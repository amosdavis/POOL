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
    close(bc->tcp_fd);
    if (bc->session_idx >= 0) {
        uint32_t idx = bc->session_idx;
        ioctl(bc->pool_fd, POOL_IOC_CLOSE_SESS, &idx);
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
            pthread_mutex_unlock(&bridge_lock);
            return &bridges[i];
        }
    }
    pthread_mutex_unlock(&bridge_lock);
    return NULL;
}

/* TCP→POOL mode: accept TCP, connect POOL, bridge bidirectionally */
static int run_tcp_to_pool(uint16_t tcp_port, uint32_t pool_dest,
                           uint16_t pool_port)
{
    int listen_fd, client_fd, opt = 1;
    struct sockaddr_in addr, client_addr;
    socklen_t clen;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(tcp_port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listen_fd); return 1;
    }
    if (listen(listen_fd, 64) < 0) {
        perror("listen"); close(listen_fd); return 1;
    }

    printf("pool_bridge: TCP:%d → POOL:%s:%d\n",
           tcp_port, inet_ntoa(*(struct in_addr *)&pool_dest), pool_port);

    while (running) {
        struct bridge_conn *bc;
        struct pool_connect_req creq;
        int ret;

        clen = sizeof(client_addr);
        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &clen);
        if (client_fd < 0) continue;

        bc = alloc_bridge();
        if (!bc) { close(client_fd); continue; }

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
        creq.peer_ip = pool_dest;
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
        pthread_detach(bc->thread);
    }

    close(listen_fd);
    return 0;
}

/* POOL→TCP mode: accept POOL sessions, forward to TCP destination */
static int run_pool_to_tcp(uint16_t pool_port, uint32_t tcp_dest,
                           uint16_t tcp_port)
{
    int ret;
    uint16_t port = pool_port;

    pool_fd_global = open("/dev/pool", O_RDWR);
    if (pool_fd_global < 0) { perror("/dev/pool"); return 1; }

    if (ioctl(pool_fd_global, POOL_IOC_LISTEN, &port) < 0) {
        perror("POOL listen"); close(pool_fd_global); return 1;
    }

    printf("pool_bridge: POOL:%d → TCP:%s:%d\n",
           pool_port, inet_ntoa(*(struct in_addr *)&tcp_dest), tcp_port);

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

            /* Check if we already have a bridge for this session */
            pthread_mutex_lock(&bridge_lock);
            for (j = 0; j < MAX_BRIDGES; j++) {
                if (bridges[j].active &&
                    bridges[j].session_idx == (int)infos[i].index) {
                    found = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&bridge_lock);
            if (found) continue;
            if (infos[i].state != POOL_STATE_ESTABLISHED) continue;

            /* New POOL session — bridge to TCP */
            bc = alloc_bridge();
            if (!bc) continue;

            bc->pool_fd = pool_fd_global;
            bc->session_idx = infos[i].index;

            /* Connect to TCP dest */
            bc->tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (bc->tcp_fd < 0) { bc->active = 0; continue; }

            struct sockaddr_in dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_addr.s_addr = htonl(tcp_dest);
            dest_addr.sin_port = htons(tcp_port);

            if (connect(bc->tcp_fd, (struct sockaddr *)&dest_addr,
                        sizeof(dest_addr)) < 0) {
                close(bc->tcp_fd);
                bc->active = 0;
                continue;
            }

            printf("  bridge: POOL session %d → TCP %s:%d\n",
                   bc->session_idx,
                   inet_ntoa(dest_addr.sin_addr), tcp_port);
            pthread_create(&bc->thread, NULL, bidir_thread, bc);
            pthread_detach(bc->thread);
        }

        usleep(100000); /* 100ms poll interval */
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
        "  pool_bridge tcp2pool <tcp_port> <pool_dest_ip> [pool_port]\n"
        "    Accept TCP on <tcp_port>, forward over POOL to <pool_dest_ip>\n\n"
        "  pool_bridge pool2tcp <pool_port> <tcp_dest_ip> <tcp_port>\n"
        "    Accept POOL on <pool_port>, forward to TCP <tcp_dest_ip>:<tcp_port>\n\n"
        "Examples:\n"
        "  pool_bridge tcp2pool 8080 10.4.4.101 9253\n"
        "  pool_bridge pool2tcp 9253 127.0.0.1 80\n");
}

int main(int argc, char **argv)
{
    struct in_addr dest_addr;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if (argc < 4) { usage(); return 1; }

    if (strcmp(argv[1], "tcp2pool") == 0) {
        uint16_t tcp_port = (uint16_t)atoi(argv[2]);
        uint16_t pool_port = (argc > 4) ? (uint16_t)atoi(argv[4]) : POOL_LISTEN_PORT;
        if (!inet_aton(argv[3], &dest_addr)) {
            fprintf(stderr, "Invalid IP: %s\n", argv[3]); return 1;
        }
        return run_tcp_to_pool(tcp_port, ntohl(dest_addr.s_addr), pool_port);
    }
    else if (strcmp(argv[1], "pool2tcp") == 0) {
        uint16_t pool_port = (uint16_t)atoi(argv[2]);
        uint16_t tcp_port = (uint16_t)atoi(argv[4]);
        if (!inet_aton(argv[3], &dest_addr)) {
            fprintf(stderr, "Invalid IP: %s\n", argv[3]); return 1;
        }
        return run_pool_to_tcp(pool_port, ntohl(dest_addr.s_addr), tcp_port);
    }
    else {
        usage();
        return 1;
    }
}
