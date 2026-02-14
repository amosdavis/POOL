/*
 * poolctl.c - POOL Protocol command-line control tool
 *
 * Usage:
 *   poolctl listen <port>        - Start listening for connections
 *   poolctl connect <ip> <port>  - Connect to a remote POOL node
 *   poolctl sessions             - List active sessions
 *   poolctl send <idx> <data>    - Send data on session
 *   poolctl close <idx>          - Close a session
 *   poolctl stop                 - Stop listener
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "pool.h"

static int pool_fd = -1;

static int open_pool(void)
{
    pool_fd = open("/dev/pool", O_RDWR);
    if (pool_fd < 0) {
        perror("open /dev/pool");
        return -1;
    }
    return 0;
}

static void cmd_listen(int argc, char **argv)
{
    uint16_t port;
    if (argc < 3) {
        fprintf(stderr, "Usage: poolctl listen <port>\n");
        return;
    }
    port = (uint16_t)atoi(argv[2]);
    if (ioctl(pool_fd, POOL_IOC_LISTEN, &port) < 0)
        perror("POOL_IOC_LISTEN");
    else
        printf("Listening on port %d\n", port);
}

static void cmd_connect(int argc, char **argv)
{
    struct pool_connect_req req;
    struct in_addr addr;
    int ret;

    if (argc < 4) {
        fprintf(stderr, "Usage: poolctl connect <ip> <port>\n");
        return;
    }
    if (!inet_aton(argv[2], &addr)) {
        fprintf(stderr, "Invalid IP: %s\n", argv[2]);
        return;
    }
    req.peer_ip = ntohl(addr.s_addr);
    req.peer_port = (uint16_t)atoi(argv[3]);
    req.reserved = 0;

    ret = ioctl(pool_fd, POOL_IOC_CONNECT, &req);
    if (ret < 0)
        perror("POOL_IOC_CONNECT");
    else
        printf("Connected, session index: %d\n", ret);
}

static void cmd_sessions(void)
{
    struct pool_session_list list;
    struct pool_session_info infos[POOL_MAX_SESSIONS];
    uint32_t i;
    static const char *state_names[] = {
        "IDLE", "INIT_SENT", "CHALLENGED", "ESTABLISHED", "REKEYING", "CLOSING"
    };

    memset(&list, 0, sizeof(list));
    list.max_sessions = POOL_MAX_SESSIONS;
    list.info_ptr = (uint64_t)(unsigned long)infos;

    if (ioctl(pool_fd, POOL_IOC_SESSIONS, &list) < 0) {
        perror("POOL_IOC_SESSIONS");
        return;
    }

    printf("Active sessions: %u\n", list.count);
    printf("%-4s %-16s %-6s %-12s %-12s %-12s %-10s\n",
           "IDX", "PEER", "PORT", "STATE", "SENT", "RECV", "RTT(us)");
    for (i = 0; i < list.count; i++) {
        struct pool_session_info *s = &infos[i];
        struct in_addr a;
        a.s_addr = htonl(s->peer_ip);
        printf("%-4u %-16s %-6u %-12s %-12llu %-12llu %-10llu\n",
               s->index, inet_ntoa(a), s->peer_port,
               (s->state < 6) ? state_names[s->state] : "?",
               (unsigned long long)s->bytes_sent,
               (unsigned long long)s->bytes_recv,
               (unsigned long long)(s->telemetry.rtt_ns / 1000));
    }
}

static void cmd_send(int argc, char **argv)
{
    struct pool_send_req req;
    if (argc < 4) {
        fprintf(stderr, "Usage: poolctl send <session_idx> <data>\n");
        return;
    }
    req.session_idx = (uint32_t)atoi(argv[2]);
    req.channel = 0;
    req.flags = 0;
    req.reserved = 0;
    req.len = strlen(argv[3]);
    req.data_ptr = (uint64_t)(unsigned long)argv[3];

    if (ioctl(pool_fd, POOL_IOC_SEND, &req) < 0)
        perror("POOL_IOC_SEND");
    else
        printf("Sent %u bytes on session %u\n", req.len, req.session_idx);
}

static void cmd_close(int argc, char **argv)
{
    uint32_t idx;
    if (argc < 3) {
        fprintf(stderr, "Usage: poolctl close <session_idx>\n");
        return;
    }
    idx = (uint32_t)atoi(argv[2]);
    if (ioctl(pool_fd, POOL_IOC_CLOSE_SESS, &idx) < 0)
        perror("POOL_IOC_CLOSE_SESS");
    else
        printf("Session %u closed\n", idx);
}

static void cmd_stop(void)
{
    if (ioctl(pool_fd, POOL_IOC_STOP) < 0)
        perror("POOL_IOC_STOP");
    else
        printf("Listener stopped\n");
}

static void usage(void)
{
    fprintf(stderr,
        "Usage: poolctl <command> [args]\n"
        "\n"
        "Commands:\n"
        "  listen <port>              Start listening\n"
        "  connect <ip> <port>        Connect to peer\n"
        "  sessions                   List sessions\n"
        "  send <idx> <data>          Send data\n"
        "  close <idx>                Close session\n"
        "  stop                       Stop listener\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 1;
    }

    if (open_pool() < 0)
        return 1;

    if (strcmp(argv[1], "listen") == 0)
        cmd_listen(argc, argv);
    else if (strcmp(argv[1], "connect") == 0)
        cmd_connect(argc, argv);
    else if (strcmp(argv[1], "sessions") == 0)
        cmd_sessions();
    else if (strcmp(argv[1], "send") == 0)
        cmd_send(argc, argv);
    else if (strcmp(argv[1], "close") == 0)
        cmd_close(argc, argv);
    else if (strcmp(argv[1], "stop") == 0)
        cmd_stop();
    else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        usage();
        close(pool_fd);
        return 1;
    }

    close(pool_fd);
    return 0;
}
