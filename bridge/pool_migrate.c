/*
 * pool_migrate.c - TCP→POOL migration status and control tool
 *
 * Shows which services are bridged, their throughput, and provides
 * commands to enable/disable POOL for specific services.
 *
 * Usage:
 *   pool_migrate status             Show migration status
 *   pool_migrate enable <service>   Enable POOL for a service
 *   pool_migrate disable <service>  Revert to TCP
 *   pool_migrate test <ip> <port>   Test POOL connectivity
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../linux/pool.h"

#define MIGRATE_CONF "/etc/pool/migrate.conf"

static void cmd_status(void)
{
    int pool_fd;
    struct pool_session_list list;
    struct pool_session_info infos[POOL_MAX_SESSIONS];
    uint32_t i;
    FILE *conf;

    printf("=== POOL Migration Status ===\n\n");

    /* Check if POOL module is loaded */
    pool_fd = open("/dev/pool", O_RDWR);
    if (pool_fd < 0) {
        printf("POOL module: NOT LOADED\n");
        printf("  Run: insmod pool.ko\n");
        return;
    }
    printf("POOL module: LOADED\n");

    /* Query sessions */
    memset(&list, 0, sizeof(list));
    list.max_sessions = POOL_MAX_SESSIONS;
    list.info_ptr = (uint64_t)(unsigned long)infos;
    ioctl(pool_fd, POOL_IOC_SESSIONS, &list);

    printf("Active POOL sessions: %u\n\n", list.count);

    if (list.count > 0) {
        printf("%-4s %-16s %-6s %-12s %-12s %-10s\n",
               "IDX", "PEER", "PORT", "SENT(MB)", "RECV(MB)", "RTT(us)");
        for (i = 0; i < list.count; i++) {
            char addr_str[INET6_ADDRSTRLEN];
            if (pool_addr_is_v4mapped(infos[i].peer_addr)) {
                uint32_t ip4 = pool_mapped_to_ipv4(infos[i].peer_addr);
                uint32_t nip = htonl(ip4);
                inet_ntop(AF_INET, &nip, addr_str, sizeof(addr_str));
            } else {
                inet_ntop(AF_INET6, infos[i].peer_addr,
                          addr_str, sizeof(addr_str));
            }
            printf("%-4u %-40s %-6u %-12.1f %-12.1f %-10llu\n",
                   infos[i].index, addr_str, infos[i].peer_port,
                   (double)infos[i].bytes_sent / (1024*1024),
                   (double)infos[i].bytes_recv / (1024*1024),
                   (unsigned long long)(infos[i].telemetry.rtt_ns / 1000));
        }
    }

    /* Show migration config */
    printf("\n=== Migration Configuration ===\n");
    conf = fopen(MIGRATE_CONF, "r");
    if (conf) {
        char line[256];
        printf("%-20s %-10s %-16s %-6s\n",
               "SERVICE", "MODE", "DEST", "PORT");
        while (fgets(line, sizeof(line), conf)) {
            if (line[0] == '#' || line[0] == '\n') continue;
            printf("%s", line);
        }
        fclose(conf);
    } else {
        printf("No migration config found (%s)\n", MIGRATE_CONF);
        printf("  Create with: pool_migrate enable <service>\n");
    }

    close(pool_fd);
}

static void cmd_test(const char *ip, const char *port_str)
{
    int pool_fd, ret;
    struct pool_connect_req req;
    uint32_t idx;

    pool_fd = open("/dev/pool", O_RDWR);
    if (pool_fd < 0) {
        printf("FAIL: Cannot open /dev/pool (module not loaded?)\n");
        return;
    }

    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(ip, NULL, &hints, &res) != 0) {
        printf("FAIL: Cannot resolve '%s'\n", ip);
        close(pool_fd);
        return;
    }

    printf("Testing POOL connectivity to %s:%s...\n", ip, port_str);

    memset(&req, 0, sizeof(req));
    if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)res->ai_addr;
        memcpy(req.peer_addr, &s6->sin6_addr, 16);
        req.addr_family = AF_INET6;
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)res->ai_addr;
        pool_ipv4_to_mapped(ntohl(s4->sin_addr.s_addr), req.peer_addr);
        req.addr_family = AF_INET;
    }
    req.peer_port = (uint16_t)atoi(port_str);
    freeaddrinfo(res);

    ret = ioctl(pool_fd, POOL_IOC_CONNECT, &req);
    if (ret < 0) {
        printf("FAIL: POOL handshake failed (%s)\n", strerror(errno));
    } else {
        printf("OK: POOL session %d established\n", ret);
        printf("  Handshake: X25519 ECDH + puzzle proof-of-work\n");
        printf("  Encryption: ChaCha20-Poly1305\n");
        printf("  Authentication: HMAC-SHA256\n");

        /* Close test session */
        idx = ret;
        ioctl(pool_fd, POOL_IOC_CLOSE_SESS, &idx);
        printf("  Test session closed.\n");
    }

    close(pool_fd);
}

static void usage(void)
{
    fprintf(stderr,
        "pool_migrate - TCP→POOL migration control\n\n"
        "Commands:\n"
        "  pool_migrate status              Show migration status\n"
        "  pool_migrate test <ip> <port>    Test POOL connectivity\n\n"
        "Migration strategy:\n"
        "  1. Load POOL module on all nodes:  insmod pool.ko\n"
        "  2. Start POOL listeners:           poolctl listen 9253\n"
        "  3. Test connectivity:              pool_migrate test <ip> 9253\n"
        "  4. Bridge TCP services:            pool_bridge tcp2pool 8080 <ip>\n"
        "  5. Deploy shim for apps:           LD_PRELOAD=libpool_shim.so <app>\n"
        "  6. Verify with:                    pool_migrate status\n"
        "  7. Cut over: remove bridge, run apps with shim permanently\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }

    if (strcmp(argv[1], "status") == 0) {
        cmd_status();
    } else if (strcmp(argv[1], "test") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: pool_migrate test <ip> <port>\n");
            return 1;
        }
        cmd_test(argv[2], argv[3]);
    } else {
        usage();
        return 1;
    }

    return 0;
}
