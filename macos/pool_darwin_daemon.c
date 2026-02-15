/*
 * pool_darwin_daemon.c - POOL macOS/BSD Daemon
 *
 * Runs POOL as a userspace daemon on macOS and BSD systems.
 * Uses Unix domain socket for the control interface (equivalent
 * to /dev/pool on Linux).
 *
 * On macOS, can also integrate with the Network Extension framework
 * for transparent packet interception.
 *
 * Build:
 *   macOS:   clang -O2 pool_darwin_daemon.c pool_darwin_platform.c
 *            -framework Security -framework CoreFoundation -o poold
 *   FreeBSD: cc -O2 pool_darwin_daemon.c pool_darwin_platform.c
 *            -lssl -lcrypto -lpthread -o poold
 *
 * Usage:
 *   poold --foreground     Run in foreground
 *   poold --daemon         Daemonize
 *   poold --launchd        Run under launchd (macOS)
 */

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>

#include "../common/pool_proto.h"
#include "../common/pool_platform.h"

#define POOL_CTRL_SOCKET    "/var/run/pool.sock"
#define POOL_PID_FILE       "/var/run/poold.pid"
#define POOL_MAX_BSD_SESSIONS 64

/* Control command codes */
#define POOL_CMD_LISTEN     1
#define POOL_CMD_CONNECT    2
#define POOL_CMD_SEND       3
#define POOL_CMD_RECV       4
#define POOL_CMD_SESSIONS   5
#define POOL_CMD_CLOSE      6
#define POOL_CMD_STOP       7

/* Session table */
struct pool_bsd_session {
    int active;
    uint32_t peer_ip;
    uint16_t peer_port;
    pool_socket_t sock;
    uint8_t session_id[POOL_SESSION_ID_SIZE];
    uint64_t bytes_sent;
    uint64_t bytes_recv;
};

static struct pool_bsd_session g_sessions[POOL_MAX_BSD_SESSIONS];
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_running = 1;

/* Control message format */
struct pool_ctrl_msg {
    uint32_t cmd;
    uint32_t len;
    uint8_t data[4096];
};

struct pool_ctrl_resp {
    int32_t  result;
    uint32_t len;
    uint8_t  data[4096];
};

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static struct pool_bsd_session *alloc_session(void)
{
    int i;
    pthread_mutex_lock(&g_session_lock);
    for (i = 0; i < POOL_MAX_BSD_SESSIONS; i++) {
        if (!g_sessions[i].active) {
            g_sessions[i].active = 1;
            g_sessions[i].bytes_sent = 0;
            g_sessions[i].bytes_recv = 0;
            pool_crypto_random(g_sessions[i].session_id,
                               POOL_SESSION_ID_SIZE);
            pthread_mutex_unlock(&g_session_lock);
            return &g_sessions[i];
        }
    }
    pthread_mutex_unlock(&g_session_lock);
    return NULL;
}

static void free_session(struct pool_bsd_session *sess)
{
    if (sess) {
        pool_net_close(sess->sock);
        sess->active = 0;
    }
}

static void handle_ctrl_command(const struct pool_ctrl_msg *cmd,
                                ssize_t bytes_read,
                                struct pool_ctrl_resp *resp)
{
    resp->result = -1;
    resp->len = 0;

    /* D03: Validate cmd->len against bytes actually read and buffer size */
    if (bytes_read < (ssize_t)(sizeof(cmd->cmd) + sizeof(cmd->len)))
        return;
    if (cmd->len > (uint32_t)(bytes_read - offsetof(struct pool_ctrl_msg, data))) {
        pool_log_warn("control command len %u exceeds read %zd", cmd->len,
                      bytes_read);
        return;
    }
    if (cmd->len > sizeof(cmd->data)) {
        pool_log_warn("control command len %u exceeds data buffer", cmd->len);
        return;
    }

    switch (cmd->cmd) {
    case POOL_CMD_CONNECT: {
        uint32_t ip;
        uint16_t port;
        struct pool_bsd_session *sess;

        if (cmd->len < 6)
            break;
        memcpy(&ip, cmd->data, 4);
        memcpy(&port, cmd->data + 4, 2);
        ip = ntohl(ip);
        port = ntohs(port);

        sess = alloc_session();
        if (!sess)
            break;

        sess->peer_ip = ip;
        sess->peer_port = port;

        if (pool_net_tcp_connect(&sess->sock, ip, port) != 0) {
            free_session(sess);
            break;
        }

        resp->result = 0;
        memcpy(resp->data, sess->session_id, POOL_SESSION_ID_SIZE);
        resp->len = POOL_SESSION_ID_SIZE;
        pool_log_info("connected to %u.%u.%u.%u:%u",
                      (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                      (ip >> 8) & 0xFF, ip & 0xFF, port);
        break;
    }

    case POOL_CMD_SESSIONS: {
        int i, count = 0;
        pthread_mutex_lock(&g_session_lock);
        for (i = 0; i < POOL_MAX_BSD_SESSIONS; i++) {
            if (!g_sessions[i].active)
                continue;
            int off = count * 22;
            if (off + 22 > (int)sizeof(resp->data))
                break;
            memcpy(resp->data + off, g_sessions[i].session_id,
                   POOL_SESSION_ID_SIZE);
            uint32_t nip = htonl(g_sessions[i].peer_ip);
            uint16_t nport = htons(g_sessions[i].peer_port);
            memcpy(resp->data + off + 16, &nip, 4);
            memcpy(resp->data + off + 20, &nport, 2);
            count++;
        }
        pthread_mutex_unlock(&g_session_lock);
        resp->result = 0;
        resp->len = count * 22;
        break;
    }

    case POOL_CMD_CLOSE: {
        int i;
        if (cmd->len < POOL_SESSION_ID_SIZE)
            break;
        pthread_mutex_lock(&g_session_lock);
        for (i = 0; i < POOL_MAX_BSD_SESSIONS; i++) {
            if (!g_sessions[i].active)
                continue;
            if (memcmp(g_sessions[i].session_id, cmd->data,
                       POOL_SESSION_ID_SIZE) == 0) {
                free_session(&g_sessions[i]);
                resp->result = 0;
                break;
            }
        }
        pthread_mutex_unlock(&g_session_lock);
        break;
    }

    case POOL_CMD_STOP:
        g_running = 0;
        resp->result = 0;
        break;

    default:
        pool_log_warn("unknown control command: %u", cmd->cmd);
        break;
    }
}

static void *ctrl_client_thread(void *arg)
{
    int client_fd = (int)(intptr_t)arg;
    struct pool_ctrl_msg cmd;
    struct pool_ctrl_resp resp;
    ssize_t n;

    n = read(client_fd, &cmd, sizeof(cmd));
    if (n >= (ssize_t)(sizeof(cmd.cmd) + sizeof(cmd.len))) {
        handle_ctrl_command(&cmd, n, &resp);
        write(client_fd, &resp, sizeof(resp));
    }

    close(client_fd);
    return NULL;
}

static int run_ctrl_loop(int ctrl_fd)
{
    struct timeval tv;
    fd_set fds;

    pool_log_info("POOL daemon started, control socket: %s", POOL_CTRL_SOCKET);

    while (g_running) {
        FD_ZERO(&fds);
        FD_SET(ctrl_fd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(ctrl_fd + 1, &fds, NULL, NULL, &tv) > 0) {
            struct sockaddr_un addr;
            socklen_t addrlen = sizeof(addr);
            int client_fd = accept(ctrl_fd, (struct sockaddr *)&addr, &addrlen);
            if (client_fd >= 0) {
                pthread_t tid;
                pthread_create(&tid, NULL, ctrl_client_thread,
                               (void *)(intptr_t)client_fd);
                pthread_detach(tid);
            }
        }
    }

    /* Cleanup sessions */
    int i;
    pthread_mutex_lock(&g_session_lock);
    for (i = 0; i < POOL_MAX_BSD_SESSIONS; i++) {
        if (g_sessions[i].active)
            free_session(&g_sessions[i]);
    }
    pthread_mutex_unlock(&g_session_lock);

    close(ctrl_fd);
    unlink(POOL_CTRL_SOCKET);
    pool_log_info("POOL daemon stopped");
    return 0;
}

static int create_ctrl_socket(void)
{
    struct sockaddr_un addr;
    int fd;

    unlink(POOL_CTRL_SOCKET);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        pool_log_error("failed to create control socket: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, POOL_CTRL_SOCKET, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        pool_log_error("bind %s failed: %s", POOL_CTRL_SOCKET, strerror(errno));
        close(fd);
        return -1;
    }

    chmod(POOL_CTRL_SOCKET, 0660);

    if (listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    if (setsid() < 0)
        exit(EXIT_FAILURE);

    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Write PID file */
    FILE *fp = fopen(POOL_PID_FILE, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    }
}

int main(int argc, char *argv[])
{
    int do_daemon = 0;
    int ctrl_fd;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--daemon") == 0 || strcmp(argv[i], "-d") == 0)
            do_daemon = 1;
        else if (strcmp(argv[i], "--foreground") == 0 || strcmp(argv[i], "-f") == 0)
            do_daemon = 0;
        else if (strcmp(argv[i], "--launchd") == 0)
            do_daemon = 0;  /* launchd manages lifecycle */
        else {
            fprintf(stderr, "Usage: %s [--foreground|--daemon|--launchd]\n",
                    argv[0]);
            return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    memset(g_sessions, 0, sizeof(g_sessions));

    if (do_daemon)
        daemonize();

    ctrl_fd = create_ctrl_socket();
    if (ctrl_fd < 0)
        return 1;

    return run_ctrl_loop(ctrl_fd);
}

#endif /* __APPLE__ || __FreeBSD__ || ... */
