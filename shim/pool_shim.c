/*
 * pool_shim.c - LD_PRELOAD socket shim for POOL protocol
 *
 * Intercepts standard POSIX socket calls and transparently routes
 * TCP connections through the POOL kernel module. Existing applications
 * (curl, nginx, ssh, etc.) work unmodified.
 *
 * Usage:
 *   LD_PRELOAD=/usr/lib/libpool_shim.so curl https://example.com
 *
 * Environment variables:
 *   POOL_SHIM_ENABLE=1      Enable the shim (default: 1)
 *   POOL_SHIM_PORTS=80,443  Only intercept these destination ports (default: all)
 *   POOL_SHIM_LOG=1         Enable debug logging to stderr
 *   POOL_SHIM_LISTEN_PORT=9253  POOL listener port (default: 9253)
 *   POOL_SHIM_FALLBACK=1    Fall back to TCP if POOL fails (default: 0)
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <poll.h>

#include "../linux/pool.h"

/* ---- Configuration ---- */

#define POOL_SHIM_MAX_FDS    65536
#define POOL_SHIM_MAX_PORTS  64

/* ---- Original libc function pointers ---- */

static int (*real_socket)(int, int, int);
static int (*real_bind)(int, const struct sockaddr *, socklen_t);
static int (*real_listen)(int, int);
static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_recv)(int, void *, size_t, int);
static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_read)(int, void *, size_t);
static int (*real_close)(int);
static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
static int (*real_getsockopt)(int, int, int, void *, socklen_t *);
static int (*real_getpeername)(int, struct sockaddr *, socklen_t *);
static int (*real_getsockname)(int, struct sockaddr *, socklen_t *);
static int (*real_shutdown)(int, int);
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
static ssize_t (*real_recvmsg)(int, struct msghdr *, int);
static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_readv)(int, const struct iovec *, int);
static int (*real_fcntl)(int, int, ...);
static int (*real_poll)(struct pollfd *, nfds_t, int);
static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);

/* ---- Per-FD POOL state ---- */

struct pool_shim_fd {
    int active;             /* is this fd managed by the shim? */
    int pool_fd;            /* file descriptor for /dev/pool */
    int session_idx;        /* POOL session index (-1 if not connected) */
    int is_listener;        /* 1 if this is a listening socket */
    int real_fd;            /* the original socket fd (kept for fallback) */
    uint32_t bind_ip;       /* bound IP (host byte order) */
    uint16_t bind_port;     /* bound port */
    uint32_t peer_ip;       /* connected peer IP (host byte order) */
    uint16_t peer_port;     /* connected peer port */
    int fallback_tcp;       /* 1 if we fell back to real TCP */
    int nonblocking;        /* 1 if O_NONBLOCK is set */
    uint64_t last_validate; /* timestamp of last session validation */
};

static struct pool_shim_fd shim_fds[POOL_SHIM_MAX_FDS];
static pthread_mutex_t shim_lock = PTHREAD_MUTEX_INITIALIZER;
static int shim_enabled = -1; /* -1 = uninitialized */
static int shim_log = 0;
static int shim_fallback = 0;
static uint16_t shim_listen_port = POOL_LISTEN_PORT;
static uint16_t shim_intercept_ports[POOL_SHIM_MAX_PORTS];
static int shim_port_count = 0; /* 0 = intercept all ports */
static int shim_initialized = 0;

/* ---- Logging ---- */

#define SHIM_LOG(fmt, ...) do { \
    if (shim_log) fprintf(stderr, "[pool_shim] " fmt "\n", ##__VA_ARGS__); \
} while (0)

/* ---- Init ---- */

static void shim_init(void)
{
    const char *env;

    if (shim_initialized)
        return;

    /* Load real functions */
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_listen = dlsym(RTLD_NEXT, "listen");
    real_accept = dlsym(RTLD_NEXT, "accept");
    real_accept4 = dlsym(RTLD_NEXT, "accept4");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_write = dlsym(RTLD_NEXT, "write");
    real_read = dlsym(RTLD_NEXT, "read");
    real_close = dlsym(RTLD_NEXT, "close");
    real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    real_getpeername = dlsym(RTLD_NEXT, "getpeername");
    real_getsockname = dlsym(RTLD_NEXT, "getsockname");
    real_shutdown = dlsym(RTLD_NEXT, "shutdown");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    real_writev = dlsym(RTLD_NEXT, "writev");
    real_readv = dlsym(RTLD_NEXT, "readv");
    real_fcntl = dlsym(RTLD_NEXT, "fcntl");
    real_poll = dlsym(RTLD_NEXT, "poll");
    real_select = dlsym(RTLD_NEXT, "select");

    memset(shim_fds, 0, sizeof(shim_fds));

    /* Read configuration from environment */
    env = getenv("POOL_SHIM_ENABLE");
    shim_enabled = (!env || atoi(env) != 0) ? 1 : 0;

    env = getenv("POOL_SHIM_LOG");
    shim_log = (env && atoi(env)) ? 1 : 0;

    env = getenv("POOL_SHIM_FALLBACK");
    shim_fallback = (env && atoi(env)) ? 1 : 0;

    env = getenv("POOL_SHIM_LISTEN_PORT");
    if (env) shim_listen_port = (uint16_t)atoi(env);

    env = getenv("POOL_SHIM_PORTS");
    if (env) {
        char buf[256];
        char *tok;
        strncpy(buf, env, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        tok = strtok(buf, ",");
        while (tok && shim_port_count < POOL_SHIM_MAX_PORTS) {
            shim_intercept_ports[shim_port_count++] = (uint16_t)atoi(tok);
            tok = strtok(NULL, ",");
        }
    }

    shim_initialized = 1;
    SHIM_LOG("initialized (enabled=%d, fallback=%d, ports=%d)",
             shim_enabled, shim_fallback, shim_port_count);
}

static int should_intercept_port(uint16_t port)
{
    int i;
    if (shim_port_count == 0)
        return 1; /* intercept all */
    for (i = 0; i < shim_port_count; i++) {
        if (shim_intercept_ports[i] == port)
            return 1;
    }
    return 0;
}

static int open_pool_dev(void)
{
    int fd = open("/dev/pool", O_RDWR);
    if (fd < 0)
        SHIM_LOG("cannot open /dev/pool: %s", strerror(errno));
    return fd;
}

static struct pool_shim_fd *get_shim(int fd)
{
    if (fd < 0 || fd >= POOL_SHIM_MAX_FDS)
        return NULL;
    if (!shim_fds[fd].active)
        return NULL;
    return &shim_fds[fd];
}

/* ---- Session validation (detect stale sessions after module reload) ---- */

#include <time.h>

#define POOL_VALIDATE_TTL_SEC 1 /* validate at most once per second */

static int validate_session(struct pool_shim_fd *sf)
{
    struct pool_session_list list;
    struct pool_session_info infos[POOL_MAX_SESSIONS];
    struct timespec ts;
    uint64_t now;
    uint32_t i;

    if (sf->session_idx < 0 || sf->pool_fd < 0)
        return 0;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    now = (uint64_t)ts.tv_sec;

    if (sf->last_validate && (now - sf->last_validate) < POOL_VALIDATE_TTL_SEC)
        return 1; /* cached: still valid */

    memset(&list, 0, sizeof(list));
    list.max_sessions = POOL_MAX_SESSIONS;
    list.info_ptr = (uint64_t)(unsigned long)infos;
    if (ioctl(sf->pool_fd, POOL_IOC_SESSIONS, &list) < 0) {
        SHIM_LOG("session validation failed (ioctl error), marking stale fd=%d",
                 sf->real_fd);
        sf->session_idx = -1;
        return 0;
    }

    for (i = 0; i < list.count; i++) {
        if ((int)infos[i].index == sf->session_idx &&
            infos[i].state == POOL_STATE_ESTABLISHED) {
            sf->last_validate = now;
            return 1;
        }
    }

    SHIM_LOG("stale session detected (session_idx=%d), falling back for fd=%d",
             sf->session_idx, sf->real_fd);
    sf->session_idx = -1;
    if (shim_fallback)
        sf->fallback_tcp = 1;
    return 0;
}

/* ---- Intercepted functions ---- */

int socket(int domain, int type, int protocol)
{
    int fd;
    shim_init();

    fd = real_socket(domain, type, protocol);
    if (fd < 0 || !shim_enabled)
        return fd;

    /* Only intercept AF_INET and AF_INET6 TCP sockets */
    if ((domain == AF_INET || domain == AF_INET6) && (type & SOCK_STREAM)) {
        if (fd < POOL_SHIM_MAX_FDS) {
            pthread_mutex_lock(&shim_lock);
            memset(&shim_fds[fd], 0, sizeof(shim_fds[fd]));
            shim_fds[fd].active = 1;
            shim_fds[fd].real_fd = fd;
            shim_fds[fd].session_idx = -1;
            shim_fds[fd].pool_fd = -1;
            pthread_mutex_unlock(&shim_lock);
            SHIM_LOG("socket(%d) -> fd %d (intercepted)", domain, fd);
        }
    }
    return fd;
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct pool_shim_fd *sf;
    struct pool_connect_req req;
    int pool_fd, ret;
    uint32_t dest_ip;
    uint16_t dest_port;

    shim_init();
    sf = get_shim(fd);
    if (!sf || !addr)
        return real_connect(fd, addr, addrlen);

    /* Extract IPv4 address from AF_INET or IPv4-mapped AF_INET6 */
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        dest_ip = ntohl(sin->sin_addr.s_addr);
        dest_port = ntohs(sin->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        /* Check for IPv4-mapped IPv6 address (::ffff:x.x.x.x) */
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            /* Extract the IPv4 portion from the last 4 bytes */
            memcpy(&dest_ip, &sin6->sin6_addr.s6_addr[12], 4);
            dest_ip = ntohl(dest_ip);
            dest_port = ntohs(sin6->sin6_port);
            SHIM_LOG("IPv4-mapped IPv6 address detected, using POOL for fd=%d", fd);
        } else {
            /* Pure IPv6 — POOL doesn't support it yet, fall through to TCP */
            SHIM_LOG("pure IPv6 address, falling back to TCP for fd=%d", fd);
            return real_connect(fd, addr, addrlen);
        }
    } else {
        return real_connect(fd, addr, addrlen);
    }

    if (!should_intercept_port(dest_port)) {
        SHIM_LOG("connect fd=%d port=%d not intercepted", fd, dest_port);
        return real_connect(fd, addr, addrlen);
    }

    SHIM_LOG("connect fd=%d -> %u.%u.%u.%u:%d via POOL",
             fd, (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF,
             (dest_ip >> 8) & 0xFF, dest_ip & 0xFF, dest_port);

    /* Open /dev/pool */
    pool_fd = open_pool_dev();
    if (pool_fd < 0) {
        if (shim_fallback) {
            SHIM_LOG("fallback to TCP for fd=%d", fd);
            sf->fallback_tcp = 1;
            return real_connect(fd, addr, addrlen);
        }
        errno = ENETUNREACH;
        return -1;
    }

    /* Connect via POOL */
    memset(&req, 0, sizeof(req));
    req.peer_ip = dest_ip;
    req.peer_port = shim_listen_port;

    ret = ioctl(pool_fd, POOL_IOC_CONNECT, &req);
    if (ret < 0) {
        SHIM_LOG("POOL connect failed: %s", strerror(errno));
        real_close(pool_fd);
        if (shim_fallback) {
            sf->fallback_tcp = 1;
            return real_connect(fd, addr, addrlen);
        }
        return -1;
    }

    pthread_mutex_lock(&shim_lock);
    sf->pool_fd = pool_fd;
    sf->session_idx = ret;
    sf->peer_ip = dest_ip;
    sf->peer_port = dest_port;
    pthread_mutex_unlock(&shim_lock);

    SHIM_LOG("POOL session %d established for fd=%d", ret, fd);
    return 0;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct pool_shim_fd *sf;
    struct sockaddr_in *sin;
    int ret;

    shim_init();
    ret = real_bind(fd, addr, addrlen);
    if (ret < 0)
        return ret;

    sf = get_shim(fd);
    if (sf && addr && addr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *)addr;
        sf->bind_ip = ntohl(sin->sin_addr.s_addr);
        sf->bind_port = ntohs(sin->sin_port);
        SHIM_LOG("bind fd=%d port=%d", fd, sf->bind_port);
    }
    return ret;
}

int listen(int fd, int backlog)
{
    struct pool_shim_fd *sf;
    int ret;

    shim_init();
    ret = real_listen(fd, backlog);
    if (ret < 0)
        return ret;

    sf = get_shim(fd);
    if (sf && should_intercept_port(sf->bind_port)) {
        int pool_fd = open_pool_dev();
        if (pool_fd >= 0) {
            uint16_t port = shim_listen_port;
            if (ioctl(pool_fd, POOL_IOC_LISTEN, &port) >= 0) {
                sf->pool_fd = pool_fd;
                sf->is_listener = 1;
                SHIM_LOG("POOL listener started on port %d for fd=%d", port, fd);
            } else {
                real_close(pool_fd);
            }
        }
    }
    return ret;
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct pool_shim_fd *sf;
    int client_fd;

    shim_init();
    sf = get_shim(fd);

    /* If this is a POOL-managed listener, check for new POOL sessions */
    if (sf && sf->is_listener && sf->pool_fd >= 0) {
        struct pool_session_list list;
        struct pool_session_info infos[POOL_MAX_SESSIONS];
        uint32_t i;
        int found_session = -1;

        /* Poll for new POOL sessions */
        memset(&list, 0, sizeof(list));
        list.max_sessions = POOL_MAX_SESSIONS;
        list.info_ptr = (uint64_t)(unsigned long)infos;
        if (ioctl(sf->pool_fd, POOL_IOC_SESSIONS, &list) >= 0) {
            for (i = 0; i < list.count; i++) {
                if (infos[i].state == POOL_STATE_ESTABLISHED) {
                    /* Check if we already have a shim FD for this session */
                    int already_managed = 0, j;
                    pthread_mutex_lock(&shim_lock);
                    for (j = 0; j < POOL_SHIM_MAX_FDS; j++) {
                        if (shim_fds[j].active &&
                            shim_fds[j].session_idx == (int)infos[i].index &&
                            shim_fds[j].pool_fd == sf->pool_fd) {
                            already_managed = 1;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&shim_lock);
                    if (!already_managed) {
                        found_session = (int)infos[i].index;
                        break;
                    }
                }
            }
        }

        if (found_session >= 0) {
            /* Create a synthetic socket FD for the POOL session */
            int syn_fd = real_socket(AF_INET, SOCK_STREAM, 0);
            if (syn_fd >= 0 && syn_fd < POOL_SHIM_MAX_FDS) {
                pthread_mutex_lock(&shim_lock);
                memset(&shim_fds[syn_fd], 0, sizeof(shim_fds[syn_fd]));
                shim_fds[syn_fd].active = 1;
                shim_fds[syn_fd].real_fd = syn_fd;
                shim_fds[syn_fd].pool_fd = sf->pool_fd;
                shim_fds[syn_fd].session_idx = found_session;
                shim_fds[syn_fd].peer_ip = infos[i].peer_ip;
                shim_fds[syn_fd].peer_port = infos[i].peer_port;
                pthread_mutex_unlock(&shim_lock);

                if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
                    sin->sin_family = AF_INET;
                    sin->sin_addr.s_addr = htonl(infos[i].peer_ip);
                    sin->sin_port = htons(infos[i].peer_port);
                    *addrlen = sizeof(struct sockaddr_in);
                }

                SHIM_LOG("accept fd=%d -> POOL session %d (syn_fd=%d)",
                         fd, found_session, syn_fd);
                return syn_fd;
            } else if (syn_fd >= 0) {
                real_close(syn_fd);
            }
        }
    }

    /* Fall through to real accept for TCP connections */
    client_fd = real_accept(fd, addr, addrlen);
    if (client_fd >= 0 && client_fd < POOL_SHIM_MAX_FDS && sf && sf->is_listener) {
        /* Track accepted TCP connections for potential POOL management */
        pthread_mutex_lock(&shim_lock);
        memset(&shim_fds[client_fd], 0, sizeof(shim_fds[client_fd]));
        shim_fds[client_fd].active = 1;
        shim_fds[client_fd].real_fd = client_fd;
        shim_fds[client_fd].session_idx = -1;
        shim_fds[client_fd].pool_fd = -1;
        shim_fds[client_fd].fallback_tcp = 1;
        pthread_mutex_unlock(&shim_lock);
    }
    return client_fd;
}

int accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    shim_init();
    return real_accept4(fd, addr, addrlen, flags);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    struct pool_shim_fd *sf;
    struct pool_send_req req;

    shim_init();
    sf = get_shim(fd);

    if (!sf || sf->session_idx < 0 || sf->fallback_tcp)
        return real_send(fd, buf, len, flags);

    if (!validate_session(sf))
        return real_send(fd, buf, len, flags);

    if (sf->nonblocking) {
        /* Non-blocking: POOL send is effectively non-blocking (queues internally) */
    }

    memset(&req, 0, sizeof(req));
    req.session_idx = sf->session_idx;
    req.channel = 0;
    req.len = (uint32_t)len;
    req.data_ptr = (uint64_t)(unsigned long)buf;

    if (ioctl(sf->pool_fd, POOL_IOC_SEND, &req) < 0) {
        if (shim_fallback && !sf->fallback_tcp) {
            SHIM_LOG("POOL send failed, falling back to TCP for fd=%d", fd);
            sf->fallback_tcp = 1;
            return real_send(fd, buf, len, flags);
        }
        return -1;
    }

    return (ssize_t)len;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    struct pool_shim_fd *sf;
    struct pool_recv_req req;

    shim_init();
    sf = get_shim(fd);

    if (!sf || sf->session_idx < 0 || sf->fallback_tcp)
        return real_recv(fd, buf, len, flags);

    if (!validate_session(sf))
        return real_recv(fd, buf, len, flags);

    if (sf->nonblocking) {
        /* Non-blocking mode: if ioctl would block, return EAGAIN */
    }

    memset(&req, 0, sizeof(req));
    req.session_idx = sf->session_idx;
    req.channel = 0;
    req.len = (uint32_t)len;
    req.data_ptr = (uint64_t)(unsigned long)buf;

    if (ioctl(sf->pool_fd, POOL_IOC_RECV, &req) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -1;
        if (shim_fallback) {
            sf->fallback_tcp = 1;
            return real_recv(fd, buf, len, flags);
        }
        return -1;
    }

    return (ssize_t)req.len;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && !sf->fallback_tcp)
        return send(fd, buf, count, 0);

    return real_write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && !sf->fallback_tcp)
        return recv(fd, buf, count, 0);

    return real_read(fd, buf, count);
}

/* ---- sendmsg/recvmsg/writev/readv interception ---- */

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && !sf->fallback_tcp && msg) {
        /* Flatten the iovec into a single buffer and send via POOL */
        size_t total = 0;
        int i;
        char *flat;
        ssize_t ret;

        for (i = 0; i < (int)msg->msg_iovlen; i++)
            total += msg->msg_iov[i].iov_len;

        flat = malloc(total);
        if (!flat) { errno = ENOMEM; return -1; }

        size_t off = 0;
        for (i = 0; i < (int)msg->msg_iovlen; i++) {
            memcpy(flat + off, msg->msg_iov[i].iov_base,
                   msg->msg_iov[i].iov_len);
            off += msg->msg_iov[i].iov_len;
        }

        ret = send(fd, flat, total, flags);
        free(flat);
        return ret;
    }

    return real_sendmsg(fd, msg, flags);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && !sf->fallback_tcp && msg) {
        /* Receive into a flat buffer, then scatter to iovec */
        size_t total = 0;
        int i;
        char *flat;
        ssize_t ret;

        for (i = 0; i < (int)msg->msg_iovlen; i++)
            total += msg->msg_iov[i].iov_len;

        flat = malloc(total);
        if (!flat) { errno = ENOMEM; return -1; }

        ret = recv(fd, flat, total, flags);
        if (ret > 0) {
            size_t off = 0;
            for (i = 0; i < (int)msg->msg_iovlen && off < (size_t)ret; i++) {
                size_t chunk = msg->msg_iov[i].iov_len;
                if (chunk > (size_t)ret - off)
                    chunk = (size_t)ret - off;
                memcpy(msg->msg_iov[i].iov_base, flat + off, chunk);
                off += chunk;
            }
        }

        free(flat);
        return ret;
    }

    return real_recvmsg(fd, msg, flags);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && !sf->fallback_tcp) {
        size_t total = 0;
        int i;
        char *flat;
        ssize_t ret;

        for (i = 0; i < iovcnt; i++)
            total += iov[i].iov_len;

        flat = malloc(total);
        if (!flat) { errno = ENOMEM; return -1; }

        size_t off = 0;
        for (i = 0; i < iovcnt; i++) {
            memcpy(flat + off, iov[i].iov_base, iov[i].iov_len);
            off += iov[i].iov_len;
        }

        ret = send(fd, flat, total, 0);
        free(flat);
        return ret;
    }

    return real_writev(fd, iov, iovcnt);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && !sf->fallback_tcp) {
        size_t total = 0;
        int i;
        char *flat;
        ssize_t ret;

        for (i = 0; i < iovcnt; i++)
            total += iov[i].iov_len;

        flat = malloc(total);
        if (!flat) { errno = ENOMEM; return -1; }

        ret = recv(fd, flat, total, 0);
        if (ret > 0) {
            size_t off = 0;
            for (i = 0; i < iovcnt && off < (size_t)ret; i++) {
                size_t chunk = iov[i].iov_len;
                if (chunk > (size_t)ret - off)
                    chunk = (size_t)ret - off;
                memcpy(iov[i].iov_base, flat + off, chunk);
                off += chunk;
            }
        }

        free(flat);
        return ret;
    }

    return real_readv(fd, iov, iovcnt);
}

/* ---- fcntl interception (track O_NONBLOCK) ---- */

int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    long arg;
    int ret;
    struct pool_shim_fd *sf;

    shim_init();

    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);

    ret = real_fcntl(fd, cmd, arg);

    sf = get_shim(fd);
    if (sf) {
        if (cmd == F_SETFL) {
            sf->nonblocking = (arg & O_NONBLOCK) ? 1 : 0;
            SHIM_LOG("fcntl fd=%d O_NONBLOCK=%d", fd, sf->nonblocking);
        } else if (cmd == F_GETFL && ret >= 0 && sf->nonblocking) {
            ret |= O_NONBLOCK;
        }
    }

    return ret;
}

/* ---- poll/select interception ---- */

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct pool_shim_fd *sf;
    nfds_t i;
    int any_pool = 0;

    shim_init();

    /* Check if any FDs are POOL-managed */
    for (i = 0; i < nfds; i++) {
        sf = get_shim(fds[i].fd);
        if (sf && sf->session_idx >= 0 && !sf->fallback_tcp) {
            any_pool = 1;
            break;
        }
    }

    if (!any_pool)
        return real_poll(fds, nfds, timeout);

    /* For POOL-managed FDs, check session state directly */
    int ready = 0;
    for (i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        sf = get_shim(fds[i].fd);
        if (sf && sf->session_idx >= 0 && !sf->fallback_tcp) {
            /* POOL FD: check if data is available via ioctl */
            if (fds[i].events & POLLIN) {
                struct pool_recv_req rreq;
                char probe;
                memset(&rreq, 0, sizeof(rreq));
                rreq.session_idx = sf->session_idx;
                rreq.channel = 0;
                rreq.len = 0; /* zero-length probe */
                rreq.data_ptr = (uint64_t)(unsigned long)&probe;
                /* Non-destructive check: if EAGAIN, nothing ready */
                if (ioctl(sf->pool_fd, POOL_IOC_RECV, &rreq) >= 0 ||
                    errno != EAGAIN) {
                    fds[i].revents |= POLLIN;
                    ready++;
                }
            }
            if (fds[i].events & POLLOUT) {
                /* POOL send is always ready (kernel queues internally) */
                fds[i].revents |= POLLOUT;
                ready++;
            }
        } else {
            /* Non-POOL FD: use real poll with 0 timeout to check */
            struct pollfd pfd = fds[i];
            if (real_poll(&pfd, 1, 0) > 0) {
                fds[i].revents = pfd.revents;
                ready++;
            }
        }
    }

    /* If nothing ready and timeout > 0, retry with a short delay */
    if (ready == 0 && timeout != 0) {
        int elapsed = 0;
        int step = 10; /* 10ms polling interval */
        while (ready == 0 && (timeout < 0 || elapsed < timeout)) {
            usleep(step * 1000);
            elapsed += step;
            for (i = 0; i < nfds; i++) {
                fds[i].revents = 0;
                sf = get_shim(fds[i].fd);
                if (sf && sf->session_idx >= 0 && !sf->fallback_tcp) {
                    if (fds[i].events & POLLIN) {
                        struct pool_recv_req rreq;
                        char probe;
                        memset(&rreq, 0, sizeof(rreq));
                        rreq.session_idx = sf->session_idx;
                        rreq.channel = 0;
                        rreq.len = 0;
                        rreq.data_ptr = (uint64_t)(unsigned long)&probe;
                        if (ioctl(sf->pool_fd, POOL_IOC_RECV, &rreq) >= 0 ||
                            errno != EAGAIN) {
                            fds[i].revents |= POLLIN;
                            ready++;
                        }
                    }
                    if (fds[i].events & POLLOUT) {
                        fds[i].revents |= POLLOUT;
                        ready++;
                    }
                } else {
                    struct pollfd pfd = fds[i];
                    if (real_poll(&pfd, 1, 0) > 0) {
                        fds[i].revents = pfd.revents;
                        ready++;
                    }
                }
            }
        }
    }

    return ready;
}

int close(int fd)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf) {
        pthread_mutex_lock(&shim_lock);
        if (sf->session_idx >= 0 && sf->pool_fd >= 0) {
            uint32_t idx = sf->session_idx;
            ioctl(sf->pool_fd, POOL_IOC_CLOSE_SESS, &idx);
            SHIM_LOG("closed POOL session %d for fd=%d", idx, fd);
        }
        if (sf->is_listener && sf->pool_fd >= 0) {
            ioctl(sf->pool_fd, POOL_IOC_STOP);
        }
        if (sf->pool_fd >= 0)
            real_close(sf->pool_fd);
        sf->active = 0;
        pthread_mutex_unlock(&shim_lock);
    }

    return real_close(fd);
}

int setsockopt(int fd, int level, int optname, const void *optval,
               socklen_t optlen)
{
    shim_init();
    /* Pass through — POOL handles its own transport parameters */
    return real_setsockopt(fd, level, optname, optval, optlen);
}

int getsockopt(int fd, int level, int optname, void *optval,
               socklen_t *optlen)
{
    shim_init();
    return real_getsockopt(fd, level, optname, optval, optlen);
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && addr && addrlen &&
        *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(sf->peer_ip);
        sin->sin_port = htons(sf->peer_port);
        *addrlen = sizeof(struct sockaddr_in);
        return 0;
    }

    return real_getpeername(fd, addr, addrlen);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    shim_init();
    return real_getsockname(fd, addr, addrlen);
}

int shutdown(int fd, int how)
{
    struct pool_shim_fd *sf;

    shim_init();
    sf = get_shim(fd);

    if (sf && sf->session_idx >= 0 && sf->pool_fd >= 0) {
        uint32_t idx = sf->session_idx;
        ioctl(sf->pool_fd, POOL_IOC_CLOSE_SESS, &idx);
        SHIM_LOG("shutdown POOL session %d for fd=%d", idx, fd);
    }

    return real_shutdown(fd, how);
}

/* Constructor/destructor */
__attribute__((constructor))
static void pool_shim_ctor(void)
{
    shim_init();
}

__attribute__((destructor))
static void pool_shim_dtor(void)
{
    int i;
    for (i = 0; i < POOL_SHIM_MAX_FDS; i++) {
        if (shim_fds[i].active && shim_fds[i].pool_fd >= 0) {
            if (shim_fds[i].session_idx >= 0) {
                uint32_t idx = shim_fds[i].session_idx;
                ioctl(shim_fds[i].pool_fd, POOL_IOC_CLOSE_SESS, &idx);
            }
            real_close(shim_fds[i].pool_fd);
        }
    }
}
