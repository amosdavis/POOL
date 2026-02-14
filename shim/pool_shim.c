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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../linux/pool.h"

/* ---- Configuration ---- */

#define POOL_SHIM_MAX_FDS    1024
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

/* ---- Intercepted functions ---- */

int socket(int domain, int type, int protocol)
{
    int fd;
    shim_init();

    fd = real_socket(domain, type, protocol);
    if (fd < 0 || !shim_enabled)
        return fd;

    /* Only intercept AF_INET TCP sockets */
    if (domain == AF_INET && (type & SOCK_STREAM)) {
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
    struct sockaddr_in *sin;
    struct pool_connect_req req;
    int pool_fd, ret;

    shim_init();
    sf = get_shim(fd);
    if (!sf || !addr || addr->sa_family != AF_INET)
        return real_connect(fd, addr, addrlen);

    sin = (struct sockaddr_in *)addr;
    if (!should_intercept_port(ntohs(sin->sin_port))) {
        SHIM_LOG("connect fd=%d port=%d not intercepted", fd, ntohs(sin->sin_port));
        return real_connect(fd, addr, addrlen);
    }

    SHIM_LOG("connect fd=%d -> %s:%d via POOL",
             fd, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));

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

    /* Ensure POOL listener is running on the remote side's expected port */
    memset(&req, 0, sizeof(req));
    req.peer_ip = ntohl(sin->sin_addr.s_addr);
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
    sf->peer_ip = ntohl(sin->sin_addr.s_addr);
    sf->peer_port = ntohs(sin->sin_port);
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

    shim_init();
    sf = get_shim(fd);

    /* For POOL-managed listeners, the kernel module handles accepts
     * internally via the listen thread. We still need the real accept
     * for the TCP side (which may be used for non-POOL connections
     * or for the bridge mode). */
    return real_accept(fd, addr, addrlen);
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
