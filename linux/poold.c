/*
 * poold.c - POOL Protocol daemon
 *
 * Starts the POOL listener and keeps the module active.
 * Usage: poold <port>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "pool.h"

static int pool_fd = -1;
static volatile int running = 1;

static void sighandler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    uint16_t port = POOL_LISTEN_PORT;

    if (argc > 1)
        port = (uint16_t)atoi(argv[1]);

    pool_fd = open("/dev/pool", O_RDWR);
    if (pool_fd < 0) {
        perror("open /dev/pool");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if (ioctl(pool_fd, POOL_IOC_LISTEN, &port) < 0) {
        perror("POOL_IOC_LISTEN");
        close(pool_fd);
        return 1;
    }
    printf("POOL daemon listening on port %d\n", port);

    while (running) {
        sleep(1);
    }

    printf("POOL daemon shutting down\n");
    ioctl(pool_fd, POOL_IOC_STOP);
    close(pool_fd);
    return 0;
}
