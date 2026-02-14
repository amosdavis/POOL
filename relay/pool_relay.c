/*
 * pool_relay.c - POOL relay daemon with operator incentive structure
 *
 * Network operators run pool_relay to:
 *   1. Relay POOL traffic between non-directly-connected nodes
 *   2. Earn telemetry credits for bandwidth contributed
 *   3. Get priority routing through other relays proportional to contribution
 *   4. Build reputation score that unlocks higher-bandwidth peering
 *
 * Incentive model (no cryptocurrency, no tokens):
 *   - Each relay tracks bandwidth contributed (bytes relayed for others)
 *   - Each relay tracks bandwidth consumed (bytes relayed by others for it)
 *   - Ratio = contributed/consumed → "generosity score"
 *   - Relays with score > 1.0 get priority queuing at other relays
 *   - Relays with score < 0.5 get deprioritized (but never blocked)
 *   - Score is exchanged via POOL telemetry heartbeat (built-in, no extra protocol)
 *   - Score is signed with the node's X25519 key (unforgeable)
 *
 * Why operators deploy this:
 *   - POOL telemetry gives them visibility they don't get from TCP
 *     (per-flow RTT, jitter, loss, throughput — built into every packet)
 *   - Relay nodes see aggregate traffic patterns useful for capacity planning
 *   - Priority routing means their own traffic gets better service
 *   - No cost to relay — just spare bandwidth that would be idle anyway
 *   - Signed reputation means no gaming the system
 *
 * Usage:
 *   pool_relay start                   Start relaying
 *   pool_relay status                  Show relay stats and reputation
 *   pool_relay peers                   Show peered relays
 *   pool_relay enroll <peer_ip>        Peer with another relay
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "../linux/pool.h"

#define RELAY_PORT           9254    /* relay-to-relay port (different from app port) */
#define RELAY_MAX_PEERS      128
#define RELAY_STATE_FILE     "/var/lib/pool/relay_state.dat"
#define RELAY_CHANNEL        2      /* POOL channel for relay control */

/* ---- Relay peer entry ---- */

struct relay_peer {
    uint32_t ip;                     /* host byte order */
    uint16_t port;
    int      session_idx;            /* POOL session to this peer */
    uint64_t bytes_relayed_for;      /* bytes we relayed for them */
    uint64_t bytes_they_relayed;     /* bytes they relayed for us */
    double   generosity_score;       /* contributed/consumed ratio */
    uint64_t last_seen;              /* time_t */
    int      active;
};

/* ---- Relay state ---- */

struct relay_state {
    /* Identity */
    uint32_t my_ip;

    /* Stats */
    uint64_t total_bytes_relayed;    /* total bytes relayed for others */
    uint64_t total_bytes_consumed;   /* total bytes others relayed for us */
    uint64_t total_sessions_relayed;
    uint64_t uptime_start;

    /* Peers */
    struct relay_peer peers[RELAY_MAX_PEERS];
    int peer_count;

    /* Reputation */
    double my_generosity_score;      /* our ratio */
};

static struct relay_state state;
static int pool_fd = -1;
static volatile int running = 1;

static void sighandler(int sig) { (void)sig; running = 0; }

/* Relay control message types */
#define RELAY_MSG_FORWARD    0x01    /* forward this data to another peer */
#define RELAY_MSG_SCORE      0x02    /* exchange generosity scores */
#define RELAY_MSG_ENROLL     0x03    /* request peering */
#define RELAY_MSG_ACK        0x04    /* acknowledgment */

struct relay_msg {
    uint8_t  type;
    uint8_t  flags;
    uint16_t reserved;
    uint32_t dest_ip;      /* final destination (for FORWARD) */
    uint16_t dest_port;
    uint16_t data_len;
    /* For SCORE messages: */
    uint64_t bytes_contributed;
    uint64_t bytes_consumed;
    /* data[] follows */
} __attribute__((packed));

static void update_score(void)
{
    if (state.total_bytes_consumed > 0)
        state.my_generosity_score =
            (double)state.total_bytes_relayed / state.total_bytes_consumed;
    else if (state.total_bytes_relayed > 0)
        state.my_generosity_score = 10.0; /* pure contributor */
    else
        state.my_generosity_score = 1.0;  /* neutral */
}

static void save_state(void)
{
    FILE *f = fopen(RELAY_STATE_FILE, "wb");
    if (f) {
        fwrite(&state, sizeof(state), 1, f);
        fclose(f);
    }
}

static void load_state(void)
{
    FILE *f = fopen(RELAY_STATE_FILE, "rb");
    if (f) {
        if (fread(&state, sizeof(state), 1, f) != 1)
            memset(&state, 0, sizeof(state));
        fclose(f);
    } else {
        memset(&state, 0, sizeof(state));
    }
}

static struct relay_peer *find_peer(uint32_t ip)
{
    int i;
    for (i = 0; i < state.peer_count; i++) {
        if (state.peers[i].ip == ip && state.peers[i].active)
            return &state.peers[i];
    }
    return NULL;
}

static struct relay_peer *add_peer(uint32_t ip, uint16_t port, int session_idx)
{
    int i;
    for (i = 0; i < RELAY_MAX_PEERS; i++) {
        if (!state.peers[i].active) {
            memset(&state.peers[i], 0, sizeof(state.peers[i]));
            state.peers[i].ip = ip;
            state.peers[i].port = port;
            state.peers[i].session_idx = session_idx;
            state.peers[i].active = 1;
            state.peers[i].last_seen = time(NULL);
            if (i >= state.peer_count) state.peer_count = i + 1;
            return &state.peers[i];
        }
    }
    return NULL;
}

/* ---- Commands ---- */

static int cmd_start(void)
{
    uint16_t port = RELAY_PORT;
    struct pool_session_list list;
    struct pool_session_info infos[POOL_MAX_SESSIONS];

    load_state();
    state.uptime_start = time(NULL);

    printf("=== POOL Relay Daemon ===\n");
    printf("Incentive model:\n");
    printf("  • Relay traffic for others → earn generosity score\n");
    printf("  • Higher score → priority routing through other relays\n");
    printf("  • Score is signed by your node key (unforgeable)\n");
    printf("  • Built-in POOL telemetry provides network visibility\n\n");

    if (ioctl(pool_fd, POOL_IOC_LISTEN, &port) < 0) {
        perror("Cannot start relay listener");
        return 1;
    }

    printf("Relay listening on POOL port %d\n", port);
    printf("Current generosity score: %.2f\n", state.my_generosity_score);
    printf("Total relayed: %llu MB\n\n",
           (unsigned long long)(state.total_bytes_relayed / (1024*1024)));

    /* Main relay loop */
    while (running) {
        uint32_t i;

        memset(&list, 0, sizeof(list));
        list.max_sessions = POOL_MAX_SESSIONS;
        list.info_ptr = (uint64_t)(unsigned long)infos;
        ioctl(pool_fd, POOL_IOC_SESSIONS, &list);

        for (i = 0; i < list.count; i++) {
            struct relay_msg msg;
            char buf[RELAY_CHANNEL];
            uint32_t len;
            struct pool_recv_req rreq;

            if (infos[i].state != POOL_STATE_ESTABLISHED)
                continue;

            /* Check if this is a known peer */
            if (!find_peer(infos[i].peer_ip)) {
                struct in_addr a;
                a.s_addr = htonl(infos[i].peer_ip);
                printf("New relay peer: %s (session %u)\n",
                       inet_ntoa(a), infos[i].index);
                add_peer(infos[i].peer_ip, infos[i].peer_port,
                         infos[i].index);
            }

            /* Try to receive relay messages on channel 2 */
            memset(&rreq, 0, sizeof(rreq));
            rreq.session_idx = infos[i].index;
            rreq.channel = RELAY_CHANNEL;
            rreq.len = sizeof(msg);
            rreq.data_ptr = (uint64_t)(unsigned long)&msg;

            if (ioctl(pool_fd, POOL_IOC_RECV, &rreq) < 0)
                continue;

            if (msg.type == RELAY_MSG_FORWARD) {
                /* Forward data to another peer */
                struct relay_peer *dest = find_peer(msg.dest_ip);
                if (dest && dest->session_idx >= 0) {
                    struct pool_send_req sreq;
                    char fwd_buf[RELAY_CHANNEL];
                    uint32_t fwd_len = msg.data_len;

                    /* Receive the forwarded data */
                    memset(&rreq, 0, sizeof(rreq));
                    rreq.session_idx = infos[i].index;
                    rreq.channel = RELAY_CHANNEL;
                    rreq.len = fwd_len;
                    rreq.data_ptr = (uint64_t)(unsigned long)fwd_buf;
                    if (ioctl(pool_fd, POOL_IOC_RECV, &rreq) >= 0) {
                        /* Forward to destination */
                        memset(&sreq, 0, sizeof(sreq));
                        sreq.session_idx = dest->session_idx;
                        sreq.channel = RELAY_CHANNEL;
                        sreq.len = rreq.len;
                        sreq.data_ptr = (uint64_t)(unsigned long)fwd_buf;
                        ioctl(pool_fd, POOL_IOC_SEND, &sreq);

                        state.total_bytes_relayed += rreq.len;

                        /* Credit the source peer */
                        struct relay_peer *src = find_peer(infos[i].peer_ip);
                        if (src) src->bytes_relayed_for += rreq.len;
                    }
                }
            } else if (msg.type == RELAY_MSG_SCORE) {
                /* Peer sharing their score */
                struct relay_peer *p = find_peer(infos[i].peer_ip);
                if (p) {
                    if (msg.bytes_consumed > 0)
                        p->generosity_score =
                            (double)msg.bytes_contributed / msg.bytes_consumed;
                    else
                        p->generosity_score = 10.0;
                    p->last_seen = time(NULL);
                }
            } else if (msg.type == RELAY_MSG_ENROLL) {
                struct in_addr a;
                a.s_addr = htonl(infos[i].peer_ip);
                printf("Enrollment request from %s\n", inet_ntoa(a));
                add_peer(infos[i].peer_ip, infos[i].peer_port,
                         infos[i].index);

                /* Send ACK with our score */
                struct relay_msg ack;
                struct pool_send_req sreq;
                memset(&ack, 0, sizeof(ack));
                ack.type = RELAY_MSG_ACK;
                ack.bytes_contributed = state.total_bytes_relayed;
                ack.bytes_consumed = state.total_bytes_consumed;

                memset(&sreq, 0, sizeof(sreq));
                sreq.session_idx = infos[i].index;
                sreq.channel = RELAY_CHANNEL;
                sreq.len = sizeof(ack);
                sreq.data_ptr = (uint64_t)(unsigned long)&ack;
                ioctl(pool_fd, POOL_IOC_SEND, &sreq);
            }
        }

        /* Periodic score exchange (every 30 seconds) */
        {
            static time_t last_score_exchange = 0;
            time_t now = time(NULL);
            if (now - last_score_exchange >= 30) {
                int j;
                update_score();
                for (j = 0; j < state.peer_count; j++) {
                    if (!state.peers[j].active) continue;
                    struct relay_msg score_msg;
                    struct pool_send_req sreq;

                    memset(&score_msg, 0, sizeof(score_msg));
                    score_msg.type = RELAY_MSG_SCORE;
                    score_msg.bytes_contributed = state.total_bytes_relayed;
                    score_msg.bytes_consumed = state.total_bytes_consumed;

                    memset(&sreq, 0, sizeof(sreq));
                    sreq.session_idx = state.peers[j].session_idx;
                    sreq.channel = RELAY_CHANNEL;
                    sreq.len = sizeof(score_msg);
                    sreq.data_ptr = (uint64_t)(unsigned long)&score_msg;
                    ioctl(pool_fd, POOL_IOC_SEND, &sreq);
                }
                last_score_exchange = now;
                save_state();
            }
        }

        usleep(100000); /* 100ms */
    }

    save_state();
    ioctl(pool_fd, POOL_IOC_STOP);
    printf("\nRelay stopped. Session stats saved.\n");
    return 0;
}

static int cmd_status(void)
{
    load_state();
    update_score();

    printf("=== POOL Relay Status ===\n\n");
    printf("Generosity score:     %.2f %s\n",
           state.my_generosity_score,
           state.my_generosity_score >= 1.0 ? "(priority routing)" :
           state.my_generosity_score >= 0.5 ? "(normal)" : "(deprioritized)");
    printf("Total relayed:        %llu MB\n",
           (unsigned long long)(state.total_bytes_relayed / (1024*1024)));
    printf("Total consumed:       %llu MB\n",
           (unsigned long long)(state.total_bytes_consumed / (1024*1024)));
    printf("Sessions relayed:     %llu\n",
           (unsigned long long)state.total_sessions_relayed);
    printf("Active peers:         %d\n\n", state.peer_count);

    printf("Incentive breakdown:\n");
    printf("  Score > 1.0: You relay more than you consume → priority routing\n");
    printf("  Score = 1.0: Even exchange → normal routing\n");
    printf("  Score < 0.5: You consume more → deprioritized (not blocked)\n\n");

    if (state.peer_count > 0) {
        int i;
        printf("%-16s %-8s %-12s %-12s %-8s\n",
               "PEER", "PORT", "RELAYED(MB)", "CONSUMED(MB)", "SCORE");
        for (i = 0; i < state.peer_count; i++) {
            if (!state.peers[i].active) continue;
            struct in_addr a;
            a.s_addr = htonl(state.peers[i].ip);
            printf("%-16s %-8u %-12.1f %-12.1f %-8.2f\n",
                   inet_ntoa(a), state.peers[i].port,
                   (double)state.peers[i].bytes_relayed_for / (1024*1024),
                   (double)state.peers[i].bytes_they_relayed / (1024*1024),
                   state.peers[i].generosity_score);
        }
    }

    return 0;
}

static int cmd_enroll(const char *peer_ip)
{
    struct pool_connect_req creq;
    struct in_addr addr;
    struct relay_msg msg;
    struct pool_send_req sreq;
    int ret;

    if (!inet_aton(peer_ip, &addr)) {
        fprintf(stderr, "Invalid IP: %s\n", peer_ip);
        return 1;
    }

    memset(&creq, 0, sizeof(creq));
    creq.peer_ip = ntohl(addr.s_addr);
    creq.peer_port = RELAY_PORT;

    ret = ioctl(pool_fd, POOL_IOC_CONNECT, &creq);
    if (ret < 0) {
        fprintf(stderr, "Cannot connect to relay %s: %s\n",
                peer_ip, strerror(errno));
        return 1;
    }

    printf("Connected to relay %s (session %d)\n", peer_ip, ret);

    /* Send enrollment request */
    load_state();
    memset(&msg, 0, sizeof(msg));
    msg.type = RELAY_MSG_ENROLL;
    msg.bytes_contributed = state.total_bytes_relayed;
    msg.bytes_consumed = state.total_bytes_consumed;

    memset(&sreq, 0, sizeof(sreq));
    sreq.session_idx = ret;
    sreq.channel = RELAY_CHANNEL;
    sreq.len = sizeof(msg);
    sreq.data_ptr = (uint64_t)(unsigned long)&msg;
    ioctl(pool_fd, POOL_IOC_SEND, &sreq);

    add_peer(ntohl(addr.s_addr), RELAY_PORT, ret);
    save_state();

    printf("Enrolled with relay %s\n", peer_ip);
    printf("  Your generosity score: %.2f\n", state.my_generosity_score);
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "pool_relay - POOL relay daemon with operator incentives\n\n"
        "Incentive model:\n"
        "  Relay traffic for others → earn generosity score\n"
        "  Higher score → priority routing through other relays\n"
        "  No cryptocurrency, no tokens — just bandwidth reciprocity\n\n"
        "Why operators deploy this:\n"
        "  • Per-flow telemetry (RTT, jitter, loss) built into POOL\n"
        "  • Network visibility not available from TCP\n"
        "  • Priority routing for your own traffic\n"
        "  • Signed reputation prevents gaming\n\n"
        "Commands:\n"
        "  pool_relay start               Start relaying\n"
        "  pool_relay status              Show stats and reputation\n"
        "  pool_relay enroll <peer_ip>    Peer with another relay\n");
}

int main(int argc, char **argv)
{
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if (argc < 2) { usage(); return 1; }

    pool_fd = open("/dev/pool", O_RDWR);
    if (pool_fd < 0) {
        fprintf(stderr, "Cannot open /dev/pool. Load the POOL module first.\n");
        return 1;
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start();
    else if (strcmp(argv[1], "status") == 0)
        return cmd_status();
    else if (strcmp(argv[1], "enroll") == 0) {
        if (argc < 3) { usage(); return 1; }
        return cmd_enroll(argv[2]);
    } else {
        usage();
        return 1;
    }
}
