/*
 * pool_sysinfo.c - POOL procfs interface
 *
 * Creates /proc/pool/ with:
 *   - status: module status and identity
 *   - sessions: active session list with stats
 *   - telemetry: per-session telemetry data
 *   - journal: change audit log
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "pool_internal.h"

/* ---- /proc/pool/status ---- */

static int pool_proc_status_show(struct seq_file *m, void *v)
{
    int i, active = 0;

    for (i = 0; i < POOL_MAX_SESSIONS; i++)
        if (pool.sessions[i].active)
            active++;

    seq_printf(m, "POOL Protocol v%d\n", POOL_VERSION);
    seq_printf(m, "Status: %s\n", pool.listening ? "listening" : "idle");
    seq_printf(m, "Listen port: %d\n", pool.listen_port);
    seq_printf(m, "Active sessions: %d / %d\n", active, POOL_MAX_SESSIONS);
    seq_printf(m, "Node pubkey: ");
    for (i = 0; i < 8; i++)
        seq_printf(m, "%02x", pool.node_pubkey[i]);
    seq_printf(m, "...\n");
    seq_printf(m, "Journal entries: %d\n", pool.journal_count);
    return 0;
}

static int pool_proc_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, pool_proc_status_show, NULL);
}

static const struct proc_ops pool_proc_status_ops = {
    .proc_open = pool_proc_status_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* ---- /proc/pool/sessions ---- */

static int pool_proc_sessions_show(struct seq_file *m, void *v)
{
    int i;
    static const char *state_names[] = {
        "IDLE", "INIT_SENT", "CHALLENGED", "ESTABLISHED", "REKEYING", "CLOSING"
    };

    seq_printf(m, "%-4s %-16s %-6s %-12s %-12s %-12s %-12s %-8s\n",
               "IDX", "PEER", "PORT", "STATE", "SENT", "RECV",
               "PKTS_SENT", "REKEYS");

    mutex_lock(&pool.sessions_lock);
    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
        struct pool_session *s = &pool.sessions[i];
        if (!s->active)
            continue;

        seq_printf(m, "%-4d %pI4h          %-6d %-12s %-12llu %-12llu %-12llu %-8u\n",
                   i, &s->peer_ip, s->peer_port,
                   (s->state < 6) ? state_names[s->state] : "UNKNOWN",
                   s->bytes_sent, s->bytes_recv,
                   s->packets_sent,
                   s->crypto.packets_since_rekey);
    }
    mutex_unlock(&pool.sessions_lock);
    return 0;
}

static int pool_proc_sessions_open(struct inode *inode, struct file *file)
{
    return single_open(file, pool_proc_sessions_show, NULL);
}

static const struct proc_ops pool_proc_sessions_ops = {
    .proc_open = pool_proc_sessions_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* ---- /proc/pool/telemetry ---- */

static int pool_proc_telemetry_show(struct seq_file *m, void *v)
{
    int i;

    seq_printf(m, "%-4s %-12s %-12s %-12s %-12s %-6s %-12s\n",
               "IDX", "RTT(us)", "JITTER(us)", "LOSS(ppm)",
               "THRU(Mbps)", "MTU", "UPTIME(s)");

    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
        struct pool_session *s = &pool.sessions[i];
        if (!s->active || s->state != POOL_STATE_ESTABLISHED)
            continue;

        seq_printf(m, "%-4d %-12llu %-12llu %-12u %-12u %-6u %-12llu\n",
                   i,
                   s->telemetry.rtt_ns / 1000,
                   s->telemetry.jitter_ns / 1000,
                   s->telemetry.loss_rate_ppm,
                   s->telemetry.throughput_bps / 1000000,
                   s->telemetry.mtu_current,
                   s->telemetry.uptime_ns / 1000000000ULL);
    }
    return 0;
}

static int pool_proc_telemetry_open(struct inode *inode, struct file *file)
{
    return single_open(file, pool_proc_telemetry_show, NULL);
}

static const struct proc_ops pool_proc_telemetry_ops = {
    .proc_open = pool_proc_telemetry_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* ---- /proc/pool/journal ---- */

static int pool_proc_journal_show(struct seq_file *m, void *v)
{
    int i;
    static const char *change_names[] = {
        "NONE", "CONNECT", "DISCONNECT", "CONFIG", "REKEY", "ERROR", "DATA"
    };

    seq_printf(m, "%-4s %-20s %-12s %-6s %-6s\n",
               "IDX", "TIMESTAMP", "TYPE", "V_BEF", "V_AFT");

    mutex_lock(&pool.journal_lock);
    for (i = 0; i < pool.journal_count; i++) {
        struct pool_journal_entry *e = &pool.journal[i];
        const char *tname = (e->change_type < 7) ?
                            change_names[e->change_type] : "UNKNOWN";
        seq_printf(m, "%-4d %-20llu %-12s %-6u %-6u\n",
                   i, e->timestamp, tname,
                   e->config_ver_before, e->config_ver_after);
    }
    mutex_unlock(&pool.journal_lock);
    return 0;
}

static int pool_proc_journal_open(struct inode *inode, struct file *file)
{
    return single_open(file, pool_proc_journal_show, NULL);
}

static const struct proc_ops pool_proc_journal_ops = {
    .proc_open = pool_proc_journal_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* ---- Init/cleanup ---- */

int pool_sysinfo_init(void)
{
    pool.proc_dir = proc_mkdir("pool", NULL);
    if (!pool.proc_dir) {
        pr_err("POOL: failed to create /proc/pool\n");
        return -ENOMEM;
    }

    pool.proc_status = proc_create("status", 0444, pool.proc_dir,
                                   &pool_proc_status_ops);
    pool.proc_sessions = proc_create("sessions", 0444, pool.proc_dir,
                                     &pool_proc_sessions_ops);
    pool.proc_telemetry = proc_create("telemetry", 0444, pool.proc_dir,
                                      &pool_proc_telemetry_ops);
    pool.proc_journal = proc_create("journal", 0444, pool.proc_dir,
                                    &pool_proc_journal_ops);

    pr_info("POOL: procfs created at /proc/pool/\n");
    return 0;
}

void pool_sysinfo_cleanup(void)
{
    if (pool.proc_journal)
        proc_remove(pool.proc_journal);
    if (pool.proc_telemetry)
        proc_remove(pool.proc_telemetry);
    if (pool.proc_sessions)
        proc_remove(pool.proc_sessions);
    if (pool.proc_status)
        proc_remove(pool.proc_status);
    if (pool.proc_dir)
        proc_remove(pool.proc_dir);
}
