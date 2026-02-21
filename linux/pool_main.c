/*
 * pool_main.c - POOL Protocol kernel module core
 *
 * Protected Orchestrated Overlay Link (POOL) v1.0
 * Character device, ioctl dispatch, module init/exit.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/crc32.h>

#include "pool_internal.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UCK Project");
MODULE_DESCRIPTION("POOL: Protected Orchestrated Overlay Link Protocol");
MODULE_VERSION("1.0");

#define POOL_DEV_NAME "pool"

struct pool_state pool;

/* ---- Character device operations ---- */

static int pool_open(struct inode *inode, struct file *filp)
{
    return 0;
}

static int pool_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static long pool_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    /* M03: Prevent ioctl during module unload */
    if (!try_module_get(THIS_MODULE))
        return -ENODEV;

    switch (cmd) {
    case POOL_IOC_LISTEN: {
        uint16_t port;
        if (copy_from_user(&port, (void __user *)arg, sizeof(port))) {
            ret = -EFAULT; goto out_put;
        }
        ret = pool_net_listen(port);
        if (ret == 0)
            pool_discover_start();
        break;
    }
    case POOL_IOC_CONNECT: {
        struct pool_connect_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
            ret = -EFAULT; goto out_put;
        }
        ret = pool_session_connect(req.peer_addr, req.addr_family,
                                   req.peer_port);
        break;
    }
    case POOL_IOC_SEND: {
        struct pool_send_req req;
        void *kdata;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
            ret = -EFAULT; goto out_put;
        }
        if (req.len > POOL_MAX_PAYLOAD || req.len == 0) {
            ret = -EINVAL; goto out_put;
        }
        if (req.session_idx >= POOL_MAX_SESSIONS) {
            ret = -EINVAL; goto out_put;
        }
        kdata = kvmalloc(req.len, GFP_KERNEL);
        if (!kdata) {
            ret = -ENOMEM; goto out_put;
        }
        if (copy_from_user(kdata, (void __user *)req.data_ptr, req.len)) {
            kvfree(kdata);
            ret = -EFAULT; goto out_put;
        }
        ret = pool_data_send(&pool.sessions[req.session_idx],
                             req.channel, kdata, req.len);
        kvfree(kdata);
        break;
    }
    case POOL_IOC_RECV: {
        struct pool_recv_req req;
        void *kdata;
        uint32_t got;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
            ret = -EFAULT; goto out_put;
        }
        if (req.len > POOL_MAX_PAYLOAD || req.len == 0) {
            ret = -EINVAL; goto out_put;
        }
        if (req.session_idx >= POOL_MAX_SESSIONS) {
            ret = -EINVAL; goto out_put;
        }
        kdata = kvmalloc(req.len, GFP_KERNEL);
        if (!kdata) {
            ret = -ENOMEM; goto out_put;
        }
        got = req.len;
        ret = pool_data_recv(&pool.sessions[req.session_idx],
                             req.channel, kdata, &got, 5000);
        if (ret == 0) {
            if (copy_to_user((void __user *)req.data_ptr, kdata, got)) {
                kvfree(kdata);
                ret = -EFAULT; goto out_put;
            }
            req.len = got;
            if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
                kvfree(kdata);
                ret = -EFAULT; goto out_put;
            }
        }
        kvfree(kdata);
        break;
    }
    case POOL_IOC_SESSIONS: {
        struct pool_session_list list;
        struct pool_session_info *infos;
        uint32_t i, count = 0;
        if (copy_from_user(&list, (void __user *)arg, sizeof(list))) {
            ret = -EFAULT; goto out_put;
        }
        if (list.max_sessions > POOL_MAX_SESSIONS)
            list.max_sessions = POOL_MAX_SESSIONS;
        infos = kzalloc(sizeof(*infos) * list.max_sessions, GFP_KERNEL);
        if (!infos) {
            ret = -ENOMEM; goto out_put;
        }
        mutex_lock(&pool.sessions_lock);
        for (i = 0; i < POOL_MAX_SESSIONS && count < list.max_sessions; i++) {
            struct pool_session *s = &pool.sessions[i];
            if (!s->active)
                continue;
            infos[count].index = i;
            memcpy(infos[count].peer_addr, s->peer_addr, 16);
            infos[count].peer_port = s->peer_port;
            infos[count].addr_family = s->addr_family;
            infos[count].state = s->state;
            memcpy(infos[count].session_id, s->session_id, POOL_SESSION_ID_SIZE);
            infos[count].bytes_sent = s->bytes_sent;
            infos[count].bytes_recv = s->bytes_recv;
            infos[count].packets_sent = s->packets_sent;
            infos[count].packets_recv = s->packets_recv;
            infos[count].rekey_count = s->crypto.packets_since_rekey;
            memcpy(&infos[count].telemetry, &s->telemetry,
                   sizeof(struct pool_telemetry));
            count++;
        }
        mutex_unlock(&pool.sessions_lock);
        list.count = count;
        if (copy_to_user((void __user *)list.info_ptr, infos,
                         sizeof(*infos) * count)) {
            kfree(infos);
            ret = -EFAULT; goto out_put;
        }
        if (copy_to_user((void __user *)arg, &list, sizeof(list))) {
            kfree(infos);
            ret = -EFAULT; goto out_put;
        }
        kfree(infos);
        break;
    }
    case POOL_IOC_CLOSE_SESS: {
        uint32_t idx;
        if (copy_from_user(&idx, (void __user *)arg, sizeof(idx))) {
            ret = -EFAULT; goto out_put;
        }
        if (idx >= POOL_MAX_SESSIONS) {
            ret = -EINVAL; goto out_put;
        }
        pool_session_close(&pool.sessions[idx]);
        break;
    }
    case POOL_IOC_STOP:
        pool_net_stop_listen();
        break;
    case POOL_IOC_CHANNEL: {
        struct pool_channel_req creq;
        struct pool_session *s;
        if (copy_from_user(&creq, (void __user *)arg, sizeof(creq))) {
            ret = -EFAULT; goto out_put;
        }
        if (creq.session_idx >= POOL_MAX_SESSIONS) {
            ret = -EINVAL; goto out_put;
        }
        /* M02: Validate channel is within bounds */
        if (creq.channel >= POOL_MAX_CHANNELS) {
            ret = -EINVAL; goto out_put;
        }
        s = &pool.sessions[creq.session_idx];
        if (!s->active) {
            ret = -ENOENT; goto out_put;
        }
        switch (creq.operation) {
        case POOL_CHAN_SUBSCRIBE:
            s->channel_subs[creq.channel / 8] |= (1 << (creq.channel % 8));
            break;
        case POOL_CHAN_UNSUBSCRIBE:
            s->channel_subs[creq.channel / 8] &= ~(1 << (creq.channel % 8));
            break;
        case POOL_CHAN_LIST:
            if (copy_to_user((void __user *)creq.data_ptr,
                             s->channel_subs, sizeof(s->channel_subs))) {
                ret = -EFAULT; goto out_put;
            }
            creq.result = POOL_MAX_CHANNELS;
            if (copy_to_user((void __user *)arg, &creq, sizeof(creq))) {
                ret = -EFAULT; goto out_put;
            }
            break;
        default:
            ret = -EINVAL; goto out_put;
        }
        break;
    }
    default:
        ret = -ENOTTY;
    }

out_put:
    module_put(THIS_MODULE);
    return ret;
}

static const struct file_operations pool_fops = {
    .owner = THIS_MODULE,
    .open = pool_open,
    .release = pool_release,
    .unlocked_ioctl = pool_ioctl,
};

/* ---- Module init/exit ---- */

static int __init pool_init(void)
{
    int ret;

    pr_info("POOL: Protected Orchestrated Overlay Link v%d initializing\n",
            POOL_VERSION);

    memset(&pool, 0, sizeof(pool));
    mutex_init(&pool.sessions_lock);
    pool.transport_mode = POOL_TRANSPORT_AUTO;  /* try raw, fall back to TCP */

    /* Register char device */
    pool.major = register_chrdev(0, POOL_DEV_NAME, &pool_fops);
    if (pool.major < 0) {
        pr_err("POOL: failed to register chrdev: %d\n", pool.major);
        return pool.major;
    }

    /* class_create() lost the owner parameter in kernel 6.4 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    pool.dev_class = class_create(POOL_DEV_NAME);
#else
    pool.dev_class = class_create(THIS_MODULE, POOL_DEV_NAME);
#endif
    if (IS_ERR(pool.dev_class)) {
        ret = PTR_ERR(pool.dev_class);
        goto err_class;
    }

    pool.dev_device = device_create(pool.dev_class, NULL,
                                    MKDEV(pool.major, 0),
                                    NULL, POOL_DEV_NAME);
    if (IS_ERR(pool.dev_device)) {
        ret = PTR_ERR(pool.dev_device);
        goto err_device;
    }

    /* Init subsystems */
    ret = pool_crypto_init();
    if (ret)
        goto err_crypto;

    /* T1: Compute CRC32 of module .text section for tamper detection (RT-C01) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
    {
        struct module *mod = THIS_MODULE;
        if (mod->core_layout.base && mod->core_layout.text_size > 0) {
            pool.text_crc32 = crc32(0, mod->core_layout.base,
                                    mod->core_layout.text_size);
            pr_info("POOL: .text CRC32 = 0x%08x (size=%u)\n",
                    pool.text_crc32, mod->core_layout.text_size);
        }
    }
#endif

    /* Generate node identity keypair */
    ret = pool_crypto_gen_keypair(pool.node_privkey, pool.node_pubkey);
    if (ret) {
        pr_err("POOL: failed to generate node keypair\n");
        goto err_keypair;
    }

    pool.wq = alloc_workqueue("pool_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!pool.wq) {
        ret = -ENOMEM;
        goto err_keypair;
    }

    ret = pool_session_init();
    if (ret)
        goto err_session;

    ret = pool_journal_init();
    if (ret)
        goto err_journal;

    ret = pool_telemetry_init();
    if (ret)
        goto err_telemetry;

    ret = pool_sysinfo_init();
    if (ret)
        goto err_sysinfo;

    pool_config_init();
    pool_discover_init();

    pr_info("POOL: initialized, /dev/pool created (major=%d)\n", pool.major);
    return 0;

err_sysinfo:
    pool_telemetry_cleanup();
err_telemetry:
    pool_journal_cleanup();
err_journal:
    pool_session_cleanup();
err_session:
    destroy_workqueue(pool.wq);
err_keypair:
    pool_crypto_cleanup();
err_crypto:
    device_destroy(pool.dev_class, MKDEV(pool.major, 0));
err_device:
    class_destroy(pool.dev_class);
err_class:
    unregister_chrdev(pool.major, POOL_DEV_NAME);
    return ret;
}

static void __exit pool_exit(void)
{
    int i;

    pr_info("POOL: shutting down\n");

    pool_discover_stop();
    pool_net_stop_listen();
    pool_net_raw_cleanup();

    /*
     * M01: Close sessions BEFORE flushing workqueue. Flushing first
     * means pending work items reference live sessions, but those
     * sessions are about to be freed. Close sessions first so no
     * new work is generated, then flush remaining work safely.
     */
    for (i = 0; i < POOL_MAX_SESSIONS; i++) {
        if (pool.sessions[i].active)
            pool_session_close(&pool.sessions[i]);
    }

    if (pool.wq)
        flush_workqueue(pool.wq);

    pool_sysinfo_cleanup();
    pool_telemetry_cleanup();
    pool_journal_cleanup();
    pool_session_cleanup();

    if (pool.wq)
        destroy_workqueue(pool.wq);

    pool_crypto_cleanup();

    device_destroy(pool.dev_class, MKDEV(pool.major, 0));
    class_destroy(pool.dev_class);
    unregister_chrdev(pool.major, POOL_DEV_NAME);

    pr_info("POOL: unloaded\n");
}

module_init(pool_init);
module_exit(pool_exit);
