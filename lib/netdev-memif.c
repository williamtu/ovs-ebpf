// libmemif support

#include <config.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <signal.h>
#include <stdlib.h>

#include <errno.h>
#include <libmemif.h>

#include "dp-packet.h"
#include "openvswitch/vlog.h"
#include "openvswitch/types.h"
#include "openvswitch/compiler.h"
#include "netdev-provider.h"
#include "netdev-memif.h"
#include "ovs-thread.h"

/* make sure this file exists
#define MEMIF_DEFAULT_SOCKET_PATH "/run/vpp/memif.sock" 
*/
VLOG_DEFINE_THIS_MODULE(netdev_memif);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define MAX_MEMIF_BUFS  256 /* Number of buffers on a ring. */
#define MAX_MEMIF_INDEX 16  /* Max Number of memif devices. */
#define MEMIF_BUF_SIZE  2048
#define MEMIF_RING_SIZE 11
#define MEMIF_HEADROOM  256

static struct ovsthread_once memif_thread_once
    = OVSTHREAD_ONCE_INITIALIZER;

static int epfd; /* Global fd to poll memif events. */

struct netdev_rxq_memif {
    struct netdev_rxq up;
    int fd;
};

struct netdev_memif {
    struct netdev up;

    uint16_t index;
    struct eth_addr mac;
    memif_conn_handle_t handle;

    /* tx buffers */
    memif_buffer_t *tx_bufs;
    uint16_t tx_buf_num;

    /* rx buffers */
    memif_buffer_t *rx_bufs;
    uint16_t rx_buf_num;

    uint16_t seq;

    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;

    uint64_t t_sec, t_nsec;
    bool connected;
    unsigned int ifi_flags;
};

static struct netdev_memif *
netdev_memif_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_memif, up);
}

static struct netdev_rxq_memif *
netdev_rxq_memif_cast(const struct netdev_rxq *rx)
{
    return CONTAINER_OF(rx, struct netdev_rxq_memif, up);
}

static void
memif_print_details(const struct netdev *netdev)
{
    int err;
    size_t buflen;
    char *buf;
    memif_details_t md;
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    if (!dev->connected)
        return;

    buflen = MEMIF_BUF_SIZE;
    buf = xzalloc(buflen);
    VLOG_INFO("==== MEMIF Details ====");

    memset(&md, 0, sizeof md);
    err = memif_get_details(dev->handle, &md, buf, buflen);
    if (err != MEMIF_ERR_SUCCESS) {
        VLOG_ERR("memif get detail error %s", memif_strerror(err));
    }

    VLOG_INFO("interface name: %s", (char *) md.if_name);
    VLOG_INFO("remote interface name: %s", (char *) md.remote_if_name);
    VLOG_INFO("remote app name: %s", (char *) md.remote_inst_name);
    VLOG_INFO("role: %s", md.role ? "slave" : "master");

    free(buf);
}

static int
epoll_fd__(int fd, uint32_t events, int op)
{
    struct epoll_event evt;
    if (fd < 0)
    {
        VLOG_ERR("invalid fd %d", fd);
        return -1;
    }

    memset (&evt, 0, sizeof evt);
    if (op != EPOLL_CTL_DEL) { 
        evt.events = events;
        evt.data.fd = fd;
    }

    if (epoll_ctl(epfd, op, fd, &evt) < 0)
    {
        VLOG_ERR("epoll_ctl: %s fd %d", ovs_strerror(errno), fd);
        return -1;
    }

    VLOG_DBG("fd %d added to epoll", fd);
    return 0;
}

static int
add_epoll_fd(int fd, uint32_t events)
{
    VLOG_DBG("fd %d add on epoll", fd);
    return epoll_fd__(fd, events, EPOLL_CTL_ADD);
}

static int
mod_epoll_fd(int fd, uint32_t events)
{
    VLOG_DBG("fd %d modify on epoll", fd);
    return epoll_fd__(fd, events, EPOLL_CTL_MOD);
}

static int
del_epoll_fd(int fd)
{
    VLOG_DBG("fd %d remove from epoll", fd);
    return epoll_fd__(fd, 0, EPOLL_CTL_DEL);
}

static int
control_fd_update(int fd, uint8_t events, void *ctx OVS_UNUSED)
{
    uint32_t evt = 0; 

    if (events & MEMIF_FD_EVENT_DEL)
        return del_epoll_fd(fd);

    if (events & MEMIF_FD_EVENT_READ)
        evt |= EPOLLIN;
    if (events & MEMIF_FD_EVENT_WRITE)
        evt |= EPOLLOUT;

    if (events & MEMIF_FD_EVENT_MOD)
        return mod_epoll_fd(fd, evt);

    return add_epoll_fd(fd, evt);
}

static void *
memif_thread(void *f_)
{
    struct netdev *netdev = (struct netdev *)f_;
    struct epoll_event evt;
    uint32_t events;
    struct timespec start, end;
    sigset_t sigset;
    int memif_err, en;
    int timeout = -1; /* block */

    while (1) {
        events = 0;

        sigemptyset(&sigset);

        memset(&evt, 0, sizeof evt);
        evt.events = EPOLLIN | EPOLLOUT;

        VLOG_INFO_RL(&rl, "epoll pwait");
        ovsrcu_quiesce_start();
        en = epoll_pwait(epfd, &evt, 1, timeout, &sigset);

        timespec_get(&start, TIME_UTC);
        if (en < 0) {
            VLOG_INFO("epoll_pwait: %s", ovs_strerror(errno));
            return NULL;
        }

        if (en > 0) {
            if (evt.data.fd > 2) {
                if (evt.events & EPOLLIN) {
                    events |= MEMIF_FD_EVENT_READ;
                }
                if (evt.events & EPOLLOUT) {
                    events |= MEMIF_FD_EVENT_WRITE;
                }
                if (evt.events & EPOLLERR) {
                    events |= MEMIF_FD_EVENT_ERROR;
                }

                memif_err = memif_control_fd_handler(evt.data.fd, events);
                if (memif_err != MEMIF_ERR_SUCCESS) {
                    VLOG_ERR_RL(&rl, "memif_control_fd_handler: %s",
                             memif_strerror(memif_err));
                }

                VLOG_INFO_RL(&rl, "valid fd %d", evt.data.fd);
                memif_print_details(netdev);
            } else {
                VLOG_ERR_RL(&rl, "unexpected event at memif_epfd. fd %d", evt.data.fd);
            }
        }
        timespec_get(&end, TIME_UTC);
        VLOG_INFO_RL(&rl, "interrupt: %ld", end.tv_nsec - start.tv_nsec);
    }
    return NULL;
}

static int
netdev_memif_init(void)
{
    int err;

    epfd = epoll_create(1);
    add_epoll_fd(0, EPOLLIN);

    /* Make sure /run/vpp/ exists. */
    err = memif_init(control_fd_update, "ovs-memif", NULL, NULL, NULL);
    VLOG_INFO("memif init done, ret = %d", err);

    return err;
}

static void
netdev_memif_destruct(struct netdev *netdev)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    memif_print_details(netdev);

    memif_delete(dev->handle);

    /* TODO: if no more connection */
    // memif_cleanup();
}

static struct netdev *
netdev_memif_alloc(void)
{
    struct netdev_memif *dev;

    VLOG_INFO("%s", __func__);

    dev = xzalloc(sizeof *dev);
    if (dev) {
        return &dev->up;
    }
    return NULL;
}

static void
netdev_memif_dealloc(struct netdev *netdev)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    free(dev);
}

static int
on_connect(memif_conn_handle_t conn, void *private_ctx)
{
    int qid = 0;
    int memif_err = 0;
    struct netdev_memif *dev;
    struct netdev *netdev;

    netdev = (struct netdev *)private_ctx;
    dev = netdev_memif_cast(netdev);

    VLOG_INFO("memif connected!");

    memif_err = memif_refill_queue(conn, qid, -1, MEMIF_HEADROOM);
    if (memif_err != MEMIF_ERR_SUCCESS) {
        VLOG_ERR("memif_refill_queue failed: %s", memif_strerror(memif_err));
    }

    dev->connected = true;
    return 0;
}

static int
on_disconnect(memif_conn_handle_t conn OVS_UNUSED, void *private_ctx)
{
    struct netdev_memif *dev;
    struct netdev *netdev;

    netdev = (struct netdev *)private_ctx;
    dev = netdev_memif_cast(netdev);

    dev->connected = false;
    VLOG_INFO("%s disconnected!", netdev_get_name(netdev));

    return 0;
}

static void
vlog_hex_dump(char *ptr, int size) 
{
    struct ds s;
    int i;

    ds_init(&s);

    for (i = 0; i < size; i++) {
        ds_put_hex(&s, ptr++, 1);
    }
    VLOG_INFO("%s", ds_cstr(&s));
    ds_destroy(&s);
}

static int
netdev_memif_batch_send(struct netdev *netdev, int qid,
                        struct dp_packet_batch *batch,
                        bool concurrent_txq OVS_UNUSED)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);
    uint16_t allocated = 0;
    struct dp_packet *packet;
    int merr, error = 0;
    int tx_count;
    uint16_t sent;
    uint64_t tx_bytes = 0;

    if (!dev->connected) {
        goto out;
    }

    tx_count = batch->count;
    merr = memif_buffer_alloc(dev->handle, (uint16_t)qid, dev->tx_bufs,
                              tx_count, &allocated, 1024);
    if ((merr != MEMIF_ERR_SUCCESS) && (merr != MEMIF_ERR_NOBUF_RING)) {
        VLOG_ERR("%s: memif_buffer_alloc: %s", netdev_get_name(netdev),
                                               memif_strerror(merr));
        error = ENOMEM;
        goto out;
    }
    dev->tx_buf_num += allocated;

    if (allocated < tx_count) {
        VLOG_ERR("%s: not enough tx buffer: %d.", netdev_get_name(netdev),
                 allocated);
        error = ENOMEM;
        goto out;
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        char *pkt;

        pkt = (dev->tx_bufs + i)->data;
        memcpy(pkt, dp_packet_data(packet), dp_packet_size(packet));
        tx_bytes += dp_packet_size(packet);
    }

    merr = memif_tx_burst(dev->handle, qid, dev->tx_bufs,
                          dev->tx_buf_num, &sent);
    if (merr != MEMIF_ERR_SUCCESS) {
        VLOG_ERR("memif_tx_burst: %s", memif_strerror(merr));
    }

    dev->tx_buf_num -= sent;
    dev->tx_packets += sent;
    dev->tx_bytes   += tx_bytes;

out:
    dp_packet_delete_batch(batch, true);

    return error;
}

static int
netdev_memif_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch,
                      int *qfill OVS_UNUSED)
{
    struct netdev_memif *dev = netdev_memif_cast(rxq->netdev);
    uint16_t recv = 0;
    int err, qid;
    int i;

    if (!dev->connected) {
        return 0;
    }

    qid = rxq->queue_id;

    err = memif_rx_burst(dev->handle, qid, dev->rx_bufs,
                         NETDEV_MAX_BURST, &recv);
    if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF)) {
        VLOG_INFO_RL(&rl, "memif_rx_burst: %s", memif_strerror(err));
    }

    dev->rx_buf_num += recv;
    dev->rx_packets += recv;

    for (i = 0; i < recv; i++) {
        struct dp_packet *packet;
        memif_buffer_t *mif_buf;
        uint32_t len;
        void *pkt;

        mif_buf = dev->rx_bufs + i;
        pkt = mif_buf->data;
        len = mif_buf->len;
        //vlog_hex_dump((char *)pkt, 20);

        packet = dp_packet_clone_data_with_headroom(pkt, len, 256);
        dp_packet_set_size(packet, len);
        dp_packet_batch_add(batch, packet);

        VLOG_INFO_RL(&rl, "receive pkt len %d", len);
        dev->rx_bytes += len;
    }

    err = memif_refill_queue(dev->handle, qid, recv, MEMIF_HEADROOM);
    if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF)) {
        VLOG_INFO_RL(&rl, "memif_refill_queue: %s", memif_strerror(err));
    }

    if (recv > 0) {
        VLOG_INFO("netdev_memif_rxq_recv: %d packets", recv);
    }
    return 0;
}

static int
netdev_memif_construct(struct netdev *netdev)
{
    int err;
    struct netdev_memif *dev = netdev_memif_cast(netdev);
    const char *dev_name;
    uint16_t memif_dev_index;

    VLOG_INFO("%s", __func__);

    /* Set memif connection arguments. */
    memif_conn_args_t args;
    memset (&args, 0, sizeof args);

    args.is_master = true;
    args.log2_ring_size = MEMIF_RING_SIZE;
    args.buffer_size = MEMIF_BUF_SIZE;
    args.num_s2m_rings = 1; /* n_rxq */
    args.num_m2s_rings = 1; /* n_txq */
    args.mode = MEMIF_INTERFACE_MODE_ETHERNET;

    /* Interface name. */
    dev_name = netdev_get_name(netdev);
    strncpy((char *)args.interface_name, dev_name, strlen(dev_name));

    ovs_scan(dev_name, "memif%"SCNu16, &memif_dev_index);

    /* Interface index. */
    dev->index = args.interface_id = memif_dev_index;
    ovs_assert(memif_dev_index < MAX_MEMIF_INDEX);

    err = memif_create(&dev->handle, &args, on_connect, on_disconnect,
                       NULL, (void *)netdev);

    VLOG_INFO("%s memif_create %d name %s index %d",
              __func__, err, dev_name, dev->index);

    /* Allocate memif buffers. */
    dev->rx_buf_num = 0;
    dev->rx_bufs =
        (memif_buffer_t *) xzalloc(sizeof(memif_buffer_t) * MAX_MEMIF_BUFS);
    dev->tx_buf_num = 0;
    dev->tx_bufs =
        (memif_buffer_t *) xzalloc(sizeof(memif_buffer_t) * MAX_MEMIF_BUFS);

    dev->seq = 0;
    dev->connected = false;

    memif_print_details(netdev);

    if (ovsthread_once_start(&memif_thread_once)) {
        ovs_thread_create("memif_conn", memif_thread, (void *)netdev);
        ovsthread_once_done(&memif_thread_once);
    }

    return 0;
}

static int
netdev_memif_update_flags(struct netdev *netdev,
                         enum netdev_flags off, enum netdev_flags on,
                         enum netdev_flags *old_flagsp)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    /* Only support NETDEV_UP. */
    if (on & NETDEV_UP) {
        dev->ifi_flags |= NETDEV_UP;
    }
    if (off & NETDEV_UP) {
        dev->ifi_flags &= ~NETDEV_UP;
    }

    *old_flagsp = dev->ifi_flags;
    return 0;
}

static int
netdev_memif_get_etheraddr(const struct netdev *netdev OVS_UNUSED,
                           struct eth_addr *mac)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    *mac = dev->mac;
    return 0;
}

static int
netdev_memif_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    VLOG_INFO("set mac "ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
    memcpy(&dev->mac, &mac, sizeof mac);
    return 0;
}

static int
netdev_memif_rxq_construct(struct netdev_rxq *rxq)
{
    struct netdev_rxq_memif *rx OVS_UNUSED = netdev_rxq_memif_cast(rxq);
    struct netdev_memif *dev = netdev_memif_cast(rxq->netdev);

    VLOG_INFO("%s", __func__);

    /* Set rx-mode to polling. */
    memif_set_rx_mode(dev->handle, MEMIF_RX_MODE_POLLING, 0);

    return 0;
}

static void
netdev_memif_rxq_dealloc(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_memif *rx = netdev_rxq_memif_cast(rxq_);
    /* Only support single queue. */
    free(rx);
}

static struct netdev_rxq *
netdev_memif_rxq_alloc(void)
{
    struct netdev_rxq_memif *rx = xzalloc(sizeof *rx);
    /* Only support single queue. */
    return &rx->up;
}

static int
netdev_memif_get_stats(const struct netdev *netdev,
                       struct netdev_stats *stats)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    // TODO: ovs_mutex_lock(&dev->mutex);
    stats->rx_packets   += dev->rx_packets;
    stats->rx_bytes     += dev->rx_bytes;
    stats->tx_packets   += dev->tx_packets;
    stats->tx_bytes     += dev->tx_bytes;

    stats->rx_errors    += 0;
    stats->tx_errors    += 0;
    stats->rx_dropped   += 0;
    stats->tx_dropped   += 0;
    return 0;
}

static const struct netdev_class memif_class = {
    .type = "memif",
    .is_pmd = true,
    .init = netdev_memif_init,
    .construct = netdev_memif_construct,
    .destruct = netdev_memif_destruct,
    .alloc = netdev_memif_alloc,
    .dealloc = netdev_memif_dealloc,
    .update_flags = netdev_memif_update_flags,
    .get_etheraddr = netdev_memif_get_etheraddr,
    .set_etheraddr = netdev_memif_set_etheraddr, 
    .rxq_alloc = netdev_memif_rxq_alloc,
    .rxq_dealloc = netdev_memif_rxq_dealloc,
    .rxq_construct = netdev_memif_rxq_construct,
    .rxq_recv = netdev_memif_rxq_recv,
    .send = netdev_memif_batch_send,
    .get_stats = netdev_memif_get_stats,
};

void
netdev_memif_register(void)
{
    netdev_register_provider(&memif_class);
}
