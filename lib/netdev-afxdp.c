/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "netdev-linux-private.h"
#include "netdev-linux.h"
#include "netdev-afxdp.h"

#include <errno.h>
#include <inttypes.h>
#include <linux/rtnetlink.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "dp-packet.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "socket-util.h"
#include "spinlock.h"
#include "util.h"
#include "xdpsock.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

VLOG_DEFINE_THIS_MODULE(netdev_afxdp);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define UMEM2DESC(elem, base) ((uint64_t)((char *)elem - (char *)base))
#define UMEM2XPKT(base, i) \
                  ALIGNED_CAST(struct dp_packet_afxdp *, (char *)base + \
                               i * sizeof(struct dp_packet_afxdp))

static struct xsk_socket_info *xsk_configure(int ifindex, int xdp_queue_id,
                                             int mode);
static void xsk_remove_xdp_program(uint32_t ifindex, int xdpmode);
static void xsk_destroy(struct xsk_socket_info *xsk);
static int xsk_configure_all(struct netdev *netdev);
static void xsk_destroy_all(struct netdev *netdev);

static struct xsk_umem_info *
xsk_configure_umem(void *buffer, uint64_t size, int xdpmode)
{
    struct xsk_umem_config uconfig OVS_UNUSED;
    struct xsk_umem_info *umem;
    int ret;
    int i;

    umem = xcalloc(1, sizeof *umem);
    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                           NULL);
    if (ret) {
        VLOG_ERR("xsk_umem__create failed (%s) mode: %s",
                 ovs_strerror(errno),
                 xdpmode == XDP_COPY ? "SKB": "DRV");
        free(umem);
        return NULL;
    }

    umem->buffer = buffer;

    /* set-up umem pool */
    if (umem_pool_init(&umem->mpool, NUM_FRAMES) < 0) {
        VLOG_ERR("umem_pool_init failed");
        if (xsk_umem__delete(umem->umem)) {
            VLOG_ERR("xsk_umem__delete failed");
        }
        free(umem);
        return NULL;
    }

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        struct umem_elem *elem;

        elem = ALIGNED_CAST(struct umem_elem *,
                            (char *)umem->buffer + i * FRAME_SIZE);
        umem_elem_push(&umem->mpool, elem);
    }

    /* set-up metadata */
    if (xpacket_pool_init(&umem->xpool, NUM_FRAMES) < 0) {
        VLOG_ERR("xpacket_pool_init failed");
        umem_pool_cleanup(&umem->mpool);
        if (xsk_umem__delete(umem->umem)) {
            VLOG_ERR("xsk_umem__delete failed");
        }
        free(umem);
        return NULL;
    }

    VLOG_DBG("%s xpacket pool from %p to %p", __func__,
              umem->xpool.array,
              (char *)umem->xpool.array +
              NUM_FRAMES * sizeof(struct dp_packet_afxdp));

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        struct dp_packet_afxdp *xpacket;
        struct dp_packet *packet;

        xpacket = UMEM2XPKT(umem->xpool.array, i);
        xpacket->mpool = &umem->mpool;

        packet = &xpacket->packet;
        packet->source = DPBUF_AFXDP;
    }

    return umem;
}

static struct xsk_socket_info *
xsk_configure_socket(struct xsk_umem_info *umem, uint32_t ifindex,
                     uint32_t queue_id, int xdpmode)
{
    struct xsk_socket_config cfg;
    struct xsk_socket_info *xsk;
    char devname[IF_NAMESIZE];
    uint32_t idx = 0, prog_id;
    int ret;
    int i;

    xsk = xcalloc(1, sizeof(*xsk));
    xsk->umem = umem;
    cfg.rx_size = CONS_NUM_DESCS;
    cfg.tx_size = PROD_NUM_DESCS;
    cfg.libbpf_flags = 0;

    if (xdpmode == XDP_ZEROCOPY) {
        cfg.bind_flags = XDP_ZEROCOPY;
        cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    } else {
        cfg.bind_flags = XDP_COPY;
        cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
    }

    if (if_indextoname(ifindex, devname) == NULL) {
        VLOG_ERR("ifindex %d to devname failed (%s)",
                 ifindex, ovs_strerror(errno));
        free(xsk);
        return NULL;
    }

    ret = xsk_socket__create(&xsk->xsk, devname, queue_id, umem->umem,
                             &xsk->rx, &xsk->tx, &cfg);
    if (ret) {
        VLOG_ERR("xsk_socket__create failed (%s) mode: %s qid: %d",
                 ovs_strerror(errno),
                 xdpmode == XDP_COPY ? "SKB": "DRV",
                 queue_id);
        free(xsk);
        return NULL;
    }

    /* Make sure the built-in AF_XDP program is loaded */
    ret = bpf_get_link_xdp_id(ifindex, &prog_id, cfg.xdp_flags);
    if (ret) {
        VLOG_ERR("Get XDP prog ID failed (%s)", ovs_strerror(errno));
        xsk_socket__delete(xsk->xsk);
        free(xsk);
        return NULL;
    }

    /* Populate (PROD_NUM_DESCS - BATCH_SIZE) elems to the FILL queue */
    while (!xsk_ring_prod__reserve(&xsk->umem->fq,
                                   PROD_NUM_DESCS - BATCH_SIZE, &idx)) {
        VLOG_WARN_RL(&rl, "Retry xsk_ring_prod__reserve to FILL queue");
    }

    for (i = 0;
         i < (PROD_NUM_DESCS - BATCH_SIZE) * FRAME_SIZE;
         i += FRAME_SIZE) {
        struct umem_elem *elem;
        uint64_t addr;

        elem = umem_elem_pop(&xsk->umem->mpool);
        addr = UMEM2DESC(elem, xsk->umem->buffer);

        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = addr;
    }

    xsk_ring_prod__submit(&xsk->umem->fq,
                          PROD_NUM_DESCS - BATCH_SIZE);
    return xsk;
}

static struct xsk_socket_info *
xsk_configure(int ifindex, int xdp_queue_id, int xdpmode)
{
    struct xsk_socket_info *xsk;
    struct xsk_umem_info *umem;
    void *bufs;

    /* umem memory region */
    bufs = xmalloc_pagealign(NUM_FRAMES * FRAME_SIZE);
    memset(bufs, 0, NUM_FRAMES * FRAME_SIZE);

    /* create AF_XDP socket */
    umem = xsk_configure_umem(bufs,
                              NUM_FRAMES * FRAME_SIZE,
                              xdpmode);
    if (!umem) {
        free_pagealign(bufs);
        return NULL;
    }

    xsk = xsk_configure_socket(umem, ifindex, xdp_queue_id, xdpmode);
    if (!xsk) {
        /* clean up umem and xpacket pool */
        if (xsk_umem__delete(umem->umem)) {
            VLOG_ERR("xsk_umem__delete failed");
        }
        free_pagealign(bufs);
        umem_pool_cleanup(&umem->mpool);
        xpacket_pool_cleanup(&umem->xpool);
        free(umem);
    }
    return xsk;
}

static int
xsk_configure_all(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    int i, ifindex, n_rxq;

    ifindex = linux_get_ifindex(netdev_get_name(netdev));

    n_rxq = netdev_n_rxq(netdev);
    dev->xsks = xzalloc(n_rxq * sizeof(struct xsk_socket_info *));

    /* configure each queue */
    for (i = 0; i < n_rxq; i++) {
        VLOG_INFO("%s configure queue %d mode %s", __func__, i,
                  dev->xdpmode == XDP_COPY ? "SKB" : "DRV");
        xsk_info = xsk_configure(ifindex, i, dev->xdpmode);
        if (!xsk_info) {
            VLOG_ERR("failed to create AF_XDP socket on queue %d", i);
            dev->xsks[i] = NULL;
            goto err;
        }
        dev->xsks[i] = xsk_info;
        xsk_info->rx_dropped = 0;
        xsk_info->tx_dropped = 0;
    }

    return 0;

err:
    xsk_destroy_all(netdev);
    return EINVAL;
}

static void
xsk_destroy(struct xsk_socket_info *xsk_info)
{
    struct xsk_umem *umem;

    xsk_socket__delete(xsk_info->xsk);
    xsk_info->xsk = NULL;

    umem = xsk_info->umem->umem;
    if (xsk_umem__delete(umem)) {
        VLOG_ERR("xsk_umem__delete failed");
    }

    /* free the packet buffer */
    free_pagealign(xsk_info->umem->buffer);

    /* cleanup umem pool */
    umem_pool_cleanup(&xsk_info->umem->mpool);

    /* cleanup metadata pool */
    xpacket_pool_cleanup(&xsk_info->umem->xpool);

    free(xsk_info->umem);
    free(xsk_info);
}

static void
xsk_destroy_all(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int i, ifindex;

    ifindex = linux_get_ifindex(netdev_get_name(netdev));

    for (i = 0; i < netdev_n_rxq(netdev); i++) {
        if (dev->xsks && dev->xsks[i]) {
            VLOG_INFO("destroy xsk[%d]", i);
            xsk_destroy(dev->xsks[i]);
            dev->xsks[i] = NULL;
        }
    }

    VLOG_INFO("remove xdp program");
    xsk_remove_xdp_program(ifindex, dev->xdpmode);

    free(dev->xsks);
}

static inline void OVS_UNUSED
log_xsk_stat(struct xsk_socket_info *xsk OVS_UNUSED) {
    struct xdp_statistics stat;
    socklen_t optlen;

    optlen = sizeof stat;
    ovs_assert(getsockopt(xsk_socket__fd(xsk->xsk), SOL_XDP, XDP_STATISTICS,
               &stat, &optlen) == 0);

    VLOG_DBG_RL(&rl, "rx dropped %llu, rx_invalid %llu, tx_invalid %llu",
                stat.rx_dropped,
                stat.rx_invalid_descs,
                stat.tx_invalid_descs);
}

int
netdev_afxdp_set_config(struct netdev *netdev, const struct smap *args,
                        char **errp OVS_UNUSED)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    const char *str_xdpmode;
    int xdpmode, new_n_rxq;

    ovs_mutex_lock(&dev->mutex);
    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq > MAX_XSKQ) {
        ovs_mutex_unlock(&dev->mutex);
        VLOG_ERR("%s: Too big 'n_rxq' (%d > %d).",
                 netdev_get_name(netdev), new_n_rxq, MAX_XSKQ);
        return EINVAL;
    }

    str_xdpmode = smap_get_def(args, "xdpmode", "skb");
    if (!strcasecmp(str_xdpmode, "drv")) {
        xdpmode = XDP_ZEROCOPY;
    } else if (!strcasecmp(str_xdpmode, "skb")) {
        xdpmode = XDP_COPY;
    } else {
        VLOG_ERR("%s: Incorrect xdpmode (%s).",
                 netdev_get_name(netdev), str_xdpmode);
        ovs_mutex_unlock(&dev->mutex);
        return EINVAL;
    }

    if (dev->requested_n_rxq != new_n_rxq
        || dev->requested_xdpmode != xdpmode) {
        dev->requested_n_rxq = new_n_rxq;
        dev->requested_xdpmode = xdpmode;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

int
netdev_afxdp_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    smap_add_format(args, "n_rxq", "%d", netdev->n_rxq);
    smap_add_format(args, "xdpmode", "%s",
        dev->xdp_bind_flags == XDP_ZEROCOPY ? "drv" : "skb");
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

static void
netdev_afxdp_alloc_txq(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int n_txqs = netdev_n_rxq(netdev);
    int i;

    dev->tx_locks = xmalloc(n_txqs * sizeof(struct ovs_spinlock));

    for (i = 0; i < n_txqs; i++) {
        ovs_spinlock_init(&dev->tx_locks[i]);
    }
}

int
netdev_afxdp_reconfigure(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int err = 0;

    ovs_mutex_lock(&dev->mutex);

    if (netdev->n_rxq == dev->requested_n_rxq
        && dev->xdpmode == dev->requested_xdpmode) {
        goto out;
    }

    xsk_destroy_all(netdev);
    free(dev->tx_locks);

    netdev->n_rxq = dev->requested_n_rxq;
    netdev_afxdp_alloc_txq(netdev);

    if (dev->requested_xdpmode == XDP_ZEROCOPY) {
        VLOG_INFO("AF_XDP device %s in DRV mode", netdev_get_name(netdev));
        /* From SKB mode to DRV mode */
        dev->xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
        dev->xdp_bind_flags = XDP_ZEROCOPY;
        dev->xdpmode = XDP_ZEROCOPY;

        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
            VLOG_ERR("ERROR: setrlimit(RLIMIT_MEMLOCK): %s",
                      ovs_strerror(errno));
        }
    } else {
        VLOG_INFO("AF_XDP device %s in SKB mode", netdev_get_name(netdev));
        /* From DRV mode to SKB mode */
        dev->xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
        dev->xdp_bind_flags = XDP_COPY;
        dev->xdpmode = XDP_COPY;
        /* TODO: set rlimit back to previous value
         * when no device is in DRV mode.
         */
    }

    err = xsk_configure_all(netdev);
    if (err) {
        VLOG_ERR("AF_XDP device %s reconfig fails", netdev_get_name(netdev));
    }
    netdev_change_seq_changed(netdev);
out:
    ovs_mutex_unlock(&dev->mutex);
    return err;
}

int
netdev_afxdp_get_numa_id(const struct netdev *netdev)
{
    /* FIXME: Get netdev's PCIe device ID, then find
     * its NUMA node id.
     */
    VLOG_INFO("FIXME: Device %s always use numa id 0",
              netdev_get_name(netdev));
    return 0;
}

static void
xsk_remove_xdp_program(uint32_t ifindex, int xdpmode)
{
    uint32_t prog_id = 0;
    uint32_t flags;

    /* remove_xdp_program() */
    if (xdpmode == XDP_COPY) {
        flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
        VLOG_INFO("%s copy mode", __func__);
    } else {
        flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
        VLOG_INFO("%s drv mode", __func__);
    }

    if (bpf_get_link_xdp_id(ifindex, &prog_id, flags)) {
        VLOG_WARN("get xdp program id fails");
    }
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
}

void
signal_remove_xdp(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int ifindex;

    ifindex = linux_get_ifindex(netdev_get_name(netdev));

    VLOG_WARN("force remove xdp program");
    xsk_remove_xdp_program(ifindex, dev->xdpmode);
}

static struct dp_packet_afxdp *
dp_packet_cast_afxdp(const struct dp_packet *d)
{
    ovs_assert(d->source == DPBUF_AFXDP);
    return CONTAINER_OF(d, struct dp_packet_afxdp, packet);
}

static inline void
prepare_fill_queue(struct xsk_socket_info *xsk_info)
{
    struct umem_elem *elems[BATCH_SIZE];
    struct xsk_umem_info *umem;
    unsigned int idx_fq;
    int nb_free;
    int i, ret;

    umem = xsk_info->umem;

    nb_free = PROD_NUM_DESCS / 2;
    if (xsk_prod_nb_free(&umem->fq, nb_free) < nb_free) {
        return;
    }

    ret = umem_elem_pop_n(&umem->mpool, BATCH_SIZE, (void **)elems);
    if (OVS_UNLIKELY(ret)) {
        return;
    }

    if (!xsk_ring_prod__reserve(&umem->fq, BATCH_SIZE, &idx_fq)) {
        umem_elem_push_n(&umem->mpool, BATCH_SIZE, (void **)elems);
        return;
    }

    for (i = 0; i < BATCH_SIZE; i++) {
        uint64_t index;
        struct umem_elem *elem;

        elem = elems[i];
        index = (uint64_t)((char *)elem - (char *)umem->buffer);
        ovs_assert((index & FRAME_SHIFT_MASK) == 0);
        *xsk_ring_prod__fill_addr(&umem->fq, idx_fq) = index;

        idx_fq++;
    }
    xsk_ring_prod__submit(&umem->fq, BATCH_SIZE);
}

int
netdev_afxdp_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet_batch *batch,
                      int *qfill)
{
    struct netdev_rxq_linux *rx = netdev_rxq_linux_cast(rxq_);
    struct netdev *netdev = rx->up.netdev;
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    struct xsk_umem_info *umem;
    uint32_t idx_rx = 0;
    int qid = rxq_->queue_id;
    unsigned int rcvd, i;

    xsk_info = dev->xsks[qid];
    if (!xsk_info || !xsk_info->xsk) {
        return 0;
    }

    prepare_fill_queue(xsk_info);

    umem = xsk_info->umem;
    rx->fd = xsk_socket__fd(xsk_info->xsk);

    rcvd = xsk_ring_cons__peek(&xsk_info->rx, BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        return 0;
    }

    /* Setup a dp_packet batch from descriptors in RX queue */
    for (i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->len;
        char *pkt = xsk_umem__get_data(umem->buffer, addr);
        uint64_t index;

        struct dp_packet_afxdp *xpacket;
        struct dp_packet *packet;

        index = addr >> FRAME_SHIFT;
        xpacket = UMEM2XPKT(umem->xpool.array, index);
        packet = &xpacket->packet;

        /* Initialize the struct dp_packet */
        dp_packet_use_afxdp(packet, pkt, FRAME_SIZE - FRAME_HEADROOM);
        dp_packet_set_size(packet, len);

        /* Add packet into batch, increase batch->count */
        dp_packet_batch_add(batch, packet);

        idx_rx++;
    }
    /* Release the RX queue */
    xsk_ring_cons__release(&xsk_info->rx, rcvd);

    if (qfill) {
        /* TODO: return the number of remaining packets in the queue. */
        *qfill = 0;
    }

#ifdef AFXDP_DEBUG
    log_xsk_stat(xsk_info);
#endif
    return 0;
}

static inline int
kick_tx(struct xsk_socket_info *xsk_info)
{
    int ret;

    if (!xsk_info->outstanding_tx) {
        return 0;
    }

    /* This causes system call into kernel's xsk_sendmsg, and
     * xsk_generic_xmit (skb mode) or xsk_async_xmit (driver mode).
     */
    ret = sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (OVS_UNLIKELY(ret < 0)) {
        if (errno == ENXIO || errno == ENOBUFS || errno == EOPNOTSUPP) {
            return errno;
        }
    }
    /* no error, or EBUSY or EAGAIN */
    return 0;
}

void
free_afxdp_buf(struct dp_packet *p)
{
    struct dp_packet_afxdp *xpacket;
    uintptr_t addr;

    xpacket = dp_packet_cast_afxdp(p);
    if (xpacket->mpool) {
        void *base = dp_packet_base(p);

        addr = (uintptr_t)base & (~FRAME_SHIFT_MASK);
        umem_elem_push(xpacket->mpool, (void *)addr);
    }
}

static void
free_afxdp_buf_batch(struct dp_packet_batch *batch)
{
    struct dp_packet_afxdp *xpacket = NULL;
    struct dp_packet *packet;
    void *elems[BATCH_SIZE];
    uintptr_t addr;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        xpacket = dp_packet_cast_afxdp(packet);
        if (xpacket->mpool) {
            void *base = dp_packet_base(packet);

            addr = (uintptr_t)base & (~FRAME_SHIFT_MASK);
            elems[i] = (void *)addr;
        }
    }
    umem_elem_push_n(xpacket->mpool, batch->count, elems);
    dp_packet_batch_init(batch);
}

static inline bool
check_free_batch(struct dp_packet_batch *batch)
{
    struct umem_pool *first_mpool = NULL;
    struct dp_packet_afxdp *xpacket;
    struct dp_packet *packet;

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        if (packet->source != DPBUF_AFXDP) {
            return false;
        }
        xpacket = dp_packet_cast_afxdp(packet);
        if (i == 0) {
            first_mpool = xpacket->mpool;
            continue;
        }
        if (xpacket->mpool != first_mpool) {
            return false;
        }
    }
    /* All packets are DPBUF_AFXDP and from the same mpool */
    return true;
}

static inline void
afxdp_complete_tx(struct xsk_socket_info *xsk_info)
{
    struct umem_elem *elems_push[BATCH_SIZE];
    struct xsk_umem_info *umem;
    uint32_t idx_cq = 0;
    int tx_to_free = 0;
    int tx_done, j;

    umem = xsk_info->umem;
    tx_done = xsk_ring_cons__peek(&umem->cq, BATCH_SIZE, &idx_cq);

    /* Recycle back to umem pool */
    for (j = 0; j < tx_done; j++) {
        struct umem_elem *elem;
        uint64_t *addr;

        addr = (uint64_t *)xsk_ring_cons__comp_addr(&umem->cq, idx_cq++);
        if (*addr == 0) {
            /* The elem has been pushed already */
            continue;
        }
        elem = ALIGNED_CAST(struct umem_elem *,
                            (char *)umem->buffer + *addr);
        elems_push[tx_to_free] = elem;
        *addr = 0; /* Mark as pushed */
        tx_to_free++;
    }

    umem_elem_push_n(&umem->mpool, tx_to_free, (void **)elems_push);

    if (tx_done > 0) {
        xsk_ring_cons__release(&umem->cq, tx_done);
        xsk_info->outstanding_tx -= tx_done;
    }
}

int
netdev_afxdp_batch_send(struct netdev *netdev, int qid,
                        struct dp_packet_batch *batch,
                        bool concurrent_txq)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info = dev->xsks[qid];
    struct umem_elem *elems_pop[BATCH_SIZE];
    struct xsk_umem_info *umem;
    struct dp_packet *packet;
    bool free_batch = true;
    uint32_t idx = 0;
    int error = 0;
    int ret;

    if (OVS_UNLIKELY(concurrent_txq)) {
        qid = qid % dev->up.n_txq;
        ovs_spin_lock(&dev->tx_locks[qid]);
    }

    if (!xsk_info || !xsk_info->xsk) {
        goto out;
    }

    afxdp_complete_tx(xsk_info);

    free_batch = check_free_batch(batch);

    umem = xsk_info->umem;
    ret = umem_elem_pop_n(&umem->mpool, batch->count, (void **)elems_pop);
    if (OVS_UNLIKELY(ret)) {
        xsk_info->tx_dropped += batch->count;
        error = ENOMEM;
        goto out;
    }

    /* Make sure we have enough TX descs */
    ret = xsk_ring_prod__reserve(&xsk_info->tx, batch->count, &idx);
    if (OVS_UNLIKELY(ret == 0)) {
        umem_elem_push_n(&umem->mpool, batch->count, (void **)elems_pop);
        xsk_info->tx_dropped += batch->count;
        error = ENOMEM;
        goto out;
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct umem_elem *elem;
        uint64_t index;

        elem = elems_pop[i];
        /* Copy the packet to the umem we just pop from umem pool.
         * TODO: avoid this copy if the packet and the pop umem
         * are located in the same umem.
         */
        memcpy(elem, dp_packet_data(packet), dp_packet_size(packet));

        index = (uint64_t)((char *)elem - (char *)umem->buffer);
        xsk_ring_prod__tx_desc(&xsk_info->tx, idx + i)->addr = index;
        xsk_ring_prod__tx_desc(&xsk_info->tx, idx + i)->len
            = dp_packet_size(packet);
    }
    xsk_ring_prod__submit(&xsk_info->tx, batch->count);
    xsk_info->outstanding_tx += batch->count;

    ret = kick_tx(xsk_info);
    if (OVS_UNLIKELY(ret)) {
        VLOG_WARN_RL(&rl, "error sending AF_XDP packet: %s",
                     ovs_strerror(ret));
    }

out:
    if (free_batch) {
        free_afxdp_buf_batch(batch);
    } else {
        dp_packet_delete_batch(batch, true);
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        ovs_spin_unlock(&dev->tx_locks[qid]);
    }
    return error;
}

int
netdev_afxdp_rxq_construct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
   /* Done at reconfigure */
   return 0;
}

void
netdev_afxdp_destruct(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);

    /* Note: tc is by-passed when using drv-mode, but when using
     * skb-mode, we might need to clean up tc. */

    xsk_destroy_all(netdev_);
    ovs_mutex_destroy(&netdev->mutex);
}

int
netdev_afxdp_get_stats(const struct netdev *netdev,
                       struct netdev_stats *stats)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk_info;
    struct netdev_stats dev_stats;
    int error, i;

    ovs_mutex_lock(&dev->mutex);

    error = get_stats_via_netlink(netdev, &dev_stats);
    if (error) {
        VLOG_WARN_RL(&rl, "Error getting AF_XDP statistics");
    } else {
        /* Use kernel netdev's packet and byte counts */
        stats->rx_packets = dev_stats.rx_packets;
        stats->rx_bytes = dev_stats.rx_bytes;
        stats->tx_packets = dev_stats.tx_packets;
        stats->tx_bytes = dev_stats.tx_bytes;

        stats->rx_errors           += dev_stats.rx_errors;
        stats->tx_errors           += dev_stats.tx_errors;
        stats->rx_dropped          += dev_stats.rx_dropped;
        stats->tx_dropped          += dev_stats.tx_dropped;
        stats->multicast           += dev_stats.multicast;
        stats->collisions          += dev_stats.collisions;
        stats->rx_length_errors    += dev_stats.rx_length_errors;
        stats->rx_over_errors      += dev_stats.rx_over_errors;
        stats->rx_crc_errors       += dev_stats.rx_crc_errors;
        stats->rx_frame_errors     += dev_stats.rx_frame_errors;
        stats->rx_fifo_errors      += dev_stats.rx_fifo_errors;
        stats->rx_missed_errors    += dev_stats.rx_missed_errors;
        stats->tx_aborted_errors   += dev_stats.tx_aborted_errors;
        stats->tx_carrier_errors   += dev_stats.tx_carrier_errors;
        stats->tx_fifo_errors      += dev_stats.tx_fifo_errors;
        stats->tx_heartbeat_errors += dev_stats.tx_heartbeat_errors;
        stats->tx_window_errors    += dev_stats.tx_window_errors;

        /* Account the dropped in each xsk */
        for (i = 0; i < netdev_n_rxq(netdev); i++) {
            xsk_info = dev->xsks[i];
            if (xsk_info) {
                stats->rx_dropped += xsk_info->rx_dropped;
                stats->tx_dropped += xsk_info->tx_dropped;
            }
        }
    }
    ovs_mutex_unlock(&dev->mutex);

    return error;
}
