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

#if !defined(__i386__) && !defined(__x86_64__)
#error AF_XDP supported only for Linux on x86 or x86_64
#endif

#include <config.h>
#include "netdev-linux.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netlink.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "netdev-provider.h"
#include "netdev-tc-offloads.h"
#include "netdev-vport.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "netnsid.h"
#include "openvswitch/ofpbuf.h"
#include "openflow/openflow.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "rtnetlink.h"
#include "openvswitch/shash.h"
#include "socket-util.h"
#include "sset.h"
#include "tc.h"
#include "timer.h"
#include "unaligned.h"
#include "openvswitch/vlog.h"
#include "util.h"
#include "netdev-afxdp.h"

#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_xdp.h>
#include "xdpsock.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

VLOG_DEFINE_THIS_MODULE(netdev_afxdp);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define UMEM2DESC(elem, base) ((uint64_t)((char *)elem - (char *)base))
#define UMEM2XPKT(base, i) \
    ALIGNED_CAST(struct dp_packet_afxdp *, (char *)base + \
    i * sizeof(struct dp_packet_afxdp))

static uint32_t prog_id;
static struct xsk_socket_info *xsk_configure(int ifindex, int xdp_queue_id,
                                             int mode);
static void xsk_remove_xdp_program(uint32_t ifindex, int xdpmode);
static void xsk_destroy(struct xsk_socket_info *xsk);

static struct xsk_umem_info *xsk_configure_umem(void *buffer, uint64_t size,
                                                int xdpmode)
{
    struct xsk_umem_info *umem;
    int ret;
    int i;

    umem = xcalloc(1, sizeof(*umem));
    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                           NULL);

    if (ret) {
        VLOG_ERR("xsk umem create failed (%s) mode: %s",
                 ovs_strerror(errno),
                 xdpmode == XDP_COPY ? "SKB": "DRV");
        return NULL;
    }

    umem->buffer = buffer;

    /* set-up umem pool */
    umem_pool_init(&umem->mpool, NUM_FRAMES);

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        struct umem_elem *elem;

        elem = ALIGNED_CAST(struct umem_elem *,
                            (char *)umem->buffer + i * FRAME_SIZE);
        umem_elem_push(&umem->mpool, elem);
    }

    /* set-up metadata */
    xpacket_pool_init(&umem->xpool, NUM_FRAMES);

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
    uint32_t idx = 0;
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
        return NULL;
    }

    ret = xsk_socket__create(&xsk->xsk, devname, queue_id, umem->umem,
                             &xsk->rx, &xsk->tx, &cfg);
    if (ret) {
        VLOG_ERR("xsk_socket_create failed (%s) mode: %s qid: %d",
                 ovs_strerror(errno),
                 xdpmode == XDP_COPY ? "SKB": "DRV",
                 queue_id);
        return NULL;
    }

    /* Make sure the built-in AF_XDP program is loaded */
    ret = bpf_get_link_xdp_id(ifindex, &prog_id, cfg.xdp_flags);
    if (ret) {
        VLOG_ERR("get XDP prog ID failed (%s)", ovs_strerror(errno));
        xsk_socket__delete(xsk->xsk);
        return NULL;
    }

    xsk_ring_prod__reserve(&xsk->umem->fq, PROD_NUM_DESCS, &idx);

    for (i = 0;
         i < PROD_NUM_DESCS * FRAME_SIZE;
         i += FRAME_SIZE) {
        struct umem_elem *elem;
        uint64_t addr;

        elem = umem_elem_pop(&xsk->umem->mpool);
        addr = UMEM2DESC(elem, xsk->umem->buffer);

        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = addr;
    }

    xsk_ring_prod__submit(&xsk->umem->fq,
                          PROD_NUM_DESCS);
    return xsk;
}

static struct xsk_socket_info *
xsk_configure(int ifindex, int xdp_queue_id, int xdpmode)
{
    struct xsk_socket_info *xsk;
    struct xsk_umem_info *umem;
    void *bufs;
    int ret;

    /* umem memory region */
    ret = posix_memalign(&bufs, getpagesize(),
                         NUM_FRAMES * FRAME_SIZE);
    memset(bufs, 0, NUM_FRAMES * FRAME_SIZE);
    ovs_assert(!ret);

    /* create AF_XDP socket */
    umem = xsk_configure_umem(bufs,
                              NUM_FRAMES * FRAME_SIZE,
                              xdpmode);
    if (!umem) {
        return NULL;
    }

    xsk = xsk_configure_socket(umem, ifindex, xdp_queue_id, xdpmode);
    if (!xsk) {
        /* clean up umem and xpacket pool */
        free(bufs);
        (void)xsk_umem__delete(umem->umem);
        umem_pool_cleanup(&xsk->umem->mpool);
        xpacket_pool_cleanup(&xsk->umem->xpool);
    }
    return xsk;
}

void
xsk_configure_all(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct xsk_socket_info *xsk;
    int i, ifindex;

    ifindex = linux_get_ifindex(netdev->name);

    /* configure each queue */
    for (i = 0; i < netdev->n_rxq; i++) {
        VLOG_INFO("%s configure queue %d mode %s", __func__, i,
                dev->xdpmode == XDP_COPY ? "SKB" : "DRV");
        xsk = xsk_configure(ifindex, i, dev->xdpmode);
        if (!xsk) {
            VLOG_ERR("failed to create AF_XDP socket on queue %d", i);
            return;
        }
        dev->xsk[i] = xsk;
    }
}

static void OVS_UNUSED vlog_hex_dump(const void *buf, size_t count)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_hex_dump(&ds, buf, count, 0, false);
    VLOG_DBG_RL(&rl, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
xsk_destroy(struct xsk_socket_info *xsk)
{
    struct xsk_umem *umem;

    if (!xsk) {
        return;
    }

    umem = xsk->umem->umem;
    xsk_socket__delete(xsk->xsk);
    (void)xsk_umem__delete(umem);

    /* free the packet buffer */
    free(xsk->umem->buffer);

    /* cleanup umem pool */
    umem_pool_cleanup(&xsk->umem->mpool);

    /* cleanup metadata pool */
    xpacket_pool_cleanup(&xsk->umem->xpool);
}

void
xsk_destroy_all(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int i, ifindex;

    ifindex = linux_get_ifindex(netdev->name);

    for (i = 0; i < MAX_XSKQ; i++) {
        if (dev->xsk[i]) {
            VLOG_INFO("destroy xsk[%d]", i);
            xsk_destroy(dev->xsk[i]);
        }
    }
    VLOG_INFO("remove xdp program");
    xsk_remove_xdp_program(ifindex, dev->xdpmode);
}

static inline void OVS_UNUSED
print_xsk_stat(struct xsk_socket_info *xsk OVS_UNUSED) {
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
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    const char *xdpmode;
    int new_n_rxq;

    ovs_mutex_lock(&dev->mutex);

    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq > MAX_XSKQ) {
        ovs_mutex_unlock(&dev->mutex);
        return EINVAL;
    }

    if (new_n_rxq != netdev->n_rxq) {
        dev->requested_n_rxq = new_n_rxq;
        netdev_request_reconfigure(netdev);
    }

    xdpmode = smap_get(args, "xdpmode");
    if (xdpmode && strncmp(xdpmode, "drv", 3) == 0) {
        dev->requested_xdpmode = XDP_ZEROCOPY;

        if (dev->xdpmode != dev->requested_xdpmode) {
            VLOG_INFO("AF_XDP device %s in DRV mode", netdev->name);

            /* From SKB mode to DRV mode */
            dev->xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
            dev->xdp_bind_flags = XDP_ZEROCOPY;
            dev->xdpmode = XDP_ZEROCOPY;
            netdev_request_reconfigure(netdev);
        }
    } else {
        dev->requested_xdpmode = XDP_COPY;
        if (dev->xdpmode != dev->requested_xdpmode) {
            VLOG_INFO("AF_XDP device %s in SKB mode", netdev->name);

            /* From DRV mode to SKB mode */
            dev->xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
            dev->xdp_bind_flags = XDP_COPY;
            dev->xdpmode = XDP_COPY;
            netdev_request_reconfigure(netdev);
        }
    }

    if (dev->xdpmode == XDP_ZEROCOPY) {
        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
            VLOG_ERR("ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                      ovs_strerror(errno));
        }
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

int
netdev_afxdp_reconfigure(struct netdev *netdev)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);

    if (netdev->n_rxq == dev->requested_n_rxq
        && dev->xdpmode == dev->requested_xdpmode) {
        goto out;
    }

    xsk_destroy_all(netdev);

    netdev->n_rxq = dev->requested_n_rxq;
    dev->xdpmode = dev->requested_xdpmode;

    xsk_configure_all(netdev);
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
    VLOG_INFO("FIXME: Device %s always use numa id 0", netdev->name);
    return 0;
}

void
xsk_remove_xdp_program(uint32_t ifindex, int xdpmode)
{
    uint32_t curr_prog_id = 0;
    uint32_t flags;

    /* remove_xdp_program() */
    if (xdpmode == XDP_COPY) {
        flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
    } else {
        flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    }

    if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, flags)) {
        bpf_set_link_xdp_fd(ifindex, -1, flags);
    }
    if (prog_id == curr_prog_id) {
        bpf_set_link_xdp_fd(ifindex, -1, flags);
    } else if (!curr_prog_id) {
        VLOG_INFO("couldn't find a prog id on a given interface");
    } else {
        VLOG_INFO("program on interface changed, not removing");
    }
}

static inline struct dp_packet_afxdp *
dp_packet_cast_afxdp(const struct dp_packet *d OVS_UNUSED)
{
    ovs_assert(d->source == DPBUF_AFXDP);
    return CONTAINER_OF(d, struct dp_packet_afxdp, packet);
}

void
free_afxdp_buf(struct dp_packet *p)
{
    struct dp_packet_afxdp *xpacket;
    unsigned long addr;

    xpacket = dp_packet_cast_afxdp(p);
    if (xpacket->mpool) {
        void *base = dp_packet_base(p);

        addr = (unsigned long)base & (~FRAME_SHIFT_MASK);
        umem_elem_push(xpacket->mpool, (void *)addr);
    }
}

void
free_afxdp_buf_batch(struct dp_packet_batch *batch)
{
        struct dp_packet_afxdp *xpacket = NULL;
        struct dp_packet *packet;
        void *elems[BATCH_SIZE];
        unsigned long addr;

       /* all packets are AF_XDP, so handles its own delete in batch */
        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            xpacket = dp_packet_cast_afxdp(packet);
            if (xpacket->mpool) {
                void *base = dp_packet_base(packet);

                addr = (unsigned long)base & (~FRAME_SHIFT_MASK);
                elems[i] = (void *)addr;
            }
        }
        umem_elem_push_n(xpacket->mpool, batch->count, elems);
        dp_packet_batch_init(batch);
}

/* Receive packet from AF_XDP socket */
int
netdev_linux_rxq_xsk(struct xsk_socket_info *xsk,
                     struct dp_packet_batch *batch)
{
    struct umem_elem *elems[BATCH_SIZE];
    uint32_t idx_rx = 0, idx_fq = 0;
    unsigned int rcvd, i;
    int ret = 0;

    /* See if there is any packet on RX queue,
     * if yes, idx_rx is the index having the packet.
     */
    rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        return 0;
    }

    /* Form a dp_packet batch from descriptor in RX queue */
    for (i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
        uint64_t index;

        struct dp_packet_afxdp *xpacket;
        struct dp_packet *packet;

        index = addr >> FRAME_SHIFT;
        xpacket = UMEM2XPKT(xsk->umem->xpool.array, index);

        packet = &xpacket->packet;
        xpacket->mpool = &xsk->umem->mpool;

        /* Initialize the struct dp_packet */
        dp_packet_set_base(packet, pkt);
        dp_packet_set_data(packet, pkt);
        dp_packet_set_size(packet, len);

        /* Add packet into batch, increase batch->count */
        dp_packet_batch_add(batch, packet);

        idx_rx++;
    }

    /* We've consume rcvd packets in RX, now re-fill the
     * same number back to FILL queue.
     */
    ret = umem_elem_pop_n(&xsk->umem->mpool, rcvd, (void **)elems);
    if (OVS_UNLIKELY(ret)) {
        return -ENOMEM;
    }

    for (i = 0; i < rcvd; i++) {
        uint64_t index;
        struct umem_elem *elem;

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, 1, &idx_fq);
        while (OVS_UNLIKELY(ret == 0)) {
            /* The FILL queue is full, so retry. (or skip)? */
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, 1, &idx_fq);
        }

        /* Get one free umem, program it into FILL queue */
        elem = elems[i];
        index = (uint64_t)((char *)elem - (char *)xsk->umem->buffer);
        ovs_assert((index & FRAME_SHIFT_MASK) == 0);
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq) = index;

        idx_fq++;
    }
    xsk_ring_prod__submit(&xsk->umem->fq, rcvd);

    /* Release the RX queue */
    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk->rx_npkts += rcvd;

#ifdef AFXDP_DEBUG
    print_xsk_stat(xsk);
#endif
    return 0;
}

static void kick_tx(struct xsk_socket_info *xsk)
{
    int ret;

    /* This causes system call into kernel, avoid calling
     * this as much as we can.
     */
    ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY) {
        return;
    }
}

int
netdev_linux_afxdp_batch_send(struct xsk_socket_info *xsk,
                              struct dp_packet_batch *batch)
{
    struct umem_elem *elems_pop[BATCH_SIZE];
    struct umem_elem *elems_push[BATCH_SIZE];
    uint32_t tx_done, idx_cq = 0;
    struct dp_packet *packet;
    uint32_t idx = 0;
    int j, ret, retry_count = 0;

    /* Make sure we have enough TX descs */
    ret = xsk_ring_prod__reserve(&xsk->tx, batch->count, &idx);
    if (OVS_UNLIKELY(ret == 0)) {
        return -EAGAIN;
    }

    ret = umem_elem_pop_n(&xsk->umem->mpool, batch->count, (void **)elems_pop);
    if (OVS_UNLIKELY(ret)) {
        return -EAGAIN;
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct umem_elem *elem;
        uint64_t index;

        elem = elems_pop[i];
        if (OVS_UNLIKELY(!elem)) {
            return -EAGAIN;
        }

        /* Copy the packet to the umem we just pop from umem pool.
         * We can avoid this copy if the packet and the pop umem
         * are located in the same umem.
         */
        memcpy(elem, dp_packet_data(packet), dp_packet_size(packet));

        index = (uint64_t)((char *)elem - (char *)xsk->umem->buffer);
        xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->addr = index;
        xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->len
            = dp_packet_size(packet);
    }
    xsk_ring_prod__submit(&xsk->tx, batch->count);
    xsk->outstanding_tx += batch->count;

    kick_tx(xsk);
retry:

    /* Process CQ */
    tx_done = xsk_ring_cons__peek(&xsk->umem->cq, batch->count, &idx_cq);
    if (tx_done > 0) {
        xsk->outstanding_tx -= tx_done;
        xsk->tx_npkts += tx_done;
    }

    /* Recycle back to umem pool */
    for (j = 0; j < tx_done; j++) {
        struct umem_elem *elem;
        uint64_t addr;

        addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++);

        elem = ALIGNED_CAST(struct umem_elem *,
                            (char *)xsk->umem->buffer + addr);
        elems_push[j] = elem;
    }
    ret = umem_elem_push_n(&xsk->umem->mpool, tx_done, (void **)elems_push);
    if (OVS_UNLIKELY(ret < 0)) {
        goto out;
    }
    xsk_ring_cons__release(&xsk->umem->cq, tx_done);

    if (xsk->outstanding_tx > PROD_NUM_DESCS - (PROD_NUM_DESCS >> 2)) {
        /* If there are still a lot not transmitted,
         * try harder.
         */
        if (retry_count++ > 4) {
            return 0;
        }

        goto retry;
    }
out:
    return 0;
}
