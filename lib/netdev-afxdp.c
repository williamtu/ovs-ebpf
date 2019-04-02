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
#include "netdev-linux.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_xdp.h>
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
#include "xdpsock.h"
#include "netdev-afxdp.h"

#ifdef HAVE_AF_XDP
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
    (struct dp_packet_afxdp *)((char *)base + i * sizeof(struct dp_packet_afxdp))

#ifdef AFXDP_NS_TEST /* test using make check-afxdp */
static uint32_t opt_xdp_bind_flags = XDP_COPY;
static uint32_t opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
#else
static uint32_t opt_xdp_bind_flags = XDP_ZEROCOPY;
static uint32_t opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
#endif
static uint32_t prog_id;

static struct xsk_umem_info *xsk_configure_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;
    int i;

    umem = calloc(1, sizeof(*umem));
    if (!umem) {
        VLOG_FATAL("xsk config umem failed (%s)", ovs_strerror(errno));
    }

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                           NULL);

    if (ret) {
        VLOG_FATAL("xsk umem create failed (%s)", ovs_strerror(errno));
    }

    umem->buffer = buffer;

    /* set-up umem pool */
    umem_pool_init(&umem->mpool, NUM_FRAMES);

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        struct umem_elem *elem;

        elem = (struct umem_elem *)((char *)umem->buffer
                            + i * FRAME_SIZE);
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
                     uint32_t queue_id)
{
    struct xsk_socket_config cfg;
    struct xsk_socket_info *xsk;
    char devname[IF_NAMESIZE];
    uint32_t idx;
    int ret;
    int i;

    xsk = calloc(1, sizeof(*xsk));
    if (!xsk) {
        VLOG_FATAL("xsk create failed (%s)", ovs_strerror(errno));
    }

    xsk->umem = umem;
    cfg.rx_size = CONS_NUM_DESCS;
    cfg.tx_size = PROD_NUM_DESCS;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = opt_xdp_flags;
    cfg.bind_flags = opt_xdp_bind_flags;

    if (if_indextoname(ifindex, devname) == NULL) {
        VLOG_FATAL("ifindex %d devname failed (%s)",
                   ifindex, ovs_strerror(errno));
    }

    ret = xsk_socket__create(&xsk->xsk, devname, queue_id, umem->umem,
                             &xsk->rx, &xsk->tx, &cfg);
    if (ret) {
        VLOG_FATAL("xsk create failed (%s)", ovs_strerror(errno));
    }

    /* make sure the XDP program is there */
    ret = bpf_get_link_xdp_id(ifindex, &prog_id, opt_xdp_flags);
    if (ret) {
        VLOG_FATAL("get XDP prog ID failed (%s)", ovs_strerror(errno));
    }

    ret = xsk_ring_prod__reserve(&xsk->umem->fq,
                                 PROD_NUM_DESCS,
                                 &idx);
    if (ret != PROD_NUM_DESCS) {
        VLOG_FATAL("fq set-up failed (%s)", ovs_strerror(errno));
    }

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

struct xsk_socket_info *
xsk_configure(int ifindex, int xdp_queue_id)
{
    struct xsk_socket_info *xsk;
    struct xsk_umem_info *umem;
    void *bufs;
    int ret;

    ret = posix_memalign(&bufs, getpagesize(),
                         NUM_FRAMES * FRAME_SIZE);
    ovs_assert(!ret);

    /* Create sockets... */
    umem = xsk_configure_umem(bufs,
                              NUM_FRAMES * FRAME_SIZE);
    xsk = xsk_configure_socket(umem, ifindex, xdp_queue_id);
    return xsk;
}

static void OVS_UNUSED vlog_hex_dump(const void *buf, size_t count)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_hex_dump(&ds, buf, count, 0, false);
    VLOG_DBG_RL(&rl, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

void
xsk_destroy(struct xsk_socket_info *xsk, uint32_t ifindex)
{
    struct xsk_umem *umem = xsk->umem->umem;
    uint32_t curr_prog_id = 0;

    xsk_socket__delete(xsk->xsk);
    (void)xsk_umem__delete(umem);

    /* cleanup umem pool */
    umem_pool_cleanup(&xsk->umem->mpool);

    /* cleanup metadata pool */
    xpacket_pool_cleanup(&xsk->umem->xpool);

    /* remove_xdp_program() */
    if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, opt_xdp_flags)) {
        bpf_set_link_xdp_fd(ifindex, -1, opt_xdp_flags);
    }
    if (prog_id == curr_prog_id) {
        bpf_set_link_xdp_fd(ifindex, -1, opt_xdp_flags);
    } else if (!curr_prog_id) {
        VLOG_WARN("couldn't find a prog id on a given interface");
    } else {
        VLOG_WARN("program on interface changed, not removing");
    }

    return;
}

static inline void
print_xsk_stat(struct xsk_socket_info *xsk OVS_UNUSED) {
    struct xdp_statistics stat;
    socklen_t optlen;

    optlen = sizeof(stat);
    ovs_assert(getsockopt(xsk_socket__fd(xsk->xsk), SOL_XDP, XDP_STATISTICS,
                &stat, &optlen) == 0);

    VLOG_DBG_RL(&rl, "rx dropped %llu, rx_invalid %llu, tx_invalid %llu",
                stat.rx_dropped, stat.rx_invalid_descs, stat.tx_invalid_descs);
    return;
}

/* Receive packet from AF_XDP socket */
int
netdev_linux_rxq_xsk(struct xsk_socket_info *xsk,
                     struct dp_packet_batch *batch)
{
    unsigned int rcvd, i;
    uint32_t idx_rx = 0, idx_fq = 0;
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

        if (packet->source != DPBUF_AFXDP) {
            /* FIXME: might be a bug */
            continue;
        }

        /* Initialize the struct dp_packet */
#ifdef AFXDP_NS_TEST /* test using make check-afxdp */
        dp_packet_set_base(packet, pkt);
#else
        dp_packet_set_base(packet, pkt - FRAME_HEADROOM);
#endif
        dp_packet_set_data(packet, pkt);
        dp_packet_set_size(packet, len);

        /* Add packet into batch, increase batch->count */
        dp_packet_batch_add(batch, packet);

        idx_rx++;
    }

    /* We've consume rcvd packets in RX, now re-fill the
     * same number back to FILL queue.
     */
    for (i = 0; i < rcvd; i++) {
        uint64_t index;
        struct umem_elem *elem;

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, 1, &idx_fq);
        while (ret == 0) {
            /* The FILL queue is full, so retry. (or skip)? */
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, 1, &idx_fq);
        }

        /* Get one free umem, program it into FILL queue */
        elem = umem_elem_pop(&xsk->umem->mpool);
        index = (uint64_t)((char *)elem - (char *)xsk->umem->buffer);
        ovs_assert((index & FRAME_SHIFT_MASK) == 0);
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq) = index;

        idx_fq++;
    }
    xsk_ring_prod__submit(&xsk->umem->fq, rcvd);

    /* Release the RX queue */
    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk->rx_npkts += rcvd;

#ifdef AFXDP_NS_TEST
    print_xsk_stat(xsk);
#endif
    return 0;
}

static void kick_tx(struct xsk_socket_info *xsk)
{
    int ret;

    ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
        return;
}

/*
 * A dp_packet might come from
 * 1) AFXDP buffer
 * 2) non-AFXDP buffer, ex: send from tap device
 */
int
netdev_linux_afxdp_batch_send(struct xsk_socket_info *xsk,
                              struct dp_packet_batch *batch)
{
    uint32_t tx_done, idx_cq = 0;
    struct dp_packet *packet;
    uint32_t idx;
    int j;

    /* Make sure we have enough TX descs */
    if (xsk_ring_prod__reserve(&xsk->tx, batch->count, &idx) == 0) {
        return -EAGAIN;
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct dp_packet_afxdp *xpacket;
        struct umem_elem *elem;
        uint64_t index;

        elem = umem_elem_pop(&xsk->umem->mpool);
        if (!elem) {
            return -EAGAIN;
        }

        memcpy(elem, dp_packet_data(packet), dp_packet_size(packet));

        index = (uint64_t)((char *)elem - (char *)xsk->umem->buffer);
        xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->addr = index;
        xsk_ring_prod__tx_desc(&xsk->tx, idx + i)->len
            = dp_packet_size(packet);

        if (packet->source == DPBUF_AFXDP) {
            xpacket = dp_packet_cast_afxdp(packet);
            umem_elem_push(xpacket->mpool, dp_packet_base(packet));
             /* Avoid freeing it twice at dp_packet_uninit */
            xpacket->mpool = NULL;
        }
    }
    xsk_ring_prod__submit(&xsk->tx, batch->count);
    xsk->outstanding_tx += batch->count;

retry:
    kick_tx(xsk);

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

        elem = (struct umem_elem *)((char *)xsk->umem->buffer + addr);
        umem_elem_push(&xsk->umem->mpool, elem);
    }
    xsk_ring_cons__release(&xsk->umem->cq, tx_done);

    if (xsk->outstanding_tx > PROD_NUM_DESCS - (PROD_NUM_DESCS >> 2)) {
        /* If there are still a lot not transmitted,
         * try harder.
         */
        goto retry;
    }

    return 0;
}

#else
struct xsk_socket_info *
xsk_configure(int ifindex OVS_UNUSED, int xdp_queue_id OVS_UNUSED)
{
    return NULL;
}

void
xsk_destroy(struct xsk_socket_info *xsk OVS_UNUSED, uint32_t ifindex OVS_UNUSED)
{
    return;
}

int
netdev_linux_rxq_xsk(struct xsk_socket_info *xsk OVS_UNUSED,
                     struct dp_packet_batch *batch OVS_UNUSED)
{
    return 0;
}

int
netdev_linux_afxdp_batch_send(struct xsk_socket_info *xsk OVS_UNUSED,
                              struct dp_packet_batch *batch OVS_UNUSED)
{
    return 0;
}
#endif
