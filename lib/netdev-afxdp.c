/*
 * Copyright (c) 2018 Nicira, Inc.
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

#ifndef HAVE_AF_XDP
#else
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
#include "lib/xdpsock.h"
#include "netdev-afxdp.h"

VLOG_DEFINE_THIS_MODULE(netdev_afxdp);

#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef AF_XDP
#define AF_XDP 44
#endif
#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define barrier() __asm__ __volatile__("": : :"memory")
#define u_smp_rmb() barrier()
#define u_smp_wmb() barrier()

#define UMEM2DESC(elem, base) ((uint64_t)((char *)elem - (char *)base))
#define UMEM2XPKT(base, i) \
    (struct dp_packet_afxdp *)((char *)base + i * sizeof(struct dp_packet_afxdp))

#define AFXDP_MODE XDP_FLAGS_SKB_MODE /* DRV_MODE or SKB_MODE */
static uint32_t opt_xdp_flags;
static uint32_t opt_xdp_bind_flags;
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static inline uint32_t xq_nb_avail(struct xdp_uqueue *q, uint32_t ndescs)
{
    uint32_t entries = q->cached_prod - q->cached_cons;

    if (entries == 0) {
        q->cached_prod = *q->producer;
        entries = q->cached_prod - q->cached_cons;
    }

    return (entries > ndescs) ? ndescs : entries;
}

static inline uint32_t umem_nb_free(struct xdp_umem_uqueue *q, uint32_t nb)
{
    uint32_t free_entries = q->cached_cons - q->cached_prod;

    if (free_entries >= nb)
        return free_entries;

    q->cached_cons = (*q->consumer + q->size) & q->mask;

    return q->cached_cons - q->cached_prod;
}

static inline int umem_fill_to_kernel_ex(struct xdp_umem_uqueue *fq,
                                         struct xdp_desc *d,
                                         size_t nb)
{
        uint32_t i;

        if (umem_nb_free(fq, nb) < nb)  {
            VLOG_ERR("%s error\n", __func__);
            return -ENOSPC;
        }

        for (i = 0; i < nb; i++) {
                uint32_t idx = fq->cached_prod++ & fq->mask;

                fq->ring[idx] = d[i].addr;
        }

        u_smp_wmb();

        *fq->producer = fq->cached_prod;

        return 0;
}

static inline int umem_fill_to_kernel(struct xdp_umem_uqueue *fq, uint64_t *d,
                      size_t nb)
{
    uint32_t i;

    if (umem_nb_free(fq, nb) < nb) {
        VLOG_ERR("%s Not enough free blocks\n", __func__);
        return -ENOSPC;
    }

    for (i = 0; i < nb; i++) {
        uint32_t idx = fq->cached_prod++ & fq->mask;

        fq->ring[idx] = d[i];
    }

    u_smp_wmb();

    *fq->producer = fq->cached_prod;

    return 0;
}

static inline uint32_t umem_nb_avail(struct xdp_umem_uqueue *q, uint32_t nb)
{
    uint32_t entries = q->cached_prod - q->cached_cons;

    if (entries == 0) {
        q->cached_prod = *q->producer;
        entries = q->cached_prod - q->cached_cons;
    }

    return (entries > nb) ? nb : entries;
}

static inline size_t umem_complete_from_kernel(struct xdp_umem_uqueue *cq,
                           uint64_t *d, size_t nb)
{
    uint32_t idx, i, entries = umem_nb_avail(cq, nb);

    u_smp_rmb();

    for (i = 0; i < entries; i++) {
        idx = cq->cached_cons++ & cq->mask;
        d[i] = cq->ring[idx];
    }

    if (entries > 0) {
        u_smp_wmb();

        *cq->consumer = cq->cached_cons;
    }

    return entries;
}

static struct xdp_umem *xdp_umem_configure(int sfd)
{
    int fq_size = FQ_NUM_DESCS, cq_size = CQ_NUM_DESCS;
    struct xdp_mmap_offsets off;
    struct xdp_umem_reg mr;
    struct xdp_umem *umem;
    socklen_t optlen;
    void *bufs;
    int i;

    umem = xcalloc(1, sizeof(*umem));

    ovs_assert(posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
                              NUM_FRAMES * FRAME_SIZE) == 0);

    VLOG_DBG("%s shared umem from %p to %p", __func__,
              bufs, (char*)bufs + NUM_FRAMES * FRAME_SIZE);

    mr.addr = (uint64_t)bufs;
    mr.len = NUM_FRAMES * FRAME_SIZE;
    mr.chunk_size = FRAME_SIZE;
    mr.headroom = FRAME_HEADROOM;

    ovs_assert(setsockopt(sfd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) == 0);
    ovs_assert(setsockopt(sfd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size,
               sizeof(int)) == 0);
    ovs_assert(setsockopt(sfd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size,
               sizeof(int)) == 0);

    optlen = sizeof(off);
    ovs_assert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
               &optlen) == 0);

    umem->fq.map = mmap(0, off.fr.desc +
                        FQ_NUM_DESCS * sizeof(uint64_t),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, sfd,
                        XDP_UMEM_PGOFF_FILL_RING);
    ovs_assert(umem->fq.map != MAP_FAILED);

    umem->fq.mask = FQ_NUM_DESCS - 1;
    umem->fq.size = FQ_NUM_DESCS;
    umem->fq.producer = (void *)((char *)umem->fq.map + off.fr.producer);
    umem->fq.consumer = (void *)((char *)umem->fq.map + off.fr.consumer);
    umem->fq.ring = (void *)((char *)umem->fq.map + off.fr.desc);
    umem->fq.cached_cons = FQ_NUM_DESCS;

    umem->cq.map = mmap(0, off.cr.desc +
                        CQ_NUM_DESCS * sizeof(uint64_t),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, sfd,
                        XDP_UMEM_PGOFF_COMPLETION_RING);
    ovs_assert(umem->cq.map != MAP_FAILED);

    umem->cq.mask = CQ_NUM_DESCS - 1;
    umem->cq.size = CQ_NUM_DESCS;
    umem->cq.producer = (void *)((char *)umem->cq.map + off.cr.producer);
    umem->cq.consumer = (void *)((char *)umem->cq.map + off.cr.consumer);
    umem->cq.ring = (void *)((char *)umem->cq.map + off.cr.desc);

    umem->frames = bufs;
    umem->fd = sfd;

    /* UMEM pool init */
    umem_pool_init(&umem->mpool, NUM_FRAMES);

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        struct umem_elem *elem;

        elem = (struct umem_elem *)((char *)umem->frames + i * FRAME_SIZE);
        umem_elem_push(&umem->mpool, elem); 
    }

    /* AF_XDP metadata init */
    xpacket_pool_init(&umem->xpool, NUM_FRAMES);

    VLOG_DBG("%s xpacket pool from %p to %p", __func__,
             umem->xpool.array,
             (char *)umem->xpool.array +
             NUM_FRAMES * sizeof(struct dp_packet_afxdp));

    for (i = NUM_FRAMES - 1; i >= 0; i--) {
        struct dp_packet_afxdp *xpacket;
        struct dp_packet *packet;
        char *base;

        xpacket = UMEM2XPKT(umem->xpool.array, i);
        xpacket->mpool = &umem->mpool;

        packet = &xpacket->packet;
        packet->source = DPBUF_AFXDP;

        base = (char *)umem->frames + i * FRAME_SIZE;
        dp_packet_use(packet, base, FRAME_SIZE);
        packet->source = DPBUF_AFXDP;
    }
    return umem;
}

void
xsk_destroy(struct xdpsock *xsk)
{
#ifdef AFXDP_HUGETLB
    munmap(xsk->umem->frames, NUM_FRAMES * FRAME_SIZE);
#else
    free(xsk->umem->frames);
#endif

    /* cleanup umem pool */
    umem_pool_cleanup(&xsk->umem->mpool);

    /* cleanup metadata */
    xpacket_pool_cleanup(&xsk->umem->xpool);

    close(xsk->sfd);
    return;
}

struct xdpsock *
xsk_configure(struct xdp_umem *umem,
              int ifindex, int xdp_queue_id)
{
    struct sockaddr_xdp sxdp = {};
    struct xdp_mmap_offsets off;
    int sfd, ndescs = NUM_DESCS;
    struct xdpsock *xsk;
    bool shared = false;
    socklen_t optlen;
    uint64_t i;

    opt_xdp_flags |= AFXDP_MODE;
    opt_xdp_bind_flags |= XDP_COPY;
    opt_xdp_bind_flags |= XDP_ATTACH;

    sfd = socket(PF_XDP, SOCK_RAW, 0);
    ovs_assert(sfd >= 0);

    xsk = calloc(1, sizeof(*xsk));
    ovs_assert(xsk);

    xsk->sfd = sfd;
    xsk->outstanding_tx = 0;
    
    VLOG_DBG("%s xsk fd %d", __func__, sfd);
    if (!umem) {
        shared = false;
        xsk->umem = xdp_umem_configure(sfd);
    } else {
        xsk->umem = umem;
        ovs_assert(0);
    }

    ovs_assert(setsockopt(sfd, SOL_XDP, XDP_RX_RING,
               &ndescs, sizeof(int)) == 0);
    ovs_assert(setsockopt(sfd, SOL_XDP, XDP_TX_RING,
               &ndescs, sizeof(int)) == 0);
    optlen = sizeof(off);
    ovs_assert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
               &optlen) == 0);

    /* Confiugre RX ring */
    xsk->rx.map = mmap(NULL,
                       off.rx.desc +
                       NUM_DESCS * sizeof(struct xdp_desc),
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, sfd,
                       XDP_PGOFF_RX_RING);
    ovs_assert(xsk->rx.map != MAP_FAILED);

    /* Populate the FILL ring */
    for (i = 0; i < NUM_DESCS; i++) {
        struct umem_elem *elem;
        uint64_t desc[1]; 

        elem = umem_elem_pop(&xsk->umem->mpool);
        desc[0] = UMEM2DESC(elem, xsk->umem->frames);
        umem_fill_to_kernel(&xsk->umem->fq, desc, 1);
    }

    /* Configure Tx ring */
    xsk->tx.map = mmap(NULL,
               off.tx.desc +
               NUM_DESCS * sizeof(struct xdp_desc),
               PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_POPULATE, sfd,
               XDP_PGOFF_TX_RING);
    ovs_assert(xsk->tx.map != MAP_FAILED);

    xsk->rx.mask = NUM_DESCS - 1;
    xsk->rx.size = NUM_DESCS;
    xsk->rx.producer = (void *)((char *)xsk->rx.map + off.rx.producer);
    xsk->rx.consumer = (void *)((char *)xsk->rx.map + off.rx.consumer);
    xsk->rx.ring = (void *)((char *)xsk->rx.map + off.rx.desc);

    xsk->tx.mask = NUM_DESCS - 1;
    xsk->tx.size = NUM_DESCS;
    xsk->tx.producer = (void *)((char *)xsk->tx.map + off.tx.producer);
    xsk->tx.consumer = (void *)((char *)xsk->tx.map + off.tx.consumer);
    xsk->tx.ring = (void *)((char *)xsk->tx.map + off.tx.desc);
    xsk->tx.cached_cons = NUM_DESCS;

    /* XSK socket */
    sxdp.sxdp_family = PF_XDP;
    sxdp.sxdp_ifindex = ifindex;
    sxdp.sxdp_queue_id = xdp_queue_id;

    if (shared) {
        sxdp.sxdp_flags = XDP_SHARED_UMEM;
        sxdp.sxdp_shared_umem_fd = umem->fd;
    } else {
        sxdp.sxdp_flags = opt_xdp_bind_flags;
    }

    if (bind(sfd, (struct sockaddr *)&sxdp, sizeof(sxdp))) {
        VLOG_FATAL("afxdp bind failed (%s)", ovs_strerror(errno));
    }
    

    return xsk;
}

static inline int xq_deq(struct xdp_uqueue *uq,
             struct xdp_desc *descs,
             int ndescs)
{
    struct xdp_desc *r = uq->ring;
    unsigned int idx;
    int i, entries;

    entries = xq_nb_avail(uq, ndescs);

    u_smp_rmb();

    for (i = 0; i < entries; i++) {
        idx = uq->cached_cons++ & uq->mask;
        descs[i] = r[idx];
    }

    if (entries > 0) {
        u_smp_wmb();

        *uq->consumer = uq->cached_cons;
    }
    return entries;
}

static inline void *xq_get_data(struct xdpsock *xsk, uint64_t addr)
{
    return &xsk->umem->frames[addr];
}

static void OVS_UNUSED vlog_hex_dump(const void *buf, size_t count)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_hex_dump(&ds, buf, count, 0, false);
    VLOG_DBG_RL(&rl, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void kick_tx(int fd)
{
    int ret;

#if AF_XDP_POLL
    struct pollfd fds[1];
    int timeout;
    fds[0].fd = fd;
    fds[0].events = POLLOUT;
    timeout = 1000; /* 1ns */

    /* this is slower due to syscall */
    ret = poll(fds, 1, timeout);
    if (ret < 0)
        return;
#endif
    ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY) {
        return;
    } else {
        VLOG_WARN_RL(&rl, "sendto fails %s", ovs_strerror(errno));
    }
}

static inline uint32_t
xq_nb_free(struct xdp_uqueue *q, uint32_t ndescs)
{
    uint32_t free_entries = q->cached_cons - q->cached_prod;

    if (free_entries >= ndescs)
        return free_entries;

    /* Refresh the local tail pointer */
    q->cached_cons = *q->consumer + q->size;
    return q->cached_cons - q->cached_prod;
}

static inline int xq_enq(struct xdp_uqueue *uq,
             const struct xdp_desc *descs,
             unsigned int ndescs)
{
    struct xdp_desc *r = uq->ring;
    unsigned int i;

    if (xq_nb_free(uq, ndescs) < ndescs)
        return -ENOSPC;

    for (i = 0; i < ndescs; i++) {
        uint32_t idx = uq->cached_prod++ & uq->mask;

        r[idx].addr = descs[i].addr;
        r[idx].len = descs[i].len;
    }

    u_smp_wmb();

    *uq->producer = uq->cached_prod;
    return 0;
}

static inline void
print_xsk_stat(struct xdpsock *xsk OVS_UNUSED) {
    struct xdp_statistics stat;
    socklen_t optlen;

    optlen = sizeof(stat);
    ovs_assert(getsockopt(xsk->sfd, SOL_XDP, XDP_STATISTICS,
                &stat, &optlen) == 0);

    VLOG_DBG_RL(&rl, "rx dropped %llu, rx_invalid %llu, tx_invalid %llu",
                stat.rx_dropped, stat.rx_invalid_descs, stat.tx_invalid_descs);
    return;
}

/* Receive packet from AF_XDP socket */
int
netdev_linux_rxq_xsk(struct xdpsock *xsk,
                     struct dp_packet_batch *batch)
{
    struct xdp_desc descs[NETDEV_MAX_BURST];
    unsigned int rcvd, i = 0, non_afxdp = 0;
    int ret = 0;

    rcvd = xq_deq(&xsk->rx, descs, NETDEV_MAX_BURST);
    if (rcvd == 0) {
        /* no packet on the RX ring */
        return 0;
    }

    for (i = 0; i < rcvd; i++) {
        struct dp_packet_afxdp *xpacket;
        struct dp_packet *packet;
        void *base;
        int index;

        base = xq_get_data(xsk, descs[i].addr);
        index = (descs[i].addr - FRAME_HEADROOM) / FRAME_SIZE;
        xpacket = UMEM2XPKT(xsk->umem->xpool.array, index);

        VLOG_DBG_RL(&rl, "rcvd %d base %p xpacket %p index %d",
                    rcvd, base, xpacket, index);
        vlog_hex_dump(base, 14);

        packet = &xpacket->packet;
        xpacket->mpool = &xsk->umem->mpool;

        if (packet->source != DPBUF_AFXDP) {
            non_afxdp++; /* FIXME: might be a bug */
            continue;
        }

        packet->source = DPBUF_AFXDP;
        dp_packet_set_data(packet, base);
        dp_packet_set_size(packet, descs[i].len);

        /* add packet into batch, increase batch->count */
        dp_packet_batch_add(batch, packet);
    }
    rcvd -= non_afxdp;
    xsk->rx_npkts += rcvd;

    for (i = 0; i < rcvd; i++) {
        struct xdp_desc fill_desc[1];
        struct umem_elem *elem;
        int retry_cnt = 0;
retry:
        elem = umem_elem_pop(&xsk->umem->mpool);
        if (!elem && retry_cnt < 10) {
            retry_cnt++;
            VLOG_WARN_RL(&rl, "retry refilling the fill queue");
            xsleep(1);
            goto retry;
        }
        descs[0].addr = (uint64_t)((char *)elem - xsk->umem->frames);
        umem_fill_to_kernel_ex(&xsk->umem->fq, fill_desc, 1);
    }

#ifdef AFXDP_DEBUG
    print_xsk_stat(xsk);
#endif
    return ret;
}

int
netdev_linux_afxdp_batch_send(struct xdpsock *xsk, /* send to xdp socket! */
                              struct dp_packet_batch *batch)
{
    struct dp_packet *packet;
    struct xdp_uqueue *uq;
    struct xdp_desc *r;
    int ndescs = batch->count;
    uint64_t descs[BATCH_SIZE];
    unsigned int tx_done = 0, total_tx = 0;
    int j;

    uq = &xsk->tx;
    r = uq->ring;

    if (xq_nb_free(uq, ndescs) < ndescs) {
        VLOG_WARN_RL(&rl, "no free desc, outstanding tx %d, free tx nb %d",
                     xsk->outstanding_tx, xq_nb_free(uq, ndescs));
        return -EAGAIN;
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct umem_elem *elem;
        struct dp_packet_afxdp *xpacket;

        uint32_t idx = uq->cached_prod++ & uq->mask;
#ifdef AFXDP_AOID_TXCOPY
        if (packet->source == DPBUF_AFXDP) {
            xpacket = dp_packet_cast_afxdp(packet);

            if (xpacket->mpool == &xsk->umem->mpool) {
                r[idx].addr = (uint64_t)((char *)dp_packet_base(packet) - xsk->umem->frames);
                r[idx].len = dp_packet_size(packet);
                xpacket->mpool = NULL;
                continue;
            }
        }
#endif
        elem = umem_elem_pop(&xsk->umem->mpool);
        if (!elem) {
            VLOG_ERR_RL(&rl, "no available elem!");
            return -EAGAIN;
        }

        memcpy(elem, dp_packet_data(packet), dp_packet_size(packet));
        vlog_hex_dump(dp_packet_data(packet), 14);

        r[idx].addr = (uint64_t)((char *)elem - xsk->umem->frames);
        r[idx].len = dp_packet_size(packet);

        if (packet->source == DPBUF_AFXDP) {
            xpacket = dp_packet_cast_afxdp(packet);
            umem_elem_push(xpacket->mpool, dp_packet_base(packet));
            /* Avoid freeing it twice at dp_packet_uninit */
            xpacket->mpool = NULL;
        }
    }
    u_smp_wmb();

    *uq->producer = uq->cached_prod;
    xsk->outstanding_tx += batch->count;

retry:
    kick_tx(xsk->sfd);

    tx_done = umem_complete_from_kernel(&xsk->umem->cq, descs, BATCH_SIZE);
    if (tx_done > 0) {
            xsk->outstanding_tx -= tx_done;
            xsk->tx_npkts += tx_done;
            total_tx += tx_done;
            VLOG_DBG_RL(&rl, "%s complete %d tx", __func__, tx_done);
    }

    /* Recycle back to the umem pool */
    for (j = 0; j < tx_done; j++) {
        struct umem_elem *elem;

        elem = (struct umem_elem *)(descs[j] + xsk->umem->frames);
        umem_elem_push(&xsk->umem->mpool, elem);
    }

    if (total_tx < batch->count && xsk->outstanding_tx > (CQ_NUM_DESCS/2)) {
        goto retry;
    }
#ifdef ADXDP_DEBUG
    print_xsk_stat(xsk);
#endif
    return 0;
}

#endif
