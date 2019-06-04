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

#ifndef XDPSOCK_H
#define XDPSOCK_H 1

#include <config.h>

#ifdef HAVE_AF_XDP

#include <bpf/xsk.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "openvswitch/thread.h"
#include "ovs-atomic.h"
#include "spinlock.h"

#define FRAME_HEADROOM  XDP_PACKET_HEADROOM
#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAME_SHIFT     XSK_UMEM__DEFAULT_FRAME_SHIFT
#define FRAME_SHIFT_MASK    ((1 << FRAME_SHIFT) - 1)

#define PROD_NUM_DESCS XSK_RING_PROD__DEFAULT_NUM_DESCS
#define CONS_NUM_DESCS XSK_RING_CONS__DEFAULT_NUM_DESCS

/* The worst case is all 4 queues TX/CQ/RX/FILL are full.
 * Setting NUM_FRAMES to this makes sure umem_pop always successes.
 */
#define NUM_FRAMES      (2 * (PROD_NUM_DESCS + CONS_NUM_DESCS))

#define BATCH_SIZE      NETDEV_MAX_BURST

BUILD_ASSERT_DECL(IS_POW2(NUM_FRAMES));
BUILD_ASSERT_DECL(PROD_NUM_DESCS == CONS_NUM_DESCS);
BUILD_ASSERT_DECL(NUM_FRAMES == 2 * (PROD_NUM_DESCS + CONS_NUM_DESCS));

/* LIFO ptr_array */
struct umem_pool {
    int index;      /* point to top */
    unsigned int size;
    struct ovs_spinlock lock;
    void **array;   /* a pointer array, point to umem buf */
};

/* array-based dp_packet_afxdp */
struct xpacket_pool {
    unsigned int size;
    struct dp_packet_afxdp **array;
};

struct xsk_umem_info {
    struct umem_pool mpool;
    struct xpacket_pool xpool;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    unsigned long rx_dropped;
    unsigned long tx_dropped;
    uint32_t outstanding_tx;
};

struct umem_elem {
    struct umem_elem *next;
};

void umem_elem_push(struct umem_pool *umemp, void *addr);
void umem_elem_push_n(struct umem_pool *umemp, int n, void **addrs);

void *umem_elem_pop(struct umem_pool *umemp);
int umem_elem_pop_n(struct umem_pool *umemp, int n, void **addrs);

int umem_pool_init(struct umem_pool *umemp, unsigned int size);
void umem_pool_cleanup(struct umem_pool *umemp);
int xpacket_pool_init(struct xpacket_pool *xp, unsigned int size);
void xpacket_pool_cleanup(struct xpacket_pool *xp);

#endif
#endif
