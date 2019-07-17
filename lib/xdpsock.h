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

#define FRAME_HEADROOM  XDP_PACKET_HEADROOM
#define OVS_XDP_HEADROOM     128
#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAME_SHIFT     XSK_UMEM__DEFAULT_FRAME_SHIFT
#define FRAME_SHIFT_MASK    ((1 << FRAME_SHIFT) - 1)

#define PROD_NUM_DESCS XSK_RING_PROD__DEFAULT_NUM_DESCS
#define CONS_NUM_DESCS XSK_RING_CONS__DEFAULT_NUM_DESCS

/* The worst case is all 4 queues TX/CQ/RX/FILL are full + some packets
 * still on processing in threads. Number of packets currently in OVS
 * processing is hard to estimate because it depends on number of ports.
 * Setting NUM_FRAMES twice as large than total of ring sizes should be
 * enough for most corner cases.
 */
#define NUM_FRAMES      (4 * (PROD_NUM_DESCS + CONS_NUM_DESCS))

#define BATCH_SIZE      NETDEV_MAX_BURST

/* LIFO ptr_array. */
struct umem_pool {
    int index;      /* Point to top. */
    unsigned int size;
    struct ovs_spin lock;
    void **array;   /* A pointer array pointing to umem buf. */
};

/* Array-based dp_packet_afxdp. */
struct xpacket_pool {
    unsigned int size;
    struct dp_packet_afxdp **array;
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
unsigned int umem_pool_count(struct umem_pool *umemp);
int xpacket_pool_init(struct xpacket_pool *xp, unsigned int size);
void xpacket_pool_cleanup(struct xpacket_pool *xp);

#endif
#endif
