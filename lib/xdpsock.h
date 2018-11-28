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

#ifndef XDPSOCK_H
#define XDPSOCK_H 1

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <locale.h>
#include <sys/types.h>
#include <poll.h>

#include "ovs-atomic.h"
#include "openvswitch/thread.h"

#define FRAME_HEADROOM 256
#define FRAME_SHIFT 11
#define FRAME_SIZE 2048
#define BATCH_SIZE NETDEV_MAX_BURST

#ifdef AFXDP_DEBUG
#define NUM_FRAMES 128
#define NUM_DESCS 64
#define FQ_NUM_DESCS 64
#define CQ_NUM_DESCS 64
#else
#define NUM_FRAMES 10240
#define NUM_DESCS 256
#define FQ_NUM_DESCS 256
#define CQ_NUM_DESCS 256
#endif

struct xdp_uqueue {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    struct xdp_desc *ring;
    void *map;
};

struct xdpsock {
    struct xdp_uqueue rx;
    struct xdp_uqueue tx;
    int sfd;
    struct xdp_umem *umem;
    uint32_t outstanding_tx;
    unsigned long rx_npkts;
    unsigned long tx_npkts;
    unsigned long prev_rx_npkts;
    unsigned long prev_tx_npkts;
};

struct umem_elem_head {
    unsigned int index;
    struct ovs_mutex mutex;
    uint32_t n;
};

struct umem_elem {
    struct umem_elem *next;
};

/* LIFO ptr_array */
struct umem_pool {
    int index;      /* point to top */
    unsigned int size;
    struct ovs_mutex mutex;
    void **array;   /* a pointer array */
};

/* array-based dp_packet_afxdp */
struct xpacket_pool {
    unsigned int size;
    struct dp_packet_afxdp **array;
};

struct xdp_umem_uqueue {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    uint64_t *ring;
    void *map;
};

struct xdp_umem {
    struct umem_pool mpool;     /* a free list/array */
    struct xpacket_pool xpool;
    char *frames;
    struct xdp_umem_uqueue fq;
    struct xdp_umem_uqueue cq;
    int fd;
};

void __umem_elem_push(struct umem_pool *umemp, void *addr);
void umem_elem_push(struct umem_pool *umemp, void *addr);
void *__umem_elem_pop(struct umem_pool *umemp);
void *umem_elem_pop(struct umem_pool *umemp);
void **__umem_pool_alloc(unsigned int size);
int umem_pool_init(struct umem_pool *umemp, unsigned int size);
void umem_pool_cleanup(struct umem_pool *umemp);
unsigned int umem_elem_count(struct umem_pool *mpool);
void __umem_elem_pop_n(struct umem_pool *umemp, void **addrs, int n);
void __umem_elem_push_n(struct umem_pool *umemp, void **addrs, int n);
int xpacket_pool_init(struct xpacket_pool *xp, unsigned int size);
void xpacket_pool_cleanup(struct xpacket_pool *xp);

#endif
