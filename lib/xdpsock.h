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
#include <net/ethernet.h>
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

//#define DEBUG
#ifdef DEBUG
#define NUM_FRAMES 128
#define NUM_DESCS 64
#define FQ_NUM_DESCS 64
#define CQ_NUM_DESCS 64
#else
//#define NUM_FRAMES 131072
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

/* array-based stack */
struct umem_pool {
    int index; /* top */
    unsigned int size;
    struct ovs_mutex lock;
    void **array;
};

/* array-based dp_packet */
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
    //struct umem_elem_head head; /* a list to keep free frame */
    struct umem_pool mpool; /* a list to keep free frame */
    struct xpacket_pool xpool;
    char *frames;
    struct xdp_umem_uqueue fq; 
    struct xdp_umem_uqueue cq; 
    int fd; 
};
#if 0
void umem_elem_push(struct umem_elem_head *head,
                    struct umem_elem *elem);
struct umem_elem *umem_elem_pop(struct umem_elem_head *head);
unsigned int umem_elem_count(struct umem_elem_head *head);
#endif
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
