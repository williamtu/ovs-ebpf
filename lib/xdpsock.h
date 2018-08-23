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

#define FRAME_HEADROOM 128
#define FRAME_SHIFT 11
#define FRAME_SIZE 2048
#define BATCH_SIZE 16

#define NUM_FRAMES 128
#define FRAME_SIZE 2048
#define NUM_DESCS 64 

#define FQ_NUM_DESCS 32
#define CQ_NUM_DESCS 32

struct umem_elem_head {
    struct umem_elem *next;
    struct ovs_mutex mutex;
    uint32_t n;
};

struct umem_elem {
    struct umem_elem *next;
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
    struct umem_elem_head head; /* a list to keep free frame */
    char *frames;
    struct xdp_umem_uqueue fq; 
    struct xdp_umem_uqueue cq; 
    int fd; 
};

void umem_elem_push(struct umem_elem_head *head,
                    struct umem_elem *elem);
struct umem_elem *umem_elem_pop(struct umem_elem_head *head);
unsigned int umem_elem_count(struct umem_elem_head *head);
#endif
