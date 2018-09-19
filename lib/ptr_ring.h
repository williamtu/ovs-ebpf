/*
 * Copy most of the ptr_ring implementation from kernel 
 * and use it in userspace.
 */
#ifndef _LINUX_PTR_RING_H
#define _LINUX_PTR_RING_H 1

#include "compiler.h"
#include "util.h"
#include "openvswitch/util.h"
#include "openvswitch/thread.h"

#define barrier() __asm__ __volatile__("": : :"memory")
#ifdef __aarch64__
#define u_smp_rmb() __asm__ __volatile__("dmb ishld": : :"memory")
#define u_smp_wmb() __asm__ __volatile__("dmb ishst": : :"memory")
#else
#define u_smp_rmb() barrier()
#define u_smp_wmb() barrier()
#endif

#define READ_ONCE(x) (*(volatile typeof(x) *) &(x))
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *) &(x)) = (val))

struct ptr_ring {
    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
        /* producer */
        int producer; /* ___cacheline_aligned_in_smp */
        struct ovs_mutex producer_lock;
    );

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline1,
        /* consumer */
        int consumer_head; /* ___cacheline_aligned_in_smp */
        int consumer_tail;
        struct ovs_mutex consumer_lock; 
    );

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline2,
        /* the ring */
        int size; /*___cacheline_aligned_in_smp */
        int batch;
        void **queue;
    );
};

void *ptr_ring_consume(struct ptr_ring *r);
int ptr_ring_produce(struct ptr_ring *r, void *ptr);
bool ptr_ring_full(struct ptr_ring *r);
bool ptr_ring_empty(struct ptr_ring *r);
int ptr_ring_init(struct ptr_ring *r, int size);
void ptr_ring_cleanup(struct ptr_ring *r);
#endif
