/*
 * Copy most of the ptr_ring implementation from kernel 
 * and use it in userspace.
 */

#include <errno.h>
#include <stdlib.h>
#include <config.h>
#include <unistd.h>
#include "ptr_ring.h"

static inline void *__ptr_ring_peek(struct ptr_ring *r)
{
    if (OVS_LIKELY(r->size)) {
        return READ_ONCE(r->queue[r->consumer_head]);
    }
    return NULL;
}

static inline void __ptr_ring_discard_one(struct ptr_ring *r)
{
    int consumer_head = r->consumer_head;
    int head = consumer_head++;

    if (OVS_UNLIKELY(consumer_head - r->consumer_tail >= r->batch ||
                     consumer_head >= r->size)) {

        while(OVS_LIKELY(head >= r->consumer_tail)) {
            r->queue[head--] = NULL;
        }
        r->consumer_tail = consumer_head;
    }
    if (OVS_UNLIKELY(consumer_head >= r->size)) {
        consumer_head = 0;
        r->consumer_tail = 0;
    }
    WRITE_ONCE(r->consumer_head, consumer_head);
}

static inline void *__ptr_ring_consume(struct ptr_ring *r)
{
    void *ptr;

    ptr = __ptr_ring_peek(r);
    if (ptr) {
        __ptr_ring_discard_one(r);
    }

    return ptr;
}

void *ptr_ring_consume(struct ptr_ring *r)
{
    void *ptr;

    ovs_mutex_lock(&r->consumer_lock);
    ptr = __ptr_ring_consume(r);
    ovs_mutex_unlock(&r->consumer_lock);

    return ptr;
}

static inline int __ptr_ring_produce(struct ptr_ring *r, void *ptr)
{
    if (OVS_UNLIKELY(!r->size) || r->queue[r->producer]) {
        return -ENOSPC;
    }

    WRITE_ONCE(r->queue[r->producer++], ptr);
    if (OVS_UNLIKELY(r->producer >= r->size)) {
        r->producer = 0;
    }

    return 0;
}

int ptr_ring_produce(struct ptr_ring *r, void *ptr)
{
    int ret;

    ovs_mutex_lock(&r->producer_lock);
    ret = __ptr_ring_produce(r, ptr);
    ovs_mutex_unlock(&r->producer_lock);

    return ret;
}

bool __ptr_ring_full(struct ptr_ring *r)
{
    return r->queue[r->producer];
}

bool __ptr_ring_empty(struct ptr_ring *r)
{
		u_smp_rmb();
    if (OVS_LIKELY(r->size)) {
        return !r->queue[READ_ONCE(r->consumer_head)];
    }
    return true;
}

static inline void __ptr_ring_set_size(struct ptr_ring *r, int size)
{
    r->size = size;
    r->batch = 16; 

    if (r->batch > r->size / 2 || !r->batch) {
        r->batch = 1;
    }
}

static inline void **__ptr_ring_init_queue_alloc(unsigned int size)
{
    void *bufs;
    ovs_assert(posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
                              size * sizeof(void *)) == 0);
    memset(bufs, 0, size * sizeof(void *));
    return (void **)bufs; 
}

int ptr_ring_init(struct ptr_ring *r, int size)
{
    r->queue = __ptr_ring_init_queue_alloc(size);
    if (!r->queue)
        return -ENOMEM;

    __ptr_ring_set_size(r, size);
    r->producer = r->consumer_head = r->consumer_tail = 0; 
    ovs_mutex_init(&r->producer_lock);
    ovs_mutex_init(&r->consumer_lock);
    return 0;
}

void ptr_ring_cleanup(struct ptr_ring *r)
{
    free(r->queue);
}
