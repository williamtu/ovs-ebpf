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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "openvswitch/vlog.h"
#include "async-append.h"
#include "coverage.h"
#include "dirs.h"
#include "ovs-thread.h"
#include "sat-math.h"
#include "socket-util.h"
#include "svec.h"
#include "syslog-direct.h"
#include "syslog-libc.h"
#include "syslog-provider.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "ovs-atomic.h"
#include "openvswitch/compiler.h"
#include "dp-packet.h"

#include "xdpsock.h"

static inline void ovs_spinlock_init(ovs_spinlock_t *sl)
{
    sl->locked = 0;
}

static inline void ovs_spin_lock(ovs_spinlock_t *sl)
{
    int exp = 0, locked = 0;

    while (!atomic_compare_exchange_strong_explicit(&sl->locked, &exp, 1,
                memory_order_acquire,
                memory_order_relaxed)) {
        locked = 1;
        while (locked) {
            atomic_read_relaxed(&sl->locked, &locked);
        }
        exp = 0;
    }
}

static inline void ovs_spin_unlock(ovs_spinlock_t *sl)
{
    atomic_store_explicit(&sl->locked, 0, memory_order_release);
}

static inline int OVS_UNUSED ovs_spin_trylock(ovs_spinlock_t *sl)
{
    int exp = 0;
    return atomic_compare_exchange_strong_explicit(&sl->locked, &exp, 1,
                memory_order_acquire,
                memory_order_relaxed);
}

inline int
__umem_elem_push_n(struct umem_pool *umemp, int n, void **addrs)
{
    void *ptr;

    if (OVS_UNLIKELY(umemp->index + n > umemp->size)) {
        return -ENOMEM;
    }

    ptr = &umemp->array[umemp->index];
    memcpy(ptr, addrs, n * sizeof(void *));
    umemp->index += n;

    return 0;
}

int umem_elem_push_n(struct umem_pool *umemp, int n, void **addrs)
{
    int ret;

    ovs_spin_lock(&umemp->mutex);
    ret = __umem_elem_push_n(umemp, n, addrs);
    ovs_spin_unlock(&umemp->mutex);

    return ret;
}

inline void
__umem_elem_push(struct umem_pool *umemp OVS_UNUSED, void *addr)
{
    umemp->array[umemp->index++] = addr;
}

void
umem_elem_push(struct umem_pool *umemp OVS_UNUSED, void *addr)
{

    if (OVS_UNLIKELY(umemp->index >= umemp->size)) {
        /* stack is full */
        /* it's possible that one umem gets pushed twice,
         * because actions=1,2,3... multiple ports?
        */
        OVS_NOT_REACHED();
    }

    ovs_assert(((uint64_t)addr & FRAME_SHIFT_MASK) == 0);

    ovs_spin_lock(&umemp->mutex);
    __umem_elem_push(umemp, addr);
    ovs_spin_unlock(&umemp->mutex);
}

inline int
__umem_elem_pop_n(struct umem_pool *umemp, int n, void **addrs)
{
    void *ptr;

    if (OVS_UNLIKELY(umemp->index - n < 0)) {
        return -ENOMEM;
    }

    umemp->index -= n;
    ptr = &umemp->array[umemp->index];
    memcpy(addrs, ptr, n * sizeof(void *));

    return 0;
}

int
umem_elem_pop_n(struct umem_pool *umemp, int n, void **addrs)
{
    int ret;

    ovs_spin_lock(&umemp->mutex);
    ret = __umem_elem_pop_n(umemp, n, addrs);
    ovs_spin_unlock(&umemp->mutex);

    return ret;
}

inline void *
__umem_elem_pop(struct umem_pool *umemp OVS_UNUSED)
{
    return umemp->array[--umemp->index];
}

void *
umem_elem_pop(struct umem_pool *umemp OVS_UNUSED)
{
    void *ptr;

    ovs_spin_lock(&umemp->mutex);
    ptr = __umem_elem_pop(umemp);
    ovs_spin_unlock(&umemp->mutex);

    return ptr;
}

void **
__umem_pool_alloc(unsigned int size)
{
    void *bufs;

    ovs_assert(posix_memalign(&bufs, getpagesize(),
                              size * sizeof(void *)) == 0);
    memset(bufs, 0, size * sizeof(void *));
    return (void **)bufs;
}

unsigned int
umem_elem_count(struct umem_pool *mpool)
{
    return mpool->index;
}

int
umem_pool_init(struct umem_pool *umemp OVS_UNUSED, unsigned int size)
{
    umemp->array = __umem_pool_alloc(size);
    if (!umemp->array) {
        OVS_NOT_REACHED();
    }

    umemp->size = size;
    umemp->index = 0;
    ovs_spinlock_init(&umemp->mutex);
    return 0;
}

void
umem_pool_cleanup(struct umem_pool *umemp OVS_UNUSED)
{
    free(umemp->array);
}

/* AF_XDP metadata init/destroy */
int
xpacket_pool_init(struct xpacket_pool *xp, unsigned int size)
{
    void *bufs;

    /* TODO: check HAVE_POSIX_MEMALIGN  */
    ovs_assert(posix_memalign(&bufs, getpagesize(),
                              size * sizeof(struct dp_packet_afxdp)) == 0);
    memset(bufs, 0, size * sizeof(struct dp_packet_afxdp));

    xp->array = bufs;
    xp->size = size;
    return 0;
}

void
xpacket_pool_cleanup(struct xpacket_pool *xp)
{
    free(xp->array);
}
