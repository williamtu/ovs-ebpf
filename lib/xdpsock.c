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
#include "openvswitch/vlog.h"
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
#include "async-append.h"
#include "coverage.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofpbuf.h"
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
#include "xdpsock.h"
#include "openvswitch/compiler.h"
#include "dp-packet.h"

void
__umem_elem_push_n(struct umem_pool *umemp, void **addrs, int n)
{
    void *ptr;

    if (OVS_UNLIKELY(umemp->index + n > umemp->size)) {
        OVS_NOT_REACHED();
    }

    ptr = &umemp->array[umemp->index];
    memcpy(ptr, addrs, n * sizeof(void *));
    umemp->index += n;
}

inline void
__umem_elem_push(struct umem_pool *umemp, void *addr)
{
    umemp->array[umemp->index++] = addr;
}

void
umem_elem_push(struct umem_pool *umemp, void *addr)
{

    if (OVS_UNLIKELY(umemp->index >= umemp->size)) {
        /* stack is full */
        OVS_NOT_REACHED();
    }

    ovs_mutex_lock(&umemp->mutex);
    __umem_elem_push(umemp, addr);
    ovs_mutex_unlock(&umemp->mutex);
}

void
__umem_elem_pop_n(struct umem_pool *umemp, void **addrs, int n)
{
    void *ptr;

    umemp->index -= n;

    if (OVS_UNLIKELY(umemp->index < 0)) {
        OVS_NOT_REACHED();
    }

    ptr = &umemp->array[umemp->index];
    memcpy(addrs, ptr, n * sizeof(void *));
}

inline void *
__umem_elem_pop(struct umem_pool *umemp)
{
    return umemp->array[--umemp->index];
}

void *
umem_elem_pop(struct umem_pool *umemp)
{
    void *ptr;

    ovs_mutex_lock(&umemp->mutex);
    ptr = __umem_elem_pop(umemp);
    ovs_mutex_unlock(&umemp->mutex);

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
umem_pool_init(struct umem_pool *umemp, unsigned int size)
{
    umemp->array = __umem_pool_alloc(size);
    if (!umemp->array)
        OVS_NOT_REACHED();

    umemp->size = size;
    umemp->index = 0;
    ovs_mutex_init(&umemp->mutex);
    return 0;
}

void
umem_pool_cleanup(struct umem_pool *umemp)
{
    free(umemp->array);
}

/* AF_XDP metadata init/destroy */
int
xpacket_pool_init(struct xpacket_pool *xp, unsigned int size)
{
    void *bufs;

    ovs_assert(posix_memalign(&bufs, getpagesize(),
                              size * sizeof(struct dp_packet_afxdp)) == 0);

    xp->array = bufs;
    xp->size = size;
    return 0;
}

void
xpacket_pool_cleanup(struct xpacket_pool *xp)
{
    free(xp->array);
}
