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
