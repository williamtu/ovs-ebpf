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
#ifndef SPINLOCK_H
#define SPINLOCK_H 1

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "ovs-atomic.h"

struct OVS_LOCKABLE ovs_spinlock {
    atomic_int locked;
    const char *where;  /* NULL if and only if uninitialized. */
};

static inline void
ovs_spinlock_init(struct ovs_spinlock *sl)
{
    sl->where = "<unlocked>";
    atomic_init(&sl->locked, 0);
}

static inline void
ovs_spin_lock_at(struct ovs_spinlock *sl, const char *w) OVS_ACQUIRES(sl)
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
    sl->where = w;
}
#define ovs_spin_lock(sl) \
        ovs_spin_lock_at(sl, OVS_SOURCE_LOCATOR)

static inline void
ovs_spin_unlock_at(struct ovs_spinlock *sl, const char *w) OVS_RELEASES(sl)
{
    atomic_store_explicit(&sl->locked, 0, memory_order_release);
    sl->where = w;
}
#define ovs_spin_unlock(sl) \
        ovs_spin_unlock_at(sl, OVS_SOURCE_LOCATOR)

static inline int
ovs_spin_trylock_at(struct ovs_spinlock *sl, const char *w) OVS_TRY_LOCK(0, sl)
{
    int exp = 0;

    sl->where = w;
    return atomic_compare_exchange_strong_explicit(&sl->locked, &exp, 1,
                memory_order_acquire,
                memory_order_relaxed);
}
#define ovs_spin_trylock(sl) \
        ovs_spin_trylock_at(sl, OVS_SOURCE_LOCATOR)
#endif
