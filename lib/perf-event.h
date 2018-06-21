/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PERF_EVENT_H
#define PERF_EVENT_H 1

#include <linux/perf_event.h>
#include "openvswitch/ofpbuf.h"
#include "openvswitch/types.h"

struct perf_event_raw {
    struct perf_event_header header;
    uint32_t size;
    /* Followed by uint8_t data[size]; */
};

struct perf_channel {
    struct perf_event_mmap_page *page;
    int cpu;
    int fd;
    size_t length;
};

int perf_channel_open(struct perf_channel *, int cpu, size_t page_len);
int perf_channel_set(struct perf_channel *channel, bool enable);
int perf_channel_read(struct perf_channel *, struct ofpbuf *);
void perf_channel_flush(struct perf_channel *);
void perf_channel_close(struct perf_channel *);

#endif /* PERF_EVENT_H */
