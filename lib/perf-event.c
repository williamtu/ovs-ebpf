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

#include <config.h>
#include "perf-event.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <openvswitch/vlog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "coverage.h"
#include "openvswitch/util.h"
#include "ovs-atomic.h"

VLOG_DEFINE_THIS_MODULE(perf_event);

COVERAGE_DEFINE(perf_lost);
COVERAGE_DEFINE(perf_sample);
COVERAGE_DEFINE(perf_unknown);

struct perf_event_lost {
    struct perf_event_header header;
    uint64_t id;
    uint64_t lost;
};

struct rb_cursor {
    struct perf_event_mmap_page *page;
    uint64_t head, tail;
};

static int
perf_event_open_fd(int *fd_out, int cpu)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_type = PERF_SAMPLE_RAW,
        .watermark = 0,
        .wakeup_events = 1,
    };
    int fd, error;

    fd = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
    if (fd < 0) {
        error = errno;
        VLOG_ERR("failed to open perf events (%s)", ovs_strerror(error));
        return error;
    }

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 1) == -1) {
        error = errno;
        VLOG_ERR("failed to reset perf events (%s)", ovs_strerror(error));
        return error;
    }

    *fd_out = fd;
    return 0;
}

int
perf_channel_open(struct perf_channel *channel, int cpu, size_t page_len)
{
    int fd = 0, error;
    void *page;

    error = perf_event_open_fd(&fd, cpu);
    if (error) {
        VLOG_WARN("failed to open perf channel (cpu %d): %s",
                  cpu, ovs_strerror(error));
        return error;
    }

    page = mmap(NULL, page_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (page == MAP_FAILED) {
        error = errno;
        VLOG_ERR("failed to mmap perf event fd (cpu %d): %s",
                 cpu, ovs_strerror(error));
        close(fd);
        return error;
    }
    channel->page = page;
    channel->cpu = cpu;
    channel->fd = fd;
    channel->length = page_len;

    return 0;
}

int
perf_channel_set(struct perf_channel *channel, bool enable)
{
    int request = enable ? PERF_EVENT_IOC_ENABLE : PERF_EVENT_IOC_DISABLE;

    if (ioctl(channel->fd, request, 0) == -1) {
        return errno;
    }
    return 0;
}

void
perf_channel_close(struct perf_channel *channel)
{
    if (ioctl(channel->fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        int error = errno;
        VLOG_ERR("failed to disable perf events (%s)",
                 ovs_strerror(error));
    }

    if (munmap((void *)channel->page, channel->length)) {
        VLOG_WARN("Failed to unmap page for cpu %d: %s",
                  channel->cpu, ovs_strerror(errno));
    }
    if (close(channel->fd)) {
        VLOG_WARN("Failed to close page for cpu %d: %s",
                  channel->cpu, ovs_strerror(errno));
    }
    channel->page = NULL;
    channel->fd = 0;
    channel->length = 0;
}

static uint8_t *
rb_base(struct rb_cursor *cursor)
{
    return ((uint8_t *)cursor->page) + cursor->page->data_offset;
}

static uint8_t *
rb_end(struct rb_cursor *cursor)
{
    return rb_base(cursor) + cursor->page->data_size;
}

static uint64_t
cursor_event_offset(struct rb_cursor *cursor)
{
    return cursor->tail % cursor->page->data_size;
}

static uint64_t
cursor_end_offset(struct rb_cursor *cursor)
{
    return cursor->head % cursor->page->data_size;
}

static void *
cursor_peek(struct rb_cursor *cursor)
{
    void *next = rb_base(cursor) + cursor_event_offset(cursor);
    void *end = rb_base(cursor) + cursor_end_offset(cursor);

    return (next != end) ? next : NULL;
}

static uint8_t *
event_end(struct perf_event_header *header)
{
    return (uint8_t *)header + header->size;
}

static bool
init_cursor(struct rb_cursor *cursor,
            struct perf_event_mmap_page *page)
{
    uint64_t head = *((volatile uint64_t *)&page->data_head);
    uint64_t tail = page->data_tail;

    /* Separate the read of 'data_head' from the read of the ringbuffer data.*/
    atomic_thread_fence(memory_order_consume);

    cursor->page = page;
    cursor->head = head;
    cursor->tail = tail;

    return head != tail;
}

static void
perf_event_pull(struct perf_event_mmap_page *page, uint64_t tail)
{
    /* Separate reads in the ringbuffer from the writing of the tail. */
    atomic_thread_fence(memory_order_release);
    page->data_tail = tail;
}

static bool
perf_event_copy(struct rb_cursor *cursor, struct ofpbuf *buffer)
{
    struct perf_event_header *header = cursor_peek(cursor);

    if (!header) {
        return false;
    }

    ofpbuf_clear(buffer);
    if (event_end(header) <= rb_end(cursor)) {
        ofpbuf_push(buffer, header, header->size);
    } else {
        uint64_t seg1_len = rb_end(cursor) - (uint8_t *)header;
        uint64_t seg2_len = header->size - seg1_len;

        ofpbuf_put(buffer, header, seg1_len);
        ofpbuf_put(buffer, rb_base(cursor), seg2_len);
    }

    buffer->header = buffer->data;
    cursor->tail += header->size;

    return true;
}

/* Reads the next full perf event from 'channel' into 'buffer'.
 *
 * 'buffer' may be reallocated, so the caller must subsequently uninitialize
 * it. 'buf->header' will be updated to point to the beginning of the event,
 * which starts with a 'struct perf_event_header'.
 *
 * Returns 0 if there is a new OVS event, otherwise a positive errno value.
 * Returns EAGAIN if there are no new events.
 */
int
perf_channel_read(struct perf_channel *channel, struct ofpbuf *buffer)
{
    struct rb_cursor cursor;
    int error = EAGAIN;

    if (!init_cursor(&cursor, channel->page)) {
        return error;
    }

    if (perf_event_copy(&cursor, buffer)) {
        struct perf_event_header *header = buffer->header;

        switch (header->type) {
        case PERF_RECORD_SAMPLE:
            /* Success! */
            COVERAGE_INC(perf_sample);
            error = 0;
            break;
        case PERF_RECORD_LOST: {
            struct perf_event_lost *e = buffer->header;
            COVERAGE_ADD(perf_lost, e->lost);
            error = ENOBUFS;
            break;
        }
        default:
            COVERAGE_INC(perf_unknown);
            error = EPROTO;
            break;
        }

        perf_event_pull(channel->page, cursor.tail);
    }

    return error;
}

void
perf_channel_flush(struct perf_channel *channel)
{
    struct perf_event_mmap_page *page = channel->page;
    uint64_t head = *((volatile uint64_t *)&page->data_head);

    /* The memory_order_consume fence is unnecessary when we don't read any
     * of the data from the ringbuffer - see perf_output_put_handle().
     * However, we still need to order the above read wrt to the tail write. */
    perf_event_pull(page, head);
}
