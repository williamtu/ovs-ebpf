/*
 * Copyright (c) 2016, 2017, 2018 Nicira, Inc.
 *
 * This file is offered under your choice of two licenses: Apache 2.0 or GNU
 * GPL 2.0 or later.  The permission statements for each of these licenses is
 * given below.  You may license your modifications to this file under either
 * of these licenses or both.  If you wish to license your modifications under
 * only one of these licenses, delete the permission text for the other
 * license.
 *
 * ----------------------------------------------------------------------
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
 * ----------------------------------------------------------------------
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 * ----------------------------------------------------------------------
 */

#ifndef BPFMAP_OPENVSWITCH_H
#define BPFMAP_OPENVSWITCH_H 1

#include "api.h"
#include "openvswitch.h"
#include "helpers.h"
#include "generated_headers.h"

/* ovs-vswitchd as a writer will update these maps.
 * bpf datapath as reader lookup and processes */

/* FIXME: copy from iproute2 */
enum {
    BPF_MAP_ID_PROTO,
    BPF_MAP_ID_QUEUE,
    BPF_MAP_ID_DROPS,
    BPF_MAP_ID_ACTION,
    BPF_MAP_ID_INGRESS,
    __BPF_MAP_ID_MAX,
#define BPF_MAP_ID_MAX  __BPF_MAP_ID_MAX
};

/* A bpf flow key is extracted from the
 * parser.h and saved in percpu_flow_key.
 * Access: BPF is the only writer/reader
 */
BPF_PERCPU_ARRAY(percpu_flow_key,
        0,
        sizeof(struct bpf_flow_key),
        0,
        1
);

/* BPF flow tale
 * Access: BPF is the reader for lookup,
 *         ovs-vswitchd is the writer
 */
BPF_HASH(flow_table,
        0,
        sizeof(struct bpf_flow_key),
        sizeof(struct bpf_action_batch),
        0,
        256
);

/* BPF flow stats table
 * Access: BPF is the writer for updating,
 *         ovs-vswitchd/revalidator is the reader
 */
BPF_HASH(dp_flow_stats,
        0,
        sizeof(struct bpf_flow_key),
        sizeof(struct bpf_flow_stats),
        0,
        256
);

/*
 * Map for implementing the upcall, which forwards the
 * first packet (lookup misses) to ovs-vswitchd
 */
BPF_PERF_OUTPUT(upcalls, 0);


/* BPF datapath stats
 * Access: BPF is the writer,
 *         ovs-vswitchd is the reader
 * XXX: switch to percpu to improve performance
 */
BPF_ARRAY(datapath_stats,
        0,
        sizeof(uint64_t),
        0,
        __OVS_DP_STATS_MAX
);

/* Global tail call map:
 *  index  0-31 for actions (OVS_ACTION_ATTR_*)
 *  index 32-63 for others
 */
BPF_PROG_ARRAY(tailcalls,
        0,
        0,
        64
);

/* A dedicated metadata field for downcall packet.
 * Access: ovs-vswitchd is the writer,
 *         BPF is the reader
 */
BPF_ARRAY(downcall_metadata,
        0,
        sizeof(struct bpf_downcall),
        0,
        1
);

/* A dedicated action list for downcall packet.
 * Access: ovs-vswitchd is the writer,
 *         BPF is the reader
 */
BPF_ARRAY(execute_actions,
        0,
        sizeof(struct bpf_action_batch),
        0,
        1
);

/* A dedicated action list after flow table lookup.
 * Access: BPF is the reader and writer.
 * Write in flow lookup or downcall, read in action execution.
 */
BPF_PERCPU_ARRAY(percpu_action_batch,
        0,
        sizeof(struct bpf_action_batch),
        0,
        1
);

struct bpf_flow_key;

static inline struct bpf_flow_key *bpf_get_flow_key()
{
    int ebpf_zero = 0;
    return bpf_map_lookup_elem(&percpu_flow_key, &ebpf_zero);
}

static inline struct bpf_action_batch *bpf_get_action_batch()
{
    int ebpf_zero = 0;
    return bpf_map_lookup_elem(&percpu_action_batch, &ebpf_zero);
}

#endif /* BPFMAP_OPENVSWITCH_H */
