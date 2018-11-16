/*
 * Copyright (c) 2016, 2017, 2018 Nicira, Inc.
 *
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
 */
#include <openvswitch/compiler.h>
#include "api.h"
#include "helpers.h"
#include "maps.h"

/* eBPF executes actions by tailcall because eBPF doesn't support for-loop and
 * unroll produces oversized code.
 *
 * After flow lookup or downcall, actions are kept in the percpu_action_batch.
 * skb->cb[OVS_CB_ACT_IDX] is an index that points to the next action.
 */
static inline void ovs_execute_actions(struct __sk_buff *skb,
                                       struct bpf_action *action)
{
    enum ovs_action_attr type;
    type = action->type;

    printt("action type %d\n", type);

	/* note: this isn't a for loop, tail call won't return. */
    switch (type) {
    case OVS_ACTION_ATTR_UNSPEC:
        printt("end of action processing\n");
        break;
    case OVS_ACTION_ATTR_OUTPUT:
        printt("output action port = %d\n", action->u.out.port);
        break;
    case OVS_ACTION_ATTR_USERSPACE:
        printt("userspace action, len = %d, ifindex = %d upcall back\n",
               action->u.userspace.nlattr_len, ovs_cb_get_ifindex(skb));
        break;
    case OVS_ACTION_ATTR_SET:
        printt("set action, is_set_tunnel = %d\n",
               action->is_set_tunnel);
        break;
    case OVS_ACTION_ATTR_PUSH_VLAN:
        printt("vlan push tci %d\n", action->u.push_vlan.vlan_tci);
        break;
    case OVS_ACTION_ATTR_POP_VLAN:
        printt("vlan pop\n");
        break;
    case OVS_ACTION_ATTR_RECIRC:
        printt("recirc\n");
        break;
    case OVS_ACTION_ATTR_HASH:
        printt("hash\n");
        break;
    case OVS_ACTION_ATTR_SET_MASKED:
        printt("set masked\n");
        break;
    case OVS_ACTION_ATTR_CT:
        printt("ct\n");
        break;
    case OVS_ACTION_ATTR_TRUNC:
        printt("truncate\n");
        break;
	case OVS_ACTION_ATTR_SAMPLE:       /* Nested case OVS_SAMPLE_ATTR_*. */
	case OVS_ACTION_ATTR_PUSH_MPLS:    /* struct ovs_action_push_mpls. */
	case OVS_ACTION_ATTR_POP_MPLS:     /* __be16 ethertype. */
	case OVS_ACTION_ATTR_PUSH_ETH:     /* struct ovs_action_push_eth. */
	case OVS_ACTION_ATTR_POP_ETH:      /* No argument. */
	case OVS_ACTION_ATTR_CT_CLEAR:     /* No argument. */
	case OVS_ACTION_ATTR_PUSH_NSH:     /* Nested case OVS_NSH_KEY_ATTR_*. */
	case OVS_ACTION_ATTR_POP_NSH:      /* No argument. */
#ifndef __KERNEL__
	case OVS_ACTION_ATTR_TUNNEL_PUSH:   /* struct ovs_action_push_tnl*/
	case OVS_ACTION_ATTR_TUNNEL_POP:    /* u32 port number. */
	case OVS_ACTION_ATTR_CLONE:         /* Nested case OVS_CLONE_ATTR_*.  */
	case OVS_ACTION_ATTR_METER:         /* u32 meter number. */
#endif
	case __OVS_ACTION_ATTR_MAX:
#ifdef __KERNEL__
	case OVS_ACTION_ATTR_SET_TO_MASKED: /* Kernel module internal masked
					* set action converted from
					* case OVS_ACTION_ATTR_SET. */
#endif
    default:
        printt("ERR: action type %d not supportedn", type);
        break;
    }

    bpf_tail_call(skb, &tailcalls, type);

    /* OVS_NOT_REACHED */
    return;
}

static inline void
stats_account(enum ovs_bpf_dp_stats index)
{
    uint32_t stat = 1;
    uint64_t *value;

    value = map_lookup_elem(&datapath_stats, &index);
    if (value) {
        __sync_fetch_and_add(value, stat);
    }
}

/* OVS revalidator thread reads each entry in eBPF map
 * (flow_table and dp_flow_stats), reports to OpenFlow
 * table statistics, and decide to remove/keep the entry
 * by comparing its timestamp.
 */
static inline void
flow_stats_account(struct ebpf_headers_t *headers,
                   struct ebpf_metadata_t *mds,
                   size_t bytes)
{
    struct bpf_flow_key flow_key;
    struct bpf_flow_stats *flow_stats;

    flow_key.headers = *headers;
    flow_key.mds = *mds;

    flow_stats = bpf_map_lookup_elem(&dp_flow_stats, &flow_key);
    if (!flow_stats) {
        struct bpf_flow_stats s = {0, 0, 0};
        int err;

        printt("flow not found in flow stats, first install\n");
        s.packet_count = 1;
        s.byte_count = bytes;
        s.used = bpf_ktime_get_ns() / (1000*1000); /* msec */
        err = bpf_map_update_elem(&dp_flow_stats, &flow_key, &s, BPF_ANY);
        if (err) {
            return;
        }
    } else {
        flow_stats->packet_count += 1;
        flow_stats->byte_count += bytes;
        flow_stats->used = bpf_ktime_get_ns() / (1000*1000); /* msec */
        printt("current: packets %d count %d ts %d\n",
            flow_stats->packet_count, flow_stats->byte_count, flow_stats->used);
    }

    return;
}

static inline void
ovs_flow_mask_key(struct bpf_flow_key *dst, struct bpf_flow_key *src,
                  struct bpf_flow_key *mask)
{
    const long *m = (const long *) mask;
    const long *s = (const long *) src;
    long *d = (long *) dst;
    int i;

    #pragma unroll
    for (i = 0; i < sizeof *dst; i += sizeof(long)) {
        *d++ = *s++ & *m++;
    }
}

static inline struct bpf_action_batch *
megaflow_lookup(struct bpf_flow_key *key)
{
    struct bpf_megaflow_key megaflow_key = {};
    struct bpf_megaflow_entry *entry;
    struct bpf_megaflow_mask *mask;
    int i, idx;

    #pragma unroll
    for (i = 0; i < BPF_DP_MAX_MEGAFLOW_MASK; ++i) {
        idx = i;
        mask = bpf_map_lookup_elem(&megaflow_mask_table, &idx);

        if (!mask) {
            break;
        } else if (mask->is_valid) {
            ovs_flow_mask_key(&megaflow_key.masked_key, key, &mask->mask);
            megaflow_key.mask_id = i;

            entry = bpf_map_lookup_elem(&megaflow_table, &megaflow_key);
            if (entry) {
                printt("Hit megaflow cache, mask %d\n", i);
                return &entry->action_batch;
            }
        }
    }

    printt("Miss megaflow cache\n");
    return NULL;
}

static inline struct bpf_action_batch *
ovs_lookup_flow(struct bpf_flow_key *flow_key)
{
    struct bpf_action_batch *actions = NULL;

    /* EMC lookup */
    actions = bpf_map_lookup_elem(&flow_table, flow_key);
    if (actions) {
        printt("Hit EMC\n");
        return actions;
    }
    printt("Miss EMC\n");

    /* Megaflow lookup */
    return  megaflow_lookup(flow_key);
}

__section_tail(MATCH_ACTION_CALL)
static int lookup(struct __sk_buff* skb OVS_UNUSED)
{
    struct bpf_action_batch *action_batch;
    struct bpf_flow_key *flow_key;

    flow_key = bpf_get_flow_key();
    if (!flow_key) {
        printt("no flow key found\n");
        ERR_EXIT();
    }

    /* LOOKUP */
    action_batch = ovs_lookup_flow(flow_key);
    if (!action_batch) {
        printt("no action found, upcall to userspace\n");
        bpf_tail_call(skb, &tailcalls, UPCALL_CALL);

        /* OVS_NOT_REACHED */
        return TC_ACT_OK;
    } else {
        printt("action found! stay in BPF\n");
        /* DP Stats Update */
        stats_account(OVS_DP_STATS_HIT);
        /* Flow Stats Update */
        flow_stats_account(&flow_key->headers, &flow_key->mds, skb->len);
    }

    /* Set action batch to percpu map. */
    int index = 0;
    int error = bpf_map_update_elem(&percpu_action_batch, &index,
                                    action_batch, BPF_ANY);
    if (error) {
        printt("update percpu_action_batch failed: %d\n", error);
        return TC_ACT_OK;
    }

    /* the subsequent actions will be tail called. */
    ovs_execute_actions(skb, &action_batch->actions[0]);

    printt("ERROR: tail call fails\n");

    /* OVS_NOT_REACHED */
    return TC_ACT_OK;
}
