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

/* OVS Datapath Execution
 * ======================
 *
 * When a lookup is successful the eBPF gets a list of actions to be
 * executed,  such as outputting the packet to a certain port, or
 * pushing a VLAN tag.  The list of actions is configured in ovs-vswitchd
 * and may be a variable length depending on the desired network processing
 * behaviour. For example, an L2 switch doing unknown broadcast sends
 * packet to all its current ports. The OVS datapath’s actions is derived
 * from the OpenFlow action specification and the OVSDB schema for
 * ovs-vswitchd.
 *
 */
#include <errno.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/ip.h>

#include "api.h"
#include "maps.h"
#include "helpers.h"

#define ENABLE_POINTER_LOOKUP 1

#define ALIGNED_CAST(TYPE, ATTR) ((TYPE) (void *) (ATTR))

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define TTL_OFF (ETH_HLEN + offsetof(struct iphdr, ttl))
#define DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))

static inline void set_ip_tos(struct __sk_buff *skb, __u8 new_tos)
{
    __u8 old_tos;

    bpf_skb_load_bytes(skb, TOS_OFF, &old_tos, 1);

    if (old_tos == new_tos) {
        printt("tos not change %d\n", old_tos);
        return;
    }

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_tos, new_tos, 2);

    /* Use helper here because using direct packet
     * access causes verifier error
     */
    bpf_skb_store_bytes(skb, TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

static inline void set_ip_ttl(struct __sk_buff *skb, __u8 new_ttl)
{
    __u8 old_ttl;

    bpf_skb_load_bytes(skb, TTL_OFF, &old_ttl, 1);

    if (old_ttl == new_ttl) {
        printt("ttl not change %d\n", old_ttl);
        return;
    }

    printt("old ttl %d -> new ttl %d\n", old_ttl, new_ttl);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ttl, new_ttl, 2);
    bpf_skb_store_bytes(skb, TTL_OFF, &new_ttl, sizeof(new_ttl), 0);
}

static inline void set_ip_dst(struct __sk_buff *skb, ovs_be32 new_dst)
{
    ovs_be32 old_dst;

    bpf_skb_load_bytes(skb, DST_OFF, &old_dst, 4);

    if (old_dst == new_dst) {
        printt("dst ip not change %x\n", old_dst);
        return;
    }
    printt("old dst %x -> new dst %x\n", old_dst, new_dst);

    l3_csum_replace4(skb, IP_CSUM_OFF, old_dst, new_dst);
    bpf_skb_store_bytes(skb, DST_OFF, &new_dst, sizeof(new_dst), 0);
}

static inline void set_ip_src(struct __sk_buff *skb, ovs_be32 new_src)
{
    ovs_be32 old_src;

    bpf_skb_load_bytes(skb, SRC_OFF, &old_src, 4);

    if (old_src == new_src) {
        printt("src ip not change %x\n", old_src);
        return;
    }
    printt("old src %x -> new src %x\n", old_src, new_src);

    l3_csum_replace4(skb, IP_CSUM_OFF, old_src, new_src);
    bpf_skb_store_bytes(skb, SRC_OFF, &new_src, sizeof(new_src), 0);
}

/*
 * Every OVS action need to lookup the action list and
 * with index, find out the next action to process
 */
static inline struct bpf_action *pre_tail_action(struct __sk_buff *skb,
    struct bpf_action_batch **__batch)
{
    uint32_t index = ovs_cb_get_action_index(skb);
    struct bpf_action *action = NULL;
    struct bpf_action_batch *batch;

    if (index >= BPF_DP_MAX_ACTION) {
        printt("ERR max ebpf action hit\n");
        return NULL;
    }

    batch = bpf_get_action_batch();

    if (!batch) {
        printt("no batch action found\n");
        return NULL;
    }

    *__batch = batch;
    action = &((batch)->actions[index]);
    return action;
}

/*
 * After processing the action, tail call the next.
 */
static inline int post_tail_action(struct __sk_buff *skb,
    struct bpf_action_batch *batch)
{
    struct bpf_action *next_action;
    uint32_t index;

    if (!batch)
        return TC_ACT_SHOT;

    index = skb->cb[OVS_CB_ACT_IDX] + 1;
    skb->cb[OVS_CB_ACT_IDX] = index;

    if (index >= BPF_DP_MAX_ACTION)
        goto finish;

    next_action = &batch->actions[index];
    if (next_action->type == 0)
        goto finish;

    printt("next action type = %d\n", next_action->type);
    bpf_tail_call(skb, &tailcalls, next_action->type);

    printt("[BUG] tail call missing\n");
    return TC_ACT_SHOT;

finish:
    return TC_ACT_STOLEN;
}

/*
 * Use this action to indicate end of action list
 * BPF program: tail-0
 */
__section_tail(OVS_ACTION_ATTR_UNSPEC)
static int tail_action_unspec(struct __sk_buff *skb)
{
    int index OVS_UNUSED = ovs_cb_get_action_index(skb);

    printt("action index = %d, end of processing\n", index);

    /* Handle actions=drop, we return SHOT so the device's dropped stats
       will be incremented (see sch_handle_ingress). 

       If there are more actions, ex: actions=a1,a2,drop, this is
       handled in post_tail_actions and return STOLEN
    */
    return TC_ACT_SHOT;
}

/*
 * BPF program: tail-1
 */
__section_tail(OVS_ACTION_ATTR_OUTPUT)
static int tail_action_output(struct __sk_buff *skb)
{
    int ret __attribute__((__unused__));
    struct bpf_action *action;
    struct bpf_action_batch *batch;
    int flags;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* Internal dev is tap type and hooked only to bpf egress filter.
       When output to an internal device, a packet is clone-redirected to
       this device's ingress so that this packet is processed by kernel stack.
       Why? Since if the packet is sent to its egress, it is delivered to the
       tap device's socket, not kernel.
    */
    flags = action->u.out.flags & OVS_BPF_FLAGS_TX_STACK ? BPF_F_INGRESS : 0;
    printt("output action port = %d ingress? %d\n",
           action->u.out.port, (flags));

    bpf_clone_redirect(skb, action->u.out.port, flags);

    return post_tail_action(skb, batch);
}

/*
 * This action implements OVS userspace
 * BPF program: tail-2
 */
__section_tail(OVS_ACTION_ATTR_USERSPACE)
static int tail_action_userspace(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* XXX If move this declaration to top, the stack will overflow. */
    struct bpf_upcall md = {
        .type = OVS_UPCALL_ACTION,
        .skb_len = skb->len,
        .ifindex = skb->ifindex,
    };

    if (action->u.userspace.nlattr_len > sizeof(md.uactions)) {
        printt("userspace action is too large\n");
        return TC_ACT_SHOT;
    }

    memcpy(md.uactions, action->u.userspace.nlattr_data, sizeof(md.uactions));
    md.uactions_len = action->u.userspace.nlattr_len;

    struct bpf_flow_key *flow_key = bpf_get_flow_key();
    if (!flow_key) {
        printt("flow key is NULL\n");
        return TC_ACT_SHOT;
    }

    memcpy(&md.key.headers, &flow_key->headers, sizeof(flow_key->headers));

    uint64_t flags = skb->len;
    flags <<= 32;
    flags |= BPF_F_CURRENT_CPU;
    int err = skb_event_output(skb, &upcalls, flags, &md, sizeof md);

    if (err) {
        printt("skb_event_output of userspace action: %d", err);
        return TC_ACT_SHOT;
    }

    return post_tail_action(skb, batch);
}

/*
 * This action implements BPF tunnel
 * BPF program: tail-3
 */
__section_tail(OVS_ACTION_ATTR_SET)
static int tail_action_tunnel_set(struct __sk_buff *skb)
{
    struct bpf_tunnel_key key;
    int ret;
    uint64_t flags;

    struct bpf_action *action;
    struct bpf_action_batch *batch;
    struct ovs_action_set_tunnel *tunnel;
    int key_attr;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* SET for tunnel */
    if (action->is_set_tunnel) {
        tunnel = &action->u.tunnel;

        /* hard-coded now, should fetch it from action->u */
        __builtin_memset(&key, 0x0, sizeof(key));
        key.tunnel_id = tunnel->tunnel_id;
        key.tunnel_tos = tunnel->tunnel_tos;
        key.tunnel_ttl = tunnel->tunnel_ttl;

        printt("tunnel_id = %x\n", key.tunnel_id);

        /* TODO: handle BPF_F_DONT_FRAGMENT and BPF_F_SEQ_NUMBER */
        flags = BPF_F_ZERO_CSUM_TX;
        if (!tunnel->use_ipv6) {
            key.remote_ipv4 = tunnel->remote_ipv4;
            flags &= ~BPF_F_TUNINFO_IPV6;
        } else {
            memcpy(&key.remote_ipv4, &tunnel->remote_ipv4, 16);
            flags |= BPF_F_TUNINFO_IPV6;
        }

        ret = bpf_skb_set_tunnel_key(skb, &key, sizeof(key), flags);
        if (ret < 0)
            printt("ERR setting tunnel key\n");

        if (tunnel->gnvopt_valid) {
            ret = bpf_skb_set_tunnel_opt(skb, &tunnel->gnvopt,
                                         sizeof tunnel->gnvopt);
            if (ret < 0)
                printt("ERR setting tunnel opt\n");
        }

        return post_tail_action(skb, batch);
    }

    /* SET for packet fields */
    key_attr = action->u.mset.key_type;

    switch (key_attr) {
    case OVS_KEY_ATTR_ETHERNET: {
        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;
        struct ethhdr *eth;
        struct ovs_key_ethernet *ether;
        int i;

        /* packet data */
        eth = (struct ethhdr *)data;
        if (data + sizeof(*eth) > data_end)
            return TC_ACT_SHOT;

        /* value from map */
        ether = &action->u.mset.key.ether;
        for (i = 0; i < 6; i++) {
            printt("mac dest[%d]: %x -> %x\n",
                   i, eth->h_dest[i], ether->eth_dst.ea[i]);
            eth->h_dest[i] = ether->eth_dst.ea[i];
        }
        for (i = 0; i < 6; i++) {
            printt("mac src[%d]: %x -> %x\n",
                   i, eth->h_dest[i], ether->eth_dst.ea[i]);
            eth->h_source[i] = ether->eth_src.ea[i];
        }
        break;
    }
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_TUNNEL:
    default:
        printt("ERR: Un-implemented key attr %d in set action\n", key_attr);
        return TC_ACT_SHOT;
    }

    return post_tail_action(skb, batch);
}

/*
 * This action implements VLAN push
 * BPF program: tail-4
 */
__section_tail(OVS_ACTION_ATTR_PUSH_VLAN)
static int tail_action_push_vlan(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    printt("push vlan\n");
    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("vlan push tci %d\n", bpf_ntohs(action->u.push_vlan.vlan_tci));
    printt("vlan push tpid %d\n", bpf_ntohs(action->u.push_vlan.vlan_tpid));

    vlan_push(skb, action->u.push_vlan.vlan_tpid,
                   bpf_ntohs(action->u.push_vlan.vlan_tci) & VLAN_VID_MASK);
                   //bpf_ntohs(action->u.push_vlan.vlan_tci) & (u16)~VLAN_TAG_PRESENT);

    return post_tail_action(skb, batch);
}

/*
 * This action implements VLAN pop
 * BPF program: tail-5
 */
__section_tail(OVS_ACTION_ATTR_POP_VLAN)
static int tail_action_pop_vlan(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("vlan pop %d\n");
    bpf_skb_vlan_pop(skb);

    /* FIXME: invalidate_flow_key()? */
    return post_tail_action(skb, batch);
}

/*
 * This action implements sample
 * BPF program: tail-6
 */
__section_tail(OVS_ACTION_ATTR_SAMPLE)
static int tail_action_sample(struct __sk_buff *skb OVS_UNUSED)
{
    printt("ERR: Sample action not implemented,\
            do you want to do it? \n");

    return TC_ACT_SHOT;
}

/*
 * This action implements recirculation
 * BPF program: tail-7
 */
__section_tail(OVS_ACTION_ATTR_RECIRC)
static int tail_action_recirc(struct __sk_buff *skb)
{
    u32 recirc_id = 0;
    struct bpf_action *action;
    struct bpf_flow_key *flow_key;
    struct bpf_action_batch *batch ;
    struct ebpf_metadata_t *ebpf_md;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* recirc should be the last action.
     * level does not handle */

    /* don't check the is_flow_key_valid(),
     * now always re-parsing the header.
     */
    recirc_id = action->u.recirc_id;
    printt("recirc id = %d\n", recirc_id);

    /* update metadata */
    flow_key = bpf_get_flow_key();
    if (!flow_key) {
        printt("lookup metadata from flow_key failed\n");
        return TC_ACT_SHOT;
    }
    ebpf_md = &flow_key->mds;
    ebpf_md->md.recirc_id = recirc_id;

    skb->cb[OVS_CB_ACT_IDX] = 0;

    /* FIXME: recirc should not call this. */
    bpf_tail_call(skb, &tailcalls, MATCH_ACTION_CALL);
    return TC_ACT_SHOT;
}

/*
 * This action implement hash
 * BPF program: tail-8
 */
__section_tail(OVS_ACTION_ATTR_HASH)
static int tail_action_hash(struct __sk_buff *skb)
{
    u32 hash = 0;
    struct ebpf_metadata_t *ebpf_md;
    struct bpf_action *action;
    struct bpf_action_batch *batch;
    struct bpf_flow_key *flow_key;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("skb->hash before = %x\n", skb->hash);
    hash = bpf_get_hash_recalc(skb);
    printt("skb->hash = %x hash \n", skb->hash);
    if (!hash)
        hash = 0x1;

    flow_key = bpf_get_flow_key();
    if (!flow_key) {
        printt("Lookup metadata from flow key failed\n");
        return TC_ACT_SHOT;
    }
    ebpf_md = &flow_key->mds;
    printt("save hash to ebpf_md->md.dp_hash\n");
    ebpf_md->md.dp_hash = hash; /* or create a ovs_flow_hash?*/

    return post_tail_action(skb, batch);
}

/*
 * This action implements MPLS push
 * BPF program: tail-9
 */
__section_tail(OVS_ACTION_ATTR_PUSH_MPLS)
static int tail_action_mpls_push(struct __sk_buff *skb OVS_UNUSED)
{
    printt("ERR: Push MPLS action not implemented,\
            do you want to do it? \n");

    return TC_ACT_SHOT;
}

/*
 * This action implements MPLS pop
 * BPF program: tail-10
 */
__section_tail(OVS_ACTION_ATTR_POP_MPLS)
static int tail_action_mpls_pop(struct __sk_buff *skb OVS_UNUSED)
{
    printt("ERR: Pop MPLS action not implemented,\
            do you want to do it? \n");

    return TC_ACT_SHOT;
}

/*
 * This action implements set packet's fields, mask not supported.
 * Many other fields not implemented yet.
 * BPF program: tail-11
 * TODO: hit verifier limit here, maybe create more program and
 *       more tail call.
 */
__section_tail(OVS_ACTION_ATTR_SET_MASKED)
static int tail_action_set_masked(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;
    int key_attr;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    key_attr = action->u.mset.key_type;

    switch (key_attr) {
    case OVS_KEY_ATTR_ETHERNET: {
        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;
        struct ethhdr *eth;
        struct ovs_key_ethernet *ether;
        int i;

        /* packet data */
        eth = (struct ethhdr *)data;
        if (data + sizeof(*eth) > data_end)
            return TC_ACT_SHOT;

        /* value from map */
        ether = &action->u.mset.key.ether;
        for (i = 0; i < 6; i++) {
            printt("mac dest[%d]: %x -> %x\n",
                   i, eth->h_dest[i], ether->eth_dst.ea[i]);
            eth->h_dest[i] = ether->eth_dst.ea[i];
        }
        for (i = 0; i < 6; i++) {
            printt("mac src[%d]: %x -> %x\n",
                   i, eth->h_dest[i], ether->eth_dst.ea[i]);
            eth->h_source[i] = ether->eth_src.ea[i];
        }
        break;
    }
    case OVS_KEY_ATTR_IPV4: {
        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;
        struct iphdr *nh;
        struct ovs_key_ipv4 *ipv4;

        /* packet data */
        nh = ALIGNED_CAST(struct iphdr *, data + sizeof(struct ethhdr));
        if ((u8 *)nh + sizeof(struct iphdr) + 12 > data_end) {
            return TC_ACT_SHOT;
        }

        /* value from map */
        ipv4 = &action->u.mset.key.ipv4;
        /* set ipv4_proto is not supported, see
         * datapath/actions.c
         */
        set_ip_tos(skb, ipv4->ipv4_tos);
        set_ip_ttl(skb, ipv4->ipv4_ttl);

#if ENABLE_POINTER_LOOKUP
        set_ip_src(skb, ipv4->ipv4_src);
        set_ip_dst(skb, ipv4->ipv4_dst);
#endif

        printt("set_masked ipv4 done\n");
        /* XXX ignore frag */

        break;
    }
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_PRIORITY:  /* u32 skb->priority */
    case OVS_KEY_ATTR_IN_PORT:   /* u32 OVS dp port number */
    case OVS_KEY_ATTR_VLAN:     /* be16 VLAN TCI */
    case OVS_KEY_ATTR_ETHERTYPE:    /* be16 Ethernet type */
    case OVS_KEY_ATTR_IPV6:      /* struct ovs_key_ipv6 */
    case OVS_KEY_ATTR_TCP:       /* struct ovs_key_tcp */
    case OVS_KEY_ATTR_UDP:       /* struct ovs_key_udp */
    case OVS_KEY_ATTR_ICMP:      /* struct ovs_key_icmp */
    case OVS_KEY_ATTR_ICMPV6:    /* struct ovs_key_icmpv6 */
    case OVS_KEY_ATTR_ARP:       /* struct ovs_key_arp */
    case OVS_KEY_ATTR_ND:        /* struct ovs_key_nd */
    case OVS_KEY_ATTR_SKB_MARK:  /* u32 skb mark */
    case OVS_KEY_ATTR_TUNNEL:    /* Nested set of ovs_tunnel attributes */
    case OVS_KEY_ATTR_SCTP:      /* struct ovs_key_sctp */
    case OVS_KEY_ATTR_TCP_FLAGS:    /* be16 TCP flags. */
    case OVS_KEY_ATTR_DP_HASH:   /* u32 hash value. Value 0 indicates the hash */
    case OVS_KEY_ATTR_RECIRC_ID: /* u32 recirc id */
    case OVS_KEY_ATTR_MPLS:      /* array of struct ovs_key_mpls. */
    case OVS_KEY_ATTR_CT_STATE:    /* u32 bitmask of OVS_CS_F_* */
    case OVS_KEY_ATTR_CT_ZONE:    /* u16 connection tracking zone. */
    case OVS_KEY_ATTR_CT_MARK:    /* u32 connection tracking mark */
    case OVS_KEY_ATTR_CT_LABELS:    /* 16-octet connection tracking labels */
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:   /* struct ovs_key_ct_tuple_ipv4 */
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:   /* struct ovs_key_ct_tuple_ipv6 */
    case OVS_KEY_ATTR_NSH:       /* Nested set of ovs_nsh_key_* */
#ifdef __KERNEL__
	case OVS_KEY_ATTR_TUNNEL_INFO:  /* struct ovs_tunnel_info */
#endif
#ifndef __KERNEL__
	case OVS_KEY_ATTR_PACKET_TYPE:  /* be32 packet type */
#endif
    case __OVS_KEY_ATTR_MAX:
    default:
        printt("ERR Un-implemented key attr %d in set_masked\n", key_attr);
        return TC_ACT_SHOT;
    }

    return post_tail_action(skb, batch);
}

/*
 * This action implements connection tracking
 * BPF program: tail-12
 */
__section_tail(OVS_ACTION_ATTR_CT)
static int tail_action_ct(struct __sk_buff *skb OVS_UNUSED)
{
    printt("ERR: CT (connection tracking) not implemented,\
            do you want to do it? \n");
    return TC_ACT_SHOT;
}

/*
 * This action implements packet truncate
 * BPF program: tail-13
 */
__section_tail(OVS_ACTION_ATTR_TRUNC)
static int tail_action_trunc(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("len before: %d\n", skb->len);
    printt("truncate to %d\n", action->u.trunc.max_len);

    /* The helper will resize the skb to the given new size */
    bpf_skb_change_tail(skb, action->u.trunc.max_len, 0);

    printt("len after: %d\n", skb->len);
    return post_tail_action(skb, batch);
}
