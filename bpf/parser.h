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

#include "api.h"
#include "helpers.h"
#include "maps.h"
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#define OVS_LOAD_BYTES(xdp, offset, dst, len) \
        bpf_skb_load_bytes(xdp, offset, dst, len)
#define OVS_SK_BUFF __sk_buff
#define PARSE_DATA tc_parse_data
#include "parser_common.h"
#undef OVS_LOAD_BYTES
#undef OVS_SK_BUFF
#undef PARSE_DATA

/* Program: tail-32 */
__section_tail(PARSER_CALL)
static int ovs_parser(struct __sk_buff* skb) {
    struct bpf_tunnel_key key;
    struct bpf_flow_key *flow_key;
    struct ebpf_headers_t *hdrs;
    struct ebpf_metadata_t *metadata;

    u32 ebpf_zero = 0;
    int err = 0, ret = 0;

    printt("=== enter tc ingress ===\n");
    printt("skb->protocol = 0x%x\n", skb->protocol);
    printt("skb->ingress_ifindex %d skb->ifindex %d\n",
           skb->ingress_ifindex, skb->ifindex);

    flow_key = bpf_get_flow_key();
    if (!flow_key) {
        printt("XDP does not parse the packet data,"\
               "start full parsing\n");

        err = tc_parse_data(skb); /* bpf/parser_common.h */
        if (err) {
            return TC_ACT_OK;
        }
        flow_key = bpf_get_flow_key();
    }
    if (!flow_key) /* need to check again */
        return TC_ACT_OK;

    hdrs = &flow_key->headers;
    metadata = &flow_key->mds;

    /* VLAN 8021Q (0x8100) or 8021AD (0x88a8) in metadata
     * note: vlan in metadata is always the outer vlan
     */
    if (skb->vlan_tci) {
        hdrs->vlan.tci = skb->vlan_tci | VLAN_TAG_PRESENT; /* host byte order */
        hdrs->vlan.etherType = skb->vlan_proto;
        hdrs->valid |= VLAN_VALID;

        printt("skb metadata: vlan proto 0x%x tci %x\n",
               bpf_ntohs(skb->vlan_proto), skb->vlan_tci);
    }

    metadata->md.skb_priority = skb->priority;

    /* Don't use ovs_cb_get_ifindex(), that gets optimized into something
     * that can't be verified. >:( */
    if (skb->cb[OVS_CB_INGRESS]) {
        metadata->md.in_port = skb->ingress_ifindex;
    }
    if (!skb->cb[OVS_CB_INGRESS]) {
        metadata->md.in_port = skb->ifindex;
    }
    metadata->md.pkt_mark = skb->mark;

    ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key), 0);
    if (!ret) {
        printt("bpf_skb_get_tunnel_key id = %d ipv4\n", key.tunnel_id);
        metadata->tnl_md.tun_id = key.tunnel_id;
        metadata->tnl_md.ip4.ip_src = key.remote_ipv4;
        metadata->tnl_md.ip_tos = key.tunnel_tos;
        metadata->tnl_md.ip_ttl = key.tunnel_ttl;
        metadata->tnl_md.use_ipv6 = 0;
        metadata->tnl_md.flags = 0;
#ifdef BPF_ENABLE_IPV6
    } else if (ret == -EPROTO) {
        ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key),
                                     BPF_F_TUNINFO_IPV6);
        if (!ret) {
            printt("bpf_skb_get_tunnel_key id = %d ipv6\n", key.tunnel_id);
            metadata->tnl_md.tun_id = key.tunnel_id;
            memcpy(&metadata->tnl_md.ip6.ipv6_src, &key.remote_ipv4, 16);
            metadata->tnl_md.ip_tos = key.tunnel_tos;
            metadata->tnl_md.ip_ttl = key.tunnel_ttl;
            metadata->tnl_md.use_ipv6 = 1;
            metadata->tnl_md.flags = 0;
        }
#endif
    }

    if (!ret) {
        ret = bpf_skb_get_tunnel_opt(skb, &metadata->tnl_md.gnvopt,
                                     sizeof metadata->tnl_md.gnvopt);
        if (ret > 0)
            metadata->tnl_md.gnvopt_valid = 1;
        printt("bpf_skb_get_tunnel_opt ret = %d\n", ret);
    }

    if (err != ovs_no_error) {
        printt("parse error: %d, drop\n", err);
        return TC_ACT_SHOT;
    }

    /* write flow key and md to key map */
    if (ovs_cb_is_initial_parse(skb)) {
        bpf_map_update_elem(&percpu_flow_key,
                            &ebpf_zero, flow_key, BPF_ANY);
    }
    skb->cb[OVS_CB_ACT_IDX] = 0;

    /* tail call next stage */
    printt("tail call match + lookup stage\n");
    bpf_tail_call(skb, &tailcalls, MATCH_ACTION_CALL);

    printt("ERR: missing tail call\n");
    return TC_ACT_OK;
}
