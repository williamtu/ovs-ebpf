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

#include "ovs-p4.h"
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

#define TCP_FLAGS_BE16(tp) (*(__be16 *)&tcp_flag_word(tp) & bpf_htons(0x0FFF))

static bool ipv6_has_ext(u8 nw_proto) {
    if ((nw_proto == IPPROTO_HOPOPTS) ||
          (nw_proto == IPPROTO_ROUTING) ||
          (nw_proto == IPPROTO_DSTOPTS) ||
          (nw_proto == IPPROTO_AH) ||
          (nw_proto == IPPROTO_FRAGMENT)) {
            return true;
    }
    return false;
}

__section_tail(PARSER_CALL)
static int ovs_parser(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    struct ebpf_headers_t hdrs = {};
    struct ebpf_metadata_t metadata = {};
    struct bpf_tunnel_key key;
    struct ethhdr *eth;
    ovs_be16 eth_proto;
    u32 ebpf_zero = 0;
    int offset = 0;
    u8 nw_proto = 0;
    int err = 0, ret = 0;

    /* Verifier Check. */
    if ((char *)data + sizeof(*eth) > (char *)(long)skb->data_end) {
        printt("ERR parsing ethernet\n");
        return TC_ACT_SHOT;
    }

    eth = data;
    if (eth->h_proto == 0) {
        printt("eth_proto == 0, return TC_ACT_OK\n");
        return TC_ACT_OK;
    }

    printt("eth_proto = 0x%x len = %d\n", bpf_ntohs(eth->h_proto), skb->len);
    printt("skb->protocol = 0x%x\n", skb->protocol);
    printt("skb->ingress_ifindex %d skb->ifindex %d\n",
           skb->ingress_ifindex, skb->ifindex);

    /* Link Layer. */
    if (skb_load_bytes(skb, offset, &hdrs.ethernet, sizeof(hdrs.ethernet)) < 0) {
        err = p4_pe_header_too_short;
        printt("ERR: load byte %d\n", __LINE__);
        goto end;
    }
    offset += sizeof(hdrs.ethernet);
    hdrs.valid |= ETHER_VALID;

    /* VLAN 8021Q (0x8100) or 8021AD (0x8a88) in metadata
     * note: vlan in metadata is always the outer vlan
     */
    if (skb->vlan_tci) {
        hdrs.vlan.tci = skb->vlan_tci | VLAN_TAG_PRESENT; /* host byte order */
        hdrs.vlan.etherType = skb->vlan_proto;
        hdrs.valid |= VLAN_VALID;

        printt("skb metadata: vlan proto 0x%x tci %x\n", bpf_ntohs(skb->vlan_proto), skb->vlan_tci);
    }

    eth_proto = eth->h_proto;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)){

        /* The inner, if exists, is VLAN 8021Q (0x8100) */
        struct vlan_hdr { /* wired format */
            ovs_be16 tci;
            ovs_be16 ethertype;
        } cvlan;

        /* parse cvlan */
        if (skb_load_bytes(skb, offset - 2, &cvlan, sizeof(cvlan)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        offset += sizeof(hdrs.cvlan);
        hdrs.valid |= CVLAN_VALID;

        hdrs.cvlan.tci = bpf_ntohs(cvlan.tci);
        hdrs.cvlan.etherType = cvlan.ethertype;

        printt("vlan tci 0x%x ethertype 0x%x\n",
               hdrs.cvlan.tci, bpf_ntohs(hdrs.cvlan.etherType));

        skb_load_bytes(skb, offset - 2, &eth_proto, 2);
        printt("eth_proto = 0x%x\n", bpf_ntohs(eth_proto));
    }

    /* Network Layer.
     *   see key_extract() in net/openvswitch/flow.c */
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr nh;

        printt("parse ipv4\n");
        if (skb_load_bytes(skb, offset, &nh, sizeof(nh)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        offset += nh.ihl * 4;
        hdrs.valid |= IPV4_VALID;

        hdrs.ipv4.ttl = nh.ttl;                /* u8 */
        hdrs.ipv4.tos = nh.tos;                /* u8 */
        hdrs.ipv4.protocol = nh.protocol;     /* u8*/
        hdrs.ipv4.srcAddr = nh.saddr;        /* be32 */
        hdrs.ipv4.dstAddr = nh.daddr;        /* be32 */

        nw_proto = hdrs.ipv4.protocol;
        printt("next proto 0x%x\n", nw_proto);

    } else if (eth_proto == bpf_htons(ETH_P_ARP) ||
               eth_proto == bpf_htons(ETH_P_RARP)) {
        struct arp_rarp_t *arp;

        printt("parse arp/rarp\n");

        /* the struct arp_rarp_t is wired format */
        arp = &hdrs.arp;
        if (skb_load_bytes(skb, offset, arp, sizeof(hdrs.arp)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        offset += sizeof(hdrs.arp);
        hdrs.valid |= ARP_VALID;

        if (arp->ar_hrd == bpf_htons(ARPHRD_ETHER) &&
            arp->ar_pro == bpf_htons(ETH_P_IP) &&
            arp->ar_hln == ETH_ALEN &&
            arp->ar_pln == 4) {
            printt("valid arp\n");
        } else {
            printt("ERR: invalid arp\n");
        }
        goto parse_metadata;

    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {

        struct ipv6hdr ip6hdr;    /* wired format */

        if (skb_load_bytes(skb, offset, &ip6hdr, sizeof(ip6hdr)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        offset += sizeof(struct ipv6hdr); /* wired format */
        hdrs.valid |= IPV6_VALID;

        printt("parse ipv6\n");

        memcpy(&hdrs.ipv6.flowLabel, &ip6hdr.flow_lbl, 4); //FIXME
        memcpy(&hdrs.ipv6.srcAddr, &ip6hdr.saddr, 16);
        memcpy(&hdrs.ipv6.dstAddr, &ip6hdr.daddr, 16);

        nw_proto = ip6hdr.nexthdr;

        if (ipv6_has_ext(nw_proto)) {
            printt("WARN: ipv6 nexthdr %x does not supported\n", nw_proto);
            // need to update offset
        }

        printt("next proto = %x\n", nw_proto);

    } else {
        printt("ERR: eth_proto %x not supported\n", bpf_ntohs(eth_proto));
        return TC_ACT_OK;
    }

    /* Transport Layer.
     *   Handle: TCP, UDP, ICMP
     */
    if (nw_proto == IPPROTO_TCP) {
        struct tcphdr tcp;

        if (skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        hdrs.valid |= TCP_VALID;

        hdrs.tcp.srcPort = tcp.source;
        hdrs.tcp.dstPort = tcp.dest;
        hdrs.tcp.flags = TCP_FLAGS_BE16(&tcp);

        printt("parse tcp src %d dst %d\n", bpf_ntohs(tcp.source), bpf_ntohs(tcp.dest));

    } else if (nw_proto == IPPROTO_UDP) {
        struct udphdr udp;

        if (skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        hdrs.valid |= UDP_VALID;

        hdrs.udp.srcPort = udp.source;
        hdrs.udp.dstPort = udp.dest;

        printt("parse udp src %d dst %d\n", bpf_ntohs(udp.source), bpf_ntohs(udp.dest));

    } else if (nw_proto == IPPROTO_ICMP) {  /* ICMP v4 */
        struct icmphdr icmp;

        if (skb_load_bytes(skb, offset, &icmp, sizeof(icmp)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        hdrs.valid |= ICMP_VALID;

        hdrs.icmp.type = icmp.type;
        hdrs.icmp.code = icmp.code;

        printt("parse icmp type %d code %d\n", icmp.type, icmp.code);

    } else if (nw_proto == 0x3a /*EXTHDR_ICMP*/) {    /* ICMP v6 */
        struct icmphdr icmp;

        if (skb_load_bytes(skb, offset, &icmp, sizeof(icmp)) < 0) {
            err = p4_pe_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        hdrs.valid |= ICMPV6_VALID;

        hdrs.icmpv6.type = icmp.type;
        hdrs.icmpv6.code = icmp.code;

        printt("parse icmp v6 type %d code %d\n", icmp.type, icmp.code);
    } else if (nw_proto == IPPROTO_GRE) {
        printt("receive gre packet\n");
    } else {
        printt("WARN: nw_proto 0x%x not parsed\n", nw_proto);
        /* Continue */
    }

parse_metadata:
    metadata.md.skb_priority = skb->priority;

    /* Don't use ovs_cb_get_ifindex(), that gets optimized into something
     * that can't be verified. >:( */
    if (skb->cb[OVS_CB_INGRESS]) {
        metadata.md.in_port = skb->ingress_ifindex;
    }
    if (!skb->cb[OVS_CB_INGRESS]) {
        metadata.md.in_port = skb->ifindex;
    }
    metadata.md.pkt_mark = skb->mark;

    ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key), 0);
    if (!ret) {
        printt("bpf_skb_get_tunnel_key id = %d ipv4\n", key.tunnel_id);
        metadata.tnl_md.tun_id = key.tunnel_id;
        metadata.tnl_md.ip4.ip_src = key.remote_ipv4;
        metadata.tnl_md.ip_tos = key.tunnel_tos;
        metadata.tnl_md.ip_ttl = key.tunnel_ttl;
        metadata.tnl_md.use_ipv6 = 0;
        metadata.tnl_md.flags = 0;
#ifdef BPF_ENABLE_IPV6
    } else if (ret == -EPROTO) {
        ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key),
                                     BPF_F_TUNINFO_IPV6);
        if (!ret) {
            printt("bpf_skb_get_tunnel_key id = %d ipv6\n", key.tunnel_id);
            metadata.tnl_md.tun_id = key.tunnel_id;
            memcpy(&metadata.tnl_md.ip6.ipv6_src, &key.remote_ipv4, 16);
            metadata.tnl_md.ip_tos = key.tunnel_tos;
            metadata.tnl_md.ip_ttl = key.tunnel_ttl;
            metadata.tnl_md.use_ipv6 = 1;
            metadata.tnl_md.flags = 0;
        }
#endif
    }

    if (!ret) {
        ret = bpf_skb_get_tunnel_opt(skb, &metadata.tnl_md.gnvopt,
                                     sizeof metadata.tnl_md.gnvopt);
        if (ret > 0)
            metadata.tnl_md.gnvopt_valid = 1;
        printt("bpf_skb_get_tunnel_opt ret = %d\n", ret);
    }

end:
    if (err != p4_pe_no_error) {
        printt("parse error: %d, drop\n", err);
        return TC_ACT_SHOT;
    }

    /* write flow key and md to key map */
    printt("Parser: updating flow key\n");
    bpf_map_update_elem(&percpu_headers,
                        &ebpf_zero, &hdrs, BPF_ANY);

    if (ovs_cb_is_initial_parse(skb)) {
        bpf_map_update_elem(&percpu_metadata,
                            &ebpf_zero, &metadata, BPF_ANY);
    }
    skb->cb[OVS_CB_ACT_IDX] = 0;

    /* tail call next stage */
    printt("tail call match + lookup stage\n");
    bpf_tail_call(skb, &tailcalls, MATCH_ACTION_CALL);

    printt("[ERROR] missing tail call\n");
    return TC_ACT_OK;
}
