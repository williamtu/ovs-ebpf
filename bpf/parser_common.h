/*
 * Copyright (c) 2018 Nicira, Inc.
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

#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#define TCP_FLAGS_BE16(tp) (*(__be16 *)&tcp_flag_word(tp) & bpf_htons(0x0FFF))

#ifndef ErrorCode
#define ErrorCode
enum ErrorCode {
    ovs_no_error,
    ovs_index_out_of_bounds,
    ovs_out_of_packet,
    ovs_header_too_long,
    ovs_header_too_short,
    ovs_unhandled_select,
    ovs_checksum,
    ovs_too_many_encap,
    ovs_ipv6_disabled,
};
#endif

/* Parse packet data: used both in TC and XDP
 * Save result in map: percpu_headers
 */
static inline int
PARSE_DATA(struct OVS_SK_BUFF *skb)
{
    struct ebpf_headers_t hdrs = {};
    ovs_be16 eth_proto;
    u32 ebpf_zero = 0;
    int offset = 0;
    u8 nw_proto = 0;
    int err = 0;

    /* Link Layer. */
    if (OVS_LOAD_BYTES(skb, offset, &hdrs.ethernet, sizeof(hdrs.ethernet)) < 0) {
        err = ovs_header_too_short;
        printt("ERR: load byte %d\n", __LINE__);
        goto end;
    }
    if (hdrs.ethernet.etherType == 0) {
        printt("Layer 3 packet with eth_proto == 0, return TC_ACT_OK\n");
        return TC_ACT_OK;
    }

    offset += sizeof(hdrs.ethernet);
    hdrs.valid |= ETHER_VALID;

    eth_proto = hdrs.ethernet.etherType;

    if (eth_proto == bpf_htons(ETH_P_8021Q)){

        /* The inner vlan, if exists, is VLAN 8021Q (0x8100)
         * The outer vlan is at skb metadata, could be 8021Q or 8021AD
         */
        struct vlan_hdr { /* wired format */
            ovs_be16 tci;
            ovs_be16 ethertype;
        } cvlan;

        /* parse cvlan */
        if (OVS_LOAD_BYTES(skb, offset - 2, &cvlan, sizeof(cvlan)) < 0) {
            err = ovs_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        offset += sizeof(hdrs.cvlan);
        hdrs.valid |= CVLAN_VALID;

        hdrs.cvlan.tci = bpf_ntohs(cvlan.tci);
        hdrs.cvlan.etherType = cvlan.ethertype;

        printt("vlan tci 0x%x ethertype 0x%x\n",
               hdrs.cvlan.tci, bpf_ntohs(hdrs.cvlan.etherType));

        OVS_LOAD_BYTES(skb, offset - 2, &eth_proto, 2);
        printt("eth_proto = 0x%x\n", bpf_ntohs(eth_proto));
    }

    /* Network Layer.
     *   see key_extract() in net/openvswitch/flow.c */
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr nh;

        printt("parse ipv4\n");
        if (OVS_LOAD_BYTES(skb, offset, &nh, sizeof(nh)) < 0) {
            err = ovs_header_too_short;
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
        if (OVS_LOAD_BYTES(skb, offset, arp, sizeof(hdrs.arp)) < 0) {
            err = ovs_header_too_short;
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
        goto end;

    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {

        struct ipv6hdr ip6hdr;    /* wired format */

        if (OVS_LOAD_BYTES(skb, offset, &ip6hdr, sizeof(ip6hdr)) < 0) {
            err = ovs_header_too_short;
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

        if ((nw_proto == IPPROTO_HOPOPTS) ||
            (nw_proto == IPPROTO_ROUTING) ||
            (nw_proto == IPPROTO_DSTOPTS) ||
            (nw_proto == IPPROTO_AH) ||
            (nw_proto == IPPROTO_FRAGMENT)) {
            printt("WARN: ipv6 nexthdr %x does not supported\n", nw_proto);
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

        if (OVS_LOAD_BYTES(skb, offset, &tcp, sizeof(tcp)) < 0) {
            err = ovs_header_too_short;
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

        if (OVS_LOAD_BYTES(skb, offset, &udp, sizeof(udp)) < 0) {
            err = ovs_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        hdrs.valid |= UDP_VALID;

        hdrs.udp.srcPort = udp.source;
        hdrs.udp.dstPort = udp.dest;

        printt("parse udp src %d dst %d\n", bpf_ntohs(udp.source), bpf_ntohs(udp.dest));

    } else if (nw_proto == IPPROTO_ICMP) {  /* ICMP v4 */
        struct icmphdr icmp;

        if (OVS_LOAD_BYTES(skb, offset, &icmp, sizeof(icmp)) < 0) {
            err = ovs_header_too_short;
            printt("ERR: load byte %d\n", __LINE__);
            goto end;
        }
        hdrs.valid |= ICMP_VALID;

        hdrs.icmp.type = icmp.type;
        hdrs.icmp.code = icmp.code;

        printt("parse icmp type %d code %d\n", icmp.type, icmp.code);

    } else if (nw_proto == 0x3a /*EXTHDR_ICMP*/) {    /* ICMP v6 */
        struct icmphdr icmp;

        if (OVS_LOAD_BYTES(skb, offset, &icmp, sizeof(icmp)) < 0) {
            err = ovs_header_too_short;
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

    /* write flow key and md to key map */
    printt("Parser: updating flow key\n");
    bpf_map_update_elem(&percpu_headers,
                        &ebpf_zero, &hdrs, BPF_ANY);
end:
    return 0;
}
