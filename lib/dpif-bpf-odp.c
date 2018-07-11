/*
 * Copyright (c) 2017 Nicira, Inc.
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
#include <linux/if_ether.h>
#include "dpif-bpf-odp.h"

#include <errno.h>

#include "bpf/odp-bpf.h"
#include "openvswitch/flow.h"
#include "openvswitch/vlog.h"
#include "netlink.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_bpf_odp);

static void
ct_action_to_bpf(const struct nlattr *ct, struct bpf_action *dst)
{
    const struct nlattr *nla;
    int left;

    NL_ATTR_FOR_EACH_UNSAFE(nla, left, ct, ct->nla_len) {
        switch ((enum ovs_ct_attr)nla->nla_type) {
        case OVS_CT_ATTR_COMMIT:
            dst->u.ct.commit = true;
            break;
        case OVS_CT_ATTR_ZONE:
        case OVS_CT_ATTR_MARK:
        case OVS_CT_ATTR_LABELS:
        case OVS_CT_ATTR_HELPER:
        case OVS_CT_ATTR_NAT:
        case OVS_CT_ATTR_FORCE_COMMIT:
        case OVS_CT_ATTR_EVENTMASK:
        default:
            VLOG_INFO("Ignoring CT attribute %d", nla->nla_type);
            break;
        case OVS_CT_ATTR_UNSPEC:
        case __OVS_CT_ATTR_MAX:
            OVS_NOT_REACHED();
        }
    }
}

enum odp_key_fitness
odp_tun_to_bpf_tun(const struct nlattr *nla, size_t nla_len,
                   struct flow_tnl_t *tun)
{
    const struct nlattr *a;
    size_t left;

    NL_ATTR_FOR_EACH(a, left, nla, nla_len) {
        enum ovs_tunnel_key_attr type = nl_attr_type(a);

        switch (type) {
        case OVS_TUNNEL_KEY_ATTR_ID:
            tun->tun_id = ntohl(be64_to_be32(nl_attr_get_be64(a)));
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
            tun->ip4.ip_src = ntohl(nl_attr_get_be32(a));
            tun->use_ipv6 = 0;
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
            tun->ip4.ip_dst = ntohl(nl_attr_get_be32(a));
            tun->use_ipv6 = 0;
            break;
        case OVS_TUNNEL_KEY_ATTR_TOS:
            tun->ip_tos = nl_attr_get_u8(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TTL:
            tun->ip_ttl = nl_attr_get_u8(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
            //tun->flags |= FLOW_TNL_F_DONT_FRAGMENT;
            // in bpf helper, there is no tun_flags extracted
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_DST:
            tun->tp_dst = nl_attr_get_be16(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_TP_SRC:
            tun->tp_src = nl_attr_get_be16(a);
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_SRC:
#ifdef BPF_ENABLE_IPV6
            memcpy(&tun->ip6.ipv6_src, nl_attr_get(a), 16);
            tun->use_ipv6 = 1;
#endif
            break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_DST:
#ifdef BPF_ENABLE_IPV6
            memcpy(&tun->ip6.ipv6_dst, nl_attr_get(a), 16);
            tun->use_ipv6 = 1;
#endif
            break;
        case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:        /* Array of Geneve options. */
            if (nl_attr_get_size(a) != sizeof tun->gnvopt) {
                VLOG_ERR("%s: geneve opts size is %ld, expect %ld", __func__,
                         nl_attr_get_size(a), sizeof tun->gnvopt);
            } else {
                memcpy(&tun->gnvopt, nl_attr_get(a), sizeof tun->gnvopt);
                tun->gnvopt_valid = 1;
            }
            break;
        case OVS_TUNNEL_KEY_ATTR_CSUM:               /* No argument. CSUM packet. */
        case OVS_TUNNEL_KEY_ATTR_OAM:                /* No argument. OAM frame.  */
        case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:		/* Nested OVS_VXLAN_EXT_* */
        case OVS_TUNNEL_KEY_ATTR_PAD:
        case __OVS_TUNNEL_KEY_ATTR_MAX:
            VLOG_INFO("%s: unknown type %d", __func__, type);
            break;
        default:
            VLOG_INFO("%s: unknown type %d", __func__, type);
            OVS_NOT_REACHED();
        }
    }

    return ODP_FIT_PERFECT;
}

/* Converts the OVS netlink-formatted action 'src' into a BPF action in 'dst'.
 *
 * Returns 0 on success, or a positive errno value on failure.
 */
int
odp_action_to_bpf_action(const struct nlattr *src, struct bpf_action *dst)
{
    enum ovs_action_attr type = nl_attr_type(src);

    switch (type) {
    case OVS_ACTION_ATTR_PUSH_VLAN: {
        const struct ovs_action_push_vlan *vlan = nl_attr_get(src);
        dst->u.push_vlan = *vlan;
        VLOG_DBG("push vlan tpid %x tci %x", vlan->vlan_tpid, vlan->vlan_tci);
        break;
    }
    case OVS_ACTION_ATTR_CT:
        ct_action_to_bpf(nl_attr_get(src), dst);
        break;
    case OVS_ACTION_ATTR_RECIRC:
        dst->u.recirc_id = nl_attr_get_u32(src);
        break;
    case OVS_ACTION_ATTR_SAMPLE:
        // XXX: ignore
        return 1;
    case OVS_ACTION_ATTR_USERSPACE:
        if (nl_attr_get_size(src) <= sizeof dst->u.userspace.nlattr_data) {
            size_t len = nl_attr_get_size(src);
            memcpy(dst->u.userspace.nlattr_data, nl_attr_get(src), len);
            dst->u.userspace.nlattr_len = len;
            VLOG_INFO("size of userspace action is %ld", len);
        } else {
            VLOG_WARN("Size of userspace action too large: %ld > %ld",
                      nl_attr_get_size(src),
                      sizeof dst->u.userspace.nlattr_data);
            return EOPNOTSUPP;
        }
        break;
    case OVS_ACTION_ATTR_HASH: {
        const struct ovs_action_hash *hash_act = nl_attr_get(src);
        dst->u.hash = *hash_act;
        break;
    }
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED: {
        const struct nlattr *a;

        dst->is_set_tunnel = 0;
        a = nl_attr_get(src);
        dst->u.mset.key_type = nl_attr_type(a);

        switch (nl_attr_type(a)) {
        case OVS_KEY_ATTR_TUNNEL: {
            enum odp_key_fitness ret;
            struct flow_tnl_t tunnel;

            dst->is_set_tunnel = 1;
            tunnel.tun_id = 0;
            ret = odp_tun_to_bpf_tun(nl_attr_get(a), nl_attr_get_size(a),
                                     &tunnel);
            if (ret != ODP_FIT_PERFECT) {
                return EOPNOTSUPP;
            }

            dst->u.tunnel.tunnel_id = tunnel.tun_id;
            if (!tunnel.use_ipv6)
                dst->u.tunnel.remote_ipv4 = tunnel.ip4.ip_dst;
#ifdef BPF_ENABLE_IPV6
            else
                memcpy(dst->u.tunnel.remote_ipv6, tunnel.ip6.ipv6_dst, 16);
#endif
            dst->u.tunnel.tunnel_tos = tunnel.ip_tos;
            dst->u.tunnel.tunnel_ttl = tunnel.ip_ttl;
            dst->u.tunnel.use_ipv6 = tunnel.use_ipv6;

            if (tunnel.gnvopt_valid) {
                dst->u.tunnel.gnvopt = tunnel.gnvopt;
                dst->u.tunnel.gnvopt_valid = 1;
            }
            break;
        }
        case OVS_KEY_ATTR_ETHERNET: {
            struct ovs_key_ethernet *ether;

            //ovs_assert(nl_attr_get_size(a) == 2 * sizeof *ether);

            ether = &dst->u.mset.key.ether;
            memcpy(ether, nl_attr_get(a), sizeof *ether);
            break;
        }
        case OVS_KEY_ATTR_IPV4: {
            struct ovs_key_ipv4 *ip;

            //ovs_assert(nl_attr_get_size(a) == 2 * sizeof *ip);

            ip = &dst->u.mset.key.ipv4;
            memcpy(ip, nl_attr_get(a), sizeof *ip);
            break;
        }
        default:
            VLOG_INFO("%s: set/set_mask %d is not supported", __func__,
                      nl_attr_type(a));
            return EOPNOTSUPP;
        }
        break;
    }
    case OVS_ACTION_ATTR_TRUNC: {
        const struct ovs_action_trunc *trunc = nl_attr_get(src);
        dst->u.trunc = *trunc;
        VLOG_INFO("truncate to %d byte", trunc->max_len);
        break;
    }
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
    case OVS_ACTION_ATTR_TUNNEL_POP:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_METER:
    case OVS_ACTION_ATTR_CT_CLEAR:
    case OVS_ACTION_ATTR_PUSH_NSH:
    case OVS_ACTION_ATTR_POP_NSH:
        VLOG_WARN("Unsupported action type %d",  nl_attr_type(src));
        return EOPNOTSUPP;
    case OVS_ACTION_ATTR_UNSPEC:
    case OVS_ACTION_ATTR_OUTPUT:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    return 0;
}

int
bpf_actions_to_odp_actions(struct bpf_action_batch *batch, struct ofpbuf *out)
{
    int i;

    for (i = 0; i < BPF_DP_MAX_ACTION; i++) {
        struct bpf_action *act = &batch->actions[i];
        enum ovs_action_attr type = act->type;

        switch (type) {
        case OVS_ACTION_ATTR_UNSPEC:
            /* End of actions list. */
            return 0;

        case OVS_ACTION_ATTR_OUTPUT: {
            /* XXX: ifindex to odp translation */
            nl_msg_put_u32(out, type, act->u.out.port);
            break;
        }
        case OVS_ACTION_ATTR_PUSH_VLAN: {
            nl_msg_put_unspec(out, type, &act->u.push_vlan,
                              sizeof act->u.push_vlan);
            break;
        }
        case OVS_ACTION_ATTR_RECIRC:
            nl_msg_put_u32(out, type, act->u.recirc_id);
            break;
        case OVS_ACTION_ATTR_TRUNC:
            nl_msg_put_unspec(out, type, &act->u.trunc, sizeof act->u.trunc);
            break;
        case OVS_ACTION_ATTR_HASH:
            nl_msg_put_unspec(out, type, &act->u.hash, sizeof act->u.hash);
            break;
        case OVS_ACTION_ATTR_PUSH_MPLS:
            nl_msg_put_unspec(out, type, &act->u.mpls, sizeof act->u.mpls);
            break;
        case OVS_ACTION_ATTR_POP_MPLS:
            nl_msg_put_be16(out, type, act->u.ethertype);
            break;
        case OVS_ACTION_ATTR_SAMPLE: {
            VLOG_WARN("XXX FIXME attr sample");
            break;
        }
        case OVS_ACTION_ATTR_SET: {
            // see parse_tc_flower_to_match
            size_t start_ofs;
			size_t tun_key_ofs;
            struct ovs_action_set_tunnel *tun;

            tun = &act->u.tunnel;
            start_ofs = nl_msg_start_nested(out, OVS_ACTION_ATTR_SET);
			tun_key_ofs = nl_msg_start_nested(out, OVS_KEY_ATTR_TUNNEL);

            nl_msg_put_be64(out, OVS_TUNNEL_KEY_ATTR_ID,
                            be32_to_be64(htonl(tun->tunnel_id)));

            if (!tun->use_ipv6) {
                if (tun->remote_ipv4) {
                    nl_msg_put_be32(out, OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                                    htonl(tun->remote_ipv4));
                }
#ifdef BPF_ENABLE_IPV6
            } else {
                if (ipv6_addr_is_set((const struct in6_addr *)&tun->remote_ipv6)) {
                    nl_msg_put_in6_addr(out, OVS_TUNNEL_KEY_ATTR_IPV6_DST,
                                        (const struct in6_addr *)&tun->remote_ipv6);
                }
#endif
            }

#if 0
            if (!tnl_type || !strcmp(tnl_type, "geneve")) {
                tun_metadata_to_geneve_nlattr(tun_key, tun_flow_key, key_buf, a);
            }
#endif
            nl_msg_end_nested(out, tun_key_ofs);
            nl_msg_end_nested(out, start_ofs);
            break;
        }
        case OVS_ACTION_ATTR_SET_MASKED: {
            VLOG_WARN("XXX FXIME attr set masked");
            size_t offset = nl_msg_start_nested(out, OVS_ACTION_ATTR_SET_MASKED);

            nl_msg_end_nested(out, offset);
            break;
        }

        case OVS_ACTION_ATTR_USERSPACE: {
            VLOG_WARN("XXX FXIME attr userspace");
#if 0
            size_t offset;
            struct ovs_action_userspace *au;

            au = &act->u.userspace;

            offset = nl_msg_start_nested(out, OVS_ACTION_ATTR_USERSPACE);
            nl_msg_put_u32(out, OVS_USERSPACE_ATTR_PID, 123);
            if (nlattr_len != 0) {
                memcpy(nl_msg_put_unspec_zero(odp_actions, OVS_USERSPACE_ATTR_USERDATA,
                       MAX(8, userdata_size)),
                        userdata, userdata_size);
            }
            nl_msg_end_nested(out, offset);
#endif
            break;
        }
        case OVS_ACTION_ATTR_CT:
        case OVS_ACTION_ATTR_POP_VLAN:
        case OVS_ACTION_ATTR_PUSH_ETH:
        case OVS_ACTION_ATTR_POP_ETH:
        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_CLONE:
        case OVS_ACTION_ATTR_METER:
        case OVS_ACTION_ATTR_CT_CLEAR:
        case OVS_ACTION_ATTR_PUSH_NSH:
        case OVS_ACTION_ATTR_POP_NSH:
            VLOG_WARN("Unexpected action type %d", type);
            return EOPNOTSUPP;
        case __OVS_ACTION_ATTR_MAX:
        default:
            OVS_NOT_REACHED();
            break;
        }
    }
    return 0;
}

/* Extracts packet metadata from the BPF-formatted flow key in 'key' into a
 * flow structure in 'flow'. Returns an ODP_FIT_* value that indicates how well
 * 'key' fits our expectations for what a flow key should contain.
 *
 * Note that flow->in_port will still contain an ifindex after this call, the
 * caller is responsible for converting it to an odp_port number.
 */
void
bpf_flow_key_extract_metadata(const struct bpf_flow_key *key,
                              struct flow *flow)
{
    const struct pkt_metadata_t *md = &key->mds.md;

    /* metadata parsing */
    flow->packet_type = htonl(PT_ETH);
    flow->in_port.odp_port = u32_to_odp(md->in_port);
    flow->recirc_id = md->recirc_id;
    flow->dp_hash = md->dp_hash;
    flow->skb_priority = md->skb_priority;
    flow->pkt_mark = md->pkt_mark;
    flow->ct_state = md->ct_state;
    flow->ct_zone = md->ct_zone;
    flow->ct_mark = md->ct_mark;
    if (flow->recirc_id != 0) {
        VLOG_INFO("recirc_id = %d", flow->recirc_id);
    }

    const struct flow_tnl_t *tun = &key->mds.tnl_md;
    if (!tun->use_ipv6) {
        flow->tunnel.ip_src = htonl(tun->ip4.ip_src);
        flow->tunnel.ip_dst = htonl(tun->ip4.ip_dst);
#ifdef BPF_ENABLE_IPV6
    } else {
        memcpy(&flow->tunnel.ipv6_src, tun->ip6.ipv6_src, 16);
        memcpy(&flow->tunnel.ipv6_dst, tun->ip6.ipv6_dst, 16);
#endif
    }
    flow->tunnel.ip_tos = tun->ip_tos;
    flow->tunnel.ip_ttl = tun->ip_ttl;
    flow->tunnel.tun_id = htonll(tun->tun_id);
    //flow->tunnel.flags = FLOW_TNL_F_DONT_FRAGMENT; // this causes key differs
    flow->tunnel.flags = 0;

    if (tun->gnvopt_valid) {
        memcpy(flow->tunnel.metadata.opts.gnv, &tun->gnvopt,
               sizeof tun->gnvopt);
        flow->tunnel.metadata.present.len = sizeof tun->gnvopt;
        flow->tunnel.flags |= FLOW_TNL_F_UDPIF;
    }

//#define IP_DF       0x4000      /* Flag: "Don't Fragment"   */                  
//    flow->tunnel.flags = 0x40; //htons(IP_DF);
    /* TODO */
    /*
    flow->ct_label = md.ct_label;
    ct_nw_proto
    ct_{nw,tp}_{src,dst}
    flow_tnl_copy__()
    */
}

/* XXX The caller must perform in_port translation. */
void
bpf_metadata_from_flow(const struct flow *flow, struct ebpf_metadata_t *md)
{
    if (flow->packet_type != htonl(PT_ETH)) {
        VLOG_WARN("Cannot convert flow to bpf metadata: non-ethernet");
    }
    md->md.in_port = odp_to_u32(flow->in_port.odp_port); /* XXX */
    md->md.recirc_id = flow->recirc_id;
    md->md.dp_hash = flow->dp_hash;
    md->md.skb_priority = flow->skb_priority;
    md->md.pkt_mark = flow->pkt_mark;
    md->md.ct_state = flow->ct_state;
    md->md.ct_zone = flow->ct_zone;
    md->md.ct_mark = flow->ct_mark;

    /* TODO */
    /*
    md->md.ct_label = flow.ct_label;
    flow_tnl_copy__()
    */
}

enum odp_key_fitness
bpf_flow_key_to_flow(const struct bpf_flow_key *key, struct flow *flow)
{
    const struct ebpf_headers_t *hdrs = &key->headers;

    memset(flow, 0, sizeof *flow);
    bpf_flow_key_extract_metadata(key, flow);

    /* L2 */
    if (hdrs->valid & ETHER_VALID) {
        memcpy(&flow->dl_dst, &hdrs->ethernet.dstAddr, sizeof(struct eth_addr));
        memcpy(&flow->dl_src, &hdrs->ethernet.srcAddr, sizeof(struct eth_addr));
        flow->dl_type = hdrs->ethernet.etherType;
    }
    if (hdrs->valid & VLAN_VALID) {
        flow->vlans[0].tpid = hdrs->vlan.etherType;
        flow->vlans[0].tci = htons(hdrs->vlan.tci) | htons(VLAN_CFI);
        // extract_
        flow->dl_type = hdrs->vlan.etherType;
    }

    /* L3 */
    if (hdrs->valid & IPV4_VALID) {
        flow->nw_src = hdrs->ipv4.srcAddr;
        flow->nw_dst = hdrs->ipv4.dstAddr;
        flow->nw_ttl = hdrs->ipv4.ttl;
        flow->nw_proto = hdrs->ipv4.protocol;
#ifdef BPF_ENABLE_IPV6
    } else if (hdrs->valid & IPV6_VALID) {
        memcpy(&flow->ipv6_src, &hdrs->ipv6.srcAddr, sizeof flow->ipv6_src);
        memcpy(&flow->ipv6_dst, &hdrs->ipv6.dstAddr, sizeof flow->ipv6_dst);
        flow->ipv6_label = htonl(hdrs->ipv6.flowLabel);
        /* XXX: flow->nw_frag */
        flow->nw_tos = hdrs->ipv6.trafficClass;
        flow->nw_ttl = hdrs->ipv6.hopLimit;
        flow->nw_proto = hdrs->ipv6.nextHdr;
#endif
    } else if (hdrs->valid & ARP_VALID) {
        memcpy(&flow->arp_sha, key->headers.arp.ar_sha, 6);
        memcpy(&flow->arp_tha, key->headers.arp.ar_tha, 6);
        memcpy(&flow->nw_src, key->headers.arp.ar_sip, 4); /* be32 */
        memcpy(&flow->nw_dst, key->headers.arp.ar_tip, 4);

        if (ntohs(key->headers.arp.ar_op) < 0xff) {
            flow->nw_proto = ntohs(key->headers.arp.ar_op);
        } else {
            flow->nw_proto = 0;
        }
    }

    /* L4 */
    if (hdrs->valid & TCP_VALID) {
        flow->tcp_flags = htons(hdrs->tcp.flags);
        flow->tp_src = hdrs->tcp.srcPort;
        flow->tp_dst = hdrs->tcp.dstPort;
    } else if (hdrs->valid & UDP_VALID) {
        flow->tp_src = htons(hdrs->udp.srcPort);
        flow->tp_dst = htons(hdrs->udp.dstPort);
    } else if (hdrs->valid & ICMP_VALID) {
        /* XXX: validate */
        flow->tp_src = htons(hdrs->icmp.type); // u8 to be16
        flow->tp_dst = htons(hdrs->icmp.code);
    } else if (hdrs->valid & ICMPV6_VALID) {
        flow->tp_src = htons(hdrs->icmpv6.type); // u8 to be16
        flow->tp_dst = htons(hdrs->icmpv6.code);
    } /* XXX: IGMP */

    return ODP_FIT_PERFECT;
}

/* Converts the 'nla_len' bytes of OVS netlink-formatted flow key in 'nla' into
 * the bpf flow structure in 'key'. Returns an ODP_FIT_* value that indicates
 * how well 'nla' fits into the BPF flow key format. On success, 'in_port' will
 * be populated with the in_port specified by 'nla', which the caller must
 * convert from an ODP port number into an ifindex and place into 'key'.
 */
enum odp_key_fitness
odp_key_to_bpf_flow_key(const struct nlattr *nla, size_t nla_len,
                        struct bpf_flow_key *key, odp_port_t *in_port,
                        bool inner, bool verbose)
{
    bool found_in_port = false;
    const struct nlattr *a;
    size_t left;

    NL_ATTR_FOR_EACH(a, left, nla, nla_len) {
        enum ovs_key_attr type = nl_attr_type(a);

        switch (type) {
        case OVS_KEY_ATTR_PRIORITY:
            key->mds.md.skb_priority = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_IN_PORT: {
            /* The caller must convert the ODP port number into ifindex. */
            *in_port = nl_attr_get_odp_port(a);
            found_in_port = true;
            break;
        }
        case OVS_KEY_ATTR_ETHERNET: {
            const struct ovs_key_ethernet *eth = nl_attr_get(a);

            for (int i = 0; i < ARRAY_SIZE(eth->eth_dst.ea); i++) {
                key->headers.ethernet.dstAddr[i] = eth->eth_dst.ea[i];
                key->headers.ethernet.srcAddr[i] = eth->eth_src.ea[i];
            }
            key->headers.valid |= ETHER_VALID;
            break;
        }
        case OVS_KEY_ATTR_VLAN: {
            ovs_be16 tci = nl_attr_get_be16(a);
            struct vlan_tag_t *vlan = inner ? &key->headers.cvlan
                                            : &key->headers.vlan;
            vlan->tci = ntohs(tci);
            key->headers.vlan.tci = ntohs(tci);
            /* etherType is set below in OVS_KEY_ATTR_ETHERTYPE. */
            key->headers.valid |= VLAN_VALID;
            break;
        }
        case OVS_KEY_ATTR_ETHERTYPE: {
            ovs_be16 dl_type;

            dl_type = nl_attr_get_be16(a);
            key->headers.ethernet.etherType = dl_type;
            key->headers.valid |= ETHER_VALID;

            if (dl_type == htons(ETH_P_IP)) {
                key->headers.valid |= IPV4_VALID;
            } else if (dl_type == htons(ETH_P_IPV6)) {
                key->headers.valid |= IPV6_VALID;
            } else if (dl_type == htons(ETH_P_ARP)) {
                key->headers.valid |= ARP_VALID;
            } else if (dl_type == htons(ETH_P_8021Q)) {
                key->headers.vlan.etherType = htons(ETH_P_8021Q);
                key->headers.valid |= VLAN_VALID;
            } else if (dl_type == htons(ETH_P_8021AD)) {
                key->headers.cvlan.etherType = htons(ETH_P_8021AD);
                key->headers.valid |= CVLAN_VALID;
            } else {
                VLOG_ERR("%s dl_type %x not supported",
                          __func__, ntohs(dl_type));
            }
            break;
        }
        case OVS_KEY_ATTR_IPV4: {
            const struct ovs_key_ipv4 *ipv4 = nl_attr_get(a);

            key->headers.ipv4.srcAddr = ipv4->ipv4_src;
            key->headers.ipv4.dstAddr = ipv4->ipv4_dst;
            key->headers.ipv4.protocol = ipv4->ipv4_proto;
            key->headers.ipv4.ttl = ipv4->ipv4_ttl;
            /* XXX: ipv4->ipv4_frag; One of OVS_FRAG_TYPE_*. */
            key->headers.valid |= IPV4_VALID;
            break;
        }
        case OVS_KEY_ATTR_IPV6: {
#ifdef BPF_ENABLE_IPV6
            const struct ovs_key_ipv6 *ipv6 = nl_attr_get(a);

            memcpy(&key->headers.ipv6.srcAddr, &ipv6->ipv6_src,
                   ARRAY_SIZE(key->headers.ipv6.srcAddr));
            memcpy(&key->headers.ipv6.dstAddr, &ipv6->ipv6_dst,
                   ARRAY_SIZE(key->headers.ipv6.dstAddr));
            key->headers.ipv6.flowLabel = ntohl(ipv6->ipv6_label);
            key->headers.ipv6.nextHdr = ipv6->ipv6_proto;
            key->headers.ipv6.trafficClass = ipv6->ipv6_tclass;
            key->headers.ipv6.hopLimit = ipv6->ipv6_hlimit;
            /* XXX: ipv6_frag;	One of OVS_FRAG_TYPE_*. */
            key->headers.valid |= IPV6_VALID;
#endif
            break;
        }
        case OVS_KEY_ATTR_TCP: {
            const struct ovs_key_tcp *tcp = nl_attr_get(a);

            key->headers.tcp.srcPort = tcp->tcp_src;
            key->headers.tcp.dstPort = tcp->tcp_dst;
            key->headers.valid |= TCP_VALID;
            break;
        }
        case OVS_KEY_ATTR_UDP: {
            const struct ovs_key_udp *udp = nl_attr_get(a);

            key->headers.udp.srcPort = ntohs(udp->udp_src);
            key->headers.udp.dstPort = ntohs(udp->udp_dst);
            key->headers.valid |= UDP_VALID;
            break;
        }
        case OVS_KEY_ATTR_ICMP: {
            const struct ovs_key_icmp *icmp = nl_attr_get(a);
            /* XXX: Double-check */
            key->headers.icmp.type = icmp->icmp_type;
            key->headers.icmp.code = icmp->icmp_code;
            key->headers.valid |= ICMP_VALID;
            break;
        }
        case OVS_KEY_ATTR_ARP: {
            const struct ovs_key_arp *arp = nl_attr_get(a);

            key->headers.arp.ar_op = arp->arp_op;
            memcpy(key->headers.arp.ar_sip, &arp->arp_sip, 4);
            memcpy(key->headers.arp.ar_tip, &arp->arp_tip, 4); /* be32 */
            memcpy(key->headers.arp.ar_sha, &arp->arp_sha, 6);
            memcpy(key->headers.arp.ar_tha, &arp->arp_tha, 6);
            key->headers.valid |= ARP_VALID;
            break;
        }
        case OVS_KEY_ATTR_SKB_MARK:
            key->mds.md.pkt_mark = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_TCP_FLAGS: {
            ovs_be16 flags_be = nl_attr_get_be16(a);
            uint16_t flags = ntohs(flags_be);

            key->headers.tcp.flags = flags;
            key->headers.tcp.res = flags >> 8;
            key->headers.valid |= TCP_VALID;
            break;
        }
        case OVS_KEY_ATTR_DP_HASH:
            key->mds.md.dp_hash = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_RECIRC_ID:
            key->mds.md.recirc_id = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_CT_STATE:
            key->mds.md.ct_state = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_CT_ZONE:
            key->mds.md.ct_zone = nl_attr_get_u16(a);
            break;
        case OVS_KEY_ATTR_CT_MARK:
            key->mds.md.ct_mark = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_CT_LABELS:
            memcpy(&key->mds.md.ct_label, nl_attr_get(a),
                   sizeof(key->mds.md.ct_label));
            break;
        case OVS_KEY_ATTR_PACKET_TYPE: {
            ovs_be32 pt = nl_attr_get_be32(a);
            if (pt != htonl(PT_ETH)) {
                return ODP_FIT_ERROR;
            }
            break;
        }
        case OVS_KEY_ATTR_MPLS: {
            const struct ovs_key_mpls *mpls = nl_attr_get(a);
            key->headers.mpls.top_lse = mpls->mpls_lse;
            break;
        }
        case OVS_KEY_ATTR_ENCAP: {
            enum odp_key_fitness ret;
            ret = odp_key_to_bpf_flow_key(nl_attr_get(a), nl_attr_get_size(a),
                                          key, in_port, true, verbose);
            if (ret != ODP_FIT_PERFECT) {
                return ret;
            }
            break;
        }
        case OVS_KEY_ATTR_TUNNEL: {
            enum odp_key_fitness ret;
            ret = odp_tun_to_bpf_tun(nl_attr_get(a), nl_attr_get_size(a),
                                     &key->mds.tnl_md);
            if (ret != ODP_FIT_PERFECT) {
                VLOG_ERR("%s odp key to bpf tunnel key error", __func__);
                return ret;
            }
            break;
        }
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
        case OVS_KEY_ATTR_ICMPV6: {
            const struct ovs_key_icmpv6 *icmpv6 = nl_attr_get(a);

            key->headers.icmpv6.type = icmpv6->icmpv6_type;
            key->headers.icmpv6.code = icmpv6->icmpv6_code;
            key->headers.valid |= ICMPV6_VALID;
            break;
        }
        case OVS_KEY_ATTR_ND: {
            // XXX skip
            break;
        }
        case OVS_KEY_ATTR_SCTP:
        case OVS_KEY_ATTR_NSH:
        {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 20);
            struct ds ds = DS_EMPTY_INITIALIZER;
			// compile error, remove it
            //odp_format_key_attr(a, NULL, NULL, &ds, verbose);
            VLOG_INFO_RL(&rl, "Cannot convert \'%s\'", ds_cstr(&ds));
            ds_destroy(&ds);
            return ODP_FIT_ERROR;
        }
        case OVS_KEY_ATTR_UNSPEC:
        case __OVS_KEY_ATTR_MAX:
        default:
            OVS_NOT_REACHED();
        }
    }

    if (!inner && !found_in_port) {
        VLOG_ERR("not found in_port");
        return ODP_FIT_ERROR;
    }

    if (!inner && verbose) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "%s\nODP:\n", __func__);
        odp_flow_key_format(nla, nla_len, &ds);
        ds_put_cstr(&ds, "\nBPF:\n");
        bpf_flow_key_format(&ds, key);
        VLOG_INFO_RL(&rl, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    return ODP_FIT_PERFECT;
}

#define TABSPACE "  "

static void
indent(struct ds *ds, struct ds *tab, const char *string)
{
    ds_put_format(ds, "%s%s", ds_cstr(tab), string);
    ds_put_cstr(tab, TABSPACE);
}

static void
trim(struct ds *ds, struct ds *tab)
{
    ds_chomp(ds, '\n');
    ds_put_char(ds, '\n');
    ds_truncate(tab, tab->length ? tab->length - strlen(TABSPACE) : 0);
}

#define PUT_FIELD(STRUCT, NAME, FORMAT)                               \
    if (STRUCT->NAME)                                                   \
        ds_put_format(ds, #NAME"=%"FORMAT",", STRUCT->NAME)

void
bpf_flow_key_format(struct ds *ds, const struct bpf_flow_key *key)
{
    struct ds tab = DS_EMPTY_INITIALIZER;

    indent(ds, &tab, "headers:\n");
    {
        if (key->headers.valid & ETHER_VALID) {
            const struct ethernet_t *eth = &key->headers.ethernet;
            const struct eth_addr *src = (struct eth_addr *)&eth->srcAddr;
            const struct eth_addr *dst = (struct eth_addr *)&eth->dstAddr;

            ds_put_format(ds, "%sethernet(", ds_cstr(&tab));
            PUT_FIELD(eth, etherType, "#"PRIx16);
            ds_put_format(ds, "dst="ETH_ADDR_FMT",", ETH_ADDR_ARGS(*dst));
            ds_put_format(ds, "src="ETH_ADDR_FMT",", ETH_ADDR_ARGS(*src));
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.valid & IPV4_VALID) {
            const struct ipv4_t *ipv4 = &key->headers.ipv4;

            ds_put_format(ds, "%sipv4(", ds_cstr(&tab));
            PUT_FIELD(ipv4, ttl, "#"PRIx8);
            PUT_FIELD(ipv4, protocol, "#"PRIx8);
            ds_put_format(ds, "srcAddr="IP_FMT",", IP_ARGS(ipv4->srcAddr));
            ds_put_format(ds, "dstAddr="IP_FMT",", IP_ARGS(ipv4->dstAddr));
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
#ifdef BPF_ENABLE_IPV6
        if (key->headers.valid & IPV6_VALID) {
            const struct ipv6_t *ipv6 = &key->headers.ipv6;

            ds_put_format(ds, "%sipv6(", ds_cstr(&tab));
            PUT_FIELD(ipv6, version, "#"PRIx8);
            PUT_FIELD(ipv6, trafficClass, "#"PRIx8);
            PUT_FIELD(ipv6, flowLabel, "#"PRIx32);
            PUT_FIELD(ipv6, payloadLen, "#"PRIx16);
            PUT_FIELD(ipv6, nextHdr, "#"PRIx8);
            PUT_FIELD(ipv6, hopLimit, "#"PRIx8);
            ds_put_cstr(ds, "src=");
            ipv6_format_addr((struct in6_addr *)&ipv6->srcAddr, ds);
            ds_put_cstr(ds, ",dst=");
            ipv6_format_addr((struct in6_addr *)&ipv6->dstAddr, ds);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
#endif
        if (key->headers.valid & ARP_VALID) {
            const struct arp_rarp_t *arp = &key->headers.arp;

            ds_put_format(ds, "%sarp(", ds_cstr(&tab));
            PUT_FIELD(arp, ar_hrd, "#"PRIx16);
            PUT_FIELD(arp, ar_pro, "#"PRIx16);
            PUT_FIELD(arp, ar_hln, "#"PRIx8);
            PUT_FIELD(arp, ar_pln, "#"PRIx8);
            PUT_FIELD(arp, ar_op, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.valid & TCP_VALID) {
            const struct tcp_t *tcp = &key->headers.tcp;

            ds_put_format(ds, "%stcp(", ds_cstr(&tab));
            PUT_FIELD(tcp, srcPort, PRIu16);
            PUT_FIELD(tcp, dstPort, PRIu16);
            PUT_FIELD(tcp, seqNo, "#"PRIx32);
            PUT_FIELD(tcp, ackNo, "#"PRIx32);
            PUT_FIELD(tcp, dataOffset, "#"PRIx8);
            PUT_FIELD(tcp, res, "#"PRIx8);
            PUT_FIELD(tcp, flags, "#"PRIx8);
            PUT_FIELD(tcp, window, "#"PRIx16);
            PUT_FIELD(tcp, checksum, "#"PRIx16);
            PUT_FIELD(tcp, urgentPtr, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.valid & UDP_VALID) {
            const struct udp_t *udp = &key->headers.udp;

            ds_put_format(ds, "%sudp(", ds_cstr(&tab));
            PUT_FIELD(udp, srcPort, PRIu16);
            PUT_FIELD(udp, dstPort, PRIu16);
            PUT_FIELD(udp, length_, "#"PRIx16);
            PUT_FIELD(udp, checksum, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.valid & ICMP_VALID) {
            const struct icmp_t *icmp = &key->headers.icmp;

            ds_put_format(ds, "%sicmp(", ds_cstr(&tab));
            PUT_FIELD(icmp, type, "#"PRIx8);
            PUT_FIELD(icmp, code, "#"PRIx8);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.valid & VLAN_VALID) {
            const struct vlan_tag_t *vlan = &key->headers.vlan;

            ds_put_format(ds, "%svlan(", ds_cstr(&tab));
            PUT_FIELD(vlan, pcp, "#"PRIx8);
            PUT_FIELD(vlan, cfi, "#"PRIx8);
            PUT_FIELD(vlan, vid, "#"PRIx16);
            PUT_FIELD(vlan, tci, "#"PRIx16);
            PUT_FIELD(vlan, etherType, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
    }
    trim(ds, &tab);
    indent(ds, &tab, "metadata:\n");
    {
        indent(ds, &tab, "md:\n");
        {
            ds_put_hex_dump(ds, &key->mds.md, sizeof key->mds.md, 0, false);
        }
        trim(ds, &tab);
        indent(ds, &tab, "tnl_md:\n");
        {
            ds_put_hex_dump(ds, &key->mds.tnl_md, sizeof key->mds.tnl_md, 0,
                            false);
        }
        trim(ds, &tab);
    }
    trim(ds, &tab);
    ds_chomp(ds, '\n');

    ds_destroy(&tab);
}
