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

#define OVS_LOAD_BYTES(xdp, offset, dst, len) \
({ \
    int ___ret = 0; \
    if ((char *)(long)xdp->data + offset + len > (char *)(long)xdp->data_end) { \
        printt("ERR: xdp load byte too short\n"); \
        return XDP_DROP; \
    } \
    memcpy(dst, (char *)(long)xdp->data + offset, len); \
    ___ret; \
})
#define OVS_SK_BUFF xdp_md
#define PARSE_DATA xdp_parse_data
#include "parser_common.h"
#undef OVS_LOAD_BYTES
#undef OVS_SK_BUFF
#undef PARSE_DATA

/* Program: xdp */
__section("xdp")
static int xdp_ingress(struct xdp_md *ctx OVS_UNUSED)
{
    printt("=== enter xdp_ingress ===\n");

    /* if a netdev supports xdp, parse the packet data
     * first, and save in map percpu_headers
     */
    xdp_parse_data(ctx);

#ifdef BPF_ENABLE_IPV6
	printt("return XDP_PASS\n");
    return XDP_PASS;
#else
    /* Early drop ipv6 */
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u16 h_proto;

	if ((char *)eth + 14 > (char *)data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;

	if (h_proto == bpf_htons(ETH_P_IPV6)) {
		printt("drop ipv6\n");
		return XDP_DROP;
	}
#endif
}

#define DEBUG
#ifdef DEBUG
#define AFXDP_REDIRECT(xskmap) { \
    int idx = 0; \
    int flags = 0; \
    int len = (long)ctx->data_end - (long)ctx->data; \
    printt("ingress_ifindex %d rx_queue_index %d pkt len %d\n", \
            ctx->ingress_ifindex, ctx->rx_queue_index, len); \
    printt("send to queue xsk queue 0\n"); \
    return bpf_redirect_map(xskmap, idx, flags); \
}
#else
#define AFXDP_REDIRECT(xskmap) { \
    int idx = 0; \
    int flags = 0; \
    return bpf_redirect_map(xskmap, idx, flags); \
}
#endif

/* For AFXDP, we need one map and one afxdp program per netdev */
__section("afxdp0")
static int af_xdp_ingress0(struct xdp_md *ctx OVS_UNUSED)
{
    AFXDP_REDIRECT(&xsks_map0);
}
__section("afxdp1")
static int af_xdp_ingress1(struct xdp_md *ctx OVS_UNUSED)
{
    AFXDP_REDIRECT(&xsks_map1);
}
__section("afxdp2")
static int af_xdp_ingress2(struct xdp_md *ctx OVS_UNUSED)
{
    AFXDP_REDIRECT(&xsks_map2);
}
__section("afxdp3")
static int af_xdp_ingress3(struct xdp_md *ctx OVS_UNUSED)
{
    AFXDP_REDIRECT(&xsks_map3);
}
