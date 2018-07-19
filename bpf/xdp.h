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

__section("xdp")
static int xdp_ingress(struct xdp_md *ctx OVS_UNUSED)
{
    /* TODO: see p4c-xdp project */
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

__section("af_xdp")
static int af_xdp_ingress(struct xdp_md *ctx OVS_UNUSED)
{
    /* TODO: see xdpsock_kern.c ans xdpsock_user.c */
    return XDP_PASS;
}
