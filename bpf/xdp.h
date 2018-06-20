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
#include "ovs-p4.h"
#include "api.h"
#include "helpers.h"

__section("xdp")
static int xdp_ingress(struct xdp_md *ctx OVS_UNUSED)
{
    /* TODO: see p4c-xdp project */
    printt("return XDP_PASS\n");
    return XDP_PASS;
}

__section("af_xdp")
static int af_xdp_ingress(struct xdp_md *ctx OVS_UNUSED)
{
    /* TODO: see xdpsock_kern.c ans xdpsock_user.c */
    return XDP_PASS;
}
