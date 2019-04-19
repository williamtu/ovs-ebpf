/*
 * Copyright (c) 2019 Nicira, Inc.
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

#ifndef NETDEV_LINUX_PRIVATE_H
#define NETDEV_LINUX_PRIVATE_H 1

#include <config.h>

#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <stdint.h>
#include <stdbool.h>

#include "netdev-provider.h"
#include "netdev-tc-offloads.h"
#include "netdev-vport.h"
#include "openvswitch/thread.h"
#include "ovs-atomic.h"
#include "timer.h"

#if HAVE_AF_XDP
#include "netdev-afxdp.h"
#endif

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

struct netdev;

int netdev_linux_ethtool_set_flag(struct netdev *netdev, uint32_t flag,
                                  const char *flag_name, bool enable);
int linux_get_ifindex(const char *netdev_name);

#define LINUX_FLOW_OFFLOAD_API                          \
   .flow_flush = netdev_tc_flow_flush,                  \
   .flow_dump_create = netdev_tc_flow_dump_create,      \
   .flow_dump_destroy = netdev_tc_flow_dump_destroy,    \
   .flow_dump_next = netdev_tc_flow_dump_next,          \
   .flow_put = netdev_tc_flow_put,                      \
   .flow_get = netdev_tc_flow_get,                      \
   .flow_del = netdev_tc_flow_del,                      \
   .init_flow_api = netdev_tc_init_flow_api

struct netdev_linux {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    unsigned int cache_valid;

    bool miimon;                    /* Link status of last poll. */
    long long int miimon_interval;  /* Miimon Poll rate. Disabled if <= 0. */
    struct timer miimon_timer;

    int netnsid;                    /* Network namespace ID. */
    /* The following are figured out "on demand" only.  They are only valid
     * when the corresponding VALID_* bit in 'cache_valid' is set. */
    int ifindex;
    struct eth_addr etheraddr;
    int mtu;
    unsigned int ifi_flags;
    long long int carrier_resets;
    uint32_t kbits_rate;        /* Policing data. */
    uint32_t kbits_burst;
    int vport_stats_error;      /* Cached error code from vport_get_stats().
                                   0 or an errno value. */
    int netdev_mtu_error;       /* Cached error code from SIOCGIFMTU
                                 * or SIOCSIFMTU.
                                 */
    int ether_addr_error;       /* Cached error code from set/get etheraddr. */
    int netdev_policing_error;  /* Cached error code from set policing. */
    int get_features_error;     /* Cached error code from ETHTOOL_GSET. */
    int get_ifindex_error;      /* Cached error code from SIOCGIFINDEX. */

    enum netdev_features current;    /* Cached from ETHTOOL_GSET. */
    enum netdev_features advertised; /* Cached from ETHTOOL_GSET. */
    enum netdev_features supported;  /* Cached from ETHTOOL_GSET. */

    struct ethtool_drvinfo drvinfo;  /* Cached from ETHTOOL_GDRVINFO. */
    struct tc *tc;

    /* For devices of class netdev_tap_class only. */
    int tap_fd;
    bool present;               /* If the device is present in the namespace */
    uint64_t tx_dropped;        /* tap device can drop if the iface is down */

    /* LAG information. */
    bool is_lag_master;         /* True if the netdev is a LAG master. */

    /* AF_XDP information */
#ifdef HAVE_AF_XDP
    struct xsk_socket_info *xsk[MAX_XSKQ];
    int requested_n_rxq;
    int xdpmode, requested_xdpmode; /* detect mode changed */
    int xdp_flags, xdp_bind_flags;
#endif
};

static struct netdev_linux *
netdev_linux_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_linux, up);
}

#endif /* netdev-linux-private.h */
