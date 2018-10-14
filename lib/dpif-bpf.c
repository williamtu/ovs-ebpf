/*
 * Copyright (c) 2016, 2017, 2018 Nicira, Inc.
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

#include <errno.h>
#include <openvswitch/hmap.h>
#include <openvswitch/types.h>
#include <openvswitch/vlog.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bpf.h"
#include "bpf/odp-bpf.h"
#include "dirs.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "dpif-bpf-odp.h"
#include "dpif-netlink-rtnl.h"
#include "fat-rwlock.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "ovs-numa.h"
#include "perf-event.h"
#include "sset.h"
#include "openvswitch/poll-loop.h"

VLOG_DEFINE_THIS_MODULE(dpif_bpf);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

#define FLOW_DUMP_MAX_BATCH 50
#define FLOW_DUMP_BUF_SIZE  2048

/* Protects against changes to 'bpf_datapaths'. */
static struct ovs_mutex bpf_datapath_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpif_bpf_dp's. */
static struct shash bpf_datapaths OVS_GUARDED_BY(bpf_datapath_mutex)
    = SHASH_INITIALIZER(&bpf_datapaths);

struct bpf_handler {
    /* Into owning dpif_bpf_dp->channels */
    int offset;
    int count;
    int index;         /* next channel to use */
};

struct dpif_bpf_dp {
    struct dpif *dpif;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Ports.
     *
     * Any lookup into 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports_by_odp OVS_GUARDED;
    struct hmap ports_by_ifindex OVS_GUARDED;
    struct seq *port_seq;       /* Incremented whenever a port changes. */
    uint64_t last_seq;

    /* Handlers */
    struct fat_rwlock upcall_lock;
    uint32_t n_handlers;
    struct bpf_handler *handlers;

    /* Upcall channels. */
    size_t page_size;
    int n_pages;
    int n_channels;
    struct perf_channel channels[];
};

struct dpif_bpf {
    struct dpif dpif;
    struct dpif_bpf_dp *dp;
};

struct dpif_bpf_port {
    struct hmap_node odp_node;  /* Node in dpif_bpf_dp 'ports_by_odp'. */
    struct hmap_node if_node;   /* Node in dpif_bpf_dp 'ports_by_ifindex'. */
    struct netdev *netdev;
    odp_port_t port_no;
    int ifindex;
    char *type;                 /* Port type as requested by user. */
    struct netdev_saved_flags *sf;

    unsigned n_rxq;
    struct netdev_rxq **rxqs;
};

static void vlog_hex_dump(const u8 *buf, size_t count)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_hex_dump(&ds, buf, count, 0, false);
    VLOG_INFO("\n%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

int create_dp_bpf(const char *name, struct dpif_bpf_dp **dp);
static void dpif_bpf_close(struct dpif *dpif);
static int do_add_port(struct dpif_bpf_dp *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static void do_del_port(struct dpif_bpf_dp *dp, struct dpif_bpf_port *port)
    OVS_REQUIRES(dp->port_mutex);
static int dpif_bpf_delete_all_flow(void);

static struct dpif_bpf *
dpif_bpf_cast(const struct dpif *dpif)
{
    ovs_assert(dpif->dpif_class == &dpif_bpf_class);
    return CONTAINER_OF(dpif, struct dpif_bpf, dpif);
}

static struct dpif_bpf_dp *
get_dpif_bpf_dp(const struct dpif *dpif)
{
    return dpif_bpf_cast(dpif)->dp;
}

static struct dp_bpf {
    struct bpf_state bpf;
    struct netdev *outport; /* Used for downcall. */
} datapath;

static int
configure_outport(struct netdev *outport)
{
    int error;

    error = netdev_set_filter(outport, &datapath.bpf.downcall);
    if (error) {
        return error;
    }

    error = netdev_set_flags(outport, NETDEV_UP, NULL);
    if (error) {
        return error;
    }

    return 0;
}

static int
dpif_bpf_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int error = 0;

    if (ovsthread_once_start(&once)) {
        struct netdev *outport;

        error = bpf_get(&datapath.bpf, true);
        if (!error) {
            /* FIXME: should we named ovs-system? */
            error = netdev_open("ovs-system", "tap", &outport);
            if (!error) {
                VLOG_INFO("%s: created BPF tap downcall device %s",
                          __func__, outport->name);

                error = configure_outport(outport);
                if (error) {
                    VLOG_ERR("%s: configure downcall device failed", __func__);
                    netdev_close(outport);
                } else {
                    datapath.outport = outport;
                }
            }
        }

        if (!error) {
            dpif_bpf_delete_all_flow();
        }
        ovsthread_once_done(&once);
    }
    return error;
}

static int
dpif_bpf_enumerate(struct sset *all_dps,
                   const struct dpif_class *dpif_class OVS_UNUSED)
{
    struct shash_node *node;

    ovs_mutex_lock(&bpf_datapath_mutex);
    SHASH_FOR_EACH(node, &bpf_datapaths) {
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&bpf_datapath_mutex);

    return 0;
}

static const char
*dpif_bpf_port_open_type(const struct dpif_class *dpif_class OVS_UNUSED,
                         const char *type)
{
    return strcmp(type, "internal") ? type : "tap";
}

static struct dpif *
create_dpif_bpf(struct dpif_bpf_dp *dp)
    OVS_REQUIRES(bpf_datapath_mutex)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_bpf *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, &dpif_bpf_class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;

    return &dpif->dpif;
}

static int
dpif_bpf_open(const struct dpif_class *dpif_class OVS_UNUSED,
              const char *name, bool create OVS_UNUSED, struct dpif **dpifp)
{
    struct dpif_bpf_dp *dp;
    int error;

    error = dpif_bpf_init();
    if (error) {
        VLOG_ERR("dpif_bpf_init failed");
        return error;
    }

    ovs_mutex_lock(&bpf_datapath_mutex);
    dp = shash_find_data(&bpf_datapaths, name);
    if (!dp) {
        error = create ? create_dp_bpf(name, &dp) : ENODEV;
    } else {
        ovs_assert(dpif_class == &dpif_bpf_class);
        error = create ? EEXIST : 0;
    }
    if (!error) {
        *dpifp = create_dpif_bpf(dp);
        if (create) { /* XXX */
            dp->dpif = *dpifp;
        }
    }
    ovs_mutex_unlock(&bpf_datapath_mutex);

    return error;
}

static int
perf_event_channels_init(struct dpif_bpf_dp *dp)
{
    size_t length = dp->page_size * (dp->n_pages + 1);
    int error = 0;
    int i, cpu;

    for (cpu = 0; cpu < dp->n_channels; cpu++) {
        struct perf_channel *channel = &dp->channels[cpu];

        error = perf_channel_open(channel, cpu, length);
        if (error) {
            goto error;
        }
    }

error:
    if (error) {
        for (i = 0; i < cpu; i++) {
            perf_channel_close(&dp->channels[cpu]);
        }
    }

    return error;
}

static void
dpif_bpf_free(struct dpif_bpf_dp *dp)
    OVS_REQUIRES(bpf_datapath_mutex)
{
    shash_find_and_delete(&bpf_datapaths, dp->name);

    if (ovs_refcount_read(&dp->ref_cnt) == 0) {
        ovs_mutex_destroy(&dp->port_mutex);
        seq_destroy(dp->port_seq);
        fat_rwlock_destroy(&dp->upcall_lock);
        hmap_destroy(&dp->ports_by_ifindex);
        hmap_destroy(&dp->ports_by_odp);
        if (dp->n_handlers) {
            free(dp->handlers);
        }
        free(dp);
    }
}

int
create_dp_bpf(const char *name, struct dpif_bpf_dp **dp_)
    OVS_REQUIRES(bpf_datapath_mutex)
{
    int max_cpu;
    struct dpif_bpf_dp *dp;
    int i, error;

    max_cpu = ovs_numa_get_n_cores();

    dp = xzalloc(sizeof *dp + max_cpu * sizeof(struct perf_channel));
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_clear(&dp->destroyed);
    hmap_init(&dp->ports_by_odp);
    hmap_init(&dp->ports_by_ifindex);
    fat_rwlock_init(&dp->upcall_lock);
    dp->port_seq = seq_create();
    ovs_mutex_init(&dp->port_mutex);
    dp->n_pages = 8;
    dp->page_size = sysconf(_SC_PAGESIZE);
    dp->n_channels = max_cpu;
    dp->last_seq = seq_read(dp->port_seq);

    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    shash_add(&bpf_datapaths, name, dp); /* XXX */

    error = perf_event_channels_init(dp);
    if (error) {
        dpif_bpf_free(dp);
        return error;
    }

    ovs_assert(datapath.bpf.upcalls.fd != -1);

    for (i = 0; i < dp->n_channels; i++) {
        error = bpf_map_update_elem(datapath.bpf.upcalls.fd, &i,
                                    &dp->channels[i].fd, 0);
        if (error) {
            VLOG_WARN("failed to insert channel fd on cpu=%d: %s",
                      i, ovs_strerror(error));
            goto out;
        }
    }

out:
    if (error) {
        dpif_bpf_free(dp);
    }
    if (!error) {
        *dp_ = dp;
    }
    return 0;
}

static void
dpif_bpf_close(struct dpif *dpif_)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);

    ovs_mutex_lock(&bpf_datapath_mutex);
    if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
        struct dpif_bpf_port *port, *next;
        int i;

        fat_rwlock_wrlock(&dp->upcall_lock);
        for (i = 0; i < dp->n_channels; i++) {
            struct perf_channel *channel = &dp->channels[i];

            perf_channel_close(channel);
        }
        fat_rwlock_unlock(&dp->upcall_lock);

        ovs_mutex_lock(&dp->port_mutex);
        HMAP_FOR_EACH_SAFE (port, next, odp_node, &dp->ports_by_odp) {
            do_del_port(dp, port);
        }
        ovs_mutex_unlock(&dp->port_mutex);
        dpif_bpf_free(dp);
    }
    ovs_mutex_unlock(&bpf_datapath_mutex);

    free(dpif_bpf_cast(dpif_));
}

static int
dpif_bpf_destroy(struct dpif *dpif_)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'.
             * The workflow is first call dpif_class->destroy() then
             * dpif->close(). */
            OVS_NOT_REACHED();
        }
    }
#if 0
    if (datapath.outport) {
        netdev_close(datapath.outport);
    }
#endif

    return 0;
}

static int
dpif_bpf_get_stats(const struct dpif *dpif OVS_UNUSED,
                   struct dpif_dp_stats *stats)
{
    uint32_t key, n_flows = 0;
    struct bpf_flow_key flow_key;
    int err = 0;

    memset(stats, 0, sizeof(*stats));
    key = OVS_DP_STATS_HIT;
    if (bpf_map_lookup_elem(datapath.bpf.datapath_stats.fd, &key,
                            &stats->n_hit)) {
        VLOG_INFO("datapath_stats lookup failed (%d): %s", key,
                  ovs_strerror(errno));
    }
    key = OVS_DP_STATS_MISSED;
    if (bpf_map_lookup_elem(datapath.bpf.datapath_stats.fd, &key,
                            &stats->n_missed)) {
        VLOG_INFO("datapath_stats lookup failed (%d): %s", key,
                  ovs_strerror(errno));
    }

    /* Count the number of datapath flow entries */
    memset(&flow_key, 0, sizeof flow_key);
    do {
        err = bpf_map_get_next_key(datapath.bpf.flow_table.fd,
                                   &flow_key, &flow_key);
        if (!err) {
            n_flows++;
        }
    } while (!err);

    stats->n_flows = n_flows;

    /* XXX: Other missing stats */
    return 0;
}

static struct dpif_bpf_port *
bpf_lookup_port(const struct dpif_bpf_dp *dp, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, odp_node, netdev_hash_port_no(port_no),
                             &dp->ports_by_odp) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static odp_port_t
choose_port(struct dpif_bpf_dp *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    uint32_t port_no;

    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!bpf_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

static int
get_port_by_name(struct dpif_bpf_dp *dp, const char *devname,
                 struct dpif_bpf_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    HMAP_FOR_EACH (port, odp_node, &dp->ports_by_odp) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }

    *portp = NULL;
    return ENOENT;
}

static uint32_t
hash_ifindex(int ifindex)
{
    return hash_int(ifindex, 0);
}

static int
get_port_by_ifindex(struct dpif_bpf_dp *dp, int ifindex,
                    struct dpif_bpf_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, if_node, hash_ifindex(ifindex),
                             &dp->ports_by_ifindex) {
        if (port->ifindex == ifindex) {
            *portp = port;
            return 0;
        }
    }

    *portp = NULL;
    return ENOENT;
}

static odp_port_t
ifindex_to_odp(struct dpif_bpf_dp *dp, int ifindex)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    if (get_port_by_ifindex(dp, ifindex, &port)) {
        return ODPP_NONE;
    }

    return port->port_no;
}

static bool output_to_local_stack(struct netdev *netdev)
{
    return !strcmp(netdev_get_type(netdev), "tap");
}

static bool netdev_support_xdp(struct netdev *netdev OVS_UNUSED)
{
    return true;
}

static uint32_t
get_port_flags(struct netdev *netdev)
{
    return output_to_local_stack(netdev) ? OVS_BPF_FLAGS_TX_STACK : 0;
}

static uint16_t
odp_port_to_ifindex(struct dpif_bpf_dp *dp, odp_port_t port_no, uint32_t *flags)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port = bpf_lookup_port(dp, port_no);

    if (port) {
        if (flags) {
            *flags = get_port_flags(port->netdev);
        }
        return port->ifindex;
    }
    return 0;
}

/* Modelled after dpif-netdev 'port_create', minus pmd and txq logic, plus bpf
 * filter set. */
static int
port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dpif_bpf_port **portp)
{
    struct netdev_saved_flags *sf;
    struct dpif_bpf_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int n_open_rxqs = 0;
    int i, error;
    int ifindex;

    *portp = NULL;

    /* Open and validate network device. */
    error = netdev_open(devname, type, &netdev);

    VLOG_DBG("%s %s type %s error %d", __func__, devname, type, error);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR_RL(&rl, "%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

    if (netdev_is_reconf_required(netdev)) {
        error = netdev_reconfigure(netdev);
        if (error) {
            goto out;
        }
    }

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_WARN_RL(&rl, "%s: Failed to get ifindex", devname);
        error = -ifindex;
        goto out;
    }

    VLOG_DBG("%s ifindex = %d", devname, ifindex);

    /* For all internal port, ex: br0, br-underlay, br-int,
       we set bpf program only to its egress queue. (due to the
       natural of tap device). For other types, ex: eth0, vxlan_sys,
       we set bpf program to its ingress queue.

       A tap device's egress queue is tied to a socket for userspace
       to receive the packet by open(/dev/tun0).  On the other hand,
       a send to the socket will show up in the tap device's ingress queue.
    */
    if (output_to_local_stack(netdev)) {
        error = netdev_set_filter(netdev, &datapath.bpf.egress);
    } else {
        error = netdev_set_filter(netdev, &datapath.bpf.ingress);
    }
    if (error) {
        goto out;
    }

    if (netdev_support_xdp(netdev)) {
        error = netdev_set_xdp(netdev, &datapath.bpf.xdp);
        if (error) {
            VLOG_WARN("%s XDP set failed", __func__);
            goto out;
        }
        VLOG_DBG("%s %s XDP set done", __func__, netdev->name);
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->ifindex = ifindex;
    port->netdev = netdev;
    port->n_rxq = netdev_n_rxq(netdev);
    port->rxqs = xcalloc(port->n_rxq, sizeof *port->rxqs);
    port->type = xstrdup(type);

    for (i = 0; i < port->n_rxq; i++) {
        error = netdev_rxq_open(netdev, &port->rxqs[i], i);
        if (error) {
            VLOG_ERR("%s: cannot receive packets on this network device (queue %d) (%s)",
                     devname, i, ovs_strerror(errno));
            goto out_rxq_close;
        }
        n_open_rxqs++;
    }

    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) {
        goto out_rxq_close;
    }
    port->sf = sf;

    *portp = port;
    return 0;

out_rxq_close:
    for (i = 0; i < n_open_rxqs; i++) {
        netdev_rxq_close(port->rxqs[i]);
    }
    free(port->type);
    free(port->rxqs);
    free(port);

out:
    netdev_close(netdev);
    return error;
}

static int
do_add_port(struct dpif_bpf_dp *dp, const char *devname,
            const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;
    int error;

    if (!get_port_by_name(dp, devname, &port)) {
        return EEXIST;
    }

    error = port_create(devname, type, port_no, &port);
    if (error) {
        VLOG_ERR("port_create return %d", error);
        return error;
    }

    hmap_insert(&dp->ports_by_odp, &port->odp_node,
                netdev_hash_port_no(port->port_no));
    hmap_insert(&dp->ports_by_ifindex, &port->if_node,
                hash_ifindex(port->ifindex));
    seq_change(dp->port_seq);

    return 0;
}

static int
dpif_bpf_port_add(struct dpif *dpif, struct netdev *netdev,
                  odp_port_t *port_nop)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    if (!strcmp(netdev_get_type(netdev), "vxlan") ||
        !strcmp(netdev_get_type(netdev), "gre") ||
        !strcmp(netdev_get_type(netdev), "geneve")) {

        VLOG_INFO("Creating %s device", netdev_get_type(netdev));
        error = dpif_netlink_rtnl_port_create(netdev);
        if (error) {
            if (error != EOPNOTSUPP) {
                VLOG_WARN_RL(&rl, "Failed to create %s with rtnetlink: %s",
                             netdev_get_name(netdev), ovs_strerror(error));
            }
            return error;
        }
    }

    ovs_mutex_lock(&dp->port_mutex);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = bpf_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (error) {
        goto unlock;
    }

    *port_nop = port_no;
    error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    if (error) {
        goto unlock;
    }

unlock:
    ovs_mutex_unlock(&dp->port_mutex);
    return error;
}

static void
do_del_port(struct dpif_bpf_dp *dp, struct dpif_bpf_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    int i, error;

    seq_change(dp->port_seq);
    hmap_remove(&dp->ports_by_odp, &port->odp_node);
    hmap_remove(&dp->ports_by_ifindex, &port->if_node);

    error = netdev_set_filter(port->netdev, NULL);
    if (error) {
        VLOG_WARN("%s: Failed to clear filter from netdev",
                  netdev_get_name(port->netdev));
    }

    if (netdev_support_xdp(port->netdev)) {
        error = netdev_set_xdp(port->netdev, NULL);
        if (error) {
            VLOG_WARN("%s: Failed to clear XDP from netdev",
                      netdev_get_name(port->netdev));
        }
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);
    for (i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i]);
    }

    free(port->type);
    free(port->rxqs);
    free(port);
}

static int
dpif_bpf_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif);
    struct dpif_bpf_port *port;
    int error = 0;

    ovs_mutex_lock(&dp->port_mutex);
    port = bpf_lookup_port(dp, port_no);
    if (!port) {
        VLOG_WARN("deleting port %d, but it doesn't exist", port_no);
        error = EINVAL;
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static void
answer_port_query(const struct dpif_bpf_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static int
dpif_bpf_port_query_by_number(const struct dpif *dpif_, odp_port_t port_no,
                              struct dpif_port *port_)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);
    struct dpif_bpf_port *port;
    int error = 0;

    ovs_mutex_lock(&dp->port_mutex);
    port = bpf_lookup_port(dp, port_no);
    if (!port) {
        errno = ENOENT;
        goto out;
    }
    answer_port_query(port, port_);

out:
    ovs_mutex_unlock(&dp->port_mutex);
    return error;
}

static int
dpif_bpf_port_query_by_name(const struct dpif *dpif_, const char *devname,
                            struct dpif_port *dpif_port)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);
    struct dpif_bpf_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

struct dpif_bpf_port_state {
    struct hmap_position position;
    char *name;
};

static int
dpif_bpf_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dpif_bpf_port_state));
    return 0;
}

static int
dpif_bpf_port_dump_next(const struct dpif *dpif_, void *state_,
                        struct dpif_port *dpif_port)
{
    struct dpif_bpf_port_state *state = state_;
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);
    struct hmap_node *node;
    int retval;

    ovs_mutex_lock(&dp->port_mutex);
    node = hmap_at_position(&dp->ports_by_odp, &state->position);
    if (node) {
        struct dpif_bpf_port *port;

        port = CONTAINER_OF(node, struct dpif_bpf_port, odp_node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return retval;
}

static int
dpif_bpf_port_dump_done(const struct dpif *dpif OVS_UNUSED,
                        void *state_)
{
    struct dpif_bpf_port_state *state = state_;

    free(state->name);
    free(state);
    return 0;
}

static int
dpif_bpf_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);
    uint64_t new_port_seq;

    new_port_seq = seq_read(dp->port_seq);
    if (dp->last_seq != new_port_seq) {
        dp->last_seq = new_port_seq;
        return ENOBUFS;
    }

    return EAGAIN;
}

static void
dpif_bpf_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);

    seq_wait(dp->port_seq, dp->last_seq);
}

static int
dpif_bpf_flow_flush(struct dpif *dpif OVS_UNUSED)
{
    struct bpf_flow_key key;
    int err = 0;

    /* Flow Entry Table */
    memset(&key, 0, sizeof key);
    do {
        err = bpf_map_get_next_key(datapath.bpf.flow_table.fd, &key, &key);
        if (!err) {
            bpf_map_delete_elem(datapath.bpf.flow_table.fd, &key);
        }
    } while (!err);

    /* Flow Stats Table */
    memset(&key, 0, sizeof key);
    do {
        err = bpf_map_get_next_key(datapath.bpf.dp_flow_stats.fd, &key, &key);
        if (!err) {
            bpf_map_delete_elem(datapath.bpf.dp_flow_stats.fd, &key);
        }
    } while (!err);


    return errno == ENOENT ? 0 : errno;
}

struct dpif_bpf_flow_dump {
    struct dpif_flow_dump up;
    int status;
    struct bpf_flow_key pos;
    struct ovs_mutex mutex;
};

static struct dpif_bpf_flow_dump *
dpif_bpf_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_bpf_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_bpf_flow_dump_create(const struct dpif *dpif_, bool terse,
                          char *type OVS_UNUSED)
{
    struct dpif_bpf_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    dump->up.terse = terse;
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_bpf_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_bpf_flow_dump *dump = dpif_bpf_flow_dump_cast(dump_);
    int status = dump->status;

    ovs_mutex_destroy(&dump->mutex);
    free(dump);

    return status == ENOENT ? 0 : status;
}

struct dpif_bpf_flow_buf {
    uint32_t buf[DIV_ROUND_UP(FLOW_DUMP_BUF_SIZE, 4)];
};

struct dpif_bpf_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_bpf_flow_dump *dump;

    /* (Key/Mask/Actions) Buffers for netdev dumping */
    struct dpif_bpf_flow_buf buf[FLOW_DUMP_MAX_BATCH];
};

static struct dpif_bpf_flow_dump_thread *
dpif_bpf_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_bpf_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_bpf_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_bpf_flow_dump *dump = dpif_bpf_flow_dump_cast(dump_);
    struct dpif_bpf_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_bpf_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_bpf_flow_dump_thread *thread =
        dpif_bpf_flow_dump_thread_cast(thread_);
    free(thread);
}

static int
fetch_flow(struct dpif_bpf_dp *dp, struct dpif_flow *flow,
           struct ofpbuf *out, const struct bpf_flow_key *key)
{
    struct flow f;
    struct odp_flow_key_parms parms = {
        .flow = &f,
    };
    struct bpf_action_batch action;
    struct bpf_flow_stats stats;
    int err;

    memset(flow, 0, sizeof *flow);

    err = bpf_map_lookup_elem(datapath.bpf.flow_table.fd, key, &action);
    if (err) {
        return errno;
    }

    /* XXX: Extract 'dp_flow' into 'flow'. */
    if (bpf_flow_key_to_flow(key, &f) == ODP_FIT_ERROR) {
        VLOG_WARN("%s: bpf flow key parsing error", __func__);
        return EINVAL;
    }
    f.in_port.odp_port = ifindex_to_odp(dp,
                                        odp_to_u32(f.in_port.odp_port));

    /* Translate BPF flow into netlink format. */
    ofpbuf_clear(out);

    /* Use 'out->header' to point to the flow key, 'out->msg' for actions */
    out->header = out->data;
    odp_flow_key_from_flow(&parms, out);
    out->msg = ofpbuf_tail(out);
    err = bpf_actions_to_odp_actions(&action, out);
    if (err) {
        VLOG_ERR("%s: bpf_actions to odp actions fails", __func__);
        return err;
    }

    flow->key = out->header;
    flow->key_len = ofpbuf_headersize(out);
    flow->actions = out->msg;
    flow->actions_len = ofpbuf_msgsize(out);

    dpif_flow_hash(dp->dpif, flow->key, flow->key_len, &flow->ufid);
    flow->ufid_present = false; /* XXX */

    /* Fetch datapath flow stats */
    err = bpf_map_lookup_elem(datapath.bpf.dp_flow_stats.fd, key, &stats);
    if (err) {
        VLOG_DBG("flow stats lookup fails, fd %d err = %d %s",
                 datapath.bpf.dp_flow_stats.fd, err, ovs_strerror(errno));
        return errno;
    } else {
        VLOG_DBG("flow stats lookup OK");
        memcpy(&flow->stats, &stats, 3 * sizeof(uint64_t));
    }

    return 0;
}

static int
dpif_bpf_insert_flow(struct bpf_flow_key *flow_key,
                     struct bpf_action_batch *actions)
{
    int err;

    VLOG_DBG("Insert bof_flow_key:");
    vlog_hex_dump((unsigned char *)flow_key, sizeof *flow_key);

    VLOG_DBG("Insert action:");
    vlog_hex_dump((unsigned char *)actions, sizeof actions[0]);

    ovs_assert(datapath.bpf.flow_table.fd != -1);
    err = bpf_map_update_elem(datapath.bpf.flow_table.fd,
                              flow_key,
                              actions, BPF_ANY);
    if (err) {
        VLOG_ERR("Failed to add flow into flow table, map fd %d, error %s",
                 datapath.bpf.flow_table.fd, ovs_strerror(errno));
        return errno;
    }

    return 0;
}

static int
dpif_bpf_delete_flow(struct bpf_flow_key *flow_key,
                     struct dpif_flow_stats *stats)
{
    int err;
    struct bpf_action_batch actions;

    ovs_assert(datapath.bpf.flow_table.fd != -1);

    err = bpf_map_lookup_elem(datapath.bpf.flow_table.fd, flow_key, &actions);
    if (err != 0) {
        VLOG_ERR("Failed to find flow into flow table, map fd %d: %s",
                 datapath.bpf.flow_table.fd, ovs_strerror(errno));
        VLOG_WARN("bpf_flow_key not found\n");
        vlog_hex_dump((unsigned char *)flow_key, sizeof *flow_key);

        goto delete_stats;
    }

    err = bpf_map_delete_elem(datapath.bpf.flow_table.fd, flow_key);
    if (err) {
        VLOG_ERR("Failed to del flow into flow table, map fd %d: %s",
                 datapath.bpf.flow_table.fd, ovs_strerror(errno));
        return errno;
    }

    if (stats) {
        /* XXX: Stats */
        memset(stats, 0, sizeof *stats);

delete_stats:
        err = bpf_map_delete_elem(datapath.bpf.dp_flow_stats.fd, flow_key);
        if (err) {
            VLOG_ERR("Failed to del flow into flow stat table, map fd %d: %s",
                      datapath.bpf.flow_table.fd, ovs_strerror(errno));
            /* Skip when element is not found */
            return 0;
        }
    }
    return 0;
}

static int
dpif_bpf_delete_all_flow(void)
{
    int err;
    struct bpf_flow_key key;

    do {
        err = bpf_map_get_next_key(datapath.bpf.flow_table.fd, NULL, &key);
        if (err) {
            return err;
        }

        err = bpf_map_delete_elem(datapath.bpf.flow_table.fd, &key);
    } while (!err);

    return err;
}

static int
dpif_bpf_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                        struct dpif_flow *flows, int max_flows)
{
    struct dpif_bpf_flow_dump_thread *thread =
        dpif_bpf_flow_dump_thread_cast(thread_);
    struct dpif_bpf_flow_dump *dump = thread->dump;
    int n = 0;
    int err;

    ovs_mutex_lock(&dump->mutex);
    err = dump->status;
    if (err) {
        goto unlock;
    }

    while (n <= max_flows) {
        struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dump->up.dpif);
        struct dpif_bpf_flow_buf *buf = &thread->buf[n];
        struct ofpbuf flow_buf;

        ofpbuf_use_stack(&flow_buf, buf, sizeof *buf);

        err = bpf_map_get_next_key(datapath.bpf.flow_table.fd,
                                   &dump->pos, &dump->pos);
        if (err) {
            err = errno;
            break;
        }
        err = fetch_flow(dp, &flows[n], &flow_buf, &dump->pos);
        if (err == ENOENT) {
            /* Flow disappeared. Oh well, we tried. */
            continue;
        } else if (err) {
            break;
        }
        n++;
    }
    dump->status = err;
unlock:
    ovs_mutex_unlock(&dump->mutex);
    return n;
}

struct dpif_bpf_downcall_parms {
    uint32_t type;
    odp_port_t port_no;
    struct bpf_action_batch *action_batch;
};

static int
dpif_bpf_downcall(struct dpif *dpif_, struct dp_packet *packet,
                  const struct flow *flow,
                  struct dpif_bpf_downcall_parms *parms)
{
    struct dp_packet_batch batch;
    struct bpf_downcall md = {
        .type = parms->type,
        .debug = 0xC0FFEEEE,
    };
    uint32_t ifindex;
    uint32_t flags;
    int error;
    int queue = 0;
    struct dp_packet *clone_pkt;

    ovs_assert(datapath.bpf.execute_actions.fd != -1);
    ovs_assert(datapath.bpf.downcall_metadata.fd != -1);

    bpf_metadata_from_flow(flow, &md.md);

    ifindex = odp_port_to_ifindex(get_dpif_bpf_dp(dpif_),
                                  flow->in_port.odp_port, &flags);
#if 0
    /* this is ok at check_support time */
    if (!ifindex) {
        VLOG_WARN("%s: in_port.odp_port %d found",
                 __func__, flow->in_port.odp_port);
        return ENODEV;
    }
#endif

    md.md.md.in_port = ifindex;
    md.ifindex = ifindex;

    if (parms->action_batch) {
        int zero_index = 0;
        error = bpf_map_update_elem(datapath.bpf.execute_actions.fd,
                                    &zero_index, parms->action_batch, 0);
        if (error) {
            VLOG_ERR("%s: map update failed", __func__);
            return error;
        }
    }

    /* XXX: Check that ovs-system device MTU is large enough to include md. */
    int zero_index = 0;
    error = bpf_map_update_elem(datapath.bpf.downcall_metadata.fd,
                                &zero_index, &md, 0);
    if (error) {
        VLOG_ERR("%s: map update failed", __func__);
        return error;
    }

    clone_pkt = dp_packet_clone(packet);
    dp_packet_batch_init_packet(&batch, clone_pkt);

    VLOG_INFO("send downcall (%d)", parms->type);
    error = netdev_send(datapath.outport, queue, &batch, false);
    dp_packet_set_size(packet, dp_packet_size(packet) - sizeof md);

    return error;
}

static int OVS_UNUSED
dpif_bpf_output(struct dpif *dpif_, struct dp_packet *packet,
                const struct flow *flow, odp_port_t port_no,
                uint32_t flags OVS_UNUSED)
{
    struct dpif_bpf_downcall_parms parms = {
        .port_no = port_no,
        .type = OVS_BPF_DOWNCALL_OUTPUT,
        .action_batch = NULL
    };
    return dpif_bpf_downcall(dpif_, packet, flow, &parms);
}

static int
dpif_bpf_execute_(struct dpif *dpif_, struct dp_packet *packet,
                  const struct flow *flow,
                  struct bpf_action_batch *action_batch)
{
    struct dpif_bpf_downcall_parms parms = {
        .type = OVS_BPF_DOWNCALL_EXECUTE,
        .action_batch = action_batch,
    };
    return dpif_bpf_downcall(dpif_, packet, flow, &parms);
}

static int
dpif_bpf_serialize_actions(struct dpif_bpf_dp *dp,
                           struct bpf_action_batch *action_batch,
                           const struct nlattr *nlactions,
                           size_t actions_len)
{

    const struct nlattr *a;
    unsigned int left, count = 0, skipped = 0;
    struct bpf_action *actions;

    memset(action_batch, 0, sizeof(*action_batch));
    actions = action_batch->actions;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, nlactions, actions_len) {
        enum ovs_action_attr type = nl_attr_type(a);
        actions[count].type = type;

        if (type == OVS_ACTION_ATTR_OUTPUT) {
            struct dpif_bpf_port *port;
            odp_port_t port_no = nl_attr_get_odp_port(a);

            ovs_mutex_lock(&dp->port_mutex);
            port = bpf_lookup_port(dp, port_no);
            if (port) {
                VLOG_INFO("output action to port %d ifindex %d", port_no,
                          port->ifindex);
                actions[count].u.out.port = port->ifindex;
                actions[count].u.out.flags = get_port_flags(port->netdev);
            }
            ovs_mutex_unlock(&dp->port_mutex);
        } else {
            if (odp_action_to_bpf_action(a, &actions[count])) {
                skipped++;
            }
        }
        count++;
    }

    VLOG_INFO("Processing flow actions (%d/%d skipped)", skipped, count);
    if (skipped) {
        /* XXX: VLOG actions that couldn't be processed */
    }
    return 0;
}

static int
dpif_bpf_execute(struct dpif *dpif_, struct dpif_execute *execute)
{
    struct bpf_action_batch batch;
    int error = 0;

    error = dpif_bpf_serialize_actions(get_dpif_bpf_dp(dpif_), &batch, execute->actions,
                                       execute->actions_len);
    if (error) {
        return error;
    }

    error = dpif_bpf_execute_(dpif_, execute->packet,
                              execute->flow, &batch);
    return error;
}

/* Translates 'port' into an ifindex and sets it inside 'key'.
 *
 * Returns 0 on success, or a positive errno otherwise. */
static int
set_in_port(struct dpif_bpf_dp *dp, struct bpf_flow_key *key, odp_port_t port)
{
    uint16_t ifindex;

    ifindex = odp_port_to_ifindex(dp, port, NULL);
    if (!ifindex && port) {
        VLOG_WARN("Could not find ifindex corresponding to port %"PRIu32,
                  port);
        return ENODEV;
    }

    key->mds.md.in_port = ifindex;
    return 0;
}

/* Converts 'key' (of size 'key_len') into a bpf flow key in 'key_out', and
 * optionally 'actions' (of size 'actions_len') into 'batch'. 'mask' (of size
 * 'mask_len') may optionally be used for logging, of which the verbosity is
 * controlled by 'verbose'.
 *
 * Returns 0 on success, or a positive errno otherwise.
 */
static int
prepare_bpf_flow__(struct dpif_bpf_dp *dp,
                   const struct nlattr *key, size_t key_len,
                   const struct nlattr *mask, size_t mask_len,
                   const struct nlattr *actions, size_t actions_len,
                   struct bpf_flow_key *key_out, struct bpf_action_batch *batch,
                   bool verbose)
{
    odp_port_t in_port;
    int err = EINVAL;

    if (1) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        /* XXX: Use dpif_format_flow()? */
        odp_flow_format(key, key_len, mask, mask_len, NULL, &ds, true);
        ds_put_cstr(&ds, ", actions=");
        format_odp_actions(&ds, actions, actions_len, NULL);
        VLOG_WARN("Translating odp key to bpf key:\n%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    memset(key_out, 0, sizeof *key_out);
    if (odp_key_to_bpf_flow_key(key, key_len, key_out,
                                &in_port, false, verbose)) {
        if (verbose) {
            struct ds ds = DS_EMPTY_INITIALIZER;

            /* XXX: Use dpif_format_flow()? */
            odp_flow_format(key, key_len, mask, mask_len, NULL, &ds,
                            true);
            VLOG_WARN("Failed to translate odp key to bpf key:\n%s",
                      ds_cstr(&ds));
            ds_destroy(&ds);
        }
        return err;
    }

    err = set_in_port(dp, key_out, in_port);
    if (err) {
        return err;
    }
    if (batch) {
        err = dpif_bpf_serialize_actions(dp, batch, actions, actions_len);
        if (err) {
            return err;
        }
    }

    /* Transfer back to flow to check if everything is good */
    if (1) {
        struct flow flow;
        enum odp_key_fitness res;

        res = bpf_flow_key_to_flow(key_out, &flow);
        if (res != ODP_FIT_PERFECT) {
            VLOG_ERR("transfer bpf key back to flow failed");
        } else {
            struct ds ds = DS_EMPTY_INITIALIZER;

            flow_format(&ds, &flow, NULL);
            ds_put_cstr(&ds, ", actions=");
            format_odp_actions(&ds, actions, actions_len, NULL);
            VLOG_WARN("Translating back:\n%s", ds_cstr(&ds));
            ds_destroy(&ds);
        }
    }

    return 0;
}

static int
prepare_bpf_flow(struct dpif_bpf_dp *dp, const struct nlattr *key,
                 size_t key_len, struct bpf_flow_key *key_out, bool verbose)
{
    return prepare_bpf_flow__(dp, key, key_len, NULL, 0, NULL, 0, key_out,
                              NULL, verbose);
}

static void
dpif_bpf_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops)
{
    struct dpif_bpf_dp *dp = get_dpif_bpf_dp(dpif_);

    for (int i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];
        struct dpif_flow_del *del OVS_UNUSED;
        struct dpif_flow_get *get OVS_UNUSED;

        switch (op->type) {
        case DPIF_OP_EXECUTE:
            op->error = dpif_bpf_execute(dpif_, &op->u.execute);
            break;
        case DPIF_OP_FLOW_PUT: {
            struct dpif_flow_put *put = &op->u.flow_put;
            bool verbose = !(put->flags & DPIF_FP_PROBE);
            struct bpf_action_batch action_batch;
            struct bpf_flow_key key;
            int err;

            err = prepare_bpf_flow__(dp, put->key, put->key_len,
                                     put->mask, put->mask_len,
                                     put->actions, put->actions_len,
                                     &key, &action_batch, verbose);
            if (!err) {
                err = dpif_bpf_insert_flow(&key, &action_batch);
            }
            op->error = err;
            break;
        }
        case DPIF_OP_FLOW_GET: {
            struct dpif_flow_get *get = &op->u.flow_get;
            struct bpf_flow_key key;
            int err;

            err = prepare_bpf_flow(dp, get->key, get->key_len, &key, true);
            if (!err) {
                err = fetch_flow(dp, get->flow, get->buffer, &key);
            }
            op->error = err;
            break;
        }
        case DPIF_OP_FLOW_DEL: {
            struct dpif_flow_del *del = &op->u.flow_del;
            struct bpf_flow_key key;
            int err;

            err = prepare_bpf_flow(dp, del->key, del->key_len, &key, true);
            if (!err) {
                err = dpif_bpf_delete_flow(&key, del->stats);
            }
            op->error = err;
            break;
        }
        default:
            OVS_NOT_REACHED();
        }
    }
}

static int
dpif_bpf_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_bpf_dp *dpif = get_dpif_bpf_dp(dpif_);
    int stored_error = 0;

    for (int i = 0; i < dpif->n_channels; i++) {
        int error = perf_channel_set(&dpif->channels[i], enable);
        if (error) {
            VLOG_ERR("failed to set recv_set %s (%s)",
                     enable ? "true": "false", ovs_strerror(error));
            stored_error = error;
        }
    }

    return stored_error;
}

static int
dpif_bpf_handlers_set__(struct dpif_bpf_dp *dp, uint32_t n_handlers)
    OVS_REQUIRES(&dp->upcall_lock)
{
    struct bpf_handler prev;
    int i, extra;

    memset(&prev, 0, sizeof prev);
    if (dp->n_handlers) {
        free(dp->handlers);
        dp->handlers = NULL;
        dp->n_handlers = 0;
    }

    if (!n_handlers) {
        return 0;
    }

    dp->handlers = xzalloc(sizeof *dp->handlers * n_handlers);
    for (i = 0; i < n_handlers; i++) {
        struct bpf_handler *curr = dp->handlers + i;

        if (i > dp->n_channels) {
            VLOG_INFO("Ignoring extraneous handlers (%d for %d channels)",
                      n_handlers, dp->n_channels);
            break;
        }

        curr->offset = prev.offset + prev.count;
        curr->count = dp->n_channels / n_handlers;
        prev = *curr;
    }
    extra = dp->n_channels % n_handlers;
    if (extra) {
        VLOG_INFO("Extra %d channels; distributing across handlers", extra);
        for (i = 0; i < extra; i++) {
            struct bpf_handler *curr = dp->handlers + n_handlers - i - 1;

            curr->offset = curr->offset + extra - i - 1;
            curr->count++;
        }
    }

    dp->n_handlers = n_handlers;
    return 0;
}

static int
dpif_bpf_handlers_set(struct dpif *dpif_, uint32_t n_handlers)
{
    struct dpif_bpf_dp *dpif = get_dpif_bpf_dp(dpif_);
    int error;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    error = dpif_bpf_handlers_set__(dpif, n_handlers);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

/* XXX: duplicate with check_support */
static struct odp_support dp_bpf_support = {
    .max_vlan_headers = 2,
    .max_mpls_depth = 2,
    .recirc = true,
    .ct_state = true,
    .ct_zone = true,
    .ct_mark = true,
    .ct_label = true,
    .ct_state_nat = true,
    .ct_orig_tuple = true,
    .ct_orig_tuple6 = true,
};

static int
extract_key(struct dpif_bpf_dp *dpif, const struct bpf_flow_key *key,
            struct dp_packet *packet, struct ofpbuf *buf)
{
    struct flow flow;
    struct odp_flow_key_parms parms = {
        .flow = &flow,
        .mask = NULL,
        .support = dp_bpf_support, /* used at odp_flow_key_from_flow */
    };

    {
        struct ds ds = DS_EMPTY_INITIALIZER;

        bpf_flow_key_format(&ds, key);
        VLOG_INFO("bpf_flow_key_format\n%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    /* This function goes first because it zeros out flow. */
    flow_extract(packet, &flow);

    bpf_flow_key_extract_metadata(key, &flow);

    VLOG_INFO("packet.md.port = %d", packet->md.in_port.odp_port);

    if (flow.in_port.odp_port != 0) {
        flow.in_port.odp_port = ifindex_to_odp(dpif,
                                    odp_to_u32(flow.in_port.odp_port));
    } else {
        flow.in_port.odp_port = packet->md.in_port.odp_port;
    }
    VLOG_INFO("flow.in_port.odp_port %d", flow.in_port.odp_port);

    if (1) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        flow_format(&ds, &flow, NULL);
        VLOG_WARN("Upcall flow:\n%s",
                  ds_cstr(&ds));
        ds_destroy(&ds);

    }

    odp_flow_key_from_flow(&parms, buf);

    return 0;
}

struct ovs_ebpf_event {
    struct perf_event_raw sample;
    struct bpf_upcall header;
    uint8_t data[];
};

static void OVS_UNUSED
dpif_bpf_flow_dump_all(struct dpif_bpf_dp *dp OVS_UNUSED)
{
    struct dpif_bpf_flow_dump dump;
    int err;

    memset(&dump, 0, sizeof dump);
    while (1) {
        err = bpf_map_get_next_key(datapath.bpf.flow_table.fd,
                                   &dump.pos, &dump.pos);
        if (err) {
            VLOG_INFO("err is %d", err);
            break;
        }
        vlog_hex_dump((unsigned char *)&dump.pos, sizeof dump.pos);
    }
}

/* perf_channel_read() fills the first part of 'buffer' with the full event.
 * Here, the key will be extracted immediately following it, and 'upcall'
 * will be initialized to point within 'buffer'.
 */
static int
perf_sample_to_upcall__(struct dpif_bpf_dp *dp, struct ovs_ebpf_event *e,
                        struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    size_t sample_len = e->sample.size - sizeof e->header;
    size_t pkt_len = e->header.skb_len;
    size_t pre_key_len;
    odp_port_t port_no;
    int err;

    if (pkt_len < ETH_HEADER_LEN) {
        VLOG_WARN_RL(&rl, "Unexpectedly short packet (%"PRIuSIZE")", pkt_len);
        return EINVAL;
    }
    if (e->sample.size - sizeof e->header < pkt_len) {
        VLOG_WARN_RL(&rl,
            "Packet longer than sample (pkt=%"PRIuSIZE", sample=%"PRIuSIZE")",
            pkt_len, sample_len);
        return EINVAL;
    }

    port_no = ifindex_to_odp(dp, e->header.ifindex);
    VLOG_INFO("ifindex %d odp %d", e->header.ifindex, port_no);
    if (port_no == ODPP_NONE) {
        VLOG_WARN_RL(&rl, "failed to map upcall ifindex=%d to odp",
                     e->header.ifindex);
        return EINVAL;
    }

    memset(upcall, 0, sizeof *upcall);

    /* Use buffer->header to point to the packet, and buffer->msg to point to
     * the extracted flow key. Therefore, when extract_key() reallocates
     * 'buffer', we can easily get pointers back to the packet and start of
     * extracted key. */
    buffer->header = e->data;
    buffer->msg = ofpbuf_tail(buffer);
    pre_key_len = buffer->size;

    VLOG_INFO("upcall key hex\n");
    vlog_hex_dump((unsigned char *)&e->header.key, sizeof e->header.key);
    //VLOG_INFO("list of bpf keys\n");
    //dpif_bpf_flow_dump_all(dp);
    VLOG_INFO("raw packet data in e->data");
    vlog_hex_dump(e->data, MIN(pkt_len, 100));

    dp_packet_use_stub(&upcall->packet, e->data, pkt_len);
    dp_packet_set_size(&upcall->packet, pkt_len);
    pkt_metadata_init(&upcall->packet.md, port_no);

    err = extract_key(dp, &e->header.key, &upcall->packet, buffer);
    if (err) {
        return err;
    }

    upcall->key = buffer->msg;
    upcall->key_len = buffer->size - pre_key_len;
    dpif_flow_hash(dp->dpif, upcall->key, upcall->key_len, &upcall->ufid);

    return 0;
}

/* perf_channel_read() fills the first part of 'buffer' with the full event.
 * Here, the key will be extracted immediately following it, and 'upcall'
 * will be initialized to point within 'buffer'.
 */
static int
perf_sample_to_upcall_miss(struct dpif_bpf_dp *dp, struct ovs_ebpf_event *e,
                           struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    int err;

    err = perf_sample_to_upcall__(dp, e, upcall, buffer);
    if (err) {
        return err;
    }

    ofpbuf_prealloc_tailroom(buffer, sizeof(struct bpf_downcall));
    upcall->type = DPIF_UC_MISS;

    return 0;
}

/* Modified from perf_sample_to_upcall.
 */
static int
perf_sample_to_upcall_userspace(struct dpif_bpf_dp *dp, struct ovs_ebpf_event *e,
                                struct dpif_upcall *upcall,
                                struct ofpbuf *buffer)
{
    const struct nlattr *actions = (struct nlattr *)e->header.uactions;
    const struct nlattr *a;
    unsigned int left;
    int err;

    err = perf_sample_to_upcall__(dp, e, upcall, buffer);
    if (err) {
        return err;
    }

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, e->header.uactions_len) {
        switch (nl_attr_type(a)) {
        case OVS_USERSPACE_ATTR_PID:
            //nl_attr_get_u32(a);
            break;
        case OVS_USERSPACE_ATTR_USERDATA:
            upcall->userdata = CONST_CAST(struct nlattr *, a);
            break;
        default:
            VLOG_INFO("%s unsupported userspace action. %d",
                      __func__, nl_attr_type(a));
            return EOPNOTSUPP;
        }
    }

    upcall->type = DPIF_UC_ACTION;
    return 0;
}

static void
bpf_debug_print(int subtype, int error)
{
    int level = error ? VLL_WARN : VLL_DBG;
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (subtype >= 0 && subtype < ARRAY_SIZE(bpf_upcall_subtypes)) {
        ds_put_cstr(&ds, bpf_upcall_subtypes[subtype]);
    } else {
        ds_put_format(&ds, "Unknown subtype %d", subtype);
    }
    ds_put_format(&ds, " reports: %s", ovs_strerror(error));

    VLOG_RL(&rl, level, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static int
recv_perf_sample(struct dpif_bpf_dp *dpif, struct ovs_ebpf_event *e,
                 struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    if (e->sample.header.size < sizeof *e
        || e->sample.size < sizeof e->header) {
        VLOG_WARN_RL(&rl, "Unexpectedly short sample (%"PRIu32")",
                     e->sample.size);
        return EINVAL;
    }

    VLOG_INFO("\nreceived upcall %d", e->header.type);

    switch (e->header.type) {
    case OVS_UPCALL_MISS:
        return perf_sample_to_upcall_miss(dpif, e, upcall, buffer);
        break;
    case OVS_UPCALL_DEBUG:
        bpf_debug_print(e->header.subtype, e->header.error);
        return EAGAIN;
    case OVS_UPCALL_ACTION:
        return perf_sample_to_upcall_userspace(dpif, e, upcall, buffer);
        break;
    default:
        break;
    }

    VLOG_WARN_RL(&rl, "Unfamiliar upcall type %d", e->header.type);
    return EINVAL;
}

static int
dpif_bpf_recv(struct dpif *dpif_, uint32_t handler_id,
              struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    struct dpif_bpf_dp *dpif = get_dpif_bpf_dp(dpif_);
    struct bpf_handler *handler;
    int error = EAGAIN;
    int i;

    fat_rwlock_rdlock(&dpif->upcall_lock);
    handler = dpif->handlers + handler_id;
    for (i = 0; i < handler->count; i++) {
        int channel_idx = (handler->index + i) % handler->count;
        struct perf_channel *channel;

        channel = &dpif->channels[handler->offset + channel_idx];
        error = perf_channel_read(channel, buffer);
        if (!error) {
            error = recv_perf_sample(dpif, buffer->header, upcall, buffer);
        }
        if (error != EAGAIN) {
            break;
        }
    }
    handler->index = (handler->index + 1) % handler->count;
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static char *
dpif_bpf_get_datapath_version(void)
{
    return xstrdup("<built-in>");
}

static void
dpif_bpf_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_bpf_dp *dpif = get_dpif_bpf_dp(dpif_);
    struct bpf_handler *handler;
    int i;

    fat_rwlock_rdlock(&dpif->upcall_lock);
    handler = dpif->handlers + handler_id;
    for (i = 0; i < handler->count; i++) {
        poll_fd_wait(dpif->channels[handler->offset + i].fd, POLLIN);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);
}

static void
dpif_bpf_recv_purge(struct dpif *dpif_)
{
    struct dpif_bpf_dp *dpif = get_dpif_bpf_dp(dpif_);
    int i;

    fat_rwlock_rdlock(&dpif->upcall_lock);
    for (i = 0; i < dpif->n_channels; i++) {
        struct perf_channel *channel = &dpif->channels[i];

        perf_channel_flush(channel);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);
}

const struct dpif_class dpif_bpf_class = {
    "bpf",
    dpif_bpf_init,
    dpif_bpf_enumerate,
    dpif_bpf_port_open_type,
    dpif_bpf_open,
    dpif_bpf_close,
    dpif_bpf_destroy,
    NULL,                       /* run */
    NULL,                       /* wait */
    dpif_bpf_get_stats,
    dpif_bpf_port_add,
    dpif_bpf_port_del,
    NULL,                       /* port_set_config */
    dpif_bpf_port_query_by_number,
    dpif_bpf_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_bpf_port_dump_start,
    dpif_bpf_port_dump_next,
    dpif_bpf_port_dump_done,
    dpif_bpf_port_poll,
    dpif_bpf_port_poll_wait,
    dpif_bpf_flow_flush,
    dpif_bpf_flow_dump_create,
    dpif_bpf_flow_dump_destroy,
    dpif_bpf_flow_dump_thread_create,
    dpif_bpf_flow_dump_thread_destroy,
    dpif_bpf_flow_dump_next,
    dpif_bpf_operate,
    dpif_bpf_recv_set,
    dpif_bpf_handlers_set,
    NULL,                       /* set_config */
    NULL,                       /* queue_to_priority */
    dpif_bpf_recv,
    dpif_bpf_recv_wait,
    dpif_bpf_recv_purge,
    NULL,                       /* register_dp_purge_cb */
    NULL,                       /* register_upcall_cb */
    NULL,                       /* enable_upcall */
    NULL,                       /* disable_upcall */
    dpif_bpf_get_datapath_version,
    NULL,                       /* ct_dump_start */
    NULL,                       /* ct_dump_next */
    NULL,                       /* ct_dump_done */
    NULL,                       /* ct_flush */
    NULL,                       /* ct_set_maxconns */
    NULL,                       /* ct_get_maxconns */
    NULL,                       /* ct_get_nconns */
    NULL,                       /* meter_get_features */
    NULL,                       /* meter_set */
    NULL,                       /* meter_get */
    NULL,                       /* meter_del */
};
