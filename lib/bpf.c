/*
 * Copyright (c) 2016 Nicira, Inc.
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
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <iproute2/bpf_elf.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/resource.h>

#include "bpf.h"
#include "bpf/odp-bpf.h"
#include "util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"

#define BPF_FS_PATH "/sys/fs/bpf/ovs/"
static const char *ovs_bpf_path = BPF_FS_PATH;

#define MAX_BPF_PROG_ARRAY 64 //FIXME
VLOG_DEFINE_THIS_MODULE(bpf);

static void
bpf_format_prog(struct ds *ds, const struct bpf_prog *prog)
{
    ds_put_format(ds, "    %s:\n", prog->name);
    ds_put_format(ds, "        handle: %08"PRIx32"\n", prog->handle);
}

typedef void map_element_writer_t(struct ds *, uint64_t, void *);

static void
format_dp_stats(struct ds *ds, uint64_t key, void *value_)
{
    uint64_t value = *(uint64_t *)value_;

    switch (key) {
    case OVS_DP_STATS_UNSPEC:
        while (ds_chomp(ds, ' ')) {
            /* nom nom nom */
        }
        break;
    case OVS_DP_STATS_HIT:
        ds_put_cstr(ds, "hit");
        break;
    case OVS_DP_STATS_MISSED:
        ds_put_cstr(ds, "missed");
        break;
    case OVS_DP_STATS_LOST:
        ds_put_cstr(ds, "lost");
        break;
    case OVS_DP_STATS_FLOWS:
        ds_put_cstr(ds, "flows");
        break;
    case OVS_DP_STATS_MASK_HIT:
        ds_put_cstr(ds, "masks_hit");
        break;
    case OVS_DP_STATS_MASKS:
        ds_put_cstr(ds, "masks");
        break;
    case OVS_DP_STATS_ERRORS:
        ds_put_cstr(ds, "errors");
        break;
    default:
        ds_put_format(ds, "unknown-%"PRIu64, key);
        break;
    }
    if (key) {
        ds_put_format(ds, ": %"PRIu64"\n", value);
    }
}

static void
format_upcalls(struct ds *ds, uint64_t key, void *value OVS_UNUSED)
{
    ds_put_format(ds, "cpu-%"PRIu64"\n", key);
}

static void
format_tailcalls(struct ds *ds, uint64_t key, void *value_)
{
    uint32_t value = *(uint32_t *)value_;
    ds_put_format(ds, "index-%"PRIu64"prog_fd-%d\n", key, value);
}

static int
lookup_elem(int fd, void *key, size_t key_len, void *value)
{
    int err = bpf_map_lookup_elem(fd, (uint64_t *)key, (uint64_t *)value);
    if (err) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_cstr(&ds, "error occurred looking up elem ");
        ds_put_hex(&ds, key, key_len);
        ds_put_format(&ds, ": %s", ovs_strerror(errno));
        VLOG_DBG("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    return err;
}

#define MAP_FORMAT_FUNC(NAME, KTYPE, VTYPE, PRINT_COUNT)                \
    static void NAME(struct ds *ds, const struct bpf_map *map,          \
                     map_element_writer_t fmt)                          \
    {                                                                   \
        KTYPE key = 0;                                                  \
        VTYPE value;                                                    \
        int count = 0;                                                  \
                                                                        \
        VLOG_DBG("reading map %s", map->name);                          \
        ds_put_format(ds, "    %s:\n", map->name);                      \
        if (!lookup_elem(map->fd, &key, sizeof key, &value)) {          \
            count++;                                                    \
            if (fmt) {                                                  \
                ds_put_cstr(ds, "        ");                            \
                fmt(ds, key, &value);                                   \
            }                                                           \
        }                                                               \
        while (!bpf_map_get_next_key(map->fd, &key, &key)) {            \
            count++;                                                    \
            if (fmt) {                                                  \
                if (!lookup_elem(map->fd, &key, sizeof key, &value)) {  \
                    ds_put_cstr(ds, "        ");                        \
                    fmt(ds, key, &value);                               \
                }                                                       \
            }                                                           \
        };                                                              \
        if (PRINT_COUNT) {                                              \
            ds_put_format(ds, "        count: %d\n", count);            \
        }                                                               \
    }

MAP_FORMAT_FUNC(bpf_format_map_stats, uint64_t, uint64_t, false);
MAP_FORMAT_FUNC(bpf_format_map_flows, uint64_t, struct bpf_flow, true);
MAP_FORMAT_FUNC(bpf_format_map_upcalls, uint32_t, uint32_t, true);
MAP_FORMAT_FUNC(bpf_format_map_tailcalls, uint32_t, uint32_t, true);//FIXME
//MAP_FORMAT_FUNC(bpf_format_map_dp_flow_stats,

void
bpf_format_state(struct ds *ds, struct bpf_state *state)
{
    ds_put_format(ds, "path: %s\n", ovs_bpf_path);
    ds_put_cstr(ds, "maps:\n");
    bpf_format_map_stats(ds, &state->datapath_stats, format_dp_stats);
    bpf_format_map_flows(ds, &state->flow_table, NULL);
    bpf_format_map_upcalls(ds, &state->upcalls, format_upcalls);
    bpf_format_map_tailcalls(ds, &state->tailcalls, format_tailcalls);
    //bpf_format_map_dp_flow_stats(ds, &state->dp_flow_stats, NULL);
    ds_put_cstr(ds, "programs:\n");
    bpf_format_prog(ds, &state->downcall);
    bpf_format_prog(ds, &state->egress);
    bpf_format_prog(ds, &state->ingress);
    bpf_format_prog(ds, &state->xdp);
    //bpf_format_prog(ds, &state->afxdp);
}

/* Populates 'state' with the standard set of programs and maps for openvswitch
 * datapath as sourced from pinned programs at ovs_bpf_path.
 *
 * Returns 0 on success, or positive errno on error. If successful, the caller
 * is resposible for releasing the resources in 'state' via bpf_put().
 */
int
bpf_get(struct bpf_state *state, bool verbose)
{
    const struct {
        int *fd;
        const char *path;
    } objs[] = {
        /* BPF Programs */
        {&state->ingress.fd, "ingress/0"},
        {&state->egress.fd, "egress/0"},
        {&state->downcall.fd, "downcall/0"},
        {&state->xdp.fd, "xdp/0"},
        {&state->afxdp[0].fd, "afxdp0/0"},
        {&state->afxdp[1].fd, "afxdp1/0"},
        {&state->afxdp[2].fd, "afxdp2/0"},
        {&state->afxdp[3].fd, "afxdp3/0"},
        /* BPF Maps */
        {&state->upcalls.fd, "upcalls"},
        {&state->flow_table.fd, "flow_table"},
        {&state->datapath_stats.fd, "datapath_stats"},
        {&state->tailcalls.fd, "tailcalls"},
        {&state->execute_actions.fd, "execute_actions"},
        {&state->dp_flow_stats.fd, "dp_flow_stats"},
        {&state->xsks_map[0].fd, "xsks_map0"},
        {&state->xsks_map[1].fd, "xsks_map1"},
        {&state->xsks_map[2].fd, "xsks_map2"},
        {&state->xsks_map[3].fd, "xsks_map3"},
    };
    int i, k, error = 0;
    char buf[BUFSIZ];
    int prog_array_fd;

    for (i = 0; i < ARRAY_SIZE(objs); i++) {
        struct stat s;

        //Failed to load /sys/fs/bpf/ovs/progs/ingress_0:
        snprintf(buf, ARRAY_SIZE(buf), "%s/%s", ovs_bpf_path, objs[i].path);
        if (stat(buf, &s)) {
            error = errno;
            break;
        }
        error = bpf_obj_get(buf);
        if (error > 0) {
            VLOG_INFO("Loaded BPF object at %s fd %d", buf, error);
            *objs[i].fd = error;
            error = 0;
            continue;
        } else {
            error = errno;
            break;
        }
    }

    prog_array_fd = state->tailcalls.fd;

    VLOG_INFO("start loading/pinning program array\n");
    for (k = 0; k < BPF_MAX_PROG_ARRAY; k++) {
        struct stat s;
        int prog_fd;

        state->tailarray[k].fd = 0;

        snprintf(buf, ARRAY_SIZE(buf), "%s/tail-%d/0", ovs_bpf_path, k);
        if (stat(buf, &s)) {
            continue;
        }

        prog_fd = bpf_obj_get(buf);
        if (prog_fd > 0) {
            VLOG_INFO("Loaded BPF object at %s", buf);
            state->tailarray[k].fd = prog_fd;
            error = bpf_map_update_elem(prog_array_fd, &k, &prog_fd, BPF_ANY);
            if (error < 0) {
                VLOG_ERR("Can not add %s into BPF_MAP_PROG_ARRAY\n", buf);
                break;
            }
        } else {
            error = errno;
            break;
        }
    }

    if (error) {
        VLOG(verbose ? VLL_WARN : VLL_DBG, "Failed to load %s: %s",
             buf, ovs_strerror(error));

        for (int j = 0; j < i; j++) {
            close(*objs[j].fd);
            *objs[j].fd = 0;
        }

        for (int j = 0; j < BPF_MAX_PROG_ARRAY; j++) {
            if (state->tailarray[j].fd)
                close(state->tailarray[j].fd);
        }
    }

    if (!error) {
        state->ingress.handle = INGRESS_HANDLE;
        state->ingress.name = xstrdup("ovs_cls_ingress");
        state->egress.handle = EGRESS_HANDLE;
        state->egress.name = xstrdup("ovs_cls_egress");
        state->downcall.handle = INGRESS_HANDLE;
        state->downcall.name = xstrdup("ovs_cls_downcall");
        state->upcalls.name = xstrdup("upcalls");
        state->xdp.name = xstrdup("xdp");
        state->afxdp[0].name = xstrdup("afxdp0");
        state->afxdp[1].name = xstrdup("afxdp1");
        state->afxdp[2].name = xstrdup("afxdp2");
        state->afxdp[3].name = xstrdup("afxdp3");
        state->flow_table.name = xstrdup("flow_table");
        state->datapath_stats.name = xstrdup("datapath_stats");
        state->dp_flow_stats.name = xstrdup("dp_flow_stats");
        state->xsks_map[0].name = xstrdup("xsks_map0");
        state->xsks_map[1].name = xstrdup("xsks_map1");
        state->xsks_map[2].name = xstrdup("xsks_map2");
        state->xsks_map[3].name = xstrdup("xsks_map3");
        // add parser, lookup, action, deparser
        state->tailcalls.name = xstrdup("tailcalls");

    }

    return error;
}

static void
xclose(int fd, const char *name)
{
    int error = close(fd);
    if (error) {
        VLOG_WARN("Failed to close BPF fd %s: %s", name, ovs_strerror(errno));
    }
}

/* Frees resources allocated by bpf_put(). */
void
bpf_put(struct bpf_state *state)
{
    xclose(state->ingress.fd, state->ingress.name);
    xclose(state->egress.fd, state->egress.name);
    xclose(state->downcall.fd, state->downcall.name);
    xclose(state->upcalls.fd, state->upcalls.name);
    xclose(state->xdp.fd, state->xdp.name);
    xclose(state->afxdp[0].fd, state->afxdp[0].name);
    xclose(state->afxdp[1].fd, state->afxdp[1].name);
    xclose(state->afxdp[2].fd, state->afxdp[2].name);
    xclose(state->afxdp[3].fd, state->afxdp[3].name);
    xclose(state->flow_table.fd, "ovs_map_flow_table");
    xclose(state->datapath_stats.fd, "ovs_datapath_stats");
    xclose(state->dp_flow_stats.fd, state->dp_flow_stats.name);
    xclose(state->xsks_map[0].fd, state->xsks_map[0].name);
    xclose(state->xsks_map[1].fd, state->xsks_map[1].name);
    xclose(state->xsks_map[2].fd, state->xsks_map[2].name);
    xclose(state->xsks_map[3].fd, state->xsks_map[3].name);
    free((void *)state->ingress.name);
    free((void *)state->egress.name);
    free((void *)state->downcall.name);
    free((void *)state->upcalls.name);
    free((void *)state->xdp.name);
    free((void *)state->afxdp[0].name);
    free((void *)state->afxdp[1].name);
    free((void *)state->afxdp[2].name);
    free((void *)state->afxdp[3].name);
    free((void *)state->flow_table.name);
    free((void *)state->datapath_stats.name);
    free((void *)state->dp_flow_stats.name);
    free((void *)state->xsks_map[0].name);
    free((void *)state->xsks_map[1].name);
    free((void *)state->xsks_map[2].name);
    free((void *)state->xsks_map[3].name);
}

static void
process(struct bpf_object *obj)
{
    struct bpf_program *prog;
    struct bpf_map *map;

    VLOG_DBG("Opened object '%s'\n", bpf_object__name(obj));
    VLOG_DBG("Programs:\n");
    bpf_object__for_each_program(prog, obj) {
        const char *title = bpf_program__title(prog, false);
        int error;

        VLOG_DBG(" - %s\n",  title);
        if (strstr(title, "xdp")) { /* handle both xdp and afxdp */
            error = bpf_program__set_xdp(prog);
        } else {
            error = bpf_program__set_sched_cls(prog); // or sched_act?
        }
        if (error) {
            VLOG_WARN("Failed to set '%s' prog type: %s\n", title,
                     ovs_strerror(error));
        }

    }

    if (VLOG_IS_DBG_ENABLED()) {
        VLOG_DBG("Maps:\n");
        bpf_map__for_each(map, obj) {
            const char *name = bpf_map__name(map);
            VLOG_DBG(" - %s\n", name);
        }
    }
}

/* Attempts to load the BPF datapath in the form of an ELF compiled for the BPF
 * ISA in 'path', install it into the kernel, and pin it to the filesystem
 * under ovs_bpf_path/{maps,progs}/foo.
 *
 * Returns 0 on success, or positive errno on error.
 */
int
bpf_load(const char *path)
{
    const char *stage = NULL;
    struct bpf_state state;
    struct bpf_object *obj;
    long error;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if ((error = setrlimit(RLIMIT_MEMLOCK, &r))) {
        VLOG_ERR("Failed to set rlimit %s", ovs_strerror(error));
        return error;
    }

    if (!bpf_get(&state, false)) {
        /* XXX: Restart; Upgrade */
        VLOG_INFO("Re-using preloaded BPF datapath");
        bpf_put(&state);
        return 0;
    }

    obj = bpf_object__open(path);
    error = libbpf_get_error(obj);
    if (error) {
        stage = "open";
        goto out;
    }
    process(obj);
    error = bpf_object__load(obj);
    if (error) {
        stage = "load";
        goto close;
    }
    error = bpf_object__pin(obj, ovs_bpf_path);
    if (error) {
        stage = "pin";
        goto close;
    }

    error = bpf_object__unload(obj);
    if (error) {
        stage = "unload";
        goto close;
    }

close:
    bpf_object__close(obj);
out:
    if (error < 0) {
        error = -error;
    } else if (!error) {
        VLOG_DBG("Loaded BPF datapath from %s", path);
    }
    if (error > __LIBBPF_ERRNO__START && error < __LIBBPF_ERRNO__END) {
        char buf[BUFSIZ];

        libbpf_strerror(error, buf, ARRAY_SIZE(buf));
        VLOG_WARN("Failed to %s BPF datapath: %s\n", stage ? stage : "", buf);
        error = EINVAL;
    }
    return error;
}

#define PRINT_FN(NAME)                                  \
static int                                              \
print_##NAME(const char *fmt, ...)                      \
{                                                       \
    va_list args;                                       \
                                                        \
    va_start(args, fmt);                                \
    vlog_valist(&this_module, VLL_##NAME, fmt, args);   \
    va_end(args);                                       \
    return 0;                                           \
}

PRINT_FN(WARN);
PRINT_FN(INFO);
PRINT_FN(DBG);

#define stringize(x) #x

static int OVS_UNUSED
mount_bpf(void)
{
    struct statfs st_fs;
    char path[PATH_MAX];
    char type[NAME_MAX];
    int err = 0;
    FILE *fp;
    int idx;

    fp = fopen("/proc/mounts", "r");
    if (fp) {
        const char *fmt;
        int match;

        fmt = "%*s %"stringize(PATH_MAX)"s %#"stringize(NAME_MAX)"s %*s\n";
        for (match = 0; match != EOF; match = fscanf(fp, fmt, path, type)) {
            if (match == 2 && !strcmp(type, "bpf"))
                break;
        }
        if (fclose(fp)) {
            err = errno;
            VLOG_INFO("Failed to close /proc/mounts: %s", ovs_strerror(err));
        }
        if (strcmp(type, "bpf")) {
            err = errno;
            VLOG_DBG("Couldn't find bpf mountpoint in /proc/mounts");
        }
    } else {
        err = errno;
        VLOG_INFO("Cannot open /proc/mounts: %s", ovs_strerror(err));
    }
    if (err || strlen(path) == 0) {
        VLOG_DBG("Using %s for BPF filesystem mountpoint", BPF_FS_PATH);
        strcpy(path, BPF_FS_PATH);
    }

    if (!statfs(path, &st_fs) && st_fs.f_type == BPF_FS_MAGIC) {
        VLOG_INFO("BPF filesystem already mounted to %s", path);
        return 0;
    }

    if (mkdir(path, 0755) && errno != EEXIST) {
        VLOG_WARN("Failed to create %s: %s", path, ovs_strerror(errno));
        return errno;
    }

    if (mount("bpf", path, "bpf", 0, NULL)) {
        VLOG_WARN("Failed to mount BPF filesystem: %s", ovs_strerror(errno));
        return errno;
    }

    idx = strlen(path);
    if (idx >= PATH_MAX - strlen("/ovs")) {
        VLOG_WARN("BPF filesystem path \"%s\" is too long.", path);
        return ENAMETOOLONG;
    } else {
        strncpy(&path[idx], "/ovs", strlen("/ovs"));
    }

    if (mkdir(path, 0755) && errno != EEXIST) {
        VLOG_WARN("Failed to create %s: %s", path, ovs_strerror(errno));
        return errno;
    }

    if (ovs_bpf_path) {
        free(CONST_CAST(char *, ovs_bpf_path));
    }
    ovs_bpf_path = xstrdup(path);
    return 0;
}

int
bpf_init(void)
{
    libbpf_set_print(print_WARN, print_INFO, print_DBG);
    /* skip using mount_bpf */
    return 0;
}
