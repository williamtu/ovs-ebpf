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
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "bpf.h"
#include "command-line.h"
#include "fatal-signal.h"
#include "util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"

static int verbosity = 0;
static bool read_only = false;

typedef int bpfctl_command_handler(int argc, const char *argv[]);
struct bpfctl_command {
    const char *name;
    const char *usage;
    int min_args;
    int max_args;
    bpfctl_command_handler *handler;
    enum { DP_RO, DP_RW} mode;
};

OVS_NO_RETURN static void usage(void *userdata OVS_UNUSED);
static void parse_options(int argc, char *argv[]);
static int bpfctl_run_command(int argc, const char *argv[]);

static void
bpfctl_print(void *userdata OVS_UNUSED, bool error, const char *msg)
{
    FILE *outfile = error ? stderr : stdout;
    fputs(msg, outfile);
}

static void
bpfctl_error(int err_no, const char *fmt, ...)
{
    const char *subprogram_name = get_subprogram_name();
    struct ds ds = DS_EMPTY_INITIALIZER;
    int save_errno = errno;
    va_list args;

    if (subprogram_name[0]) {
        ds_put_format(&ds, "%s(%s): ", program_name,subprogram_name);
    } else {
        ds_put_format(&ds, "%s: ", program_name);
    }

    va_start(args, fmt);
    ds_put_format_valist(&ds, fmt, args);
    va_end(args);

    if (err_no != 0) {
        ds_put_format(&ds, " (%s)", ovs_retval_to_string(err_no));
    }
    ds_put_cstr(&ds, "\n");

    bpfctl_print(NULL, true, ds_cstr(&ds));

    ds_destroy(&ds);

    errno = save_errno;
}

int
main(int argc, char *argv[])
{
    int error;
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    error = bpfctl_run_command(argc - optind, (const char **) argv + optind);
    return error ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_CLEAR = UCHAR_MAX + 1,
        OPT_MAY_CREATE,
        OPT_READ_ONLY,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"read-only", no_argument, NULL, OPT_READ_ONLY},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_READ_ONLY:
            read_only = true;
            break;

        case 'm':
            verbosity++;
            break;

        case 'h':
            usage(NULL);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void *userdata OVS_UNUSED)
{
    printf("%s: Open vSwitch bpf management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  show                     show basic info on bpf datapaths\n"
           "  load-dp FILENAME         load datapath from FILENAME\n",
           program_name, program_name);
    vlog_usage();
    printf("  -m, --more                  increase verbosity of output\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static int
bpfctl_show(int argc OVS_UNUSED, const char *argv[] OVS_UNUSED)
{
    struct bpf_state bpf;

    if (!bpf_get(&bpf, verbosity)) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        bpf_format_state(&ds, &bpf);
        printf("%s", ds_cstr(&ds));
        ds_destroy(&ds);
        bpf_put(&bpf);
    }
    return 0;
}

static int
bpfctl_load_dp(int argc OVS_UNUSED, const char *argv[])
{
    int error;

    error = bpf_init();
    if (error) {
        return error;
    }
    return bpf_load(argv[1]);
}

static const struct bpfctl_command all_commands[] = {
    { "load-dp", "[file]", 1, 1, bpfctl_load_dp, DP_RW },
    { "show", "", 0, 0, bpfctl_show, DP_RO },
    { NULL, NULL, 0, 0, NULL, DP_RO },
};

/* Runs the command designated by argv[0] within the command table specified by
 * 'commands', which must be terminated by a command whose 'name' member is a
 * null pointer. */
static int
bpfctl_run_command(int argc, const char *argv[])
{
    const struct bpfctl_command *p;

    if (argc < 1) {
        bpfctl_error(0, "missing command name; use --help for help");
        return EINVAL;
    }

    for (p = all_commands; p->name != NULL; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args) {
                bpfctl_error(0, "'%s' command requires at least %d arguments",
                            p->name, p->min_args);
                return EINVAL;
            } else if (n_arg > p->max_args) {
                bpfctl_error(0, "'%s' command takes at most %d arguments",
                            p->name, p->max_args);
                return EINVAL;
            } else {
                if (p->mode == DP_RW && read_only) {
                    bpfctl_error(0,
                                "'%s' command does not work in read only mode",
                                p->name);
                    return EINVAL;
                }
                return p->handler(argc, argv);
            }
        }
    }

    bpfctl_error(0, "unknown command '%s'; use --help for help",
                argv[0]);
    return EINVAL;
}
