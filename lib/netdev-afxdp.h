/*
 * Copyright (c) 2018 Nicira, Inc.
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

#ifndef NETDEV_AFXDP_H
#define NETDEV_AFXDP_H 1

#include <stdint.h>
#include <stdbool.h>

/* These functions are Linux AF_XDP specific, so they should be used directly
 * only by Linux-specific code. */
#define MAX_XSKQ 16
struct netdev;
struct xsk_socket_info;
struct xdp_umem;
struct dp_packet_batch;
struct smap;
struct dp_packet;

struct dp_packet_afxdp * dp_packet_cast_afxdp(const struct dp_packet *d);

int xsk_configure_all(struct netdev *netdev);

void xsk_destroy_all(struct netdev *netdev);

int netdev_linux_rxq_xsk(struct xsk_socket_info *xsk,
                         struct dp_packet_batch *batch);

int netdev_linux_afxdp_batch_send(struct xsk_socket_info *xsk,
                                  struct dp_packet_batch *batch);

int netdev_afxdp_set_config(struct netdev *netdev, const struct smap *args,
                            char **errp);
int netdev_afxdp_get_config(const struct netdev *netdev, struct smap *args);
int netdev_afxdp_get_numa_id(const struct netdev *netdev);

void free_afxdp_buf(struct dp_packet *p);
void free_afxdp_buf_batch(struct dp_packet_batch *batch);
int netdev_afxdp_reconfigure(struct netdev *netdev);
#endif /* netdev-afxdp.h */
