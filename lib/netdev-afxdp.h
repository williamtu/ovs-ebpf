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
struct netdev;
struct xsk_socket_info;
struct xdp_umem;
struct dp_packet_batch;

struct xsk_socket_info *xsk_configure(int ifindex, int xdp_queue_id);
void xsk_destroy(struct xsk_socket_info *xsk, uint32_t ifindex);

int netdev_linux_rxq_xsk(struct xsk_socket_info *xsk,
                         struct dp_packet_batch *batch);

int netdev_linux_afxdp_batch_send(struct xsk_socket_info *xsk,
                                  struct dp_packet_batch *batch);

#endif /* netdev-afxdp.h */
