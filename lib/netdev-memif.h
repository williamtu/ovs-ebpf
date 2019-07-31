// memif.h

#ifndef NETDEV_MEMIF_H
#define NETDEV_MEMIF_H 1

#include <stdint.h>
#include <stdbool.h>

struct dp_packet;
void netdev_memif_register(void);

void free_memif_buf(struct dp_packet *b);
#endif
