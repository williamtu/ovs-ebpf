// libmemif support

#include <config.h>
#include <sys/types.h>

#include <libmemif.h>

#include "openvswitch/vlog.h"
#include "netdev-provider.h"
#include "netdev-memif.h"

VLOG_DEFINE_THIS_MODULE(netdev_memif);

#define MAX_CONNS 32

struct memif_conn {
    uint16_t index;
    memif_conn_handle_t conn_handle;

    /* tx buffers */
    memif_buffer_t *tx_bufs;
    uint16_t tx_buf_num;

    /* rx buffers */
    memif_buffer_t *rx_bufs;
    uint16_t rx_buf_num;

    uint8_t ip_addr[4];
    uint16_t seq;
    uint64_t tx_counter, rx_counter, tx_err_counter;
    uint64_t t_sec, t_nsec;
};

struct memif_thread_data {
    uint16_t index;
    uint64_t packet_num;
    uint8_t ip_addr[4];
    uint8_t hw_daddr[6];
};

struct netdev_memif {
    struct netdev up;
    struct memif_conn conn[MAX_CONNS];
    struct memif_thread_data thread_data[MAX_CONNS];
//    pthread_t thread[MAX_CONNS];
    long ctx[MAX_CONNS];
};

static struct netdev_memif *
netdev_memif_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_memif, up);
}

static int
netdev_memif_init(void)
{
    int err;

    err = memif_init(NULL, "ovs-memif", NULL, NULL, NULL);

    VLOG_INFO("memif init done, ret = %d", err);
    return err;
}

static void
netdev_memif_destruct(struct netdev *netdev)
{
    ;
}

static struct netdev *
netdev_memif_alloc(void)
{
    struct netdev_memif *dev;

    VLOG_INFO("%s", __func__);

    dev = xzalloc(sizeof *dev);
    if (dev) {
        return &dev->up;
    }
    return NULL;
}

static void
netdev_memif_dealloc(struct netdev *netdev)
{
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    free(dev);
}

static int
netdev_memif_construct(struct netdev *netdev)
{
    int err;
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    return 0;
}

static int
netdev_memif_update_flags(struct netdev *netdev,
                         enum netdev_flags off, enum netdev_flags on,
                         enum netdev_flags *old_flagsp)
{
    VLOG_INFO("%s", __func__);
    return 0;
}

static int
netdev_memif_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    VLOG_INFO("%s", __func__);
    return 0;
}

static const struct netdev_class memif_class = {
    .type = "memif",
    .is_pmd = true,
    .init = netdev_memif_init,
    .destruct = netdev_memif_destruct,
    .alloc = netdev_memif_alloc,
    .dealloc = netdev_memif_dealloc,
    .construct = netdev_memif_construct,
    .update_flags = netdev_memif_update_flags,
    .get_etheraddr = netdev_memif_get_etheraddr,
//    .rxq_recv = netdev_memif_rxq_recv,
};

void
netdev_memif_register(void)
{
    netdev_register_provider(&memif_class);
}
