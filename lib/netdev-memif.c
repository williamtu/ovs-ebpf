// libmemif support

#include <config.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <signal.h>

#include <errno.h>
#include <libmemif.h>

#include "openvswitch/vlog.h"
#include "netdev-provider.h"
#include "netdev-memif.h"

VLOG_DEFINE_THIS_MODULE(netdev_memif);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define MAX_CONNS 32

static struct ovsthread_once memif_thread_once
    = OVSTHREAD_ONCE_INITIALIZER;

int epfd;

struct memif_thread_data {
    uint16_t index;
    uint64_t packet_num;
    uint8_t ip_addr[4];
    uint8_t hw_daddr[6];
};

struct netdev_memif {
    struct netdev up;

    uint16_t index;
    memif_conn_handle_t handle;

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

    struct memif_thread_data thread_data;;
//    pthread_t thread[MAX_CONNS];
    long ctx;
};

static struct netdev_memif *
netdev_memif_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_memif, up);
}

static void
memif_print_details(const struct netdev *netdev)
{
    int err;
    size_t buflen;
    char *buf;
    memif_details_t md;
    struct netdev_memif *dev = netdev_memif_cast(netdev);

    buflen = 1024;
    buf = xzalloc(buflen);
    VLOG_INFO("==== MEMIF Details ====");

return; // connected!
    memset(&md, 0, sizeof md);
    err = memif_get_details(dev->handle, &md, buf, buflen);
    if (err != MEMIF_ERR_SUCCESS) {
        VLOG_ERR("memif get detail error %s", memif_strerror(err));
    }

    VLOG_INFO("interface name: %s", (char *) md.if_name);
    VLOG_INFO("remote interface name: %s", (char *) md.remote_if_name);
    VLOG_INFO("remote app name: %s", (char *) md.remote_inst_name);
    VLOG_INFO("role: %s", md.role ? "slave" : "master");

    free(buf);
}

#define DBG VLOG_INFO
int
add_epoll_fd (int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d added to epoll", fd);
  return 0;
}

int
mod_epoll_fd (int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl (epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d moddified on epoll", fd);
  return 0;
}

int
del_epoll_fd (int fd)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  if (epoll_ctl (epfd, EPOLL_CTL_DEL, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d removed from epoll", fd);
  return 0;
}

int
control_fd_update (int fd, uint8_t events, void *ctx)
{
  /* convert memif event definitions to epoll events */
  if (events & MEMIF_FD_EVENT_DEL)
    return del_epoll_fd (fd);

  uint32_t evt = 0; 
  if (events & MEMIF_FD_EVENT_READ)
    evt |= EPOLLIN;
  if (events & MEMIF_FD_EVENT_WRITE)
    evt |= EPOLLOUT;

  if (events & MEMIF_FD_EVENT_MOD)
    return mod_epoll_fd (fd, evt);

  return add_epoll_fd (fd, evt);
}

static void *
memif_thread(void *f_)
{
    struct netdev *netdev = (struct netdev *)f_;
    struct epoll_event evt;
    uint32_t events;
    struct timespec start, end;
    sigset_t sigset;
    int memif_err, en;
    int timeout = -1; /* block */

    while (1) {
        events = 0;

        ovsrcu_quiesce_start(); // why?

        sigemptyset(&sigset);

        memset(&evt, 0, sizeof evt);
        evt.events = EPOLLIN | EPOLLOUT;

        VLOG_INFO_RL(&rl, "epoll pwait");
        en = epoll_pwait(epfd, &evt, 1, timeout, &sigset);

        timespec_get(&start, TIME_UTC);
        if (en < 0) {
            VLOG_INFO("epoll_pwait: %s", ovs_strerror(errno));
            return -1;
        }

        if (en > 0) {
            if (evt.data.fd > 2) {
                if (evt.events & EPOLLIN) {
                    events |= MEMIF_FD_EVENT_READ;
                }
                if (evt.events & EPOLLOUT) {
                    events |= MEMIF_FD_EVENT_WRITE;
                }
                if (evt.events & EPOLLERR) {
                    events |= MEMIF_FD_EVENT_ERROR;
                }

                memif_err = memif_control_fd_handler(evt.data.fd, events);
                if (memif_err != MEMIF_ERR_SUCCESS) {
                    VLOG_ERR_RL(&rl, "memif_control_fd_handler: %s",
                             memif_strerror(memif_err));
                }

                VLOG_INFO_RL(&rl, "valid fd %d", evt.data.fd);
                memif_print_details(netdev);
            } else {
                VLOG_ERR_RL(&rl, "unexpected event at memif_epfd. fd %d", evt.data.fd);
            }
        }
        timespec_get(&end, TIME_UTC);
        VLOG_INFO_RL(&rl, "interrupt: %ld", end.tv_nsec - start.tv_nsec);
        ovsrcu_quiesce_end();
    }
    return NULL;
}

/* Invoke when register */
static int
netdev_memif_init(void)
{
    int err;
    pthread_t pt;

    epfd = epoll_create(1);
    add_epoll_fd(0, EPOLLIN);

    err = memif_init(control_fd_update, "ovs-memif", NULL, NULL, NULL);
    VLOG_INFO("memif init done, ret = %d", err);

    return err;
}

static void
netdev_memif_destruct(struct netdev *netdev)
{
    memif_print_details(netdev);
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
on_connect(memif_conn_handle_t conn, void *private_ctx)
{
    const int headroom = 128;
    const int count = 128;
    int qid = 0;
    int memif_err = 0;

    VLOG_INFO("memif connected!");

    memif_err = memif_refill_queue(conn, qid, count, headroom);
    if (memif_err != MEMIF_ERR_SUCCESS) {
        VLOG_ERR("memif_refill_queue failed: %s", memif_strerror(memif_err));
    }

//  enable_log = 1; 
    return 0;
}

/* informs user about disconnected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
static int
on_disconnect(memif_conn_handle_t conn, void *private_ctx)
{
    VLOG_INFO("memif disconnected!");
    return 0;
}

static int
on_interrupt(memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
    struct netdev_memif *dev;
    struct netdev *netdev;

    netdev = (struct netdev *)private_ctx;
    dev = netdev_memif_cast(netdev);

    VLOG_INFO("memif on_interrupt, name %s qid %d", netdev->name, qid);

    return 0;
}

static int
netdev_memif_construct(struct netdev *netdev)
{
    int err;
    struct netdev_memif *dev = netdev_memif_cast(netdev);
    struct memif_conn *conn;
    const char *dev_name;

    VLOG_INFO("%s", __func__);

    /* setting memif connection arguments */
    memif_conn_args_t args;
    memset (&args, 0, sizeof (args));
    args.is_master = true;
    args.log2_ring_size = 11;
    args.buffer_size = 2048;
    args.num_s2m_rings = 1;
    args.num_m2s_rings = 1;
    args.mode = MEMIF_INTERFACE_MODE_ETHERNET;

    dev_name = netdev_get_name(netdev);
    strncpy((char *) args.interface_name, dev_name, strlen(dev_name));
    args.interface_id = 0;

    err = memif_create(&dev->handle, &args, on_connect, on_disconnect,
                       on_interrupt, (void *)netdev);

    VLOG_INFO("%s memif_create %d name %s", __func__, err, dev_name);

    if (ovsthread_once_start(&memif_thread_once)) {
        ovs_thread_create("memif_control", memif_thread, (void *)netdev);
        VLOG_INFO("memif thread created");
        ovsthread_once_done(&memif_thread_once);
    }

    memif_print_details(netdev);
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
