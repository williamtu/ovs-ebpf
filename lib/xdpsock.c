#include <config.h>
#include "openvswitch/vlog.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "async-append.h"
#include "coverage.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-thread.h"
#include "sat-math.h"
#include "socket-util.h"
#include "svec.h"
#include "syslog-direct.h"
#include "syslog-libc.h"
#include "syslog-provider.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "ovs-atomic.h"
#include "xdpsock.h"

inline void
umem_elem_push(struct umem_elem_head *head,
               struct umem_elem *elem)
{
    struct umem_elem *next;

//    ovs_mutex_lock(&head->mutex);
    next = head->next;
    head->next = elem;
    elem->next = next;
    head->n++;
//    ovs_mutex_unlock(&head->mutex);
}

inline struct umem_elem *
umem_elem_pop(struct umem_elem_head *head)
{
    struct umem_elem *next, *new_head;

//    ovs_mutex_lock(&head->mutex);
    next = head->next;
    if (!next) {
//        ovs_mutex_unlock(&head->mutex);
        return NULL;
    }
    new_head = next->next;
    head->next = new_head;
    head->n--;
//    ovs_mutex_unlock(&head->mutex);
    return next;
}

inline unsigned int
umem_elem_count(struct umem_elem_head *head)
{
    return head->n;
}


