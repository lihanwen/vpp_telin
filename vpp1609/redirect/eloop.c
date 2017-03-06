/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 文件名称: eloop.c 
 功能描述: select事件循环的处理
*******************************************************************************/

/*
 * Event loop based on select() loop
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

//#include "includes.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
//#include <sys/time.h>
#include <time.h>

#include <assert.h>

//#include "common.h"
//#include "os.h"
//#include "trace.h"

#include "eloop.h"

#define os_malloc(s) malloc((s))
#define os_realloc(p, s) realloc((p), (s))
#define os_free(p) free((p))
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#define os_memmove(d, s, n) memmove((d), (s), (n))
#define os_memset(s, c, n) memset(s, c, n)
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
static inline void * os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
    if (size && nmemb > (~(size_t) 0) / size)
        return NULL;
    return os_realloc(ptr, nmemb * size);
}
static inline int os_reltime_before(struct os_reltime *a,
                    struct os_reltime *b)
{
    return (a->sec < b->sec) ||
           (a->sec == b->sec && a->usec < b->usec);
}
static inline void os_reltime_sub(struct os_reltime *a, struct os_reltime *b,
                  struct os_reltime *res)
{
    res->sec = a->sec - b->sec;
    res->usec = a->usec - b->usec;
    if (res->usec < 0) {
        res->sec--;
        res->usec += 1000000;
    }
}


#include "list.h"

/* 使用 POLL 机制 */
//#define CONFIG_ELOOP_POLL
/* 使用 select 机制 */
#define CONFIG_ELOOP_SELECT


#if defined(CONFIG_ELOOP_POLL) && defined(CONFIG_ELOOP_EPOLL)
#error Do not define both of poll and epoll
#endif

#if !defined(CONFIG_ELOOP_POLL) && !defined(CONFIG_ELOOP_EPOLL)
#define CONFIG_ELOOP_SELECT
#endif

#ifdef CONFIG_ELOOP_POLL
#include <poll.h>
#endif /* CONFIG_ELOOP_POLL */

#ifdef CONFIG_ELOOP_EPOLL
#include <sys/epoll.h>
#endif /* CONFIG_ELOOP_EPOLL */


#include <time.h>
#include <unistd.h>
#define wpa_printf(level, args...) do { } while (0)

void * os_zalloc(size_t size)
{
    return calloc(1, size);
}

int os_get_reltime(struct os_reltime *t)
{
#if defined(CLOCK_BOOTTIME)
    static clockid_t clock_id = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC)
    static clockid_t clock_id = CLOCK_MONOTONIC;
#else
    static clockid_t clock_id = CLOCK_REALTIME;
#endif
    struct timespec ts;
    int res;

    while (1) {
        res = clock_gettime(clock_id, &ts);
        if (res == 0) {
            t->sec = ts.tv_sec;
            t->usec = ts.tv_nsec / 1000;
            return 0;
        }
        switch (clock_id) {
#ifdef CLOCK_BOOTTIME
        case CLOCK_BOOTTIME:
            clock_id = CLOCK_MONOTONIC;
            break;
#endif
#ifdef CLOCK_MONOTONIC
        case CLOCK_MONOTONIC:
            clock_id = CLOCK_REALTIME;
            break;
#endif
        case CLOCK_REALTIME:
            return -1;
        }
    }
}







struct eloop_sock {
    int sock;
    void *eloop_data;
    void *user_data;
    eloop_sock_handler handler;
//    WPA_TRACE_REF(eloop);
//    WPA_TRACE_REF(user);
//    WPA_TRACE_INFO
};

struct eloop_timeout {
    struct dl_list list;
    struct os_reltime time;
    void *eloop_data;
    void *user_data;
    eloop_timeout_handler handler;
//    WPA_TRACE_REF(eloop);
//    WPA_TRACE_REF(user);
//    WPA_TRACE_INFO
};

struct eloop_signal {
    int sig;
    void *user_data;
    eloop_signal_handler handler;
    int signaled;
};

struct eloop_sock_table {
    int count;
    struct eloop_sock *table;
#ifdef CONFIG_ELOOP_EPOLL
    eloop_event_type type;
#else /* CONFIG_ELOOP_EPOLL */
    int changed;
#endif /* CONFIG_ELOOP_EPOLL */
};

struct eloop_data {
    int max_sock;

    int count; /* sum of all table counts */
#ifdef CONFIG_ELOOP_POLL
    int max_pollfd_map; /* number of pollfds_map currently allocated */
    int max_poll_fds; /* number of pollfds currently allocated */
    struct pollfd *pollfds;
    struct pollfd **pollfds_map;
#endif /* CONFIG_ELOOP_POLL */
#ifdef CONFIG_ELOOP_EPOLL
    int epollfd;
    int epoll_max_event_num;
    int epoll_max_fd;
    struct eloop_sock *epoll_table;
    struct epoll_event *epoll_events;
#endif /* CONFIG_ELOOP_EPOLL */
    struct eloop_sock_table readers;
    struct eloop_sock_table writers;
    struct eloop_sock_table exceptions;

    struct dl_list timeout;

    int signal_count;
    struct eloop_signal *signals;
    int signaled;
    int pending_terminate;

    int terminate;
};

static struct eloop_data eloop;



#define eloop_trace_sock_add_ref(table) do { } while (0)
#define eloop_trace_sock_remove_ref(table) do { } while (0)



int eloop_init(void)
{
    os_memset(&eloop, 0, sizeof(eloop));
    dl_list_init(&eloop.timeout);
#ifdef CONFIG_ELOOP_EPOLL
    eloop.epollfd = epoll_create1(0);
    if (eloop.epollfd < 0) {
        wpa_printf(MSG_ERROR, "%s: epoll_create1 failed. %s\n",
               __func__, strerror(errno));
        return -1;
    }
    eloop.readers.type = EVENT_TYPE_READ;
    eloop.writers.type = EVENT_TYPE_WRITE;
    eloop.exceptions.type = EVENT_TYPE_EXCEPTION;
#endif /* CONFIG_ELOOP_EPOLL */
#ifdef WPA_TRACE
    signal(SIGSEGV, eloop_sigsegv_handler);
#endif /* WPA_TRACE */
    return 0;
}


static int eloop_sock_table_add_sock(struct eloop_sock_table *table,
                                     int sock, eloop_sock_handler handler,
                                     void *eloop_data, void *user_data)
{
#ifdef CONFIG_ELOOP_EPOLL
    struct eloop_sock *temp_table;
    struct epoll_event ev, *temp_events;
    int next;
#endif /* CONFIG_ELOOP_EPOLL */
    struct eloop_sock *tmp;
    int new_max_sock;

    if (sock > eloop.max_sock)
        new_max_sock = sock;
    else
        new_max_sock = eloop.max_sock;

    if (table == NULL)
        return -1;

#ifdef CONFIG_ELOOP_POLL
    if (new_max_sock >= eloop.max_pollfd_map) {
        struct pollfd **nmap;
        nmap = os_realloc_array(eloop.pollfds_map, (size_t)new_max_sock + 50,
                    sizeof(struct pollfd *));
        if (nmap == NULL)
            return -1;

        eloop.max_pollfd_map = new_max_sock + 50;
        eloop.pollfds_map = nmap;
    }

    if (eloop.count + 1 > eloop.max_poll_fds) {
        struct pollfd *n;
        int nmax = eloop.count + 1 + 50;
        n = os_realloc_array(eloop.pollfds, (size_t)nmax,
                     sizeof(struct pollfd));
        if (n == NULL)
            return -1;

        eloop.max_poll_fds = nmax;
        eloop.pollfds = n;
    }
#endif /* CONFIG_ELOOP_POLL */
#ifdef CONFIG_ELOOP_EPOLL
    if (new_max_sock >= eloop.epoll_max_fd) {
        next = eloop.epoll_max_fd == 0 ? 16 : eloop.epoll_max_fd * 2;
        temp_table = os_realloc_array(eloop.epoll_table, next,
                          sizeof(struct eloop_sock));
        if (temp_table == NULL)
            return -1;

        eloop.epoll_max_fd = next;
        eloop.epoll_table = temp_table;
    }

    if (eloop.count + 1 > eloop.epoll_max_event_num) {
        next = eloop.epoll_max_event_num == 0 ? 8 :
            eloop.epoll_max_event_num * 2;
        temp_events = os_realloc_array(eloop.epoll_events, next,
                           sizeof(struct epoll_event));
        if (temp_events == NULL) {
            wpa_printf(MSG_ERROR, "%s: malloc for epoll failed. "
                   "%s\n", __func__, strerror(errno));
            return -1;
        }

        eloop.epoll_max_event_num = next;
        eloop.epoll_events = temp_events;
    }
#endif /* CONFIG_ELOOP_EPOLL */

    eloop_trace_sock_remove_ref(table);
    tmp = os_realloc_array(table->table, (size_t)(table->count + 1),
                   sizeof(struct eloop_sock));
    if (tmp == NULL) {
        eloop_trace_sock_add_ref(table);
        return -1;
    }

    tmp[table->count].sock = sock;
    tmp[table->count].eloop_data = eloop_data;
    tmp[table->count].user_data = user_data;
    tmp[table->count].handler = handler;
//    wpa_trace_record(&tmp[table->count]);
    table->count++;
    table->table = tmp;
    eloop.max_sock = new_max_sock;
    eloop.count++;
#ifndef CONFIG_ELOOP_EPOLL
    table->changed = 1;
#endif /* CONFIG_ELOOP_EPOLL */
    eloop_trace_sock_add_ref(table);

#ifdef CONFIG_ELOOP_EPOLL
    os_memset(&ev, 0, sizeof(ev));
    switch (table->type) {
    case EVENT_TYPE_READ:
        ev.events = EPOLLIN;
        break;
    case EVENT_TYPE_WRITE:
        ev.events = EPOLLOUT;
        break;
    /*
     * Exceptions are always checked when using epoll, but I suppose it's
     * possible that someone registered a socket *only* for exception
     * handling.
     */
    case EVENT_TYPE_EXCEPTION:
        ev.events = EPOLLERR | EPOLLHUP;
        break;
    }
    ev.data.fd = sock;
    if (epoll_ctl(eloop.epollfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        wpa_printf(MSG_ERROR, "%s: epoll_ctl(ADD) for fd=%d "
               "failed. %s\n", __func__, sock, strerror(errno));
        return -1;
    }
    os_memcpy(&eloop.epoll_table[sock], &table->table[table->count - 1],
          sizeof(struct eloop_sock));
#endif /* CONFIG_ELOOP_EPOLL */

    return 0;
}


static void eloop_sock_table_remove_sock(struct eloop_sock_table *table,
                                         int sock)
{
    int i;

    if (table == NULL || table->table == NULL || table->count == 0)
        return;

    for (i = 0; i < table->count; i++) {
        if (table->table[i].sock == sock)
            break;
    }
    if (i == table->count)
        return;
    eloop_trace_sock_remove_ref(table);
    if (i != table->count - 1) {
        os_memmove(&table->table[i], &table->table[i + 1],
               (unsigned int)(table->count - i - 1) *
               sizeof(struct eloop_sock));
    }
    table->count--;
    eloop.count--;
#ifndef CONFIG_ELOOP_EPOLL
    table->changed = 1;
#endif /* CONFIG_ELOOP_EPOLL */
    eloop_trace_sock_add_ref(table);
#ifdef CONFIG_ELOOP_EPOLL
    if (epoll_ctl(eloop.epollfd, EPOLL_CTL_DEL, sock, NULL) < 0) {
        wpa_printf(MSG_ERROR, "%s: epoll_ctl(DEL) for fd=%d "
               "failed. %s\n", __func__, sock, strerror(errno));
        return;
    }
    os_memset(&eloop.epoll_table[sock], 0, sizeof(struct eloop_sock));
#endif /* CONFIG_ELOOP_EPOLL */
}


#ifdef CONFIG_ELOOP_POLL

static struct pollfd * find_pollfd(struct pollfd **pollfds_map, int fd, int mx)
{
    if (fd < mx && fd >= 0)
        return pollfds_map[fd];
    return NULL;
}


static int eloop_sock_table_set_fds(struct eloop_sock_table *readers,
                    struct eloop_sock_table *writers,
                    struct eloop_sock_table *exceptions,
                    struct pollfd *pollfds,
                    struct pollfd **pollfds_map,
                    int max_pollfd_map)
{
    int i;
    int nxt = 0;
    int fd;
    struct pollfd *pfd;

    /* Clear pollfd lookup map. It will be re-populated below. */
    os_memset(pollfds_map, 0, sizeof(struct pollfd *) * (size_t)max_pollfd_map);

    if (readers && readers->table) {
        for (i = 0; i < readers->count; i++) {
            fd = readers->table[i].sock;
            assert(fd >= 0 && fd < max_pollfd_map);
            pollfds[nxt].fd = fd;
            pollfds[nxt].events = POLLIN;
            pollfds[nxt].revents = 0;
            pollfds_map[fd] = &(pollfds[nxt]);
            nxt++;
        }
    }

    if (writers && writers->table) {
        for (i = 0; i < writers->count; i++) {
            /*
             * See if we already added this descriptor, update it
             * if so.
             */
            fd = writers->table[i].sock;
            assert(fd >= 0 && fd < max_pollfd_map);
            pfd = pollfds_map[fd];
            if (!pfd) {
                pfd = &(pollfds[nxt]);
                pfd->events = 0;
                pfd->fd = fd;
                pollfds[i].revents = 0;
                pollfds_map[fd] = pfd;
                nxt++;
            }
            pfd->events |= POLLOUT;
        }
    }

    /*
     * Exceptions are always checked when using poll, but I suppose it's
     * possible that someone registered a socket *only* for exception
     * handling. Set the POLLIN bit in this case.
     */
    if (exceptions && exceptions->table) {
        for (i = 0; i < exceptions->count; i++) {
            /*
             * See if we already added this descriptor, just use it
             * if so.
             */
            fd = exceptions->table[i].sock;
            assert(fd >= 0 && fd < max_pollfd_map);
            pfd = pollfds_map[fd];
            if (!pfd) {
                pfd = &(pollfds[nxt]);
                pfd->events = POLLIN;
                pfd->fd = fd;
                pollfds[i].revents = 0;
                pollfds_map[fd] = pfd;
                nxt++;
            }
        }
    }

    return nxt;
}


static int eloop_sock_table_dispatch_table(struct eloop_sock_table *table,
                       struct pollfd **pollfds_map,
                       int max_pollfd_map,
                       short int revents)
{
    int i;
    struct pollfd *pfd;

    if (!table || !table->table)
        return 0;

    table->changed = 0;
    for (i = 0; i < table->count; i++) {
        pfd = find_pollfd(pollfds_map, table->table[i].sock,
                  max_pollfd_map);
        if (!pfd)
            continue;

        if (!(pfd->revents & revents))
            continue;

        table->table[i].handler(table->table[i].sock,
                    table->table[i].eloop_data,
                    table->table[i].user_data);
        if (table->changed)
            return 1;
    }

    return 0;
}


static void eloop_sock_table_dispatch(struct eloop_sock_table *readers,
                      struct eloop_sock_table *writers,
                      struct eloop_sock_table *exceptions,
                      struct pollfd **pollfds_map,
                      int max_pollfd_map)
{
    if (eloop_sock_table_dispatch_table(readers, pollfds_map,
                        max_pollfd_map, POLLIN | POLLERR |
                        POLLHUP))
        return; /* pollfds may be invalid at this point */

    if (eloop_sock_table_dispatch_table(writers, pollfds_map,
                        max_pollfd_map, POLLOUT))
        return; /* pollfds may be invalid at this point */

    eloop_sock_table_dispatch_table(exceptions, pollfds_map,
                    max_pollfd_map, POLLERR | POLLHUP);
}

#endif /* CONFIG_ELOOP_POLL */

#ifdef CONFIG_ELOOP_SELECT

static void eloop_sock_table_set_fds(struct eloop_sock_table *table,
                     fd_set *fds)
{
    int i;

    FD_ZERO(fds);

    if (table->table == NULL)
        return;

    for (i = 0; i < table->count; i++) {
        assert(table->table[i].sock >= 0);
        FD_SET(table->table[i].sock, fds);
    }
}


static void eloop_sock_table_dispatch(struct eloop_sock_table *table,
                      fd_set *fds)
{
    int i;

    if (table == NULL || table->table == NULL)
        return;

    table->changed = 0;
    for (i = 0; i < table->count; i++) {
        if (FD_ISSET((long unsigned int)table->table[i].sock, fds)) {
            table->table[i].handler(table->table[i].sock,
                        table->table[i].eloop_data,
                        table->table[i].user_data);
            if (table->changed)
                break;
        }
    }
}

#endif /* CONFIG_ELOOP_SELECT */


#ifdef CONFIG_ELOOP_EPOLL
static void eloop_sock_table_dispatch(struct epoll_event *events, int nfds)
{
    struct eloop_sock *table;
    int i;

    for (i = 0; i < nfds; i++) {
        table = &eloop.epoll_table[events[i].data.fd];
        if (table->handler == NULL)
            continue;
        table->handler(table->sock, table->eloop_data,
                   table->user_data);
    }
}
#endif /* CONFIG_ELOOP_EPOLL */


static void eloop_sock_table_destroy(struct eloop_sock_table *table)
{
    if (table) {
        int i;
        for (i = 0; i < table->count && table->table; i++) {
            wpa_printf(MSG_INFO, "ELOOP: remaining socket: "
                   "sock=%d eloop_data=%p user_data=%p "
                   "handler=%p",
                   table->table[i].sock,
                   table->table[i].eloop_data,
                   table->table[i].user_data,
                   table->table[i].handler);
//            wpa_trace_dump_funcname("eloop unregistered socket ""handler", table->table[i].handler);
//            wpa_trace_dump("eloop sock", &table->table[i]);
        }
        os_free(table->table);
    }
}


int eloop_register_read_sock(int sock, eloop_sock_handler handler,
                 void *eloop_data, void *user_data)
{
    return eloop_register_sock(sock, EVENT_TYPE_READ, handler,
                   eloop_data, user_data);
}


void eloop_unregister_read_sock(int sock)
{
    eloop_unregister_sock(sock, EVENT_TYPE_READ);
}


static struct eloop_sock_table *eloop_get_sock_table(eloop_event_type type)
{
    switch (type) {
    case EVENT_TYPE_READ:
        return &eloop.readers;
    case EVENT_TYPE_WRITE:
        return &eloop.writers;
    case EVENT_TYPE_EXCEPTION:
        return &eloop.exceptions;
    }

    return NULL;
}


int eloop_register_sock(int sock, eloop_event_type type,
            eloop_sock_handler handler,
            void *eloop_data, void *user_data)
{
    struct eloop_sock_table *table;

    assert(sock >= 0);
    table = eloop_get_sock_table(type);
    return eloop_sock_table_add_sock(table, sock, handler,
                     eloop_data, user_data);
}


void eloop_unregister_sock(int sock, eloop_event_type type)
{
    struct eloop_sock_table *table;

    table = eloop_get_sock_table(type);
    eloop_sock_table_remove_sock(table, sock);
}


int eloop_register_timeout(unsigned int secs, unsigned int usecs,
               eloop_timeout_handler handler,
               void *eloop_data, void *user_data)
{
    struct eloop_timeout *timeout, *tmp;
    os_time_t now_sec;

    timeout = os_zalloc(sizeof(*timeout));
    if (timeout == NULL)
        return -1;
    if (os_get_reltime(&timeout->time) < 0) {
        os_free(timeout);
        return -1;
    }
    now_sec = timeout->time.sec;
    timeout->time.sec += (int)secs;
    if (timeout->time.sec < now_sec) {
        /*
         * Integer overflow - assume long enough timeout to be assumed
         * to be infinite, i.e., the timeout would never happen.
         */
        wpa_printf(MSG_DEBUG, "ELOOP: Too long timeout (secs=%u) to "
               "ever happen - ignore it", secs);
        os_free(timeout);
        return 0;
    }
    timeout->time.usec += (int)usecs;
    while (timeout->time.usec >= 1000000) {
        timeout->time.sec++;
        timeout->time.usec -= 1000000;
    }
    timeout->eloop_data = eloop_data;
    timeout->user_data = user_data;
    timeout->handler = handler;
//    wpa_trace_add_ref(timeout, eloop, eloop_data);
//    wpa_trace_add_ref(timeout, user, user_data);
//    wpa_trace_record(timeout);

    /* Maintain timeouts in order of increasing time */
    dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
        if (os_reltime_before(&timeout->time, &tmp->time)) {

            dl_list_add(tmp->list.prev, &timeout->list);
            return 0;
        }
    }

    dl_list_add_tail(&eloop.timeout, &timeout->list);

    return 0;
}


static void eloop_remove_timeout(struct eloop_timeout *timeout)
{
    dl_list_del(&timeout->list);
//    wpa_trace_remove_ref(timeout, eloop, timeout->eloop_data);
//    wpa_trace_remove_ref(timeout, user, timeout->user_data);
    os_free(timeout);
}


int eloop_cancel_timeout(eloop_timeout_handler handler,
             void *eloop_data, void *user_data)
{
    struct eloop_timeout *timeout, *prev;
    int removed = 0;

    dl_list_for_each_safe(timeout, prev, &eloop.timeout,
                  struct eloop_timeout, list) {
        if (timeout->handler == handler &&
            (timeout->eloop_data == eloop_data ||
             eloop_data == ELOOP_ALL_CTX) &&
            (timeout->user_data == user_data ||
             user_data == ELOOP_ALL_CTX)) {
            eloop_remove_timeout(timeout);
            removed++;
        }
    }

    return removed;
}


int eloop_cancel_timeout_one(eloop_timeout_handler handler,
                 void *eloop_data, void *user_data,
                 struct os_reltime *remaining)
{
    struct eloop_timeout *timeout, *prev;
    int removed = 0;
    struct os_reltime now;

    os_get_reltime(&now);
    remaining->sec = remaining->usec = 0;

    dl_list_for_each_safe(timeout, prev, &eloop.timeout,
                  struct eloop_timeout, list) {
        if (timeout->handler == handler &&
            (timeout->eloop_data == eloop_data) &&
            (timeout->user_data == user_data)) {
            removed = 1;
            if (os_reltime_before(&now, &timeout->time))
                os_reltime_sub(&timeout->time, &now, remaining);
            eloop_remove_timeout(timeout);
            break;
        }
    }
    return removed;
}


int eloop_is_timeout_registered(eloop_timeout_handler handler,
                void *eloop_data, void *user_data)
{
    struct eloop_timeout *tmp;

    dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
        if (tmp->handler == handler &&
            tmp->eloop_data == eloop_data &&
            tmp->user_data == user_data)
            return 1;
    }

    return 0;
}


int eloop_deplete_timeout(unsigned int req_secs, unsigned int req_usecs,
              eloop_timeout_handler handler, void *eloop_data,
              void *user_data)
{
    struct os_reltime now, requested, remaining;
    struct eloop_timeout *tmp;

    dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
        if (tmp->handler == handler &&
            tmp->eloop_data == eloop_data &&
            tmp->user_data == user_data) {
            requested.sec = (int)req_secs;
            requested.usec = (int)req_usecs;
            os_get_reltime(&now);
            os_reltime_sub(&tmp->time, &now, &remaining);
            if (os_reltime_before(&requested, &remaining)) {
                eloop_cancel_timeout(handler, eloop_data,
                             user_data);
                eloop_register_timeout((unsigned int)requested.sec,
                               (unsigned int)requested.usec,
                               handler, eloop_data,
                               user_data);
                return 1;
            }
            return 0;
        }
    }

    return -1;
}


int eloop_replenish_timeout(unsigned int req_secs, unsigned int req_usecs,
                eloop_timeout_handler handler, void *eloop_data,
                void *user_data)
{
    struct os_reltime now, requested, remaining;
    struct eloop_timeout *tmp;

    dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
        if (tmp->handler == handler &&
            tmp->eloop_data == eloop_data &&
            tmp->user_data == user_data) {
            requested.sec = (int)req_secs;
            requested.usec = (int)req_usecs;
            os_get_reltime(&now);
            os_reltime_sub(&tmp->time, &now, &remaining);
            if (os_reltime_before(&remaining, &requested)) {
                eloop_cancel_timeout(handler, eloop_data,
                             user_data);
                eloop_register_timeout((unsigned int)requested.sec,
                               (unsigned int)requested.usec,
                               handler, eloop_data,
                               user_data);
                return 1;
            }
            return 0;
        }
    }

    return -1;
}


static void eloop_handle_alarm(int sig)
{
    wpa_printf(MSG_ERROR, "eloop: could not process SIGINT or SIGTERM in "
           "two seconds. Looks like there\n"
           "is a bug that ends up in a busy loop that "
           "prevents clean shutdown.\n"
           "Killing program forcefully.\n");
    exit(1);
}


static void eloop_handle_signal(int sig)
{
    int i;

    if ((sig == SIGINT || sig == SIGTERM) && !eloop.pending_terminate) {
        /* Use SIGALRM to break out from potential busy loops that
         * would not allow the program to be killed. */
        eloop.pending_terminate = 1;
        signal(SIGALRM, eloop_handle_alarm);
        alarm(2);
    }

    eloop.signaled++;
    for (i = 0; i < eloop.signal_count; i++) {
        if (eloop.signals[i].sig == sig) {
            eloop.signals[i].signaled++;
            break;
        }
    }
}


static void eloop_process_pending_signals(void)
{
    int i;

    if (eloop.signaled == 0)
        return;
    eloop.signaled = 0;

    if (eloop.pending_terminate) {
        alarm(0);
        eloop.pending_terminate = 0;
    }

    for (i = 0; i < eloop.signal_count; i++) {
        if (eloop.signals[i].signaled) {
            eloop.signals[i].signaled = 0;
            eloop.signals[i].handler(eloop.signals[i].sig,
                         eloop.signals[i].user_data);
        }
    }
}


int eloop_register_signal(int sig, eloop_signal_handler handler,
              void *user_data)
{
    struct eloop_signal *tmp;

    tmp = os_realloc_array(eloop.signals, (size_t)(eloop.signal_count + 1),
                   sizeof(struct eloop_signal));
    if (tmp == NULL)
        return -1;

    tmp[eloop.signal_count].sig = sig;
    tmp[eloop.signal_count].user_data = user_data;
    tmp[eloop.signal_count].handler = handler;
    tmp[eloop.signal_count].signaled = 0;
    eloop.signal_count++;
    eloop.signals = tmp;
    signal(sig, eloop_handle_signal);

    return 0;
}


int eloop_register_signal_terminate(eloop_signal_handler handler,
                    void *user_data)
{
    int ret = eloop_register_signal(SIGINT, handler, user_data);
    if (ret == 0)
        ret = eloop_register_signal(SIGTERM, handler, user_data);
    return ret;
}


int eloop_register_signal_reconfig(eloop_signal_handler handler,
                   void *user_data)
{
    return eloop_register_signal(SIGHUP, handler, user_data);
}


void eloop_run(void)
{
#ifdef CONFIG_ELOOP_POLL
    int num_poll_fds;
    int timeout_ms = 0;
#endif /* CONFIG_ELOOP_POLL */
#ifdef CONFIG_ELOOP_SELECT
    fd_set *rfds, *wfds, *efds;
    struct timeval _tv;
#endif /* CONFIG_ELOOP_SELECT */
#ifdef CONFIG_ELOOP_EPOLL
    int timeout_ms = -1;
#endif /* CONFIG_ELOOP_EPOLL */
    int res;
    struct os_reltime tv, now;

#ifdef CONFIG_ELOOP_SELECT
    rfds = os_malloc(sizeof(*rfds));
    wfds = os_malloc(sizeof(*wfds));
    efds = os_malloc(sizeof(*efds));
    if (rfds == NULL || wfds == NULL || efds == NULL)
        goto out;
#endif /* CONFIG_ELOOP_SELECT */

    while (!eloop.terminate &&
           (!dl_list_empty(&eloop.timeout) || eloop.readers.count > 0 ||
        eloop.writers.count > 0 || eloop.exceptions.count > 0)) {
        struct eloop_timeout *timeout;
        timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
                    list);
        if (timeout) {
            os_get_reltime(&now);
            if (os_reltime_before(&now, &timeout->time))
                os_reltime_sub(&timeout->time, &now, &tv);
            else
                tv.sec = tv.usec = 0;
#if defined(CONFIG_ELOOP_POLL) || defined(CONFIG_ELOOP_EPOLL)
            timeout_ms = tv.sec * 1000 + tv.usec / 1000;
#endif /* defined(CONFIG_ELOOP_POLL) || defined(CONFIG_ELOOP_EPOLL) */
#ifdef CONFIG_ELOOP_SELECT
            _tv.tv_sec = tv.sec;
            _tv.tv_usec = tv.usec;
#endif /* CONFIG_ELOOP_SELECT */
        }

#ifdef CONFIG_ELOOP_POLL
        num_poll_fds = eloop_sock_table_set_fds(
            &eloop.readers, &eloop.writers, &eloop.exceptions,
            eloop.pollfds, eloop.pollfds_map,
            eloop.max_pollfd_map);
        res = poll(eloop.pollfds, (nfds_t)num_poll_fds,
               timeout ? timeout_ms : -1);
#endif /* CONFIG_ELOOP_POLL */
#ifdef CONFIG_ELOOP_SELECT
        eloop_sock_table_set_fds(&eloop.readers, rfds);
        eloop_sock_table_set_fds(&eloop.writers, wfds);
        eloop_sock_table_set_fds(&eloop.exceptions, efds);
        res = select(eloop.max_sock + 1, rfds, wfds, efds,
                 timeout ? &_tv : NULL);

#endif /* CONFIG_ELOOP_SELECT */
#ifdef CONFIG_ELOOP_EPOLL
        if (eloop.count == 0) {
            res = 0;
        } else {
            res = epoll_wait(eloop.epollfd, eloop.epoll_events,
                     eloop.count, timeout_ms);
        }
#endif /* CONFIG_ELOOP_EPOLL */
        if (res < 0 && errno != EINTR && errno != 0) {
            wpa_printf(MSG_ERROR, "eloop: %s: %s",
#ifdef CONFIG_ELOOP_POLL
                   "poll"
#endif /* CONFIG_ELOOP_POLL */
#ifdef CONFIG_ELOOP_SELECT
                   "select"
#endif /* CONFIG_ELOOP_SELECT */
#ifdef CONFIG_ELOOP_EPOLL
                   "epoll"
#endif /* CONFIG_ELOOP_EPOLL */
                   , strerror(errno));
            goto out;
        }
        eloop_process_pending_signals();

        /* check if some registered timeouts have occurred */
        timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
                    list);
        if (timeout) {
            os_get_reltime(&now);
            if (!os_reltime_before(&now, &timeout->time)) {
                void *eloop_data = timeout->eloop_data;
                void *user_data = timeout->user_data;
                eloop_timeout_handler handler =
                    timeout->handler;
                eloop_remove_timeout(timeout);
                handler(eloop_data, user_data);
            }

        }

        if (res <= 0)
            continue;

#ifdef CONFIG_ELOOP_POLL
        eloop_sock_table_dispatch(&eloop.readers, &eloop.writers,
                      &eloop.exceptions, eloop.pollfds_map,
                      eloop.max_pollfd_map);
#endif /* CONFIG_ELOOP_POLL */
#ifdef CONFIG_ELOOP_SELECT
        eloop_sock_table_dispatch(&eloop.readers, rfds);
        eloop_sock_table_dispatch(&eloop.writers, wfds);
        eloop_sock_table_dispatch(&eloop.exceptions, efds);
#endif /* CONFIG_ELOOP_SELECT */
#ifdef CONFIG_ELOOP_EPOLL
        eloop_sock_table_dispatch(eloop.epoll_events, res);
#endif /* CONFIG_ELOOP_EPOLL */
    }

    eloop.terminate = 0;
out:
#ifdef CONFIG_ELOOP_SELECT
    os_free(rfds);
    os_free(wfds);
    os_free(efds);
#endif /* CONFIG_ELOOP_SELECT */
    return;
}


void eloop_terminate(void)
{
    eloop.terminate = 1;
}


void eloop_destroy(void)
{
    struct eloop_timeout *timeout, *prev;
    struct os_reltime now;

    os_get_reltime(&now);
    dl_list_for_each_safe(timeout, prev, &eloop.timeout,
                  struct eloop_timeout, list) {
        int sec, usec;
        sec = (int)timeout->time.sec - (int)now.sec;
        usec = (int)timeout->time.usec - (int)now.usec;
        if (timeout->time.usec < now.usec) {
            sec--;
            usec += 1000000;
        }
        wpa_printf(MSG_INFO, "ELOOP: remaining timeout: %d.%06d "
               "eloop_data=%p user_data=%p handler=%p",
               sec, usec, timeout->eloop_data, timeout->user_data,
               timeout->handler);
//        wpa_trace_dump_funcname("eloop unregistered timeout handler", timeout->handler);
//        wpa_trace_dump("eloop timeout", timeout);
        eloop_remove_timeout(timeout);
    }
    eloop_sock_table_destroy(&eloop.readers);
    eloop_sock_table_destroy(&eloop.writers);
    eloop_sock_table_destroy(&eloop.exceptions);
    os_free(eloop.signals);

#ifdef CONFIG_ELOOP_POLL
    os_free(eloop.pollfds);
    os_free(eloop.pollfds_map);
#endif /* CONFIG_ELOOP_POLL */
#ifdef CONFIG_ELOOP_EPOLL
    os_free(eloop.epoll_table);
    os_free(eloop.epoll_events);
    close(eloop.epollfd);
#endif /* CONFIG_ELOOP_EPOLL */
}


int eloop_terminated(void)
{
    return eloop.terminate;
}


void eloop_wait_for_read_sock(int sock)
{
#ifdef CONFIG_ELOOP_POLL
    struct pollfd pfd;

    if (sock < 0)
        return;

    os_memset(&pfd, 0, sizeof(pfd));
    pfd.fd = sock;
    pfd.events = POLLIN;

    poll(&pfd, 1, -1);
#endif /* CONFIG_ELOOP_POLL */
#if defined(CONFIG_ELOOP_SELECT) || defined(CONFIG_ELOOP_EPOLL)
    /*
     * We can use epoll() here. But epoll() requres 4 system calls.
     * epoll_create1(), epoll_ctl() for ADD, epoll_wait, and close() for
     * epoll fd. So select() is better for performance here.
     */
    fd_set rfds;

    if (sock < 0)
        return;

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    select(sock + 1, &rfds, NULL, NULL, NULL);
#endif /* defined(CONFIG_ELOOP_SELECT) || defined(CONFIG_ELOOP_EPOLL) */
}

#ifdef CONFIG_ELOOP_SELECT
#undef CONFIG_ELOOP_SELECT
#endif /* CONFIG_ELOOP_SELECT */
