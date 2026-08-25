/*
 ============================================================================
 Name        : hev-socks5-udp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 UDP
 ============================================================================
 */

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

#include "hev-socks5.h"
#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-udp.h"

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5 *self = data;

    if (self->type == HEV_SOCKS5_TYPE_UDP_IN_UDP) {
        ssize_t res;
        char buf;

        res = recv (self->fd, &buf, sizeof (buf), 0);
        if ((res == 0) || ((res < 0) && (errno != EAGAIN))) {
            hev_socks5_set_timeout (self, 0);
            return -1;
        }
    }

    return hev_socks5_task_io_yielder (type, data);
}

int
hev_socks5_udp_get_fd (HevSocks5UDP *self)
{
    HevSocks5UDPIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_UDP_TYPE);
    return iface->get_fd (self);
}

int
hev_socks5_udp_sendmmsg (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                         unsigned int num)
{
    struct iovec iov[num * 3];
    struct mmsghdr mvec[num];
    HevSocks5UDPHdr udp[num];
    int i, res;

    for (i = 0; i < num; i++) {
        int addrlen;

        addrlen = hev_socks5_addr_len (msgv[i].addr);
        if (addrlen <= 0) {
            LOG_D ("%p socks5 udp addr", self);
            return -1;
        }

        udp[i].datlen = 0;
        udp[i].hdrlen = 0;

        iov[i * 3].iov_base = &udp[i];
        iov[i * 3].iov_len = 3;
        iov[i * 3 + 1].iov_base = msgv[i].addr;
        iov[i * 3 + 1].iov_len = addrlen;
        iov[i * 3 + 2].iov_base = msgv[i].buf;
        iov[i * 3 + 2].iov_len = msgv[i].len;

        mvec[i].msg_hdr.msg_name = NULL;
        mvec[i].msg_hdr.msg_namelen = 0;
        mvec[i].msg_hdr.msg_control = NULL;
        mvec[i].msg_hdr.msg_controllen = 0;
        mvec[i].msg_hdr.msg_iov = &iov[i * 3];
        mvec[i].msg_hdr.msg_iovlen = 3;
    }

    res = hev_task_io_socket_sendmmsg (hev_socks5_udp_get_fd (self), mvec, num,
                                       MSG_WAITALL, task_io_yielder, self);
    if (res <= 0)
        LOG_D ("%p socks5 udp write udp", self);

    return res;
}

int
hev_socks5_udp_recvmmsg (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                         unsigned int num, int nonblock)
{
    struct sockaddr_in6 taddr;
    struct mmsghdr mvec[num];
    struct iovec iov[num];
    int i, fd, res;

    fd = hev_socks5_udp_get_fd (self);

    if (nonblock)
        nonblock = MSG_DONTWAIT;

    for (i = 0; i < num; i++) {
        mvec[i].msg_hdr.msg_name = NULL;
        mvec[i].msg_hdr.msg_namelen = 0;
        mvec[i].msg_hdr.msg_control = NULL;
        mvec[i].msg_hdr.msg_controllen = 0;
        mvec[i].msg_hdr.msg_iov = &iov[i];
        mvec[i].msg_hdr.msg_iovlen = 1;

        iov[i].iov_base = msgv[i].buf;
        iov[i].iov_len = msgv[i].len;
    }

    if (!HEV_SOCKS5 (self)->udp_associated) {
        mvec[0].msg_hdr.msg_name = &taddr;
        mvec[0].msg_hdr.msg_namelen = sizeof (taddr);
    }

    res = hev_task_io_socket_recvmmsg (fd, mvec, num, nonblock, task_io_yielder,
                                       self);
    if (res <= 0) {
        if (res != -1 || errno != EAGAIN)
            LOG_D ("%p socks5 udp read udp", self);
        return res;
    }

    if (!HEV_SOCKS5 (self)->udp_associated) {
        struct sockaddr *saddr = mvec[0].msg_hdr.msg_name;
        socklen_t alen = mvec[0].msg_hdr.msg_namelen;
        if (connect (fd, saddr, alen) < 0)
            return -1;
        HEV_SOCKS5 (self)->udp_associated = 1;
    }

    for (i = 0; i < res; i++) {
        HevSocks5UDPHdr *udp = msgv[i].buf;
        int addrlen = hev_socks5_addr_len (&udp->addr);
        int doff;

        msgv[i].len = mvec[i].msg_len;
        if (msgv[i].len < 4) {
            msgv[i].addr = NULL;
            msgv[i].len = 0;
            continue;
        }

        if (addrlen <= 0) {
            LOG_D ("%p socks5 udp addr", self);
            return -1;
        }

        doff = 3 + addrlen;
        if (doff > msgv[i].len) {
            LOG_D ("%p socks5 udp data len", self);
            return -1;
        }

        msgv[i].addr = &udp->addr;
        msgv[i].buf += doff;
        msgv[i].len -= doff;
    }

    return res;
}

void *
hev_socks5_udp_iface (void)
{
    static HevSocks5UDPIface type;

    return &type;
}
