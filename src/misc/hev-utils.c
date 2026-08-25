/*
 ============================================================================
 Name        : hev-utils.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2023 hev
 Description : Utils
 ============================================================================
 */

#include <string.h>
#include <arpa/inet.h>

#include <hev-socks5-misc.h>

#include "hev-utils.h"

int
hev_socks5_addr_from_lwip (HevSocks5Addr *addr, const ip_addr_t *ip, u16_t port)
{
    hev_socks5_addr_from_ipv4 (addr, ip, htons (port));
    return 0;
}

int
hev_socks5_addr_into_lwip (const HevSocks5Addr *addr, ip_addr_t *ip,
                           u16_t *port)
{
    switch (addr->atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        memcpy (ip, addr->ipv4.addr, 4);
        *port = ntohs (addr->ipv4.port);
        return 0;
    default:
        return -1;
    }
}
