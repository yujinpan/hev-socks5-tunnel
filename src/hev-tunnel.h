/*
 ============================================================================
 Name        : hev-tunnel.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2023 - 2025 hev
 Description : Tunnel
 ============================================================================
 */

#ifndef __HEV_TUNNEL_H__
#define __HEV_TUNNEL_H__

#include <lwip/pbuf.h>

#include "hev-tunnel-macos.h"

int hev_tunnel_open (const char *name);
void hev_tunnel_close (int fd);

int hev_tunnel_set_mtu (int mtu);
int hev_tunnel_set_state (int state);

int hev_tunnel_set_ipv4 (const char *addr, unsigned int prefix);

const char *hev_tunnel_get_name (void);
const char *hev_tunnel_get_index (void);

int hev_tunnel_add_task (int fd, HevTask *task);
void hev_tunnel_del_task (int fd, HevTask *task);

#endif /* __HEV_TUNNEL_H__ */
