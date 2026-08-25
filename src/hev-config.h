/*
 ============================================================================
 Name        : hev-config.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Config
 ============================================================================
 */

#ifndef __HEV_CONFIG_H__
#define __HEV_CONFIG_H__

#include "hev-main.h"

typedef struct _HevConfigServer HevConfigServer;

struct _HevConfigServer
{
    unsigned short port;
    char udp_addr[256];
    char addr[256];
};

int hev_config_init (const HevSocks5TunnelConfig *config);

const char *hev_config_get_tunnel_name (void);
unsigned int hev_config_get_tunnel_mtu (void);
const char *hev_config_get_tunnel_ipv4_address (void);

HevConfigServer *hev_config_get_socks5_server (void);

int hev_config_get_misc_task_stack_size (void);
int hev_config_get_misc_tcp_buffer_size (void);
int hev_config_get_misc_udp_recv_buffer_size (void);
int hev_config_get_misc_udp_copy_buffer_nums (void);
int hev_config_get_misc_max_session_count (void);
int hev_config_get_misc_connect_timeout (void);
int hev_config_get_misc_tcp_read_write_timeout (void);
int hev_config_get_misc_udp_read_write_timeout (void);
const char *hev_config_get_misc_log_file (void);
int hev_config_get_misc_log_level (void);

#endif /* __HEV_CONFIG_H__ */
