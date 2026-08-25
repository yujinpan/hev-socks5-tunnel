/*
 ============================================================================
 Name        : hev-config.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2024 hev
 Description : Config
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <lwip/tcp.h>

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-config-const.h"

static char tun_name[64];
static unsigned int tun_mtu;
static char tun_ipv4_address[16];

static HevConfigServer srv;

static char log_file[1024];
static int max_session_count;
static int task_stack_size;
static int tcp_buffer_size;
static int udp_recv_buffer_size;
static int udp_copy_buffer_nums;
static int connect_timeout;
static int tcp_read_write_timeout;
static int udp_read_write_timeout;
static int log_level;

static int
parse_log_level (const char *value)
{
    if (!value)
        return HEV_LOGGER_WARN;
    if (0 == strcmp (value, "debug"))
        return HEV_LOGGER_DEBUG;
    if (0 == strcmp (value, "info"))
        return HEV_LOGGER_INFO;
    if (0 == strcmp (value, "error"))
        return HEV_LOGGER_ERROR;

    return HEV_LOGGER_WARN;
}

int
hev_config_init (const HevSocks5TunnelConfig *config)
{
    int min_task_stack_size;
    int udp_buffer_size;

    if (!config || !config->socks5_address || !config->socks5_port) {
        fprintf (stderr, "socks5_address and socks5_port are required\n");
        return -1;
    }

    memset (tun_name, 0, sizeof (tun_name));
    memset (tun_ipv4_address, 0, sizeof (tun_ipv4_address));
    memset (log_file, 0, sizeof (log_file));
    memset (&srv, 0, sizeof (srv));

    strncpy (srv.addr, config->socks5_address, sizeof (srv.addr) - 1);
    srv.port = config->socks5_port;
    if (config->socks5_udp_address)
        strncpy (srv.udp_addr, config->socks5_udp_address,
                 sizeof (srv.udp_addr) - 1);

    if (config->tunnel_name)
        strncpy (tun_name, config->tunnel_name, sizeof (tun_name) - 1);
    if (config->tunnel_ipv4)
        strncpy (tun_ipv4_address, config->tunnel_ipv4,
                 sizeof (tun_ipv4_address) - 1);

    tun_mtu = config->tunnel_mtu ? config->tunnel_mtu : 8500;
    max_session_count = config->max_session_count;
    task_stack_size = config->task_stack_size ? config->task_stack_size : 86016;
    tcp_buffer_size = config->tcp_buffer_size ? config->tcp_buffer_size : 65536;
    udp_recv_buffer_size = config->udp_recv_buffer_size ?
                               config->udp_recv_buffer_size :
                               524288;
    udp_copy_buffer_nums = config->udp_copy_buffer_nums ?
                               config->udp_copy_buffer_nums :
                               10;
    connect_timeout = config->connect_timeout ? config->connect_timeout : 10000;
    tcp_read_write_timeout = config->tcp_read_write_timeout ?
                                 config->tcp_read_write_timeout :
                                 300000;
    udp_read_write_timeout = config->udp_read_write_timeout ?
                                 config->udp_read_write_timeout :
                                 60000;
    log_level = parse_log_level (config->log_level);
    if (config->log_file)
        strncpy (log_file, config->log_file, sizeof (log_file) - 1);

    if (tcp_buffer_size > TCP_SND_BUF)
        tcp_buffer_size = TCP_SND_BUF;

    udp_buffer_size = UDP_BUF_SIZE * udp_copy_buffer_nums;

    if (tcp_buffer_size > udp_buffer_size)
        min_task_stack_size = TASK_STACK_SIZE + tcp_buffer_size;
    else
        min_task_stack_size = TASK_STACK_SIZE + udp_buffer_size;

    if (task_stack_size < min_task_stack_size)
        task_stack_size = min_task_stack_size;

    return 0;
}

const char *
hev_config_get_tunnel_name (void)
{
    if (!tun_name[0])
        return NULL;

    return tun_name;
}

unsigned int
hev_config_get_tunnel_mtu (void)
{
    return tun_mtu;
}

const char *
hev_config_get_tunnel_ipv4_address (void)
{
    if (!tun_ipv4_address[0])
        return NULL;

    return tun_ipv4_address;
}

HevConfigServer *
hev_config_get_socks5_server (void)
{
    return &srv;
}

int
hev_config_get_misc_task_stack_size (void)
{
    return task_stack_size;
}

int
hev_config_get_misc_tcp_buffer_size (void)
{
    return tcp_buffer_size;
}

int
hev_config_get_misc_udp_recv_buffer_size (void)
{
    return udp_recv_buffer_size;
}

int
hev_config_get_misc_udp_copy_buffer_nums (void)
{
    return udp_copy_buffer_nums;
}

int
hev_config_get_misc_max_session_count (void)
{
    return max_session_count;
}

int
hev_config_get_misc_connect_timeout (void)
{
    return connect_timeout;
}

int
hev_config_get_misc_tcp_read_write_timeout (void)
{
    return tcp_read_write_timeout;
}

int
hev_config_get_misc_udp_read_write_timeout (void)
{
    return udp_read_write_timeout;
}

const char *
hev_config_get_misc_log_file (void)
{
    if (!log_file[0])
        return NULL;
    if (0 == strcmp (log_file, "null"))
        return NULL;

    return log_file;
}

int
hev_config_get_misc_log_level (void)
{
    return log_level;
}
