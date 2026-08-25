/*
 ============================================================================
 Name        : hev-main.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Main
 ============================================================================
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <lwip/init.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-socks5-misc.h>

#include "hev-config.h"
#include "hev-config-const.h"
#include "hev-logger.h"
#include "hev-socks5-logger.h"
#include "hev-socks5-tunnel.h"

#include "hev-main.h"

static int
hev_socks5_tunnel_main_inner (int tun_fd)
{
    const char *log_file;
    int log_level;
    int res;

    log_file = hev_config_get_misc_log_file ();
    log_level = hev_config_get_misc_log_level ();

    res = hev_config_get_misc_connect_timeout ();
    hev_socks5_set_connect_timeout (res);
    res = hev_config_get_misc_tcp_read_write_timeout ();
    hev_socks5_set_tcp_timeout (res);
    res = hev_config_get_misc_udp_read_write_timeout ();
    hev_socks5_set_udp_timeout (res);

    res = hev_config_get_misc_udp_recv_buffer_size ();
    hev_socks5_set_udp_recv_buffer_size (res);

    res = hev_logger_init (log_level, log_file);
    if (res < 0)
        goto exit;

    res = hev_socks5_logger_init (log_level, log_file);
    if (res < 0)
        goto free_logger;

    res = hev_task_system_init ();
    if (res < 0)
        goto free_socks5_logger;

    lwip_init ();

    res = hev_socks5_tunnel_init (tun_fd);
    if (res < 0)
        goto free_task_sys;

    hev_socks5_tunnel_run ();

    hev_socks5_tunnel_fini ();

free_task_sys:
    hev_task_system_fini ();
free_socks5_logger:
    hev_socks5_logger_fini ();
free_logger:
    hev_logger_fini ();
exit:
    return res;
}

int
hev_socks5_tunnel_main (const HevSocks5TunnelConfig *config, int tun_fd)
{
    int res = hev_config_init (config);
    if (res < 0)
        return -1;

    return hev_socks5_tunnel_main_inner (tun_fd);
}

void
hev_socks5_tunnel_quit (void)
{
    hev_socks5_tunnel_stop ();
}

#ifndef ENABLE_LIBRARY
static void
show_help (const char *self_path)
{
    printf ("%s [-s ADDR] [-p PORT] [-n NAME] [-4 IPV4] [-m MTU]\n",
            self_path);
    printf ("Version: %u.%u.%u %s\n", MAJOR_VERSION, MINOR_VERSION,
            MICRO_VERSION, COMMIT_ID);
}

static void
sig_handler (int signum)
{
    hev_socks5_tunnel_stop ();
}

int
main (int argc, char *argv[])
{
    HevSocks5TunnelConfig config = { 0 };
    int res;
    int opt;

    config.socks5_address = "127.0.0.1";
    config.socks5_port = 1080;

    while ((opt = getopt (argc, argv, "s:p:n:4:m:h")) != -1) {
        switch (opt) {
        case 's':
            config.socks5_address = optarg;
            break;
        case 'p':
            config.socks5_port = (unsigned short)strtoul (optarg, NULL, 10);
            break;
        case 'n':
            config.tunnel_name = optarg;
            break;
        case '4':
            config.tunnel_ipv4 = optarg;
            break;
        case 'm':
            config.tunnel_mtu = (unsigned int)strtoul (optarg, NULL, 10);
            break;
        default:
            show_help (argv[0]);
            return -1;
        }
    }

    if (optind < argc && strcmp (argv[optind], "--version") == 0) {
        show_help (argv[0]);
        return -1;
    }

    signal (SIGINT, sig_handler);
    signal (SIGTERM, sig_handler);

    res = hev_socks5_tunnel_main (&config, -1);
    if (res < 0)
        return -2;

    return 0;
}
#endif /* ENABLE_LIBRARY */
