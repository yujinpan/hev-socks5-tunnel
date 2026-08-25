/*
 ============================================================================
 Name        : hev-main.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Main
 ============================================================================
 */

#ifndef __HEV_MAIN_H__
#define __HEV_MAIN_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HevSocks5TunnelConfig:
 *
 * Zero-initialized fields use built-in defaults. socks5_address and
 * socks5_port are required.
 */
typedef struct _HevSocks5TunnelConfig HevSocks5TunnelConfig;

struct _HevSocks5TunnelConfig
{
    const char *socks5_address;
    unsigned short socks5_port;
    const char *socks5_udp_address;

    const char *tunnel_name;
    unsigned int tunnel_mtu;
    const char *tunnel_ipv4;

    int task_stack_size;
    int tcp_buffer_size;
    int udp_recv_buffer_size;
    int udp_copy_buffer_nums;
    int max_session_count;
    int connect_timeout;
    int tcp_read_write_timeout;
    int udp_read_write_timeout;
    const char *log_file;
    const char *log_level;
};

/**
 * hev_socks5_tunnel_main:
 * @config: tunnel configuration
 * @tun_fd: tunnel file descriptor, or -1 to create one
 *
 * Start and run the socks5 tunnel. Blocks until hev_socks5_tunnel_quit
 * is called or an error occurs.
 *
 * Returns: zero on success, otherwise -1.
 */
int hev_socks5_tunnel_main (const HevSocks5TunnelConfig *config, int tun_fd);

/**
 * hev_socks5_tunnel_quit:
 *
 * Stop the socks5 tunnel.
 */
void hev_socks5_tunnel_quit (void);

/**
 * hev_socks5_tunnel_stats:
 *
 * Retrieve tunnel interface traffic statistics.
 */
void hev_socks5_tunnel_stats (size_t *tx_packets, size_t *tx_bytes,
                              size_t *rx_packets, size_t *rx_bytes);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_MAIN_H__ */
