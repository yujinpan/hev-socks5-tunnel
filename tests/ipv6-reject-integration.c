/*
 ============================================================================
 Name        : ipv6-reject-integration.c
 Author      : Aestate
 Copyright   : Copyright (c) 2026 Aestate
 Description : Runs the tunnel on a datagram socketpair standing in for utun
               and checks the IPv6 replies; run tests/ipv6-reject-test.sh
 ============================================================================
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "hev-main.h"

static int failures;

#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf (stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                \
        }                                                              \
    } while (0)

static const uint8_t addr_tun[16] = { 0xfd, 0x6a, 0xae, 0x57, [15] = 1 };
static const uint8_t addr_remote[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 2 };
static const uint8_t multicast[16] = { 0xff, 0x02, [15] = 1 };

static int tun_fd;

static void *
run_tunnel (void *data __attribute__ ((unused)))
{
    HevSocks5TunnelConfig config = { 0 };
    static int res;

    config.socks5_address = "127.0.0.1";
    config.socks5_port = 9; /* never dialed: IPv6 does not reach lwIP */
    config.tunnel_mtu = 1500;
    config.log_level = "error";
    res = hev_socks5_tunnel_main (&config, tun_fd);

    return &res;
}

/* Sends a utun frame: 4-byte address family, then the IPv6 packet. */
static void
send_ipv6 (int fd, const uint8_t *dst, uint8_t next, const uint8_t *upper,
           size_t upper_len)
{
    uint8_t frame[4 + 40 + 64];
    uint32_t family = htonl (AF_INET6);

    memcpy (frame, &family, 4);
    memset (frame + 4, 0, 40);
    frame[4] = 0x60;
    frame[8] = upper_len >> 8;
    frame[9] = upper_len;
    frame[10] = next;
    frame[11] = 64;
    memcpy (frame + 12, addr_tun, 16);
    memcpy (frame + 28, dst, 16);
    memcpy (frame + 44, upper, upper_len);
    CHECK (send (fd, frame, 44 + upper_len, 0) == (ssize_t)(44 + upper_len));
}

static ssize_t
receive (int fd, uint8_t *buf, size_t size, int timeout_ms)
{
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };

    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
    return recv (fd, buf, size, 0);
}

static void
send_syn (int fd, const uint8_t *dst, uint16_t port)
{
    uint8_t tcp[20] = { 0xc0, 0x30, port >> 8, port, 0, 0, 0x03, 0xe8 };

    tcp[12] = 5 << 4;
    tcp[13] = 0x02;
    send_ipv6 (fd, dst, 6, tcp, sizeof (tcp));
}

int
main (void)
{
    uint8_t buf[2048];
    uint32_t family;
    pthread_t thread;
    size_t replied, dropped;
    int sv[2];
    ssize_t n;
    int i, flood;

    CHECK (socketpair (AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    /* Room for the whole burst, so only the limiter decides what is lost. */
    for (i = 0; i < 2; i++) {
        int size = 1 << 20;

        setsockopt (sv[i], SOL_SOCKET, SO_SNDBUF, &size, sizeof (size));
        setsockopt (sv[i], SOL_SOCKET, SO_RCVBUF, &size, sizeof (size));
    }
    tun_fd = sv[1];
    pthread_create (&thread, NULL, run_tunnel, NULL);

    /* TCP SYN: RST|ACK in an AF_INET6 frame. */
    send_syn (sv[0], addr_remote, 443);
    n = receive (sv[0], buf, sizeof (buf), 2000);
    CHECK (n == 4 + 60);
    memcpy (&family, buf, 4);
    CHECK (ntohl (family) == AF_INET6);
    CHECK (buf[4 + 6] == 6);
    CHECK (memcmp (buf + 4 + 8, addr_remote, 16) == 0);
    CHECK (memcmp (buf + 4 + 24, addr_tun, 16) == 0);
    CHECK (buf[4 + 40] == 0x01 && buf[4 + 41] == 0xbb);
    CHECK (buf[4 + 53] == 0x14);

    /* UDP: ICMPv6 port unreachable quoting the datagram. */
    {
        uint8_t udp[12] = { 0xd4, 0x31, 0x00, 0x35, 0x00, 0x0c };

        send_ipv6 (sv[0], addr_remote, 17, udp, sizeof (udp));
        n = receive (sv[0], buf, sizeof (buf), 2000);
        CHECK (n == 4 + 48 + 52);
        CHECK (buf[4 + 6] == 58);
        CHECK (buf[4 + 40] == 1 && buf[4 + 41] == 4);
    }

    /* Multicast destination: no reply. */
    send_syn (sv[0], multicast, 443);
    n = receive (sv[0], buf, sizeof (buf), 300);
    CHECK (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

    /* A burst beyond the bucket is limited; 2 tokens are already used. */
    for (i = 0; i < 300; i++)
        send_syn (sv[0], addr_remote, 80);
    for (flood = 0; receive (sv[0], buf, sizeof (buf), 300) > 0; flood++)
        ;
    CHECK (flood >= 90 && flood <= 110);

    hev_socks5_tunnel_quit ();
    pthread_join (thread, NULL);

    /* Counters cover the run and stay readable after it returns. */
    hev_socks5_tunnel_ipv6_stats (&replied, &dropped);
    CHECK (replied == (size_t)(2 + flood));
    CHECK (dropped == (size_t)(1 + 300 - flood));

    if (failures) {
        fprintf (stderr, "%d check(s) failed (burst replies %d, replied %zu, "
                 "dropped %zu)\n", failures, flood, replied, dropped);
        return 1;
    }

    printf ("ipv6-reject integration: all checks passed (burst replies %d, "
            "replied %zu, dropped %zu)\n", flood, replied, dropped);
    return 0;
}
