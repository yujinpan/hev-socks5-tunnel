/*
 ============================================================================
 Name        : ipv6-reject-test.c
 Author      : Aestate
 Copyright   : Copyright (c) 2026 Aestate
 Description : Tests for hev-ipv6-reject; run tests/ipv6-reject-test.sh
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "hev-ipv6-reject.h"

static int failures;
static FILE *pcap;

#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf (stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                \
        }                                                              \
    } while (0)

/* 2001:db8::1 -> 2001:db8::2; documentation prefix, never routed. */
static const uint8_t addr_a[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 };
static const uint8_t addr_b[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 2 };
static const uint8_t multicast[16] = { 0xff, 0x02, [15] = 1 };
static const uint8_t link_local[16] = { 0xfe, 0x80, [15] = 1 };
static const uint8_t unspecified[16] = { 0 };
static const uint8_t loopback[16] = { [15] = 1 };

static uint32_t
be32 (const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           p[3];
}

static size_t
packet (uint8_t *out, const uint8_t *src, const uint8_t *dst, uint8_t next,
        const uint8_t *upper, size_t upper_len)
{
    memset (out, 0, 40);
    out[0] = 0x60;
    out[4] = upper_len >> 8;
    out[5] = upper_len;
    out[6] = next;
    out[7] = 64;
    memcpy (out + 8, src, 16);
    memcpy (out + 24, dst, 16);
    memcpy (out + 40, upper, upper_len);
    return 40 + upper_len;
}

static size_t
tcp_segment (uint8_t *out, uint32_t seq, uint32_t ack, uint8_t flags,
             size_t data_len)
{
    memset (out, 0, 20 + data_len);
    out[0] = 0xc0; /* source port 49200 */
    out[1] = 0x30;
    out[3] = 80; /* destination port 80 */
    out[4] = seq >> 24;
    out[5] = seq >> 16;
    out[6] = seq >> 8;
    out[7] = seq;
    out[8] = ack >> 24;
    out[9] = ack >> 16;
    out[10] = ack >> 8;
    out[11] = ack;
    out[12] = 5 << 4;
    out[13] = flags;
    out[14] = 0xff;
    out[15] = 0xff;
    return 20 + data_len;
}

/* The one's-complement sum over pseudo-header and upper layer, including
 * the checksum field, must be 0xffff. */
static int
checksum_ok (const uint8_t *reply, size_t len)
{
    size_t upper_len = len - 40;
    uint32_t sum = 0;
    size_t i;

    for (i = 8; i < 40; i += 2)
        sum += (uint32_t)reply[i] << 8 | reply[i + 1];
    sum += (uint32_t)upper_len + reply[6];
    for (i = 40; i + 1 < len; i += 2)
        sum += (uint32_t)reply[i] << 8 | reply[i + 1];
    if (upper_len & 1)
        sum += (uint32_t)reply[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return sum == 0xffff;
}

static void
pcap_write (const uint8_t *data, size_t len)
{
    uint32_t record[4] = { 0, 0, (uint32_t)len, (uint32_t)len };

    if (!pcap)
        return;
    fwrite (record, sizeof (record), 1, pcap);
    fwrite (data, len, 1, pcap);
}

static void
check_reply_header (const uint8_t *reply, size_t len, uint8_t next)
{
    CHECK (reply[0] == 0x60);
    CHECK (((size_t)reply[4] << 8 | reply[5]) == len - 40);
    CHECK (reply[6] == next);
    CHECK (reply[7] == 64);
    CHECK (memcmp (reply + 8, addr_b, 16) == 0);
    CHECK (memcmp (reply + 24, addr_a, 16) == 0);
    CHECK (checksum_ok (reply, len));
    pcap_write (reply, len);
}

static void
test_tcp (void)
{
    uint8_t seg[64], pkt[128], reply[HEV_IPV6_REJECT_MAX_REPLY];
    size_t seg_len, len, n;

    /* SYN: RST|ACK acknowledging the SYN. */
    seg_len = tcp_segment (seg, 1000, 0, 0x02, 0);
    len = packet (pkt, addr_a, addr_b, 6, seg, seg_len);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 60);
    check_reply_header (reply, n, 6);
    CHECK (reply[40] == 0 && reply[41] == 80);
    CHECK (reply[42] == 0xc0 && reply[43] == 0x30);
    CHECK (be32 (reply + 44) == 0);
    CHECK (be32 (reply + 48) == 1001);
    CHECK (reply[52] == 0x50);
    CHECK (reply[53] == 0x14);
    CHECK (reply[54] == 0 && reply[55] == 0);

    /* Data with ACK: RST with SEQ = SEG.ACK and no ACK. */
    seg_len = tcp_segment (seg, 5000, 0x80000001u, 0x18, 10);
    len = packet (pkt, addr_a, addr_b, 6, seg, seg_len);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 60);
    check_reply_header (reply, n, 6);
    CHECK (be32 (reply + 44) == 0x80000001u);
    CHECK (be32 (reply + 48) == 0);
    CHECK (reply[53] == 0x04);

    /* SYN|FIN with data and no ACK: acknowledge data, SYN and FIN; the
     * sequence number wraps. */
    seg_len = tcp_segment (seg, 0xfffffffeu, 0, 0x03, 3);
    len = packet (pkt, addr_a, addr_b, 6, seg, seg_len);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 60);
    CHECK (be32 (reply + 48) == 3);
    CHECK (reply[53] == 0x14);

    /* RST is never answered. */
    seg_len = tcp_segment (seg, 1, 0, 0x04, 0);
    len = packet (pkt, addr_a, addr_b, 6, seg, seg_len);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);

    /* Data offset below 5 or past the segment. */
    seg_len = tcp_segment (seg, 1, 0, 0x02, 0);
    seg[12] = 4 << 4;
    len = packet (pkt, addr_a, addr_b, 6, seg, seg_len);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
    seg[12] = 6 << 4;
    len = packet (pkt, addr_a, addr_b, 6, seg, seg_len);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);

    /* Truncated TCP header. */
    len = packet (pkt, addr_a, addr_b, 6, seg, 19);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
}

static void
test_icmp_errors (void)
{
    uint8_t upper[1500], pkt[1600], reply[HEV_IPV6_REJECT_MAX_REPLY];
    size_t len, n;

    /* UDP: port unreachable quoting the whole packet. */
    memset (upper, 0xab, 16);
    upper[4] = 0;
    upper[5] = 16;
    len = packet (pkt, addr_a, addr_b, 17, upper, 16);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 48 + len);
    check_reply_header (reply, n, 58);
    CHECK (reply[40] == 1 && reply[41] == 4);
    CHECK (be32 (reply + 44) == 0);
    CHECK (memcmp (reply + 48, pkt, len) == 0);

    /* Large UDP: the reply stops at 1280 bytes. */
    memset (upper, 0x5a, 1400);
    len = packet (pkt, addr_a, addr_b, 17, upper, 1400);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == HEV_IPV6_REJECT_MAX_REPLY);
    check_reply_header (reply, n, 58);
    CHECK (memcmp (reply + 48, pkt, n - 48) == 0);

    /* Short UDP header. */
    len = packet (pkt, addr_a, addr_b, 17, upper, 7);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);

    /* Echo request: administratively prohibited. */
    memset (upper, 0, 16);
    upper[0] = 128;
    len = packet (pkt, addr_a, addr_b, 58, upper, 16);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 48 + len);
    check_reply_header (reply, n, 58);
    CHECK (reply[40] == 1 && reply[41] == 1);

    /* ICMPv6 errors, echo replies and neighbor discovery are dropped. */
    upper[0] = 1;
    len = packet (pkt, addr_a, addr_b, 58, upper, 16);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
    upper[0] = 129;
    len = packet (pkt, addr_a, addr_b, 58, upper, 16);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
    upper[0] = 135;
    len = packet (pkt, addr_a, addr_b, 58, upper, 24);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);

    /* Other upper layers (SCTP): administratively prohibited. */
    len = packet (pkt, addr_a, addr_b, 132, upper, 12);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 48 + len);
    check_reply_header (reply, n, 58);
    CHECK (reply[40] == 1 && reply[41] == 1);
}

static void
test_extension_headers (void)
{
    uint8_t upper[128], pkt[256], reply[HEV_IPV6_REJECT_MAX_REPLY];
    size_t len, n;

    /* Hop-by-hop (8 bytes) then TCP SYN. */
    memset (upper, 0, sizeof (upper));
    upper[0] = 6;
    tcp_segment (upper + 8, 42, 0, 0x02, 0);
    len = packet (pkt, addr_a, addr_b, 0, upper, 28);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 60);
    check_reply_header (reply, n, 6);
    CHECK (be32 (reply + 48) == 43);

    /* Destination options (16 bytes) then UDP. */
    memset (upper, 0, sizeof (upper));
    upper[0] = 17;
    upper[1] = 1;
    len = packet (pkt, addr_a, addr_b, 60, upper, 24);
    n = hev_ipv6_reject_build (pkt, len, reply);
    CHECK (n == 48 + len);
    CHECK (reply[41] == 4);

    /* Fragments are dropped, also behind another extension header. */
    len = packet (pkt, addr_a, addr_b, 44, upper, 24);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
    memset (upper, 0, sizeof (upper));
    upper[0] = 44;
    len = packet (pkt, addr_a, addr_b, 0, upper, 24);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);

    /* Extension header longer than the packet. */
    upper[0] = 6;
    upper[1] = 4;
    len = packet (pkt, addr_a, addr_b, 0, upper, 24);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);

    /* Truncated extension header. */
    len = packet (pkt, addr_a, addr_b, 43, upper, 4);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);

    /* A chain longer than the walk limit. */
    memset (upper, 0, sizeof (upper));
    for (n = 0; n < 9; n++)
        upper[n * 8] = 60;
    len = packet (pkt, addr_a, addr_b, 60, upper, 96);
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
}

static void
test_addresses_and_framing (void)
{
    const uint8_t *bad[] = { multicast, link_local, unspecified, loopback };
    uint8_t seg[64], pkt[128], reply[HEV_IPV6_REJECT_MAX_REPLY];
    size_t seg_len, len;
    size_t i;

    seg_len = tcp_segment (seg, 1, 0, 0x02, 0);
    for (i = 0; i < sizeof (bad) / sizeof (bad[0]); i++) {
        len = packet (pkt, bad[i], addr_b, 6, seg, seg_len);
        CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
        len = packet (pkt, addr_a, bad[i], 6, seg, seg_len);
        CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
    }

    len = packet (pkt, addr_a, addr_b, 6, seg, seg_len);
    CHECK (hev_ipv6_reject_build (pkt, 39, reply) == 0);
    CHECK (hev_ipv6_reject_build (pkt, len - 1, reply) == 0);
    pkt[0] = 0x45;
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
    pkt[0] = 0x60;
    pkt[4] = 0;
    pkt[5] = 0; /* jumbogram */
    CHECK (hev_ipv6_reject_build (pkt, len, reply) == 0);
}

static void
test_limiter (void)
{
    HevIPv6RejectLimiter limiter;
    int i, allowed;

    hev_ipv6_reject_limiter_init (&limiter, 5000);
    for (i = 0, allowed = 0; i < 150; i++)
        allowed += hev_ipv6_reject_limiter_take (&limiter, 5000);
    CHECK (allowed == HEV_IPV6_REJECT_RATE);

    /* One token per 10 ms, and partial intervals carry over. */
    CHECK (hev_ipv6_reject_limiter_take (&limiter, 5009) == 0);
    CHECK (hev_ipv6_reject_limiter_take (&limiter, 5010) == 1);
    CHECK (hev_ipv6_reject_limiter_take (&limiter, 5015) == 0);
    CHECK (hev_ipv6_reject_limiter_take (&limiter, 5021) == 1);
    CHECK (hev_ipv6_reject_limiter_take (&limiter, 5021) == 0);

    /* A clock that goes back never refills. */
    CHECK (hev_ipv6_reject_limiter_take (&limiter, 100) == 0);

    /* After a quiet second the burst is full again, but not larger. */
    for (i = 0, allowed = 0; i < 150; i++)
        allowed += hev_ipv6_reject_limiter_take (&limiter, 9000);
    CHECK (allowed == HEV_IPV6_REJECT_RATE);
}

int
main (int argc, char *argv[])
{
    if (argc > 1) {
        /* pcap header, LINKTYPE_RAW */
        const uint32_t header[6] = { 0xa1b2c3d4, 0x00040002, 0, 0, 65535,
                                     101 };

        pcap = fopen (argv[1], "wb");
        if (!pcap)
            return 2;
        fwrite (header, sizeof (header), 1, pcap);
    }

    test_tcp ();
    test_icmp_errors ();
    test_extension_headers ();
    test_addresses_and_framing ();
    test_limiter ();

    if (pcap)
        fclose (pcap);

    if (failures) {
        fprintf (stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf ("ipv6-reject: all checks passed\n");
    return 0;
}
