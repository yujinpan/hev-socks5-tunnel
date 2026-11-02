/*
 ============================================================================
 Name        : hev-ipv6-reject.c
 Author      : Aestate
 Copyright   : Copyright (c) 2026 Aestate
 Description : Reject IPv6 packets read from the tunnel
 ============================================================================
 */

#include <string.h>

#include "hev-ipv6-reject.h"

#define IPV6_HEADER_LEN (40)
#define TCP_HEADER_LEN (20)
#define ICMPV6_HEADER_LEN (8)
#define HOP_LIMIT (64)

#define NEXT_HOP_BY_HOP (0)
#define NEXT_TCP (6)
#define NEXT_UDP (17)
#define NEXT_ROUTING (43)
#define NEXT_FRAGMENT (44)
#define NEXT_ICMPV6 (58)
#define NEXT_DEST_OPTS (60)

#define TCP_FIN (0x01)
#define TCP_SYN (0x02)
#define TCP_RST (0x04)
#define TCP_ACK (0x10)

#define ICMPV6_DEST_UNREACH (1)
#define ICMPV6_ADMIN_PROHIBITED (1)
#define ICMPV6_PORT_UNREACH (4)
#define ICMPV6_ECHO_REQUEST (128)

/* Bounds the extension header walk; real stacks send one or two. */
#define MAX_EXTENSION_HEADERS (8)

static uint32_t
read_be32 (const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           p[3];
}

static void
write_be16 (uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}

static void
write_be32 (uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static int
is_replyable_address (const uint8_t *a)
{
    static const uint8_t zero[15];

    if (a[0] == 0xff) /* multicast */
        return 0;
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) /* link-local */
        return 0;
    if (memcmp (a, zero, sizeof (zero)) == 0 && a[15] <= 1)
        return 0; /* unspecified or loopback */

    return 1;
}

static uint32_t
sum_words (uint32_t sum, const uint8_t *p, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)p[i] << 8 | p[i + 1];
    if (len & 1)
        sum += (uint32_t)p[len - 1] << 8;

    return sum;
}

/* Fills the upper-layer checksum at @reply + 40 + @offset over the IPv6
 * pseudo-header (RFC 8200 8.1); the field must be zero on entry. */
static void
fill_checksum (uint8_t *reply, size_t upper_len, uint8_t next,
               size_t offset)
{
    uint32_t sum;

    sum = sum_words (0, reply + 8, 32);
    sum += (uint32_t)(upper_len >> 16) + (uint32_t)(upper_len & 0xffff);
    sum += next;
    sum = sum_words (sum, reply + IPV6_HEADER_LEN, upper_len);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    write_be16 (reply + IPV6_HEADER_LEN + offset, ~sum);
}

static void
write_ipv6_header (uint8_t *reply, const uint8_t *packet, size_t upper_len,
                   uint8_t next)
{
    memset (reply, 0, IPV6_HEADER_LEN);
    reply[0] = 0x60;
    write_be16 (reply + 4, upper_len);
    reply[6] = next;
    reply[7] = HOP_LIMIT;
    memcpy (reply + 8, packet + 24, 16);
    memcpy (reply + 24, packet + 8, 16);
}

static size_t
build_tcp_reset (const uint8_t *packet, const uint8_t *tcp, size_t tcp_len,
                 uint8_t *reply)
{
    uint8_t *out = reply + IPV6_HEADER_LEN;
    size_t header_len;
    uint8_t flags;
    uint32_t ack;

    if (tcp_len < TCP_HEADER_LEN)
        return 0;
    header_len = (tcp[12] >> 4) * 4;
    if (header_len < TCP_HEADER_LEN || header_len > tcp_len)
        return 0;
    flags = tcp[13];
    if (flags & TCP_RST)
        return 0;

    write_ipv6_header (reply, packet, TCP_HEADER_LEN, NEXT_TCP);
    memset (out, 0, TCP_HEADER_LEN);
    memcpy (out, tcp + 2, 2);
    memcpy (out + 2, tcp, 2);
    out[12] = (TCP_HEADER_LEN / 4) << 4;

    /* RFC 9293 3.10.7.1: answer with SEQ = SEG.ACK when the segment has an
     * ACK, otherwise acknowledge everything it occupies. */
    if (flags & TCP_ACK) {
        memcpy (out + 4, tcp + 8, 4);
        out[13] = TCP_RST;
    } else {
        ack = read_be32 (tcp + 4) + (uint32_t)(tcp_len - header_len);
        ack += (flags & TCP_SYN) ? 1 : 0;
        ack += (flags & TCP_FIN) ? 1 : 0;
        write_be32 (out + 8, ack);
        out[13] = TCP_RST | TCP_ACK;
    }

    fill_checksum (reply, TCP_HEADER_LEN, NEXT_TCP, 16);

    return IPV6_HEADER_LEN + TCP_HEADER_LEN;
}

static size_t
build_icmpv6_error (const uint8_t *packet, size_t len, uint8_t code,
                    uint8_t *reply)
{
    uint8_t *out = reply + IPV6_HEADER_LEN;
    size_t quote;
    size_t upper_len;

    quote = HEV_IPV6_REJECT_MAX_REPLY - IPV6_HEADER_LEN - ICMPV6_HEADER_LEN;
    if (quote > len)
        quote = len;
    upper_len = ICMPV6_HEADER_LEN + quote;

    write_ipv6_header (reply, packet, upper_len, NEXT_ICMPV6);
    memset (out, 0, ICMPV6_HEADER_LEN);
    out[0] = ICMPV6_DEST_UNREACH;
    out[1] = code;
    memcpy (out + ICMPV6_HEADER_LEN, packet, quote);

    fill_checksum (reply, upper_len, NEXT_ICMPV6, 2);

    return IPV6_HEADER_LEN + upper_len;
}

size_t
hev_ipv6_reject_build (const uint8_t *packet, size_t len, uint8_t *reply)
{
    size_t offset = IPV6_HEADER_LEN;
    size_t payload_len;
    uint8_t next;
    int i;

    if (len < IPV6_HEADER_LEN || (packet[0] >> 4) != 6)
        return 0;
    payload_len = (size_t)packet[4] << 8 | packet[5];
    if (payload_len == 0 || IPV6_HEADER_LEN + payload_len != len)
        return 0;
    if (!is_replyable_address (packet + 8) ||
        !is_replyable_address (packet + 24))
        return 0;

    next = packet[6];
    for (i = 0; i < MAX_EXTENSION_HEADERS; i++) {
        if (next != NEXT_HOP_BY_HOP && next != NEXT_ROUTING &&
            next != NEXT_DEST_OPTS)
            break;
        if (offset + 8 > len)
            return 0;
        next = packet[offset];
        offset += ((size_t)packet[offset + 1] + 1) * 8;
        if (offset > len)
            return 0;
    }

    switch (next) {
    case NEXT_TCP:
        return build_tcp_reset (packet, packet + offset, len - offset,
                                reply);
    case NEXT_UDP:
        if (len - offset < 8)
            return 0;
        return build_icmpv6_error (packet, len, ICMPV6_PORT_UNREACH, reply);
    case NEXT_ICMPV6:
        /* Never answer errors (RFC 4443 2.4 e) or neighbor discovery. */
        if (len - offset < 8 || packet[offset] != ICMPV6_ECHO_REQUEST)
            return 0;
        return build_icmpv6_error (packet, len, ICMPV6_ADMIN_PROHIBITED,
                                   reply);
    case NEXT_FRAGMENT:
    case NEXT_HOP_BY_HOP:
    case NEXT_ROUTING:
    case NEXT_DEST_OPTS:
        return 0;
    default:
        return build_icmpv6_error (packet, len, ICMPV6_ADMIN_PROHIBITED,
                                   reply);
    }
}

void
hev_ipv6_reject_limiter_init (HevIPv6RejectLimiter *self, uint64_t now_ms)
{
    self->last_ms = now_ms;
    self->tokens = HEV_IPV6_REJECT_RATE;
}

int
hev_ipv6_reject_limiter_take (HevIPv6RejectLimiter *self, uint64_t now_ms)
{
    const uint64_t interval = 1000 / HEV_IPV6_REJECT_RATE;
    uint64_t refill;

    if (now_ms > self->last_ms) {
        refill = (now_ms - self->last_ms) / interval;
        if (refill >= HEV_IPV6_REJECT_RATE - self->tokens) {
            self->tokens = HEV_IPV6_REJECT_RATE;
            self->last_ms = now_ms;
        } else if (refill) {
            self->tokens += refill;
            self->last_ms += refill * interval;
        }
    }

    if (!self->tokens)
        return 0;

    self->tokens--;
    return 1;
}
