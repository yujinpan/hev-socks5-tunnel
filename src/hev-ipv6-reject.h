/*
 ============================================================================
 Name        : hev-ipv6-reject.h
 Author      : Aestate
 Copyright   : Copyright (c) 2026 Aestate
 Description : Reject IPv6 packets read from the tunnel
 ============================================================================
 */

#ifndef __HEV_IPV6_REJECT_H__
#define __HEV_IPV6_REJECT_H__

#include <stddef.h>
#include <stdint.h>

/* An ICMPv6 error never exceeds the IPv6 minimum MTU (RFC 4443 2.4 c). */
#define HEV_IPV6_REJECT_MAX_REPLY (1280)

/* Replies allowed per second; the bucket holds one second of burst. */
#define HEV_IPV6_REJECT_RATE (100)

typedef struct _HevIPv6RejectLimiter HevIPv6RejectLimiter;

struct _HevIPv6RejectLimiter
{
    uint64_t last_ms;
    uint32_t tokens;
};

/**
 * hev_ipv6_reject_build:
 * @packet: an IPv6 packet read from the tunnel
 * @len: length of @packet
 * @reply: buffer of at least HEV_IPV6_REJECT_MAX_REPLY bytes
 *
 * Builds the reply that makes the sender fail at once: a TCP RST for TCP,
 * ICMPv6 port unreachable for UDP, and ICMPv6 administratively prohibited
 * for echo requests and other upper layers.
 *
 * Returns: the reply length, or zero when the packet must be dropped
 * silently (RST, ICMPv6 other than echo request, fragments, multicast,
 * link-local, loopback or unspecified addresses, malformed packets).
 */
size_t hev_ipv6_reject_build (const uint8_t *packet, size_t len,
                              uint8_t *reply);

void hev_ipv6_reject_limiter_init (HevIPv6RejectLimiter *self,
                                   uint64_t now_ms);

/**
 * hev_ipv6_reject_limiter_take:
 *
 * Returns: non-zero when a reply may be sent at @now_ms.
 */
int hev_ipv6_reject_limiter_take (HevIPv6RejectLimiter *self,
                                  uint64_t now_ms);

#endif /* __HEV_IPV6_REJECT_H__ */
