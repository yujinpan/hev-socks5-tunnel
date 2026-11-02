#!/bin/sh
# Builds and runs the IPv6 reject tests on the host with sanitizers, has
# tcpdump verify the TCP / ICMPv6 checksums of every generated reply, and runs
# the socketpair integration test when the XCFramework has been built.

set -eu
cd "$(dirname "$0")/.."

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

cc -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined \
   -Isrc tests/ipv6-reject-test.c src/hev-ipv6-reject.c -o "$out/test"
"$out/test" "$out/replies.pcap"

if command -v tcpdump >/dev/null 2>&1; then
    tcpdump -nn -S -vv -r "$out/replies.pcap" 2>/dev/null > "$out/decoded.txt"
    replies=$(grep -c '^.* IP6 ' "$out/decoded.txt" || true)
    correct=$(grep -cE 'cksum 0x[0-9a-f]+ \(correct\)|\[icmp6 sum ok\]' \
        "$out/decoded.txt" || true)
    if [ "$replies" -eq 0 ] || [ "$correct" -ne "$replies" ]; then
        cat "$out/decoded.txt"
        echo "tcpdump: $correct of $replies checksums correct" >&2
        exit 1
    fi
    echo "tcpdump: $correct of $replies checksums correct"
fi

# After ./build-apple.sh: drive the real tunnel loop of the macOS slice over a
# datagram socketpair standing in for utun.
slice=HevSocks5Tunnel-2.17.1-no-handshake-no-mapdns.xcframework/macos-arm64_x86_64
if [ -f "$slice/libhev-socks5-tunnel.a" ]; then
    cc -std=c11 -Wall -Wextra -Werror -I"$slice/Headers" \
       tests/ipv6-reject-integration.c "$slice/libhev-socks5-tunnel.a" \
       -lpthread -o "$out/integration" 2>&1 | grep -v 'reducing alignment' || true
    "$out/integration"
else
    echo "skip integration: run ./build-apple.sh first"
fi
