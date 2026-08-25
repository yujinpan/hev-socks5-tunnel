# HevSocks5Tunnel

[![status](https://github.com/heiher/hev-socks5-tunnel/actions/workflows/build.yaml/badge.svg?branch=main&event=push)](https://github.com/heiher/hev-socks5-tunnel)

A simple, lightweight tunnel over Socks5 proxy (tun2socks).

## Simplifications on this branch

Trimmed for an Apple local split-proxy: TUN traffic is forwarded to a local
SOCKS server.

- [x] Vendor `src/core` in-tree (no longer a submodule)
- [x] Vendor `third-part/lwip` in-tree (no longer a submodule; IPv4-only `LWIP_IPV6=0`)
- [x] Skip SOCKS5 authentication handshake (method / username-password). CONNECT and UDP ASSOCIATE are still sent
- [x] Remove MapDNS (fake IP / mapped DNS cache)
- [x] Remove local ICMP Echo (ping) replies (`icmp: reply` / `NETIF_FLAG_PRETEND_ICMP`)
- [x] Remove `pipeline` / `username` / `password` (ignored after handshake skip)
- [x] Remove `tcp-fastopen` / `mark` (Linux-only; no-ops on Apple)
- [x] Remove `pid-file` / `limit-nofile` (standalone daemon, not library / Network Extension)
- [x] Remove `post-up-script` / `pre-down-script` (skipped when the app passes `tun_fd`)
- [x] Remove `multi-queue` (Linux TUN only)
- [x] Remove SOCKS server code in `src/core`: `hev-socks5-server`, authenticator, user, rbtree
- [x] Remove JNI, Windows/Linux/FreeBSD/NetBSD tun backends, wintun
- [x] Remove UDP-in-TCP (`udp: tcp` / FWD UDP); UDP uses UDP ASSOCIATE only
- [x] Disable IPv6 (`LWIP_IPV6`) if the split path is IPv4-only
- [x] Drop YAML parser if config is a struct / hardcoded instead of `hev_socks5_tunnel_main_from_str`
- [x] Drop tvOS slices in `build-apple.sh`

Do not remove: TCP/UDP forwarding, session / lwIP TCP+UDP, `misc` buffer and session limits, `hev-tunnel-macos.c`, lwIP internal ICMP/ICMPv6 (NDP, dest-unreach).

## Features

* IPv4 TUN.
* Redirect TCP connections.
* Redirect UDP packets. (Fullcone NAT, UDP ASSOCIATE)
* macOS / iOS.

## Benchmarks

See [here](https://github.com/heiher/hev-socks5-tunnel/wiki/Benchmarks) for more details.

### Speed

![](https://github.com/heiher/hev-socks5-tunnel/wiki/res/upload-speed.png)
![](https://github.com/heiher/hev-socks5-tunnel/wiki/res/download-speed.png)

### CPU usage

![](https://github.com/heiher/hev-socks5-tunnel/wiki/res/upload-cpu.png)
![](https://github.com/heiher/hev-socks5-tunnel/wiki/res/download-cpu.png)

### Memory usage

![](https://github.com/heiher/hev-socks5-tunnel/wiki/res/upload-mem.png)
![](https://github.com/heiher/hev-socks5-tunnel/wiki/res/download-mem.png)

## How to Build

### Unix (macOS)

```bash
git clone --recursive https://github.com/yujinpan/hev-socks5-tunnel
cd hev-socks5-tunnel
make
```

### iOS and macOS

```bash
git clone --recursive https://github.com/yujinpan/hev-socks5-tunnel
cd hev-socks5-tunnel
# will generate HevSocks5Tunnel.xcframework
./build-apple.sh
```

### Library

```bash
git clone --recursive https://github.com/yujinpan/hev-socks5-tunnel
cd hev-socks5-tunnel

# Static library
make static

# Shared library
make shared
```

## How to Use

### CLI

```zsh
# Defaults: socks 127.0.0.1:1080
bin/hev-socks5-tunnel -s 127.0.0.1 -p 1080 -n utun -4 198.18.0.1 -m 8500
```

Bypass the upstream SOCKS server, then send the rest through the TUN:

```zsh
# 10.0.0.1: socks5 server
# 10.0.2.2: default gateway
sudo route add -net 10.0.0.1/32 10.0.2.2
sudo route change -inet default -interface utunN
```

### Low memory usage

On low-memory systems like iOS, reducing the size of the TCP buffer and
task stack, as well as limiting the maximum session count, can help prevent
out-of-memory issues. Set the matching fields on `HevSocks5TunnelConfig`:

```c
HevSocks5TunnelConfig config = {
    .socks5_address = "127.0.0.1",
    .socks5_port = 1080,
    .task_stack_size = 24576, /* 20480 + tcp_buffer_size */
    .tcp_buffer_size = 4096,
    .max_session_count = 1200,
};
```

## API

### C

```c
/**
 * HevSocks5TunnelConfig:
 *
 * Zero-initialized fields use built-in defaults. socks5_address and
 * socks5_port are required.
 */
typedef struct _HevSocks5TunnelConfig {
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
} HevSocks5TunnelConfig;

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
```

## Use Cases

### iOS

* [Aestate](https://apps.apple.com/us/app/aestate/id6749141594)

## Contributors

* **arror** - https://github.com/arror
* **bazuchan** - https://github.com/bazuchan
* **codewithtamim** - https://github.com/codewithtamim
* **dovecoteescapee** - https://github.com/dovecoteescapee
* **ebrahimtahernejad** - https://github.com/ebrahimtahernejad
* **heiby** - https://github.com/heiby
* **hev** - https://hev.cc
* **ihipop** - https://ihipop.com
* **katana** - https://github.com/officialkatana
* **pronebird** - https://github.com/pronebird
* **saeeddev94** - https://github.com/saeeddev94
* **sskaje** - https://github.com/sskaje
* **wankkoree** - https://github.com/wankkoree
* **xiguagua** - https://github.com/xiguagua
* **xz-dev** - https://github.com/xz-dev
* **yiguous** - https://github.com/yiguous
* **yujinpan** - https://github.com/yujinpan
* **zheshinicheng** - https://github.com/zheshinicheng

## License

MIT
