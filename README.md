# jlu-drcom-authd

A systemd-native Drcom authentication daemon for the Jilin University
campus network.  Written in C17 with first-class `sd-event`, `sd-journal`,
`sd-daemon` integration and tuned for arm64 (with amd64 as a fully
supported secondary target).

The daemon implements the JLU Drcom wire protocol (challenge → login →
keep-alive → logout) and is designed to live its entire lifecycle inside
systemd: it consumes `sd_event` for the main loop, feeds the systemd
watchdog, sends structured journal entries, exposes live status via
`sd_notify("STATUS=…")`, and ships with hardened unit files.

## Features

* **Systemd-first design.** `Type=notify` service, `sd_event` main loop,
  `sd_journal_send` structured logging, `sd_event_set_watchdog` automatic
  watchdog feeding, plus manual `sd_notify("WATCHDOG=1")` between network
  operations to survive slow server replies.
* **Hardened unit files.** `NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, capability
  bounding set empty, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`,
  and a 30 s watchdog.  Both a default instance and a template
  (`jlu-drcom-authd@<iface>.service`) are provided for multi-interface
  deployments.
* **Runtime CPU feature detection.** Uses `getauxval(AT_HWCAP)` to probe
  for NEON/ASIMD, CRC32, AES, SHA, PMULL at runtime.  A single generic
  arm64 binary runs on every aarch64 SoC, with the NEON fast path
  dispatched only when the kernel reports `HWCAP_ASIMD`.  No compile-time
  `-march` flags required.
* **Link state monitoring.** Subscribes to rtnetlink `RTMGRP_LINK` and
  reacts to interface up/down events in ~1 ms — closing the UDP socket
  immediately on link-down and re-authenticating on link-up, instead of
  waiting for a keepalive timeout (up to 20 s).  Integrated into the
  `sd_event` loop as a non-blocking IO source.
* **DNS fallback for pre-authentication.** On campus networks the
  system DNS resolver (via `/etc/resolv.conf`) often cannot recurse
  until the host is authenticated, so `getaddrinfo(3)` fails to resolve
  the auth server hostname.  An optional `DnsServer` config setting
  enables a minimal in-tree RFC 1035 DNS client that sends a direct
  A-record query to a specified DNS server (e.g. the campus DNS at
  `10.10.10.10`), bypassing `/etc/resolv.conf` entirely.  The system
  resolver is tried first; the fallback only activates on failure.
* **arm64 tuning.** `drcom_checksum()` uses NEON `vrev32q_u8` +
  `veorq_u32` to fold 16 input bytes per iteration on aarch64; the amd64
  fallback is a plain scalar loop that the compiler is free to
  auto-vectorise.  All multi-byte field accesses are little-endian
  loads/stores via `__builtin_memcpy`, which both gcc and clang turn into
  a single load on amd64/aarch64.
* **No heavyweight dependencies.** Only `libsystemd`.  MD5 is a small
  in-tree implementation derived from RFC 1321 - removing the OpenSSL
  dependency and keeping the daemon statically linkable on minimal arm64
  images.
* **Modern C17.** Designated initialisers, `bool`, fixed-size field
  types, `static_assert`-friendly layout, no VLAs, no implicit
  declarations, strict-prototype warnings enabled.
* **Tested.** Unit tests for the crypto, protocol, cpufeatures, netlink
  and config modules cover RFC 1321 MD5 vectors, hand-computed
  checksum/CRC outputs, packet structural invariants, runtime CPU
  feature probing, and netlink link-state queries.  An end-to-end test
  runs the daemon against a Python mock Drcom server (in `tests/e2e/`)
  that implements the full protocol, and verifies the
  challenge/login/keepalive/logout sequence.
* **Debian packaging.** `debian/` directory with `debhelper-compat 13`
  and `meson+ninja` build system.  CI produces `.deb` packages for both
  amd64 and arm64.
* **CI/CD.** GitHub Actions build matrix runs native amd64 and arm64,
  runs unit + e2e tests, builds `.deb` packages, and publishes a
  release tarball + debs on tag push.

## Building from source

```sh
meson setup build
meson compile -C build
meson test -C build           # unit + e2e tests
sudo meson install -C build   # installs binary + unit files
```

## Installing from .deb

Pre-built `.deb` packages for amd64 and arm64 are published on the
[releases page](https://github.com/TES286/jlu-drcom-authd/releases).
Download and install:

```sh
sudo apt install ./jlu-drcom-authd_0.1.0-1_<arch>.deb
```

The package installs the binary (`/usr/sbin/jlu-drcom-authd`), systemd
units, example config, and a `tmpfiles.d` snippet that creates
`/etc/jlu-drcom-authd/`, `/var/lib/jlu-drcom-authd/`, and
`/var/log/jlu-drcom-authd/` with safe permissions.  Edit
`/etc/jlu-drcom-authd/jlu-drcom-authd.conf` to set your credentials, then:

```sh
sudo systemctl enable --now jlu-drcom-authd
```

### Building .deb from source

```sh
sudo apt install build-essential meson ninja-build pkg-config \
    libsystemd-dev debhelper dpkg-dev
dpkg-buildpackage -us -uc -b
# Output: ../jlu-drcom-authd_0.1.0-1_<arch>.deb
```

Build options (override with `-D`):

| Option                    | Default | Description                              |
| ------------------------- | ------- | ---------------------------------------- |
| `systemdsystemunitdir`    | auto    | Where to install unit files              |
| `tests`                   | enabled | Build unit + e2e tests                   |
| `asan`                    | false   | Compile with AddressSanitizer (debug)    |

## Configuration

The daemon reads `/etc/jlu-drcom-authd/jlu-drcom-authd.conf` by default;
override with `--config`.  See
[`systemd/jlu-drcom-authd.conf.example`](systemd/jlu-drcom-authd.conf.example)
for the full list of options.  Briefly:

```ini
[Authentication]
Username = 2023xxxxxx
PasswordFile = /etc/jlu-drcom-authd/password

[Network]
Server = auth.jlu.edu.cn
Port = 61440
# Interface = eth0      # auto-detect if unset
# MAC = aa:bb:cc:dd:ee:ff  # auto-detect if unset
# DnsServer = 10.10.10.10  # campus DNS for pre-auth fallback

[Daemon]
KeepAliveSec = 20
LogLevel = info
Foreground = false
```

A `PasswordFile = /path/to/file` (mode `0600`) is preferred over an
inline `Password =` for production; the daemon reads it once at startup.

## Running

Enable and start the default instance:

```sh
sudo systemctl enable --now jlu-drcom-authd.service
journalctl -u jlu-drcom-authd -f
```

For a per-interface instance (e.g. `eth0`), use the template unit:

```sh
sudo systemctl enable --now jlu-drcom-authd@eth0.service
```

The template expects a per-interface config file at
`/etc/jlu-drcom-authd/jlu-drcom-authd-eth0.conf` and exports
`DRCOM_INTERFACE=eth0` for the daemon.

## Status & control

The daemon publishes its state via `sd_notify` so `systemctl status`
shows live progress:

```
$ systemctl status jlu-drcom-authd
● jlu-drcom-authd.service - JLU Drcom Authentication Daemon
     Active: active (running)
   Main PID: 1234
     Status: "online (keep38=42)"
```

`systemctl reload` (SIGHUP) is currently a no-op; the daemon logs and
ignores it.  `systemctl stop` (SIGTERM) triggers a graceful logout.

## Architecture

```
                 ┌──────────────────────────────────────┐
                 │              sd_event                │
                 │  ┌────────────┐  ┌────────────────┐  │
   SIGTERM ──────┼─▶│ signal src │  │ keepalive timer│  │
                 │  └────────────┘  └────────┬───────┘  │
                 │                          │           │
                 │              ┌───────────▼────────┐  │
                 │              │   authd state      │  │
                 │              │   machine          │  │
                 │              │  ┌─────────────┐   │  │
                 │              │  │ drcom_net_t │   │  │
                 │              │  │   (UDP)     │   │  │
                 │              │  └─────────────┘   │  │
                 │              └────────┬───────────┘  │
                 │                       │              │
                 │              ┌────────▼───────────┐  │
                 │              │  protocol.c        │  │
                 │              │  (de)serialise     │  │
                 │              │  packets           │  │
                 │              └────────┬───────────┘  │
                 │              ┌────────▼───────────┐  │
                 │              │  crypto.c          │  │
                 │              │  MD5, ror,         │  │
                 │              │  checksum, crc     │  │
                 │              │  (NEON on aarch64) │  │
                 │              └────────────────────┘  │
                 └──────────────────────────────────────┘
                              │
                              ▼
                  sd_journal_send ─▶ journald
                  sd_notify ─▶ systemd (READY/WATCHDOG/STATUS/STOPPING)
```

The protocol layer is fully synchronous inside each phase (challenge,
login, keepalive cycle, logout): the Drcom wire protocol is strictly
request/response with bounded timeouts, so blocking `recv(2)` with
`SO_RCVTIMEO` is simpler and faster than wiring every recv into
`sd_event` IO sources.  `sd_event` still drives the outer loop: the
keepalive timer, signal handlers, netlink IO source, and the systemd
watchdog all live in the event loop.  Between network operations we feed
the watchdog manually via `sd_notify("WATCHDOG=1")` so a slow server
cannot trigger a spurious kill.

### Link state monitoring

When an interface name is configured (either explicitly or via
auto-detection), the daemon opens a `NETLINK_ROUTE` socket subscribed to
`RTMGRP_LINK` and registers it as an `sd_event` IO source.  On
`RTM_NEWLINK`/`RTM_DELLINK` notifications, it checks whether the
watched interface's `IFF_UP | IFF_LOWER_UP` flags changed:

* **Link down**: closes the UDP socket immediately, pauses keepalive
  (the timer stays armed but skips), and sets state to `initializing`.
* **Link up**: schedules a deferred re-authentication (challenge +
  login) on the next event loop iteration.  Using `sd_event_add_defer`
  avoids blocking the netlink IO callback during the network round-trip.

This cuts recovery time from a keepalive timeout (~20 s) to ~1 ms.

### Runtime CPU feature detection

At startup, `drcom_cpufeatures_init()` calls `getauxval(AT_HWCAP)` to
read the auxiliary vector populated by the kernel.  The result is cached
in a singleton and queried by the crypto module on every `drcom_checksum()`
call.  On aarch64, `HWCAP_ASIMD` (NEON) is checked; on other
architectures the accessors unconditionally return false.

This replaces the previous compile-time `HAVE_NEON` macro, making a
single generic arm64 binary portable across all aarch64 SoCs — from
Cortex-A53 (Raspberry Pi 3) to Neoverse N1 (Graviton2) — with the NEON
fast path enabled when available and the scalar fallback used
otherwise.

## Testing

### Unit tests

Located in `tests/unit/`:

* `test_cpufeatures.c` — verifies `getauxval` probing: NEON must be
  detected on aarch64, no features on amd64.
* `test_crypto.c` — RFC 1321 MD5 vectors, hand-computed checksum/CRC
  outputs (verified against a Python port of the Java reference
  algorithm), `ror` correctness.
* `test_dns.c` — DNS name encoding, response parsing (compression
  pointers, A-record extraction, error handling), and a mock-DNS-server
  end-to-end transport test.
* `test_protocol.c` — packet structural invariants: header bytes,
  length formulas, field offsets.
* `test_appconf.c` — config parser: defaults, quoted values, MAC
  formats, password-file resolution, unknown-key tolerance,
  cross-field validation.
* `test_netlink.c` — `drcom_netlink_query_link()` against `lo` and
  nonexistent interfaces; `drcom_netlink_new/free()` lifecycle.

### End-to-end test

`tests/e2e/`:

* `mock_server.py` — a Python implementation of the JLU Drcom server
  side.  Verifies the client's md5a, username, and md5a^mac fields
  against expected values derived from the agreed-upon credentials.
* `run_e2e.py` — spawns the mock server, generates a config pointing
  the daemon at `127.0.0.1:<port>`, runs the daemon for ~6 s of
  keepalive cycles, sends SIGTERM, and asserts that:
  * the daemon logged `login successful` and `logout successful`,
  * the mock server observed at least 2 keep38 cycles,
  * all expected packet types were exchanged.

The mock server doubles as a reference router-software process for
testing per the project brief.

## Protocol reference

The implementation follows the protocol documented at
<https://github.com/drcoms/jlu-drcom-client/blob/master/jlu-drcom-java/jlu-drcom-protocol.md>
and the Java reference implementation in the same repository.  A
mirrored copy of the protocol notes lives in `docs/protocol.md`.

## License

AGPL-3.0-or-later.  See [`LICENSE`](LICENSE).
