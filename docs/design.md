# Design notes

## Goals

1. Be a drop-in replacement for the official JLU Drcom client that runs
   unattended as a `Type=notify` systemd service.
2. Integrate with systemd components (sd-event, sd-journal, sd-daemon)
   rather than reinventing them.
3. Target arm64 as the primary platform, with amd64 as a fully supported
   secondary target.
4. Have no heavyweight runtime dependencies beyond libsystemd.

## Non-goals

* GUI / interactive login prompt.  Configuration is file-only.
* 802.1X EAP authentication (the dogcom `--802.1x` mode).  JLU's wired
  network uses pure Drcom-over-UDP; the EAP path is irrelevant.
* Supporting non-JLU Drcom variants (the `R`/`P` versions that dogcom
  also handles).  The wire formats differ.

## Why synchronous I/O inside each phase?

The Drcom wire protocol is strictly request/response: the client sends
a packet, the server replies, the client sends the next packet.  There
are no asynchronous server pushes that the client must handle mid-phase.
This makes blocking `recv(2)` with `SO_RCVTIMEO` strictly simpler than
wiring every recv into an `sd_event` IO source:

* fewer state-machine transitions to test,
* no need for a receive-buffer-and-resume abstraction,
* no syscall overhead from arming/disarming IO sources per packet.

The trade-off is that the daemon blocks inside the keepalive callback
for up to ~4 × `RecvTimeoutMs` (default 5 s, so 20 s worst case).  This
is bounded and well within the 30 s `WatchdogSec` configured in the
unit file.  We additionally feed the watchdog manually between
network operations via `sd_notify("WATCHDOG=1")` so a slow server
cannot trigger a spurious kill.

## Why no OpenSSL?

OpenSSL's MD5 API is deprecated in 3.x (`MD5_Init` etc.), forcing
callers through the verbose `EVP_MD_CTX` abstraction.  For a daemon
that uses only MD5 (no TLS, no asymmetric crypto), the ~150-line
in-tree implementation is:

* smaller in binary size,
* easier to cross-compile to arm64 (no `libcrypto.so` to ship),
* sufficient for the protocol's needs.

The implementation passes the RFC 1321 test vectors including the
1,000,000-byte 'a' input (see `tests/unit/test_crypto.c`).

## Why is the checksum NEON-only on aarch64?

The Drcom checksum is a 4-byte XOR fold of the input followed by a
32-bit multiply.  On arm64 the `vrev32q_u8` + `veorq_u8` pair lets us
fold 16 input bytes per iteration with no extra cost; the horizontal
reduction (two `vextq` + `veorq` pairs) is amortised over the entire
input.  The data sizes in question (the login packet is ~330 bytes)
mean the speed-up is modest in absolute terms, but it's free and
demonstrates the project's arm64-first stance.

On amd64 we deliberately leave the loop in scalar form: the compiler
auto-vectorises it well (SSE2 is always available), and writing SSE2
intrinsics would add platform-specific code without measurable
benefit.

## Packet size invariant

For a password of length `passLen` (capped to 16), the login packet
length is:

```
dataLen = 334 + ((passLen - 1) / 4) * 4
```

This equals `330 + passLen + zeroCount` where `zeroCount = (4 -
passLen % 4) % 4`.  The constant `DRCOM_LOGIN_REQ_MAX` (= 346) covers
the largest possible packet (passLen = 16).  The unit test in
`test_protocol.c` checks the length formula for a known passLen.

## Restart strategy

The unit file uses `Restart=on-failure` with `RestartSec=5s` and
`StartLimitBurst=10` / `StartLimitIntervalSec=120`.  This gives the
daemon up to 10 restart attempts within any 2-minute window - enough
to ride through transient network blips, but not so many that it
hides a persistent misconfiguration.  The daemon itself re-attempts
authentication inline on a keepalive failure (see
`on_keepalive()` in `authd.c`) before falling back to a full restart.

## What's deliberately missing

* **D-Bus / sd-bus control interface.** Could be added later if a
  desktop applet or `busctl`-driven status query is wanted.  For now
  `systemctl status` + `journalctl` cover all operational needs.
* **Reload on SIGHUP.** The unit file accepts SIGHUP but the daemon
  logs and ignores it.  A real reload would need to re-read config,
  tear down the existing session (logout), and start a new one -
  equivalent to a `systemctl restart`, which is already cheap.
* **Capabilities.** The daemon does not need any capabilities
  (`CapabilityBoundingSet=` is empty in the unit file).  It binds to
  ephemeral ports and connects to the auth server on port 61440
  (>= 1024, no privilege needed).
