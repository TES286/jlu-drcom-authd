#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mock Drcom authentication server for end-to-end testing.

Implements just enough of the JLU Drcom protocol to drive the
jlu-drcom-authd client through a full challenge -> login -> keepalive
-> logout cycle.  Run as:

    ./mock_server.py PORT

Logs every received packet (hex) and the response sent.
"""

import hashlib
import socket
import struct
import sys
import time


def md5(*parts: bytes) -> bytes:
    h = hashlib.md5()
    for p in parts:
        h.update(p)
    return h.digest()


def main(port: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    print(f"[mock] listening on 127.0.0.1:{port}", flush=True)

    # Pre-agreed test fixture.  These MUST match what the test config gives
    # the client.
    USERNAME = b"e2euser"
    PASSWORD = b"e2epass"
    MAC = bytes([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    SALT = bytes([0x11, 0x22, 0x33, 0x44])
    CLIENT_IP = bytes([10, 20, 30, 40])
    TAIL1 = bytes(range(0x80, 0x90))  # 16 bytes
    TAIL2 = bytes([0xaa, 0xbb, 0xcc, 0xdd])
    KEEP_ALIVE_VER = bytes([0xdc, 0x02])

    # Track state across packets so we can validate the keepalive schedule.
    keep38_count = 0
    keep40_count_seen = []
    login_count = 0
    challenge_count = 0
    logout_count = 0

    deadline = time.time() + 30  # safety: stop after 30s no matter what

    while time.time() < deadline:
        sock.settimeout(max(0.5, deadline - time.time()))
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue

        if not data:
            continue

        code = data[0]
        print(f"[mock] recv {len(data)}B from {addr}: {data.hex()}", flush=True)

        # ----- challenge ---------------------------------------------------
        if code == 0x01 and len(data) >= 20:
            challenge_count += 1
            rand_echo = data[2:4]
            resp = bytearray(76)
            resp[0] = 0x02
            resp[1] = 0x02
            resp[2:4] = rand_echo
            resp[4:8] = SALT
            resp[20:24] = CLIENT_IP
            sock.sendto(bytes(resp), addr)
            print(f"[mock] sent challenge reply", flush=True)
            continue

        # ----- login -------------------------------------------------------
        if code == 0x03 and len(data) >= 334:
            login_count += 1
            # Verify md5a (data[4:20]) == md5(0x03 0x01, salt, password).
            expected_md5a = md5(bytes([0x03, 0x01]), SALT, PASSWORD)
            got_md5a = data[4:20]
            if got_md5a != expected_md5a:
                print(f"[mock] login md5a mismatch: expected {expected_md5a.hex()}, got {got_md5a.hex()}",
                      flush=True)
                resp = bytearray(128)
                resp[0] = 0x05
                resp[4] = 0x03
                sock.sendto(bytes(resp), addr)
                continue
            # Verify username at [20:56].
            got_user = data[20:56].rstrip(b"\x00")
            if got_user != USERNAME:
                print(f"[mock] login username mismatch: expected {USERNAME!r}, got {got_user!r}",
                      flush=True)
                resp = bytearray(128)
                resp[0] = 0x05
                resp[4] = 0x03
                sock.sendto(bytes(resp), addr)
                continue
            # Verify md5a^mac at [58:64].
            expected_xor = bytes(expected_md5a[i] ^ MAC[i] for i in range(6))
            if data[58:64] != expected_xor:
                print(f"[mock] login md5a^mac mismatch: expected {expected_xor.hex()}, got {data[58:64].hex()}",
                      flush=True)
            resp = bytearray(128)
            resp[0] = 0x04  # success
            resp[23:39] = TAIL1
            sock.sendto(bytes(resp), addr)
            print(f"[mock] sent login OK", flush=True)
            continue

        # ----- keep38 ------------------------------------------------------
        if code == 0xff and len(data) >= 38:
            keep38_count += 1
            rand_echo = data[36:38]
            resp = bytearray(40)
            resp[0] = 0x07  # not strictly required by client but harmless
            resp[6:8] = rand_echo
            resp[12:16] = CLIENT_IP
            resp[28:30] = KEEP_ALIVE_VER
            sock.sendto(bytes(resp), addr)
            print(f"[mock] sent keep38 reply (count={keep38_count})", flush=True)
            continue

        # ----- keep40 family ----------------------------------------------
        if code == 0x07 and len(data) >= 40:
            count_byte = data[1]
            type_byte = data[5]
            keep40_count_seen.append((count_byte, type_byte))
            rand_echo = data[8:10]

            if data[6] == 0x0f and data[7] == 0x27:
                # keep40_extra: client sent type=01, server replies with type=06
                resp = bytearray(272)
                resp[0] = 0x07
                resp[1] = count_byte
                resp[5] = 0x06
                resp[6:8] = KEEP_ALIVE_VER
                resp[8:10] = rand_echo
                sock.sendto(bytes(resp), addr)
                print(f"[mock] sent keep40_extra reply (272B)", flush=True)
                continue

            if type_byte == 0x01:
                # keep40_1: server replies with type=02, includes tail2
                resp = bytearray(40)
                resp[0] = 0x07
                resp[1] = count_byte
                resp[5] = 0x02
                resp[6:8] = KEEP_ALIVE_VER
                resp[8:10] = rand_echo
                resp[16:20] = TAIL2
                sock.sendto(bytes(resp), addr)
                print(f"[mock] sent keep40_1 reply (with tail2)", flush=True)
                continue

            if type_byte == 0x03:
                # keep40_2: server replies with type=04
                resp = bytearray(40)
                resp[0] = 0x07
                resp[1] = count_byte
                resp[5] = 0x04
                resp[6:8] = KEEP_ALIVE_VER
                resp[8:10] = rand_echo
                sock.sendto(bytes(resp), addr)
                print(f"[mock] sent keep40_2 reply", flush=True)
                continue

            print(f"[mock] unknown keep40 variant type={type_byte:#x}", flush=True)
            continue

        # ----- logout ------------------------------------------------------
        if code == 0x06 and len(data) >= 80:
            logout_count += 1
            resp = bytearray(25)
            resp[0] = 0x04
            sock.sendto(bytes(resp), addr)
            print(f"[mock] sent logout OK", flush=True)
            continue

        print(f"[mock] unknown packet code={code:#x} len={len(data)}", flush=True)

    print(f"[mock] stats: challenges={challenge_count} logins={login_count} "
          f"keep38={keep38_count} keep40={len(keep40_count_seen)} "
          f"logouts={logout_count}", flush=True)
    sock.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: mock_server.py PORT", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(int(sys.argv[1])))
