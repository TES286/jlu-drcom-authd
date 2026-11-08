#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end test runner for jlu-drcom-authd.

Steps:
  1. Pick a free UDP port on 127.0.0.1.
  2. Start tests/e2e/mock_server.py on that port.
  3. Write a temp config that points the daemon at the mock server.
  4. Start the daemon in foreground + debug mode, capture its stderr.
  5. Let it run for ~6 seconds (long enough for challenge/login and at
     least one keepalive cycle).
  6. Send SIGTERM and wait for it to exit cleanly.
  7. Assert that the daemon's log shows "login successful" and
     "logout successful", and that the mock server observed at least
     one keep38/keep40 cycle.

Exit code 0 on success, non-zero on failure.
"""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time


HERE = os.path.dirname(os.path.abspath(__file__))


def pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_line(proc: subprocess.Popen, needle: bytes, timeout: float) -> bool:
    """Return True if `needle` appears in proc.stdout within `timeout` seconds."""
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        sys.stderr.write(f"[daemon] {line.decode('utf-8', 'replace')}")
        if needle in line:
            return True
    return False


def main(daemon_path: str) -> int:
    if not os.path.exists(daemon_path):
        print(f"daemon not found: {daemon_path}", file=sys.stderr)
        return 1

    port = pick_port()
    mock_log_path = tempfile.mktemp(prefix="drcom_mock_", suffix=".log")
    mock = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "mock_server.py"), str(port)],
        stdout=open(mock_log_path, "w"),
        stderr=subprocess.STDOUT,
    )
    print(f"[e2e] mock server pid={mock.pid} port={port} log={mock_log_path}", flush=True)

    # Wait for mock to be ready.
    time.sleep(0.5)
    if mock.poll() is not None:
        print("[e2e] mock server died at startup:", file=sys.stderr)
        with open(mock_log_path) as fp:
            print(fp.read(), file=sys.stderr)
        return 1

    cfg_path = tempfile.mktemp(prefix="drcom_cfg_", suffix=".conf")
    with open(cfg_path, "w") as fp:
        fp.write(textwrap.dedent(f"""\
            [Authentication]
            Username = e2euser
            Password = e2epass

            [Network]
            Server = 127.0.0.1
            Port = {port}
            MAC = de:ad:be:ef:00:01
            Hostname = e2e-host

            [Daemon]
            KeepAliveSec = 2
            RecvTimeoutMs = 2000
            LogLevel = debug
            Foreground = true
        """))

    daemon_log = tempfile.mktemp(prefix="drcom_daemon_", suffix=".log")
    daemon = subprocess.Popen(
        [daemon_path, "-c", cfg_path, "-f", "-d"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "DRCOM_FOREGROUND": "1"},
    )
    print(f"[e2e] daemon pid={daemon.pid} log={daemon_log}", flush=True)

    try:
        # Wait for login.
        if not wait_for_line(daemon, b"login successful", timeout=10.0):
            print("[e2e] FAIL: did not see 'login successful'", file=sys.stderr)
            return 1
        # Let one or more keepalive cycles happen.
        time.sleep(6.0)
        if daemon.poll() is not None:
            print("[e2e] FAIL: daemon exited prematurely", file=sys.stderr)
            return 1
        # Stop the daemon (triggers logout path).
        daemon.send_signal(signal.SIGTERM)
        if not wait_for_line(daemon, b"logout successful", timeout=8.0):
            print("[e2e] FAIL: did not see 'logout successful'", file=sys.stderr)
            return 1
        try:
            daemon.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            print("[e2e] FAIL: daemon did not exit after SIGTERM", file=sys.stderr)
            daemon.kill()
            return 1
    finally:
        # Drain remaining daemon output and dump to log file for debugging.
        try:
            out, _ = daemon.communicate(timeout=3.0)
        except subprocess.TimeoutExpired:
            daemon.kill()
            out, _ = daemon.communicate()
        with open(daemon_log, "wb") as fp:
            fp.write(out)
        if mock.poll() is None:
            mock.terminate()
            try:
                mock.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                mock.kill()

    # Inspect mock server log for the expected packet sequence.
    with open(mock_log_path) as fp:
        mock_log = fp.read()
    print("[e2e] mock log:", flush=True)
    print(mock_log)

    expected = [
        "sent challenge reply",
        "sent login OK",
        "sent keep38 reply",
        "sent keep40_extra reply",
        "sent keep40_1 reply",
        "sent keep40_2 reply",
        "sent logout OK",
    ]
    missing = [s for s in expected if s not in mock_log]
    if missing:
        print(f"[e2e] FAIL: mock log missing: {missing}", file=sys.stderr)
        return 1

    # Sanity: at least 2 keep38 cycles (initial + at least one scheduled).
    keep38_count = mock_log.count("sent keep38 reply")
    if keep38_count < 2:
        print(f"[e2e] FAIL: only {keep38_count} keep38 cycles (expected >= 2)", file=sys.stderr)
        return 1

    print(f"[e2e] PASS: {keep38_count} keep38 cycles observed", flush=True)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: run_e2e.py /path/to/jlu-drcom-authd", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
