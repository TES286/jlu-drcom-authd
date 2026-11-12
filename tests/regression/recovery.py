#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise real daemon timeout exits, failed re-logins and session resets."""
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


class Server:
    def __init__(self, scenario):
        self.scenario = scenario
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.05)
        self.stop = threading.Event()
        self.logins = 0
        self.extra_after_relogin = False
        self.bad_keep_before_login = False
        self.failed_challenge = False
        self.expect_login = False
        self.injected = False
        self.good_cycles = 0
        self.error = None
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    packet, peer = self.sock.recvfrom(2048)
                except socket.timeout:
                    continue
                if packet[0] == 1:
                    if self.scenario == 'retry_login' and self.injected and not self.failed_challenge:
                        # The protocol-error path does a logout challenge first;
                        # drop the next challenge (the actual re-login attempt).
                        self.failed_challenge = 'logout'
                    elif self.failed_challenge == 'logout':
                        self.failed_challenge = True
                        self.expect_login = True
                        continue
                    reply = bytearray(76)
                    reply[0] = 2
                    reply[4:8] = bytes.fromhex('11223344')
                    reply[20:24] = bytes([10, 20, 30, 40])
                elif packet[0] == 3:
                    self.logins += 1
                    self.expect_login = False
                    reply = bytearray(128)
                    reply[0] = 4
                    reply[23:39] = bytes(range(16))
                elif packet[0] == 0xff:
                    if self.expect_login:
                        self.bad_keep_before_login = True
                    if self.scenario == 'silent':
                        continue
                    # First finish one cycle, so count/tail2 are nonzero at re-login.
                    if self.good_cycles >= 1 and not self.injected:
                        self.injected = True
                        reply = bytearray(1)  # malformed keep38 response
                    else:
                        reply = bytearray(40)
                        reply[0] = 7
                        reply[28:30] = bytes.fromhex('dc02')
                elif packet[0] == 7:
                    reply = bytearray(40)
                    reply[0] = 7
                    if packet[6:8] == bytes.fromhex('0f27'):
                        if self.logins >= 2:
                            assert packet[1] == 0, 'new login must restart keep40 sequence at zero'
                            assert packet[16:20] == bytes(4), 'stale tail2 after re-login'
                            self.extra_after_relogin = True
                    elif packet[5] == 1:
                        reply[16:20] = bytes.fromhex('aabbccdd')
                    elif packet[5] == 3:
                        self.good_cycles += 1
                elif packet[0] == 6:
                    reply = bytearray([4])
                else:
                    raise AssertionError(f'Unexpected packet {packet.hex()}')
                self.sock.sendto(reply, peer)
        except BaseException as error:
            self.error = error

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


def run(daemon, scenario):
    server = Server(scenario)
    try:
        with tempfile.TemporaryDirectory(prefix='drcom-recovery-') as tmp:
            config = Path(tmp) / 'test.conf'
            config.write_text(f'''[Authentication]
Username=testuser
Password=testpass
[Network]
Server=127.0.0.1
Port={server.sock.getsockname()[1]}
MAC=de:ad:be:ef:00:01
[Daemon]
KeepAliveSec=1
RecvTimeoutMs=100
MaxKeepaliveFails={1 if scenario == 'threshold_recovered' else 2}
Foreground=true
LogLevel=debug
''')
            with (Path(tmp) / 'daemon.log').open('w+') as log:
                proc = subprocess.Popen([str(daemon), '-c', str(config), '-f'], stdout=log, stderr=log)
                try:
                    if scenario == 'silent':
                        code = proc.wait(timeout=8)
                        assert code == 1, f'failure threshold returned {code}, expected 1'
                    else:
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline and not server.extra_after_relogin and proc.poll() is None and not server.error:
                            time.sleep(0.05)
                        assert not server.error, server.error
                        assert proc.poll() is None, f'daemon exited during recovery: {proc.returncode}'
                        assert server.logins >= 2, 'daemon did not retry authentication'
                        assert server.extra_after_relogin, 'missing first-cycle extra after re-login'
                        assert not server.bad_keep_before_login, 'keepalive sent while login was pending'
                        proc.terminate()
                        assert proc.wait(timeout=5) == 0, 'SIGTERM should exit cleanly'
                except BaseException:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)
                    raise
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
        print(f'{scenario}: PASS')
    finally:
        server.close()
    assert not server.error, server.error


if __name__ == '__main__':
    daemon = Path(sys.argv[1]).resolve()
    for scenario in ['silent', 'retry_login', 'threshold_recovered']:
        run(daemon, scenario)
