#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate staged units and run postinst against an isolated test config tree.

Run after: meson install -C build --destdir "$PWD/build/stage"
No service is started and no host configuration is changed.
"""
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def main(build):
    installed = json.loads((build / 'meson-info/intro-installed.json').read_text())
    paths = {Path(src).name: dest for src, dest in installed.items()}
    stage = build / 'stage'
    binary = stage / paths['jlu-drcom-authd'].lstrip('/')
    assert binary.is_file() and os.access(binary, os.X_OK), binary
    with tempfile.TemporaryDirectory(prefix='drcom-install-') as tmp:
        root = Path(tmp)
        for name in ['jlu-drcom-authd.service', 'jlu-drcom-authd@.service']:
            unit = (stage / paths[name].lstrip('/')).read_text()
            assert '@sbindir@' not in unit, 'Unexpanded executable path'
            command = next(line.split('=', 1)[1] for line in unit.splitlines() if line.startswith('ExecStart='))
            executable = shlex.split(command.rstrip('\\').strip())[0]
            assert executable == paths['jlu-drcom-authd'], (executable, paths['jlu-drcom-authd'])
            # Verify syntax against the host's systemd, using the staged binary.
            check_unit = root / name
            check_unit.write_text(unit.replace('ExecStart=' + executable, 'ExecStart=' + str(binary)))
            subprocess.run(['systemd-analyze', 'verify', '--man=no', str(check_unit)], check=True)

        config_dir = root / 'etc/jlu-drcom-authd'
        config_dir.mkdir(parents=True)
        example = stage / paths['jlu-drcom-authd.conf.example'].lstrip('/')
        shutil.copyfile(example, config_dir / example.name)
        mocks = root / 'bin'
        mocks.mkdir()
        for command in ['getent', 'systemd-tmpfiles']:
            path = mocks / command
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o755)
        source = Path(__file__).resolve().parents[2]
        postinst = (source / 'debian/jlu-drcom-authd.postinst').read_text()
        # Redirect paths and file ownership only; execute the real shell logic.
        postinst = postinst.replace('/etc/jlu-drcom-authd', str(config_dir))
        postinst = postinst.replace('/usr/share/doc/jlu-drcom-authd', str(root / 'nonexistent-doc-dir'))
        postinst = postinst.replace('-o root -g root', f'-o {os.getuid()} -g {os.getgid()}')
        script = root / 'postinst'
        script.write_text(postinst)
        env = {**os.environ, 'PATH': str(mocks) + os.pathsep + os.environ['PATH']}
        subprocess.run(['sh', str(script), 'configure'], env=env, check=True)
        config = config_dir / 'jlu-drcom-authd.conf'
        assert config.read_bytes() == example.read_bytes(), 'Default config was not installed'
        assert stat.S_IMODE(config.stat().st_mode) == 0o640, 'Unsafe config permissions'
        config.write_text('existing user configuration\n')
        subprocess.run(['sh', str(script), 'configure'], env=env, check=True)
        assert config.read_text() == 'existing user configuration\n', 'Upgrade overwrote user config'
    print('staged units, fresh postinst and config-preserving upgrade: PASS')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve())
