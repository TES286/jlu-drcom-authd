# SPDX-License-Identifier: AGPL-3.0-or-later

# All unit tests link against libdrcom_dep (defined in src/meson.build).

tests_unit = [
    ['test_cpufeatures', 'unit/test_cpufeatures.c'],
    ['test_crypto',      'unit/test_crypto.c'],
    ['test_protocol',    'unit/test_protocol.c'],
    ['test_appconf',     'unit/test_appconf.c'],
    ['test_netlink',     'unit/test_netlink.c'],
]

foreach t : tests_unit
    name = t[0]
    src  = t[1]
    exe = executable(
        name,
        src,
        dependencies : [libdrcom_dep],
        install : false,
        pie : true,
    )
    test(name, exe, workdir : meson.project_build_root())
endforeach

# End-to-end test: spin up the Python mock server, start the daemon with a
# generated config pointing at 127.0.0.1, run for ~5 seconds of keep-alive
# cycles, then verify that challenge/login/keepalive all happened.

e2e_script = find_program('e2e/run_e2e.py', required : get_option('tests'))
if e2e_script.found()
    test('e2e', e2e_script,
        args : [meson.project_build_root() / 'src' / 'jlu-drcom-authd'],
        workdir : meson.current_source_dir(),
        timeout : 60,
        suite : 'e2e',
    )
endif
