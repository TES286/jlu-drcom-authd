# SPDX-License-Identifier: AGPL-3.0-or-later
# jlu-drcom-authd - systemd-native Drcom authentication daemon for JLU
project(
    'jlu-drcom-authd',
    'c',
    version : '0.1.0',
    license : 'AGPL-3.0-or-later',
    default_options : [
        'c_std=c17',
        'warning_level=2',
        'b_lto=true',
        'b_ndebug=if-release',
        'b_pie=true',
        'default_library=static',
    ],
)

cc = meson.get_compiler('c')

# Common warning flags enforced regardless of warning_level.
extra_warnings = [
    '-Wextra',
    '-Wpedantic',
    '-Wconversion',
    '-Wsign-conversion',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
    '-Wmissing-declarations',
    '-Wmissing-include-dirs',
    '-Wold-style-definition',
    '-Wredundant-decls',
    '-Wfloat-equal',
    '-Wundef',
    '-Wvla',
    '-Wwrite-strings',
    '-Wno-unused-parameter',   # noise from callbacks
    '-Wno-format-truncation',  # explicit bounded truncation is intentional
]
add_project_arguments(
    cc.get_supported_arguments(extra_warnings),
    language : 'c',
)

# Dependencies
libsystemd_dep = dependency('libsystemd', version : '>= 252', required : true)
systemd_dep    = dependency('systemd',    required : false)

# ARM64 / NEON detection for crypto fast paths.
host_cpu = host_machine.cpu()
have_neon = host_cpu == 'aarch64' or host_cpu == 'arm64'

conf_data = configuration_data()
conf_data.set10('HAVE_NEON', have_neon)
conf_data.set_quoted('PACKAGE_VERSION', meson.project_version())
conf_data.set_quoted('PACKAGE_NAME', meson.project_name())

subdir('src')
subdir('tests')

# Install systemd unit files. The directory picked at runtime comes from
# pkg-config --variable=systemdsystemunitdir; this lets distro packagers
# override it through -Dsystemdsystemunitdir=/path.
systemdsystemunitdir = get_option('systemdsystemunitdir')
if systemdsystemunitdir == ''
    if systemd_dep.found()
        systemdsystemunitdir = systemd_dep.get_variable(pkgconfig : 'systemdsystemunitdir')
    else
        systemdsystemunitdir = '/lib/systemd/system'
    endif
endif

install_data(
    'systemd/jlu-drcom-authd.service',
    'systemd/jlu-drcom-authd@.service',
    install_dir : systemdsystemunitdir,
)

# Example config under /etc via sysconfdir.
install_data(
    'systemd/jlu-drcom-authd.conf.example',
    install_dir : get_option('sysconfdir') / 'jlu-drcom-authd',
    rename : 'jlu-drcom-authd.conf.example',
)
