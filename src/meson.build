# SPDX-License-Identifier: AGPL-3.0-or-later

# Generate build-time config.h into the src/ build directory so that
# include_directories('.') in this file resolves both src/ source and
# src/ build dirs.
config_h = configure_file(
    output : 'config.h',
    configuration : conf_data,
)

inc = include_directories('.')

lib_sources = files(
    'crypto.c',
    'protocol.c',
    'appconf.c',
    'network.c',
    'util.c',
    'log.c',
    'authd.c',
)

# Internal convenience static library so tests can link against the
# individual modules without dragging in main().
libdrcom = static_library(
    'drcom',
    lib_sources,
    include_directories : inc,
    dependencies : [libsystemd_dep],
    install : false,
)

libdrcom_dep = declare_dependency(
    link_with : libdrcom,
    include_directories : inc,
    dependencies : [libsystemd_dep],
    sources : config_h,
)

executable(
    'jlu-drcom-authd',
    'main.c',
    include_directories : inc,
    dependencies : [libdrcom_dep],
    install : true,
    install_dir : get_option('sbindir'),
    pie : true,
)
