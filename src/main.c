/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file main.c
 * @brief jlu-drcom-authd entry point.
 *
 * Lifecycle:
 *   1. Parse command line / config file.
 *   2. Set up sd_event with signal handling (SIGTERM, SIGINT, SIGHUP).
 *   3. Construct the authd state machine and call drcom_authd_start().
 *   4. Run sd_event_loop until a signal arrives.
 *   5. Tear down cleanly: logout, sd_notify("STOPPING=1").
 */
#define _GNU_SOURCE 1
#include "config.h"
#include "appconf.h"
#include "authd.h"
#include "log.h"
#include "protocol.h"
#include "util.h"

#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <unistd.h>
#include <errno.h>

static const char *opt_config = NULL;
static const char *opt_iface  = NULL;
static int         opt_foreground = 0;
static int         opt_debug = 0;
static const char *opt_pid_file = NULL;

static void usage(FILE *fp, const char *prog)
{
    fprintf(fp,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "A systemd-native Drcom authentication daemon for JLU.\n"
        "\n"
        "Options:\n"
        "  -c, --config=PATH      Configuration file (default: /etc/jlu-drcom-authd/jlu-drcom-authd.conf)\n"
        "  -i, --interface=NAME   Network interface (overrides config)\n"
        "  -f, --foreground       Do not detach (auto-detected under systemd)\n"
        "  -d, --debug            Verbose logging (equivalent to LogLevel=debug)\n"
        "  -p, --pid-file=PATH    Write PID to PATH (default: none)\n"
        "  -v, --version          Print version and exit\n"
        "  -h, --help             Show this help\n",
        prog);
}

static int parse_args(int argc, char **argv)
{
    static const struct option opts[] = {
        {"config",     required_argument, 0, 'c'},
        {"interface",  required_argument, 0, 'i'},
        {"foreground", no_argument,       0, 'f'},
        {"debug",      no_argument,       0, 'd'},
        {"pid-file",   required_argument, 0, 'p'},
        {"version",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };
    int c;
    while ((c = getopt_long(argc, argv, "c:i:fdp:vh", opts, NULL)) != -1) {
        switch (c) {
        case 'c': opt_config = optarg; break;
        case 'i': opt_iface = optarg; break;
        case 'f': opt_foreground = 1; break;
        case 'd': opt_debug = 1; break;
        case 'p': opt_pid_file = optarg; break;
        case 'v':
            printf("%s %s\n", "jlu-drcom-authd", PACKAGE_VERSION);
            return 1;
        case 'h':
            usage(stdout, argv[0]);
            return 1;
        default:
            usage(stderr, argv[0]);
            return -1;
        }
    }
    return 0;
}

static int on_signal(sd_event_source *s, const struct signalfd_siginfo *si,
                     void *userdata)
{
    (void)s; (void)si;
    sd_event *e = userdata;
    switch (si->ssi_signo) {
    case SIGTERM:
    case SIGINT:
        drcom_log_notice("received signal %u, exiting", si->ssi_signo);
        sd_event_exit(e, 0);
        return 0;
    case SIGHUP:
        /* Reload not yet implemented; log and continue. */
        drcom_log_notice("SIGHUP received (reload not implemented)");
        return 0;
    default:
        return 0;
    }
}

static int setup_signals(sd_event *e)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return -errno;
    int r;
    if ((r = sd_event_add_signal(e, NULL, SIGTERM, on_signal, e)) < 0) return r;
    if ((r = sd_event_add_signal(e, NULL, SIGINT,  on_signal, e)) < 0) return r;
    if ((r = sd_event_add_signal(e, NULL, SIGHUP,  on_signal, e)) < 0) return r;
    return 0;
}

int main(int argc, char **argv)
{
    int r = parse_args(argc, argv);
    if (r > 0) return 0;
    if (r < 0) return 2;

    drcom_appconf_t conf;
    drcom_appconf_defaults(&conf);

    char errbuf[256] = "";
    const char *cfg_path = opt_config;
    if (!cfg_path) {
        /* Try a few standard locations. */
        static const char *const paths[] = {
            "/etc/jlu-drcom-authd/jlu-drcom-authd.conf",
            "./jlu-drcom-authd.conf",
        };
        for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
            if (access(paths[i], R_OK) == 0) {
                cfg_path = paths[i];
                break;
            }
        }
    }
    if (cfg_path) {
        r = drcom_appconf_load(&conf, cfg_path, errbuf, sizeof(errbuf));
        if (r < 0) {
            fprintf(stderr, "config error: %s\n", errbuf);
            return 2;
        }
    }
    if (opt_iface) {
        size_t n = strlen(opt_iface);
        if (n >= sizeof(conf.interface)) n = sizeof(conf.interface) - 1;
        __builtin_memcpy(conf.interface, opt_iface, n);
        conf.interface[n] = 0;
    }
    if (opt_foreground) conf.foreground = 1;
    if (opt_debug)       conf.log_level = DRCOM_LOG_LEVEL_DEBUG;
    drcom_appconf_apply_env(&conf);
    r = drcom_appconf_resolve_password(&conf, errbuf, sizeof(errbuf));
    if (r < 0) {
        fprintf(stderr, "password file error: %s\n", errbuf);
        return 2;
    }

    /* Auto-detect foreground when run from a TTY (no systemd). */
    bool under_systemd = getenv("INVOCATION_ID") != NULL;
    if (!under_systemd && !conf.foreground) {
        conf.foreground = !isatty(STDERR_FILENO);
    }

    drcom_log_init("jlu-drcom-authd", conf.log_level, conf.foreground);
    drcom_log_info("starting %s version %s", "jlu-drcom-authd", PACKAGE_VERSION);

    if (conf.username[0] == 0) {
        drcom_log_err("no Username configured");
        return 2;
    }

    sd_event *event = NULL;
    r = sd_event_default(&event);
    if (r < 0) {
        drcom_log_err("sd_event_default failed: %s", strerror(-r));
        return 1;
    }
    /* Enable systemd watchdog feeding inside sd_event. */
    (void)sd_event_set_watchdog(event, 1);

    r = setup_signals(event);
    if (r < 0) {
        drcom_log_err("signal setup failed: %s", strerror(-r));
        sd_event_unref(event);
        return 1;
    }

    drcom_authd_t *a = drcom_authd_new(&conf, event);
    if (!a) {
        drcom_log_err("out of memory");
        sd_event_unref(event);
        return 1;
    }

    r = drcom_authd_start(a);
    if (r < 0) {
        drcom_log_err("startup failed: %s", strerror(-r));
        drcom_authd_free(a);
        sd_event_unref(event);
        return 1;
    }

    if (opt_pid_file) {
        FILE *pf = fopen(opt_pid_file, "w");
        if (pf) {
            fprintf(pf, "%d\n", (int)getpid());
            fclose(pf);
        }
    }

    r = sd_event_loop(event);
    if (r < 0) {
        drcom_log_err("event loop exited with error: %s", strerror(-r));
    }

    drcom_authd_stop(a);
    drcom_authd_free(a);
    (void)sd_notify(0, "STOPPING=1");
    sd_event_unref(event);
    drcom_log_info("exiting");
    drcom_log_close();
    return (r < 0) ? 1 : 0;
}
