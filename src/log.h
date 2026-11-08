/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file log.h
 * @brief Structured logging facade over sd-journal with stderr fallback.
 *
 * When the daemon is connected to the journal (i.e. SD_JOURNAL_SOCKET_PATH
 * is reachable, or simply running under systemd), messages are sent via
 * sd_journal_send.  Otherwise they go to stderr with a syslog-style prefix
 * so they still show up in `journalctl -t` style captures.
 */
#ifndef DRCOM_LOG_H
#define DRCOM_LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void drcom_log_init(const char *identifier, int min_level, bool foreground);
void drcom_log_close(void);

void drcom_log(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

void drcom_vlog(int level, const char *fmt, va_list ap)
    __attribute__((format(printf, 2, 0)));

/* Convenience macros that capture call site automatically. */
#define drcom_log_emerg(...)   drcom_log(DRCOM_LOG_LEVEL_EMERG, __VA_ARGS__)
#define drcom_log_alert(...)   drcom_log(DRCOM_LOG_LEVEL_ALERT, __VA_ARGS__)
#define drcom_log_crit(...)    drcom_log(DRCOM_LOG_LEVEL_CRIT,  __VA_ARGS__)
#define drcom_log_err(...)     drcom_log(DRCOM_LOG_LEVEL_ERR,   __VA_ARGS__)
#define drcom_log_warn(...)    drcom_log(DRCOM_LOG_LEVEL_WARN,  __VA_ARGS__)
#define drcom_log_notice(...)  drcom_log(DRCOM_LOG_LEVEL_NOTICE,__VA_ARGS__)
#define drcom_log_info(...)    drcom_log(DRCOM_LOG_LEVEL_INFO,  __VA_ARGS__)
#define drcom_log_debug(...)   drcom_log(DRCOM_LOG_LEVEL_DEBUG, __VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_LOG_H */
