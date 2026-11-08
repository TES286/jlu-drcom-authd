/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file log.c
 * @brief sd-journal wrapper with stderr fallback.
 */
#define _GNU_SOURCE 1
#include "appconf.h"
#include "log.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <systemd/sd-journal.h>

static struct {
	char identifier[32];
	int min_level;
	bool foreground;
	bool journal_ok;
	_Atomic int seq;
} g_log = {
	.identifier = "jlu-drcom-authd",
	.min_level = DRCOM_LOG_LEVEL_INFO,
	.foreground = false,
	.journal_ok = false,
	.seq = 0,
};

void drcom_log_init(const char *identifier, int min_level, bool foreground)
{
	if (identifier) {
		size_t n = strlen(identifier);
		if (n >= sizeof(g_log.identifier))
			n = sizeof(g_log.identifier) - 1;
		__builtin_memcpy(g_log.identifier, identifier, n);
		g_log.identifier[n] = 0;
	}
	g_log.min_level = min_level;
	g_log.foreground = foreground;
	/* When running in foreground (e.g. under `systemctl status`, in a
	 * terminal, or in CI), always log to stderr so the output is visible
	 * to the operator.  Otherwise probe the journal socket once at
	 * startup; if unreachable, fall back to stderr without retrying. */
	if (foreground) {
		g_log.journal_ok = false;
		return;
	}
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		g_log.journal_ok = false;
		return;
	}
	struct sockaddr_un sa = {0};
	sa.sun_family = AF_UNIX;
	__builtin_strncpy(
		sa.sun_path, "/run/systemd/journal/socket", sizeof(sa.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		g_log.journal_ok = true;
	} else {
		g_log.journal_ok = false;
	}
	close(fd);
}

void drcom_log_close(void)
{
	/* Nothing to free; included for symmetry. */
}

void drcom_vlog(int level, const char *fmt, va_list ap)
{
	if (level > g_log.min_level) {
		return;
	}

	char body[1024];
	int n = vsnprintf(body, sizeof(body), fmt, ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(body)) {
		n = (int)sizeof(body) - 1;
	}

	if (g_log.journal_ok) {
		/* sd_journal_send automatically attaches CODE_FILE/LINE/FUNC
		 * (suppressed via SD_JOURNAL_SUPPRESS_LOCATION if needed). */
		sd_journal_send("PRIORITY=%d",
						level,
						"SYSLOG_IDENTIFIER=%s",
						g_log.identifier,
						"MESSAGE=%s",
						body,
						NULL);
	} else {
		/* Stderr fallback.  systemd's sd-daemon parses the <N> prefix. */
		fprintf(stderr,
				"<%d>%s[%d]: %s\n",
				level,
				g_log.identifier,
				atomic_fetch_add(&g_log.seq, 1),
				body);
	}
}

void drcom_log(int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	drcom_vlog(level, fmt, ap);
	va_end(ap);
}
