/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file appconf.h
 * @brief Runtime configuration: parse /etc/jlu-drcom-authd/jlu-drcom-authd.conf
 *
 * The file uses an INI-like grammar compatible with systemd's
 * configuration file conventions: comments start with '#' or ';', sections
 * are written as '[name]', and entries are 'Key = Value'.
 */
#ifndef DRCOM_APPCONF_H
#define DRCOM_APPCONF_H

#include "protocol.h" /* for DRCOM_USERNAME_MAX / PASSWORD_MAX / HOSTNAME_MAX */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DRCOM_HOST_MAX 64
#define DRCOM_IFACE_MAX 16

typedef enum {
	DRCOM_LOG_LEVEL_EMERG = 0,
	DRCOM_LOG_LEVEL_ALERT = 1,
	DRCOM_LOG_LEVEL_CRIT = 2,
	DRCOM_LOG_LEVEL_ERR = 3,
	DRCOM_LOG_LEVEL_WARN = 4,
	DRCOM_LOG_LEVEL_NOTICE = 5,
	DRCOM_LOG_LEVEL_INFO = 6,
	DRCOM_LOG_LEVEL_DEBUG = 7,
} drcom_log_level_t;

typedef struct {
	/* [Authentication] */
	char username[DRCOM_USERNAME_MAX];
	char password[DRCOM_PASSWORD_MAX];
	/** Optional password file path (read once at startup, mode 0600). */
	char password_file[256];

	/* [Network] */
	char server[DRCOM_HOST_MAX];	 /* hostname or IP */
	uint16_t port;					 /* default 61440 */
	char interface[DRCOM_IFACE_MAX]; /* optional, auto-detect if empty */
	uint8_t mac[6];					 /* explicit override, all-zero = auto */
	char hostname[DRCOM_HOSTNAME_MAX];

	/* [Daemon] */
	unsigned keepalive_sec;		  /* default 20 */
	unsigned recv_timeout_ms;	  /* default 5000 */
	unsigned restart_backoff_sec; /* default 5 */
	unsigned max_keepalive_fails; /* default 5; 0 = never exit */
	int log_level;				  /* drcom_log_level_t */
	int foreground;				  /* 1 = do not call daemon(3) */
} drcom_appconf_t;

/** Reset to defaults. */
void drcom_appconf_defaults(drcom_appconf_t *c);

/**
 * Parse a config file.
 *
 * @param c      Config to populate (call drcom_appconf_defaults first).
 * @param path   File to parse.  Use "-" for stdin.
 * @param errbuf Optional error buffer (256 bytes).
 * @return 0 on success, negative errno-style code on failure.
 */
int drcom_appconf_load(drcom_appconf_t *c,
					   const char *path,
					   char *errbuf,
					   size_t errbuf_sz);

/** Parse a single 'Key = Value' line in the context of the current section. */
int drcom_appconf_set(drcom_appconf_t *c,
					  const char *section,
					  const char *key,
					  const char *value,
					  char *errbuf,
					  size_t errbuf_sz);

/** Resolve environment overrides on top of an existing config. */
void drcom_appconf_apply_env(drcom_appconf_t *c);

/** Resolve password from password_file if set.  Returns 0 on success. */
int drcom_appconf_resolve_password(drcom_appconf_t *c, char *errbuf, size_t errbuf_sz);

/**
 * Validate cross-field constraints that drcom_appconf_load() cannot check
 * while parsing individual lines.
 *
 * Checks performed:
 *   - Username must be set.
 *   - Password must be set (either inline or resolved from PasswordFile).
 *   - Server must be set and non-empty.
 *   - Port must be in 1..65535.
 *   - If Interface is set, the interface must exist and have a MAC.
 *   - If MAC is set, it must not be all-zero.
 *   - If neither Interface nor MAC is set, an auto-detectable interface
 *     must exist.
 *   - Hostname, if set, must be non-empty and fit the protocol field.
 *   - KeepAliveSec, RecvTimeoutMs, RestartBackoffSec must be > 0.
 *
 * @return 0 on success, negative errno-style code on failure (errbuf
 *         filled with a human-readable message).
 */
int drcom_appconf_validate(const drcom_appconf_t *c, char *errbuf, size_t errbuf_sz);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_APPCONF_H */
