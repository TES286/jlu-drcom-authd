/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file appconf.c
 * @brief INI-style configuration parser.
 *
 * The grammar is intentionally a subset of systemd's .conf format; it is
 * small enough to fit in one file and avoids any external dependency.
 */
#include "appconf.h"
#include "protocol.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DRCOM_ERRBUF_SIZE 256

static int set_err(char *errbuf, size_t sz, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int set_err(char *errbuf, size_t sz, const char *fmt, ...)
{
    if (errbuf && sz > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(errbuf, sz, fmt, ap);
        va_end(ap);
    }
    return -EINVAL;
}

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = 0;
    }
    return s;
}

static int parse_uint(const char *v, unsigned *out)
{
    if (!*v) return -EINVAL;
    char *end;
    errno = 0;
    unsigned long x = strtoul(v, &end, 10);
    if (errno != 0 || *end != 0 || x > 0xffffffffu) return -EINVAL;
    *out = (unsigned)x;
    return 0;
}

static int parse_mac(const char *v, uint8_t out[6])
{
    /* Accept xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx (case-insensitive). */
    unsigned int t[6];
    int n = sscanf(v, "%x:%x:%x:%x:%x:%x",
                   &t[0], &t[1], &t[2], &t[3], &t[4], &t[5]);
    if (n != 6) {
        n = sscanf(v, "%x-%x-%x-%x-%x-%x",
                   &t[0], &t[1], &t[2], &t[3], &t[4], &t[5]);
    }
    if (n != 6) return -EINVAL;
    for (int i = 0; i < 6; i++) {
        if (t[i] > 0xff) return -EINVAL;
        out[i] = (uint8_t)t[i];
    }
    return 0;
}

void drcom_appconf_defaults(drcom_appconf_t *c)
{
    *c = (drcom_appconf_t){0};
    c->port = DRCOM_PORT;
    c->keepalive_sec = DRCOM_KEEPALIVE_SEC;
    c->recv_timeout_ms = DRCOM_RECV_TIMEOUT_MS;
    c->restart_backoff_sec = 5;
    c->log_level = DRCOM_LOG_LEVEL_INFO;
    c->foreground = 0;
    strncat(c->server, "auth.jlu.edu.cn", sizeof(c->server) - 1);
    /* hostname stays empty: resolved from uname() at runtime. */
}

static int copy_str(char *dst, size_t cap, const char *src)
{
    if (src == NULL) return -EINVAL;
    size_t n = strlen(src);
    if (n >= cap) return -ENAMETOOLONG;
    __builtin_memcpy(dst, src, n);
    dst[n] = 0;
    return 0;
}

int drcom_appconf_set(drcom_appconf_t *c, const char *section,
                      const char *key, const char *value,
                      char *errbuf, size_t errbuf_sz)
{
    if (strcmp(section, "Authentication") == 0) {
        if (strcmp(key, "Username") == 0) return copy_str(c->username, sizeof(c->username), value) ? set_err(errbuf, errbuf_sz, "username too long") : 0;
        if (strcmp(key, "Password") == 0) return copy_str(c->password, sizeof(c->password), value) ? set_err(errbuf, errbuf_sz, "password too long") : 0;
        if (strcmp(key, "PasswordFile") == 0) return copy_str(c->password_file, sizeof(c->password_file), value) ? set_err(errbuf, errbuf_sz, "password file path too long") : 0;
    } else if (strcmp(section, "Network") == 0) {
        if (strcmp(key, "Server") == 0) return copy_str(c->server, sizeof(c->server), value) ? set_err(errbuf, errbuf_sz, "server too long") : 0;
        if (strcmp(key, "Port") == 0) {
            unsigned p;
            int r = parse_uint(value, &p);
            if (r < 0 || p == 0 || p > 65535) return set_err(errbuf, errbuf_sz, "invalid Port: %s", value);
            c->port = (uint16_t)p;
            return 0;
        }
        if (strcmp(key, "Interface") == 0) return copy_str(c->interface, sizeof(c->interface), value) ? set_err(errbuf, errbuf_sz, "interface name too long") : 0;
        if (strcmp(key, "MAC") == 0) {
            int r = parse_mac(value, c->mac);
            if (r < 0) return set_err(errbuf, errbuf_sz, "invalid MAC: %s", value);
            return 0;
        }
        if (strcmp(key, "Hostname") == 0) return copy_str(c->hostname, sizeof(c->hostname), value) ? set_err(errbuf, errbuf_sz, "hostname too long") : 0;
    } else if (strcmp(section, "Daemon") == 0) {
        if (strcmp(key, "KeepAliveSec") == 0) {
            unsigned v; int r = parse_uint(value, &v);
            if (r < 0 || v == 0) return set_err(errbuf, errbuf_sz, "invalid KeepAliveSec: %s", value);
            c->keepalive_sec = v;
            return 0;
        }
        if (strcmp(key, "RecvTimeoutMs") == 0) {
            unsigned v; int r = parse_uint(value, &v);
            if (r < 0) return set_err(errbuf, errbuf_sz, "invalid RecvTimeoutMs: %s", value);
            c->recv_timeout_ms = v;
            return 0;
        }
        if (strcmp(key, "RestartBackoffSec") == 0) {
            unsigned v; int r = parse_uint(value, &v);
            if (r < 0) return set_err(errbuf, errbuf_sz, "invalid RestartBackoffSec: %s", value);
            c->restart_backoff_sec = v;
            return 0;
        }
        if (strcmp(key, "LogLevel") == 0) {
            if      (strcmp(value, "emerg")   == 0) c->log_level = DRCOM_LOG_LEVEL_EMERG;
            else if (strcmp(value, "alert")   == 0) c->log_level = DRCOM_LOG_LEVEL_ALERT;
            else if (strcmp(value, "crit")    == 0) c->log_level = DRCOM_LOG_LEVEL_CRIT;
            else if (strcmp(value, "err")     == 0) c->log_level = DRCOM_LOG_LEVEL_ERR;
            else if (strcmp(value, "warning") == 0) c->log_level = DRCOM_LOG_LEVEL_WARN;
            else if (strcmp(value, "notice")  == 0) c->log_level = DRCOM_LOG_LEVEL_NOTICE;
            else if (strcmp(value, "info")    == 0) c->log_level = DRCOM_LOG_LEVEL_INFO;
            else if (strcmp(value, "debug")   == 0) c->log_level = DRCOM_LOG_LEVEL_DEBUG;
            else return set_err(errbuf, errbuf_sz, "invalid LogLevel: %s", value);
            return 0;
        }
        if (strcmp(key, "Foreground") == 0) {
            if (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0) c->foreground = 1;
            else if (strcmp(value, "false") == 0 || strcmp(value, "no") == 0 || strcmp(value, "0") == 0) c->foreground = 0;
            else return set_err(errbuf, errbuf_sz, "invalid Foreground: %s", value);
            return 0;
        }
    }
    /* Unknown keys are silently ignored to allow forward compatibility. */
    return 0;
}

int drcom_appconf_load(drcom_appconf_t *c, const char *path, char *errbuf, size_t errbuf_sz)
{
    FILE *fp = (strcmp(path, "-") == 0) ? stdin : fopen(path, "r");
    if (!fp) {
        return set_err(errbuf, errbuf_sz, "cannot open %s: %s", path, strerror(errno));
    }

    char line[512];
    char section[64] = "";
    int lineno = 0;
    int rc = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;
        /* Strip trailing newline. */
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) {
            line[--n] = 0;
        }
        char *s = trim(line);
        if (*s == 0 || *s == '#' || *s == ';') continue;
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) {
                rc = set_err(errbuf, errbuf_sz, "%s:%d: missing ] in section header", path, lineno);
                break;
            }
            *end = 0;
            char *name = trim(s + 1);
            if (strlen(name) >= sizeof(section)) {
                rc = set_err(errbuf, errbuf_sz, "%s:%d: section name too long", path, lineno);
                break;
            }
            size_t sn = strlen(name);
            __builtin_memcpy(section, name, sn);
            section[sn] = 0;
            continue;
        }
        char *eq = strchr(s, '=');
        if (!eq) {
            rc = set_err(errbuf, errbuf_sz, "%s:%d: missing '='", path, lineno);
            break;
        }
        *eq = 0;
        char *key = trim(s);
        char *val = trim(eq + 1);
        /* Strip optional surrounding quotes. */
        size_t vn = strlen(val);
        if (vn >= 2 && ((val[0] == '"' && val[vn-1] == '"') ||
                        (val[0] == '\'' && val[vn-1] == '\''))) {
            val[vn-1] = 0;
            val++;
        }
        rc = drcom_appconf_set(c, section, key, val, errbuf, errbuf_sz);
        if (rc < 0) {
            char buf2[DRCOM_ERRBUF_SIZE] = "";
            if (errbuf && errbuf_sz > 0) {
                snprintf(buf2, sizeof(buf2), "%s", errbuf);
            }
            rc = set_err(errbuf, errbuf_sz, "%s:%d: %s", path, lineno, buf2);
            break;
        }
    }

    if (fp != stdin) fclose(fp);
    return rc;
}

void drcom_appconf_apply_env(drcom_appconf_t *c)
{
    const char *e;
    if ((e = getenv("DRCOM_USERNAME")) != NULL) (void)copy_str(c->username, sizeof(c->username), e);
    if ((e = getenv("DRCOM_PASSWORD")) != NULL) (void)copy_str(c->password, sizeof(c->password), e);
    if ((e = getenv("DRCOM_SERVER"))   != NULL) (void)copy_str(c->server,    sizeof(c->server),    e);
    if ((e = getenv("DRCOM_INTERFACE"))!= NULL) (void)copy_str(c->interface, sizeof(c->interface), e);
    if ((e = getenv("DRCOM_FOREGROUND")) != NULL) {
        c->foreground = (strcmp(e, "1") == 0 || strcmp(e, "true") == 0 || strcmp(e, "yes") == 0);
    }
}

int drcom_appconf_resolve_password(drcom_appconf_t *c, char *errbuf, size_t errbuf_sz)
{
    if (c->password_file[0] == 0) {
        return 0;
    }
    FILE *fp = fopen(c->password_file, "r");
    if (!fp) {
        return set_err(errbuf, errbuf_sz, "cannot open password file %s: %s",
                       c->password_file, strerror(errno));
    }
    char buf[DRCOM_PASSWORD_MAX];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    /* Strip a single trailing newline if present. */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) {
        n--;
    }
    buf[n] = 0;
    if (n == 0) {
        return set_err(errbuf, errbuf_sz, "password file %s is empty", c->password_file);
    }
    __builtin_memcpy(c->password, buf, n + 1);
    return 0;
}
