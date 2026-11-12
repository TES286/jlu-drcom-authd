/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file test_appconf.c
 * @brief Unit tests for the appconf (config) parser.
 */
#include "appconf.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, ...)                                                                 \
	do {                                                                                 \
		if (!(cond)) {                                                                   \
			fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                         \
			fprintf(stderr, __VA_ARGS__);                                                \
			fprintf(stderr, "\n");                                                       \
			failures++;                                                                  \
		}                                                                                \
	} while (0)

static void write_tmp(const char *path, const char *content)
{
	FILE *fp = fopen(path, "w");
	CHECK(fp != NULL, "could not write %s", path);
	if (fp) {
		fputs(content, fp);
		fclose(fp);
	}
}

static void test_defaults(void)
{
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	CHECK(c.port == 61440, "default port should be 61440, got %u", (unsigned)c.port);
	CHECK(c.keepalive_sec == 20, "default keepalive should be 20");
	CHECK(c.recv_timeout_ms == 5000, "default recv timeout should be 5000");
	CHECK(c.restart_backoff_sec == 5, "default restart backoff should be 5");
	CHECK(c.max_keepalive_fails == 5, "default max_keepalive_fails should be 5");
	CHECK(strcmp(c.server, "auth.jlu.edu.cn") == 0, "default server wrong: %s", c.server);
	CHECK(c.log_level == DRCOM_LOG_LEVEL_INFO, "default log level should be INFO");
}

static void test_parse_basic(void)
{
	const char *path = "/tmp/drcom_test_basic.conf";
	write_tmp(path,
			  "# Comment line\n"
			  "[Authentication]\n"
			  "Username = alice\n"
			  "Password = secret\n"
			  "\n"
			  "[Network]\n"
			  "Server = 10.100.61.3\n"
			  "Port = 61440\n"
			  "MAC = aa:bb:cc:dd:ee:ff\n"
			  "Hostname = myhost\n"
			  "\n"
			  "[Daemon]\n"
			  "KeepAliveSec = 30\n"
			  "LogLevel = debug\n"
			  "Foreground = true\n");

	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	char err[256] = "";
	int r = drcom_appconf_load(&c, path, err, sizeof(err));
	CHECK(r == 0, "load failed: %s", err);
	CHECK(strcmp(c.username, "alice") == 0, "username wrong: %s", c.username);
	CHECK(strcmp(c.password, "secret") == 0, "password wrong");
	CHECK(strcmp(c.server, "10.100.61.3") == 0, "server wrong: %s", c.server);
	CHECK(c.port == 61440, "port wrong");
	CHECK(c.mac[0] == 0xaa && c.mac[5] == 0xff, "mac not parsed");
	CHECK(strcmp(c.hostname, "myhost") == 0, "hostname wrong: %s", c.hostname);
	CHECK(c.keepalive_sec == 30, "keepalive wrong");
	CHECK(c.log_level == DRCOM_LOG_LEVEL_DEBUG, "log level wrong");
	CHECK(c.foreground == 1, "foreground should be true");
	unlink(path);
}

static void test_parse_dashed_mac(void)
{
	const char *path = "/tmp/drcom_test_dash.conf";
	write_tmp(path,
			  "[Network]\n"
			  "MAC = aa-bb-cc-dd-ee-ff\n");
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	char err[256] = "";
	int r = drcom_appconf_load(&c, path, err, sizeof(err));
	CHECK(r == 0, "load failed: %s", err);
	CHECK(c.mac[0] == 0xaa && c.mac[5] == 0xff, "dashed mac not parsed");
	unlink(path);
}

static void test_parse_invalid_port(void)
{
	const char *path = "/tmp/drcom_test_inv.conf";
	write_tmp(path,
			  "[Network]\n"
			  "Port = 99999\n");
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	char err[256] = "";
	int r = drcom_appconf_load(&c, path, err, sizeof(err));
	CHECK(r < 0, "invalid port should fail");
	unlink(path);
}

static void test_parse_quoted_value(void)
{
	const char *path = "/tmp/drcom_test_quoted.conf";
	write_tmp(path,
			  "[Authentication]\n"
			  "Username = \"bob\"\n"
			  "Password = 'p@ss with spaces'\n");
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	char err[256] = "";
	int r = drcom_appconf_load(&c, path, err, sizeof(err));
	CHECK(r == 0, "load failed: %s", err);
	CHECK(strcmp(c.username, "bob") == 0, "quoted username wrong: %s", c.username);
	CHECK(strcmp(c.password, "p@ss with spaces") == 0,
		  "quoted password wrong: %s",
		  c.password);
	unlink(path);
}

static void test_password_file(void)
{
	const char *pwfile = "/tmp/drcom_test_pw.txt";
	const char *cfgpath = "/tmp/drcom_test_pw.conf";
	write_tmp(pwfile, "filepassword\n");
	write_tmp(cfgpath,
			  "[Authentication]\n"
			  "Username = carol\n"
			  "PasswordFile = /tmp/drcom_test_pw.txt\n");
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	char err[256] = "";
	int r = drcom_appconf_load(&c, cfgpath, err, sizeof(err));
	CHECK(r == 0, "load failed: %s", err);
	CHECK(c.password[0] == 0, "password should not be set yet");
	r = drcom_appconf_resolve_password(&c, err, sizeof(err));
	CHECK(r == 0, "resolve_password failed: %s", err);
	CHECK(strcmp(c.password, "filepassword") == 0,
		  "password not loaded from file: %s",
		  c.password);
	unlink(pwfile);
	unlink(cfgpath);
}

static void test_unknown_keys_ignored(void)
{
	const char *path = "/tmp/drcom_test_unk.conf";
	write_tmp(path,
			  "[Authentication]\n"
			  "Username = dave\n"
			  "UnknownKey = whatever\n"
			  "[UnknownSection]\n"
			  "Foo = bar\n");
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	char err[256] = "";
	int r = drcom_appconf_load(&c, path, err, sizeof(err));
	CHECK(r == 0, "unknown keys should be ignored, got error: %s", err);
	CHECK(strcmp(c.username, "dave") == 0, "username should still be parsed");
	unlink(path);
}

/* ---- drcom_appconf_validate() tests ---- */

static void test_validate_missing_username(void)
{
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	/* Set password but not username. */
	strncat(c.password, "secret", sizeof(c.password) - 1);
	char err[256] = "";
	int r = drcom_appconf_validate(&c, err, sizeof(err));
	CHECK(r < 0, "validate should fail with missing username");
	CHECK(strstr(err, "Username") != NULL, "error should mention Username: %s", err);
}

static void test_validate_missing_password(void)
{
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	strncat(c.username, "user", sizeof(c.username) - 1);
	/* No password, no password_file. */
	char err[256] = "";
	int r = drcom_appconf_validate(&c, err, sizeof(err));
	CHECK(r < 0, "validate should fail with missing password");
	CHECK(strstr(err, "Password") != NULL, "error should mention Password: %s", err);
}

static void test_validate_bad_interface(void)
{
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	strncat(c.username, "user", sizeof(c.username) - 1);
	strncat(c.password, "pass", sizeof(c.password) - 1);
	strncat(c.interface, "nonexistent_iface_xyz", sizeof(c.interface) - 1);
	char err[256] = "";
	int r = drcom_appconf_validate(&c, err, sizeof(err));
	CHECK(r < 0, "validate should fail with non-existent interface");
	CHECK(strstr(err, "Interface") != NULL, "error should mention Interface: %s", err);
}

static void test_validate_max_keepalive_fails(void)
{
	/* max_keepalive_fails == 0 is allowed (means "never exit"). */
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	strncat(c.username, "user", sizeof(c.username) - 1);
	strncat(c.password, "pass", sizeof(c.password) - 1);
	/* Provide a MAC so interface detection is skipped. */
	c.mac[0] = 0xaa;
	c.mac[5] = 0xff;
	c.interface[0] = 0; /* no interface, use explicit MAC */
	c.max_keepalive_fails = 0;
	char err[256] = "";
	int r = drcom_appconf_validate(&c, err, sizeof(err));
	CHECK(r == 0, "max_keepalive_fails=0 should be valid: %s", err);
}

static void test_validate_timing_zero(void)
{
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	strncat(c.username, "user", sizeof(c.username) - 1);
	strncat(c.password, "pass", sizeof(c.password) - 1);
	c.mac[0] = 0xaa;
	c.interface[0] = 0;
	c.keepalive_sec = 0;
	char err[256] = "";
	int r = drcom_appconf_validate(&c, err, sizeof(err));
	CHECK(r < 0, "validate should fail with keepalive_sec=0");
	CHECK(strstr(err, "KeepAliveSec") != NULL,
		  "error should mention KeepAliveSec: %s",
		  err);
}

static void test_validate_credential_limits(void)
{
	drcom_appconf_t c;
	drcom_appconf_defaults(&c);
	memset(c.username, 'u', 36);
	memset(c.password, 'p', 16);
	c.mac[0] = 1;
	char err[256];
	CHECK(drcom_appconf_validate(&c, err, sizeof(err)) == 0,
		  "maximum ASCII credentials should validate: %s",
		  err);
	c.password[16] = 'p';
	CHECK(drcom_appconf_validate(&c, err, sizeof(err)) < 0,
		  "17-byte password should be rejected instead of truncated");
	c.password[16] = 0;
	c.username[36] = 'u';
	CHECK(drcom_appconf_validate(&c, err, sizeof(err)) < 0,
		  "37-byte username should be rejected instead of truncated");
	c.username[36] = 0;
	c.password[0] = (char)0xc3;
	CHECK(drcom_appconf_validate(&c, err, sizeof(err)) < 0,
		  "non-ASCII credentials should be rejected");
}

int main(void)
{
	test_defaults();
	test_parse_basic();
	test_parse_dashed_mac();
	test_parse_invalid_port();
	test_parse_quoted_value();
	test_password_file();
	test_unknown_keys_ignored();
	test_validate_missing_username();
	test_validate_missing_password();
	test_validate_bad_interface();
	test_validate_max_keepalive_fails();
	test_validate_timing_zero();
	test_validate_credential_limits();

	if (failures == 0) {
		printf("test_appconf: PASS\n");
		return 0;
	}
	printf("test_appconf: %d FAILURES\n", failures);
	return 1;
}
