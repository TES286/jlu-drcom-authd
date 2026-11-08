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

int main(void)
{
	test_defaults();
	test_parse_basic();
	test_parse_dashed_mac();
	test_parse_invalid_port();
	test_parse_quoted_value();
	test_password_file();
	test_unknown_keys_ignored();

	if (failures == 0) {
		printf("test_appconf: PASS\n");
		return 0;
	}
	printf("test_appconf: %d FAILURES\n", failures);
	return 1;
}
