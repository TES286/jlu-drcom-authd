/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Test-only deterministic RNG. protocol.c is compiled with
 * -Ddrcom_random=reference_random; the production binary is untouched. */
#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t random_state;

void reference_random(uint8_t *out, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		random_state = random_state * 1664525u + 1013904223u;
		out[i] = (uint8_t)(random_state >> 24);
	}
}

static void decode(const char *hex, void *out, size_t cap)
{
	size_t len = strlen(hex);
	if (len % 2 || len / 2 > cap)
		exit(2);
	for (size_t i = 0; i < len / 2; i++) {
		unsigned byte;
		if (sscanf(hex + i * 2, "%2x", &byte) != 1)
			exit(2);
		((uint8_t *)out)[i] = (uint8_t)byte;
	}
}

static void emit(const char *type, const uint8_t *packet, size_t n)
{
	printf("%s ", type);
	for (size_t i = 0; i < n; i++)
		printf("%02x", packet[i]);
	putchar('\n');
}

int main(void)
{
	char *line = NULL;
	size_t cap = 0;
	while (getline(&line, &cap, stdin) >= 0) {
		char *fields[13];
		char *save = NULL;
		for (size_t i = 0; i < 13; i++) {
			fields[i] = strtok_r(i ? NULL : line, " \r\n", &save);
			if (!fields[i])
				return 2;
		}
		drcom_session_t s;
		drcom_session_init(&s);
		decode(fields[0], s.username, sizeof(s.username) - 1);
		decode(fields[1], s.password, sizeof(s.password) - 1);
		decode(fields[2], s.mac, sizeof(s.mac));
		decode(fields[3], s.salt, sizeof(s.salt));
		decode(fields[4], s.client_ip, sizeof(s.client_ip));
		decode(fields[5], s.hostname, sizeof(s.hostname));
		uint8_t ver[2], tail1[16], tail2[4];
		decode(fields[6], ver, sizeof(ver));
		decode(fields[7], tail1, sizeof(tail1));
		decode(fields[8], tail2, sizeof(tail2));
		random_state = (uint32_t)strtoul(fields[9], NULL, 10);
		unsigned cycles = (unsigned)strtoul(fields[10], NULL, 10);
		s.challenge_times = (uint8_t)strtoul(fields[11], NULL, 10);
		s.count = (uint32_t)strtoul(fields[12], NULL, 10);
		uint8_t packet[DRCOM_LOGIN_REQ_MAX];
		size_t n = drcom_challenge_pack(packet, &s);
		emit("challenge", packet, n);
		n = drcom_login_pack(packet, sizeof(packet), &s);
		if (n == 0)
			return 2;
		emit("login", packet, n);
		memcpy(s.tail1, tail1, sizeof(tail1));
		for (unsigned i = 0; i < cycles; i++) {
			n = drcom_keep38_pack(packet, &s);
			emit("keep38", packet, n);
			memcpy(s.keep_alive_ver, ver, sizeof(ver));
			if (drcom_keep38_needs_extra(&s)) {
				n = drcom_keep40_extra_pack(packet, &s);
				emit("extra", packet, n);
			}
			n = drcom_keep40_1_pack(packet, &s);
			emit("keep40_1", packet, n);
			memcpy(s.tail2, tail2, sizeof(tail2));
			n = drcom_keep40_2_pack(packet, &s);
			emit("keep40_2", packet, n);
			drcom_keep38_advance(&s);
		}
		n = drcom_challenge_pack(packet, &s);
		emit("logout_challenge", packet, n);
		n = drcom_logout_pack(packet, &s);
		emit("logout", packet, n);
		puts("end");
	}
	free(line);
	return 0;
}
