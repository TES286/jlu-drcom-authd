/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file protocol.c
 * @brief JLU Drcom wire protocol implementation.
 *
 * Field offsets and constants follow the protocol document at
 *   https://github.com/drcoms/jlu-drcom-client/blob/master/jlu-drcom-java/jlu-drcom-protocol.md
 *
 * All multi-byte integer fields in the on-wire format are little-endian or
 * byte-aligned; there is no endianness-sensitive integer interpretation
 * beyond what @ref crypto.c handles.
 */
#define _POSIX_C_SOURCE 200809L /* strnlen */

#include "crypto.h"
#include "protocol.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

/* Magic strings embedded verbatim in the login packet.
 * Using unsigned char avoids the 0xcf sign-conversion warning. */
static const unsigned char k_drcom_check_str[] = {
	0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0xcf, 0x07};
static const char k_login_str[] = "1c210c99585fd22ad03d35c956911aeec1eb449b";

/* Primary DNS (10.10.10.10) emitted in the login packet. */
static const uint8_t k_primary_dns[4] = {10, 10, 10, 10};

/* Initial keepAliveVer used before the first keep38 response. */
static const uint8_t k_keep_alive_ver_init[2] = {0xdc, 0x02};

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

const char *drcom_strerror(drcom_err_t e)
{
	switch (e) {
	case DRCOM_OK:
		return "success";
	case DRCOM_ERR_BAD_PACKET:
		return "malformed packet from server";
	case DRCOM_ERR_AUTH:
		return "authentication rejected by server";
	case DRCOM_ERR_SERVER:
		return "unexpected server reply";
	case DRCOM_ERR_BUFFER:
		return "buffer too small";
	case DRCOM_ERR_INVALID:
		return "invalid session state";
	}
	return "unknown error";
}

void drcom_session_init(drcom_session_t *s)
{
	*s = (drcom_session_t){0};
	s->challenge_times = 2; /* server expects 0x02 on first contact */
	__builtin_memcpy(s->keep_alive_ver, k_keep_alive_ver_init, 2);
}

static size_t bounded_strlen(const char *s, size_t max_len)
{
	size_t n = strnlen(s, max_len);
	return n;
}

static void copy_ljust(uint8_t *dst, size_t cap, const char *src, size_t src_len)
{
	if (src_len > cap)
		src_len = cap;
	__builtin_memcpy(dst, src, src_len);
	__builtin_memset(dst + src_len, 0, cap - src_len);
}

/* ------------------------------------------------------------------ */
/* Challenge                                                          */
/* ------------------------------------------------------------------ */

size_t drcom_challenge_pack(uint8_t out[DRCOM_CHALLENGE_REQ_SIZE], drcom_session_t *s)
{
	static const uint8_t k_tail[15] = {0};
	out[0] = 0x01;
	out[1] = s->challenge_times++;
	drcom_random(out + 2, 2); /* rand1, rand2 */
	out[4] = 0x6a;
	__builtin_memcpy(out + 5, k_tail, sizeof(k_tail));
	return DRCOM_CHALLENGE_REQ_SIZE;
}

drcom_err_t drcom_challenge_parse(const uint8_t *in, size_t len, drcom_session_t *s)
{
	if (len < DRCOM_CHALLENGE_REP_SIZE) {
		return DRCOM_ERR_BAD_PACKET;
	}
	if (in[0] != 0x02) {
		return DRCOM_ERR_SERVER;
	}
	__builtin_memcpy(s->salt, in + 4, 4);
	__builtin_memcpy(s->client_ip, in + 20, 4);
	return DRCOM_OK;
}

/* ------------------------------------------------------------------ */
/* Login                                                              */
/* ------------------------------------------------------------------ */

/**
 * Login packet layout (offsets):
 *   [0]    code=0x03
 *   [1]    type=0x01
 *   [2]    EOF=0x00
 *   [3]    unameLen + 20
 *   [4..19]  md5a
 *   [20..55] username, ljust to 36 bytes
 *   [56]   controlCheck=0x20
 *   [57]   adapterNum=0x05
 *   [58..63] md5a[0..5] ^ mac[0..5]
 *   [64..79] md5b = md5(0x01, password, salt, 0x00000000)
 *   [80]   numOfIP = 1
 *   [81..84] IP1 = client_ip
 *   [85..96] IP2/3/4 = zeros
 *   [97..104] md5c[0..7]  (md5c = md5(data[0:97] ++ 0x14_00_07_0b))
 *   [105]  ipDog=0x01
 *   [110..141] hostname ljust to 32 bytes
 *   [142..145] primaryDNS = 10.10.10.10
 *   [146..149] dhcp = zeros
 *   [150..153] 2ndDNS = zeros
 *   [162]  0x94
 *   [166]  0x06  (os major)
 *   [170]  0x02  (os minor)
 *   [174..175] 0xf0 0x23  (os build)
 *   [178]  0x02
 *   [182..189] DRCOM CHECK magic
 *   [190]  0x6a
 *   [246..285] 40-byte ASCII str
 *   [310]  0x6a
 *   [311..312] 0x00 0x00
 *   [313]  passLen
 *   [314..313+passLen] ror(md5a, password)
 *   [314+passLen] 0x02
 *   [315+passLen] 0x0c
 *   [316+passLen..319+passLen] checksum
 *   [320+passLen..321+passLen] 0x00 0x00
 *   [322+passLen..327+passLen] mac[0..5]
 *   [328+passLen..328+passLen+zeroCount-1] zeros
 *   [328+passLen+zeroCount..329+passLen+zeroCount] rand1, rand2
 *
 * Total length = 334 + ((passLen - 1) / 4) * 4
 */
size_t drcom_login_pack(uint8_t *out, size_t cap, drcom_session_t *s)
{
	size_t pass_len = bounded_strlen(s->password, sizeof(s->password));
	size_t uname_len = bounded_strlen(s->username, sizeof(s->username));
	if (pass_len == 0 || pass_len > 16 || uname_len > 36) {
		return 0;
	}
	size_t data_len = 334u + ((pass_len - 1u) / 4u) * 4u;
	if (cap < data_len) {
		return 0;
	}
	size_t zero_count = (4u - pass_len % 4u) % 4u;

	/* md5a = md5(0x03 0x01, salt, password). */
	static const uint8_t k_login_code[2] = {0x03, 0x01};
	static const uint8_t k_md5b_prefix[1] = {0x01};
	static const uint8_t k_md5b_suffix[4] = {0, 0, 0, 0};

	{
		const uint8_t *parts[3] = {k_login_code, s->salt, (const uint8_t *)s->password};
		const size_t lens[3] = {sizeof(k_login_code), sizeof(s->salt), pass_len};
		drcom_md5_multi(s->md5a, parts, lens, 3);
	}

	uint8_t md5b[16];
	{
		const uint8_t *parts[4] = {
			k_md5b_prefix,
			(const uint8_t *)s->password,
			s->salt,
			k_md5b_suffix,
		};
		const size_t lens[4] = {
			sizeof(k_md5b_prefix),
			pass_len,
			sizeof(s->salt),
			sizeof(k_md5b_suffix),
		};
		drcom_md5_multi(md5b, parts, lens, 4);
	}

	__builtin_memset(out, 0, data_len);
	out[0] = 0x03;
	out[1] = 0x01;
	out[2] = 0x00;
	out[3] = (uint8_t)(uname_len + 20u);
	__builtin_memcpy(out + 4, s->md5a, 16);
	copy_ljust(out + 20, 36, s->username, uname_len);
	out[56] = 0x20; /* controlCheck */
	out[57] = 0x05; /* adapterNum */
	/* md5a[0..5] ^ mac[0..5] */
	for (int i = 0; i < 6; i++) {
		out[58 + i] = (uint8_t)(s->md5a[i] ^ s->mac[i]);
	}
	__builtin_memcpy(out + 64, md5b, 16);
	out[80] = 0x01; /* numOfIP */
	__builtin_memcpy(out + 81, s->client_ip, 4);
	/* [85..96] IP2/3/4 zeros (already zero). */
	/* [97..100] will be md5c[0..3]; first write the suffix constant. */
	out[97] = 0x14;
	out[98] = 0x00;
	out[99] = 0x07;
	out[100] = 0x0b;
	/* md5c = md5(out[0:101]).  We use the first 8 bytes. */
	{
		uint8_t md5c[16];
		const uint8_t *parts[1] = {out};
		const size_t lens[1] = {101};
		drcom_md5_multi(md5c, parts, lens, 1);
		__builtin_memcpy(out + 97, md5c, 8);
	}
	out[105] = 0x01; /* ipDog */
	/* [106..109] zeros. */
	{
		size_t hn_len = bounded_strlen(s->hostname, 32);
		copy_ljust(out + 110, 32, s->hostname, hn_len);
	}
	__builtin_memcpy(out + 142, k_primary_dns, 4);
	/* [146..149] dhcp zeros, [150..161] zeros. */
	out[162] = 0x94;
	/* [163..165] zeros. */
	out[166] = 0x06;
	/* [167..169] zeros. */
	out[170] = 0x02;
	/* [171..173] zeros. */
	out[174] = (uint8_t)0xf0;
	out[175] = 0x23;
	/* [176..177] zeros. */
	out[178] = 0x02;
	/* [179..181] zeros. */
	__builtin_memcpy(out + 182, k_drcom_check_str, 8);
	out[190] = 0x6a;
	/* [191..245] zeros. */
	__builtin_memcpy(out + 246, k_login_str, 40);
	/* [286..309] zeros. */
	out[310] = 0x6a;
	/* [311..312] zeros. */
	out[313] = (uint8_t)pass_len;

	/* ror(md5a, password) at [314:314+pass_len]. */
	drcom_ror(out + 314, s->md5a, (const uint8_t *)s->password, pass_len);

	/* 0x02, 0x0c, checksum placeholder, then real checksum. */
	out[314 + pass_len] = 0x02;
	out[315 + pass_len] = 0x0c;
	/* Temporarily write the suffix constants used in the checksum input. */
	out[316 + pass_len] = 0x01;
	out[317 + pass_len] = 0x26;
	out[318 + pass_len] = 0x07;
	out[319 + pass_len] = 0x11;
	out[320 + pass_len] = 0x00;
	out[321 + pass_len] = 0x00;
	__builtin_memcpy(out + 322 + pass_len, s->mac, 4);
	/* Match the Java reference: include the first four MAC bytes. */
	{
		uint8_t cks[DRCOM_CHECKSUM_SIZE];
		drcom_checksum(cks, out, 326u + pass_len);
		__builtin_memcpy(out + 316 + pass_len, cks, 4);
	}
	out[320 + pass_len] = 0x00;
	out[321 + pass_len] = 0x00;
	__builtin_memcpy(out + 322 + pass_len, s->mac, 6);
	/* [328+pass_len .. 328+pass_len+zero_count-1] zeros (already zero). */
	/* rand1, rand2 at the end. */
	drcom_random(out + 328u + pass_len + zero_count, 2);

	return data_len;
}

drcom_err_t drcom_login_parse(const uint8_t *in, size_t len, drcom_session_t *s)
{
	if (len < 1) {
		return DRCOM_ERR_BAD_PACKET;
	}
	if (in[0] == 0x04) {
		/* Success: need at least 39 bytes to extract tail1. */
		if (len < 39) {
			return DRCOM_ERR_BAD_PACKET;
		}
		__builtin_memcpy(s->tail1, in + 23, 16);
		return DRCOM_OK;
	}
	if (in[0] == 0x05) {
		/* Failure: server sends at least 5 bytes (05 00 00 05 <code>). */
		if (len < 5) {
			return DRCOM_ERR_BAD_PACKET;
		}
		return DRCOM_ERR_AUTH; /* username/password or MAC rejected */
	}
	return DRCOM_ERR_SERVER;
}

/* ------------------------------------------------------------------ */
/* Keepalive                                                          */
/* ------------------------------------------------------------------ */

size_t drcom_keep38_pack(uint8_t out[DRCOM_KEEP38_SIZE], drcom_session_t *s)
{
	__builtin_memset(out, 0, DRCOM_KEEP38_SIZE);
	out[0] = 0xff;
	__builtin_memcpy(out + 1, s->md5a, 16);
	/* [17..19] zero. */
	__builtin_memcpy(out + 20, s->tail1, 16);
	drcom_random(out + 36, 2);
	return DRCOM_KEEP38_SIZE;
}

drcom_err_t drcom_keep38_parse(const uint8_t *in, size_t len, drcom_session_t *s)
{
	if (len < 30) {
		return DRCOM_ERR_BAD_PACKET;
	}
	/* Echoed random bytes at [6:8] (we ignore - server just echoes). */
	/* IP at [12:16] (we ignore, already known). */
	s->keep_alive_ver[0] = in[28];
	s->keep_alive_ver[1] = in[29];
	return DRCOM_OK;
}

size_t drcom_keep40_extra_pack(uint8_t out[DRCOM_KEEP40_SIZE], drcom_session_t *s)
{
	__builtin_memset(out, 0, DRCOM_KEEP40_SIZE);
	out[0] = 0x07;
	out[1] = (uint8_t)s->count++;
	out[2] = 0x28;
	out[3] = 0x00;
	out[4] = 0x0b;
	out[5] = 0x01; /* type */
	out[6] = 0x0f;
	out[7] = 0x27;
	drcom_random(out + 8, 2);
	/* [10..15] zero. */
	__builtin_memcpy(out + 16, s->tail2, 4);
	/* [20..39] zero. */
	return DRCOM_KEEP40_SIZE;
}

size_t drcom_keep40_1_pack(uint8_t out[DRCOM_KEEP40_SIZE], drcom_session_t *s)
{
	__builtin_memset(out, 0, DRCOM_KEEP40_SIZE);
	out[0] = 0x07;
	out[1] = (uint8_t)s->count++;
	out[2] = 0x28;
	out[3] = 0x00;
	out[4] = 0x0b;
	out[5] = 0x01; /* type */
	out[6] = s->keep_alive_ver[0];
	out[7] = s->keep_alive_ver[1];
	drcom_random(out + 8, 2);
	/* [10..15] zero. */
	__builtin_memcpy(out + 16, s->tail2, 4);
	/* [20..39] zero. */
	return DRCOM_KEEP40_SIZE;
}

drcom_err_t drcom_keep40_1_parse(const uint8_t *in, size_t len, drcom_session_t *s)
{
	if (len < 20) {
		return DRCOM_ERR_BAD_PACKET;
	}
	if (in[0] != 0x07) {
		return DRCOM_ERR_SERVER;
	}
	__builtin_memcpy(s->tail2, in + 16, 4);
	return DRCOM_OK;
}

size_t drcom_keep40_2_pack(uint8_t out[DRCOM_KEEP40_SIZE], drcom_session_t *s)
{
	__builtin_memset(out, 0, DRCOM_KEEP40_SIZE);
	out[0] = 0x07;
	out[1] = (uint8_t)s->count++;
	out[2] = 0x28;
	out[3] = 0x00;
	out[4] = 0x0b;
	out[5] = 0x03; /* type for keep40_2 */
	out[6] = s->keep_alive_ver[0];
	out[7] = s->keep_alive_ver[1];
	drcom_random(out + 8, 2);
	/* [10..15] zero. */
	__builtin_memcpy(out + 16, s->tail2, 4);
	/* [20..23] zero. */
	/* Compute crc over out[0:28], write to out[24:28]. */
	__builtin_memcpy(out + 24, s->client_ip, 4); /* placeholder so crc sees IP */
	{
		uint8_t crc[DRCOM_CRC_SIZE];
		drcom_crc(crc, out, 28);
		__builtin_memcpy(out + 24, crc, 4);
	}
	__builtin_memcpy(out + 28, s->client_ip, 4);
	/* [32..39] zero. */
	return DRCOM_KEEP40_SIZE;
}

int drcom_keep38_needs_extra(const drcom_session_t *s)
{
	/* The Drcom keepalive schedule: after every 10 keep38 packets, send a
	 * keep40_extra.  With three count-incrementing packets per "extra"
	 * cycle and two per plain cycle, this is exactly count % 21 == 0. */
	return (s->count % 21u) == 0u;
}

void drcom_keep38_advance(drcom_session_t *s)
{
	s->keep38_index++;
}

/* ------------------------------------------------------------------ */
/* Logout                                                             */
/* ------------------------------------------------------------------ */

size_t drcom_logout_pack(uint8_t out[DRCOM_LOGOUT_REQ_SIZE], drcom_session_t *s)
{
	static const uint8_t k_logout_code[2] = {0x06, 0x01};
	__builtin_memset(out, 0, DRCOM_LOGOUT_REQ_SIZE);
	out[0] = 0x06;
	out[1] = 0x01;
	out[2] = 0x00;
	size_t uname_len = bounded_strlen(s->username, 36);
	out[3] = (uint8_t)(uname_len + 20u);

	/* md5 = md5(0x06 0x01, salt, password). */
	{
		const uint8_t *parts[3] = {k_logout_code, s->salt, (const uint8_t *)s->password};
		const size_t lens[3] = {
			sizeof(k_logout_code), sizeof(s->salt), bounded_strlen(s->password, 16)};
		uint8_t md5[16];
		drcom_md5_multi(md5, parts, lens, 3);
		__builtin_memcpy(out + 4, md5, 16);
	}
	copy_ljust(out + 20, 36, s->username, uname_len);
	out[56] = 0x20;
	out[57] = 0x05;
	for (int i = 0; i < 6; i++) {
		out[58 + i] = (uint8_t)(out[4 + i] ^ s->mac[i]);
	}
	__builtin_memcpy(out + 64, s->tail1, 16);
	return DRCOM_LOGOUT_REQ_SIZE;
}

drcom_err_t drcom_logout_parse(const uint8_t *in, size_t len)
{
	if (len < 1) {
		return DRCOM_ERR_BAD_PACKET;
	}
	if (in[0] != 0x04) {
		return DRCOM_ERR_SERVER;
	}
	return DRCOM_OK;
}
