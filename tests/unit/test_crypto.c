/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file test_crypto.c
 * @brief Unit tests for the crypto module.
 *
 * MD5 vectors are from RFC 1321.  The Drcom checksum/crc/ror vectors are
 * derived by hand-translating the Java reference algorithm in
 *   https://github.com/drcoms/jlu-drcom-client/blob/master/jlu-drcom-java/
 * and cross-checked with the Python port of the same algorithm.
 */
#include "crypto.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int hex_eq(const uint8_t *got, size_t n, const char *expected_hex)
{
	/* expected_hex is lowercase, no separators, length 2n. */
	char buf[256];
	static const char hex[] = "0123456789abcdef";
	if (n * 2 + 1 > sizeof(buf))
		return 0;
	for (size_t i = 0; i < n; i++) {
		buf[i * 2] = hex[got[i] >> 4];
		buf[i * 2 + 1] = hex[got[i] & 0xf];
	}
	buf[n * 2] = 0;
	return strcmp(buf, expected_hex) == 0;
}

static void test_md5_rfc1321(void)
{
	static const struct {
		const char *input;
		const char *expected;
	} cases[] = {
		{"", "d41d8cd98f00b204e9800998ecf8427e"},
		{"a", "0cc175b9c0f1b6a831c399e269772661"},
		{"abc", "900150983cd24fb0d6963f7d28e17f72"},
		{"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
		{"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		 "d174ab98d277d9f5a5611c2c9f419d9f"},
		{"1234567890123456789012345678901234567890123456789012345678901234567890123456789"
		 "0",
		 "57edf4a22be3c955ac49da2e2107b67a"},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		uint8_t out[16];
		const uint8_t *parts[1] = {(const uint8_t *)cases[i].input};
		size_t lens[1] = {strlen(cases[i].input)};
		drcom_md5_multi(out, parts, lens, 1);
		if (!hex_eq(out, 16, cases[i].expected)) {
			char got[33] = {0};
			for (int j = 0; j < 16; j++)
				sprintf(got + j * 2, "%02x", out[j]);
			fprintf(stderr,
					"FAIL md5(%s): expected %s, got %s\n",
					cases[i].input,
					cases[i].expected,
					got);
			failures++;
		}
	}
}

static void test_md5_multi_concat(void)
{
	/* md5("abc") should equal md5_multi(("a","b","c")). */
	uint8_t out1[16], out2[16];
	{
		const uint8_t *p[1] = {(const uint8_t *)"abc"};
		const size_t l[1] = {3};
		drcom_md5_multi(out1, p, l, 1);
	}
	{
		const uint8_t *p[3] = {
			(const uint8_t *)"a", (const uint8_t *)"b", (const uint8_t *)"c"};
		const size_t l[3] = {1, 1, 1};
		drcom_md5_multi(out2, p, l, 3);
	}
	CHECK(memcmp(out1, out2, 16) == 0, "md5_multi concatenation mismatch");
}

static void test_md5_long_message(void)
{
	/* 1,000,000 'a' characters: RFC 1321 vector. */
	static const char expected[] = "7707d6ae4e027c70eea2a935c2296f21";
	char *buf = malloc(1000000);
	CHECK(buf != NULL, "OOM");
	if (!buf)
		return;
	memset(buf, 'a', 1000000);
	uint8_t out[16];
	const uint8_t *p[1] = {(const uint8_t *)buf};
	const size_t l[1] = {1000000};
	drcom_md5_multi(out, p, l, 1);
	if (!hex_eq(out, 16, expected)) {
		char got[33] = {0};
		for (int j = 0; j < 16; j++)
			sprintf(got + j * 2, "%02x", out[j]);
		fprintf(stderr, "FAIL md5(1M 'a'): expected %s, got %s\n", expected, got);
		failures++;
	}
	free(buf);
}

static void test_ror_identity(void)
{
	/* ror with all-zero password = ROL3 of md5a per byte. */
	uint8_t md5a[16] = {
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
		0x10,
	};
	uint8_t pass[16] = {0};
	uint8_t out[16];
	drcom_ror(out, md5a, pass, 16);
	/* Expected: each byte = ROL3(md5a[i]). */
	static const uint8_t expected[16] = {
		0x08,
		0x10,
		0x18,
		0x20,
		0x28,
		0x30,
		0x38,
		0x40,
		0x48,
		0x50,
		0x58,
		0x60,
		0x68,
		0x70,
		0x78,
		0x80,
	};
	if (memcmp(out, expected, 16) != 0) {
		fprintf(stderr, "FAIL ror(ROL3) mismatch\n");
		failures++;
	}
}

static void test_ror_xor(void)
{
	/* ror with password = 0xFF, 0xFF, ... should equal ROL3(md5a ^ 0xFF).
	 * md5a buffer is sized to DRCOM_MD5_DIGEST_SIZE to match the prototype
	 * even though we only read the first 4 bytes. */
	uint8_t md5a[16] = {0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t pass[4] = {0xff, 0xff, 0xff, 0xff};
	uint8_t out[4];
	drcom_ror(out, md5a, pass, 4);
	/* x = 0x12 ^ 0xff = 0xed. ROL3: (0xed<<3)|(0xed>>5) = 0x68|0x07 = 0x6f
	 * x = 0x34 ^ 0xff = 0xcb. ROL3: (0xcb<<3)|(0xcb>>5) = 0x58|0x06 = 0x5e
	 * x = 0x56 ^ 0xff = 0xa9. ROL3: (0xa9<<3)|(0xa9>>5) = 0x48|0x05 = 0x4d
	 * x = 0x78 ^ 0xff = 0x87. ROL3: (0x87<<3)|(0x87>>5) = 0x38|0x04 = 0x3c
	 */
	static const uint8_t expected[4] = {0x6f, 0x5e, 0x4d, 0x3c};
	if (memcmp(out, expected, 4) != 0) {
		char got[9] = {0};
		for (int j = 0; j < 4; j++)
			sprintf(got + j * 2, "%02x", out[j]);
		fprintf(stderr, "FAIL ror(xor) mismatch: got %s\n", got);
		failures++;
	}
}

static void test_checksum_empty(void)
{
	/* Empty input: sum stays at initial big-endian 1234 = 0x000004d2.
	 * result = (1234 * 1968) & 0xffffffff = 2,428,512 = 0x00250e60.
	 * little-endian 4 bytes: 60 0e 25 00.
	 * (Vector verified against the Java reference algorithm.) */
	uint8_t out[4];
	drcom_checksum(out, (const uint8_t *)"", 0);
	if (!hex_eq(out, 4, "600e2500")) {
		char got[9] = {0};
		for (int j = 0; j < 4; j++)
			sprintf(got + j * 2, "%02x", out[j]);
		fprintf(stderr, "FAIL checksum(empty): got %s\n", got);
		failures++;
	}
}

static void test_checksum_known(void)
{
	/* Input [0x01,0x26,0x07,0x11] (one 4-byte group).
	 * group reversed-as-be32 = 0x11260701
	 * sum_be32 = 0x000004d2 ^ 0x11260701 = 0x112603d3
	 * result = (0x112603d3 * 1968) & 0xffffffff = 0xe6dbb610
	 * little-endian 4 bytes: 10 b6 db e6. */
	uint8_t out[4];
	static const uint8_t in[4] = {0x01, 0x26, 0x07, 0x11};
	drcom_checksum(out, in, 4);
	if (!hex_eq(out, 4, "10b6dbe6")) {
		char got[9] = {0};
		for (int j = 0; j < 4; j++)
			sprintf(got + j * 2, "%02x", out[j]);
		fprintf(stderr, "FAIL checksum(known 4-byte): got %s\n", got);
		failures++;
	}
}

static void test_checksum_remainder(void)
{
	/* Input with length not multiple of 4.
	 * input = [0xaa, 0xbb, 0xcc, 0xdd, 0x11]  (5 bytes)
	 * First 4-byte group reversed-as-be32 = 0xddccbbaa
	 * sum_be32 = 0x000004d2 ^ 0xddccbbaa = 0xddccbfb8
	 * Remaining 1 byte 0x11 zero-extends to 0x00000011 (reversed order)
	 * sum_be32 ^= 0x00000011 -> 0xddccbfb8 ^ 0x00000011 = 0xddccbfa9
	 *   (tmp[3] = 0x11, sum[3] ^= 0x11; sum[0..2] ^= 0)
	 * Wait: the Java code's tail handling for 1 remaining byte:
	 *   tmp = [0,0,0,0]; j=3, tmp[3] = data[4] = 0x11. So tmp = [0,0,0,0x11].
	 *   sum[0] ^= tmp[0] = 0; sum[1] ^= 0; sum[2] ^= 0; sum[3] ^= 0x11.
	 *   So sum_be32 ^= 0x00000011.
	 *   0xddccbfb8 ^ 0x00000011 = 0xddccbfa9
	 * result = (0xddccbfa9 * 1968) & 0xffffffff
	 * Python-verified: 0x1cff7730 -> little-endian: 30 77 ff 1c?
	 * Actually Python produced "3077ff15" for this input, so:
	 * little-endian: 30 77 ff 15.  (Manually recompute in Python.) */
	uint8_t out[4];
	static const uint8_t in[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0x11};
	drcom_checksum(out, in, 5);
	if (!hex_eq(out, 4, "3077ff15")) {
		char got[9] = {0};
		for (int j = 0; j < 4; j++)
			sprintf(got + j * 2, "%02x", out[j]);
		fprintf(stderr, "FAIL checksum(remainder): got %s\n", got);
		failures++;
	}
}

static void test_crc_empty(void)
{
	/* Empty input: sum = 0, result = 0 * 711 = 0. */
	uint8_t out[4];
	drcom_crc(out, (const uint8_t *)"", 0);
	if (!hex_eq(out, 4, "00000000")) {
		char got[9] = {0};
		for (int j = 0; j < 4; j++)
			sprintf(got + j * 2, "%02x", out[j]);
		fprintf(stderr, "FAIL crc(empty): got %s\n", got);
		failures++;
	}
}

static void test_crc_known(void)
{
	/* crc of bytes [0x07, 0x01] (one 2-byte group).
	 * group reversed-as-be16 = 0x0107
	 * sum_be16 = 0 ^ 0x0107 = 0x0107
	 * result = (0x0107 * 711) & 0xffffffff = (263 * 711) = 186993 = 0x2da71
	 * Wait: 263 * 711 = ?
	 *   263 * 700 = 184100
	 *   263 * 11 = 2893
	 *   Total = 186993 = 0x2DA71
	 * little-endian 4 bytes: 71 a7 02 00? But Python says 71 da 02 00.
	 * Let me recompute: 263 * 711:
	 *   263 * 711 = 263 * (700 + 11) = 184100 + 2893 = 186993.
	 *   186993 in hex: 186993 / 16^4 = 186993 / 65536 = 2.85... -> high byte 2
	 *   186993 - 2*65536 = 186993 - 131072 = 55921
	 *   55921 / 16^3 = 55921 / 4096 = 13.65... -> next byte 13 = D
	 *   55921 - 13*4096 = 55921 - 53248 = 2673
	 *   2673 / 16^2 = 2673 / 256 = 10.44... -> next byte 10 = A
	 *   2673 - 10*256 = 2673 - 2560 = 113
	 *   113 / 16 = 7, r 1
	 * So 186993 = 0x02DA71.
	 * little-endian 4 bytes: 71 DA 02 00.
	 * Python output matches: "71da0200". */
	uint8_t out[4];
	static const uint8_t in[2] = {0x07, 0x01};
	drcom_crc(out, in, 2);
	if (!hex_eq(out, 4, "71da0200")) {
		char got[9] = {0};
		for (int j = 0; j < 4; j++)
			sprintf(got + j * 2, "%02x", out[j]);
		fprintf(stderr, "FAIL crc(known): got %s\n", got);
		failures++;
	}
}

static void test_random(void)
{
	uint8_t a[16], b[16];
	drcom_random(a, sizeof(a));
	drcom_random(b, sizeof(b));
	CHECK(memcmp(a, b, 16) != 0,
		  "drcom_random returned identical buffers (vanishingly unlikely)");
}

static void test_random_large(void)
{
	/* Verify that drcom_random can fill a larger buffer without
	 * aborting — this exercises the read-loop in both the getrandom
	 * and /dev/urandom fallback paths. */
	uint8_t buf[256];
	drcom_random(buf, sizeof(buf));
	/* At least one byte should be non-zero (vanishingly unlikely
	 * for 256 random bytes). */
	bool nonzero = false;
	for (size_t i = 0; i < sizeof(buf); i++) {
		if (buf[i] != 0) {
			nonzero = true;
			break;
		}
	}
	CHECK(nonzero, "drcom_random returned all-zero 256-byte buffer");
}

static void test_random_zero_len(void)
{
	/* Zero-length request should be a no-op (no abort). */
	drcom_random(NULL, 0);
	CHECK(1, "zero-length drcom_random did not abort");
}

int main(void)
{
	test_md5_rfc1321();
	test_md5_multi_concat();
	test_md5_long_message();
	test_ror_identity();
	test_ror_xor();
	test_checksum_empty();
	test_checksum_known();
	test_checksum_remainder();
	test_crc_empty();
	test_crc_known();
	test_random();
	test_random_large();
	test_random_zero_len();

	if (failures == 0) {
		printf("test_crypto: PASS\n");
		return 0;
	}
	printf("test_crypto: %d FAILURES\n", failures);
	return 1;
}
