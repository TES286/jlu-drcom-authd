/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file test_protocol.c
 * @brief Unit tests for the protocol module.
 *
 * Verifies packet structure invariants: header bytes, length formulas,
 * field offsets.  Cryptographic fields (md5a, checksum) are validated
 * structurally rather than against captured vectors because they depend
 * on per-call random bytes and credential material; the e2e test in
 * tests/e2e/ exercises the full round-trip against a mock server.
 */
#include "crypto.h"
#include "protocol.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n"); \
            failures++; \
        } \
    } while (0)

static void test_session_init(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    CHECK(s.challenge_times == 2, "challenge_times should start at 2, got %u",
          (unsigned)s.challenge_times);
    CHECK(s.count == 0, "count should start at 0");
    CHECK(s.keep_alive_ver[0] == 0xdc && s.keep_alive_ver[1] == 0x02,
          "keep_alive_ver default wrong: %02x%02x",
          s.keep_alive_ver[0], s.keep_alive_ver[1]);
    CHECK(s.keep38_index == 0, "keep38_index should start at 0");
}

static void test_challenge_pack(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    uint8_t out[20];
    size_t n = drcom_challenge_pack(out, &s);
    CHECK(n == 20, "challenge packet should be 20 bytes, got %zu", n);
    CHECK(out[0] == 0x01, "challenge[0] should be 0x01, got %02x", out[0]);
    CHECK(out[1] == 0x02, "challenge[1] should be 0x02 on first call, got %02x", out[1]);
    CHECK(out[4] == 0x6a, "challenge[4] should be 0x6a, got %02x", out[4]);
    for (int i = 5; i < 20; i++) {
        CHECK(out[i] == 0, "challenge[%d] should be 0, got %02x", i, out[i]);
    }
    /* challenge_times should have been incremented. */
    CHECK(s.challenge_times == 3, "challenge_times should be 3 after one pack, got %u",
          (unsigned)s.challenge_times);
    /* Random bytes [2:4] should not be all-zero (vanishingly unlikely). */
    CHECK(!(out[2] == 0 && out[3] == 0), "challenge rand bytes are both zero (unlikely)");
}

static void test_challenge_parse(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    /* Construct a synthetic 76-byte response. */
    uint8_t in[76] = {0};
    in[0] = 0x02;  /* code */
    in[1] = 0x02;  /* type */
    in[2] = 0xab; in[3] = 0xcd;  /* echoed random */
    in[4] = 0x11; in[5] = 0x22; in[6] = 0x33; in[7] = 0x44;  /* salt */
    in[20] = 0x0a; in[21] = 0x14; in[22] = 0x40; in[23] = 0x01;  /* IP 10.20.64.1 */
    int r = drcom_challenge_parse(in, sizeof(in), &s);
    CHECK(r == DRCOM_OK, "challenge parse should succeed");
    CHECK(s.salt[0] == 0x11 && s.salt[3] == 0x44, "salt not extracted");
    CHECK(s.client_ip[0] == 0x0a && s.client_ip[3] == 0x01, "client_ip not extracted");

    /* Short packet. */
    r = drcom_challenge_parse(in, 50, &s);
    CHECK(r == DRCOM_ERR_BAD_PACKET, "short challenge should fail");

    /* Wrong code. */
    in[0] = 0x03;
    r = drcom_challenge_parse(in, sizeof(in), &s);
    CHECK(r == DRCOM_ERR_SERVER, "wrong code should return ERR_SERVER");
}

static void test_login_pack_structure(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    __builtin_strncpy(s.username, "testuser", sizeof(s.username) - 1);
    __builtin_strncpy(s.password, "pass1234", sizeof(s.password) - 1);
    static const uint8_t mac[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x42};
    __builtin_memcpy(s.mac, mac, 6);
    static const uint8_t salt[4] = {0x11, 0x22, 0x33, 0x44};
    __builtin_memcpy(s.salt, salt, 4);
    static const uint8_t ip[4] = {10, 20, 30, 40};
    __builtin_memcpy(s.client_ip, ip, 4);
    __builtin_strncpy(s.hostname, "testhost", sizeof(s.hostname) - 1);

    uint8_t out[DRCOM_LOGIN_REQ_MAX];
    size_t n = drcom_login_pack(out, sizeof(out), &s);
    CHECK(n > 0, "login_pack returned 0");

    /* For 8-char password: data_len = 334 + (7/4)*4 = 338. */
    CHECK(n == 338, "login packet for 8-char password should be 338 bytes, got %zu", n);

    /* Header. */
    CHECK(out[0] == 0x03, "login[0] should be 0x03");
    CHECK(out[1] == 0x01, "login[1] should be 0x01");
    CHECK(out[2] == 0x00, "login[2] should be 0x00");
    CHECK(out[3] == 8 + 20, "login[3] should be unameLen+20 = 28, got %u", out[3]);

    /* Username. */
    CHECK(memcmp(out + 20, "testuser", 8) == 0, "username not at offset 20");
    CHECK(out[28] == 0, "username not zero-terminated");

    /* controlCheck, adapterNum. */
    CHECK(out[56] == 0x20, "login[56] should be 0x20");
    CHECK(out[57] == 0x05, "login[57] should be 0x05");

    /* md5a ^ mac at [58:64]. */
    for (int i = 0; i < 6; i++) {
        CHECK(out[58 + i] == (uint8_t)(s.md5a[i] ^ mac[i]),
              "md5a^mac mismatch at offset %d", 58 + i);
    }

    /* numOfIP. */
    CHECK(out[80] == 0x01, "login[80] should be 0x01");
    CHECK(memcmp(out + 81, ip, 4) == 0, "client_ip not at offset 81");

    /* ipDog. */
    CHECK(out[105] == 0x01, "login[105] should be 0x01");

    /* primary DNS = 10.10.10.10. */
    CHECK(out[142] == 10 && out[143] == 10 && out[144] == 10 && out[145] == 10,
          "primary DNS wrong");

    /* Static magic bytes. */
    CHECK(out[162] == 0x94, "login[162] should be 0x94");
    CHECK(out[166] == 0x06, "login[166] should be 0x06");
    CHECK(out[170] == 0x02, "login[170] should be 0x02");
    CHECK(out[174] == 0xf0 && out[175] == 0x23, "login[174:176] should be f0 23");
    CHECK(out[178] == 0x02, "login[178] should be 0x02");

    /* DRCOM CHECK magic. */
    static const uint8_t drcom_check[8] = {0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0xcf, 0x07};
    CHECK(memcmp(out + 182, drcom_check, 8) == 0, "DRCOM CHECK magic wrong");

    CHECK(out[190] == 0x6a, "login[190] should be 0x6a");
    CHECK(out[310] == 0x6a, "login[310] should be 0x6a");

    /* 40-byte str at [246:286]. */
    static const char str[] = "1c210c99585fd22ad03d35c956911aeec1eb449b";
    CHECK(memcmp(out + 246, str, 40) == 0, "str magic wrong");

    /* passLen at [313]. */
    CHECK(out[313] == 8, "login[313] should be passLen=8");

    /* 0x02, 0x0c at [314+passLen, 315+passLen] = [322, 323]. */
    CHECK(out[322] == 0x02, "login[322] should be 0x02");
    CHECK(out[323] == 0x0c, "login[323] should be 0x0c");

    /* mac at [322+passLen:328+passLen] = [330:336]. */
    CHECK(memcmp(out + 330, mac, 6) == 0, "mac not at offset 330");

    /* Last two bytes are random (not all-zero). */
    CHECK(!(out[n - 2] == 0 && out[n - 1] == 0), "trailing random bytes both zero");
}

static void test_login_parse_ok(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    uint8_t in[64] = {0};
    in[0] = 0x04;  /* login success */
    for (int i = 0; i < 16; i++) in[23 + i] = (uint8_t)(0x80 + i);
    int r = drcom_login_parse(in, sizeof(in), &s);
    CHECK(r == DRCOM_OK, "login parse should succeed");
    for (int i = 0; i < 16; i++) {
        CHECK(s.tail1[i] == (uint8_t)(0x80 + i), "tail1[%d] wrong", i);
    }
}

static void test_login_parse_auth_fail(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    uint8_t in[8] = {0x05, 0x00, 0x00, 0x05, 0x03, 0x00, 0x00, 0x00};
    int r = drcom_login_parse(in, sizeof(in), &s);
    CHECK(r == DRCOM_ERR_AUTH, "auth fail should return DRCOM_ERR_AUTH");

    in[4] = 0x0b;  /* MAC error */
    r = drcom_login_parse(in, sizeof(in), &s);
    CHECK(r == DRCOM_ERR_AUTH, "MAC error should also return DRCOM_ERR_AUTH");
}

static void test_keep38_pack(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    static const uint8_t md5a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static const uint8_t tail1[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xe1, 0xe2, 0xe3, 0xe4,
                                       0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec};
    __builtin_memcpy(s.md5a, md5a, 16);
    __builtin_memcpy(s.tail1, tail1, 16);

    uint8_t out[38];
    size_t n = drcom_keep38_pack(out, &s);
    CHECK(n == 38, "keep38 should be 38 bytes, got %zu", n);
    CHECK(out[0] == 0xff, "keep38[0] should be 0xff");
    CHECK(memcmp(out + 1, md5a, 16) == 0, "md5a not at offset 1");
    CHECK(out[17] == 0 && out[18] == 0 && out[19] == 0, "keep38[17:20] should be zero");
    CHECK(memcmp(out + 20, tail1, 16) == 0, "tail1 not at offset 20");
    /* Random [36:38] not both zero. */
    CHECK(!(out[36] == 0 && out[37] == 0), "keep38 trailing random both zero");
}

static void test_keep38_parse(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    uint8_t in[40] = {0};
    in[28] = 0xdc;
    in[29] = 0x02;
    int r = drcom_keep38_parse(in, sizeof(in), &s);
    CHECK(r == DRCOM_OK, "keep38 parse should succeed");
    CHECK(s.keep_alive_ver[0] == 0xdc && s.keep_alive_ver[1] == 0x02,
          "keep_alive_ver not extracted");

    r = drcom_keep38_parse(in, 10, &s);
    CHECK(r == DRCOM_ERR_BAD_PACKET, "short keep38 should fail");
}

static void test_keep40_packs(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    s.count = 7;
    static const uint8_t kav[2] = {0xdc, 0x02};
    __builtin_memcpy(s.keep_alive_ver, kav, 2);
    static const uint8_t tail2[4] = {0x12, 0x34, 0x56, 0x78};
    __builtin_memcpy(s.tail2, tail2, 4);
    static const uint8_t ip[4] = {10, 0, 0, 1};
    __builtin_memcpy(s.client_ip, ip, 4);

    /* extra */
    uint8_t e[40];
    size_t n = drcom_keep40_extra_pack(e, &s);
    CHECK(n == 40, "keep40_extra should be 40 bytes");
    CHECK(e[0] == 0x07, "extra[0]");
    CHECK(e[1] == 7, "extra[1] should be 7 (count was 7), got %u", e[1]);
    CHECK(e[2] == 0x28 && e[3] == 0x00 && e[4] == 0x0b, "extra[2:5]");
    CHECK(e[5] == 0x01, "extra[5] should be 0x01");
    CHECK(e[6] == 0x0f && e[7] == 0x27, "extra[6:8] should be 0f 27");
    CHECK(memcmp(e + 16, tail2, 4) == 0, "tail2 not at extra offset 16");
    CHECK(s.count == 8, "count should be 8 after extra, got %u", s.count);

    /* keep40_1 */
    uint8_t a[40];
    n = drcom_keep40_1_pack(a, &s);
    CHECK(n == 40, "keep40_1 should be 40 bytes");
    CHECK(a[1] == 8, "keep40_1[1] should be 8, got %u", a[1]);
    CHECK(a[5] == 0x01, "keep40_1[5] should be 0x01");
    CHECK(a[6] == 0xdc && a[7] == 0x02, "keep40_1[6:8] should be keep_alive_ver");
    CHECK(memcmp(a + 16, tail2, 4) == 0, "tail2 not at keep40_1 offset 16");
    CHECK(s.count == 9, "count should be 9 after keep40_1, got %u", s.count);

    /* keep40_2 */
    uint8_t b[40];
    n = drcom_keep40_2_pack(b, &s);
    CHECK(n == 40, "keep40_2 should be 40 bytes");
    CHECK(b[1] == 9, "keep40_2[1] should be 9, got %u", b[1]);
    CHECK(b[5] == 0x03, "keep40_2[5] should be 0x03");
    CHECK(b[6] == 0xdc && b[7] == 0x02, "keep40_2[6:8] should be keep_alive_ver");
    /* IP at [28:32]. */
    CHECK(memcmp(b + 28, ip, 4) == 0, "client_ip not at keep40_2 offset 28");
    /* CRC at [24:28] is computed; just verify it's not all-zero (in general). */
    CHECK(!(b[24] == 0 && b[25] == 0 && b[26] == 0 && b[27] == 0),
          "keep40_2 crc is all zero (would only happen for trivial input)");
    CHECK(s.count == 10, "count should be 10 after keep40_2, got %u", s.count);
}

static void test_keep40_1_parse(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    uint8_t in[40] = {0};
    in[0] = 0x07;
    in[16] = 0xaa; in[17] = 0xbb; in[18] = 0xcc; in[19] = 0xdd;
    int r = drcom_keep40_1_parse(in, sizeof(in), &s);
    CHECK(r == DRCOM_OK, "keep40_1 parse should succeed");
    CHECK(s.tail2[0] == 0xaa && s.tail2[3] == 0xdd, "tail2 not extracted");
}

static void test_keep38_needs_extra(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    /* count starts at 0, so first cycle needs extra. */
    CHECK(drcom_keep38_needs_extra(&s), "first cycle should need extra");
    s.count = 21;
    CHECK(drcom_keep38_needs_extra(&s), "count=21 should need extra");
    s.count = 3;
    CHECK(!drcom_keep38_needs_extra(&s), "count=3 should not need extra");
}

static void test_logout_pack(void)
{
    drcom_session_t s;
    drcom_session_init(&s);
    __builtin_strncpy(s.username, "user", sizeof(s.username) - 1);
    __builtin_strncpy(s.password, "pass1234", sizeof(s.password) - 1);
    static const uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    __builtin_memcpy(s.mac, mac, 6);
    static const uint8_t salt[4] = {0x10, 0x20, 0x30, 0x40};
    __builtin_memcpy(s.salt, salt, 4);
    static const uint8_t tail1[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xe1, 0xe2, 0xe3, 0xe4,
                                       0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec};
    __builtin_memcpy(s.tail1, tail1, 16);

    uint8_t out[80];
    size_t n = drcom_logout_pack(out, &s);
    CHECK(n == 80, "logout should be 80 bytes, got %zu", n);
    CHECK(out[0] == 0x06, "logout[0] should be 0x06");
    CHECK(out[1] == 0x01, "logout[1] should be 0x01");
    CHECK(out[2] == 0x00, "logout[2] should be 0x00");
    CHECK(out[3] == 4 + 20, "logout[3] should be unameLen+20=24, got %u", out[3]);
    CHECK(memcmp(out + 20, "user", 4) == 0, "username not at offset 20");
    CHECK(out[56] == 0x20, "logout[56] should be 0x20");
    CHECK(out[57] == 0x05, "logout[57] should be 0x05");
    /* md5[0..5] ^ mac at [58:64]. */
    for (int i = 0; i < 6; i++) {
        CHECK(out[58 + i] == (uint8_t)(out[4 + i] ^ mac[i]),
              "md5^mac mismatch at logout offset %d", 58 + i);
    }
    CHECK(memcmp(out + 64, tail1, 16) == 0, "tail1 not at logout offset 64");
}

static void test_logout_parse(void)
{
    uint8_t ok[16] = {0x04, 0x00, 0x00, 0x05, 0x00};
    CHECK(drcom_logout_parse(ok, sizeof(ok)) == DRCOM_OK, "logout ack should be OK");

    uint8_t fail[16] = {0x05, 0x00, 0x00, 0x05, 0x00};
    CHECK(drcom_logout_parse(fail, sizeof(fail)) == DRCOM_ERR_SERVER,
          "logout non-ack should return ERR_SERVER");
}

int main(void)
{
    test_session_init();
    test_challenge_pack();
    test_challenge_parse();
    test_login_pack_structure();
    test_login_parse_ok();
    test_login_parse_auth_fail();
    test_keep38_pack();
    test_keep38_parse();
    test_keep40_packs();
    test_keep40_1_parse();
    test_keep38_needs_extra();
    test_logout_pack();
    test_logout_parse();

    if (failures == 0) {
        printf("test_protocol: PASS\n");
        return 0;
    }
    printf("test_protocol: %d FAILURES\n", failures);
    return 1;
}
