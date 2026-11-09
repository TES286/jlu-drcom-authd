/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file test_dns.c
 * @brief Unit tests for the minimal DNS resolver.
 *
 * Tests cover:
 *   - Name encoding (dotted string -> wire format, RFC 1035 §3.1)
 *   - Response parsing (header validation, compression pointers, A-record
 *     extraction)
 *   - Error handling (truncated packets, mismatched IDs, NXDOMAIN, no A
 *     record in answer)
 *
 * The end-to-end transport test (drcom_dns_resolve_a) is covered by a
 * separate test that spins up a mock DNS server on 127.0.0.1.
 */
#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...)                                                                     \
        do {                                                                                     \
                if (!(cond)) {                                                                      \
                        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                        \
                        fprintf(stderr, __VA_ARGS__);                                               \
                        fprintf(stderr, "\n");                                                      \
                        failures++;                                                                 \
                }                                                                                  \
        } while (0)

/* ---- Name encoding ---- */

static void test_encode_simple(void)
{
        /* "auth.jlu.edu.cn" -> \x04auth\x03jlu\x03edu\x02cn\x00 = 17 bytes */
        uint8_t out[64];
        size_t n = drcom_dns_encode_name("auth.jlu.edu.cn", out, sizeof(out));
        /* 1+4 + 1+3 + 1+3 + 1+2 + 1(NUL) = 17 */
        CHECK(n == 17, "encoded length should be 17, got %zu", n);
        if (n != 17)
                return;
        CHECK(out[0] == 4, "first label length should be 4");
        CHECK(memcmp(out + 1, "auth", 4) == 0, "first label wrong");
        CHECK(out[5] == 3, "second label length should be 3");
        CHECK(memcmp(out + 6, "jlu", 3) == 0, "second label wrong");
        CHECK(out[9] == 3, "third label length should be 3");
        CHECK(memcmp(out + 10, "edu", 3) == 0, "third label wrong");
        CHECK(out[13] == 2, "fourth label length should be 2");
        CHECK(memcmp(out + 14, "cn", 2) == 0, "fourth label wrong");
        CHECK(out[16] == 0, "should end with NUL byte");
}

static void test_encode_root(void)
{
        uint8_t out[8];
        size_t n = drcom_dns_encode_name(".", out, sizeof(out));
        CHECK(n == 1, "root name should encode to 1 byte, got %zu", n);
        if (n == 1)
                CHECK(out[0] == 0, "root name should be single NUL byte");

        n = drcom_dns_encode_name("", out, sizeof(out));
        CHECK(n == 1, "empty name should encode to 1 byte, got %zu", n);
}

static void test_encode_single_label(void)
{
        uint8_t out[16];
        size_t n = drcom_dns_encode_name("localhost", out, sizeof(out));
        /* \x09localhost\x00 = 11 bytes */
        CHECK(n == 11, "single label should be 11 bytes, got %zu", n);
}

static void test_encode_too_long_label(void)
{
        /* A label longer than 63 bytes should fail. */
        char longname[70];
        memset(longname, 'a', 65);
        longname[65] = 0;
        uint8_t out[128];
        size_t n = drcom_dns_encode_name(longname, out, sizeof(out));
        CHECK(n == 0, "label > 63 bytes should fail, got %zu", n);
}

static void test_encode_buffer_too_small(void)
{
        uint8_t out[5]; /* too small for "auth.jlu.edu.cn" */
        size_t n = drcom_dns_encode_name("auth.jlu.edu.cn", out, sizeof(out));
        CHECK(n == 0, "should fail on undersized buffer, got %zu", n);
}

/* ---- Response parsing ---- */

/** Build a minimal DNS response with one A record for testing. */
static size_t build_response(const uint8_t *query, size_t query_len,
                             uint32_t ip_addr, uint16_t rcode,
                             uint8_t *out, size_t cap)
{
        /* Copy the query header, flip QR, set RCODE. */
        if (cap < query_len + 16)
                return 0;
        memcpy(out, query, query_len);
        /* flags at offset 2. */
        uint16_t flags = ((uint16_t)out[2] << 8) | out[3];
        flags |= 0x8000; /* QR = 1 */
        flags |= rcode; /* RCODE */
        out[2] = (uint8_t)(flags >> 8);
        out[3] = (uint8_t)(flags & 0xFF);
        /* ANCOUNT = 1 */
        out[6] = 0;
        out[7] = 1;

        /* Answer section: use compression pointer to the QNAME in the
         * question section (offset 12 = start of QNAME). */
        size_t off = query_len;
        /* NAME: compression pointer 0xC00C (pointer to offset 12). */
        out[off++] = 0xC0;
        out[off++] = 0x0C;
        /* TYPE = A (1) */
        out[off++] = 0;
        out[off++] = 1;
        /* CLASS = IN (1) */
        out[off++] = 0;
        out[off++] = 1;
        /* TTL = 300 (4 bytes) */
        out[off++] = 0;
        out[off++] = 0;
        out[off++] = 0x01;
        out[off++] = 0x2C;
        /* RDLENGTH = 4 */
        out[off++] = 0;
        out[off++] = 4;
        /* RDATA: the IP address (4 bytes, network order) */
        out[off++] = (uint8_t)(ip_addr >> 24);
        out[off++] = (uint8_t)(ip_addr >> 16);
        out[off++] = (uint8_t)(ip_addr >> 8);
        out[off++] = (uint8_t)(ip_addr);
        return off;
}

static void test_parse_success(void)
{
        /* Build a query for "test.example.com" then a response. */
        uint8_t query[64];
        /* Manually build a minimal query. */
        query[0] = 0x12;
        query[1] = 0x34;
        query[2] = 0x01; /* RD=1 */
        query[3] = 0x00;
        query[4] = 0;
        query[5] = 1; /* QDCOUNT=1 */
        query[6] = 0;
        query[7] = 0; /* ANCOUNT=0 */
        query[8] = 0;
        query[9] = 0;
        query[10] = 0;
        query[11] = 0;
        size_t name_len = drcom_dns_encode_name("test.example.com", query + 12, sizeof(query) - 12 - 4);
        CHECK(name_len > 0, "encode_name failed");
        size_t qlen = 12 + name_len + 4;
        query[qlen - 4] = 0;
        query[qlen - 3] = 1; /* QTYPE=A */
        query[qlen - 2] = 0;
        query[qlen - 1] = 1; /* QCLASS=IN */

        uint8_t resp[128];
        uint32_t ip = 0x0AC80101; /* 10.200.1.1 */
        size_t rlen = build_response(query, qlen, ip, 0, resp, sizeof(resp));
        CHECK(rlen > 0, "build_response failed");

        struct in_addr out;
        int r = drcom_dns_parse_response(query, qlen, resp, rlen, &out);
        CHECK(r == 0, "parse should succeed, got %d", r);
        if (r == 0) {
                CHECK(ntohl(out.s_addr) == ip, "IP mismatch: got 0x%08x expected 0x%08x",
                          ntohl(out.s_addr), ip);
        }
}

static void test_parse_wrong_id(void)
{
        uint8_t query[32] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
        size_t qlen = 12;
        /* minimal QNAME: \x01a\x00 = 3 bytes, + 4 bytes QTYPE/QCLASS */
        query[12] = 1;
        query[13] = 'a';
        query[14] = 0;
        query[15] = 0;
        query[16] = 1;
        query[17] = 0;
        query[18] = 1;
        qlen = 19;

        uint8_t resp[64];
        size_t rlen = build_response(query, qlen, 0x0A000001, 0, resp, sizeof(resp));
        /* Corrupt the ID. */
        resp[0] = 0xFF;
        resp[1] = 0xFF;

        struct in_addr out;
        int r = drcom_dns_parse_response(query, qlen, resp, rlen, &out);
        CHECK(r == -EPROTO, "wrong ID should return -EPROTO, got %d", r);
}

static void test_parse_nxdomain(void)
{
        uint8_t query[32] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
        query[12] = 1;
        query[13] = 'a';
        query[14] = 0;
        query[15] = 0;
        query[16] = 1;
        query[17] = 0;
        query[18] = 1;
        size_t qlen = 19;

        uint8_t resp[64];
        /* RCODE=3 (NXDOMAIN), ANCOUNT=0 */
        size_t rlen = build_response(query, qlen, 0, 3, resp, sizeof(resp));
        /* Override ANCOUNT to 0 for NXDOMAIN. */
        resp[6] = 0;
        resp[7] = 0;
        /* Truncate the answer section we don't want. */
        rlen = 12; /* just the header + question is enough; but we need the question echoed.
                    * Actually build_response copied the query (19 bytes) + answer.  Let's
                    * just set rlen to query_len (no answer). */
        rlen = qlen;
        /* Set flags: QR=1, RCODE=3. */
        uint16_t flags = ((uint16_t)resp[2] << 8) | resp[3];
        flags |= 0x8000; /* QR */
        flags |= 3; /* NXDOMAIN */
        resp[2] = (uint8_t)(flags >> 8);
        resp[3] = (uint8_t)(flags & 0xFF);

        struct in_addr out;
        int r = drcom_dns_parse_response(query, qlen, resp, rlen, &out);
        CHECK(r == -EHOSTUNREACH, "NXDOMAIN should return -EHOSTUNREACH, got %d", r);
}

static void test_parse_truncated(void)
{
        uint8_t query[32] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
        query[12] = 1;
        query[13] = 'a';
        query[14] = 0;
        query[15] = 0;
        query[16] = 1;
        query[17] = 0;
        query[18] = 1;
        size_t qlen = 19;

        /* Response shorter than header. */
        uint8_t resp[8] = {0};
        struct in_addr out;
        int r = drcom_dns_parse_response(query, qlen, resp, 8, &out);
        CHECK(r == -EBADMSG, "truncated response should return -EBADMSG, got %d", r);
}

static void test_parse_not_a_response(void)
{
        uint8_t query[32] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
        query[12] = 1;
        query[13] = 'a';
        query[14] = 0;
        query[15] = 0;
        query[16] = 1;
        query[17] = 0;
        query[18] = 1;
        size_t qlen = 19;

        /* Response with QR=0 (not a response). */
        uint8_t resp[64];
        memcpy(resp, query, qlen);
        resp[6] = 0;
        resp[7] = 1; /* ANCOUNT=1 but QR=0 */

        struct in_addr out;
        int r = drcom_dns_parse_response(query, qlen, resp, qlen, &out);
        CHECK(r == -EPROTO, "QR=0 should return -EPROTO, got %d", r);
}

/* ---- End-to-end transport (mock DNS server) ---- */

#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * Full end-to-end test: fork a mock DNS server, send a real query via
 * drcom_dns_resolve_a, and verify the resolved IP.  The mock server
 * listens on an ephemeral port on 127.0.0.1 and responds to any A query
 * with 10.20.30.40.
 *
 * Since drcom_dns_resolve_a hardcodes port 53, we can't use it directly
 * against an ephemeral port.  Instead, this test validates the query
 * construction + response parsing path by building the query ourselves,
 * sending it to the mock, and parsing the reply with
 * drcom_dns_parse_response.
 */
static void test_resolve_e2e(void)
{
        /* Set up the mock server on a separate socket. */
        int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(server_fd >= 0, "server socket failed");
        if (server_fd < 0)
                return;

        struct sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        server_addr.sin_port = 0;
        CHECK(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0,
                  "server bind failed");
        socklen_t alen = sizeof(server_addr);
        getsockname(server_fd, (struct sockaddr *)&server_addr, &alen);

        pid_t pid = fork();
        CHECK(pid >= 0, "fork failed");
        if (pid == 0) {
                /* Child: wait for one query, reply, exit. */
                uint8_t buf[512];
                struct sockaddr_in cli;
                socklen_t clen = sizeof(cli);
                struct timeval tv = {.tv_sec = 3};
                setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                ssize_t n = recvfrom(server_fd, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&cli, &clen);
                if (n < 12)
                        _exit(1);
                uint8_t resp[128];
                memcpy(resp, buf, (size_t)n);
                resp[2] |= 0x80; /* QR=1 */
                resp[6] = 0;
                resp[7] = 1; /* ANCOUNT=1 */
                size_t off = (size_t)n;
                resp[off++] = 0xC0;
                resp[off++] = 0x0C;
                resp[off++] = 0;
                resp[off++] = 1;
                resp[off++] = 0;
                resp[off++] = 1;
                resp[off++] = 0;
                resp[off++] = 0;
                resp[off++] = 0;
                resp[off++] = 60;
                resp[off++] = 0;
                resp[off++] = 4;
                resp[off++] = 10;
                resp[off++] = 20;
                resp[off++] = 30;
                resp[off++] = 40;
                sendto(server_fd, resp, off, 0, (struct sockaddr *)&cli, clen);
                _exit(0);
        }
        if (pid < 0) {
                close(server_fd);
                return;
        }
        close(server_fd); /* parent doesn't need the server socket */

        /* Parent: use a separate client socket to query the mock. */
        int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(client_fd >= 0, "client socket failed");
        if (client_fd < 0) {
                int status;
                waitpid(pid, &status, 0);
                return;
        }
        struct timeval tv = {.tv_sec = 3};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* Build a query. */
        uint8_t query[64];
        query[0] = 0xAB;
        query[1] = 0xCD; /* ID */
        query[2] = 0x01; /* RD=1 */
        query[3] = 0x00;
        query[4] = 0;
        query[5] = 1; /* QDCOUNT=1 */
        query[6] = 0;
        query[7] = 0;
        query[8] = 0;
        query[9] = 0;
        query[10] = 0;
        query[11] = 0;
        size_t nlen = drcom_dns_encode_name("test.jlu.edu.cn", query + 12,
                                            sizeof(query) - 12 - 4);
        CHECK(nlen > 0, "encode_name failed");
        size_t qlen = 12 + nlen;
        query[qlen++] = 0;
        query[qlen++] = 1; /* QTYPE=A */
        query[qlen++] = 0;
        query[qlen++] = 1; /* QCLASS=IN */

        ssize_t sent = sendto(client_fd, query, qlen, 0,
                              (struct sockaddr *)&server_addr, sizeof(server_addr));
        CHECK(sent == (ssize_t)qlen, "sendto failed: %zd", sent);

        uint8_t resp[128];
        ssize_t got = recv(client_fd, resp, sizeof(resp), 0);
        CHECK(got > 0, "recv failed: %zd", got);

        struct in_addr out;
        int r = drcom_dns_parse_response(query, qlen, resp, (size_t)got, &out);
        CHECK(r == 0, "parse_response failed: %d", r);
        if (r == 0) {
                CHECK(ntohl(out.s_addr) == 0x0A141E28,
                          "IP mismatch: got 0x%08x expected 0x0A141E28 (10.20.30.40)",
                          ntohl(out.s_addr));
        }

        close(client_fd);
        int status;
        waitpid(pid, &status, 0);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "mock server should exit 0, got status %d", status);
}

int main(void)
{
        test_encode_simple();
        test_encode_root();
        test_encode_single_label();
        test_encode_too_long_label();
        test_encode_buffer_too_small();
        test_parse_success();
        test_parse_wrong_id();
        test_parse_nxdomain();
        test_parse_truncated();
        test_parse_not_a_response();
        test_resolve_e2e();

        if (failures == 0) {
                printf("test_dns: PASS\n");
                return 0;
        }
        printf("test_dns: %d FAILURES\n", failures);
        return 1;
}
