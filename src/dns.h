/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file dns.h
 * @brief Minimal DNS A-record resolver for pre-authentication fallback.
 *
 * Before the Drcom daemon authenticates, the host's primary DNS resolver
 * (configured via /etc/resolv.conf) is often unable to recurse: the
 * campus gateway blocks external DNS until the host is authenticated.
 * The system getaddrinfo(3) path therefore fails, and the daemon cannot
 * resolve "auth.jlu.edu.cn" to reach the auth server.
 *
 * This module implements a minimal RFC 1035 DNS client that sends a
 * single A-record query directly to a user-specified DNS server (e.g.
 * the campus DNS at 10.10.10.10, which is reachable pre-auth).  It
 * performs no caching, no recursion, and no TCP fallback — just enough
 * to get an IPv4 address for the auth server.
 *
 * Wire format reference: RFC 1035 §4.1.
 */
#ifndef DRCOM_DNS_H
#define DRCOM_DNS_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DRCOM_DNS_PORT 53
#define DRCOM_DNS_MAX_NAME 255
#define DRCOM_DNS_MAX_UDP 512 /* RFC 1035 §2.3.4 */
#define DRCOM_DNS_TIMEOUT_MS 3000

/**
 * Resolve @p hostname to an IPv4 address by querying @p dns_server.
 *
 * Sends a single DNS A-record query over UDP to @p dns_server:53 and
 * parses the response.  Returns the first A record found.
 *
 * @param hostname     NUL-terminated domain name (e.g. "auth.jlu.edu.cn").
 * @param dns_server   IPv4 address of the DNS server to query.
 * @param timeout_ms   Per-recv timeout in milliseconds.
 * @param out          Output: resolved IPv4 address (network byte order).
 * @return 0 on success, negative errno on failure.
 */
int drcom_dns_resolve_a(const char *hostname,
                        const struct in_addr *dns_server,
                        unsigned timeout_ms,
                        struct in_addr *out);

/**
 * Encode a dotted domain name into DNS wire format (length-prefixed
 * labels, NUL-terminated).  Writes into @p out (capacity @p cap).
 * Returns the number of bytes written, or 0 on error (cap too small
 * or name too long).
 *
 * Exposed for unit testing.
 */
size_t drcom_dns_encode_name(const char *hostname, uint8_t *out, size_t cap);

/**
 * Parse a DNS response and extract the first A record from the
 * answer section.  @p query is the original query message (used to
 * match the question section and follow compression pointers safely).
 *
 * Exposed for unit testing.
 *
 * @param query     The query packet we sent (for QNAME matching).
 * @param query_len Length of @p query.
 * @param resp      The response packet received.
 * @param resp_len  Length of @p resp.
 * @param out       Output: resolved IPv4 address.
 * @return 0 on success, negative errno on failure.
 */
int drcom_dns_parse_response(const uint8_t *query, size_t query_len,
                             const uint8_t *resp, size_t resp_len,
                             struct in_addr *out);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_DNS_H */
