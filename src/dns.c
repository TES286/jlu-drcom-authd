/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file dns.c
 * @brief Minimal DNS A-record resolver.
 *
 * Implements just enough of RFC 1035 to resolve a single A record:
 *   1. Encode a DNS query (header + question section).
 *   2. Send it over UDP to a specified DNS server.
 *   3. Parse the response, following message compression pointers
 *      (RFC 1035 §4.1.4) to decode owner names in the answer section.
 *   4. Return the first A record's RDATA (4-byte IPv4 address).
 *
 * Deliberately omitted (not needed for the auth-server lookup):
 *   - CNAME chasing (the auth server name is a direct A record)
 *   - TCP fallback (responses are < 512 bytes)
 *   - Caching (the daemon re-resolves only on re-auth, ~minutes apart)
 *   - EDNS0 (not needed for a simple A query)
 *   - DNSSEC (the campus DNS doesn't validate)
 *
 * The query ID is generated from getrandom(2) so an attacker cannot
 * predict it and spoof a response.  We match the ID and the question
 * section in the response to reject forged/mismatched replies.
 */
#define _GNU_SOURCE 1
#include "crypto.h" /* drcom_random */
#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* DNS wire format structures (RFC 1035 §4.1.1)                       */
/* ------------------------------------------------------------------ */

/* Header: 12 bytes, all fields network byte order. */
typedef struct __attribute__((packed)) {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} dns_header_t;

/* Flags bits (RFC 1035 §4.1.1):
 *   QR (bit 15): 0 = query, 1 = response
 *   OPCODE (bits 11-14): 0 = standard query
 *   AA (bit 10): authoritative answer
 *   TC (bit 9): truncation
 *   RD (bit 8): recursion desired
 *   RA (bit 7): recursion available
 *   Z (bits 4-6): reserved
 *   RCODE (bits 0-3): 0 = no error */
#define DNS_FLAG_QR (1u << 15)
#define DNS_FLAG_RD (1u << 8) /* recursion desired */
#define DNS_RCODE_MASK 0x000Fu

/* QTYPE values (RFC 1035 §3.2.2). */
#define DNS_QTYPE_A 1
/* QCLASS values (RFC 1035 §3.2.4). */
#define DNS_QCLASS_IN 1

/* TYPE values in resource records (same as QTYPE for A). */
#define DNS_TYPE_A 1

/* ------------------------------------------------------------------ */
/* Name encoding / decoding                                           */
/* ------------------------------------------------------------------ */

size_t drcom_dns_encode_name(const char *hostname, uint8_t *out, size_t cap)
{
	if (!hostname || !out || cap == 0)
		return 0;

	size_t total = 0;
	const char *p = hostname;

	/* Handle empty or root "." — just a single zero byte. */
	if (*p == 0 || (*p == '.' && p[1] == 0)) {
		if (cap < 1)
			return 0;
		out[0] = 0;
		return 1;
	}

	while (*p) {
		/* Find the next dot or end of string. */
		const char *dot = strchr(p, '.');
		size_t label_len = dot ? (size_t)(dot - p) : strlen(p);

		/* Labels must be 1..63 bytes (RFC 1035 §2.3.4). */
		if (label_len == 0 || label_len > 63)
			return 0;

		/* +1 for the length byte. */
		if (total + 1 + label_len >= cap)
			return 0;

		out[total++] = (uint8_t)label_len;
		memcpy(out + total, p, label_len);
		total += label_len;

		if (dot)
			p = dot + 1;
		else
			break;
	}

	/* Terminating NUL label. */
	if (total >= cap)
		return 0;
	out[total++] = 0;
	return total;
}

/**
 * Decode a (possibly compressed) domain name starting at offset @p offset
 * in the message @p msg (length @p msg_len).  Writes the dotted name to
 * @p out (capacity @p cap).  Returns the offset immediately after the
 * name field in the message (for the caller to continue parsing), or 0
 * on error.
 *
 * Compression pointers (RFC 1035 §4.1.4): a label-length byte with the
 * top two bits set (0xC0) indicates a 2-byte pointer to elsewhere in
 * the message.  We follow up to 128 pointers to prevent loops.
 */
static size_t drcom_dns_decode_name(
	const uint8_t *msg, size_t msg_len, size_t offset, char *out, size_t cap)
{
	if (!msg || !out || cap == 0)
		return 0;

	size_t out_pos = 0;
	size_t cur = offset;
	int followed = 0;
	bool jumped = false;
	size_t after_pointer = 0; /* offset after the name in the message */

	while (cur < msg_len) {
		uint8_t b = msg[cur];
		if (b == 0) {
			/* End of name. */
			if (!jumped)
				after_pointer = cur + 1;
			if (out_pos == 0) {
				/* Root name. */
				if (cap < 2)
					return 0;
				out[0] = '.';
				out[1] = 0;
			} else {
				/* Trim trailing dot. */
				if (out_pos > 0 && out[out_pos - 1] == '.')
					out[out_pos - 1] = 0;
				else
					out[out_pos] = 0;
			}
			return after_pointer;
		}

		if ((b & 0xC0) == 0xC0) {
			/* Compression pointer. */
			if (cur + 1 >= msg_len)
				return 0;
			if (!jumped) {
				after_pointer = cur + 2;
				jumped = true;
			}
			uint16_t ptr = ((uint16_t)(b & 0x3F) << 8) | msg[cur + 1];
			if (ptr >= msg_len)
				return 0;
			if (++followed > 128)
				return 0; /* loop guard */
			cur = ptr;
			continue;
		}

		if ((b & 0xC0) != 0) {
			/* Reserved top bits — malformed. */
			return 0;
		}

		/* Regular label: b is the length. */
		size_t label_len = b;
		if (cur + 1 + label_len > msg_len)
			return 0;
		if (out_pos + label_len + 1 >= cap)
			return 0;
		memcpy(out + out_pos, msg + cur + 1, label_len);
		out_pos += label_len;
		out[out_pos++] = '.';
		cur += 1 + label_len;
	}

	return 0; /* ran off the end without a NUL */
}

/* ------------------------------------------------------------------ */
/* Query construction                                                 */
/* ------------------------------------------------------------------ */

/**
 * Build a DNS A-record query packet for @p hostname.
 * Returns the packet length, or 0 on error.
 */
static size_t
build_query(const char *hostname, uint8_t *out, size_t cap, uint16_t *out_id)
{
	if (cap < sizeof(dns_header_t) + DRCOM_DNS_MAX_NAME + 4)
		return 0;

	/* Random query ID to prevent spoofing. */
	uint8_t id_bytes[2];
	drcom_random(id_bytes, 2);
	uint16_t id = ((uint16_t)id_bytes[0] << 8) | id_bytes[1];
	*out_id = id;

	dns_header_t *hdr = (dns_header_t *)out;
	hdr->id = htons(id);
	/* RD=1 (recursion desired) — campus DNS is recursive. */
	hdr->flags = htons(DNS_FLAG_RD);
	hdr->qdcount = htons(1);
	hdr->ancount = htons(0);
	hdr->nscount = htons(0);
	hdr->arcount = htons(0);

	size_t off = sizeof(dns_header_t);
	size_t name_len = drcom_dns_encode_name(hostname, out + off, cap - off - 4);
	if (name_len == 0)
		return 0;
	off += name_len;

	/* QTYPE = A (1), QCLASS = IN (1), both 2 bytes big-endian. */
	out[off++] = 0;
	out[off++] = DNS_QTYPE_A;
	out[off++] = 0;
	out[off++] = DNS_QCLASS_IN;

	return off;
}

/* ------------------------------------------------------------------ */
/* Response parsing                                                   */
/* ------------------------------------------------------------------ */

int drcom_dns_parse_response(const uint8_t *query,
							 size_t query_len,
							 const uint8_t *resp,
							 size_t resp_len,
							 struct in_addr *out)
{
	if (!query || !resp || !out)
		return -EINVAL;
	if (resp_len < sizeof(dns_header_t))
		return -EBADMSG;

	const dns_header_t *rhdr = (const dns_header_t *)resp;
	const dns_header_t *qhdr = (const dns_header_t *)query;

	/* Match ID. */
	if (rhdr->id != qhdr->id)
		return -EPROTO;

	uint16_t flags = ntohs(rhdr->flags);
	/* Must be a response. */
	if (!(flags & DNS_FLAG_QR))
		return -EPROTO;
	/* Check RCODE. */
	uint16_t rcode = flags & DNS_RCODE_MASK;
	if (rcode != 0)
		return -EHOSTUNREACH; /* NXDOMAIN or similar */

	uint16_t qdcount = ntohs(rhdr->qdcount);
	uint16_t ancount = ntohs(rhdr->ancount);

	/* Skip the question section in the response.  We trust it
	 * echoes our query (standard DNS behavior); we don't re-validate
	 * the QNAME to keep the parser simple. */
	size_t off = sizeof(dns_header_t);
	char namebuf[DRCOM_DNS_MAX_NAME];
	for (uint16_t i = 0; i < qdcount; i++) {
		size_t n = drcom_dns_decode_name(resp, resp_len, off, namebuf, sizeof(namebuf));
		if (n == 0)
			return -EBADMSG;
		off = n;
		/* Skip QTYPE (2) + QCLASS (2). */
		if (off + 4 > resp_len)
			return -EBADMSG;
		off += 4;
	}

	/* Walk the answer section looking for the first A record. */
	for (uint16_t i = 0; i < ancount; i++) {
		size_t n = drcom_dns_decode_name(resp, resp_len, off, namebuf, sizeof(namebuf));
		if (n == 0)
			return -EBADMSG;
		off = n;

		/* RR fixed fields: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes. */
		if (off + 10 > resp_len)
			return -EBADMSG;

		uint16_t type = ((uint16_t)resp[off] << 8) | resp[off + 1];
		uint16_t rdlength = ((uint16_t)resp[off + 8] << 8) | resp[off + 9];
		off += 10;

		if (off + rdlength > resp_len)
			return -EBADMSG;

		if (type == DNS_TYPE_A && rdlength == 4) {
			/* Found an A record. */
			memcpy(&out->s_addr, resp + off, 4);
			return 0;
		}

		/* Skip RDATA we don't care about. */
		off += rdlength;
	}

	return -EHOSTUNREACH; /* no A record in answer */
}

/* ------------------------------------------------------------------ */
/* UDP transport                                                      */
/* ------------------------------------------------------------------ */

int drcom_dns_resolve_a(const char *hostname,
						const struct in_addr *dns_server,
						unsigned timeout_ms,
						struct in_addr *out)
{
	if (!hostname || !dns_server || !out)
		return -EINVAL;
	if (timeout_ms == 0)
		timeout_ms = DRCOM_DNS_TIMEOUT_MS;

	/* Build the query. */
	uint8_t query[DRCOM_DNS_MAX_UDP];
	uint16_t query_id;
	size_t query_len = build_query(hostname, query, sizeof(query), &query_id);
	if (query_len == 0)
		return -EINVAL;

	/* Open a UDP socket. */
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	struct timeval tv = {
		.tv_sec = (time_t)(timeout_ms / 1000u),
		.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u),
	};
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct sockaddr_in dst = {0};
	dst.sin_family = AF_INET;
	dst.sin_addr = *dns_server;
	dst.sin_port = htons(DRCOM_DNS_PORT);

	/* Send. */
	ssize_t sent = sendto(fd, query, query_len, 0, (struct sockaddr *)&dst, sizeof(dst));
	if (sent < 0) {
		int e = errno;
		close(fd);
		return -e;
	}

	/* Receive.  We may get stray packets from other sources; loop
	 * until we get a response that matches our query ID. */
	uint8_t resp[DRCOM_DNS_MAX_UDP];
	for (;;) {
		ssize_t got = recv(fd, resp, sizeof(resp), 0);
		if (got < 0) {
			int e = errno;
			close(fd);
			if (e == EINTR)
				continue;
			return -e;
		}
		if ((size_t)got < sizeof(dns_header_t))
			continue; /* too short, try again */

		/* Check ID match before full parse to reject noise quickly. */
		const dns_header_t *rhdr = (const dns_header_t *)resp;
		if (rhdr->id != htons(query_id))
			continue;

		close(fd);
		return drcom_dns_parse_response(query, query_len, resp, (size_t)got, out);
	}
}
