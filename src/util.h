/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file util.h
 * @brief Small platform helpers: MAC/hostname lookup, address resolution,
 *        hex dump.
 */
#ifndef DRCOM_UTIL_H
#define DRCOM_UTIL_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Fill @p mac with the MAC address of @p ifname (e.g. "eth0").
 *  Returns 0 on success, negative errno-style on failure. */
int drcom_get_mac(const char *ifname, uint8_t mac[6]);

/** Find the first non-loopback UP IPv4 interface and copy its name to @p ifname
 *  (capacity @p cap) and MAC to @p mac.  Useful when the user did not specify
 *  an interface.  Returns 0 on success, negative errno-style on failure. */
int drcom_detect_interface(char *ifname, size_t cap, uint8_t mac[6]);

/** Copy the system hostname (uname(2)) to @p out (capacity @p cap). */
int drcom_get_hostname(char *out, size_t cap);

/** Resolve a host:port into an IPv4 sockaddr_in.  Returns 0 on success. */
int drcom_resolve_ipv4(const char *host, uint16_t port, struct sockaddr_in *out);

/** Hex-dump @p len bytes of @p data to @p out (capacity @p cap).
 *  Returns the number of bytes written (excl. NUL). */
size_t drcom_hexdump(char *out, size_t cap, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_UTIL_H */
