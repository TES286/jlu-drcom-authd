/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file network.h
 * @brief Thin UDP wrapper used by the authd state machine.
 *
 * The functions here are intentionally synchronous: the Drcom protocol is
 * strictly request/response with bounded timeouts, so a blocking socket
 * with SO_RCVTIMEO is simpler and faster than wiring up sd_event IO
 * sources for every recv.
 */
#ifndef DRCOM_NETWORK_H
#define DRCOM_NETWORK_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int fd;
	struct sockaddr_in server;
	unsigned recv_timeout_ms;
} drcom_net_t;

/**
 * Create a UDP socket, bind to ephemeral port, connect to @p server:port.
 * @return 0 on success, negative errno on failure.
 */
int drcom_net_open(drcom_net_t *n,
				   const struct sockaddr_in *server,
				   unsigned recv_timeout_ms);

/** Send @p len bytes.  Returns 0 on success, negative errno on failure. */
int drcom_net_send(drcom_net_t *n, const uint8_t *buf, size_t len);

/** Receive up to @p cap bytes into @p buf.  Returns the number of bytes
 *  received (>=0) or a negative errno on failure/timeout. */
ssize_t drcom_net_recv(drcom_net_t *n, uint8_t *buf, size_t cap);

void drcom_net_close(drcom_net_t *n);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_NETWORK_H */
