/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file network.c
 * @brief UDP socket helpers.
 */
#define _GNU_SOURCE 1
#include "network.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int drcom_net_open(drcom_net_t *n,
				   const struct sockaddr_in *server,
				   unsigned recv_timeout_ms)
{
	n->fd = -1;
	n->recv_timeout_ms = recv_timeout_ms;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	/* Bind to ephemeral port; explicit bind avoids surprises when there are
	 * multiple interfaces. */
	struct sockaddr_in local = {0};
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}

	/* Connect so we can use send(2) instead of sendto(2).  For UDP this
	 * also lets the kernel reject packets from non-server peers. */
	if (connect(fd, (const struct sockaddr *)server, sizeof(*server)) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}

	struct timeval tv = {
		.tv_sec = (time_t)(recv_timeout_ms / 1000u),
		.tv_usec = (suseconds_t)((recv_timeout_ms % 1000u) * 1000u),
	};
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	n->fd = fd;
	n->server = *server;
	return 0;
}

int drcom_net_send(drcom_net_t *n, const uint8_t *buf, size_t len)
{
	if (n->fd < 0)
		return -EBADF;
	size_t off = 0;
	while (off < len) {
		ssize_t r = send(n->fd, buf + off, len - off, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		off += (size_t)r;
	}
	return 0;
}

ssize_t drcom_net_recv(drcom_net_t *n, uint8_t *buf, size_t cap)
{
	if (n->fd < 0)
		return -EBADF;
	while (true) {
		ssize_t r = recv(n->fd, buf, cap, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		return r;
	}
}

void drcom_net_close(drcom_net_t *n)
{
	if (n->fd >= 0) {
		close(n->fd);
		n->fd = -1;
	}
}
