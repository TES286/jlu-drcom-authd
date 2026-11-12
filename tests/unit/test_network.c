/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define _GNU_SOURCE 1
#include "network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(expr)                                                                      \
	do {                                                                                 \
		if (!(expr)) {                                                                   \
			perror(#expr);                                                               \
			return 1;                                                                    \
		}                                                                                \
	} while (0)

int main(void)
{
	int server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	CHECK(server >= 0);
	struct sockaddr_in addr = {.sin_family = AF_INET,
							   .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	CHECK(bind(server, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	socklen_t len = sizeof(addr);
	CHECK(getsockname(server, (struct sockaddr *)&addr, &len) == 0);
	struct timeval timeout = {.tv_sec = 1};
	CHECK(setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);

	drcom_net_t net = {.fd = -1};
	CHECK(drcom_net_open(&net, &addr, 50, "lo") == 0);
	uint32_t iface = 0;
	len = sizeof(iface);
	CHECK(getsockopt(net.fd, IPPROTO_IP, IP_UNICAST_IF, &iface, &len) == 0);
	CHECK(ntohl(iface) == if_nametoindex("lo"));
	const uint8_t payload[] = {0x01, 0x02, 0xaa, 0xff};
	CHECK(drcom_net_send(&net, payload, sizeof(payload)) == 0);
	uint8_t packet[16];
	struct sockaddr_in peer;
	len = sizeof(peer);
	CHECK(recvfrom(server, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &len) ==
		  (ssize_t)sizeof(payload));
	CHECK(memcmp(packet, payload, sizeof(payload)) == 0);
	CHECK(sendto(server, payload, sizeof(payload), 0, (struct sockaddr *)&peer, len) ==
		  (ssize_t)sizeof(payload));
	CHECK(drcom_net_recv(&net, packet, sizeof(packet)) == (ssize_t)sizeof(payload));
	CHECK(memcmp(packet, payload, sizeof(payload)) == 0);
	CHECK(drcom_net_recv(&net, packet, sizeof(packet)) == -EAGAIN);
	drcom_net_close(&net);
	CHECK(net.fd == -1);
	CHECK(drcom_net_open(&net, &addr, 50, "missing-drcom") < 0);
	CHECK(net.fd == -1);
	CHECK(drcom_net_open(&net, &addr, 50, NULL) == 0);
	iface = 1;
	len = sizeof(iface);
	CHECK(getsockopt(net.fd, IPPROTO_IP, IP_UNICAST_IF, &iface, &len) == 0);
	CHECK(iface == 0);
	drcom_net_close(&net);
	close(server);
	puts("test_network: PASS");
	return 0;
}
