/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file util.c
 * @brief Small platform helpers.
 */
#define _GNU_SOURCE 1
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <unistd.h>

int drcom_get_mac(const char *ifname, uint8_t mac[6])
{
	if (!ifname || !*ifname)
		return -EINVAL;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	struct ifreq ifr = {0};
	ifr.ifr_addr.sa_family = AF_INET;
	__builtin_strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	int rc = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (rc < 0)
		return -errno;
	__builtin_memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

int drcom_detect_interface(char *ifname, size_t cap, uint8_t mac[6])
{
	if (cap < 2)
		return -ENAMETOOLONG;
	struct ifaddrs *ifa = NULL;
	if (getifaddrs(&ifa) < 0)
		return -errno;

	int rc = -ENOENT;
	for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
		if (!p->ifa_addr)
			continue;
		if (p->ifa_addr->sa_family != AF_PACKET)
			continue;
		if (!(p->ifa_flags & IFF_UP))
			continue;
		if (p->ifa_flags & IFF_LOOPBACK)
			continue;
		const struct sockaddr_ll *s = (const struct sockaddr_ll *)p->ifa_addr;
		if (s->sll_halen != 6)
			continue;
		/* Skip all-zero MACs (some virtual interfaces). */
		bool nonzero = false;
		for (int i = 0; i < 6; i++) {
			if (s->sll_addr[i] != 0) {
				nonzero = true;
				break;
			}
		}
		if (!nonzero)
			continue;
		size_t nl = strlen(p->ifa_name);
		if (nl >= cap)
			continue;
		__builtin_memcpy(ifname, p->ifa_name, nl);
		ifname[nl] = 0;
		__builtin_memcpy(mac, s->sll_addr, 6);
		rc = 0;
		break;
	}
	freeifaddrs(ifa);
	return rc;
}

int drcom_get_hostname(char *out, size_t cap)
{
	if (cap == 0)
		return -EINVAL;
	struct utsname uts;
	if (uname(&uts) < 0)
		return -errno;
	size_t n = strlen(uts.nodename);
	if (n >= cap)
		n = cap - 1;
	__builtin_memcpy(out, uts.nodename, n);
	out[n] = 0;
	return 0;
}

int drcom_resolve_ipv4(const char *host, uint16_t port, struct sockaddr_in *out)
{
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_ADDRCONFIG,
	};
	struct addrinfo *res = NULL;
	char portbuf[8];
	snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
	int rc = getaddrinfo(host, portbuf, &hints, &res);
	if (rc != 0) {
		return -EHOSTUNREACH;
	}
	__builtin_memcpy(out, res->ai_addr, res->ai_addrlen);
	out->sin_port = htons(port);
	freeaddrinfo(res);
	return 0;
}

size_t drcom_hexdump(char *out, size_t cap, const uint8_t *data, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	if (cap == 0)
		return 0;
	size_t needed = len * 3;
	if (needed == 0) {
		out[0] = 0;
		return 0;
	}
	size_t to_write = (needed - 1 < cap - 1) ? len : (cap - 1) / 3;
	for (size_t i = 0; i < to_write; i++) {
		out[i * 3 + 0] = hex[data[i] >> 4];
		out[i * 3 + 1] = hex[data[i] & 0xf];
		out[i * 3 + 2] = ' ';
	}
	if (to_write > 0) {
		out[to_write * 3 - 1] = 0; /* overwrite last space with NUL */
	} else {
		out[0] = 0;
	}
	return to_write * 3 - (to_write > 0 ? 1 : 0);
}
