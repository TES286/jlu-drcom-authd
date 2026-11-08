/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file netlink.c
 * @brief rtnetlink link state monitoring.
 *
 * The socket is opened as SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC on
 * NETLINK_ROUTE and bound to RTMGRP_LINK.  We then add it as an IO
 * source to the sd_event loop.  On EPOLLIN, we drain the socket in a
 * loop (NLMSG_DONE-aware) and dispatch each RTM_NEWLINK / RTM_DELLINK
 * message to the callback.
 *
 * The message parsing follows the rtnetlink(7) layout:
 *   [nlmsghdr][ifinfomsg][rtattr...][rtattr...]
 * We extract IFLA_IFNAME to get the interface name and check
 * ifi_flags & (IFF_UP | IFF_LOWER_UP) for the link-up state.
 */
#define _GNU_SOURCE 1
#include "appconf.h" /* for DRCOM_LOG_LEVEL_* used by log.h macros */
#include "log.h"
#include "netlink.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h> /* SIOCGIFFLAGS */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h> /* ioctl() */
#include <sys/socket.h>
#include <unistd.h>

#include <systemd/sd-event.h>

struct drcom_netlink {
	int fd;
	sd_event_source *io_source;
	drcom_link_cb_t cb;
	void *userdata;
};

static int parse_ifinfomsg(const struct nlmsghdr *nh,
						   int *out_ifindex,
						   char *out_ifname,
						   size_t ifname_cap,
						   unsigned *out_flags)
{
	if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
		return -EBADMSG;

	const struct ifinfomsg *ifi = (const struct ifinfomsg *)NLMSG_DATA(nh);
	*out_ifindex = ifi->ifi_index;
	*out_flags = ifi->ifi_flags;

	/* Default ifname to empty; IFLA_IFNAME may override. */
	if (ifname_cap > 0)
		out_ifname[0] = 0;

	/* Walk rtattr list. */
	const struct rtattr *rta = (const struct rtattr *)RTM_RTA(ifi);
	size_t remaining = RTM_PAYLOAD(nh);
	for (; RTA_OK(rta, remaining); rta = RTA_NEXT(rta, remaining)) {
		if (rta->rta_type == IFLA_IFNAME) {
			size_t len = RTA_PAYLOAD(rta);
			if (len >= ifname_cap)
				len = ifname_cap - 1;
			memcpy(out_ifname, RTA_DATA(rta), len);
			out_ifname[len] = 0;
		}
	}
	return 0;
}

static int on_netlink_io(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	(void)s;
	(void)revents;
	drcom_netlink_t *nl = userdata;

	/* Drain the socket.  NETLINK sockets deliver each notification as
	 * a separate datagram, so a single recvfrom() returns one message
	 * (or a buffer-full if the kernel batches). */
	for (;;) {
		uint8_t buf[8192];
		ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break; /* drained */
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (len == 0)
			break;

		/* Iterate over nlmsghdr entries in the buffer. */
		for (const struct nlmsghdr *nh = (const struct nlmsghdr *)buf;
			 NLMSG_OK(nh, (size_t)len);
			 nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nh->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nh);
				if (err->error != 0)
					drcom_log_debug("netlink error: %s", strerror(-err->error));
				continue;
			}

			if (nh->nlmsg_type != RTM_NEWLINK && nh->nlmsg_type != RTM_DELLINK)
				continue;

			int ifindex;
			char ifname[IFNAMSIZ] = "";
			unsigned flags = 0;
			if (parse_ifinfomsg(nh, &ifindex, ifname, sizeof(ifname), &flags) < 0)
				continue;

			/* link_up = administratively up AND carrier present.
			 * In the netlink ifinfomsg, ifi_flags is 32-bit and
			 * IFF_LOWER_UP (1<<16) indicates L1 carrier.  For
			 * RTM_DELLINK the interface is gone, so always treat
			 * it as down. */
			bool link_up;
			if (nh->nlmsg_type == RTM_DELLINK)
				link_up = false;
			else
				link_up = (flags & (IFF_UP | IFF_LOWER_UP)) == (IFF_UP | IFF_LOWER_UP);

			if (nl->cb)
				nl->cb(ifindex, ifname, link_up, nl->userdata);
		}
	}
	return 0;
}

int drcom_netlink_new(drcom_netlink_t **out,
					  sd_event *event,
					  drcom_link_cb_t cb,
					  void *userdata)
{
	if (!out || !event)
		return -EINVAL;

	drcom_netlink_t *nl = calloc(1, sizeof(*nl));
	if (!nl)
		return -ENOMEM;
	nl->fd = -1;
	nl->cb = cb;
	nl->userdata = userdata;

	nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (nl->fd < 0) {
		int e = errno;
		free(nl);
		return -e;
	}

	struct sockaddr_nl sa = {0};
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK;
	if (bind(nl->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;
		close(nl->fd);
		free(nl);
		return -e;
	}

	int r = sd_event_add_io(event, &nl->io_source, nl->fd, EPOLLIN, on_netlink_io, nl);
	if (r < 0) {
		close(nl->fd);
		free(nl);
		return r;
	}

	*out = nl;
	return 0;
}

void drcom_netlink_free(drcom_netlink_t *nl)
{
	if (!nl)
		return;
	if (nl->io_source)
		sd_event_source_unref(nl->io_source);
	if (nl->fd >= 0)
		close(nl->fd);
	free(nl);
}

int drcom_netlink_query_link(const char *ifname)
{
	if (!ifname || !*ifname)
		return -EINVAL;

	/* Use SIOCGIFFLAGS via ioctl — simpler than a rtnetlink round-trip
	 * and sufficient for a one-shot query at startup. */
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	struct ifreq ifr = {0};
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	int rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
	int saved_errno = errno;
	close(fd);
	if (rc < 0)
		return -saved_errno;

	/* ifr_flags is a 16-bit short, so IFF_LOWER_UP (1<<16) is truncated
	 * away.  IFF_RUNNING (1<<6) indicates the interface is operational
	 * (RFC 2863 OPER_UP), which implies carrier.  Use it for the ioctl
	 * path; the netlink path (32-bit ifi_flags) uses IFF_LOWER_UP. */
	unsigned flags = (unsigned)(unsigned short)ifr.ifr_flags;
	bool link_up = (flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
	return link_up ? 1 : 0;
}
