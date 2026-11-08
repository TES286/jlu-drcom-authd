/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file authd.c
 * @brief Drcom authentication state machine.
 */
#define _GNU_SOURCE 1
#include "authd.h"
#include "log.h"
#include "netlink.h"
#include "util.h"

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

struct drcom_authd {
	drcom_appconf_t conf;
	sd_event *event;
	sd_event_source *keepalive_timer;
	sd_event_source *reauth_defer;
	drcom_netlink_t *netlink;
	drcom_session_t session;
	drcom_net_t net;
	drcom_state_t state;
	drcom_status_cb_t status_cb;
	void *status_userdata;
	char status_buf[128];
	int watched_ifindex;		   /* -1 = no link monitoring */
	bool link_up;				   /* current link state of the watched iface */
	unsigned keepalive_fail_count; /* consecutive failures, reset on success */
	bool started : 1;
	bool stopping : 1;
};

static const char *state_name(drcom_state_t s)
{
	switch (s) {
	case DRCOM_STATE_INIT:
		return "initializing";
	case DRCOM_STATE_ONLINE:
		return "online";
	case DRCOM_STATE_LOGGING_OUT:
		return "logging-out";
	case DRCOM_STATE_STOPPED:
		return "stopped";
	}
	return "unknown";
}

/**
 * Classification of keepalive failures, used by on_keepalive() to pick
 * the right recovery action.
 *
 *   TRANSIENT  — the local socket or kernel reported a transient error
 *                (EAGAIN/EWOULDBLOCK from SO_RCVTIMEO, or ENOMEM).
 *                The server may simply be slow or the network briefly
 *                congested.  Retry on the next keepalive tick without
 *                tearing down the session.
 *
 *   NETWORK    — the network path is broken (ENETUNREACH, EHOSTUNREACH,
 *                ECONNREFUSED, EPIPE, EBADF, ETIMEDOUT).  The UDP socket
 *                is dead or the server is unreachable.  Re-authenticate
 *                (close + challenge + login) on the next tick.
 *
 *   PROTOCOL   — the server replied with a malformed or unexpected
 *                packet (DRCOM_ERR_BAD_PACKET / DRCOM_ERR_SERVER / -EIO
 *                from a parser).  The session is logically invalid;
 *                perform a logout + re-challenge/login.
 *
 *   FATAL      — anything else.  Treat as a persistent failure; after a
 *                configurable number of consecutive FATAL/PROTOCOL
 *                failures, exit the event loop so systemd can restart
 *                the daemon fresh.
 */
typedef enum {
	KEEPALIVE_ERR_TRANSIENT,
	KEEPALIVE_ERR_NETWORK,
	KEEPALIVE_ERR_PROTOCOL,
	KEEPALIVE_ERR_FATAL,
} keepalive_err_class_t;

static keepalive_err_class_t classify_keepalive_err(int err)
{
	switch (err) {
	case -EAGAIN: /* EWOULDBLOCK is the same value on Linux */
	case -ENOMEM:
		return KEEPALIVE_ERR_TRANSIENT;

	case -ENETUNREACH:
	case -EHOSTUNREACH:
	case -ECONNREFUSED:
	case -ECONNRESET:
	case -EPIPE:
	case -EBADF:
	case -ETIMEDOUT:
		return KEEPALIVE_ERR_NETWORK;

	case -EIO:
		return KEEPALIVE_ERR_PROTOCOL;

	case -EACCES:
		/* Login rejected by server (bad credentials / MAC). */
		return KEEPALIVE_ERR_FATAL;

	default:
		return KEEPALIVE_ERR_FATAL;
	}
}

static void set_status(drcom_authd_t *a, drcom_state_t s)
{
	a->state = s;
	snprintf(a->status_buf,
			 sizeof(a->status_buf),
			 "%s (keep38=%u)",
			 state_name(s),
			 a->session.keep38_index);
	if (a->status_cb) {
		a->status_cb(a->status_userdata, s);
	}
	/* Mirror to systemd so `systemctl status` shows live progress. */
	char msg[160];
	int n = snprintf(msg, sizeof(msg), "STATUS=%s", a->status_buf);
	if (n > 0 && (size_t)n < sizeof(msg)) {
		(void)sd_notify(0, msg);
	}
}

static void feed_watchdog(void)
{
	/* Cheap manual ping; the sd_event-managed watchdog handles the steady
	 * state, this guards against slow server replies inside a phase. */
	(void)sd_notify(0, "WATCHDOG=1");
}

static int do_challenge_login(drcom_authd_t *a)
{
	uint8_t req[DRCOM_LOGIN_REQ_MAX]; /* big enough for challenge + login */
	uint8_t rep[256];
	size_t n;

	/* Challenge. */
	n = drcom_challenge_pack(req, &a->session);
	int r = drcom_net_send(&a->net, req, n);
	if (r < 0) {
		drcom_log_warn("challenge send failed: %s", strerror(-r));
		return r;
	}
	feed_watchdog();
	ssize_t got = drcom_net_recv(&a->net, rep, sizeof(rep));
	if (got < 0) {
		drcom_log_warn("challenge recv failed: %s", strerror(-(int)got));
		return (int)got;
	}
	r = drcom_challenge_parse(rep, (size_t)got, &a->session);
	if (r != DRCOM_OK) {
		drcom_log_warn("challenge parse failed: %s", drcom_strerror((drcom_err_t)r));
		return -EIO;
	}
	drcom_log_debug("challenge ok: salt=%02x%02x%02x%02x ip=%u.%u.%u.%u",
					a->session.salt[0],
					a->session.salt[1],
					a->session.salt[2],
					a->session.salt[3],
					a->session.client_ip[0],
					a->session.client_ip[1],
					a->session.client_ip[2],
					a->session.client_ip[3]);

	feed_watchdog();

	/* Login. */
	n = drcom_login_pack(req, sizeof(req), &a->session);
	if (n == 0) {
		drcom_log_err("login packet construction failed");
		return -EINVAL;
	}
	r = drcom_net_send(&a->net, req, n);
	if (r < 0) {
		drcom_log_warn("login send failed: %s", strerror(-r));
		return r;
	}
	feed_watchdog();
	got = drcom_net_recv(&a->net, rep, sizeof(rep));
	if (got < 0) {
		drcom_log_warn("login recv failed: %s", strerror(-(int)got));
		return (int)got;
	}
	r = drcom_login_parse(rep, (size_t)got, &a->session);
	if (r != DRCOM_OK) {
		drcom_log_err("login rejected: %s", drcom_strerror((drcom_err_t)r));
		return -EACCES;
	}
	drcom_log_info("login successful as %s", a->session.username);
	return 0;
}

static int do_keepalive_cycle(drcom_authd_t *a)
{
	uint8_t req[DRCOM_KEEP40_SIZE];
	uint8_t rep[1024];
	size_t n;
	ssize_t got;
	int r;

	/* keep38. */
	n = drcom_keep38_pack(req, &a->session);
	r = drcom_net_send(&a->net, req, n);
	if (r < 0) {
		drcom_log_warn("keep38 send failed: %s", strerror(-r));
		return r;
	}
	feed_watchdog();
	got = drcom_net_recv(&a->net, rep, sizeof(rep));
	if (got < 0) {
		drcom_log_warn("keep38 recv failed: %s", strerror(-(int)got));
		return (int)got;
	}
	r = drcom_keep38_parse(rep, (size_t)got, &a->session);
	if (r != DRCOM_OK) {
		drcom_log_warn("keep38 parse failed: %s", drcom_strerror((drcom_err_t)r));
		return -EIO;
	}

	/* keep40_extra (every 10 keep38). */
	if (drcom_keep38_needs_extra(&a->session)) {
		n = drcom_keep40_extra_pack(req, &a->session);
		r = drcom_net_send(&a->net, req, n);
		if (r < 0)
			return r;
		feed_watchdog();
		got = drcom_net_recv(&a->net, rep, sizeof(rep));
		if (got < 0)
			return (int)got;
		/* keep40_extra response is ignored; server just acks. */
	}

	/* keep40_1. */
	n = drcom_keep40_1_pack(req, &a->session);
	r = drcom_net_send(&a->net, req, n);
	if (r < 0)
		return r;
	feed_watchdog();
	got = drcom_net_recv(&a->net, rep, sizeof(rep));
	if (got < 0)
		return (int)got;
	r = drcom_keep40_1_parse(rep, (size_t)got, &a->session);
	if (r != DRCOM_OK) {
		drcom_log_warn("keep40_1 parse failed: %s", drcom_strerror((drcom_err_t)r));
		return -EIO;
	}

	/* keep40_2. */
	n = drcom_keep40_2_pack(req, &a->session);
	r = drcom_net_send(&a->net, req, n);
	if (r < 0)
		return r;
	feed_watchdog();
	got = drcom_net_recv(&a->net, rep, sizeof(rep));
	if (got < 0)
		return (int)got;
	/* keep40_2 response is ignored. */

	drcom_keep38_advance(&a->session);
	return 0;
}

static int do_logout(drcom_authd_t *a)
{
	/* Per protocol: re-challenge, then logout. */
	uint8_t req[DRCOM_LOGOUT_REQ_SIZE > DRCOM_CHALLENGE_REQ_SIZE
					? DRCOM_LOGOUT_REQ_SIZE
					: DRCOM_CHALLENGE_REQ_SIZE];
	uint8_t rep[256];
	size_t n = drcom_challenge_pack(req, &a->session);
	if (drcom_net_send(&a->net, req, n) < 0)
		goto done;
	feed_watchdog();
	ssize_t got = drcom_net_recv(&a->net, rep, sizeof(rep));
	if (got < 0)
		goto done;
	(void)drcom_challenge_parse(rep, (size_t)got, &a->session);

	uint8_t out[DRCOM_LOGOUT_REQ_SIZE];
	n = drcom_logout_pack(out, &a->session);
	if (drcom_net_send(&a->net, out, n) < 0)
		goto done;
	feed_watchdog();
	got = drcom_net_recv(&a->net, rep, sizeof(rep));
	if (got < 0)
		goto done;
	if (drcom_logout_parse(rep, (size_t)got) == DRCOM_OK) {
		drcom_log_info("logout successful");
	} else {
		drcom_log_warn("logout: server did not ack");
	}
done:
	return 0;
}

/**
 * Tear down the current session and re-authenticate from scratch.
 * Called on keepalive failure or link-up after a link-down.
 * Returns 0 on success, negative errno on failure.
 */
static int reauthenticate(drcom_authd_t *a)
{
	drcom_net_close(&a->net);
	set_status(a, DRCOM_STATE_INIT);

	struct sockaddr_in srv;
	if (drcom_resolve_ipv4(a->conf.server, a->conf.port, &srv) < 0) {
		drcom_log_err("re-auth: cannot resolve %s", a->conf.server);
		return -EHOSTUNREACH;
	}
	if (drcom_net_open(&a->net, &srv, a->conf.recv_timeout_ms) < 0) {
		drcom_log_err("re-auth: socket open failed");
		return -EIO;
	}
	if (do_challenge_login(a) != 0) {
		drcom_log_err("re-authentication failed; will retry next tick");
		return -EACCES;
	}
	set_status(a, DRCOM_STATE_ONLINE);
	return 0;
}

static int on_keepalive(sd_event_source *s, uint64_t usec, void *userdata)
{
	(void)usec;
	drcom_authd_t *a = userdata;

	/* If we are monitoring link state and the link is down, skip the
	 * keepalive cycle entirely — the server can't hear us and we'd
	 * just waste a timeout.  Re-arm the timer and wait for link-up. */
	if (a->watched_ifindex >= 0 && !a->link_up) {
		uint64_t next;
		(void)sd_event_now(sd_event_source_get_event(s), CLOCK_MONOTONIC, &next);
		next += (uint64_t)a->conf.keepalive_sec * UINT64_C(1000000);
		(void)sd_event_source_set_time(s, next);
		(void)sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
		return 0;
	}

	int r = do_keepalive_cycle(a);
	if (r < 0) {
		keepalive_err_class_t cls = classify_keepalive_err(r);
		a->keepalive_fail_count++;

		switch (cls) {
		case KEEPALIVE_ERR_TRANSIENT:
			/* EAGAIN/EWOULDBLOCK from SO_RCVTIMEO or ENOMEM.
			 * The server may just be slow; retry on the next
			 * tick without tearing down the session. */
			drcom_log_warn("keepalive transient error (%s); will retry next tick [%u/%u]",
						   strerror(-r),
						   a->keepalive_fail_count,
						   a->conf.max_keepalive_fails);
			break;

		case KEEPALIVE_ERR_NETWORK:
			/* Network path broken.  Re-authenticate (close +
			 * challenge + login) so the next tick starts fresh. */
			drcom_log_warn("keepalive network error (%s); re-authenticating [%u/%u]",
						   strerror(-r),
						   a->keepalive_fail_count,
						   a->conf.max_keepalive_fails);
			(void)reauthenticate(a);
			break;

		case KEEPALIVE_ERR_PROTOCOL:
			/* Server replied with a malformed/unexpected packet.
			 * The session is logically invalid; logout + re-auth. */
			drcom_log_warn("keepalive protocol error (%s); re-authenticating [%u/%u]",
						   strerror(-r),
						   a->keepalive_fail_count,
						   a->conf.max_keepalive_fails);
			/* Best-effort logout before re-auth.  We ignore the
			 * return value because the session may already be
			 * half-broken. */
			if (a->net.fd >= 0)
				(void)do_logout(a);
			(void)reauthenticate(a);
			break;

		case KEEPALIVE_ERR_FATAL:
			/* Login rejected (bad creds/MAC) or unknown error.
			 * Re-auth won't help; let systemd restart us after
			 * the configured failure threshold. */
			drcom_log_err("keepalive fatal error (%s) [%u/%u]",
						  strerror(-r),
						  a->keepalive_fail_count,
						  a->conf.max_keepalive_fails);
			(void)reauthenticate(a);
			break;
		}

		/* If we've hit the consecutive failure threshold, exit the
		 * event loop so systemd can restart the daemon fresh.  A
		 * threshold of 0 means "never exit" (rely on watchdog). */
		if (a->conf.max_keepalive_fails > 0 &&
			a->keepalive_fail_count >= a->conf.max_keepalive_fails) {
			drcom_log_err("reached MaxKeepaliveFails (%u); exiting for systemd restart",
						  a->conf.max_keepalive_fails);
			sd_event_exit(sd_event_source_get_event(s), 0);
			return 0;
		}
	} else {
		if (a->keepalive_fail_count > 0) {
			drcom_log_info("keepalive recovered after %u consecutive failures",
						   a->keepalive_fail_count);
		}
		a->keepalive_fail_count = 0;
	}

	/* Re-arm timer for the next cycle. */
	uint64_t next;
	(void)sd_event_now(sd_event_source_get_event(s), CLOCK_MONOTONIC, &next);
	next += (uint64_t)a->conf.keepalive_sec * UINT64_C(1000000);
	(void)sd_event_source_set_time(s, next);
	(void)sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
	return 0;
}

static int schedule_keepalive(drcom_authd_t *a)
{
	if (a->keepalive_timer) {
		return 0;
	}
	int r =
		sd_event_add_time_relative(a->event,
								   &a->keepalive_timer,
								   CLOCK_MONOTONIC,
								   (uint64_t)a->conf.keepalive_sec * UINT64_C(1000000),
								   1000, /* accuracy */
								   on_keepalive,
								   a);
	if (r < 0)
		return r;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Link state monitoring                                              */
/* ------------------------------------------------------------------ */

/**
 * Deferred re-authentication callback.  Scheduled by on_link_state()
 * when the link comes back up.  Doing the re-auth in a defer source
 * (rather than inside the netlink IO callback) avoids blocking the
 * event loop during the challenge/login network round-trips.
 */
static int on_reauth_defer(sd_event_source *s, void *userdata)
{
	(void)s;
	drcom_authd_t *a = userdata;
	a->reauth_defer = NULL; /* one-shot; auto-unrefs */
	if (a->stopping)
		return 0;
	if (!a->link_up) {
		drcom_log_debug("link went down again before re-auth; deferring");
		return 0;
	}
	drcom_log_info("link up — re-authenticating");
	(void)reauthenticate(a);
	return 0;
}

static int schedule_reauth(drcom_authd_t *a)
{
	if (a->reauth_defer)
		return 0; /* already scheduled */
	return sd_event_add_defer(a->event, &a->reauth_defer, on_reauth_defer, a);
}

/**
 * Netlink link state callback.  Invoked by drcom_netlink_t on every
 * RTM_NEWLINK / RTM_DELLINK notification for any interface.  We filter
 * to the watched interface and update the link_up flag.
 */
static void on_link_state(int ifindex, const char *ifname, bool link_up, void *userdata)
{
	(void)ifname;
	drcom_authd_t *a = userdata;
	if (a->watched_ifindex < 0 || ifindex != a->watched_ifindex)
		return;

	if (link_up == a->link_up)
		return; /* no change */

	a->link_up = link_up;
	if (link_up) {
		drcom_log_info("link up on %s (ifindex %d)", ifname, ifindex);
		/* Schedule a re-auth on the next event loop iteration. */
		(void)schedule_reauth(a);
	} else {
		drcom_log_warn(
			"link down on %s (ifindex %d) — pausing keepalive", ifname, ifindex);
		/* Close the UDP socket immediately so the next keepalive
		 * tick doesn't waste a recv timeout.  The keepalive timer
		 * stays armed but will skip (see on_keepalive). */
		drcom_net_close(&a->net);
		set_status(a, DRCOM_STATE_INIT);
	}
}

drcom_authd_t *drcom_authd_new(const drcom_appconf_t *conf, sd_event *event)
{
	drcom_authd_t *a = calloc(1, sizeof(*a));
	if (!a)
		return NULL;
	a->conf = *conf;
	a->event = event;
	a->state = DRCOM_STATE_INIT;
	a->net.fd = -1;
	a->watched_ifindex = -1;
	a->link_up = true; /* assume up until proven otherwise */
	drcom_session_init(&a->session);

	/* Resolve MAC if not configured. */
	int has_mac = 0;
	for (int i = 0; i < 6; i++) {
		if (a->conf.mac[i] != 0) {
			has_mac = 1;
			break;
		}
	}
	if (!has_mac) {
		char ifn[DRCOM_IFACE_MAX];
		uint8_t mac[6];
		const char *use_iface = a->conf.interface[0] ? a->conf.interface : NULL;
		int r;
		if (use_iface) {
			r = drcom_get_mac(use_iface, mac);
		} else {
			r = drcom_detect_interface(ifn, sizeof(ifn), mac);
			if (r == 0) {
				__builtin_strncpy(a->conf.interface, ifn, sizeof(a->conf.interface) - 1);
				use_iface = a->conf.interface;
			}
		}
		if (r < 0) {
			drcom_log_err("could not determine MAC address: %s", strerror(-r));
		} else {
			__builtin_memcpy(a->session.mac, mac, 6);
			drcom_log_info("using interface %s, MAC %02x:%02x:%02x:%02x:%02x:%02x",
						   use_iface ? use_iface : "?",
						   mac[0],
						   mac[1],
						   mac[2],
						   mac[3],
						   mac[4],
						   mac[5]);
		}
	} else {
		__builtin_memcpy(a->session.mac, a->conf.mac, 6);
	}

	/* Hostname. */
	if (a->conf.hostname[0] == 0) {
		(void)drcom_get_hostname(a->conf.hostname, sizeof(a->conf.hostname));
	}
	size_t hn = strlen(a->conf.hostname);
	if (hn > DRCOM_HOSTNAME_MAX - 1)
		hn = DRCOM_HOSTNAME_MAX - 1;
	__builtin_memcpy(a->session.hostname, a->conf.hostname, hn);
	/* Pad with zeros to fill the 32-byte field on the wire. */
	if (hn < DRCOM_HOSTNAME_MAX) {
		__builtin_memset(a->session.hostname + hn, 0, DRCOM_HOSTNAME_MAX - hn);
	}

	/* Credentials. */
	__builtin_strncpy(
		a->session.username, a->conf.username, sizeof(a->session.username) - 1);
	__builtin_strncpy(
		a->session.password, a->conf.password, sizeof(a->session.password) - 1);
	return a;
}

void drcom_authd_free(drcom_authd_t *a)
{
	if (!a)
		return;
	if (a->reauth_defer)
		sd_event_source_unref(a->reauth_defer);
	if (a->keepalive_timer)
		sd_event_source_unref(a->keepalive_timer);
	drcom_netlink_free(a->netlink);
	drcom_net_close(&a->net);
	free(a);
}

int drcom_authd_start(drcom_authd_t *a)
{
	if (a->started)
		return -EBUSY;

	/* Validate critical config. */
	if (a->conf.username[0] == 0 || a->conf.password[0] == 0) {
		drcom_log_err("username or password not configured");
		return -EINVAL;
	}
	if (a->session.mac[0] == 0 && a->session.mac[1] == 0 && a->session.mac[2] == 0 &&
		a->session.mac[3] == 0 && a->session.mac[4] == 0 && a->session.mac[5] == 0) {
		drcom_log_err("MAC address could not be determined");
		return -EINVAL;
	}

	/* Set up link state monitoring for the configured interface.
	 * This lets us react to link down/up in ~1 ms instead of waiting
	 * for a keepalive timeout.  If the interface name is known we
	 * resolve its ifindex and subscribe to RTMGRP_LINK. */
	if (a->conf.interface[0]) {
		unsigned idx = if_nametoindex(a->conf.interface);
		if (idx > 0) {
			a->watched_ifindex = (int)idx;
			int r = drcom_netlink_new(&a->netlink, a->event, on_link_state, a);
			if (r < 0) {
				drcom_log_warn("netlink monitoring unavailable "
							   "(%s); will rely on keepalive timeouts",
							   strerror(-r));
				a->watched_ifindex = -1;
			} else {
				/* Query the current link state so we don't
				 * attempt to authenticate on a dead link. */
				int q = drcom_netlink_query_link(a->conf.interface);
				if (q == 0) {
					drcom_log_info("interface %s is down; "
								   "waiting for link-up",
								   a->conf.interface);
					a->link_up = false;
				} else {
					a->link_up = true;
				}
			}
		}
	}

	/* If the link is down, don't attempt to authenticate now — just
	 * signal READY and wait for the link-up callback. */
	if (a->watched_ifindex >= 0 && !a->link_up) {
		set_status(a, DRCOM_STATE_INIT);
		/* Schedule the keepalive timer; it will skip while the
		 * link is down and re-auth when it comes up. */
		int r = schedule_keepalive(a);
		if (r < 0) {
			drcom_log_err("failed to schedule keepalive: %s", strerror(-r));
			return r;
		}
		a->started = true;
		(void)sd_notify(0, "READY=1");
		return 0;
	}

	struct sockaddr_in srv;
	int r = drcom_resolve_ipv4(a->conf.server, a->conf.port, &srv);
	if (r < 0) {
		drcom_log_err("cannot resolve %s: %s", a->conf.server, strerror(-r));
		return r;
	}
	r = drcom_net_open(&a->net, &srv, a->conf.recv_timeout_ms);
	if (r < 0) {
		drcom_log_err("socket open failed: %s", strerror(-r));
		return r;
	}

	r = do_challenge_login(a);
	if (r < 0) {
		drcom_net_close(&a->net);
		return r;
	}

	set_status(a, DRCOM_STATE_ONLINE);
	r = schedule_keepalive(a);
	if (r < 0) {
		drcom_log_err("failed to schedule keepalive: %s", strerror(-r));
		return r;
	}

	a->started = true;
	(void)sd_notify(0, "READY=1");
	return 0;
}

int drcom_authd_stop(drcom_authd_t *a)
{
	if (a->stopping)
		return 0;
	a->stopping = true;
	(void)sd_notify(0, "STOPPING=1");

	if (a->reauth_defer) {
		sd_event_source_unref(a->reauth_defer);
		a->reauth_defer = NULL;
	}
	if (a->keepalive_timer) {
		sd_event_source_unref(a->keepalive_timer);
		a->keepalive_timer = NULL;
	}
	if (a->state == DRCOM_STATE_ONLINE && a->net.fd >= 0) {
		set_status(a, DRCOM_STATE_LOGGING_OUT);
		(void)do_logout(a);
	}
	drcom_net_close(&a->net);
	set_status(a, DRCOM_STATE_STOPPED);
	return 0;
}

drcom_state_t drcom_authd_state(const drcom_authd_t *a)
{
	return a->state;
}

const char *drcom_authd_status(const drcom_authd_t *a)
{
	return a->status_buf;
}

void drcom_authd_set_status_cb(drcom_authd_t *a, drcom_status_cb_t cb, void *userdata)
{
	a->status_cb = cb;
	a->status_userdata = userdata;
}
