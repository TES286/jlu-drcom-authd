/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file authd.c
 * @brief Drcom authentication state machine.
 */
#define _GNU_SOURCE 1
#include "authd.h"
#include "log.h"
#include "util.h"

#include <errno.h>
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
	drcom_session_t session;
	drcom_net_t net;
	drcom_state_t state;
	drcom_status_cb_t status_cb;
	void *status_userdata;
	char status_buf[128];
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

static int on_keepalive(sd_event_source *s, uint64_t usec, void *userdata)
{
	drcom_authd_t *a = userdata;
	int r = do_keepalive_cycle(a);
	if (r < 0) {
		drcom_log_warn("keepalive cycle failed (%s); will restart challenge/login",
					   strerror(-r));
		/* Tear down and re-login. */
		drcom_net_close(&a->net);
		set_status(a, DRCOM_STATE_INIT);
		struct sockaddr_in srv;
		if (drcom_resolve_ipv4(a->conf.server, a->conf.port, &srv) == 0 &&
			drcom_net_open(&a->net, &srv, a->conf.recv_timeout_ms) == 0) {
			if (do_challenge_login(a) == 0) {
				set_status(a, DRCOM_STATE_ONLINE);
			} else {
				drcom_log_err("re-authentication failed; will retry next tick");
			}
		}
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

drcom_authd_t *drcom_authd_new(const drcom_appconf_t *conf, sd_event *event)
{
	drcom_authd_t *a = calloc(1, sizeof(*a));
	if (!a)
		return NULL;
	a->conf = *conf;
	a->event = event;
	a->state = DRCOM_STATE_INIT;
	a->net.fd = -1;
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
	if (a->keepalive_timer) {
		sd_event_source_unref(a->keepalive_timer);
	}
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
