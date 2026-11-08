/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file authd.h
 * @brief Drcom authentication state machine driven by sd_event.
 *
 * The state machine is intentionally synchronous inside each "phase"
 * (challenge/login/keepalive/logout): the Drcom wire protocol is strictly
 * request/response with bounded timeouts, so blocking recv(2) with
 * SO_RCVTIMEO is simpler and has lower overhead than wiring every recv
 * into sd_event IO sources.
 *
 * sd_event still drives the outer loop: the keepalive timer, signal
 * handlers, and the systemd watchdog (sd_event_set_watchdog) all live in
 * the event loop.  Between network operations we feed the watchdog
 * manually via sd_notify("WATCHDOG=1") so a slow server cannot trigger a
 * spurious kill.
 */
#ifndef DRCOM_AUTHD_H
#define DRCOM_AUTHD_H

#include "appconf.h"
#include "netlink.h"
#include "network.h"
#include "protocol.h"

#include <stdbool.h>
#include <stdint.h>

#include <systemd/sd-event.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	DRCOM_STATE_INIT = 0,	 /* fresh; not yet challenged */
	DRCOM_STATE_ONLINE,		 /* logged in, keepalive running */
	DRCOM_STATE_LOGGING_OUT, /* logout in flight */
	DRCOM_STATE_STOPPED,	 /* terminal */
} drcom_state_t;

typedef struct drcom_authd drcom_authd_t;

typedef void (*drcom_status_cb_t)(void *userdata, drcom_state_t state);

/** Allocate a new authd instance.  Returns NULL on OOM. */
drcom_authd_t *drcom_authd_new(const drcom_appconf_t *conf, sd_event *event);

void drcom_authd_free(drcom_authd_t *a);

/** Start the state machine: open socket, run challenge + login, schedule
 *  the keepalive timer.  Returns 0 on success. */
int drcom_authd_start(drcom_authd_t *a);

/** Stop the state machine: send logout (best-effort), close socket, remove
 *  timer.  Returns 0 on success. */
int drcom_authd_stop(drcom_authd_t *a);

/** Current state. */
drcom_state_t drcom_authd_state(const drcom_authd_t *a);

/** Human-readable status line suitable for sd_notify("STATUS=..."). */
const char *drcom_authd_status(const drcom_authd_t *a);

/** Set a callback invoked on every state transition. */
void drcom_authd_set_status_cb(drcom_authd_t *a, drcom_status_cb_t cb, void *userdata);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_AUTHD_H */
