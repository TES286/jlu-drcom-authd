/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file netlink.h
 * @brief Monitor network interface up/down state via rtnetlink.
 *
 * Opens an AF_NETLINK / NETLINK_ROUTE socket subscribed to RTMGRP_LINK
 * and wires it into an sd_event loop.  When the kernel sends
 * RTM_NEWLINK/RTM_DELLINK notifications (interface create/destroy or
 * flag changes such as IFF_UP / IFF_LOWER_UP toggling), the registered
 * callback is invoked with the interface index, name, and new link-up
 * state.
 *
 * This lets the authd state machine react to link state changes in
 * ~1 ms instead of waiting for a keepalive timeout (up to 20 s).
 *
 * Kernel ABI reference:
 *   https://www.kernel.org/doc/html/latest/userspace-api/netlink/index.html
 *   https://man7.org/linux/man-pages/man7/rtnetlink.7.html
 */
#ifndef DRCOM_NETLINK_H
#define DRCOM_NETLINK_H

#include <stdbool.h>
#include <stdint.h>

#include <systemd/sd-event.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct drcom_netlink drcom_netlink_t;

/**
 * Callback invoked on every link state change.
 *
 * @param ifindex  Kernel interface index (1-based; matches if_nametoindex).
 * @param ifname   Interface name (e.g. "eth0").  May be empty for
 *                 RTM_DELLINK of an already-removed interface.
 * @param link_up  True if the interface is administratively up AND has
 *                 carrier (IFF_UP | IFF_LOWER_UP).  False otherwise.
 * @param userdata Caller-supplied opaque pointer.
 */
typedef void (*drcom_link_cb_t)(int ifindex, const char *ifname,
                                bool link_up, void *userdata);

/**
 * Open a netlink route socket, subscribe to link notifications, and
 * register it with @p event.
 *
 * @param nl       Output handle (caller-owned, free with drcom_netlink_free).
 * @param event    sd_event loop to attach to.
 * @param cb       Callback for link state changes.
 * @param userdata Opaque pointer passed to @p cb.
 * @return 0 on success, negative errno on failure.
 */
int drcom_netlink_new(drcom_netlink_t **nl, sd_event *event,
                      drcom_link_cb_t cb, void *userdata);

void drcom_netlink_free(drcom_netlink_t *nl);

/**
 * Query the current link-up state of @p ifname (IFF_UP | IFF_LOWER_UP).
 *
 * @param ifname  Interface name (e.g. "eth0").
 * @return 1 if link is up, 0 if down, negative errno on error.
 */
int drcom_netlink_query_link(const char *ifname);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_NETLINK_H */
