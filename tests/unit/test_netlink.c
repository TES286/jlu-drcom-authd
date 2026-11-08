/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file test_netlink.c
 * @brief Unit tests for the netlink link-state monitoring module.
 *
 * Tests the query function (drcom_netlink_query_link) against well-known
 * interfaces.  The full RTMGRP_LINK notification path requires root
 * privileges to toggle an interface and is exercised by the E2E test
 * suite instead.
 */
#include "netlink.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <systemd/sd-event.h>

static int failures = 0;

#define CHECK(cond, ...)                                                                     \
        do {                                                                                     \
                if (!(cond)) {                                                                      \
                        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                        \
                        fprintf(stderr, __VA_ARGS__);                                               \
                        fprintf(stderr, "\n");                                                      \
                        failures++;                                                                 \
                }                                                                                  \
        } while (0)

static void test_query_loopback(void)
{
        /* The loopback interface is always UP and has carrier. */
        int r = drcom_netlink_query_link("lo");
        if (r < 0) {
                /* In some sandboxes lo might not be accessible via ioctl;
                 * skip rather than fail. */
                fprintf(stderr, "SKIP: cannot query lo: %s\n", strerror(-r));
                return;
        }
        CHECK(r == 1, "lo should be up, got %d", r);
}

static void test_query_nonexistent(void)
{
        int r = drcom_netlink_query_link("this_iface_does_not_exist");
        CHECK(r < 0, "nonexistent interface should return error, got %d", r);
}

static void test_query_empty_name(void)
{
        int r = drcom_netlink_query_link("");
        CHECK(r < 0, "empty interface name should return error, got %d", r);
        CHECK(r == -EINVAL, "empty name should return -EINVAL, got %d", r);
}

static void test_netlink_new_free(void)
{
        /* Verify that we can create and destroy a netlink monitor without
         * a real event loop (the IO source is registered but never fires). */
        sd_event *event = NULL;
        if (sd_event_default(&event) < 0 || !event) {
                fprintf(stderr, "SKIP: cannot create sd_event\n");
                return;
        }

        drcom_netlink_t *nl = NULL;
        int r = drcom_netlink_new(&nl, event, NULL, NULL);
        CHECK(r == 0, "drcom_netlink_new failed: %s", strerror(-r));
        if (r == 0) {
                CHECK(nl != NULL, "nl should be non-NULL on success");
                drcom_netlink_free(nl);
        }

        sd_event_unref(event);
}

int main(void)
{
        test_query_loopback();
        test_query_nonexistent();
        test_query_empty_name();
        test_netlink_new_free();

        if (failures == 0) {
                printf("test_netlink: PASS\n");
                return 0;
        }
        printf("test_netlink: %d FAILURES\n", failures);
        return 1;
}
