/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file test_cpufeatures.c
 * @brief Unit tests for the runtime CPU feature detection module.
 *
 * On the amd64 test runner, none of the aarch64 features should be
 * reported as available.  On an aarch64 host, NEON (ASIMD) is
 * architecturally mandatory and must always be detected.
 */
#include "cpufeatures.h"

#include <stdio.h>

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

int main(void)
{
        drcom_cpufeatures_init();

        /* Idempotency: calling init twice must not crash or change results. */
        drcom_cpufeatures_init();

        bool neon = drcom_cpufeatures_neon();

#if defined(__aarch64__) && defined(__ARM_NEON)
        /* On aarch64, ASIMD is mandatory per the ARMv8 architecture spec.
         * The kernel always sets HWCAP_ASIMD in AT_HWCAP on a real aarch64
         * CPU.  If this fails, either the kernel is broken or getauxval
         * is not working. */
        CHECK(neon, "NEON should be available on aarch64, but was not detected");
#else
        /* On non-aarch64 hosts (e.g. amd64 CI runners), no ARM features
         * should be reported. */
        CHECK(!neon, "NEON should not be available on non-aarch64, but was detected");
        CHECK(!drcom_cpufeatures_crc32(), "CRC32 wrongly detected on non-aarch64");
        CHECK(!drcom_cpufeatures_aes(), "AES wrongly detected on non-aarch64");
        CHECK(!drcom_cpufeatures_sha1(), "SHA1 wrongly detected on non-aarch64");
        CHECK(!drcom_cpufeatures_sha2(), "SHA2 wrongly detected on non-aarch64");
        CHECK(!drcom_cpufeatures_pmull(), "PMULL wrongly detected on non-aarch64");
#endif

        /* Laziness: accessors should work even without explicit init, but
         * since we already called init, just verify consistency. */
        CHECK(drcom_cpufeatures_neon() == neon, "neon result inconsistent across calls");

        if (failures == 0) {
                printf("test_cpufeatures: PASS (neon=%d)\n", (int)neon);
                return 0;
        }
        printf("test_cpufeatures: %d FAILURES\n", failures);
        return 1;
}
