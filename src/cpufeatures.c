/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file cpufeatures.c
 * @brief Runtime CPU feature detection.
 *
 * Uses getauxval(3) to read the AT_HWCAP / AT_HWCAP2 entries from the
 * auxiliary vector, which the kernel populates based on the ELF HWCAP
 * tables documented in
 *   https://www.kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html
 *
 * On aarch64, HWCAP_ASIMD (NEON) is bit 2 of AT_HWCAP.  Although ASIMD
 * is architecturally mandatory on aarch64, we still check at runtime so
 * the same binary works correctly on emulators or hypervisors that might
 * trap/fault NEON instructions.
 *
 * On non-aarch64 platforms the module compiles to a set of functions
 * that unconditionally return false.
 */
#include "cpufeatures.h"

#include <stdint.h>
#include <string.h>

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <sys/auxv.h>
/* HWCAP_AARCH64_* constants are provided by <bits/hwcap.h> via <sys/auxv.h>
 * on glibc >= 2.18.  They are always defined when compiling for aarch64
 * with a glibc toolchain. */
#define DRCOM_CPU_AARCH64 1
#else
#define DRCOM_CPU_AARCH64 0
#endif

typedef struct {
        bool neon;
        bool crc32;
        bool aes;
        bool sha1;
        bool sha2;
        bool pmull;
        bool initialised;
} cpufeatures_cache;

static cpufeatures_cache g_cache;

#if DRCOM_CPU_AARCH64

#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1UL << 2)
#endif
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1UL << 7)
#endif
#ifndef HWCAP_AES
#define HWCAP_AES (1UL << 3)
#endif
#ifndef HWCAP_SHA1
#define HWCAP_SHA1 (1UL << 5)
#endif
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1UL << 6)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1UL << 4)
#endif

static void probe(cpufeatures_cache *c)
{
        unsigned long hwcap = getauxval(AT_HWCAP);
        c->neon = (hwcap & HWCAP_ASIMD) != 0;
        c->crc32 = (hwcap & HWCAP_CRC32) != 0;
        c->aes = (hwcap & HWCAP_AES) != 0;
        c->sha1 = (hwcap & HWCAP_SHA1) != 0;
        c->sha2 = (hwcap & HWCAP_SHA2) != 0;
        c->pmull = (hwcap & HWCAP_PMULL) != 0;
}

#else /* !DRCOM_CPU_AARCH64 */

static void probe(cpufeatures_cache *c)
{
        /* On non-aarch64 platforms no optional ARM features are available. */
        memset(c, 0, sizeof(*c));
}

#endif

void drcom_cpufeatures_init(void)
{
        if (g_cache.initialised)
                return;
        probe(&g_cache);
        g_cache.initialised = true;
}

/* Each accessor lazily initialises on first call so callers that forget
 * drcom_cpufeatures_init() still get correct results (at the cost of a
 * single atomic check per call). */
bool drcom_cpufeatures_neon(void)
{
        if (!g_cache.initialised)
                drcom_cpufeatures_init();
        return g_cache.neon;
}

bool drcom_cpufeatures_crc32(void)
{
        if (!g_cache.initialised)
                drcom_cpufeatures_init();
        return g_cache.crc32;
}

bool drcom_cpufeatures_aes(void)
{
        if (!g_cache.initialised)
                drcom_cpufeatures_init();
        return g_cache.aes;
}

bool drcom_cpufeatures_sha1(void)
{
        if (!g_cache.initialised)
                drcom_cpufeatures_init();
        return g_cache.sha1;
}

bool drcom_cpufeatures_sha2(void)
{
        if (!g_cache.initialised)
                drcom_cpufeatures_init();
        return g_cache.sha2;
}

bool drcom_cpufeatures_pmull(void)
{
        if (!g_cache.initialised)
                drcom_cpufeatures_init();
        return g_cache.pmull;
}
