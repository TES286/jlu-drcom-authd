/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file cpufeatures.h
 * @brief Runtime CPU feature detection via getauxval(AT_HWCAP).
 *
 * On aarch64, NEON/ASIMD is mandatory in the base architecture (every
 * aarch64 CPU implements it), but optional extensions like CRC32, AES,
 * SHA, PMULL are not.  A "generic aarch64" binary (as shipped by distros
 * and OpenWrt) must detect these at runtime rather than hard-coding them
 * at compile time.
 *
 * This module probes the auxiliary vector once at startup and caches the
 * result in a thread-local singleton.  Callers use drcom_cpufeatures_*
 * accessors to dispatch to the optimal code path.
 *
 * On non-aarch64 platforms (amd64 secondary target), every accessor
 * returns false.
 */
#ifndef DRCOM_CPUFEATURES_H
#define DRCOM_CPUFEATURES_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Probe the auxiliary vector and cache the result.
 *
 * Thread-safety: this function is idempotent and safe to call from any
 * thread.  The first call performs the actual probe; subsequent calls
 * are no-ops.  Call once at startup for best performance.
 */
void drcom_cpufeatures_init(void);

/** Returns true if the CPU supports NEON / Advanced SIMD (ASIMD). */
bool drcom_cpufeatures_neon(void);

/** Returns true if the CPU supports the ARMv8 CRC32 instructions. */
bool drcom_cpufeatures_crc32(void);

/** Returns true if the CPU supports the ARMv8 AES instructions. */
bool drcom_cpufeatures_aes(void);

/** Returns true if the CPU supports the ARMv8 SHA1 instructions. */
bool drcom_cpufeatures_sha1(void);

/** Returns true if the CPU supports the ARMv8 SHA2 instructions. */
bool drcom_cpufeatures_sha2(void);

/** Returns true if the CPU supports the ARMv8 PMULL instructions. */
bool drcom_cpufeatures_pmull(void);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_CPUFEATURES_H */
