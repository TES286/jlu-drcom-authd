/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file crypto.h
 * @brief Drcom cryptographic primitives: MD5, ror, checksum, crc.
 *
 * The checksum and crc algorithms are reverse-engineered from the official
 * JLU Drcom client and documented in @ref jlu-drcom-protocol.md.
 *
 * MD5 is implemented in pure C with optional ARMv8 NEON for the bulk xor
 * operations in checksum()/crc().  We deliberately avoid OpenSSL to keep
 * the daemon statically linkable on minimal arm64 images and to remove the
 * only non-systemd dependency.
 */
#ifndef DRCOM_CRYPTO_H
#define DRCOM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DRCOM_MD5_DIGEST_SIZE 16
#define DRCOM_CHECKSUM_SIZE 4
#define DRCOM_CRC_SIZE 4

/** MD5 digest of the concatenation of all variadic buffers. */
void drcom_md5_multi(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
					 const uint8_t *const *parts,
					 const size_t *lens,
					 size_t n);

/** Convenience two-part MD5. */
void drcom_md5_2(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
				 const uint8_t *a,
				 size_t a_len,
				 const uint8_t *b,
				 size_t b_len);

/** Convenience three-part MD5. */
void drcom_md5_3(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
				 const uint8_t *a,
				 size_t a_len,
				 const uint8_t *b,
				 size_t b_len,
				 const uint8_t *c,
				 size_t c_len);

/** Convenience four-part MD5. */
void drcom_md5_4(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
				 const uint8_t *a,
				 size_t a_len,
				 const uint8_t *b,
				 size_t b_len,
				 const uint8_t *c,
				 size_t c_len,
				 const uint8_t *d,
				 size_t d_len);

/**
 * ror(md5a, password) - per-byte rotate left by 3 of (md5a[i] ^ password[i]).
 * Output length equals password length.
 *
 * @param out     Destination buffer (>= pass_len bytes).
 * @param md5a    16-byte MD5 digest.
 * @param pass    Password bytes.
 * @param pass_len  Password length (capped to 16 by the caller).
 */
void drcom_ror(uint8_t *out,
			   const uint8_t md5a[DRCOM_MD5_DIGEST_SIZE],
			   const uint8_t *pass,
			   size_t pass_len);

/**
 * Drcom checksum.  See protocol doc.
 *
 * XORs the input in 4-byte big-endian groups, multiplies the 32-bit sum by
 * 1968, and emits the low 4 bytes in little-endian order.
 *
 * @param out   4-byte output.
 * @param data  Input buffer; length need not be a multiple of 4.
 * @param len   Input length.
 */
void drcom_checksum(uint8_t out[DRCOM_CHECKSUM_SIZE], const uint8_t *data, size_t len);

/**
 * Drcom CRC (used in keep40_2).  XORs 2-byte groups, multiplies by 711,
 * emits the low 4 bytes little-endian.
 */
void drcom_crc(uint8_t out[DRCOM_CRC_SIZE], const uint8_t *data, size_t len);

/** Fill the buffer with cryptographically secure random bytes via getrandom(2). */
void drcom_random(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_CRYPTO_H */
