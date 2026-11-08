/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file crypto.c
 * @brief Drcom cryptographic primitives.
 *
 * MD5 is a minimal, public-domain style implementation derived from RFC
 * 1321.  We deliberately avoid OpenSSL: it keeps the daemon statically
 * linkable on minimal arm64 images, removes a heavyweight runtime
 * dependency, and lets us tune the inner loop for arm64 (the only ISA the
 * project actually targets as primary).
 *
 * The XOR reductions in drcom_checksum() use NEON on aarch64 to process
 * 16 input bytes per iteration; on every other architecture we fall back
 * to a plain scalar loop that the compiler is free to auto-vectorise.
 */
#include "crypto.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define DRCOM_HAVE_NEON 1
#else
#define DRCOM_HAVE_NEON 0
#endif

/* ------------------------------------------------------------------ */
/* MD5 - RFC 1321                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t a, b, c, d;
} md5_state;

static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint8_t md5_s[64] = {
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* Read 4 bytes as little-endian.  The project targets only little-endian
 * architectures (arm64 primary, amd64 secondary) so a plain memcpy is
 * correct and lets the compiler emit a single load. */
static inline uint32_t le32_load(const uint8_t *p)
{
    uint32_t v;
    __builtin_memcpy(&v, p, sizeof(v));
    return v;
}

static inline void le32_store(uint8_t *p, uint32_t v)
{
    __builtin_memcpy(p, &v, sizeof(v));
}

static void md5_compress(md5_state *st, const uint8_t block[64])
{
    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
        M[i] = le32_load(block + i * 4);
    }

    uint32_t a = st->a, b = st->b, c = st->c, d = st->d;

    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = 5 * i + 1;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = 3 * i + 5;
        } else {
            f = c ^ (b | ~d);
            g = 7 * i;
        }
        g &= 15;
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + md5_k[i] + M[g], md5_s[i]);
        a = temp;
    }

    st->a += a;
    st->b += b;
    st->c += c;
    st->d += d;
}

void drcom_md5_multi(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
                     const uint8_t *const *parts, const size_t *lens, size_t n)
{
    md5_state st = {
        .a = 0x67452301,
        .b = 0xefcdab89,
        .c = 0x98badcfe,
        .d = 0x10325476,
    };
    uint8_t buf[64];
    size_t buflen = 0;
    uint64_t total = 0;

    for (size_t i = 0; i < n; i++) {
        total += lens[i];
        const uint8_t *p = parts[i];
        size_t l = lens[i];

        /* Flush pending bytes plus as many full blocks as possible. */
        if (buflen > 0) {
            size_t need = 64 - buflen;
            size_t take = (l < need) ? l : need;
            __builtin_memcpy(buf + buflen, p, take);
            buflen += take;
            p += take;
            l -= take;
            if (buflen == 64) {
                md5_compress(&st, buf);
                buflen = 0;
            }
        }
        while (l >= 64) {
            md5_compress(&st, p);
            p += 64;
            l -= 64;
        }
        if (l > 0) {
            __builtin_memcpy(buf, p, l);
            buflen = l;
        }
    }

    /* Padding: 0x80, then zeros, then 8-byte length in bits, little-endian. */
    uint64_t bitlen = total * 8;
    buf[buflen++] = 0x80;
    if (buflen > 56) {
        __builtin_memset(buf + buflen, 0, 64 - buflen);
        md5_compress(&st, buf);
        buflen = 0;
    }
    __builtin_memset(buf + buflen, 0, 56 - buflen);
    for (int i = 0; i < 8; i++) {
        buf[56 + i] = (uint8_t)(bitlen >> (8 * i));
    }
    md5_compress(&st, buf);

    le32_store(out +  0, st.a);
    le32_store(out +  4, st.b);
    le32_store(out +  8, st.c);
    le32_store(out + 12, st.d);
}

void drcom_md5_2(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
                 const uint8_t *a, size_t a_len,
                 const uint8_t *b, size_t b_len)
{
    const uint8_t *parts[2] = {a, b};
    const size_t lens[2] = {a_len, b_len};
    drcom_md5_multi(out, parts, lens, 2);
}

void drcom_md5_3(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
                 const uint8_t *a, size_t a_len,
                 const uint8_t *b, size_t b_len,
                 const uint8_t *c, size_t c_len)
{
    const uint8_t *parts[3] = {a, b, c};
    const size_t lens[3] = {a_len, b_len, c_len};
    drcom_md5_multi(out, parts, lens, 3);
}

void drcom_md5_4(uint8_t out[DRCOM_MD5_DIGEST_SIZE],
                 const uint8_t *a, size_t a_len,
                 const uint8_t *b, size_t b_len,
                 const uint8_t *c, size_t c_len,
                 const uint8_t *d, size_t d_len)
{
    const uint8_t *parts[4] = {a, b, c, d};
    const size_t lens[4] = {a_len, b_len, c_len, d_len};
    drcom_md5_multi(out, parts, lens, 4);
}

/* ------------------------------------------------------------------ */
/* ror - per-byte left rotate by 3 of (md5a[i] ^ password[i])         */
/* ------------------------------------------------------------------ */

void drcom_ror(uint8_t *out,
               const uint8_t md5a[DRCOM_MD5_DIGEST_SIZE],
               const uint8_t *pass, size_t pass_len)
{
    for (size_t i = 0; i < pass_len; i++) {
        uint8_t x = (uint8_t)(md5a[i] ^ pass[i]);
        /* ROL by 3 in 8 bits: low 8 bits of (x<<3) | (x>>5). */
        out[i] = (uint8_t)((x << 3) | (x >> 5));
    }
}

/* ------------------------------------------------------------------ */
/* checksum - 4-byte group XOR, multiply by 1968, little-endian out   */
/* ------------------------------------------------------------------ */

/* Initial sum bytes (big-endian 1234 = 0x000004d2). */
static const uint8_t k_checksum_init[4] = {0x00, 0x00, 0x04, 0xd2};

static inline void checksum_xorscalar(uint8_t sum[4], const uint8_t *data, size_t len)
{
    size_t i = 0;
    for (; i + 4 <= len; i += 4) {
        sum[0] ^= data[i + 3];
        sum[1] ^= data[i + 2];
        sum[2] ^= data[i + 1];
        sum[3] ^= data[i + 0];
    }
    if (i < len) {
        uint8_t tmp[4] = {0, 0, 0, 0};
        int j = 3;
        while (i < len && j >= 0) {
            tmp[j--] = data[i++];
        }
        sum[0] ^= tmp[0];
        sum[1] ^= tmp[1];
        sum[2] ^= tmp[2];
        sum[3] ^= tmp[3];
    }
}

#if DRCOM_HAVE_NEON
static inline void checksum_xor_neon(uint8_t sum[4], const uint8_t *data, size_t len)
{
    /* Replicate the 4-byte init pattern across all 4 lanes of a 16-byte
     * vector.  vld1q_dup_u32 loads one 32-bit value and broadcasts it. */
    uint8x16_t v_sum = vreinterpretq_u8_u32(
        vld1q_dup_u32((const uint32_t *)k_checksum_init));

    size_t i = 0;
    for (; i + 16 <= len; i += 16) {
        uint8x16_t v = vld1q_u8(data + i);
        /* Reverse bytes within each 4-byte group: d0..d3 -> d3..d0. */
        v = vrev32q_u8(v);
        v_sum = veorq_u8(v_sum, v);
    }
    /* Horizontal reduction: 16 bytes -> 4 bytes (XOR the four 32-bit
     * lanes together).  vextq shifts the vector; we XOR twice. */
    uint8x16_t hi = vextq_u8(v_sum, v_sum, 8);
    v_sum = veorq_u8(v_sum, hi);
    uint8x16_t mid = vextq_u8(v_sum, v_sum, 4);
    v_sum = veorq_u8(v_sum, mid);

    uint32_t lane;
    vst1q_lane_u32(&lane, vreinterpretq_u32_u8(v_sum), 0);
    __builtin_memcpy(sum, &lane, 4);

    /* Tail in scalar. */
    if (i < len) {
        checksum_xorscalar(sum, data + i, len - i);
    }
}
#endif

void drcom_checksum(uint8_t out[DRCOM_CHECKSUM_SIZE],
                    const uint8_t *data, size_t len)
{
    uint8_t sum[4];
    __builtin_memcpy(sum, k_checksum_init, 4);

#if DRCOM_HAVE_NEON
    checksum_xor_neon(sum, data, len);
#else
    checksum_xorscalar(sum, data, len);
#endif

    uint32_t val = ((uint32_t)sum[0] << 24) |
                   ((uint32_t)sum[1] << 16) |
                   ((uint32_t)sum[2] <<  8) |
                   ((uint32_t)sum[3]);
    val = (val * 1968u);
    /* Low 4 bytes, little-endian. */
    out[0] = (uint8_t)(val);
    out[1] = (uint8_t)(val >>  8);
    out[2] = (uint8_t)(val >> 16);
    out[3] = (uint8_t)(val >> 24);
}

/* ------------------------------------------------------------------ */
/* crc - 2-byte group XOR, multiply by 711, little-endian 4-byte out  */
/* ------------------------------------------------------------------ */

void drcom_crc(uint8_t out[DRCOM_CRC_SIZE],
               const uint8_t *data, size_t len)
{
    uint8_t sum[2] = {0, 0};
    size_t i = 0;
    for (; i + 2 <= len; i += 2) {
        sum[0] ^= data[i + 1];
        sum[1] ^= data[i + 0];
    }
    if (i < len) {
        /* One trailing byte: protocol doc treats data as if there were a
         * phantom 0 byte before it; mirror that by XORing the byte into
         * sum[1] only.  This branch is exercised only by malformed input
         * in practice. */
        sum[1] ^= data[i];
    }

    uint32_t val = ((uint32_t)sum[0] << 8) | (uint32_t)sum[1];
    val = (val * 711u);
    out[0] = (uint8_t)(val);
    out[1] = (uint8_t)(val >>  8);
    out[2] = (uint8_t)(val >> 16);
    out[3] = (uint8_t)(val >> 24);
}

/* ------------------------------------------------------------------ */
/* Random bytes via getrandom(2)                                      */
/* ------------------------------------------------------------------ */

void drcom_random(uint8_t *out, size_t len)
{
    while (len > 0) {
        ssize_t r = getrandom(out, len, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            /* Should not happen on any modern kernel; abort defensively. */
            abort();
        }
        out += r;
        len -= (size_t)r;
    }
}
