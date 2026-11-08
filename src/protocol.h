/* SPDX-License-Identifier: AGPL-3.0-or-later */
/**
 * @file protocol.h
 * @brief JLU Drcom wire protocol: packet builders and parsers.
 *
 * The protocol is fully described in
 *   https://github.com/drcoms/jlu-drcom-client/blob/master/jlu-drcom-java/jlu-drcom-protocol.md
 * (mirrored in docs/protocol.md).  All builders write into a caller-supplied
 * buffer and return the number of bytes written; parsers mutate the session
 * in place and return a negative errno-style code on failure.
 */
#ifndef DRCOM_PROTOCOL_H
#define DRCOM_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DRCOM_PORT 61440u
#define DRCOM_RECV_TIMEOUT_MS 5000u
#define DRCOM_KEEPALIVE_SEC 20u

#define DRCOM_USERNAME_MAX 64
#define DRCOM_PASSWORD_MAX 64
#define DRCOM_HOSTNAME_MAX 32

/* Fixed packet sizes. */
#define DRCOM_CHALLENGE_REQ_SIZE 20
#define DRCOM_CHALLENGE_REP_SIZE 76
#define DRCOM_KEEP38_SIZE 38
#define DRCOM_KEEP40_SIZE 40
#define DRCOM_LOGOUT_REQ_SIZE 80

/* Maximum login packet size (pass_len capped to 16). */
#define DRCOM_LOGIN_REQ_MAX (334u + 12u) /* 346 bytes */

typedef enum {
	DRCOM_OK = 0,
	DRCOM_ERR_BAD_PACKET = -1, /* malformed response */
	DRCOM_ERR_AUTH = -2,	   /* server rejected credentials / MAC */
	DRCOM_ERR_SERVER = -3,	   /* unexpected server reply */
	DRCOM_ERR_BUFFER = -4,	   /* caller-supplied buffer too small */
	DRCOM_ERR_INVALID = -5,	   /* invalid session state */
} drcom_err_t;

/** Convert error code to short human-readable string. */
const char *drcom_strerror(drcom_err_t e);

/**
 * Per-connection session state.  Lifetime: from challenge to logout.
 * Lives in heap memory owned by the authd state machine.
 */
typedef struct {
	/* Credentials (NUL-terminated, ASCII). */
	char username[DRCOM_USERNAME_MAX];
	char password[DRCOM_PASSWORD_MAX];

	/* Host identity. */
	uint8_t mac[6];
	char hostname[DRCOM_HOSTNAME_MAX]; /* not necessarily NUL-terminated when emitted */

	/* Server-derived values. */
	uint8_t salt[4];		   /* challenge response [4:8] */
	uint8_t client_ip[4];	   /* challenge response [20:24] */
	uint8_t md5a[16];		   /* login: md5(code,type,salt,password) */
	uint8_t tail1[16];		   /* login response [23:39] */
	uint8_t tail2[4];		   /* keep40_1 response [16:20] */
	uint8_t keep_alive_ver[2]; /* keep38 response [28:30] */

	/* Counters. */
	uint8_t challenge_times; /* starts at 2, incremented per challenge */
	uint8_t count;			 /* keep40 counter, wraps 0..255 */
	unsigned keep38_index;	 /* 1-based index of the current keep38 cycle */
} drcom_session_t;

/** Initialise a fresh session (zeroed, with sane counter defaults). */
void drcom_session_init(drcom_session_t *s);

/* ----------------------------------------------------------------- */
/* Challenge                                                         */
/* ----------------------------------------------------------------- */

/** Build a 20-byte challenge request.  Random bytes [2:4] are fresh. */
size_t drcom_challenge_pack(uint8_t out[DRCOM_CHALLENGE_REQ_SIZE], drcom_session_t *s);

/** Parse a 76-byte challenge response; extract salt and client_ip. */
drcom_err_t drcom_challenge_parse(const uint8_t *in, size_t len, drcom_session_t *s);

/* ----------------------------------------------------------------- */
/* Login                                                             */
/* ----------------------------------------------------------------- */

/**
 * Build a login packet into @p out (capacity @p cap).
 * On success returns the number of bytes written (<= DRCOM_LOGIN_REQ_MAX).
 * Returns 0 on error (cap too small).  Updates s->md5a.
 */
size_t drcom_login_pack(uint8_t *out, size_t cap, drcom_session_t *s);

/** Parse a login response; extract tail1. */
drcom_err_t drcom_login_parse(const uint8_t *in, size_t len, drcom_session_t *s);

/* ----------------------------------------------------------------- */
/* Keepalive                                                         */
/* ----------------------------------------------------------------- */

/** Build a 38-byte keep38 packet. */
size_t drcom_keep38_pack(uint8_t out[DRCOM_KEEP38_SIZE], drcom_session_t *s);

/** Parse a keep38 response; refresh keep_alive_ver and (optionally) IP. */
drcom_err_t drcom_keep38_parse(const uint8_t *in, size_t len, drcom_session_t *s);

/** Build a 40-byte keep40_extra packet (sent right after the 1st and
 *  every 10th keep38). */
size_t drcom_keep40_extra_pack(uint8_t out[DRCOM_KEEP40_SIZE], drcom_session_t *s);

/** Build a 40-byte keep40_1 packet.  The response parser extracts tail2. */
size_t drcom_keep40_1_pack(uint8_t out[DRCOM_KEEP40_SIZE], drcom_session_t *s);

/** Parse a keep40_1 response; extract tail2 [16:20]. */
drcom_err_t drcom_keep40_1_parse(const uint8_t *in, size_t len, drcom_session_t *s);

/** Build a 40-byte keep40_2 packet (carries CRC + client IP). */
size_t drcom_keep40_2_pack(uint8_t out[DRCOM_KEEP40_SIZE], drcom_session_t *s);

/** Returns non-zero if the current keep38 cycle requires a keep40_extra. */
int drcom_keep38_needs_extra(const drcom_session_t *s);

/** Mark the current keep38 cycle as completed (increment index). */
void drcom_keep38_advance(drcom_session_t *s);

/* ----------------------------------------------------------------- */
/* Logout                                                            */
/* ----------------------------------------------------------------- */

/** Build an 80-byte logout packet (challenge must precede this). */
size_t drcom_logout_pack(uint8_t out[DRCOM_LOGOUT_REQ_SIZE], drcom_session_t *s);

/** Parse a logout response.  Returns DRCOM_OK iff the server acked. */
drcom_err_t drcom_logout_parse(const uint8_t *in, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* DRCOM_PROTOCOL_H */
