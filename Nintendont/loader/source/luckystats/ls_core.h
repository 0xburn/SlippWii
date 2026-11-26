/* loader/source/luckystats/ls_core.h
 * Lucky Stats (luckystats.gg): the work that is the same on a Wii and on a PC (where its tests run).
 *
 * Finished games (.slp files) that SlippWii saved go to the player's own Lucky Stats account. It is
 * off unless the player puts an upload key on the card, and it runs in the loader only: no game is
 * running then, and every file the kernel wrote is closed.
 *
 *   ls_core.c   the key's file, what was sent already (a file on the drive the games are on), the
 *               upload itself
 *   ls_http.c   HTTPS with the server's certificate checked: chain, host name and dates
 *
 * The platform gives sockets and memory (upd_plat_*, the updater's, update/upd_core.h), and the
 * files, the clock and the screen (ls_plat_*): luckystats.c on a Wii, tests/luckystats/ on a PC.
 */
#ifndef LS_CORE_H
#define LS_CORE_H

#include <stddef.h>
#include <stdint.h>

#define LS_HOST "luckystats.gg"
#define LS_STORAGE ".amazonaws.com"	/* where the server's upload links may point (never with the key) */
#define LS_APP "slippwii"

#define LS_KEY_LEN 68			/* "l7u_" and 64 hex digits */
#define LS_NAME_MAX 64
#define LS_BATCH_FILES 16
#define LS_BATCH_BYTES (48u << 20)
#define LS_FILE_MAX (48u << 20)		/* a long game is a few MB */
#define LS_ANSWER_MAX 0x10000		/* 16 upload links are up to 40 KB */
#define LS_URL_MAX 3072
#define LS_ROUNDS 3			/* tries in one start, 2 and 4 seconds apart */

enum {
	LS_OK = 0,
	LS_NOTHING,		/* no key: the feature is off */
	LS_CANCEL,		/* the player went on to the game */
	LS_LATER,		/* failed lately: not yet again */
	LS_BAD_KEY_FILE,	/* the key's file has no key */
	LS_CARD,		/* a drive could not be read or written */
	LS_NET,			/* no connection, or it broke */
	LS_CLOCK,		/* the server's certificate is not valid at this console's date */
	LS_CERT,		/* not the server: its certificate is not trusted */
	LS_KEY,			/* the key is not accepted (revoked, or the app is off) */
	LS_PREMIUM,		/* the account may not upload */
	LS_QUOTA,		/* the account's storage is full */
	LS_BUSY,		/* the server said later (429, 5xx) */
	LS_SERVER,		/* an answer this version does not understand */
	LS_REDO			/* (inside) this upload is void: the same files again in a new one */
};

typedef struct {
	char key[LS_KEY_LEN + 1];
	int history;		/* upload what was there before the key, too */
} LsConfig;

/* Reads the key's file. LS_OK, or LS_BAD_KEY_FILE. */
int ls_config(const char *text, uint32_t len, LsConfig *c);

/* The whole of it, for the drives of `devs` (a bit each: 1 SD, 2 USB); `state_dev` (0 or 1) keeps when to
 * try again. `*sent`: games uploaded. LS_*. */
int ls_run(const LsConfig *c, int devs, int state_dev, int *sent);

/* ---- ls_http.c ---- */

typedef struct {
	const char *host;
	uint16_t port;
	int storage;		/* the file store's authorities, not the site's */
	const char *method, *path;
	const char *headers;	/* more lines, each with its "\r\n" */
	const char *content_type;
	const uint8_t *body;	/* the body, or NULL: body_len bytes of `file` */
	uint32_t body_len;
	void *file;
	const uint8_t *secret;	/* the key: its hash is in the connection's random numbers */
} LsRequest;

typedef struct {
	int status;
	uint32_t retry_after;	/* seconds, 0: not said */
	char *body;		/* LS_ANSWER_MAX bytes; a string */
	uint32_t len;
	int tls_error;		/* BearSSL's, when the connection failed */
} LsAnswer;

/* LS_OK (then a->status), LS_NET, LS_CLOCK, LS_CERT, LS_CANCEL, LS_CARD, LS_SERVER. */
int ls_request(const LsRequest *r, LsAnswer *a);
int ls_url(const char *url, char *host, size_t size, uint16_t *port, const char **path);

/* ---- the platform's part ---- */

typedef void (*LsFound)(void *arg, const char *name, uint32_t size);

uint32_t ls_plat_time(void);			/* seconds since 1970 by the console's clock */
/* The HTTPS connection's bytes, on a socket from upd_plat_connect: some of `len` (> 0), or < 0. Not
 * upd_plat_send/recv: on a Wii those send again after -EAGAIN, which IOS can answer to a big send it took
 * part of, and a byte sent twice breaks TLS (luckystats.c). */
int ls_plat_send(int sock, const uint8_t *buf, int len);
int ls_plat_recv(int sock, uint8_t *buf, int len);	/* > 0; 0: closed; < 0: failed or timed out */
int ls_plat_network(void);			/* LS_OK, LS_NET or LS_CANCEL; may wait */
int ls_plat_cancelled(void);			/* the player wants to go on */
int ls_plat_wait(uint32_t ms);			/* LS_OK or LS_CANCEL */
void ls_plat_progress(const char *what, uint32_t done, uint32_t total);

int ls_plat_list(int dev, LsFound found, void *arg);	/* the files of /Slippi; 0 (also with no folder), < 0: failed */
void *ls_plat_open(int dev, const char *name, uint32_t *size);	/* one at a time */
int ls_plat_read(void *f, uint8_t *buf, int len);	/* bytes; 0: the end; < 0: failed */
void ls_plat_close(void *f);

/* What was sent, on drive `dev`. Both writes are on the drive when they return 0. */
int ls_plat_state_load(int dev, char **text, uint32_t *len);	/* 0 (upd_plat_free it), 1: there is none, < 0 */
int ls_plat_state_create(int dev, const char *text, uint32_t len);	/* whole or not at all */
int ls_plat_state_append(int dev, const char *text, uint32_t len);

#endif
