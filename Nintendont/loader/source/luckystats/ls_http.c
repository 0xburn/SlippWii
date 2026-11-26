/* loader/source/luckystats/ls_http.c
 * One HTTPS request to Lucky Stats or to the file store its upload links name (see ls_core.h).
 *
 * Unlike the updater's downloads (update/upd_http.c, whose files carry a signature), a key goes out
 * here, so the connection is checked whole: TLS 1.2, the certificate chain up to one of the roots
 * compiled in (ls_roots.inc: the site's and the store's are separate lists), the server's name, and
 * the certificates' dates by the console's clock. A clock that is wrong fails the check: nothing is
 * sent then. Redirects are never followed.
 *
 * A Wii has no good random numbers to give TLS. The connection's seed is therefore also the
 * player's key (hashed): who could work the seed out would have the key already (the idea of RFC 8937).
 */
#include "ls_core.h"
#include "../update/upd_core.h"
#include "bearssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ls_roots.inc"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define HEAD_MAX 8192
#define PIECE 0x4000

static const uint16_t suites[] = {
	BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};

/* On the heap while a request runs: without a key none of this takes memory. */
typedef struct {
	int sock;
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	br_sslio_context io;
	unsigned char buf[BR_SSL_BUFSIZE_BIDI];
	char head[HEAD_MAX];
	uint8_t piece[PIECE];
} Conn;

#ifdef LS_TEST
/* tests/luckystats/: one more root, and where the two servers are. Never in the loader. */
br_x509_trust_anchor ls_test_root;
int ls_test_root_set;
#endif

static int low_read(void *ctx, unsigned char *buf, size_t len)
{
	int n = ls_plat_recv(((Conn *)ctx)->sock, buf, (int)(len > PIECE ? PIECE : len));
	return n > 0 ? n : -1;
}

static int low_write(void *ctx, const unsigned char *buf, size_t len)
{
	int n = ls_plat_send(((Conn *)ctx)->sock, buf, (int)(len > PIECE ? PIECE : len));
	return n > 0 ? n : -1;
}

/* Every check of the certificate is BearSSL's X.509 engine's: chain, name (the one given to
 * br_ssl_client_reset) and dates (the time set here; with none it accepts nothing). */
static void tls_profile(Conn *c, const LsRequest *r)
{
	static uint32_t calls;
	const br_x509_trust_anchor *roots = r->storage ? ls_storage_roots : ls_site_roots;
	size_t n = r->storage ? COUNT(ls_storage_roots) : COUNT(ls_site_roots);
	uint32_t now = ls_plat_time();
	br_sha256_context h;
	uint8_t seed[32];

#ifdef LS_TEST
	if (ls_test_root_set) {
		roots = &ls_test_root;
		n = 1;
	}
#endif
	br_ssl_client_init_full(&c->sc, &c->xc, roots, n);
	br_ssl_engine_set_versions(&c->sc.eng, BR_TLS12, BR_TLS12);
	br_ssl_engine_set_suites(&c->sc.eng, suites, COUNT(suites));
	br_ssl_engine_add_flags(&c->sc.eng, BR_OPT_NO_RENEGOTIATION);
	br_x509_minimal_set_time(&c->xc, now / 86400 + 719528, now % 86400);	/* (days since the year 0) */
	br_ssl_engine_set_buffer(&c->sc.eng, c->buf, sizeof(c->buf), 1);

	calls++;
	upd_plat_entropy(seed);
	br_sha256_init(&h);
	br_sha256_update(&h, "SlippWii Lucky Stats", 20);
	br_sha256_update(&h, seed, sizeof(seed));
	br_sha256_update(&h, &calls, sizeof(calls));
	br_sha256_update(&h, &now, sizeof(now));
	br_sha256_update(&h, r->secret, LS_KEY_LEN);
	br_sha256_out(&h, seed);
	br_ssl_engine_inject_entropy(&c->sc.eng, seed, sizeof(seed));
	memset(seed, 0, sizeof(seed));
	memset(&h, 0, sizeof(h));
}

static int failed(Conn *c, LsAnswer *a)
{
	int e = br_ssl_engine_last_error(&c->sc.eng);
	a->tls_error = e;
	if (e == BR_ERR_X509_EXPIRED)
		return LS_CLOCK;
	if (e >= BR_ERR_X509_OK && e <= BR_ERR_X509_NOT_TRUSTED)
		return LS_CERT;
	return LS_NET;
}

static int lower(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }

static const char *header(const char *head, const char *name)
{
	size_t n = strlen(name), i;
	const char *p;
	for (p = strstr(head, "\r\n"); p; p = strstr(p + 2, "\r\n")) {
		for (i = 0; i < n && lower(p[2 + i]) == lower(name[i]); i++)
			;
		if (i == n && p[2 + n] == ':') {
			for (p += 3 + n; *p == ' ' || *p == '\t'; p++)
				;
			return p;
		}
	}
	return NULL;
}

/* "https://host[:port]/path": 0, or < 0. Nothing but https. */
int ls_url(const char *url, char *host, size_t size, uint16_t *port, const char **path)
{
	const char *p = url + 8, *slash;
	size_t n, i;
	if (strncmp(url, "https://", 8) != 0 || !(slash = strchr(p, '/')))
		return -1;
	n = (size_t)(slash - p);
	if (n == 0 || n >= size)
		return -1;
	memcpy(host, p, n);
	host[n] = 0;
	*port = 443;
#ifdef LS_TEST
	if (strchr(host, ':')) {
		*port = (uint16_t)atoi(strchr(host, ':') + 1);
		*strchr(host, ':') = 0;
	}
#endif
	for (i = 0; host[i]; i++)
		if (!((host[i] >= 'a' && host[i] <= 'z') || (host[i] >= '0' && host[i] <= '9') || host[i] == '.' || host[i] == '-'))
			return -1;	/* (a user name, a port, anything else that is not a plain host) */
	for (p = slash; *p; p++)
		if (*p <= 0x20 || *p >= 0x7F)
			return -1;
	*path = slash;
	return 0;
}

/* One response head into c->head. How many bytes of it there are in all; `*body`: where the rest
 * of them, the body's first, start. < 0: no answer. */
static int read_head(Conn *c, int *body, int *status)
{
	int have = 0, n;
	char *end = NULL;
	while (!end) {
		if (have >= HEAD_MAX - 1)
			return -1;
		n = br_sslio_read(&c->io, c->head + have, (size_t)(HEAD_MAX - 1 - have));
		if (n <= 0)
			return -1;
		have += n;
		c->head[have] = 0;
		end = strstr(c->head, "\r\n\r\n");
	}
	*body = (int)(end + 4 - c->head);
	end[2] = 0;
	if (strncmp(c->head, "HTTP/1.", 7) != 0 || strlen(c->head) < 12)
		return -1;
	*status = (int)strtol(c->head + 9, NULL, 10);
	return have;
}

static int put(LsAnswer *a, const uint8_t *p, uint32_t n)
{
	if (n > LS_ANSWER_MAX - 1 - a->len)
		return -1;
	memcpy(a->body + a->len, p, n);
	a->len += n;
	return 0;
}

/* The body's bytes: first those that came with the head, then the connection's. */
typedef struct {
	Conn *c;
	int at, have;		/* in c->head */
} In;

static int in_byte(In *in)
{
	if (in->at == in->have) {
		in->at = 0;
		in->have = br_sslio_read(&in->c->io, in->c->head, HEAD_MAX);
		if (in->have <= 0) {
			in->have = 0;
			return -1;
		}
	}
	return (uint8_t)in->c->head[in->at++];
}

/* 0: whole; < 0: broken off, too long, or not HTTP. */
static int read_body(In *in, const char *length, int chunked, LsAnswer *a)
{
	uint32_t left;
	int ch;
	uint8_t b;
	for (;;) {
		if (chunked) {
			int digits = 0, over = 0;
			left = 0;
			while ((ch = in_byte(in)) != '\n') {
				int d = ch >= '0' && ch <= '9' ? ch - '0' : lower(ch) >= 'a' && lower(ch) <= 'f' ? lower(ch) - 'a' + 10 : -1;
				if (ch < 0)
					return -1;
				if (d < 0)
					over = 1;
				if (over)
					continue;
				if (++digits > 6)
					return -1;
				left = left << 4 | (uint32_t)d;
			}
			if (!digits)
				return -1;
			if (left == 0)
				return 0;
		} else if (length) {
			left = (uint32_t)strtoul(length, NULL, 10);
		} else {
			return -1;	/* (a body that ends with the connection could be cut short unseen) */
		}
		for (; left; left--) {
			if ((ch = in_byte(in)) < 0)
				return -1;
			b = (uint8_t)ch;
			if (put(a, &b, 1) < 0)
				return -1;
		}
		if (!chunked)
			return 0;
		if (in_byte(in) != '\r' || in_byte(in) != '\n')
			return -1;
	}
}

static int send_body(Conn *c, const LsRequest *r, LsAnswer *a)
{
	uint32_t at = 0;
	while (at < r->body_len) {
		uint32_t n = r->body_len - at < PIECE ? r->body_len - at : PIECE;
		const uint8_t *from = r->body ? r->body + at : c->piece;
		if (!r->body) {
			int got = ls_plat_read(r->file, c->piece, (int)n);
			if (got <= 0)
				return LS_CARD;	/* (shorter than it was, or unreadable) */
			n = (uint32_t)got;
		}
		if (ls_plat_cancelled())
			return LS_CANCEL;
		if (br_sslio_write_all(&c->io, from, n) != 0)
			return failed(c, a);
		at += n;
		if (!r->body)
			ls_plat_progress(NULL, at, r->body_len);
	}
	return br_sslio_flush(&c->io) == 0 ? LS_OK : failed(c, a);
}

static int exchange(Conn *c, const LsRequest *r, LsAnswer *a)
{
	char authority[144], type[80] = "";
	const char *v;
	int n, at, res;
	In in;

	if (!br_ssl_client_reset(&c->sc, r->host, 0))
		return failed(c, a);
	br_sslio_init(&c->io, &c->sc.eng, low_read, c, low_write, c);
	snprintf(authority, sizeof(authority), r->port == 443 ? "%s" : "%s:%u", r->host, (unsigned)r->port);
	if (r->content_type)
		snprintf(type, sizeof(type), "Content-Type: %s\r\n", r->content_type);
	/* (a file is announced first: a link that has run out, or a file that is there already, is told
	 * before its megabytes are sent) */
	n = snprintf(c->head, HEAD_MAX, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: SlippWii\r\nAccept: application/json\r\n"
		"Connection: close\r\n%sContent-Length: %lu\r\n%s%s\r\n", r->method, r->path, authority, type,
		(unsigned long)r->body_len, r->file ? "Expect: 100-continue\r\n" : "", r->headers ? r->headers : "");
	if (n >= HEAD_MAX)
		return LS_SERVER;
	res = br_sslio_write_all(&c->io, c->head, (size_t)n) == 0 && br_sslio_flush(&c->io) == 0 ? LS_OK : failed(c, a);
	memset(c->head, 0, (size_t)n);	/* (it held the key) */
	if (res == LS_OK && !r->file)
		res = send_body(c, r, a);
	if (res != LS_OK)
		return res;
	for (;;) {
		n = read_head(c, &at, &a->status);
		if (n < 0)
			return failed(c, a);
		if (a->status != 100)
			break;
		if (!r->file)
			return LS_SERVER;
		res = send_body(c, r, a);
		if (res != LS_OK)
			return res;
	}
	v = header(c->head, "Retry-After");
	a->retry_after = v ? (uint32_t)strtoul(v, NULL, 10) : 0;
	if (r->storage || a->status == 204 || a->status == 304)
		return LS_OK;	/* (the file store's answer is its status) */
	{
		char length[16] = "";
		int chunked = (v = header(c->head, "Transfer-Encoding")) && lower(v[0]) == 'c';
		if ((v = header(c->head, "Content-Length")))
			snprintf(length, sizeof(length), "%.10s", v);
		in.c = c;
		in.at = at;
		in.have = n;
		if (read_body(&in, length[0] ? length : NULL, chunked, a) < 0)
			return LS_NET;
	}
	a->body[a->len] = 0;
	return LS_OK;
}

int ls_request(const LsRequest *r, LsAnswer *a)
{
	Conn *c;
	int res;

	a->status = 0;
	a->retry_after = 0;
	a->len = 0;
	a->body[0] = 0;
	a->tls_error = 0;
	if (ls_plat_cancelled())
		return LS_CANCEL;
	c = upd_plat_alloc(sizeof(*c));
	if (!c)
		return LS_NET;
	memset(c, 0, sizeof(*c));
	c->sock = upd_plat_connect(r->host, r->port);
	if (c->sock < 0) {
		upd_plat_free(c);
		return LS_NET;
	}
	tls_profile(c, r);
	res = exchange(c, r, a);
	upd_plat_close(c->sock);
	memset(c, 0, sizeof(*c));
	upd_plat_free(c);
	return res;
}
