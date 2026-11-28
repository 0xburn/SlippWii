/* loader/source/luckystats/ls_core.c
 * What goes to Lucky Stats, and what went (see ls_core.h).
 *
 * The games are sent in uploads of up to LS_BATCH_FILES files: the server is told their names, sizes
 * and SHA-256s and answers with a link for each, each file is PUT to its link, and the server is told
 * that this is all of them. It checks every file's size and SHA-256 then.
 *
 * What was sent is kept in a text file on the drive the games are on, which only grows; a line:
 *
 *	SlippWii Lucky Stats 1			the first
 *	s <size> <name>				there before the key was: not sent (unless history=yes)
 *	x <size> <name>				not a finished game: not sent
 *	p <id> <count>				an upload begins; then its <count> files:
 *	f <size> <sha256> <name>
 *	k <index>				that file of it was PUT
 *	r					PUT them all again
 *	c					the server has it: its files are sent
 *	d					it is void: its files are to be sent
 *	w <seconds since 1970> <failures>	not again before then
 *
 * A line is on the drive before the next step is taken, so whatever the power does, the next start goes
 * on where this one stopped: the same id (the server's Idempotency-Key) and the same files give the same
 * upload, not a second one. A line the power cut short has no "\n" and is passed over.
 */
#include "ls_core.h"
#include "../update/upd_core.h"
#include "bearssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char HEAD[] = "SlippWii Lucky Stats 1\n";
#define STATE_MAX (4u << 20)

typedef struct {
	char name[LS_NAME_MAX];
	uint32_t size;
	char sha256[65];
	int put;
	char url[LS_URL_MAX];
} LsFile;

typedef struct {
	int dev;
	uint64_t *known;	/* the files that are not to be sent, as hashes; sorted */
	uint32_t known_count, known_room;
	int no_memory, card_error;
	int torn;		/* the file's last line has no end */
	uint32_t voided;	/* uploads that came to nothing: in the next one's id */
	uint32_t wait_until, failures;
	char wait_key[9];	/* short hash of the key that failed (a new key does not wait for an old failure) */
	char id[33];		/* the upload that is under way ("": none) */
	int count;
	LsFile *f;		/* LS_BATCH_FILES of them */
	uint32_t waiting;	/* (found in the folder: to be sent) */
	uint32_t found_bytes;
} Drive;

/* ---- the key's file ---- */

int ls_config(const char *t, uint32_t len, LsConfig *c)
{
	uint32_t at = 0;
	memset(c, 0, sizeof(*c));
	if (len >= 3 && memcmp(t, "\xEF\xBB\xBF", 3) == 0)
		at = 3;		/* (Notepad's mark) */
	while (at < len) {
		uint32_t end = at, n, i;
		while (end < len && t[end] != '\n')
			end++;
		n = end - at;
		while (n && (t[at + n - 1] == '\r' || t[at + n - 1] == ' ' || t[at + n - 1] == '\t'))
			n--;
		if (n == 4 + LS_KEY_LEN && memcmp(t + at, "key=l7u_", 8) == 0) {
			for (i = 8; i < n; i++)
				if (!((t[at + i] >= '0' && t[at + i] <= '9') || (t[at + i] >= 'a' && t[at + i] <= 'f')))
					break;
			if (i == n)
				memcpy(c->key, t + at + 4, LS_KEY_LEN);
		} else if (n == 11 && memcmp(t + at, "history=yes", 11) == 0) {
			c->history = 1;
		}
		at = end + 1;
	}
	return c->key[0] ? LS_OK : LS_BAD_KEY_FILE;
}

/* ---- what was sent ---- */

static uint64_t file_hash(const char *name, uint32_t size)
{
	uint64_t h = 14695981039346656037ull;	/* FNV-1a */
	for (; *name; name++)
		h = (h ^ (unsigned char)*name) * 1099511628211ull;
	for (; size; size >>= 8)
		h = (h ^ (size & 0xFF)) * 1099511628211ull;
	return h;
}

static int by_hash(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

static void know(Drive *d, const char *name, uint32_t size)
{
	if (d->known_count == d->known_room) {
		uint32_t room = d->known_room ? d->known_room * 2 : 256;
		uint64_t *more = realloc(d->known, room * sizeof(*more));
		if (!more) {
			d->no_memory = 1;
			return;
		}
		d->known = more;
		d->known_room = room;
	}
	d->known[d->known_count++] = file_hash(name, size);
}

/* A file name the kernel writes ("Game_<MAC>_<date>.slp"); nothing else is looked at. */
static int game_name(const char *name)
{
	size_t n = strlen(name), i;
	if (n < 10 || n >= LS_NAME_MAX || strncmp(name, "Game_", 5) != 0 || strcmp(name + n - 4, ".slp") != 0)
		return 0;
	for (i = 0; i < n; i++)
		if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'A' && name[i] <= 'Z') ||
		      (name[i] >= 'a' && name[i] <= 'z') || name[i] == '_' || name[i] == '-' || name[i] == '.'))
			return 0;
	return 1;
}

static int append(Drive *d, const char *text)
{
	if (d->torn && ls_plat_state_append(d->dev, "\n", 1) < 0)
		return LS_CARD;
	d->torn = 0;
	if (ls_plat_state_append(d->dev, text, (uint32_t)strlen(text)) < 0) {
		d->torn = 1;
		return LS_CARD;
	}
	return LS_OK;
}

static void upload_over(Drive *d, int sent)
{
	int i;
	for (i = 0; sent && i < d->count; i++)
		know(d, d->f[i].name, d->f[i].size);
	if (!sent)
		d->voided++;
	d->id[0] = 0;
	d->count = 0;
}

/* The state file's lines. */
static void read_state(Drive *d, char *t, uint32_t len, int history)
{
	uint32_t at, end;
	int want = 0;	/* "f" lines still to come */
	char name[LS_NAME_MAX], sha[65], id[33];
	unsigned long size, b;
	int i;

	d->torn = len && t[len - 1] != '\n';
	for (at = sizeof(HEAD) - 1; at < len; at = end + 1) {
		char *line = t + at;
		for (end = at; end < len && t[end] != '\n'; end++)
			;
		if (end == len)
			break;	/* (cut short) */
		t[end] = 0;
		if (line[0] == 'f' && want && sscanf(line, "f %lu %64s %63s", &size, sha, name) == 3 &&
		    strspn(sha, "0123456789abcdef") == 64 && game_name(name)) {
			LsFile *f = &d->f[d->count++];
			strcpy(f->name, name);
			strcpy(f->sha256, sha);
			f->size = (uint32_t)size;
			f->put = 0;
			if (--want == 0)
				strcpy(d->id, id);
			continue;
		}
		if (want) {	/* (its files were cut short: nothing was sent of it) */
			want = 0;
			d->count = 0;
		}
		if ((line[0] == 's' || line[0] == 'x') && sscanf(line + 1, " %lu %63s", &size, name) == 2) {
			if (line[0] == 'x' || !history)
				know(d, name, (uint32_t)size);
		} else if (sscanf(line, "p %32s %lu", id, &b) == 2 && strlen(id) == 32 && b >= 1 && b <= LS_BATCH_FILES) {
			d->id[0] = 0;
			d->count = 0;
			want = (int)b;
		} else if (sscanf(line, "k %lu", &b) == 1 && d->id[0] && b < (unsigned long)d->count) {
			d->f[b].put = 1;
		} else if (strcmp(line, "r") == 0) {
			for (i = 0; i < d->count; i++)
				d->f[i].put = 0;
		} else if ((strcmp(line, "c") == 0 || strcmp(line, "d") == 0) && d->id[0]) {
			upload_over(d, line[0] == 'c');
		} else if (line[0] == 'w') {
			char tag[9] = "";
			int got = sscanf(line, "w %lu %lu %8s", &size, &b, tag);
			if (got >= 2) {
				d->wait_until = (uint32_t)size;
				d->failures = (uint32_t)b;
				if (got == 3 && strlen(tag) == 8 && strspn(tag, "0123456789abcdef") == 8)
					strcpy(d->wait_key, tag);
				else
					d->wait_key[0] = 0;
			}
		}
	}
	if (want)
		d->count = 0;
	if (!d->id[0])
		d->count = 0;
}

typedef struct {
	char *text;
	uint32_t len, room;
	int failed;
} Text;

static void found_first(void *arg, const char *name, uint32_t size)
{
	Text *t = arg;
	if (!game_name(name) || t->failed)
		return;
	if (t->len + LS_NAME_MAX + 16 > t->room) {
		char *more = realloc(t->text, t->room * 2);
		if (!more) {
			t->failed = 1;
			return;
		}
		t->text = more;
		t->room *= 2;
	}
	t->len += (uint32_t)sprintf(t->text + t->len, "s %lu %s\n", (unsigned long)size, name);
}

/* A drive seen for the first time: what is on it now is not sent. */
static int first_time(int dev)
{
	Text t;
	int res;
	t.room = 8192;
	t.failed = 0;
	t.text = malloc(t.room);
	if (!t.text)
		return LS_CARD;
	t.len = (uint32_t)sprintf(t.text, "%s", HEAD);
	res = ls_plat_list(dev, found_first, &t);
	if (res == 0 && !t.failed)
		res = ls_plat_state_create(dev, t.text, t.len);
	res = res < 0 || t.failed ? LS_CARD : LS_OK;
	free(t.text);
	return res;
}

static int open_state(Drive *d, int dev, int history)
{
	char *text = NULL;
	uint32_t len = 0;
	int res, again;

	d->dev = dev;
	for (again = 0; again < 2; again++) {
		res = ls_plat_state_load(dev, &text, &len);
		if (res != 1)
			break;
		res = first_time(dev);
		if (res != LS_OK)
			return res;
	}
	if (res != 0)
		return LS_CARD;
	if (len < sizeof(HEAD) - 1 || memcmp(text, HEAD, sizeof(HEAD) - 1) != 0 || len > STATE_MAX) {
		upd_plat_free(text);
		return LS_CARD;	/* (not this version's: not touched, and nothing sent) */
	}
	read_state(d, text, len, history);
	upd_plat_free(text);
	if (d->no_memory)
		return LS_CARD;
	if (d->known_count)
		qsort(d->known, d->known_count, sizeof(*d->known), by_hash);
	return LS_OK;
}

/* ---- what is to be sent ---- */

/* The oldest files by name (a name has its game's date) that are not known, LS_BATCH_FILES of them. */
static void found_game(void *arg, const char *name, uint32_t size)
{
	Drive *d = arg;
	uint64_t h;
	int i;
	if (!game_name(name) || size < 16)
		return;
	h = file_hash(name, size);
	if (d->known_count && bsearch(&h, d->known, d->known_count, sizeof(h), by_hash))
		return;
	d->waiting++;
	for (i = d->count; i > 0 && strcmp(name, d->f[i - 1].name) < 0; i--)
		;
	if (i == LS_BATCH_FILES)
		return;
	if (d->count == LS_BATCH_FILES)
		d->count--;
	memmove(&d->f[i + 1], &d->f[i], (size_t)(d->count - i) * sizeof(d->f[0]));
	memset(&d->f[i], 0, sizeof(d->f[0]));
	strcpy(d->f[i].name, name);
	d->f[i].size = size;
	d->count++;
}

static void hex(const uint8_t *b, int n, char *out)
{
	for (; n; n--, b++, out += 2)
		sprintf(out, "%02x", *b);
}

/* The file's SHA-256, and whether it is a game saved to its end: the kernel writes the game data's
 * length into the file's head only when the game is over, and the metadata behind the data. 1 if it is,
 * 0 if not, < 0: it could not be read, -2: the player went on. */
static int read_game(Drive *d, LsFile *f, uint8_t *buf, int room)
{
	static const uint8_t start[11] = { '{', 'U', 3, 'r', 'a', 'w', '[', '$', 'U', '#', 'l' };
	static const uint8_t meta[11] = { 'U', 8, 'm', 'e', 't', 'a', 'd', 'a', 't', 'a', '{' };
	br_sha256_context h;
	uint8_t digest[32], last[2] = { 0, 0 }, name[11];
	uint32_t size, at = 0, raw = 0, i;
	int n, ok = 1, seen = 0;
	void *file;

	if (f->size > LS_FILE_MAX)
		return 0;
	file = ls_plat_open(d->dev, f->name, &size);
	if (!file)
		return -1;
	br_sha256_init(&h);
	ok = size == f->size;
	while (ok && at < size) {
		n = ls_plat_read(file, buf, room);
		if (n <= 0 || ls_plat_cancelled()) {
			ls_plat_close(file);
			return n <= 0 ? -1 : -2;
		}
		if (at == 0) {
			ok = n >= 15 && memcmp(buf, start, sizeof(start)) == 0;
			if (ok)
				raw = (uint32_t)buf[11] << 24 | (uint32_t)buf[12] << 16 | (uint32_t)buf[13] << 8 | buf[14];
			ok = ok && raw > 0 && size > 15 + 13 && raw <= size - 15 - 13;
		}
		br_sha256_update(&h, buf, (size_t)n);
		for (i = 0; ok && seen < 11 && i < 11; i++)	/* (the metadata's name may lie across two reads) */
			if (15 + raw + i >= at && 15 + raw + i < at + (uint32_t)n) {
				name[i] = buf[15 + raw + i - at];
				seen++;
			}
		if (n >= 2)
			memcpy(last, buf + n - 2, 2);
		else {
			last[0] = last[1];
			last[1] = buf[0];
		}
		at += (uint32_t)n;
	}
	ls_plat_close(file);
	if (!ok || at != size || seen != 11 || memcmp(name, meta, 11) != 0 || last[0] != '}' || last[1] != '}')
		return 0;
	br_sha256_out(&h, digest);
	hex(digest, 32, f->sha256);
	return 1;
}

/* A new upload of what is found on the drive. LS_OK with d->count 0: nothing to send. */
static int new_upload(Drive *d)
{
	const int room = 0x8000;
	uint32_t bytes, i, kept;
	br_sha256_context h;
	uint8_t digest[32], *buf;
	char *text, line[160];
	int res = LS_OK, n;

	buf = upd_plat_alloc((uint32_t)room);
	text = malloc(LS_BATCH_FILES * sizeof(line) + sizeof(line));
	if (!buf || !text)
		res = LS_CARD;
	while (res == LS_OK) {
		d->count = 0;
		d->waiting = 0;
		if (ls_plat_list(d->dev, found_game, d) < 0) {
			res = LS_CARD;
			break;
		}
		if (!d->count)
			break;
		kept = 0;
		bytes = 0;
		for (i = 0; i < (uint32_t)d->count && res == LS_OK; i++) {
			LsFile *f = &d->f[i];
			if (kept && bytes + f->size > LS_BATCH_BYTES)
				break;
			ls_plat_progress("Reading new games", i, (uint32_t)d->count);
			n = read_game(d, f, buf, room);
			if (n == -2) {
				res = LS_CANCEL;
			} else if (n < 0) {
				res = LS_CARD;
			} else if (n == 0) {
				snprintf(line, sizeof(line), "x %lu %s\n", (unsigned long)f->size, f->name);
				res = append(d, line);
				know(d, f->name, f->size);
				if (d->no_memory)
					res = LS_CARD;
			} else {
				bytes += f->size;
				if (kept != i)
					d->f[kept] = *f;
				kept++;
			}
		}
		d->count = (int)kept;
		if (d->known_count)
			qsort(d->known, d->known_count, sizeof(*d->known), by_hash);
		if (res == LS_OK && kept)
			break;
		/* (none of them was a game: the next ones) */
	}
	upd_plat_free(buf);
	if (res == LS_OK && d->count) {
		/* The id: of these files, after this many that came to nothing. */
		br_sha256_init(&h);
		br_sha256_update(&h, &d->voided, sizeof(d->voided));
		for (i = 0; i < (uint32_t)d->count; i++) {
			br_sha256_update(&h, d->f[i].name, strlen(d->f[i].name));
			br_sha256_update(&h, d->f[i].sha256, 64);
		}
		br_sha256_out(&h, digest);
		hex(digest, 16, d->id);
		n = sprintf(text, "p %s %d\n", d->id, d->count);
		for (i = 0; i < (uint32_t)d->count; i++)
			n += sprintf(text + n, "f %lu %s %s\n", (unsigned long)d->f[i].size, d->f[i].sha256, d->f[i].name);
		res = append(d, text);
	}
	free(text);
	if (res != LS_OK) {
		d->id[0] = 0;
		d->count = 0;
	}
	return res;
}

/* ---- the server's answers ----
 *
 * Just enough JSON to pick values out of objects whose names are known. */

static const char *js_space(const char *p)
{
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;
	return p;
}

/* A string into `out` (which may be NULL); behind it, or NULL. */
static const char *js_string(const char *p, char *out, size_t size)
{
	size_t n = 0;
	if (*p++ != '"')
		return NULL;
	for (; *p && *p != '"'; p++) {
		char ch = *p;
		if (ch == '\\') {
			ch = *++p;
			if (ch == 'u') {
				char code[5];
				size_t i;
				for (i = 0; i < 4 && p[1 + i]; i++)
					code[i] = p[1 + i];
				if (i < 4)
					return NULL;
				code[4] = 0;
				ch = (char)strtoul(code, NULL, 16);	/* (plain ASCII is all that is asked for) */
				p += 4;
			} else if (ch != '"' && ch != '\\' && ch != '/') {
				ch = ' ';
			}
			if (!*p)
				return NULL;
		}
		if (out) {
			if (n + 1 >= size)
				return NULL;
			out[n++] = ch;
		}
	}
	if (out)
		out[n] = 0;
	return *p == '"' ? p + 1 : NULL;
}

static const char *js_skip(const char *p)
{
	int depth = 0;
	for (p = js_space(p); *p; ) {
		if (*p == '"') {
			p = js_string(p, NULL, 0);
			if (!p)
				return NULL;
		} else if (*p == '{' || *p == '[') {
			depth++;
			p++;
		} else if (*p == '}' || *p == ']') {
			if (depth == 0)
				return p;
			depth--;
			p++;
		} else if (depth == 0 && *p == ',') {
			return p;
		} else {
			p++;
			continue;
		}
		if (depth == 0)
			return p;
	}
	return depth == 0 ? p : NULL;
}

/* The value of `name` in the object at `p`, or NULL. */
static const char *js_get(const char *p, const char *name)
{
	char key[32];
	p = js_space(p);
	if (*p++ != '{')
		return NULL;
	for (;;) {
		const char *after;
		p = js_space(p);
		if (*p != '"')
			return NULL;
		after = js_string(p, key, sizeof(key));
		if (!after) {
			key[0] = 0;	/* (a name longer than any asked for) */
			after = js_string(p, NULL, 0);
		}
		if (!after)
			return NULL;
		p = js_space(after);
		if (*p++ != ':')
			return NULL;
		p = js_space(p);
		if (strcmp(key, name) == 0)
			return p;
		p = js_skip(p);
		if (!p)
			return NULL;
		p = js_space(p);
		if (*p++ != ',')
			return NULL;
	}
}

static int js_text(const char *object, const char *name, char *out, size_t size)
{
	const char *v = js_get(object, name);
	out[0] = 0;
	return v && js_string(v, out, size) ? 0 : -1;
}

/* ---- an upload ---- */

typedef struct {
	const LsConfig *config;
	LsAnswer a;
	uint32_t retry_after;
} Session;

/* A request to the site, which alone gets the key. */
static int site(Session *s, const char *path, const char *idempotency, const char *body)
{
	char headers[256];
	LsRequest r;
	int res;

	memset(&r, 0, sizeof(r));
	r.host = LS_HOST;
	r.port = 443;
	r.method = "POST";
	r.path = path;
	r.headers = headers;
	r.content_type = "application/json";
	r.body = (const uint8_t *)body;
	r.body_len = (uint32_t)strlen(body);
	r.secret = (const uint8_t *)s->config->key;
	snprintf(headers, sizeof(headers), "Authorization: Bearer %s\r\nX-App-Id: " LS_APP "\r\n%s%s%s", s->config->key,
		idempotency ? "Idempotency-Key: " : "", idempotency ? idempotency : "", idempotency ? "\r\n" : "");
#ifdef LS_TEST
	{
		extern uint16_t ls_test_port;
		r.port = ls_test_port;
	}
#endif
	res = ls_request(&r, &s->a);
	memset(headers, 0, sizeof(headers));
	if (s->a.retry_after > s->retry_after)
		s->retry_after = s->a.retry_after;
	return res;
}

/* What an answer that is not 200 means. */
static int refused(Session *s)
{
	char code[48];
	js_text(s->a.body, "error", code, sizeof(code));
	switch (s->a.status) {
	case 401:
		return LS_KEY;
	case 403:
		return strcmp(code, "not_supporter") == 0 ? LS_PREMIUM : LS_KEY;
	case 404:
		return LS_REDO;		/* (the upload is gone: or this version's address, which the second try says) */
	case 409:
		return strcmp(code, "upload_incomplete") == 0 ? LS_BUSY : LS_REDO;
	case 410:
		return LS_REDO;
	case 413:
		return LS_QUOTA;
	case 429:
		return LS_BUSY;
	default:
		return s->a.status >= 500 ? LS_BUSY : LS_SERVER;
	}
}

/* Asks for the upload: its id into `upload`, and the links. `*done`: the server has it already. */
static int ask(Session *s, Drive *d, char upload[40], int *done)
{
	char *body, line[200], host[128], path[LS_NAME_MAX + 8];
	const char *v, *p;
	uint16_t port;
	size_t n;
	int i, j, res;

	body = malloc(LS_BATCH_FILES * sizeof(line) + 32);
	if (!body)
		return LS_NET;
	n = (size_t)sprintf(body, "{\"files\":[");
	for (i = 0; i < d->count; i++)
		n += (size_t)sprintf(body + n, "%s{\"path\":\"%s\",\"size\":%lu,\"sha256\":\"%s\"}", i ? "," : "", d->f[i].name,
			(unsigned long)d->f[i].size, d->f[i].sha256);
	sprintf(body + n, "]}");
	res = site(s, "/api/integrations/v1/uploads/personal", d->id, body);
	free(body);
	if (res != LS_OK)
		return res;
	if (s->a.status != 200)
		return refused(s);

	if (js_text(s->a.body, "uploadId", upload, 40) < 0 || strlen(upload) != 36 || strspn(upload, "0123456789abcdef-") != 36)
		return LS_SERVER;
	v = js_get(s->a.body, "handoffAccepted");
	*done = v && strncmp(v, "true", 4) == 0;
	if (*done)
		return LS_OK;
	for (i = 0; i < d->count; i++)
		d->f[i].url[0] = 0;
	v = js_get(s->a.body, "files");
	if (!v || *v != '[')
		return LS_SERVER;
	for (p = js_space(v + 1); *p == '{'; p = js_space(p + 1)) {
		if (js_text(p, "path", path, sizeof(path)) < 0)
			return LS_SERVER;
		for (j = 0; j < d->count && strcmp(d->f[j].name, path) != 0; j++)
			;
		if (j == d->count || js_text(p, "url", d->f[j].url, LS_URL_MAX) < 0 ||
		    ls_url(d->f[j].url, host, sizeof(host), &port, &v) < 0)
			return LS_SERVER;
#ifndef LS_TEST
		n = strlen(host);
		if (n <= sizeof(LS_STORAGE) - 1 || strcmp(host + n - (sizeof(LS_STORAGE) - 1), LS_STORAGE) != 0)
			return LS_SERVER;
#endif
		p = js_skip(p);
		if (!p)
			return LS_SERVER;
		p = js_space(p);
		if (*p != ',')
			break;
	}
	for (i = 0; i < d->count; i++)
		if (!d->f[i].url[0])
			return LS_SERVER;
	return LS_OK;
}

static void base64_of_hex(const char *h, char *out)
{
	static const char set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint8_t b[33];
	char two[3] = "";
	int i;
	for (i = 0; i < 32; i++) {
		memcpy(two, h + 2 * i, 2);
		b[i] = (uint8_t)strtoul(two, NULL, 16);
	}
	b[32] = 0;
	for (i = 0; i < 33; i += 3) {
		*out++ = set[b[i] >> 2];
		*out++ = set[(b[i] & 3) << 4 | b[i + 1] >> 4];
		*out++ = set[(b[i + 1] & 15) << 2 | b[i + 2] >> 6];
		*out++ = set[b[i + 2] & 63];
	}
	out[-1] = '=';
	*out = 0;
}

/* One file to its link. The link's host never sees the key. */
static int put_file(Session *s, Drive *d, LsFile *f)
{
	char headers[128], sum[48], host[128];
	LsRequest r;
	uint32_t size = 0;
	int res;

	memset(&r, 0, sizeof(r));
	if (ls_url(f->url, host, sizeof(host), &r.port, &r.path) < 0)
		return LS_SERVER;
	r.host = host;
	r.storage = 1;
	r.method = "PUT";
	r.headers = headers;
	r.content_type = "application/octet-stream";
	r.body_len = f->size;
	r.secret = (const uint8_t *)s->config->key;
	base64_of_hex(f->sha256, sum);
	snprintf(headers, sizeof(headers), "x-amz-checksum-sha256: %s\r\nIf-None-Match: *\r\n", sum);
	r.file = ls_plat_open(d->dev, f->name, &size);
	if (!r.file || size != f->size) {
		if (r.file)
			ls_plat_close(r.file);
		return LS_REDO;		/* (deleted or another file since) */
	}
	res = ls_request(&r, &s->a);
	ls_plat_close(r.file);
	if (res != LS_OK)
		return res;
	if (s->a.status == 200 || s->a.status == 412)	/* (412: it is there; an answer was lost) */
		return LS_OK;
	if (s->a.status == 400)
		return LS_REDO;		/* (not the bytes their SHA-256 was made of) */
	return LS_BUSY;			/* (403: the link ran out: the next round has new ones) */
}

static int upload(Session *s, Drive *d, int sent_before)
{
	char id[40], path[96], line[16], what[64];
	int i, res, done = 0;

	for (i = 0; i < d->count; i++) {
		void *f;
		uint32_t size = 0;
		if (d->f[i].put)
			continue;
		f = ls_plat_open(d->dev, d->f[i].name, &size);
		if (f)
			ls_plat_close(f);
		if (!f || size != d->f[i].size)
			return LS_REDO;
	}
	res = ask(s, d, id, &done);
	if (res != LS_OK)
		return res;
	for (i = 0; !done && i < d->count; i++) {
		if (d->f[i].put)
			continue;
		snprintf(what, sizeof(what), "Uploading game %d of %d", sent_before + i + 1,
			sent_before + ((int)d->waiting > d->count ? (int)d->waiting : d->count));
		ls_plat_progress(what, 0, d->f[i].size);
		res = put_file(s, d, &d->f[i]);
		if (res != LS_OK)
			return res;
		d->f[i].put = 1;
		snprintf(line, sizeof(line), "k %d\n", i);
		res = append(d, line);
		if (res != LS_OK)
			return res;
	}
	if (!done) {
		snprintf(path, sizeof(path), "/api/integrations/v1/uploads/%s/complete", id);
		res = site(s, path, NULL, "");
		if (res != LS_OK)
			return res;
		if (s->a.status != 200) {
			res = refused(s);
			if (res == LS_BUSY && s->a.status == 409) {	/* a file is missing there: all of them again */
				for (i = 0; i < d->count; i++)
					d->f[i].put = 0;
				if (append(d, "r\n") != LS_OK)
					return LS_CARD;
			}
			return res;
		}
		{
			const char *v = js_get(s->a.body, "handoffAccepted");
			if (!v || strncmp(v, "true", 4) != 0)
				return LS_SERVER;
		}
	}
	return append(d, "c\n");
}

/* One drive's games, all of them. */
static int drive(Session *s, Drive *d, int *sent, int *online)
{
	int res, tries = 0, voids = 0, before = *sent;

	for (;;) {
		if (!d->id[0]) {
			res = new_upload(d);
			if (res != LS_OK || !d->count)
				return res;
			tries = 0;
		}
		if (!*online) {
			res = ls_plat_network();
			if (res != LS_OK)
				return res;
			*online = 1;
		}
		res = upload(s, d, *sent - before);
		if (res == LS_OK) {
			*sent += d->count;
			upload_over(d, 1);
			if (d->no_memory)
				return LS_CARD;
			if (d->known_count)
				qsort(d->known, d->known_count, sizeof(*d->known), by_hash);
			voids = 0;
		} else if (res == LS_REDO) {
			if (append(d, "d\n") != LS_OK)
				return LS_CARD;
			upload_over(d, 0);
			if (++voids == LS_ROUNDS)
				return LS_SERVER;
		} else if (res == LS_NET || (res == LS_BUSY && s->a.status != 429)) {
			if (++tries == LS_ROUNDS)
				return res;
			if (ls_plat_wait(2000u * (uint32_t)tries) != LS_OK)
				return LS_CANCEL;
		} else {
			return res;
		}
	}
}

static void key_tag(const char *key, char out[9])
{
	br_sha256_context h;
	uint8_t digest[32];
	br_sha256_init(&h);
	br_sha256_update(&h, "SlippWii key tag", 16);
	br_sha256_update(&h, key, LS_KEY_LEN);
	br_sha256_out(&h, digest);
	hex(digest, 4, out);
	memset(digest, 0, sizeof(digest));
	memset(&h, 0, sizeof(h));
}

int ls_run(const LsConfig *config, int devs, int state_dev, int *sent, uint32_t *later)
{
	Drive *d[2] = { NULL, NULL };
	Session s;
	uint32_t now = ls_plat_time(), wait;
	int res = LS_OK, online = 0, dev, key_changed = 0;
	char line[64], tag[9];

	*sent = 0;
	*later = 0;
	memset(&s, 0, sizeof(s));
	s.config = config;
	key_tag(config->key, tag);
	for (dev = 0; dev < 2 && res == LS_OK; dev++) {
		if (!(devs & 1 << dev))
			continue;
		d[dev] = calloc(1, sizeof(Drive));
		if (d[dev])
			d[dev]->f = calloc(LS_BATCH_FILES, sizeof(LsFile));
		if (!d[dev] || !d[dev]->f)
			res = LS_CARD;
		else
			res = open_state(d[dev], dev, config->history);
	}
	/* A new key in luckystats.txt clears an earlier failure's wait so the player does not have to wait
	 * up to 6 hours after fixing a revoked or wrong key. */
	if (res == LS_OK && d[state_dev]->wait_key[0] && strcmp(d[state_dev]->wait_key, tag) != 0) {
		d[state_dev]->wait_until = 0;
		d[state_dev]->failures = 0;
		key_changed = 1;
	}
	/* After failures it waits: 5 minutes, twice that, ... 6 hours, or what the server said. (A time further
	 * off than that: the clock was set. Not waited for.) */
	if (res == LS_OK && d[state_dev]->wait_until > now && d[state_dev]->wait_until - now <= 24 * 3600) {
		res = LS_LATER;
		*later = d[state_dev]->wait_until - now;
	}
	if (res == LS_OK) {
		s.a.body = malloc(LS_ANSWER_MAX);
		if (!s.a.body)
			res = LS_CARD;
		for (dev = 0; dev < 2 && res == LS_OK; dev++)
			if (d[dev])
				res = drive(&s, d[dev], sent, &online);
		if (res == LS_OK && (d[state_dev]->failures || key_changed)) {
			append(d[state_dev], "w 0 0\n");
		} else if (res != LS_OK && res != LS_CANCEL && res != LS_CARD) {
			uint32_t n = d[state_dev]->failures;
			wait = n < 7 ? 300u << n : 6 * 3600;
			if (wait > 6 * 3600)
				wait = 6 * 3600;
			if (s.retry_after > wait)
				wait = s.retry_after < 24 * 3600 ? s.retry_after : 24 * 3600;
			snprintf(line, sizeof(line), "w %lu %lu %s\n", (unsigned long)(ls_plat_time() + wait), (unsigned long)(n < 100 ? n + 1 : n), tag);
			append(d[state_dev], line);
		}
		if (s.a.body) {
			memset(s.a.body, 0, LS_ANSWER_MAX);	/* (upload links) */
			free(s.a.body);
		}
	}
	for (dev = 0; dev < 2; dev++)
		if (d[dev]) {
			free(d[dev]->known);
			free(d[dev]->f);
			free(d[dev]);
		}
	return res;
}
