/* loader/tests/luckystats/ls_test.c
 * The Lucky Stats upload (loader/source/luckystats/) as a PC program; tools/test_luckystats.py drives it.
 * The drives are folders ("sd" and "usb" in ROOT), the servers are on this PC.
 *
 *	ls_test config FILE				the key file's result, key and history
 *	ls_test run ROOT DEVS NOW PORT DN KEYHEX HISTORY	a start of SlippWii: the result and the games sent
 *	ls_test chain HOST NOW LIST DER...		BearSSL's error for that chain, against the roots compiled in
 *
 * DN and KEYHEX are the test authority's name (DER) and P-256 point. In the environment: LS_DIE=N: the
 * process ends, as at a power cut, in the Nth write of what was sent, half of it written; LS_CANCEL=N: the
 * player presses B at the Nth look; LS_FAIL_APPEND=1: the drive takes no writes; LS_RESOLVE=0: no network.
 */
#include "ls_core.h"
#include "upd_core.h"
#include "bearssl.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern br_x509_trust_anchor ls_test_root;
extern int ls_test_root_set;
uint16_t ls_test_port;

#include "ls_roots.inc"

static const char *root;
static uint32_t now;

/* (upd_core.h's platform, as on a Wii but for sockets: both servers are 127.0.0.1) */
int upd_plat_connect(const char *host, uint16_t port)
{
	struct sockaddr_in a;
	struct timeval t = { 20, 0 };
	int s;
	(void)host;
	s = socket(AF_INET, SOCK_STREAM, 0);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons(port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
		close(s);
		return -4;
	}
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
	return s;
}

int upd_plat_recv(int s, uint8_t *buf, int len) { return (int)recv(s, buf, (size_t)len, 0); }
#ifdef MSG_NOSIGNAL
int upd_plat_send(int s, const uint8_t *buf, int len) { return (int)send(s, buf, (size_t)len, MSG_NOSIGNAL); }
#else
int upd_plat_send(int s, const uint8_t *buf, int len) { return (int)send(s, buf, (size_t)len, 0); }
#endif
void upd_plat_close(int s) { close(s); }
int ls_plat_send(int s, const uint8_t *buf, int len) { return upd_plat_send(s, buf, len); }
int ls_plat_recv(int s, uint8_t *buf, int len) { return upd_plat_recv(s, buf, len); }
void upd_plat_entropy(uint8_t out[32]) { memset(out, 7, 32); }	/* (the worst a Wii could give) */
void *upd_plat_alloc(uint32_t size) { return malloc(size ? size : 1); }
void upd_plat_free(void *p) { free(p); }

uint32_t ls_plat_time(void) { return now; }
int ls_plat_network(void) { return getenv("LS_RESOLVE") ? LS_NET : LS_OK; }

int ls_plat_cancelled(void)
{
	static int looks;
	const char *v = getenv("LS_CANCEL");
	return v && ++looks >= atoi(v);
}

int ls_plat_wait(uint32_t ms) { printf("wait %u\n", (unsigned)ms); return ls_plat_cancelled() ? LS_CANCEL : LS_OK; }
void ls_plat_progress(const char *what, uint32_t done, uint32_t total)
{
	(void)done;
	(void)total;
	if (what)
		printf("%s\n", what);
}

static void path_of(char *out, size_t size, int dev, const char *rel)
{
	snprintf(out, size, "%s/%s/%s", root, dev ? "usb" : "sd", rel);
}

int ls_plat_list(int dev, LsFound found, void *arg)
{
	char path[600], file[1200];
	struct dirent *e;
	struct stat st;
	DIR *d;
	path_of(path, sizeof(path), dev, "Slippi");
	d = opendir(path);
	if (!d)
		return 0;
	while ((e = readdir(d))) {
		snprintf(file, sizeof(file), "%s/%s", path, e->d_name);
		if (stat(file, &st) == 0 && S_ISREG(st.st_mode))
			found(arg, e->d_name, (uint32_t)st.st_size);
	}
	closedir(d);
	return 0;
}

void *ls_plat_open(int dev, const char *name, uint32_t *size)
{
	char path[600], rel[200];
	struct stat st;
	FILE *f;
	snprintf(rel, sizeof(rel), "Slippi/%s", name);
	path_of(path, sizeof(path), dev, rel);
	f = fopen(path, "rb");
	if (f && fstat(fileno(f), &st) == 0)
		*size = (uint32_t)st.st_size;
	return f;
}

int ls_plat_read(void *f, uint8_t *buf, int len) { return (int)fread(buf, 1, (size_t)len, f); }
void ls_plat_close(void *f) { fclose(f); }

static int load(const char *path, char **text, uint32_t *len)
{
	FILE *f = fopen(path, "rb");
	long n;
	if (!f)
		return 1;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	*text = malloc((size_t)n + 1);
	*len = (uint32_t)fread(*text, 1, (size_t)n, f);
	(*text)[*len] = 0;
	fclose(f);
	return 0;
}

int ls_plat_state_load(int dev, char **text, uint32_t *len)
{
	char path[600];
	path_of(path, sizeof(path), dev, "slippwii/luckystats_sent.txt");
	return load(path, text, len);
}

static int put(const char *path, const char *mode, const char *text, uint32_t len)
{
	static int writes;
	const char *die = getenv("LS_DIE");
	int dies = die && ++writes == atoi(die);
	FILE *f;
	if (getenv("LS_FAIL_APPEND"))
		return -1;
	f = fopen(path, mode);
	if (!f)
		return -1;
	fwrite(text, 1, dies ? len / 2 : len, f);
	fclose(f);
	if (dies)
		_exit(9);
	return 0;
}

int ls_plat_state_create(int dev, const char *text, uint32_t len)
{
	char path[600], name[600];
	path_of(path, sizeof(path), dev, "slippwii");
	mkdir(path, 0777);
	path_of(name, sizeof(name), dev, "slippwii/luckystats_sent.txt");
	path_of(path, sizeof(path), dev, "slippwii/luckystats_sent.txt.new");
	return put(path, "wb", text, len) == 0 && rename(path, name) == 0 ? 0 : -1;
}

int ls_plat_state_append(int dev, const char *text, uint32_t len)
{
	char path[600];
	path_of(path, sizeof(path), dev, "slippwii/luckystats_sent.txt");
	return put(path, "ab", text, len);
}

static int unhex(const char *s, uint8_t *out, int max)
{
	unsigned v;
	int n = 0;
	for (; s[0] && s[1] && n < max; s += 2) {
		sscanf(s, "%2x", &v);
		out[n++] = (uint8_t)v;
	}
	return n;
}

static int chain(int argc, char **argv)
{
	int storage = strcmp(argv[4], "storage") == 0, i;
	uint32_t t = (uint32_t)strtoul(argv[3], NULL, 10);
	static br_x509_minimal_context xc;
	static br_ssl_client_context sc;
	unsigned e;
	br_ssl_client_init_full(&sc, &xc, storage ? ls_storage_roots : ls_site_roots, storage ?
		sizeof(ls_storage_roots) / sizeof(ls_storage_roots[0]) : sizeof(ls_site_roots) / sizeof(ls_site_roots[0]));
	br_x509_minimal_set_time(&xc, t / 86400 + 719528, t % 86400);
	xc.vtable->start_chain(&xc.vtable, argv[2]);
	for (i = 5; i < argc; i++) {
		char *der;
		uint32_t len;
		if (load(argv[i], &der, &len) != 0)
			return 2;
		xc.vtable->start_cert(&xc.vtable, len);
		xc.vtable->append(&xc.vtable, (unsigned char *)der, len);
		xc.vtable->end_cert(&xc.vtable);
		free(der);
	}
	e = xc.vtable->end_chain(&xc.vtable);
	printf("%u\n", e);
	return 0;
}

int main(int argc, char **argv)
{
	LsConfig c;
	char *text;
	uint32_t len;
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc == 3 && strcmp(argv[1], "config") == 0) {
		if (load(argv[2], &text, &len) != 0)
			return 2;
		len = (uint32_t)ls_config(text, len, &c);
		printf("%u %s %d\n", (unsigned)len, c.key, c.history);
		return 0;
	}
	if (argc >= 6 && strcmp(argv[1], "chain") == 0)
		return chain(argc, argv);
	if (argc == 9 && strcmp(argv[1], "run") == 0) {
		static uint8_t dn[256], q[65];
		int sent = 0, devs = atoi(argv[3]);
		uint32_t later = 0;
		root = argv[2];
		now = (uint32_t)strtoul(argv[4], NULL, 10);
		ls_test_port = (uint16_t)atoi(argv[5]);
		ls_test_root.dn.data = dn;
		ls_test_root.dn.len = (size_t)unhex(argv[6], dn, sizeof(dn));
		ls_test_root.flags = BR_X509_TA_CA;
		ls_test_root.pkey.key_type = BR_KEYTYPE_EC;
		ls_test_root.pkey.key.ec.curve = BR_EC_secp256r1;
		ls_test_root.pkey.key.ec.q = q;
		ls_test_root.pkey.key.ec.qlen = (size_t)unhex(argv[7], q, sizeof(q));
		ls_test_root_set = 1;
		memset(&c, 0, sizeof(c));
		sprintf(c.key, "l7u_%064d", 5);
		c.history = atoi(argv[8]);
		len = (uint32_t)ls_run(&c, devs, devs & 1 ? 0 : 1, &sent, &later);
		printf("RESULT %u %d\nLATER %u\n", (unsigned)len, sent, (unsigned)later);
		return 0;
	}
	return 2;
}
