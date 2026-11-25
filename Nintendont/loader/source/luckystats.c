/* SlippWii: finished games to the player's Lucky Stats account (luckystats.h).
 *
 * The work is in luckystats/ls_core.c and ls_http.c (which tools/test_luckystats.py tests on a PC); this
 * file is the Wii's part: the drives (FatFs), the clock and the screen. The sockets are the updater's
 * (update.c). It runs in the loader, before the game list, never with a game: the network and the
 * drives are the loader's own then, and the kernel closed every file it wrote when the last game ended.
 *
 *	/slippwii/luckystats.txt	the player's key ("key=l7u_..."), on the card SlippWii is on
 *	/slippwii/luckystats_sent.txt	what was sent, on each drive (ls_core.c)
 */
#include <gccore.h>
#include <network.h>
#include <ogc/lwp_watchdog.h>
#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "global.h"
#include "font.h"
#include "FPad.h"
#include "menu.h"
#include "ff_utf8.h"
#include "diskio.h"
#include "update.h"
#include "luckystats.h"
#include "luckystats/ls_core.h"
#include "update/upd_core.h"

#define KEY_FILE "luckystats.txt"
#define SENT_FILE "luckystats_sent.txt"

extern FATFS *devices[2];
extern u32 Shutdown;	/* menu.c */

static const char *const dev_name[2] = { "sd", "usb" };
static u32 start_time;
static s64 start_ticks;

/* ---- the screen ---- */

static char line1[64];
static int cancelled;

static void draw(const char *text, u32 color, const char *text2, const char *btn_a, const char *btn_b)
{
	PrintBuildInfo();
	PrintButtonActions(NULL, btn_a, btn_b, NULL);
	PrintFormat(DEFAULT_SIZE, DARK_BLUE, MENU_POS_X, MENU_POS_Y + 20 * 3 + 10, "Lucky Stats");
	PrintFormat(DEFAULT_SIZE, color, MENU_POS_X, MENU_POS_Y + 20 * 5, "%s", text);
	if (text2)
		PrintFormat(DEFAULT_SIZE, BLACK, MENU_POS_X, MENU_POS_Y + 20 * 6, "%s", text2);
	GRRLIB_Render();
	ClearScreen();
}

int ls_plat_cancelled(void)
{
	if (Shutdown)
		LoaderShutdown();
	FPAD_Update();
	if (FPAD_Cancel(0))
		cancelled = 1;
	return cancelled;
}

int ls_plat_wait(uint32_t ms)
{
	s64 t = gettime();
	while (ticks_to_millisecs(diff_ticks(t, gettime())) < ms) {
		if (ls_plat_cancelled())
			return LS_CANCEL;
		usleep(20 * 1000);
	}
	return LS_OK;
}

void ls_plat_progress(const char *what, uint32_t done, uint32_t total)
{
	static s64 drawn;
	char text[80];
	if (what)
		snprintf(line1, sizeof(line1), "%s", what);
	else if (done != total && ticks_to_millisecs(diff_ticks(drawn, gettime())) < 200)
		return;
	drawn = gettime();
	if (total && done)
		snprintf(text, sizeof(text), "%s  %u%%", line1, (unsigned)(done * 100ull / total));
	else
		snprintf(text, sizeof(text), "%s", line1);
	draw(text, BLACK, "Skip: they are sent the next time SlippWii starts.", NULL, "Skip");
}

/* Said for a few seconds, or until a button. */
static void tell(u32 color, const char *text, const char *text2)
{
	s64 t = gettime();
	draw(text, color, text2, "OK", NULL);
	while (ticks_to_millisecs(diff_ticks(t, gettime())) < 6000) {
		VIDEO_WaitVSync();
		FPAD_Update();
		if (Shutdown)
			LoaderShutdown();
		if (FPAD_OK(0) || FPAD_Cancel(0))
			break;
	}
}

/* ---- the clock and the network ---- */

uint32_t ls_plat_time(void)
{
	return start_time + (u32)ticks_to_secs(diff_ticks(start_ticks, gettime()));
}

int ls_plat_network(void)
{
	ls_plat_progress("Connecting to the network", 0, 0);
	if (SlippWii_NetworkStart(ls_plat_cancelled) >= 0)
		return LS_OK;
	return cancelled ? LS_CANCEL : LS_NET;
}

/* ---- the drives ---- */

static void path_of(char *out, size_t size, int dev, const char *rel)
{
	snprintf(out, size, "%s:/slippwii/%s", dev_name[dev], rel);
}

static FIL game;

void *ls_plat_open(int dev, const char *name, uint32_t *size)
{
	char path[96];
	snprintf(path, sizeof(path), "%s:/Slippi/%s", dev_name[dev], name);
	if (f_open_char(&game, path, FA_READ | FA_OPEN_EXISTING) != FR_OK)
		return NULL;
	*size = f_size(&game) > 0xFFFFFFFFu ? 0xFFFFFFFFu : (u32)f_size(&game);
	return &game;
}

int ls_plat_read(void *f, uint8_t *buf, int len)
{
	UINT got = 0;
	return f_read(f, buf, (UINT)len, &got) == FR_OK ? (int)got : -1;
}

void ls_plat_close(void *f)
{
	f_close(f);
}

int ls_plat_list(int dev, LsFound found, void *arg)
{
	static FILINFO info;
	char path[16], name[LS_NAME_MAX];
	FRESULT res;
	DIR dir;
	int i;

	snprintf(path, sizeof(path), "%s:/Slippi", dev_name[dev]);
	res = f_opendir_char(&dir, path);
	if (res == FR_NO_PATH || res == FR_NO_FILE)
		return 0;
	if (res != FR_OK)
		return -1;
	while ((res = f_readdir(&dir, &info)) == FR_OK && info.fname[0]) {
		if ((info.fattrib & AM_DIR) || info.fsize > LS_FILE_MAX)
			continue;
		for (i = 0; i < LS_NAME_MAX - 1 && info.fname[i]; i++)
			name[i] = info.fname[i] < 0x80 ? (char)info.fname[i] : '?';
		name[i] = 0;
		if (!info.fname[i])
			found(arg, name, (u32)info.fsize);
	}
	f_closedir(&dir);
	return res == FR_OK ? 0 : -1;
}

static int load(int dev, const char *rel, char **text, uint32_t *len)
{
	char path[96];
	UINT got = 0;
	FRESULT res;
	FIL f;

	path_of(path, sizeof(path), dev, rel);
	res = f_open_char(&f, path, FA_READ | FA_OPEN_EXISTING);
	if (res == FR_NO_FILE || res == FR_NO_PATH)
		return 1;
	if (res != FR_OK)
		return -1;
	*len = (u32)f_size(&f);
	*text = upd_plat_alloc(*len + 1);
	if (*text)
		res = f_read(&f, *text, *len, &got);
	f_close(&f);
	if (!*text || res != FR_OK || got != *len) {
		upd_plat_free(*text);
		return -1;
	}
	(*text)[*len] = 0;
	return 0;
}

int ls_plat_state_load(int dev, char **text, uint32_t *len)
{
	return load(dev, SENT_FILE, text, len);
}

static int write_text(const char *path, const char *text, uint32_t len, BYTE mode)
{
	UINT wrote = 0;
	FRESULT res;
	FIL f;
	if (f_open_char(&f, path, mode) != FR_OK)
		return -1;
	res = mode & FA_CREATE_ALWAYS ? FR_OK : f_lseek(&f, f_size(&f));
	if (res == FR_OK)
		res = f_write(&f, text, len, &wrote);
	/* (f_close writes the file's entry, and the disk cache out to the drive: diskio.c, CTRL_SYNC) */
	if (f_close(&f) != FR_OK || res != FR_OK || wrote != len)
		return -1;
	return 0;
}

int ls_plat_state_append(int dev, const char *text, uint32_t len)
{
	char path[96];
	path_of(path, sizeof(path), dev, SENT_FILE);
	return write_text(path, text, len, FA_WRITE | FA_OPEN_EXISTING);
}

int ls_plat_state_create(int dev, const char *text, uint32_t len)
{
	char path[96], name[96];
	WCHAR from[96], to[96];
	unsigned i;
	snprintf(path, sizeof(path), "%s:/slippwii", dev_name[dev]);
	f_mkdir_char(path);	/* (there already, most times) */
	path_of(name, sizeof(name), dev, SENT_FILE);
	path_of(path, sizeof(path), dev, SENT_FILE ".new");
	if (write_text(path, text, len, FA_WRITE | FA_CREATE_ALWAYS) < 0)
		return -1;
	for (i = 0; i < 96; i++) {
		from[i] = (unsigned char)path[i];
		to[i] = (unsigned char)name[i];
	}
	if (f_rename(from, to) != FR_OK)
		return -1;
	return disk_flush(dev == 0 ? DEV_SD : DEV_USB) == RES_OK ? 0 : -1;
}

/* ---- the entry ---- */

void LuckyStats_Run(u32 now)
{
	int home = devices[DEV_SD] ? 0 : 1, res, sent = 0;
	LsConfig config;
	uint32_t len = 0;
	char *text = NULL, said[64], date[64];
	time_t t = (time_t)now;
	struct tm tm;

	if (load(home, KEY_FILE, &text, &len) != 0)
		return;		/* no key: off */
	start_time = now;
	start_ticks = gettime();
	cancelled = 0;
	res = ls_config(text, len, &config);
	memset(text, 0, len);
	upd_plat_free(text);
	if (res == LS_OK)
		res = ls_run(&config, (devices[DEV_SD] ? 1 : 0) | (devices[DEV_USB] ? 2 : 0), home, &sent);
	memset(&config, 0, sizeof(config));
	if (net_get_status() == -EBUSY)
		net_deinit();	/* (skipped while it connected: not left running) */

	snprintf(said, sizeof(said), "%d new game%s sent to Lucky Stats.", sent, sent == 1 ? "" : "s");
	switch (res) {
	case LS_OK:
		if (sent)
			tell(BLACK, said, NULL);
		break;
	case LS_BAD_KEY_FILE:
		tell(MAROON, "slippwii/" KEY_FILE " has no upload key.", "It needs a line: key=l7u_... (from luckystats.gg/account)");
		break;
	case LS_CARD:
		tell(MAROON, "A drive could not be read or written. Nothing was lost.", NULL);
		break;
	case LS_NET:
		tell(MAROON, "No connection to Lucky Stats.", "Your games are kept and sent another time.");
		break;
	case LS_CLOCK:
		localtime_r(&t, &tm);
		snprintf(date, sizeof(date), "This Wii's date is %04d-%02d-%02d (Wii Settings > Calendar).", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday);
		tell(MAROON, "The connection was not trusted: is the date right?", date);
		break;
	case LS_CERT:
		tell(MAROON, "The connection was not trusted. Nothing was sent.", "If it stays like this, SlippWii needs an update.");
		break;
	case LS_KEY:
		tell(MAROON, "Lucky Stats did not accept the upload key.", "Make a new one at luckystats.gg/account.");
		break;
	case LS_PREMIUM:
		tell(MAROON, "This Lucky Stats account cannot upload games.", "Uploads need Premium.");
		break;
	case LS_QUOTA:
		tell(MAROON, "Your Lucky Stats storage is full.", NULL);
		break;
	case LS_BUSY:
	case LS_SERVER:
		tell(MAROON, "Lucky Stats could not take the games now.", "They are kept and sent another time.");
		break;
	default:
		break;		/* (skipped, or too soon after a failure) */
	}
	ClearScreen();
}
