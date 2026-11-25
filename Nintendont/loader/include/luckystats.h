/* SlippWii: finished games to the player's Lucky Stats account (source/luckystats.c). */
#ifndef __LUCKYSTATS_H__
#define __LUCKYSTATS_H__

#include <gctypes.h>

/* When SlippWii starts, before its game list (main.c): uploads the games saved since the last time.
 * Does nothing, and nothing else of it runs, without a key in /slippwii/luckystats.txt. `now`: seconds
 * since 1970 by the console's clock (what the saved games are named by). */
void LuckyStats_Run(u32 now);

#endif
