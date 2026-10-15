/*
 * dynload_hosted.c — process-wide dynload context for hosted binaries.
 *
 * This is the only piece of the dynload layer with a writable global, so it is
 * compiled into hosted agents but never into a freestanding (-nostdlib)
 * payload. First use is not thread-safe; call dynload_hosted() once during
 * single-threaded startup (or protect it with the caller's own lock).
 */

#include "util/dynload.h"

static dynload g_hosted;

dynload *dynload_hosted(void) { return &g_hosted; }
