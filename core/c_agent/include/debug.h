#ifndef C2_DEBUG_H
#define C2_DEBUG_H

/*
 * debug.h — the DEBUG compile-time logging switch.
 *
 * In a release build every debug call compiles to nothing, so no format
 * strings from the debugging layer survive into a shipped artifact.
 */

#ifdef DEBUG
void debug_print(const char *format, ...);
void perror(const char *s);
#else
#define debug_print(...)                                                       \
  do {                                                                         \
  } while (0)
#define perror(s)                                                              \
  do {                                                                         \
  } while (0)
#endif

#endif /* C2_DEBUG_H */
