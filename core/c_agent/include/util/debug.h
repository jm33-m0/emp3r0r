#ifndef UTIL_DEBUG_H
#define UTIL_DEBUG_H

/*
 * debug.h — the DEBUG compile-time logging switch.
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

#endif /* UTIL_DEBUG_H */
