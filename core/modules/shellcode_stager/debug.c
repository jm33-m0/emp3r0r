#ifdef DEBUG
#include "utils.h"
#include <stdarg.h>

static void put_char(char c) { write(1, &c, 1); }

static void put_str(const char *s) {
  if (!s) {
    s = "(null)";
  }
  while (*s) {
    put_char(*s++);
  }
}

/* Recursive unsigned number printer for any base up to 16 */
static void put_uint(unsigned long n, unsigned long base) {
  if (n >= base) {
    put_uint(n / base, base);
  }
  unsigned long rem = n % base;
  if (rem < 10) {
    put_char(rem + '0');
  } else {
    put_char(rem - 10 + 'a');
  }
}

static void put_int(int n) {
  unsigned int num = n;
  if (n < 0) {
    put_char('-');
    num = -num;
  }
  put_uint(num, 10);
}

void debug_print(const char *format, ...) {
  va_list args;
  va_start(args, format);

  while (*format) {
    if (*format == '%' && *(format + 1) != '\0') {
      format++; /* Move past the percent sign */

      if (*format == 'c') {
        char c = (char)va_arg(args, int);
        put_char(c);
      } else if (*format == 's') {
        char *s = va_arg(args, char *);
        put_str(s);
      } else if (*format == 'd' || *format == 'i') {
        int d = va_arg(args, int);
        put_int(d);
      } else if (*format == 'x') {
        unsigned int x = va_arg(args, unsigned int);
        put_uint(x, 16);
      } else if (*format == 'p') {
        unsigned long p = va_arg(args, unsigned long);
        put_str("0x");
        put_uint(p, 16);
      } else if (*format == '%') {
        put_char('%');
      } else {
        /* Print unrecognized specifiers literally */
        put_char('%');
        put_char(*format);
      }
    } else {
      put_char(*format);
    }
    format++;
  }
  va_end(args);
}

void perror(const char *s) { debug_print("Error: %s\n", s); }
#endif
