/*
 * maps.c — pure /proc/self/maps parser.
 *
 * Each line is "start-end perms offset dev inode [path]". Only the fields the
 * sleep mask needs are retained; path-less mappings are marked anonymous.
 */

#include "util/maps.h"

static int parse_hex(const char *s, size_t len, size_t *pos, uintptr_t *out) {
  size_t i = *pos;
  uintptr_t v = 0;
  int any = 0;
  while (i < len) {
    unsigned d;
    char c = s[i];
    if (c >= '0' && c <= '9')
      d = (unsigned)(c - '0');
    else if (c >= 'a' && c <= 'f')
      d = (unsigned)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F')
      d = (unsigned)(c - 'A' + 10);
    else
      break;
    v = (v << 4) | d;
    any = 1;
    i++;
  }
  *pos = i;
  *out = v;
  return any;
}

/* True when the line has no pathname after offset/dev/inode. */
static int line_is_anonymous(const char *line, size_t len) {
  size_t i = 0;
  while (i < len && line[i] != ' ')
    i++; /* start-end */
  while (i < len && line[i] == ' ')
    i++;
  while (i < len && line[i] != ' ')
    i++; /* perms */
  for (int field = 0; field < 3; field++) { /* offset, dev, inode */
    while (i < len && line[i] == ' ')
      i++;
    while (i < len && line[i] != ' ' && line[i] != '\n')
      i++;
  }
  while (i < len && (line[i] == ' ' || line[i] == '\t'))
    i++;
  return i >= len || line[i] == '\n' || line[i] == '\r' || line[i] == '\0';
}

size_t c2_maps_parse(const char *text, size_t len, struct c2_map *maps,
                     size_t cap) {
  if (text == NULL || maps == NULL || cap == 0)
    return 0;

  size_t n = 0;
  size_t off = 0;
  while (off < len && n < cap) {
    size_t end = off;
    while (end < len && text[end] != '\n')
      end++;

    size_t pos = off;
    uintptr_t start, finish;
    if (parse_hex(text, end, &pos, &start) && pos < end && text[pos] == '-') {
      pos++;
      if (parse_hex(text, end, &pos, &finish) && finish > start &&
          pos + 4 <= end && text[pos] == ' ') {
        char r = text[pos + 1], w = text[pos + 2], x = text[pos + 3];
        if ((r == 'r' || r == '-') && (w == 'w' || w == '-') &&
            (x == 'x' || x == '-')) {
          int prot = 0;
          if (r == 'r')
            prot |= PROT_READ;
          if (w == 'w')
            prot |= PROT_WRITE;
          if (x == 'x')
            prot |= PROT_EXEC;
          maps[n].start = start;
          maps[n].end = finish;
          maps[n].prot = prot;
          maps[n].anonymous = line_is_anonymous(text + off, end - off);
          n++;
        }
      }
    }
    off = end + 1;
  }
  return n;
}
