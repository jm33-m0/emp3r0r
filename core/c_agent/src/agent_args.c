/*
 * agent_args.c — command-slice parsing for the reference agent.
 *
 * These helpers are separated from agent.c so fuzz_command_args can exercise
 * them directly without linking the filesystem/network/module handlers.
 */

#include "agent_args.h"

#include <stdio.h>
#include <string.h>

void c2_cmd_pick_path(const c2_str_list *cmd, size_t start, const char *def,
                      char *out, size_t cap) {
  out[0] = '\0';
  int have_pos = 0;
  for (size_t i = start; i < cmd->count; i++) {
    c2_str a = cmd->items[i];
    if (a.ptr == NULL || a.len == 0)
      continue;
    char tok[512];
    size_t n = a.len < sizeof(tok) - 1 ? a.len : sizeof(tok) - 1;
    memcpy(tok, a.ptr, n);
    tok[n] = '\0';
    int is_path_flag = strcmp(tok, "--dst") == 0 || strcmp(tok, "-d") == 0 ||
                       strcmp(tok, "--path") == 0 || strcmp(tok, "-p") == 0;
    if (is_path_flag) {
      if (i + 1 < cmd->count) {
        c2_str v = cmd->items[++i];
        size_t vn = v.len < cap - 1 ? v.len : cap - 1;
        memcpy(out, v.ptr, vn);
        out[vn] = '\0';
      }
      continue;
    }
    if (strncmp(tok, "--dst=", 6) == 0 || strncmp(tok, "--path=", 7) == 0 ||
        strncmp(tok, "-d=", 3) == 0 || strncmp(tok, "-p=", 3) == 0) {
      const char *v = strchr(tok, '=') + 1;
      snprintf(out, cap, "%s", v);
      continue;
    }
    if (tok[0] == '-')
      continue; /* unknown flag */
    if (!have_pos) {
      snprintf(out, cap, "%s", tok);
      have_pos = 1;
    }
  }
  if (out[0] == '\0' && def != NULL)
    snprintf(out, cap, "%s", def);
}

void c2_cmd_argn(const c2_str_list *cmd, size_t n, char *out, size_t cap) {
  out[0] = '\0';
  if (cmd->count <= n || cmd->items[n].ptr == NULL)
    return;
  size_t len = cmd->items[n].len;
  if (len >= cap)
    len = cap - 1;
  memcpy(out, cmd->items[n].ptr, len);
  out[len] = '\0';
}

void c2_cmd_pick_flag(const c2_str_list *cmd, const char *name, char *out,
                      size_t cap) {
  out[0] = '\0';
  size_t nlen = strlen(name);
  for (size_t i = 0; i < cmd->count; i++) {
    c2_str a = cmd->items[i];
    if (a.ptr == NULL || a.len == 0)
      continue;
    if (a.len > nlen && memcmp(a.ptr, name, nlen) == 0 && a.ptr[nlen] == '=') {
      size_t vn = a.len - nlen - 1;
      if (vn >= cap)
        vn = cap - 1;
      memcpy(out, a.ptr + nlen + 1, vn);
      out[vn] = '\0';
      return;
    }
    if (a.len == nlen && memcmp(a.ptr, name, nlen) == 0) {
      if (i + 1 < cmd->count) {
        c2_str v = cmd->items[++i];
        size_t vn = v.len < cap - 1 ? v.len : cap - 1;
        memcpy(out, v.ptr, vn);
        out[vn] = '\0';
      }
      return;
    }
  }
}
