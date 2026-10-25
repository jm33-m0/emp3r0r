#ifndef C2_AGENT_ARGS_H
#define C2_AGENT_ARGS_H

/*
 * agent_args.h — parsing helpers shared by the reference agent's command
 * handlers and their fuzz/test harnesses.
 *
 * The command slice arrives over the wire, so every helper treats its items as
 * untrusted lengths and always NUL-terminates the destination. Every helper
 * requires cap >= 1.
 */

#include "messages.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Resolve the path argument of a filesystem command the way the Go agent's
 * cobra flags do: --dst/-d (or --path/-p), else the first positional argument,
 * else `def` (NULL means "empty"). `cap` must be at least 1.
 */
void c2_cmd_pick_path(const c2_str_list *cmd, size_t start, const char *def,
                      char *out, size_t cap);

/* Copy command argument `n` (1-based, after the command name). */
void c2_cmd_argn(const c2_str_list *cmd, size_t n, char *out, size_t cap);

/* Copy the value of `--name value` or `--name=value`, or "". */
void c2_cmd_pick_flag(const c2_str_list *cmd, const char *name, char *out,
                      size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* C2_AGENT_ARGS_H */
