#ifndef C2_SYSINFO_H
#define C2_SYSINFO_H

/*
 * sysinfo.h — host facts for the Emp3r0rAgent check-in body.
 *
 * Mirrors the Go agent's agentutils.GatherSystemDetails: OS/arch/kernel,
 * identity, process, user/groups, uptime, IPs, memfs listing and the transport
 * label. The agent calls c2_gather_agent_info once before check-in.
 *
 * Everything is best-effort: an unavailable fact is reported as "N/A" (or left
 * unset) rather than failing the check-in. Only PublicKey is required by the
 * server, and c2_session_checkin fills it from the session identity.
 */

#include "common.h"
#include "memfile.h"
#include "messages.h"
#include "transport.h"

/* Backing storage for every string and list the info borrows. One instance is
 * used per check-in and must outlive the c2_agent_info. */
#define C2_SYSINFO_STRBUF 16384u
#define C2_SYSINFO_ITEMS_MAX 192u

typedef struct {
  char buf[C2_SYSINFO_STRBUF];
  size_t buf_len;
  c2_str items[C2_SYSINFO_ITEMS_MAX];
  size_t items_len;
} c2_sysinfo_store;

/*
 * Fill `info` with host facts. `version` is the build version to report (may be
 * NULL). `mem` may be NULL to report an empty file list. `store` backs every
 * string/list and must outlive `info`. Returns C2_OK.
 */
c2_status c2_gather_agent_info(c2_agent_info *info, const c2_agent_config *cfg,
                               const c2_memfile *mem, const char *version,
                               c2_sysinfo_store *store);

#endif /* C2_SYSINFO_H */
