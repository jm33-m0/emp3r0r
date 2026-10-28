/*
 * test_sysinfo.c — c2_gather_agent_info must report the same identity
 * fields the Go agent's GatherSystemDetails does, so the C2 (and BOF dispatch)
 * sees a Linux target with a full system profile.
 */

#include "sysinfo.h"

#include "cbor.h"

#include "test.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int str_eq(c2_str s, const char *lit) {
  size_t n = strlen(lit);
  return s.ptr != NULL && s.len == n && memcmp(s.ptr, lit, n) == 0;
}

static int str_has(c2_str s, const char *lit) {
  size_t n = strlen(lit);
  if (s.ptr == NULL || s.len < n)
    return 0;
  for (size_t i = 0; i + n <= s.len; i++)
    if (memcmp(s.ptr + i, lit, n) == 0)
      return 1;
  return 0;
}

int main(void) {
  c2_agent_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.cc_address = c2_str_lit("127.0.0.1:8080");
  cfg.agent_uuid = c2_str_lit("11111111-1111-1111-1111-111111111111");
  cfg.agent_uuid_sig = c2_bytes_of("sig", 3);
  cfg.agent_tag = c2_str_lit("deadbeef");
  cfg.c2_channel_mode = c2_str_lit("http_poll");

  c2_agent_info info;
  c2_sysinfo_store store;
  CHECK_EQ_LONG(c2_gather_agent_info(&info, &cfg, NULL, "9.9.9", &store),
                C2_OK);

  /* The fields module selection and operator display depend on. */
  CHECK(str_eq(info.goos, "linux"));
  CHECK(info.goarch.ptr != NULL && info.goarch.len > 0);
  CHECK(info.os.ptr != NULL && info.os.len > 0);
  CHECK(info.kernel.ptr != NULL && info.kernel.len > 0);
  CHECK(info.hostname.ptr != NULL && info.hostname.len > 0);
  CHECK(info.name.ptr != NULL && info.name.len > 0);
  CHECK(info.user.ptr != NULL && str_has(info.user, "uid="));
  /* getgroups() gives only supplementary groups and is empty in a minimal
   * container; the primary GID must still be reported, like Go's GroupIds. */
  CHECK(info.groups.ptr != NULL && info.groups.len > 0);
  {
    char primary_gid[32];
    snprintf(primary_gid, sizeof(primary_gid), "%u", (unsigned)getgid());
    CHECK(str_has(info.groups, primary_gid));
  }
  CHECK(info.uptime.ptr != NULL && info.uptime.len > 0);
  CHECK(info.cwd.ptr != NULL && info.cwd.len > 0);
  CHECK(str_eq(info.version, "9.9.9"));
  CHECK(str_eq(info.mesh_route, "direct"));
  CHECK(str_has(info.transport, "HTTP (127.0.0.1:8080)"));
  CHECK(info.hardware.ptr != NULL && str_eq(info.hardware, "N/A"));
  CHECK(info.cpu.ptr != NULL && str_eq(info.cpu, "N/A"));

  /* A custom transport reports its configured name, not an HTTP label. */
  {
    c2_agent_config custom = cfg;
    custom.c2_channel_mode = c2_str_lit("tor");
    c2_agent_info custom_info;
    c2_sysinfo_store custom_store;
    CHECK_EQ_LONG(c2_gather_agent_info(&custom_info, &custom, NULL, "9.9.9",
                                       &custom_store),
                  C2_OK);
    CHECK(str_has(custom_info.transport, "tor (127.0.0.1:8080)"));
  }

  CHECK(info.has_root == 1);
  CHECK(info.process.has_pid && info.process.pid > 0);
  CHECK(info.process.cmdline.ptr != NULL && info.process.cmdline.len > 0);
  CHECK(info.ips.count > 0);
  CHECK(info.ips.items[0].len > 0);

  /* The gathered body must encode as a well-formed Emp3r0rAgent. */
  uint8_t buf[16384];
  CborEncoder enc;
  cbor_encoder_init(&enc, buf, sizeof(buf), 0);
  CHECK_EQ_LONG(c2_agent_info_encode(&enc, &info), C2_OK);
  CHECK(cbor_encoder_get_buffer_size(&enc, buf) > 0);

  TEST_DONE();
}
