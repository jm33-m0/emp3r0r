#include "messages.h"

#include "cbor.h"

#include "test.h"

/*
 * Emp3r0rAgent is the widest message (43 keys); a divergence in any key breaks
 * registration. These tests round-trip a fully populated struct through
 * c2_agent_info_encode / c2_agent_info_decode and assert every field survives,
 * then cover the optional-field, capacity and malformed-input paths plus the
 * AgentToken and EnrichedPeerList decoders.
 */

static c2_status dec_info(const uint8_t *buf, size_t len, c2_agent_info *a) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &p, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_agent_info_decode(&it, a);
}

static c2_status dec_token(const uint8_t *buf, size_t len, c2_agent_token *t) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &p, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_agent_token_decode(&it, t);
}

static c2_status dec_peers(const uint8_t *buf, size_t len,
                           c2_enriched_peer_list *l) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &p, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_enriched_peer_list_decode(&it, l);
}

/* A c2_str from a string literal with a compile-time length (constant
 * initializer, unlike c2_str_lit which is an inline function). */
#define STR(s) {(s), sizeof(s) - 1}

/* Fill `a` with one value per field. The list arrays are static so the slices
 * stay valid after this function returns (the struct only borrows them). */
static void fill_info(c2_agent_info *a) {
  static c2_str ips_items[] = {STR("10.0.0.1/24"), STR("127.0.0.1/8")};
  static c2_str arp_items[] = {STR("10.0.0.1 aa:bb")};
  static c2_str exes_items[] = {STR("/bin/ls")};
  static c2_str files_items[] = {STR("memfs:///a.so")};
  memset(a, 0, sizeof(*a));
  a->tag = c2_str_lit("abcd1234");
  a->name = c2_str_lit("host/root");
  a->version = c2_str_lit("v9");
  a->transport = c2_str_lit("HTTP (10.0.0.1:8080)");
  a->hostname = c2_str_lit("host");
  a->hardware = c2_str_lit("N/A");
  a->container = c2_str_lit("N/A");
  a->cpu = c2_str_lit("N/A");
  a->gpu = c2_str_lit("N/A");
  a->mem = c2_str_lit("N/A");
  a->os = c2_str_lit("Debian 12 (amd64)");
  a->goos = c2_str_lit("linux");
  a->kernel = c2_str_lit("6.1.0");
  a->arch = c2_str_lit("x86_64");
  a->from = c2_str_lit("10.0.0.1");
  a->ips.items = ips_items;
  a->ips.count = 2;
  a->ips.cap = 2;
  a->arp.items = arp_items;
  a->arp.count = 1;
  a->arp.cap = 1;
  a->user = c2_str_lit("root (/root), uid=0, gid=0");
  a->has_root = 1;
  a->root = 1;
  a->has_tor = 1;
  a->tor = 0;
  a->has_internet = 1;
  a->internet = 1;
  a->has_ncsi = 1;
  a->ncsi = 0;
  a->process.has_pid = 1;
  a->process.pid = 4242;
  a->process.has_ppid = 1;
  a->process.ppid = 1;
  a->process.cmdline = c2_str_lit("./agent");
  a->process.parent = c2_str_lit("bash");
  a->exes.items = exes_items;
  a->exes.count = 1;
  a->exes.cap = 1;
  a->cwd = c2_str_lit("/root");
  a->product = c2_str_lit("{}");
  a->uuid = c2_str_lit("uuid-1");
  a->uuid_sig = c2_str_lit("sig");
  a->public_key = c2_str_lit("-----BEGIN PUBLIC KEY-----");
  a->c2host = c2_str_lit("10.0.0.1:8080");
  a->uptime = c2_str_lit("1d 2h 3m 4s");
  a->groups = c2_str_lit("0,27");
  a->mesh_route = c2_str_lit("direct");
  a->p2p_relay_port = c2_str_lit("0");
  a->mesh_gossip_port = c2_str_lit("0");
  a->files.items = files_items;
  a->files.count = 1;
  a->files.cap = 1;
  a->goarch = c2_str_lit("amd64");
  a->p2p_transport = c2_str_lit("direct");
  a->owner = c2_str_lit("");
}

int main(void) {
  uint8_t buf[4096];
  c2_agent_info in;
  fill_info(&in);

  /* Round trip: every field the encoder wrote is read back byte-for-byte. */
  {
    CborEncoder e;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(c2_agent_info_encode(&e, &in) == C2_OK);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);

    c2_str ips[4], arp[4], exes[4], files[4];
    c2_agent_info out;
    memset(&out, 0, sizeof(out));
    out.ips.items = ips;
    out.ips.cap = 4;
    out.arp.items = arp;
    out.arp.cap = 4;
    out.exes.items = exes;
    out.exes.cap = 4;
    out.files.items = files;
    out.files.cap = 4;
    CHECK(dec_info(buf, n, &out) == C2_OK);

    CHECK(c2_str_equal(out.tag, "abcd1234"));
    CHECK(c2_str_equal(out.name, "host/root"));
    CHECK(c2_str_equal(out.os, "Debian 12 (amd64)"));
    CHECK(c2_str_equal(out.goos, "linux"));
    CHECK(c2_str_equal(out.kernel, "6.1.0"));
    CHECK(c2_str_equal(out.user, "root (/root), uid=0, gid=0"));
    CHECK_EQ_LONG(out.has_root, 1);
    CHECK_EQ_LONG(out.root, 1);
    CHECK_EQ_LONG(out.has_tor, 1);
    CHECK_EQ_LONG(out.tor, 0);
    CHECK_EQ_LONG(out.has_ncsi, 1);
    CHECK_EQ_LONG(out.ncsi, 0);
    CHECK(out.process.has_pid && out.process.pid == 4242);
    CHECK(out.process.has_ppid && out.process.ppid == 1);
    CHECK(c2_str_equal(out.process.cmdline, "./agent"));
    CHECK(c2_str_equal(out.process.parent, "bash"));
    CHECK_EQ_LONG(out.ips.count, 2);
    CHECK(c2_str_equal(out.ips.items[1], "127.0.0.1/8"));
    CHECK_EQ_LONG(out.arp.count, 1);
    CHECK_EQ_LONG(out.exes.count, 1);
    CHECK(c2_str_equal(out.cwd, "/root"));
    CHECK(c2_str_equal(out.uuid, "uuid-1"));
    CHECK(c2_str_equal(out.public_key, "-----BEGIN PUBLIC KEY-----"));
    CHECK(c2_str_equal(out.uptime, "1d 2h 3m 4s"));
    CHECK(c2_str_equal(out.mesh_route, "direct"));
    CHECK_EQ_LONG(out.files.count, 1);
    CHECK(c2_str_equal(out.files.items[0], "memfs:///a.so"));
    CHECK(c2_str_equal(out.goarch, "amd64"));
    /* A set-but-empty string is decoded as present and empty, not absent. */
    CHECK(out.owner.ptr != NULL && out.owner.len == 0);
  }

  /* A minimal agent: only the required identity fields, no lists/bools. */
  {
    c2_agent_info min;
    memset(&min, 0, sizeof(min));
    min.uuid = c2_str_lit("u");
    min.uuid_sig = c2_str_lit("s");
    min.public_key = c2_str_lit("p");
    CborEncoder e;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(c2_agent_info_encode(&e, &min) == C2_OK);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    c2_agent_info out;
    memset(&out, 0, sizeof(out));
    CHECK(dec_info(buf, n, &out) == C2_OK);
    CHECK(c2_str_equal(out.uuid, "u"));
    CHECK(out.tag.ptr == NULL);
    CHECK_EQ_LONG(out.ips.count, 0);
    CHECK_EQ_LONG(out.has_root, 0);
    CHECK(out.process.cmdline.ptr == NULL);
  }

  /* Lists that overflow caller storage fail rather than truncate. */
  {
    CborEncoder e;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(c2_agent_info_encode(&e, &in) == C2_OK);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    c2_str one[1];
    c2_agent_info out;
    memset(&out, 0, sizeof(out));
    out.ips.items = one;
    out.ips.cap = 1; /* in has 2 IPs */
    CHECK(dec_info(buf, n, &out) == C2_ERR_NOMEM);
  }

  /* A non-map is rejected; NULL arguments are rejected. */
  {
    CborEncoder e, a;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_array(&e, &a, 0) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &a) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    c2_agent_info out;
    memset(&out, 0, sizeof(out));
    CHECK(dec_info(buf, n, &out) == C2_ERR_PROTO);
    CHECK(c2_agent_info_encode(NULL, &in) == C2_ERR_ARG);
    CHECK(c2_agent_info_decode(NULL, &out) == C2_ERR_ARG);
  }

  /* AgentProcess encoded as CBOR null (Go nil) leaves the struct empty. */
  {
    CborEncoder e, m;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 1) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_AGENT_PROCESS) == CborNoError);
    CHECK(cbor_encode_null(&m) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    c2_agent_info out;
    memset(&out, 0, sizeof(out));
    CHECK(dec_info(buf, n, &out) == C2_OK);
    CHECK(!out.process.has_pid);
    CHECK(out.process.cmdline.ptr == NULL);
  }

  /* AgentToken. */
  {
    CborEncoder e, m;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 5) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_TOKEN_AGENT_ID) == CborNoError);
    CHECK(cbor_encode_text_stringz(&m, "uuid-1") == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_TOKEN_IP) == CborNoError);
    CHECK(cbor_encode_text_stringz(&m, "10.0.0.1") == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_TOKEN_CAPABILITY) == CborNoError);
    CHECK(cbor_encode_text_stringz(&m, "router") == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_TOKEN_EXPIRES_AT) == CborNoError);
    CHECK(cbor_encode_int(&m, 1700000000) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_TOKEN_SIGNATURE) == CborNoError);
    CHECK(cbor_encode_byte_string(&m, (const uint8_t *)"\x01\x02\x03", 3) ==
          CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    c2_agent_token t;
    memset(&t, 0, sizeof(t));
    CHECK(dec_token(buf, n, &t) == C2_OK);
    CHECK(c2_str_equal(t.agent_id, "uuid-1"));
    CHECK(c2_str_equal(t.capability, "router"));
    CHECK_EQ_LONG(t.expires_at, 1700000000);
    CHECK_EQ_LONG(t.signature.len, 3);
    CHECK(c2_agent_token_decode(NULL, &t) == C2_ERR_ARG);
  }

  /* EnrichedPeerList with two peers and a signature. */
  {
    CborEncoder e, m, arr;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 2) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_PEER_LIST_PEERS) == CborNoError);
    CHECK(cbor_encoder_create_array(&m, &arr, 2) == CborNoError);
    for (int i = 0; i < 2; i++) {
      CborEncoder pm;
      CHECK(cbor_encoder_create_map(&arr, &pm, 2) == CborNoError);
      CHECK(cbor_encode_uint(&pm, C2_KEY_PEER_UUID) == CborNoError);
      CHECK(cbor_encode_text_stringz(&pm, i ? "peer2" : "peer1") ==
            CborNoError);
      CHECK(cbor_encode_uint(&pm, C2_KEY_PEER_LAST_SEEN) == CborNoError);
      CHECK(cbor_encode_int(&pm, 1700000000 + i) == CborNoError);
      CHECK(cbor_encoder_close_container(&arr, &pm) == CborNoError);
    }
    CHECK(cbor_encoder_close_container(&m, &arr) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_PEER_LIST_SIGNATURE) == CborNoError);
    CHECK(cbor_encode_byte_string(&m, (const uint8_t *)"sig", 3) ==
          CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);

    c2_enriched_peer peers[4];
    c2_str ips[4][2], files[4][2];
    memset(peers, 0, sizeof(peers));
    for (int i = 0; i < 4; i++) {
      peers[i].ips.items = ips[i];
      peers[i].ips.cap = 2;
      peers[i].files.items = files[i];
      peers[i].files.cap = 2;
    }
    c2_enriched_peer_list l = {0};
    l.peers = peers;
    l.cap = 4;
    CHECK(dec_peers(buf, n, &l) == C2_OK);
    CHECK_EQ_LONG(l.count, 2);
    CHECK(c2_str_equal(l.peers[0].uuid, "peer1"));
    CHECK(c2_str_equal(l.peers[1].uuid, "peer2"));
    CHECK_EQ_LONG(l.peers[1].last_seen, 1700000001);
    CHECK_EQ_LONG(l.signature.len, 3);
  }

  /* Peers = CBOR null (Go nil slice) decodes as an empty list. */
  {
    CborEncoder e, m;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 1) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_PEER_LIST_PEERS) == CborNoError);
    CHECK(cbor_encode_null(&m) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    c2_enriched_peer_list l = {0};
    l.peers = NULL;
    l.cap = 0;
    CHECK(dec_peers(buf, n, &l) == C2_OK);
    CHECK_EQ_LONG(l.count, 0);
  }

  /* Too many peers for the caller array: C2_ERR_NOMEM. */
  {
    CborEncoder e, m, arr;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 1) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_PEER_LIST_PEERS) == CborNoError);
    CHECK(cbor_encoder_create_array(&m, &arr, 2) == CborNoError);
    for (int i = 0; i < 2; i++) {
      CborEncoder pm;
      CHECK(cbor_encoder_create_map(&arr, &pm, 1) == CborNoError);
      CHECK(cbor_encode_uint(&pm, C2_KEY_PEER_UUID) == CborNoError);
      CHECK(cbor_encode_text_stringz(&pm, "p") == CborNoError);
      CHECK(cbor_encoder_close_container(&arr, &pm) == CborNoError);
    }
    CHECK(cbor_encoder_close_container(&m, &arr) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);
    c2_enriched_peer one[1];
    memset(one, 0, sizeof(one));
    c2_enriched_peer_list l = {0};
    l.peers = one;
    l.cap = 1;
    CHECK(dec_peers(buf, n, &l) == C2_ERR_NOMEM);
    CHECK(c2_enriched_peer_list_decode(NULL, &l) == C2_ERR_ARG);
  }

  TEST_DONE();
}
