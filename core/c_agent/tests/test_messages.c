#include "messages.h"

#include "cbor.h"

#include "test.h"

/* Authoritative vectors produced by the Go encoder (fxamacker/cbor) for the
 * exact structs the C2 marshals, so a divergence in key order or integer width
 * fails here. */
static const char kMsgauthHex[] =
    "aa0b67617574685f76310c69757569642d313233340d67644739725a57340e1a6553f100"
    "0f656e6f6e636510826663322d6d736763626f66116763484a7662325912440102030413"
    "6673747265616d1401";
static const char kMsgtunHex[] =
    "a701656a6f622d31028267216c735f646972642f746d700344deadbeef0464616263"
    "6405600844090807060af6";

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
  long n = c2_hex_decode(hex, strlen(hex), out, cap);
  return n < 0 ? 0 : (size_t)n;
}

static c2_status decode_msgauth(const uint8_t *buf, size_t len, c2_msgauth *m) {
  CborParser parser;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &parser, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_msgauth_decode(&it, m);
}

static c2_status decode_msgtun(const uint8_t *buf, size_t len, c2_msgtun *m) {
  CborParser parser;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &parser, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_msgtun_decode(&it, m);
}

int main(void) {
  uint8_t buf[512];

  /* MsgAuth: encode must be byte-identical to Go. */
  {
    uint8_t exp[256];
    size_t exp_len = unhex(kMsgauthHex, exp, sizeof(exp));
    CHECK(exp_len > 0);

    c2_str caps[2] = {c2_str_lit("c2-msg"), c2_str_lit("bof")};
    c2_msgauth m = {0};
    m.type = c2_str_lit("auth_v1");
    m.agent_uuid = c2_str_lit("uuid-1234");
    m.identity_token = c2_str_lit("dG9rZW4");
    m.timestamp = 1700000000;
    m.nonce = c2_str_lit("nonce");
    m.capabilities.items = caps;
    m.capabilities.count = 2;
    m.capabilities.cap = 2;
    m.agent_proof = c2_str_lit("cHJvb2Y");
    m.ephem_public_key = c2_bytes_of("\x01\x02\x03\x04", 4);
    m.stream_id = c2_str_lit("stream");
    m.protocol_version = 1;

    CborEncoder enc;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    CHECK(c2_msgauth_encode(&enc, &m) == C2_OK);
    size_t n = cbor_encoder_get_buffer_size(&enc, buf);
    CHECK_EQ_LONG(n, exp_len);
    CHECK(memcmp(buf, exp, exp_len) == 0);
  }

  /* MsgAuth: decode the Go vector. */
  {
    uint8_t enc[256];
    size_t enc_len = unhex(kMsgauthHex, enc, sizeof(enc));
    c2_str caps[4];
    c2_msgauth m = {0};
    m.capabilities.items = caps;
    m.capabilities.cap = 4;
    CHECK(decode_msgauth(enc, enc_len, &m) == C2_OK);
    CHECK(c2_str_equal(m.type, "auth_v1"));
    CHECK(c2_str_equal(m.agent_uuid, "uuid-1234"));
    CHECK(c2_str_equal(m.identity_token, "dG9rZW4"));
    CHECK_EQ_LONG(m.timestamp, 1700000000);
    CHECK(c2_str_equal(m.nonce, "nonce"));
    CHECK_EQ_LONG(m.capabilities.count, 2);
    CHECK(c2_str_equal(m.capabilities.items[0], "c2-msg"));
    CHECK(c2_str_equal(m.capabilities.items[1], "bof"));
    CHECK(c2_str_equal(m.agent_proof, "cHJvb2Y"));
    CHECK_EQ_LONG(m.ephem_public_key.len, 4);
    CHECK(m.ephem_public_key.ptr[3] == 4);
    CHECK(c2_str_equal(m.stream_id, "stream"));
    CHECK_EQ_LONG(m.protocol_version, 1);
  }

  /* MsgTunData: decode the Go vector (which includes a null field 10). */
  {
    uint8_t enc[256];
    size_t enc_len = unhex(kMsgtunHex, enc, sizeof(enc));
    c2_str cmds[4];
    c2_msgtun m = {0};
    m.cmd_slice.items = cmds;
    m.cmd_slice.cap = 4;
    CHECK(decode_msgtun(enc, enc_len, &m) == C2_OK);
    CHECK(c2_str_equal(m.job_id, "job-1"));
    CHECK_EQ_LONG(m.cmd_slice.count, 2);
    CHECK(c2_str_equal(m.cmd_slice.items[0], "!ls_dir"));
    CHECK(c2_str_equal(m.cmd_slice.items[1], "/tmp"));
    CHECK_EQ_LONG(m.response.len, 4);
    CHECK(m.response.ptr[0] == 0xde && m.response.ptr[3] == 0xef);
    CHECK(c2_str_equal(m.tag, "abcd"));
    CHECK_EQ_LONG(m.time.len, 0);
    CHECK_EQ_LONG(m.ephem_public_key.len, 4);
    CHECK(m.ephem_public_key.ptr[0] == 9);
    CHECK(m.enriched_peer_list == NULL);
  }

  /* MsgTunData: encode then decode round-trip (no null field 10). */
  {
    c2_str cmds[1] = {c2_str_lit("!stat")};
    c2_msgtun m = {0};
    m.job_id = c2_str_lit("job-2");
    m.cmd_slice.items = cmds;
    m.cmd_slice.count = 1;
    m.cmd_slice.cap = 1;
    m.response = c2_bytes_of("ok", 2);
    m.tag = c2_str_lit("abcd");
    m.ephem_public_key = c2_bytes_of("\x09\x08\x07\x06", 4);

    CborEncoder enc;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    CHECK(c2_msgtun_encode(&enc, &m) == C2_OK);
    size_t n = cbor_encoder_get_buffer_size(&enc, buf);

    c2_str dcmds[2];
    c2_msgtun d = {0};
    d.cmd_slice.items = dcmds;
    d.cmd_slice.cap = 2;
    CHECK(decode_msgtun(buf, n, &d) == C2_OK);
    CHECK(c2_str_equal(d.job_id, "job-2"));
    CHECK(d.response.len == 2 && d.response.ptr[0] == 'o');
    CHECK(!c2_msgtun_is_hello(&d));

    /* A hello has an empty response and a non-empty command slice. */
    c2_msgtun hello = {0};
    c2_str hello_cmd[1] = {c2_str_lit("random")};
    hello.cmd_slice.items = hello_cmd;
    hello.cmd_slice.count = 1;
    hello.cmd_slice.cap = 1;
    CHECK(c2_msgtun_is_hello(&hello));
  }

  /* MsgTunData: the enriched peer list decodes through the envelope. */
  {
    CborEncoder e, m, list, arr, pm;
    cbor_encoder_init(&e, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&e, &m, 1) == CborNoError);
    CHECK(cbor_encode_uint(&m, C2_KEY_TUN_ENRICHED_PEER_LIST) == CborNoError);
    CHECK(cbor_encoder_create_map(&m, &list, 1) == CborNoError);
    CHECK(cbor_encode_uint(&list, C2_KEY_PEER_LIST_PEERS) == CborNoError);
    CHECK(cbor_encoder_create_array(&list, &arr, 1) == CborNoError);
    CHECK(cbor_encoder_create_map(&arr, &pm, 1) == CborNoError);
    CHECK(cbor_encode_uint(&pm, C2_KEY_PEER_UUID) == CborNoError);
    CHECK(cbor_encode_text_stringz(&pm, "peer1") == CborNoError);
    CHECK(cbor_encoder_close_container(&arr, &pm) == CborNoError);
    CHECK(cbor_encoder_close_container(&list, &arr) == CborNoError);
    CHECK(cbor_encoder_close_container(&m, &list) == CborNoError);
    CHECK(cbor_encoder_close_container(&e, &m) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&e, buf);

    c2_enriched_peer peers[1] = {0};
    c2_str ips[1][2], files[1][2];
    peers[0].ips.items = ips[0];
    peers[0].ips.cap = 2;
    peers[0].files.items = files[0];
    peers[0].files.cap = 2;
    c2_enriched_peer_list list_out = {0};
    list_out.peers = peers;
    list_out.cap = 1;
    c2_msgtun msg = {0};
    msg.enriched_peer_list = &list_out;
    CHECK(decode_msgtun(buf, n, &msg) == C2_OK);
    CHECK_EQ_LONG(list_out.count, 1);
    CHECK(c2_str_equal(peers[0].uuid, "peer1"));
  }

  /* Unknown keys are skipped, not rejected. */
  {
    CborEncoder enc, map, arr;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&enc, &map, 2) == CborNoError);
    CHECK(cbor_encode_uint(&map, 1) == CborNoError);
    CHECK(cbor_encode_text_string(&map, "job-x", 5) == CborNoError);
    CHECK(cbor_encode_uint(&map, 99) == CborNoError); /* unknown */
    CHECK(cbor_encoder_create_array(&map, &arr, 2) == CborNoError);
    CHECK(cbor_encode_uint(&arr, 1) == CborNoError);
    CHECK(cbor_encode_uint(&arr, 2) == CborNoError);
    CHECK(cbor_encoder_close_container(&map, &arr) == CborNoError);
    CHECK(cbor_encoder_close_container(&enc, &map) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&enc, buf);

    c2_msgtun m = {0};
    CHECK(decode_msgtun(buf, n, &m) == C2_OK);
    CHECK(c2_str_equal(m.job_id, "job-x"));
  }

  /* A list that does not fit reports NOMEM instead of overflowing. */
  {
    CborEncoder enc, map, arr;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    CHECK(cbor_encoder_create_map(&enc, &map, 1) == CborNoError);
    CHECK(cbor_encode_uint(&map, 2) == CborNoError);
    CHECK(cbor_encoder_create_array(&map, &arr, 2) == CborNoError);
    CHECK(cbor_encode_text_string(&arr, "a", 1) == CborNoError);
    CHECK(cbor_encode_text_string(&arr, "b", 1) == CborNoError);
    CHECK(cbor_encoder_close_container(&map, &arr) == CborNoError);
    CHECK(cbor_encoder_close_container(&enc, &map) == CborNoError);
    size_t n = cbor_encoder_get_buffer_size(&enc, buf);

    c2_str one[1];
    c2_msgtun m = {0};
    m.cmd_slice.items = one;
    m.cmd_slice.cap = 1;
    CHECK(decode_msgtun(buf, n, &m) == C2_ERR_NOMEM);
  }

  /* Regression: a tagged value under an unknown key must be skipped whole, not
   * misread as the next map key (found by fuzz_messages). */
  {
    static const uint8_t tagged[] = {0xbf, 0x01, 0xd5, 0x03, 0xff};
    c2_msgtun t = {0};
    CHECK(decode_msgtun(tagged, sizeof(tagged), &t) == C2_ERR_PROTO);
    c2_str caps[1];
    c2_msgauth a = {0};
    a.capabilities.items = caps;
    a.capabilities.cap = 1;
    CHECK(decode_msgauth(tagged, sizeof(tagged), &a) == C2_OK);

    /* A key with no value ends the map: malformed, never a crash. */
    static const uint8_t odd[] = {0xa1, 0x01};
    c2_msgtun t2 = {0};
    CHECK(decode_msgtun(odd, sizeof(odd), &t2) == C2_ERR_PROTO);
  }

  TEST_DONE();
}
