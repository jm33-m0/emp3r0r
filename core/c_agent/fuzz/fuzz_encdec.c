#include "c2_messages.h"

#include "cbor.h"

#include "fuzz_common.h"

static c2_status dec_tun(const uint8_t *buf, size_t len, c2_msgtun *m) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &p, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_msgtun_decode(&it, m);
}

static c2_status dec_auth(const uint8_t *buf, size_t len, c2_msgauth *m) {
  CborParser p;
  CborValue it;
  if (cbor_parser_init(buf, len, 0, &p, &it) != CborNoError)
    return C2_ERR_PROTO;
  return c2_msgauth_decode(&it, m);
}

/* Decode a message, re-encode it, then decode the result again. This drives
 * the encoders with decoded (possibly hostile) content and checks the two
 * directions agree on not crashing. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t buf[8192];

  c2_str cmds1[4], peers1[4];
  c2_msgtun t1 = {0};
  t1.cmd_slice.items = cmds1;
  t1.cmd_slice.cap = 4;
  t1.peer_list.items = peers1;
  t1.peer_list.cap = 4;
  if (dec_tun(data, size, &t1) == C2_OK) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    if (c2_msgtun_encode(&enc, &t1) == C2_OK) {
      size_t n = cbor_encoder_get_buffer_size(&enc, buf);
      c2_str cmds2[4], peers2[4];
      c2_msgtun t2 = {0};
      t2.cmd_slice.items = cmds2;
      t2.cmd_slice.cap = 4;
      t2.peer_list.items = peers2;
      t2.peer_list.cap = 4;
      (void)dec_tun(buf, n, &t2);
    }
  }

  c2_str caps1[4];
  c2_msgauth a1 = {0};
  a1.capabilities.items = caps1;
  a1.capabilities.cap = 4;
  if (dec_auth(data, size, &a1) == C2_OK) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    if (c2_msgauth_encode(&enc, &a1) == C2_OK) {
      size_t n = cbor_encoder_get_buffer_size(&enc, buf);
      c2_str caps2[4];
      c2_msgauth a2 = {0};
      a2.capabilities.items = caps2;
      a2.capabilities.cap = 4;
      (void)dec_auth(buf, n, &a2);
    }
  }

  return 0;
}
