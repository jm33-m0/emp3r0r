#include "transport.h"

#include "fuzz_common.h"

#include "http_poll.h"

#include <stdlib.h>
#include <string.h>

/*
 * The shared HTTP-poll state machine sits between the selected transport and
 * SecureConn. Feed its request/response engine a fuzz-controlled body and
 * malleable-header profile, then drive init, long-poll reads, writes and close.
 * The transport itself is mocked, so no network is involved; the property is
 * memory safety plus bounded buffering/reassembly.
 */

static const uint8_t *g_body;
static size_t g_body_len;
static int g_mode;
static int g_calls;

c2_status hp_http_perform(const hp_http_request *req) {
  if (req == NULL || req->resp == NULL || req->resp_len == NULL ||
      req->status == NULL)
    return C2_ERR_ARG;
  g_calls++;

  /* Keep the init POST successful so the state machine is reachable, then
   * exercise the non-200 and 404 read paths on later exchanges. */
  long status = 200;
  if (g_calls > 1) {
    if (g_mode == 1)
      status = 404;
    else if (g_mode == 2)
      status = 500;
  }
  size_t n = g_body_len < req->resp_cap ? g_body_len : req->resp_cap;
  if (n && status == 200)
    memcpy(req->resp, g_body, n);
  else
    n = 0;
  *req->resp_len = n;
  *req->status = status;
  return C2_OK;
}

static void slice(const uint8_t *data, size_t size, size_t index, size_t pieces,
                  c2_str *out) {
  if (size == 0) {
    *out = c2_str_of(NULL, 0);
    return;
  }
  size_t start = size * index / pieces;
  size_t end = size * (index + 1) / pieces;
  *out = c2_str_of((const char *)data + start, end - start);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  c2_agent_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.ca_pem = c2_str_of(NULL, 0);
  cfg.doh_server = c2_str_of(NULL, 0);

  c2_str keys[4], values[4];
  c2_http_profile profile;
  memset(&profile, 0, sizeof(profile));
  slice(data, size, 0, 10, &profile.session_header);
  slice(data, size, 1, 10, &profile.session_value);
  slice(data, size, 2, 10, &profile.init_header);
  slice(data, size, 3, 10, &profile.init_value);
  slice(data, size, 4, 10, &profile.close_header);
  slice(data, size, 5, 10, &profile.close_value);
  profile.header_keys = keys;
  profile.header_values = values;
  profile.header_count = 4;
  for (size_t i = 0; i < 4; i++) {
    slice(data, size, 6 + i, 10, &keys[i]);
    values[i] = c2_str_of("v", 1);
  }

  g_body = data;
  g_body_len = size;
  g_mode = size ? data[0] % 4 : 0;
  g_calls = 0;

  c2_transport transport = c2_transport_create(&cfg);
  if (transport.ops == NULL || transport.ops->open == NULL)
    return 0;

  c2_stream stream;
  memset(&stream, 0, sizeof(stream));
  if (transport.ops->open(transport.ctx, "http://127.0.0.1/fuzz", &profile,
                          &stream) != C2_OK)
    return 0;
  if (stream.ops == NULL) {
    return 0;
  }

  uint8_t buf[512];
  for (int i = 0; i < 8; i++) {
    long n = stream.ops->read(stream.ctx, buf, sizeof(buf));
    if (n <= 0)
      break;
  }
  for (int i = 0; i < 2; i++)
    (void)stream.ops->write(stream.ctx, data, size);
  for (int i = 0; i < 8; i++) {
    long n = stream.ops->read(stream.ctx, buf, sizeof(buf));
    if (n <= 0)
      break;
  }
  if (stream.ops->close != NULL)
    stream.ops->close(stream.ctx);
  return 0;
}
