/*
 * test_module.c — c2_coff_invocation_parse must turn a base64
 * def.ResolvedInvocation into the same loader tokens the Go agent packs:
 * z/Z text, i/s integer, b base64->hex.
 */

#include "module.h"

#include "common.h"
#include "test.h"

#include "cbor.h"

#include <string.h>

static void enc_arg_map(CborEncoder *arr, const char *wire, const char *text,
                        double number, int use_number) {
  CborEncoder arg;
  cbor_encoder_create_map(arr, &arg, 2);
  cbor_encode_uint(&arg, 1);
  cbor_encode_text_stringz(&arg, wire);
  cbor_encode_uint(&arg, 2);
  if (use_number)
    cbor_encode_double(&arg, number);
  else
    cbor_encode_text_stringz(&arg, text);
  cbor_encoder_close_container(arr, &arg);
}

int main(void) {
  /* {4: {1: "go", 2: [
   *        {1:"z",2:"World"}, {1:"i",2:1337.0},
   *        {1:"s",2:25.0},    {1:"b",2:"aGk="}]}}   ("aGk=" = "hi") */
  uint8_t cbor[512];
  CborEncoder enc, top, coff, arr;
  cbor_encoder_init(&enc, cbor, sizeof(cbor), 0);
  CHECK_EQ_LONG(cbor_encoder_create_map(&enc, &top, 1), CborNoError);
  cbor_encode_uint(&top, 4);
  cbor_encoder_create_map(&top, &coff, 2);
  cbor_encode_uint(&coff, 1);
  cbor_encode_text_stringz(&coff, "go");
  cbor_encode_uint(&coff, 2);
  cbor_encoder_create_array(&coff, &arr, 4);
  enc_arg_map(&arr, "z", "World", 0, 0);
  enc_arg_map(&arr, "i", NULL, 1337.0, 1);
  enc_arg_map(&arr, "s", NULL, 25.0, 1);
  enc_arg_map(&arr, "b", "aGk=", 0, 0);
  cbor_encoder_close_container(&coff, &arr);
  cbor_encoder_close_container(&top, &coff);
  cbor_encoder_close_container(&enc, &top);
  size_t cbor_len = cbor_encoder_get_buffer_size(&enc, cbor);
  CHECK(cbor_len > 0);

  char b64[1024];
  size_t b64_len = c2_base64url_encode(cbor, cbor_len, b64, sizeof(b64));
  CHECK(b64_len > 0);

  char export_name[64];
  c2_str tokens[8];
  size_t tokenc = 0;
  char tbuf[4096];
  size_t tbuf_used = 0;
  c2_status rst = c2_coff_invocation_parse(
      b64, b64_len, export_name, sizeof(export_name), tokens, &tokenc, 8, tbuf,
      sizeof(tbuf), &tbuf_used);
  CHECK_EQ_LONG(rst, C2_OK);

  CHECK(strcmp(export_name, "go") == 0);
  CHECK_EQ_LONG(tokenc, 4);
  CHECK_EQ_LONG(tokens[0].len, 6);
  CHECK_BYTES(tokens[0].ptr, "zWorld", 6);
  CHECK_EQ_LONG(tokens[1].len, 5);
  CHECK_BYTES(tokens[1].ptr, "i1337", 5);
  CHECK_EQ_LONG(tokens[2].len, 3);
  CHECK_BYTES(tokens[2].ptr, "s25", 3);
  CHECK_EQ_LONG(tokens[3].len, 5);
  CHECK_BYTES(tokens[3].ptr, "b6869", 5);

  /* Regression: Go marshals a no-argument ResolvedCoffInvocation with a nil
   * Args slice as CBOR null. Most SA_linux BOFs have no parameters, and the
   * decoder used to reject them with "bad invocation". */
  {
    static const uint8_t no_args[] = {0xa1, 0x04, 0xa2, 0x01, 0x62,
                                      0x67, 0x6f, 0x02, 0xf6};
    char no_args_b64[64];
    size_t n = c2_base64url_encode(no_args, sizeof(no_args), no_args_b64,
                                   sizeof(no_args_b64));
    CHECK(n > 0);
    rst = c2_coff_invocation_parse(no_args_b64, n, export_name,
                                   sizeof(export_name), tokens, &tokenc, 8,
                                   tbuf, sizeof(tbuf), &tbuf_used);
    CHECK_EQ_LONG(rst, C2_OK);
    CHECK(strcmp(export_name, "go") == 0);
    CHECK_EQ_LONG(tokenc, 0);
  }

  /* Malformed base64 and a truncated CBOR body must fail, not crash. */
  CHECK(c2_coff_invocation_parse("!!!!", 4, export_name, sizeof(export_name),
                                 tokens, &tokenc, 8, tbuf, sizeof(tbuf),
                                 &tbuf_used) != C2_OK);
  CHECK(c2_coff_invocation_parse("AAAA", 4, export_name, sizeof(export_name),
                                 tokens, &tokenc, 8, tbuf, sizeof(tbuf),
                                 &tbuf_used) != C2_OK);

  /* Regression: a truncated 64-bit integer inside an argument map. The decoder
   * used to re-enter the desynchronised map after a tinycbor error and read
   * out of bounds (minimized libFuzzer artifact a1 04 a2 02 8f bf 00 00 1b). */
  {
    static const uint8_t bad[] = {0xa1, 0x04, 0xa2, 0x02, 0x8f, 0xbf,
                                  0x00, 0x00, 0x1b};
    char bad_b64[64];
    size_t n = c2_base64url_encode(bad, sizeof(bad), bad_b64, sizeof(bad_b64));
    CHECK(n > 0);
    CHECK(c2_coff_invocation_parse(bad_b64, n, export_name,
                                   sizeof(export_name), tokens, &tokenc, 8,
                                   tbuf, sizeof(tbuf), &tbuf_used) != C2_OK);
  }

  /* A zero-length export buffer must be accepted without writing through it
   * (regression: `export_cap - 1` underflowed to SIZE_MAX). */
  {
    char one = 'X';
    CHECK(c2_coff_invocation_parse(b64, b64_len, &one, 0, tokens, &tokenc, 8,
                                   tbuf, sizeof(tbuf), &tbuf_used) == C2_OK);
    CHECK(one == 'X');
  }

  /* Regression: NaN/out-of-range float or double arguments must be rejected,
   * not cast to int64 (undefined behaviour) and not read with the wrong
   * tinycbor getter. `fb`/`fa` encode a double/float NaN; a finite float is
   * still accepted. */
  {
    static const uint8_t nan_double[] = {
        0xa1, 0x04, 0xa2, 0x01, 0x62, 0x67, 0x6f, 0x02, 0x81, 0xa2,
        0x01, 0x61, 0x73, 0x02, 0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00};
    static const uint8_t nan_float[] = {
        0xa1, 0x04, 0xa2, 0x01, 0x62, 0x67, 0x6f, 0x02, 0x81, 0xa2,
        0x01, 0x61, 0x73, 0x02, 0xfa, 0x7f, 0xc0, 0x00, 0x00};
    static const uint8_t inf_double[] = {
        0xa1, 0x04, 0xa2, 0x01, 0x62, 0x67, 0x6f, 0x02, 0x81, 0xa2,
        0x01, 0x61, 0x73, 0x02, 0xfb, 0x7f, 0xf0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00};
    const uint8_t *cases[] = {nan_double, nan_float, inf_double};
    const size_t lens[] = {sizeof(nan_double), sizeof(nan_float),
                           sizeof(inf_double)};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      char bad_b64[64];
      size_t n =
          c2_base64url_encode(cases[i], lens[i], bad_b64, sizeof(bad_b64));
      CHECK(n > 0);
      CHECK(c2_coff_invocation_parse(bad_b64, n, export_name,
                                     sizeof(export_name), tokens, &tokenc, 8,
                                     tbuf, sizeof(tbuf), &tbuf_used) != C2_OK);
    }
  }

  TEST_DONE();
}
