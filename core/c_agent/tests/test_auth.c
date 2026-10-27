#include "messages.h"

#include "test.h"

int main(void) {
  char out[256];
  size_t n;

  /* Exact Go test vector: one route, newline-separated. */
  {
    CHECK(c2_auth_canonical(c2_str_lit("agent-uuid"), 1234567890,
                            c2_str_lit("nonce-x"), c2_str_lit("c2-msg"), out,
                            sizeof(out), &n) == C2_OK);
    CHECK(strcmp(out, "agent-uuid\n1234567890\nnonce-x\nc2-msg") == 0);
    CHECK_EQ_LONG(n, strlen(out));
  }

  /* Empty route keeps the trailing newline. */
  {
    CHECK(c2_auth_canonical(c2_str_lit("u"), 1, c2_str_lit("n"), c2_str_lit(""),
                            out, sizeof(out), &n) == C2_OK);
    CHECK(strcmp(out, "u\n1\nn\n") == 0);
  }

  /* Extreme timestamps. */
  {
    CHECK(c2_auth_canonical(c2_str_lit("u"), -1, c2_str_lit("n"),
                            c2_str_lit("r"), out, sizeof(out), NULL) == C2_OK);
    CHECK(strcmp(out, "u\n-1\nn\nr") == 0);
    CHECK(c2_auth_canonical(c2_str_lit("u"), INT64_MIN, c2_str_lit("n"),
                            c2_str_lit("r"), out, sizeof(out), NULL) == C2_OK);
    CHECK(strcmp(out, "u\n-9223372036854775808\nn\nr") == 0);
  }

  /* Buffer too small reports NOMEM rather than truncating. */
  {
    char tiny[4];
    CHECK(c2_auth_canonical(c2_str_lit("agent"), 1, c2_str_lit("n"),
                            c2_str_lit("r"), tiny, sizeof(tiny),
                            NULL) == C2_ERR_NOMEM);
  }

  TEST_DONE();
}
