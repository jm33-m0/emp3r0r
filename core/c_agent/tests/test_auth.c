#include "messages.h"

#include "test.h"

static c2_str_list caps_of(c2_str *items, size_t n) {
  c2_str_list l;
  l.items = items;
  l.count = n;
  l.cap = n;
  return l;
}

int main(void) {
  char out[256];
  size_t n;

  /* Exact Go test vector: capabilities are sorted, duplicates kept. */
  {
    c2_str items[3] = {c2_str_lit("exec"), c2_str_lit("shell"),
                       c2_str_lit("get")};
    c2_str_list caps = caps_of(items, 3);
    CHECK(c2_auth_canonical(c2_str_lit("agent-uuid"), 1234567890,
                            c2_str_lit("nonce-x"), &caps, out, sizeof(out),
                            &n) == C2_OK);
    CHECK(strcmp(out, "agent-uuid\n1234567890\nnonce-x\nexec,get,shell") == 0);
    CHECK_EQ_LONG(n, strlen(out));
  }

  /* Argument order does not matter. */
  {
    c2_str a[3] = {c2_str_lit("shell"), c2_str_lit("get"), c2_str_lit("exec")};
    c2_str b[3] = {c2_str_lit("exec"), c2_str_lit("shell"), c2_str_lit("get")};
    c2_str_list la = caps_of(a, 3), lb = caps_of(b, 3);
    char o1[128], o2[128];
    CHECK(c2_auth_canonical(c2_str_lit("u"), 1, c2_str_lit("n"), &la, o1,
                            sizeof(o1), NULL) == C2_OK);
    CHECK(c2_auth_canonical(c2_str_lit("u"), 1, c2_str_lit("n"), &lb, o2,
                            sizeof(o2), NULL) == C2_OK);
    CHECK(strcmp(o1, o2) == 0);
    /* Caller arrays must not be reordered. */
    CHECK(strcmp(a[0].ptr, "shell") == 0 && strcmp(a[2].ptr, "exec") == 0);
  }

  /* No capabilities: a trailing newline and an empty join. */
  {
    CHECK(c2_auth_canonical(c2_str_lit("u"), 1, c2_str_lit("n"), NULL, out,
                            sizeof(out), &n) == C2_OK);
    CHECK(strcmp(out, "u\n1\nn\n") == 0);
    c2_str_list empty = caps_of(NULL, 0);
    CHECK(c2_auth_canonical(c2_str_lit("u"), 1, c2_str_lit("n"), &empty, out,
                            sizeof(out), NULL) == C2_OK);
    CHECK(strcmp(out, "u\n1\nn\n") == 0);
  }

  /* Bytewise sort (uppercase before lowercase) and duplicates kept. */
  {
    c2_str items[3] = {c2_str_lit("b"), c2_str_lit("B"), c2_str_lit("b")};
    c2_str_list caps = caps_of(items, 3);
    CHECK(c2_auth_canonical(c2_str_lit("u"), 0, c2_str_lit(""), &caps, out,
                            sizeof(out), NULL) == C2_OK);
    CHECK(strcmp(out, "u\n0\n\nB,b,b") == 0);
  }

  /* Extreme timestamps. */
  {
    CHECK(c2_auth_canonical(c2_str_lit("u"), -1, c2_str_lit("n"), NULL, out,
                            sizeof(out), NULL) == C2_OK);
    CHECK(strcmp(out, "u\n-1\nn\n") == 0);
    CHECK(c2_auth_canonical(c2_str_lit("u"), INT64_MIN, c2_str_lit("n"), NULL,
                            out, sizeof(out), NULL) == C2_OK);
    CHECK(strcmp(out, "u\n-9223372036854775808\nn\n") == 0);
  }

  /* Buffer too small reports NOMEM rather than truncating. */
  {
    char tiny[4];
    CHECK(c2_auth_canonical(c2_str_lit("agent"), 1, c2_str_lit("n"), NULL, tiny,
                            sizeof(tiny), NULL) == C2_ERR_NOMEM);
  }

  TEST_DONE();
}
