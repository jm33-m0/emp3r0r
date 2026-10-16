#include "messages.h"

#include "cbor.h"

#include "fuzz_common.h"

#include <string.h>

/* Decode arbitrary bytes as the wide check-in body, AgentToken and enriched
 * peer list. All of these read nested maps/arrays from hostile input, so the
 * property under test is memory safety and bounded recursion (ASan/UBSan), not
 * acceptance. List storage is deliberately small and varies with the input so
 * the out-of-capacity path is hit. The build config has its own fuzz target
 * (fuzz_config). */

#define PEER_MAX 4
#define IPS_PER_PEER 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  c2_str items[16];
  size_t cap = size % 17;

  CborParser parser;
  CborValue it;

  if (cbor_parser_init(data, size, 0, &parser, &it) == CborNoError) {
    c2_agent_info a = {0};
    a.ips.items = items;
    a.ips.cap = cap;
    a.arp.items = items;
    a.arp.cap = cap;
    a.exes.items = items;
    a.exes.cap = cap;
    a.files.items = items;
    a.files.cap = cap;
    (void)c2_agent_info_decode(&it, &a);
  }

  if (cbor_parser_init(data, size, 0, &parser, &it) == CborNoError) {
    c2_agent_token t = {0};
    (void)c2_agent_token_decode(&it, &t);
  }

  if (cbor_parser_init(data, size, 0, &parser, &it) == CborNoError) {
    c2_enriched_peer peers[PEER_MAX];
    c2_str peer_ips[PEER_MAX][IPS_PER_PEER];
    c2_str peer_files[PEER_MAX][IPS_PER_PEER];
    memset(peers, 0, sizeof(peers));
    c2_enriched_peer_list l = {0};
    l.peers = peers;
    l.cap = size % (PEER_MAX + 1);
    for (size_t i = 0; i < PEER_MAX; i++) {
      peers[i].ips.items = peer_ips[i];
      peers[i].ips.cap = IPS_PER_PEER;
      peers[i].files.items = peer_files[i];
      peers[i].files.cap = IPS_PER_PEER;
    }
    (void)c2_enriched_peer_list_decode(&it, &l);
  }

  return 0;
}
