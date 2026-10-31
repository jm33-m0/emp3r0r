/*
 * module.c — decode a def.ResolvedInvocation into COFF loader tokens.
 *
 * The C2 sends `!custom_module ... --invocation <base64 CBOR(def.ResolvedInvocation)>`
 * for a BOF module. The COFF part is
 *
 *   ResolvedInvocation.Coff (key 4) = {
 *     Export (key 1): text,
 *     Args   (key 2): [ { WireType (key 1): text, Value (key 2): any }, ... ]
 *   }
 *
 * WireType is the loader token prefix (z/Z/i/s/b). Value is the resolved value:
 * text for strings and binary (base64), a number for ints/shorts. Each is
 * turned into the token string c2_bof_pack_args consumes.
 */

#include "module.h"

#include "cbor_util.h"

#include "cbor.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read one ResolvedCoffArg.Value and build the token c2_bof_pack_args wants:
 * `z`/`Z` text, `i`/`s` integer, `b` base64->hex. */
static c2_status coff_arg_token(CborValue *v, char wire, char *buf, size_t cap,
                                size_t *off, c2_str *tok) {
  char tmp[4096];
  tmp[0] = wire;
  size_t tn = 1;
  c2_status st;
  switch (wire) {
  case 'z':
  case 'Z': {
    c2_str s;
    if (!cbor_value_is_text_string(v))
      return C2_ERR_PROTO;
    if ((st = c2_cbor_read_text(v, &s)) != C2_OK)
      return st;
    if (tn + s.len >= sizeof(tmp))
      return C2_ERR_NOMEM;
    memcpy(tmp + tn, s.ptr, s.len);
    tn += s.len;
    break;
  }
  case 'b': {
    c2_str s;
    if (!cbor_value_is_text_string(v))
      return C2_ERR_PROTO;
    if ((st = c2_cbor_read_text(v, &s)) != C2_OK)
      return st;
    size_t dec_cap = s.len / 4 * 3 + 4;
    uint8_t *dec = (uint8_t *)malloc(dec_cap);
    if (dec == NULL)
      return C2_ERR_NOMEM;
    size_t dec_len = 0;
    st = c2_base64url_decode(s.ptr, s.len, dec, dec_cap, &dec_len);
    if (st == C2_OK) {
      if (1 + dec_len * 2 > sizeof(tmp))
        st = C2_ERR_NOMEM;
      else
        tn += c2_hex_encode(dec, dec_len, tmp + 1);
    }
    free(dec);
    if (st != C2_OK)
      return st;
    break;
  }
  case 'i':
  case 's': {
    int64_t n = 0;
    if (cbor_value_is_integer(v)) {
      if (cbor_value_get_int64_checked(v, &n) != CborNoError)
        return C2_ERR_OVERFLOW;
      if ((st = c2_cbor_dc(cbor_value_advance(v))) != C2_OK)
        return st;
    } else if (cbor_value_is_double(v) || cbor_value_is_float(v)) {
      double d = 0;
      if (cbor_value_is_double(v)) {
        if (cbor_value_get_double(v, &d) != CborNoError)
          return C2_ERR_PROTO;
      } else {
        float f = 0;
        if (cbor_value_get_float(v, &f) != CborNoError)
          return C2_ERR_PROTO;
        d = f;
      }
      /* A hostile float argument can be NaN or out of int64 range; casting
       * either is undefined behaviour, so reject instead of converting. */
      if (!isfinite(d) || d < (double)INT64_MIN || d >= (double)INT64_MAX)
        return C2_ERR_OVERFLOW;
      n = (int64_t)d;
      if ((st = c2_cbor_dc(cbor_value_advance(v))) != C2_OK)
        return st;
    } else if (cbor_value_is_text_string(v)) {
      c2_str s;
      if ((st = c2_cbor_read_text(v, &s)) != C2_OK)
        return st;
      char numstr[32];
      size_t nn2 = s.len < sizeof(numstr) - 1 ? s.len : sizeof(numstr) - 1;
      memcpy(numstr, s.ptr, nn2);
      numstr[nn2] = '\0';
      n = strtoll(numstr, NULL, 10);
    } else {
      return C2_ERR_PROTO;
    }
    char num[24];
    int nn = snprintf(num, sizeof(num), "%lld", (long long)n);
    if (nn < 0 || (size_t)nn >= sizeof(num) || tn + (size_t)nn >= sizeof(tmp))
      return C2_ERR_NOMEM;
    memcpy(tmp + tn, num, (size_t)nn);
    tn += (size_t)nn;
    break;
  }
  default:
    return C2_ERR_UNSUPPORTED;
  }

  if (*off + tn >= cap)
    return C2_ERR_NOMEM;
  memcpy(buf + *off, tmp, tn);
  *tok = c2_str_of(buf + *off, tn);
  *off += tn;
  buf[*off] = '\0';
  return C2_OK;
}

/* Decode the base64 CBOR ResolvedInvocation (standard or URL-safe alphabet)
 * into a root iterator. On success *rawp is malloc'd and the caller frees it;
 * the iterator borrows that buffer. */
static c2_status invocation_open(const char *b64, size_t b64len, uint8_t **rawp,
                                 CborParser *p, CborValue *it) {
  size_t raw_cap = b64len / 4 * 3 + 4;
  uint8_t *raw = (uint8_t *)malloc(raw_cap);
  if (raw == NULL)
    return C2_ERR_NOMEM;
  size_t raw_len = 0;
  c2_status st = c2_base64url_decode(b64, b64len, raw, raw_cap, &raw_len);
  if (st != C2_OK) {
    free(raw);
    return st;
  }
  if (cbor_parser_init(raw, raw_len, 0, p, it) != CborNoError) {
    free(raw);
    return C2_ERR_PROTO;
  }
  *rawp = raw;
  return C2_OK;
}

c2_status c2_coff_invocation_parse(const char *b64, size_t b64len,
                                   char *export_name, size_t export_cap,
                                   c2_str *tokens, size_t *tokenc,
                                   size_t tokens_cap, char *buf, size_t buf_cap,
                                   size_t *buf_used) {
  if (b64 == NULL || export_name == NULL || tokens == NULL || tokenc == NULL ||
      buf == NULL || buf_used == NULL)
    return C2_ERR_ARG;
  *tokenc = 0;
  *buf_used = 0;
  if (export_cap > 0)
    export_name[0] = '\0';

  uint8_t *raw = NULL;
  CborParser p;
  CborValue it;
  c2_status st = invocation_open(b64, b64len, &raw, &p, &it);
  if (st != C2_OK)
    return st;

  CborValue map;
  st = c2_cbor_map_enter(&it, &map);
  if (st != C2_OK) {
    free(raw);
    return st;
  }

  int done = 0;
  uint64_t key = 0;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    if (key != 4) { /* ResolvedInvocation.Coff */
      st = c2_cbor_map_skip(&map);
      if (st != C2_OK)
        break;
      continue;
    }
    if (!cbor_value_is_map(&map)) {
      st = C2_ERR_PROTO;
      break;
    }
    CborValue coff;
    st = c2_cbor_map_enter(&map, &coff);
    if (st != C2_OK)
      break;

    int cdone = 0;
    uint64_t ckey = 0;
    while ((st = c2_cbor_map_key(&coff, &ckey, &cdone)) == C2_OK && !cdone) {
      if (ckey == 1) { /* Export */
        c2_str ex;
        st = c2_cbor_read_text(&coff, &ex);
        if (st == C2_OK && export_cap > 0) {
          size_t en = ex.len < export_cap - 1 ? ex.len : export_cap - 1;
          memcpy(export_name, ex.ptr, en);
          export_name[en] = '\0';
        }
      } else if (ckey == 2) { /* Args */
        /* Go encodes a nil []ResolvedCoffArg as CBOR null. No-argument BOFs
         * (most SA_linux modules) use that form, so treat it as an empty
         * argument list instead of rejecting the invocation. */
        if (cbor_value_is_null(&coff)) {
          st = c2_cbor_map_skip(&coff);
          if (st != C2_OK)
            break;
          continue;
        }
        if (!cbor_value_is_array(&coff)) {
          st = C2_ERR_PROTO;
          break;
        }
        CborValue arr;
        st = c2_cbor_dc(cbor_value_enter_container(&coff, &arr));
        if (st != C2_OK)
          break;
        while (!cbor_value_at_end(&arr) && st == C2_OK) {
          if (*tokenc >= tokens_cap || !cbor_value_is_map(&arr)) {
            st = (*tokenc >= tokens_cap) ? C2_ERR_NOMEM : C2_ERR_PROTO;
            break;
          }
          CborValue amap;
          st = c2_cbor_map_enter(&arr, &amap);
          if (st != C2_OK)
            break;
          char wire = 0;
          CborValue val;
          int have_val = 0;
          int adone = 0;
          uint64_t akey = 0;
          while ((st = c2_cbor_map_key(&amap, &akey, &adone)) == C2_OK &&
                 !adone) {
            if (akey == 1) { /* WireType */
              c2_str w;
              st = c2_cbor_read_text(&amap, &w);
              if (st == C2_OK) {
                if (w.len == 1)
                  wire = w.ptr[0];
                else
                  st = C2_ERR_PROTO;
              }
            } else if (akey == 2) { /* Value: borrow, then skip */
              val = amap;
              have_val = 1;
              st = c2_cbor_map_skip(&amap);
            } else {
              st = c2_cbor_map_skip(&amap);
            }
            /* tinycbor calls after an error are undefined behaviour: stop now
             * so the loop condition cannot re-enter the desynchronised map. */
            if (st != C2_OK)
              break;
          }
          if (st == C2_OK && wire != 0 && have_val) {
            st = coff_arg_token(&val, wire, buf, buf_cap, buf_used,
                                &tokens[*tokenc]);
            if (st == C2_OK)
              (*tokenc)++;
          }
          if (st == C2_OK)
            st = c2_cbor_dc(cbor_value_leave_container(&arr, &amap));
          if (st != C2_OK)
            break;
        }
        if (st == C2_OK)
          st = c2_cbor_dc(cbor_value_leave_container(&coff, &arr));
      } else {
        st = c2_cbor_map_skip(&coff);
      }
      if (st != C2_OK)
        break;
    }
    if (st == C2_OK)
      st = c2_cbor_dc(cbor_value_leave_container(&map, &coff));
    if (st != C2_OK)
      break;
  }
  if (st == C2_OK)
    st = c2_cbor_dc(cbor_value_leave_container(&it, &map));
  free(raw);
  return st;
}

/*
 * ResolvedInvocation.ModuleFiles (key 10) lists companion files hosted for a
 * multi-file module. Each entry is { Name(1), MemPath(2), Checksum(3) }.
 */
c2_status c2_module_files_parse(const char *b64, size_t b64len,
                                c2_module_file *files, size_t *count) {
  if (b64 == NULL || files == NULL || count == NULL)
    return C2_ERR_ARG;
  *count = 0;

  uint8_t *raw = NULL;
  CborParser p;
  CborValue it;
  c2_status st = invocation_open(b64, b64len, &raw, &p, &it);
  if (st != C2_OK)
    return st;

  CborValue map;
  st = c2_cbor_map_enter(&it, &map);
  if (st != C2_OK) {
    free(raw);
    return st;
  }

  int done = 0;
  uint64_t key = 0;
  while ((st = c2_cbor_map_key(&map, &key, &done)) == C2_OK && !done) {
    if (key != 10) {
      st = c2_cbor_map_skip(&map);
      if (st != C2_OK)
        break;
      continue;
    }
    if (cbor_value_is_null(&map)) {
      st = c2_cbor_map_skip(&map);
      if (st != C2_OK)
        break;
      continue;
    }
    if (!cbor_value_is_array(&map)) {
      st = C2_ERR_PROTO;
      break;
    }
    CborValue arr;
    st = c2_cbor_dc(cbor_value_enter_container(&map, &arr));
    if (st != C2_OK)
      break;
    while (!cbor_value_at_end(&arr)) {
      if (*count >= C2_MODULE_FILE_MAX || !cbor_value_is_map(&arr)) {
        st = (*count >= C2_MODULE_FILE_MAX) ? C2_ERR_NOMEM : C2_ERR_PROTO;
        break;
      }
      c2_module_file *f = &files[*count];
      memset(f, 0, sizeof(*f));
      CborValue m;
      st = c2_cbor_map_enter(&arr, &m);
      if (st != C2_OK)
        break;
      int mdone = 0;
      uint64_t mkey = 0;
      while ((st = c2_cbor_map_key(&m, &mkey, &mdone)) == C2_OK && !mdone) {
        c2_str v;
        char *dst = NULL;
        size_t cap = 0;
        switch (mkey) {
        case 1:
          dst = f->name;
          cap = sizeof(f->name);
          break;
        case 2:
          dst = f->mem_path;
          cap = sizeof(f->mem_path);
          break;
        case 3:
          dst = f->checksum;
          cap = sizeof(f->checksum);
          break;
        default:
          st = c2_cbor_map_skip(&m);
          if (st != C2_OK)
            break;
          continue;
        }
        st = c2_cbor_read_text(&m, &v);
        if (st != C2_OK)
          break;
        if (v.len >= cap)
          v.len = cap - 1;
        memcpy(dst, v.ptr, v.len);
        dst[v.len] = '\0';
      }
      if (st == C2_OK)
        st = c2_cbor_dc(cbor_value_leave_container(&arr, &m));
      if (st != C2_OK)
        break;
      (*count)++;
    }
    if (st == C2_OK)
      st = c2_cbor_dc(cbor_value_leave_container(&map, &arr));
    if (st != C2_OK)
      break;
    /* Keep consuming later keys (SessionUser, Ticket, ...). */
  }
  if (st == C2_OK)
    st = c2_cbor_dc(cbor_value_leave_container(&it, &map));
  free(raw);
  return st;
}
