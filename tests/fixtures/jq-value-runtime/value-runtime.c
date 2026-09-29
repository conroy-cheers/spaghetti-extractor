/* Source-assisted from jq 1.8.1 jv.c; see COPYING. */
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "value-runtime-inputs.h"
#include "value-runtime-renames.h"
#include "jv_alloc.h"
#include "jv_unicode.h"
#define MIN(a,b) ((a)<(b)?(a):(b))
/* Shared seed initialization and lifetime remain in the runtime provider. */
uint32_t spx_string_hash_seed(void);
#define jvp_hash_seed spx_string_hash_seed
typedef struct jv_refcnt {
  int count;
} jv_refcnt;

static const jv_refcnt JV_REFCNT_INIT = {1};

static int jvp_refcnt_dec(jv_refcnt* c) {
  c->count--;
  return c->count == 0;
}

static int jvp_refcnt_unshared(jv_refcnt* c) {
  assert(c->count > 0);
  return c->count == 1;
}

#define KIND_MASK   0xF
#define PFLAGS_MASK 0xF0
#define PTYPE_MASK  0x70

typedef enum {
  JVP_PAYLOAD_NONE = 0,
  JVP_PAYLOAD_ALLOCATED = 0x80,
} payload_flags;

#define JVP_MAKE_PFLAGS(ptype, allocated) ((((ptype) << 4) & PTYPE_MASK) | ((allocated) ? JVP_PAYLOAD_ALLOCATED : 0))
#define JVP_MAKE_FLAGS(kind, pflags) ((kind & KIND_MASK) | (pflags & PFLAGS_MASK))

#define JVP_FLAGS(j)  ((j).kind_flags)
#define JVP_KIND(j)   (JVP_FLAGS(j) & KIND_MASK)

#define JVP_HAS_FLAGS(j, flags) (JVP_FLAGS(j) == flags)
#define JVP_HAS_KIND(j, kind)   (JVP_KIND(j) == kind)

#define JVP_IS_ALLOCATED(j) (j.kind_flags & JVP_PAYLOAD_ALLOCATED)

#define JVP_FLAGS_NULL      JVP_MAKE_FLAGS(JV_KIND_NULL, JVP_PAYLOAD_NONE)
#define JVP_FLAGS_INVALID   JVP_MAKE_FLAGS(JV_KIND_INVALID, JVP_PAYLOAD_NONE)
#define JVP_FLAGS_FALSE     JVP_MAKE_FLAGS(JV_KIND_FALSE, JVP_PAYLOAD_NONE)
#define JVP_FLAGS_TRUE      JVP_MAKE_FLAGS(JV_KIND_TRUE, JVP_PAYLOAD_NONE)

jv_kind jv_get_kind(jv x) {
  return JVP_KIND(x);
}

const char* jv_kind_name(jv_kind k) {
  switch (k) {
  case JV_KIND_INVALID: return "<invalid>";
  case JV_KIND_NULL:    return "null";
  case JV_KIND_FALSE:   return "boolean";
  case JV_KIND_TRUE:    return "boolean";
  case JV_KIND_NUMBER:  return "number";
  case JV_KIND_STRING:  return "string";
  case JV_KIND_ARRAY:   return "array";
  case JV_KIND_OBJECT:  return "object";
  }
  assert(0 && "invalid kind");
  return "<unknown>";
}

static const jv JV_NULL = {JVP_FLAGS_NULL, 0, 0, 0, {0}};
static const jv JV_INVALID = {JVP_FLAGS_INVALID, 0, 0, 0, {0}};
static const jv JV_FALSE = {JVP_FLAGS_FALSE, 0, 0, 0, {0}};
static const jv JV_TRUE = {JVP_FLAGS_TRUE, 0, 0, 0, {0}};

jv jv_true(void) {
  return JV_TRUE;
}

jv jv_false(void) {
  return JV_FALSE;
}

jv jv_null(void) {
  return JV_NULL;
}

jv jv_bool(int x) {
  return x ? JV_TRUE : JV_FALSE;
}

/*
 * Invalid objects, with optional error messages
 */

#define JVP_FLAGS_INVALID_MSG   JVP_MAKE_FLAGS(JV_KIND_INVALID, JVP_PAYLOAD_ALLOCATED)

typedef struct {
  jv_refcnt refcnt;
  jv errmsg;
} jvp_invalid;

jv jv_invalid_with_msg(jv err) {
  jvp_invalid* i = jv_mem_alloc(sizeof(jvp_invalid));
  i->refcnt = JV_REFCNT_INIT;
  i->errmsg = err;

  jv x = {JVP_FLAGS_INVALID_MSG, 0, 0, 0, {&i->refcnt}};
  return x;
}

jv jv_invalid(void) {
  return JV_INVALID;
}

jv jv_invalid_get_msg(jv inv) {
  assert(JVP_HAS_KIND(inv, JV_KIND_INVALID));

  jv x;
  if (JVP_HAS_FLAGS(inv, JVP_FLAGS_INVALID_MSG)) {
    x = jv_copy(((jvp_invalid*)inv.u.ptr)->errmsg);
  }
  else {
    x = jv_null();
  }

  jv_free(inv);
  return x;
}

int jv_invalid_has_msg(jv inv) {
  assert(JVP_HAS_KIND(inv, JV_KIND_INVALID));
  int r = JVP_HAS_FLAGS(inv, JVP_FLAGS_INVALID_MSG);
  jv_free(inv);
  return r;
}

void jvp_invalid_free(jv x) {
  assert(JVP_HAS_KIND(x, JV_KIND_INVALID));
  if (JVP_HAS_FLAGS(x, JVP_FLAGS_INVALID_MSG) && jvp_refcnt_dec(x.u.ptr)) {
    jv_free(((jvp_invalid*)x.u.ptr)->errmsg);
    jv_mem_free(x.u.ptr);
  }
}

jv jv_array(void) {
  return jv_array_sized(16);
}




jv jv_array_append(jv j, jv val) {
  // copy/free of val,j coalesced
  return jv_array_set(j, jv_array_length(jv_copy(j)), val);
}

jv jv_array_concat(jv a, jv b) {
  assert(JVP_HAS_KIND(a, JV_KIND_ARRAY));
  assert(JVP_HAS_KIND(b, JV_KIND_ARRAY));

  // FIXME: could be faster
  jv_array_foreach(b, i, elem) {
    a = jv_array_append(a, elem);
    if (!jv_is_valid(a)) break;
  }
  jv_free(b);
  return a;
}



#define JVP_FLAGS_STRING  JVP_MAKE_FLAGS(JV_KIND_STRING, JVP_PAYLOAD_ALLOCATED)

typedef struct {
  jv_refcnt refcnt;
  uint32_t hash;
  // high 31 bits are length, low bit is a flag
  // indicating whether hash has been computed.
  uint32_t length_hashed;
  uint32_t alloc_length;
  char data[];
} jvp_string;

static jvp_string* jvp_string_ptr(jv a) {
  assert(JVP_HAS_KIND(a, JV_KIND_STRING));
  return (jvp_string*)a.u.ptr;
}

static jvp_string* jvp_string_alloc(uint32_t size) {
  jvp_string* s = jv_mem_alloc(sizeof(jvp_string) + size + 1);
  s->refcnt.count = 1;
  s->alloc_length = size;
  return s;
}

/* Copy a UTF8 string, replacing all badly encoded points with U+FFFD */
static jv jvp_string_copy_replace_bad(const char* data, uint32_t length) {
  const char* end = data + length;
  const char* i = data;

  // worst case: all bad bytes, each becomes a 3-byte U+FFFD
  uint64_t maxlength = (uint64_t)length * 3 + 1;
  if (maxlength >= INT_MAX) {
    return jv_invalid_with_msg(jv_string("String too long"));
  }

  jvp_string* s = jvp_string_alloc(maxlength);
  char* out = s->data;
  int c = 0;

  while ((i = jvp_utf8_next(i, end, &c))) {
    if (c == -1) {
      c = 0xFFFD; // U+FFFD REPLACEMENT CHARACTER
    }
    out += jvp_utf8_encode(c, out);
    assert(out < s->data + maxlength);
  }
  length = out - s->data;
  s->data[length] = 0;
  s->length_hashed = length << 1;
  jv r = {JVP_FLAGS_STRING, 0, 0, 0, {&s->refcnt}};
  return r;
}

/* Assumes valid UTF8 */
static jv jvp_string_new(const char* data, uint32_t length) {
  jvp_string* s = jvp_string_alloc(length);
  s->length_hashed = length << 1;
  if (data != NULL)
    memcpy(s->data, data, length);
  s->data[length] = 0;
  jv r = {JVP_FLAGS_STRING, 0, 0, 0, {&s->refcnt}};
  return r;
}

static jv jvp_string_empty_new(uint32_t length) {
  jvp_string* s = jvp_string_alloc(length);
  s->length_hashed = 0;
  memset(s->data, 0, length);
  s->data[length] = 0;
  jv r = {JVP_FLAGS_STRING, 0, 0, 0, {&s->refcnt}};
  return r;
}


void jvp_string_free(jv js) {
  jvp_string* s = jvp_string_ptr(js);
  if (jvp_refcnt_dec(&s->refcnt)) {
    jv_mem_free(s);
  }
}

static uint32_t jvp_string_length(jvp_string* s) {
  return s->length_hashed >> 1;
}

static uint32_t jvp_string_remaining_space(jvp_string* s) {
  assert(s->alloc_length >= jvp_string_length(s));
  uint32_t r = s->alloc_length - jvp_string_length(s);
  return r;
}

static jv jvp_string_append(jv string, const char* data, uint32_t len) {
  jvp_string* s = jvp_string_ptr(string);
  uint32_t currlen = jvp_string_length(s);
  if ((uint64_t)currlen + len >= INT_MAX) {
    jv_free(string);
    return jv_invalid_with_msg(jv_string("String too long"));
  }

  if (jvp_refcnt_unshared(string.u.ptr) &&
      jvp_string_remaining_space(s) >= len) {
    // the next string fits at the end of a
    memcpy(s->data + currlen, data, len);
    s->data[currlen + len] = 0;
    s->length_hashed = (currlen + len) << 1;
    return string;
  } else {
    // allocate a bigger buffer and copy
    uint32_t allocsz = (currlen + len) * 2;
    if (allocsz < 32) allocsz = 32;
    jvp_string* news = jvp_string_alloc(allocsz);
    news->length_hashed = (currlen + len) << 1;
    memcpy(news->data, s->data, currlen);
    memcpy(news->data + currlen, data, len);
    news->data[currlen + len] = 0;
    jvp_string_free(string);
    jv r = {JVP_FLAGS_STRING, 0, 0, 0, {&news->refcnt}};
    return r;
  }
}

static uint32_t rotl32 (uint32_t x, int8_t r){
  return (x << r) | (x >> (32 - r));
}

static uint32_t jvp_string_hash(jv jstr) {
  jvp_string* str = jvp_string_ptr(jstr);
  if (str->length_hashed & 1)
    return str->hash;

  /* The following is based on MurmurHash3.
     MurmurHash3 was written by Austin Appleby, and is placed
     in the public domain. */

  const uint8_t* data = (const uint8_t*)str->data;
  int len = (int)jvp_string_length(str);
  const int nblocks = len / 4;

  uint32_t h1 = jvp_hash_seed();

  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;
  /* Preserve the target's little-endian words without alignment or aliasing
   * assumptions about the destination machine. */
  for (int i = 0; i < nblocks; i++) {
    const uint8_t *word = data + i * 4;
    uint32_t k1 = (uint32_t)word[0] | ((uint32_t)word[1] << 8) |
                  ((uint32_t)word[2] << 16) | ((uint32_t)word[3] << 24);

    k1 *= c1;
    k1 = rotl32(k1,15);
    k1 *= c2;

    h1 ^= k1;
    h1 = rotl32(h1,13);
    h1 = h1*5+0xe6546b64;
  }

  const uint8_t* tail = (const uint8_t*)(data + nblocks*4);

  uint32_t k1 = 0;

  switch(len & 3) {
  case 3: k1 ^= tail[2] << 16;
          JQ_FALLTHROUGH;
  case 2: k1 ^= tail[1] << 8;
          JQ_FALLTHROUGH;
  case 1: k1 ^= tail[0];
          k1 *= c1; k1 = rotl32(k1,15); k1 *= c2; h1 ^= k1;
  }

  h1 ^= len;

  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  str->length_hashed |= 1;
  str->hash = h1;

  return h1;
}


static int jvp_string_equal(jv a, jv b) {
  assert(JVP_HAS_KIND(a, JV_KIND_STRING));
  assert(JVP_HAS_KIND(b, JV_KIND_STRING));
  jvp_string* stra = jvp_string_ptr(a);
  jvp_string* strb = jvp_string_ptr(b);
  if (jvp_string_length(stra) != jvp_string_length(strb)) return 0;
  return memcmp(stra->data, strb->data, jvp_string_length(stra)) == 0;
}

/*
 * Strings (public API)
 */

jv jv_string_sized(const char* str, int len) {
  return
    jvp_utf8_is_valid(str, str+len) ?
    jvp_string_new(str, len) :
    jvp_string_copy_replace_bad(str, len);
}

jv jv_string_empty(int len) {
  return jvp_string_empty_new(len);
}

jv jv_string(const char* str) {
  return jv_string_sized(str, strlen(str));
}





jv jv_string_repeat(jv j, int n) {
  assert(JVP_HAS_KIND(j, JV_KIND_STRING));
  if (n < 0) {
    jv_free(j);
    return jv_null();
  }
  int len = jv_string_length_bytes(jv_copy(j));
  int64_t res_len = (int64_t)len * n;
  if (res_len >= INT_MAX) {
    jv_free(j);
    return jv_invalid_with_msg(jv_string("Repeat string result too long"));
  }
  if (res_len == 0) {
    jv_free(j);
    return jv_string("");
  }
  jv res = jv_string_empty(res_len);
  res = jvp_string_append(res, jv_string_value(j), len);
  for (int curr = len, grow; curr < res_len; curr += grow) {
    grow = MIN(res_len - curr, curr);
    res = jvp_string_append(res, jv_string_value(res), grow);
  }
  jv_free(j);
  return res;
}


jv jv_string_explode(jv j) {
  assert(JVP_HAS_KIND(j, JV_KIND_STRING));
  const char* i = jv_string_value(j);
  int len = jv_string_length_bytes(jv_copy(j));
  const char* end = i + len;
  jv a = jv_array_sized(len);
  int c;
  while ((i = jvp_utf8_next(i, end, &c))) {
    a = jv_array_append(a, jv_number(c));
    if (!jv_is_valid(a)) break;
  }
  jv_free(j);
  return a;
}

jv jv_string_implode(jv j) {
  assert(JVP_HAS_KIND(j, JV_KIND_ARRAY));
  int len = jv_array_length(jv_copy(j));
  jv s = jv_string_empty(len);
  int i;

  assert(len >= 0);

  for (i = 0; i < len; i++) {
    jv n = jv_array_get(jv_copy(j), i);
    assert(JVP_HAS_KIND(n, JV_KIND_NUMBER));
    int nv = jv_number_value(n);
    jv_free(n);
    // outside codepoint range or in utf16 surrogate pair range
    if (nv < 0 || nv > 0x10FFFF || (nv >= 0xD800 && nv <= 0xDFFF))
      nv = 0xFFFD; // U+FFFD REPLACEMENT CHARACTER
    s = jv_string_append_codepoint(s, nv);
  }

  jv_free(j);
  return s;
}

unsigned long jv_string_hash(jv j) {
  assert(JVP_HAS_KIND(j, JV_KIND_STRING));
  uint32_t hash = jvp_string_hash(j);
  jv_free(j);
  return hash;
}

const char* jv_string_value(jv j) {
  assert(JVP_HAS_KIND(j, JV_KIND_STRING));
  return jvp_string_ptr(j)->data;
}


jv jv_string_concat(jv a, jv b) {
  a = jvp_string_append(a, jv_string_value(b),
                        jvp_string_length(jvp_string_ptr(b)));
  jv_free(b);
  return a;
}

jv jv_string_append_buf(jv a, const char* buf, int len) {
  if (jvp_utf8_is_valid(buf, buf+len)) {
    a = jvp_string_append(a, buf, len);
  } else {
    jv b = jvp_string_copy_replace_bad(buf, len);
    a = jv_string_concat(a, b);
  }
  return a;
}

jv jv_string_append_codepoint(jv a, uint32_t c) {
  char buf[5];
  int len = jvp_utf8_encode(c, buf);
  a = jvp_string_append(a, buf, len);
  return a;
}

jv jv_string_append_str(jv a, const char* str) {
  return jv_string_append_buf(a, str, strlen(str));
}

jv jv_string_vfmt(const char* fmt, va_list ap) {
  int size = 1024;
  while (1) {
    char* buf = jv_mem_alloc(size);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(buf, size, fmt, ap2);
    va_end(ap2);
    /*
     * NOTE: here we support old vsnprintf()s that return -1 because the
     * buffer is too small.
     */
    if (n >= 0 && n < size) {
      jv ret = jv_string_sized(buf, n);
      jv_mem_free(buf);
      return ret;
    } else {
      jv_mem_free(buf);
      size = (n > 0) ? /* standard */ (n * 2) : /* not standard */ (size * 2);
    }
  }
}

#define JVP_FLAGS_OBJECT  JVP_MAKE_FLAGS(JV_KIND_OBJECT, JVP_PAYLOAD_ALLOCATED)

struct object_slot {
  int next; /* next slot with same hash, for collisions */
  uint32_t hash;
  jv string;
  jv value;
};

typedef struct {
  jv_refcnt refcnt;
  int next_free;
  struct object_slot elements[];
} jvp_object;


/* warning: nontrivial justification of alignment */
jv jvp_object_new(int size);

static jvp_object* jvp_object_ptr(jv o) {
  assert(JVP_HAS_KIND(o, JV_KIND_OBJECT));
  return (jvp_object*)o.u.ptr;
}

static uint32_t jvp_object_mask(jv o) {
  assert(JVP_HAS_KIND(o, JV_KIND_OBJECT));
  return (o.size * 2) - 1;
}

static int jvp_object_size(jv o) {
  assert(JVP_HAS_KIND(o, JV_KIND_OBJECT));
  return o.size;
}

static int* jvp_object_buckets(jv o) {
  return (int*)(&jvp_object_ptr(o)->elements[o.size]);
}

static int* jvp_object_find_bucket(jv object, jv key) {
  return jvp_object_buckets(object) + (jvp_object_mask(object) & jvp_string_hash(key));
}

static struct object_slot* jvp_object_get_slot(jv object, int slot) {
  assert(slot == -1 || (slot >= 0 && slot < jvp_object_size(object)));
  if (slot == -1) return 0;
  else return &jvp_object_ptr(object)->elements[slot];
}

static struct object_slot* jvp_object_next_slot(jv object, struct object_slot* slot) {
  return jvp_object_get_slot(object, slot->next);
}

static struct object_slot* jvp_object_find_slot(jv object, jv keystr, int* bucket) {
  uint32_t hash = jvp_string_hash(keystr);
  for (struct object_slot* curr = jvp_object_get_slot(object, *bucket);
       curr;
       curr = jvp_object_next_slot(object, curr)) {
    if (curr->hash == hash && jvp_string_equal(keystr, curr->string)) {
      return curr;
    }
  }
  return 0;
}

static struct object_slot* jvp_object_add_slot(jv object, jv key, int* bucket) {
  jvp_object* o = jvp_object_ptr(object);
  int newslot_idx = o->next_free;
  if (newslot_idx == jvp_object_size(object)) return 0;
  struct object_slot* newslot = jvp_object_get_slot(object, newslot_idx);
  o->next_free++;
  newslot->next = *bucket;
  *bucket = newslot_idx;
  newslot->hash = jvp_string_hash(key);
  newslot->string = key;
  return newslot;
}

static jv* jvp_object_read(jv object, jv key) {
  assert(JVP_HAS_KIND(key, JV_KIND_STRING));
  int* bucket = jvp_object_find_bucket(object, key);
  struct object_slot* slot = jvp_object_find_slot(object, key, bucket);
  if (slot == 0) return 0;
  else return &slot->value;
}

void jvp_object_free(jv o);

static int jvp_object_rehash(jv *objectp) {
  jv object = *objectp;
  assert(JVP_HAS_KIND(object, JV_KIND_OBJECT));
  assert(jvp_refcnt_unshared(object.u.ptr));
  int size = jvp_object_size(object);
  if (size > INT_MAX >> 2)
    return 0;
  jv new_object = jvp_object_new(size * 2);
  for (int i=0; i<size; i++) {
    struct object_slot* slot = jvp_object_get_slot(object, i);
    if (jv_get_kind(slot->string) == JV_KIND_NULL) continue;
    int* new_bucket = jvp_object_find_bucket(new_object, slot->string);
    assert(!jvp_object_find_slot(new_object, slot->string, new_bucket));
    struct object_slot* new_slot = jvp_object_add_slot(new_object, slot->string, new_bucket);
    assert(new_slot);
    new_slot->value = slot->value;
  }
  // references are transported, just drop the old table
  jv_mem_free(jvp_object_ptr(object));
  *objectp = new_object;
  return 1;
}

jv jvp_object_unshare(jv object);

static int jvp_object_write(jv* object, jv key, jv **valpp) {
  *object = jvp_object_unshare(*object);
  int* bucket = jvp_object_find_bucket(*object, key);
  struct object_slot* slot = jvp_object_find_slot(*object, key, bucket);
  if (slot) {
    // already has the key
    jvp_string_free(key);
    *valpp = &slot->value;
    return 1;
  }
  slot = jvp_object_add_slot(*object, key, bucket);
  if (slot) {
    slot->value = jv_invalid();
  } else {
    if (!jvp_object_rehash(object)) {
      *valpp = NULL;
      return 0;
    }
    bucket = jvp_object_find_bucket(*object, key);
    assert(!jvp_object_find_slot(*object, key, bucket));
    slot = jvp_object_add_slot(*object, key, bucket);
    assert(slot);
    slot->value = jv_invalid();
  }
  *valpp = &slot->value;
  return 1;
}

static int jvp_object_length(jv object) {
  int n = 0;
  for (int i=0; i<jvp_object_size(object); i++) {
    struct object_slot* slot = jvp_object_get_slot(object, i);
    if (jv_get_kind(slot->string) != JV_KIND_NULL) n++;
  }
  return n;
}

int jvp_object_equal(jv o1, jv o2);

int jvp_object_contains(jv a, jv b);

/*
 * Objects (public interface)
 */
#define DEFAULT_OBJECT_SIZE 8
jv jv_object(void) {
  return jvp_object_new(8);
}


int jv_object_has(jv object, jv key) {
  assert(JVP_HAS_KIND(object, JV_KIND_OBJECT));
  assert(JVP_HAS_KIND(key, JV_KIND_STRING));
  jv* slot = jvp_object_read(object, key);
  int res = slot ? 1 : 0;
  jv_free(object);
  jv_free(key);
  return res;
}

jv jv_object_set(jv object, jv key, jv value) {
  assert(JVP_HAS_KIND(object, JV_KIND_OBJECT));
  assert(JVP_HAS_KIND(key, JV_KIND_STRING));
  // copy/free of object, key, value coalesced
  jv* slot;
  if (!jvp_object_write(&object, key, &slot)) {
    jv_free(object);
    return jv_invalid_with_msg(jv_string("Object too big"));
  }
  jv_free(*slot);
  *slot = value;
  return object;
}


int jv_object_length(jv object) {
  assert(JVP_HAS_KIND(object, JV_KIND_OBJECT));
  int n = jvp_object_length(object);
  jv_free(object);
  return n;
}



/*
 * Object iteration (internal helpers)
 */

enum { ITER_FINISHED = -2 };

int jv_object_iter_valid(jv object, int i) {
  (void)object;
  return i != ITER_FINISHED;
}

int jv_object_iter(jv object) {
  assert(JVP_HAS_KIND(object, JV_KIND_OBJECT));
  return jv_object_iter_next(object, -1);
}

int jv_object_iter_next(jv object, int iter) {
  assert(JVP_HAS_KIND(object, JV_KIND_OBJECT));
  assert(iter != ITER_FINISHED);
  struct object_slot* slot;
  do {
    iter++;
    if (iter >= jvp_object_size(object))
      return ITER_FINISHED;
    slot = jvp_object_get_slot(object, iter);
  } while (jv_get_kind(slot->string) == JV_KIND_NULL);
  assert(jv_get_kind(jvp_object_get_slot(object,iter)->string)
         == JV_KIND_STRING);
  return iter;
}

jv jv_object_iter_key(jv object, int iter) {
  jv s = jvp_object_get_slot(object, iter)->string;
  assert(JVP_HAS_KIND(s, JV_KIND_STRING));
  return jv_copy(s);
}

jv jv_object_iter_value(jv object, int iter) {
  return jv_copy(jvp_object_get_slot(object, iter)->value);
}

int jv_get_refcnt(jv j) {
  if (JVP_IS_ALLOCATED(j)) {
    return j.u.ptr->count;
  } else {
    return 1;
  }
}

/* Destructors retain their own layout and lifecycle boundaries. The dispatcher
 * consumes exactly one reference and does nothing for immediate values. */
void spx_value_array_release(jv value);
void jvp_number_free(jv value);
void jvp_object_free(jv value);
void portable_jv_free(jv value) {
  switch (JVP_KIND(value)) {
  case JV_KIND_ARRAY: spx_value_array_release(value); break;
  case JV_KIND_STRING: jvp_string_free(value); break;
  case JV_KIND_OBJECT: jvp_object_free(value); break;
  case JV_KIND_INVALID: jvp_invalid_free(value); break;
  case JV_KIND_NUMBER: jvp_number_free(value); break;
  }
}
