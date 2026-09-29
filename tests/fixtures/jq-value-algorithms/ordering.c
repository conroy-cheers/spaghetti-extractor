/* Source-assisted lifting of jq 1.8.1; see COPYING. */
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "value-algorithms.h"
#include "jv_alloc.h"
#include "jv_private.h"
#include "windows-sort.h"

static int string_cmp(const void* pa, const void* pb){
  const jv* a = pa;
  const jv* b = pb;
  int lena = jv_string_length_bytes(jv_copy(*a));
  int lenb = jv_string_length_bytes(jv_copy(*b));
  int minlen = lena < lenb ? lena : lenb;
  int r = memcmp(jv_string_value(*a), jv_string_value(*b), minlen);
  /* The pinned CRT returns -1/+1 for unequal bytes. Host memcmp may return
   * their arithmetic difference; jv_cmp exposes this integer to C callers. */
  r = (r > 0) - (r < 0);
  if (r == 0) r = lena - lenb;
  return r;
}

jv portable_jv_keys_unsorted(jv x) {
  if (jv_get_kind(x) != JV_KIND_OBJECT)
    return portable_jv_keys(x);
  jv answer = jv_array_sized(jv_object_length(jv_copy(x)));
  jv_object_foreach(x, key, value) {
    answer = jv_array_append(answer, key);
    jv_free(value);
  }
  jv_free(x);
  return answer;
}

jv portable_jv_keys(jv x) {
  (void)&jv_is_valid;
  if (jv_get_kind(x) == JV_KIND_OBJECT) {
    int nkeys = jv_object_length(jv_copy(x));
    if (nkeys == 0) {
      jv_free(x);
      return jv_array();
    }
    jv* keys = jv_mem_calloc(nkeys, sizeof(jv));
    int kidx = 0;
    jv_object_foreach(x, key, value) {
      keys[kidx++] = key;
      jv_free(value);
    }
    spx_windows_qsort(keys, nkeys, sizeof(jv), string_cmp);
    jv answer = jv_array_sized(nkeys);
    for (int i = 0; i<nkeys; i++) {
      answer = jv_array_append(answer, keys[i]);
    }
    jv_mem_free(keys);
    jv_free(x);
    return answer;
  } else if (jv_get_kind(x) == JV_KIND_ARRAY) {
    int n = jv_array_length(x);
    jv answer = jv_array();
    for (int i=0; i<n; i++){
      answer = jv_array_set(answer, i, jv_number(i));
    }
    return answer;
  } else {
    assert(0 && "portable_jv_keys passed something neither object nor array");
    return jv_invalid();
  }
}

int portable_jv_cmp(jv a, jv b) {
  if (jv_get_kind(a) != jv_get_kind(b)) {
    int r = (int)jv_get_kind(a) - (int)jv_get_kind(b);
    jv_free(a);
    jv_free(b);
    return r;
  }
  int r = 0;
  switch (jv_get_kind(a)) {
  default:
    assert(0 && "invalid kind passed to portable_jv_cmp");
  case JV_KIND_NULL:
  case JV_KIND_FALSE:
  case JV_KIND_TRUE:
    // there's only one of each of these values
    r = 0;
    break;

  case JV_KIND_NUMBER: {
    if (jvp_number_is_nan(a)) {
      r = portable_jv_cmp(jv_null(), jv_copy(b));
    } else if (jvp_number_is_nan(b)) {
      r = portable_jv_cmp(jv_copy(a), jv_null());
    } else {
      r = jvp_number_cmp(a, b);
    }
    break;
  }

  case JV_KIND_STRING: {
    r = string_cmp(&a, &b);
    break;
  }

  case JV_KIND_ARRAY: {
    // Lexical ordering of arrays
    int i = 0;
    while (r == 0) {
      int a_done = i >= jv_array_length(jv_copy(a));
      int b_done = i >= jv_array_length(jv_copy(b));
      if (a_done || b_done) {
        r = b_done - a_done; //suddenly, logic
        break;
      }
      jv xa = jv_array_get(jv_copy(a), i);
      jv xb = jv_array_get(jv_copy(b), i);
      r = portable_jv_cmp(xa, xb);
      i++;
    }
    break;
  }

  case JV_KIND_OBJECT: {
    jv keys_a = portable_jv_keys(jv_copy(a));
    jv keys_b = portable_jv_keys(jv_copy(b));
    r = portable_jv_cmp(jv_copy(keys_a), keys_b);
    if (r == 0) {
      jv_array_foreach(keys_a, i, key) {
        jv xa = jv_object_get(jv_copy(a), jv_copy(key));
        jv xb = jv_object_get(jv_copy(b), key);
        r = portable_jv_cmp(xa, xb);
        if (r) break;
      }
    }
    jv_free(keys_a);
    break;
  }
  }

  jv_free(a);
  jv_free(b);
  return r;
}


/* Each item owns its value and key; position preserves stable ordering. */
struct sort_entry {
    jv value;
    jv key;
    int position;
};

struct sorted_values {
    struct sort_entry *items;
    int length;
};

static int sort_cmp(const void *left, const void *right) {
    const struct sort_entry *a = left, *b = right;
    int order = portable_jv_cmp(jv_copy(a->key), jv_copy(b->key));
    return order ? order : a->position - b->position;
}

/* Transfer array elements into one private sorting buffer. The three consumers
 * below transfer or release every key and value, then release this buffer. */
static struct sorted_values sort_items(jv values, jv keys) {
    assert(jv_get_kind(values) == JV_KIND_ARRAY);
    assert(jv_get_kind(keys) == JV_KIND_ARRAY);
    int length = jv_array_length(jv_copy(values));
    assert(length == jv_array_length(jv_copy(keys)));
    struct sort_entry *items = length ? jv_mem_calloc(length, sizeof(*items)) : NULL;
    for (int i = 0; i < length; ++i) {
        items[i].value = jv_array_get(jv_copy(values), i);
        items[i].key = jv_array_get(jv_copy(keys), i);
        items[i].position = i;
    }
    jv_free(values);
    jv_free(keys);
    if (length) spx_windows_qsort(items, length, sizeof(*items), sort_cmp);
    return (struct sorted_values){items, length};
}

jv portable_jv_sort(jv values, jv keys) {
    struct sorted_values sorted = sort_items(values, keys);
    jv result = jv_array();
    for (int i = 0; i < sorted.length; ++i) {
        jv_free(sorted.items[i].key);
        result = jv_array_set(result, i, sorted.items[i].value);
    }
    jv_mem_free(sorted.items);
    return result;
}

jv portable_jv_group(jv values, jv keys) {
    struct sorted_values sorted = sort_items(values, keys);
    jv result = jv_array();
    if (sorted.length) {
        jv key = sorted.items[0].key;
        jv group = jv_array_append(jv_array(), sorted.items[0].value);
        for (int i = 1; i < sorted.length; ++i) {
            struct sort_entry *item = &sorted.items[i];
            if (jv_equal(jv_copy(key), jv_copy(item->key))) {
                jv_free(item->key);
            } else {
                jv_free(key);
                key = item->key;
                result = jv_array_append(result, group);
                group = jv_array();
            }
            group = jv_array_append(group, item->value);
        }
        jv_free(key);
        result = jv_array_append(result, group);
    }
    jv_mem_free(sorted.items);
    return result;
}

jv portable_jv_unique(jv values, jv keys) {
    struct sorted_values sorted = sort_items(values, keys);
    jv result = jv_array();
    jv key = jv_invalid();
    for (int i = 0; i < sorted.length; ++i) {
        struct sort_entry *item = &sorted.items[i];
        if (jv_equal(jv_copy(key), jv_copy(item->key))) {
            jv_free(item->key);
            jv_free(item->value);
        } else {
            jv_free(key);
            key = item->key;
            result = jv_array_append(result, item->value);
        }
    }
    jv_free(key);
    jv_mem_free(sorted.items);
    return result;
}
