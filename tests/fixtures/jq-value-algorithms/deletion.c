/* Source-assisted lifting of jq 1.8.1; see COPYING. */
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "value-algorithms.h"
#include "jv_alloc.h"
#include "jv_private.h"

// making this static verbose function here
// until we introduce a less confusing naming scheme
// of jv_* API with regards to the memory management
static double jv_number_get_value_and_consume(jv number) {
  double value = jv_number_value(number);
  jv_free(number);
  return value;
}

static jv parse_slice(jv j, jv slice, int* pstart, int* pend) {
  // Array slices
  jv start_jv = jv_object_get(jv_copy(slice), jv_string("start"));
  jv end_jv = jv_object_get(slice, jv_string("end"));
  if (jv_get_kind(start_jv) == JV_KIND_NULL) {
    jv_free(start_jv);
    start_jv = jv_number(0);
  }
  int len;
  if (jv_get_kind(j) == JV_KIND_ARRAY) {
    len = jv_array_length(j);
  } else if (jv_get_kind(j) == JV_KIND_STRING) {
    len = jv_string_length_codepoints(j);
  } else {
    /*
     * XXX This should be dead code because callers shouldn't call this
     * function if `j' is neither an array nor a string.
     */
    jv_free(j);
    jv_free(start_jv);
    jv_free(end_jv);
    return jv_invalid_with_msg(jv_string("Only arrays and strings can be sliced"));
  }
  if (jv_get_kind(end_jv) == JV_KIND_NULL) {
    jv_free(end_jv);
    end_jv = jv_number(len);
  }
  if (jv_get_kind(start_jv) != JV_KIND_NUMBER ||
      jv_get_kind(end_jv) != JV_KIND_NUMBER) {
    jv_free(start_jv);
    jv_free(end_jv);
    return jv_invalid_with_msg(jv_string("Array/string slice indices must be integers"));
  }

  double dstart = jv_number_value(start_jv);
  double dend = jv_number_value(end_jv);
  int start, end;

  jv_free(start_jv);
  jv_free(end_jv);
  if (isnan(dstart)) dstart = 0;
  if (dstart < 0)    dstart += len;
  if (dstart < 0)    dstart = 0;
  if (dstart > len)  dstart = len;
  start = dstart > INT_MAX ? INT_MAX : (int)dstart; // Rounds down

  if (isnan(dend))   dend = len;
  if (dend < 0)      dend += len;
  if (dend < 0)      dend  = start;
  end = dend > INT_MAX ? INT_MAX : (int)dend;
  if (end > len)     end = len;
  if (end < len)     end += end < dend ? 1 : 0; // We round start down
                                                // but round end up

  if (end < start) end = start;
  assert(0 <= start && start <= end && end <= len);
  *pstart = start;
  *pend = end;
  return jv_true();
}

jv portable_jv_has(jv t, jv k) {
  assert(jv_is_valid(t));
  assert(jv_is_valid(k));
  jv ret;
  if (jv_get_kind(t) == JV_KIND_NULL) {
    jv_free(t);
    jv_free(k);
    ret = jv_false();
  } else if (jv_get_kind(t) == JV_KIND_OBJECT &&
             jv_get_kind(k) == JV_KIND_STRING) {
    jv elem = jv_object_get(t, k);
    ret = jv_bool(jv_is_valid(elem));
    jv_free(elem);
  } else if (jv_get_kind(t) == JV_KIND_ARRAY &&
             jv_get_kind(k) == JV_KIND_NUMBER) {
    if (jvp_number_is_nan(k)) {
      jv_free(t);
      ret = jv_false();
    } else {
      jv elem = jv_array_get(t, (int)jv_number_value(k));
      ret = jv_bool(jv_is_valid(elem));
      jv_free(elem);
    }
    jv_free(k);
  } else {
    ret = jv_invalid_with_msg(jv_string_fmt("Cannot check whether %s has a %s key",
                                            jv_kind_name(jv_get_kind(t)),
                                            jv_kind_name(jv_get_kind(k))));
    jv_free(t);
    jv_free(k);
  }
  return ret;
}

// assumes keys is a sorted array
static jv jv_dels(jv t, jv keys) {
  assert(jv_get_kind(keys) == JV_KIND_ARRAY);
  assert(jv_is_valid(t));

  if (jv_get_kind(t) == JV_KIND_NULL || jv_array_length(jv_copy(keys)) == 0) {
    // no change
  } else if (jv_get_kind(t) == JV_KIND_ARRAY) {
    // extract slices, they must be handled differently
    jv neg_keys = jv_array();
    jv nonneg_keys = jv_array();
    jv new_array = jv_array();
    jv starts = jv_array(), ends = jv_array();
    jv_array_foreach(keys, i, key) {
      if (jv_get_kind(key) == JV_KIND_NUMBER) {
        if (jv_number_value(key) < 0) {
          neg_keys = jv_array_append(neg_keys, key);
        } else {
          nonneg_keys = jv_array_append(nonneg_keys, key);
        }
      } else if (jv_get_kind(key) == JV_KIND_OBJECT) {
        int start = 0, end = 0;
        jv e = parse_slice(jv_copy(t), key, &start, &end);
        if (jv_get_kind(e) == JV_KIND_TRUE) {
          starts = jv_array_append(starts, jv_number(start));
          ends = jv_array_append(ends, jv_number(end));
        } else {
          jv_free(new_array);
          jv_free(key);
          new_array = e;
          goto arr_out;
        }
      } else {
        jv_free(new_array);
        new_array = jv_invalid_with_msg(jv_string_fmt("Cannot delete %s element of array",
                                                      jv_kind_name(jv_get_kind(key))));
        jv_free(key);
        goto arr_out;
      }
    }

    int neg_idx = 0;
    int nonneg_idx = 0;
    int len = jv_array_length(jv_copy(t));
    for (int i = 0; i < len; ++i) {
      int del = 0;
      while (neg_idx < jv_array_length(jv_copy(neg_keys))) {
        int delidx = len + (int)jv_number_get_value_and_consume(jv_array_get(jv_copy(neg_keys), neg_idx));
        if (i == delidx) {
          del = 1;
        }
        if (i < delidx) {
          break;
        }
        neg_idx++;
      }
      while (nonneg_idx < jv_array_length(jv_copy(nonneg_keys))) {
        int delidx = (int)jv_number_get_value_and_consume(jv_array_get(jv_copy(nonneg_keys), nonneg_idx));
        if (i == delidx) {
          del = 1;
        }
        if (i < delidx) {
          break;
        }
        nonneg_idx++;
      }
      for (int sidx=0; !del && sidx<jv_array_length(jv_copy(starts)); sidx++) {
        if ((int)jv_number_get_value_and_consume(jv_array_get(jv_copy(starts), sidx)) <= i &&
            i < (int)jv_number_get_value_and_consume(jv_array_get(jv_copy(ends), sidx))) {
          del = 1;
        }
      }
      if (!del)
        new_array = jv_array_append(new_array, jv_array_get(jv_copy(t), i));
    }
  arr_out:
    jv_free(neg_keys);
    jv_free(nonneg_keys);
    jv_free(starts);
    jv_free(ends);
    jv_free(t);
    t = new_array;
  } else if (jv_get_kind(t) == JV_KIND_OBJECT) {
    jv_array_foreach(keys, i, k) {
      if (jv_get_kind(k) != JV_KIND_STRING) {
        jv_free(t);
        t = jv_invalid_with_msg(jv_string_fmt("Cannot delete %s field of object",
                                              jv_kind_name(jv_get_kind(k))));
        jv_free(k);
        break;
      }
      t = jv_object_delete(t, k);
    }
  } else {
    jv err = jv_invalid_with_msg(jv_string_fmt("Cannot delete fields from %s",
                                               jv_kind_name(jv_get_kind(t))));
    jv_free(t);
    t = err;
  }
  jv_free(keys);
  return t;
}

#ifndef MAX_PATH_DEPTH
#define MAX_PATH_DEPTH (10000)
#endif

// assumes paths is a sorted array of arrays
static jv delpaths_sorted(jv object, jv paths, int start) {
  jv delkeys = jv_array();
  for (int i=0; i<jv_array_length(jv_copy(paths));) {
    int j = i;
    assert(jv_array_length(jv_array_get(jv_copy(paths), i)) > start);
    int delkey = jv_array_length(jv_array_get(jv_copy(paths), i)) == start + 1;
    jv key = jv_array_get(jv_array_get(jv_copy(paths), i), start);
    while (j < jv_array_length(jv_copy(paths)) &&
           jv_equal(jv_copy(key), jv_array_get(jv_array_get(jv_copy(paths), j), start)))
      j++;
    // if i <= entry < j, then entry starts with key
    if (delkey) {
      // deleting this entire key, we don't care about any more specific deletions
      delkeys = jv_array_append(delkeys, key);
    } else {
      // deleting certain sub-parts of this key
      jv subobject = jv_get(jv_copy(object), jv_copy(key));
      if (!jv_is_valid(subobject)) {
        jv_free(key);
        jv_free(object);
        object = subobject;
        break;
      } else if (jv_get_kind(subobject) == JV_KIND_NULL) {
        jv_free(key);
        jv_free(subobject);
      } else {
        jv newsubobject = delpaths_sorted(subobject, jv_array_slice(jv_copy(paths), i, j), start+1);
        if (!jv_is_valid(newsubobject)) {
          jv_free(key);
          jv_free(object);
          object = newsubobject;
          break;
        }
        object = jv_set(object, key, newsubobject);
      }
      if (!jv_is_valid(object)) break;
    }
    i = j;
  }
  jv_free(paths);
  if (jv_is_valid(object))
    object = jv_dels(object, delkeys);
  else
    jv_free(delkeys);
  return object;
}

jv portable_jv_delpaths(jv object, jv paths) {
  if (jv_get_kind(paths) != JV_KIND_ARRAY) {
    jv_free(object);
    jv_free(paths);
    return jv_invalid_with_msg(jv_string("Paths must be specified as an array"));
  }
  paths = portable_jv_sort(paths, jv_copy(paths));
  jv_array_foreach(paths, i, elem) {
    if (jv_get_kind(elem) != JV_KIND_ARRAY) {
      jv_free(object);
      jv_free(paths);
      jv err = jv_invalid_with_msg(jv_string_fmt("Path must be specified as array, not %s",
                                                 jv_kind_name(jv_get_kind(elem))));
      jv_free(elem);
      return err;
    }
    if (jv_array_length(jv_copy(elem)) > MAX_PATH_DEPTH) {
      jv_free(object);
      jv_free(paths);
      jv_free(elem);
      return jv_invalid_with_msg(jv_string("Path too deep"));
    }
    jv_free(elem);
  }
  if (jv_array_length(jv_copy(paths)) == 0) {
    // nothing is being deleted
    jv_free(paths);
    return object;
  }
  if (jv_array_length(jv_array_get(jv_copy(paths), 0)) == 0) {
    // everything is being deleted
    jv_free(paths);
    jv_free(object);
    return jv_null();
  }
  return delpaths_sorted(object, paths, 0);
}
