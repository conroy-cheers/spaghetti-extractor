#include <limits.h>
#include "portable-component-implementation.h"
#include "path-contract.h"
#include "numeric-index.h"

spx_jv_value_v2 lifted_value_set(spx_value_set_context_v5 *context,
    spx_jv_value_v2 value, spx_jv_value_v2 key, spx_jv_value_v2 item) {
  const spx_value_set_services_v5 *s = context->services;
  void *e = s->context;
  if (!s->valid(e, item)) {
    s->release(e, value); s->release(e, key);
    return item;
  }
  uint32_t kind = s->kind(e, value), key_kind = s->kind(e, key);
  if (key_kind == PATH_STRING && (kind == PATH_OBJECT || kind == PATH_NULL)) {
    if (kind == PATH_NULL) { s->release(e, value); value = s->object(e); }
    return s->object_set(e, value, key, item);
  }
  if (key_kind == PATH_NUMBER && (kind == PATH_ARRAY || kind == PATH_NULL)) {
    spx_numeric_index_v2 number = path_numeric_index(s->number(e, key));
    if (number.is_nan) {
      s->release(e, value); s->release(e, key);
      /* jv_set loses this owned reference on the pinned original's NaN path. */
      s->abandon(e, item);
      return s->error(e, PATH_NAN_INDEX);
    }
    if (kind == PATH_NULL) { s->release(e, value); value = s->array(e); }
    value = s->array_set(e, value, number.index, item);
    /* The original keeps the index reference until allocation/mutation returns. */
    s->release(e, key);
    return value;
  }
  if (key_kind == PATH_OBJECT && (kind == PATH_ARRAY || kind == PATH_NULL)) {
    if (kind == PATH_NULL) { s->release(e, value); value = s->array(e); }
    spx_slice_range_v2 range = s->slice_bounds(e, s->copy(e, value), key);
    if (!s->valid(e, range.status)) {
      s->release(e, value); s->release(e, item);
      return range.status;
    }
    s->release(e, range.status);
    if (s->kind(e, item) != PATH_ARRAY) {
      s->release(e, value); s->release(e, item);
      return s->error(e, PATH_SLICE_VALUE);
    }
    int32_t old_length = (int32_t)s->length(e, s->copy(e, value));
    int32_t inserted = (int32_t)s->length(e, s->copy(e, item));
    int32_t removed = range.end - range.start;
    if (inserted > removed) {
      int32_t shift = inserted - removed;
      for (int32_t i = old_length - 1; i >= range.end && s->valid(e, value); --i) {
        spx_jv_value_v2 element = s->array_get(e, s->copy(e, value), i);
        value = s->array_set(e, value, i + shift, element);
      }
    } else if (removed > inserted) {
      int32_t shift = removed - inserted;
      for (int32_t i = range.end; i < old_length && s->valid(e, value); ++i) {
        spx_jv_value_v2 element = s->array_get(e, s->copy(e, value), i);
        value = s->array_set(e, value, i - shift, element);
      }
      if (s->valid(e, value)) value = s->array_slice(e, value, 0, old_length - shift);
    }
    for (int32_t i = 0; i < inserted && s->valid(e, value); ++i) {
      spx_jv_value_v2 element = s->array_get(e, s->copy(e, item), i);
      value = s->array_set(e, value, range.start + i, element);
    }
    s->release(e, item);
    return value;
  }
  if (kind == PATH_STRING && key_kind == PATH_OBJECT) {
    s->release(e, value); s->release(e, key); s->release(e, item);
    return s->error(e, PATH_STRING_UPDATE);
  }
  return s->update_error(e, value, key, item);
}
