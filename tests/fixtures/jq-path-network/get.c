#include <limits.h>
#include "portable-component-implementation.h"
#include "path-contract.h"
#include "numeric-index.h"

spx_jv_value_v2 lifted_value_get(spx_value_get_context_v5 *context,
                                spx_jv_value_v2 value, spx_jv_value_v2 key) {
  const spx_value_get_services_v5 *s = context->services;
  void *e = s->context;
  uint32_t kind = s->kind(e, value), key_kind = s->kind(e, key);
  spx_jv_value_v2 result;
  if (kind == PATH_OBJECT && key_kind == PATH_STRING) {
    result = s->object_get(e, value, key);
  } else if (kind == PATH_ARRAY && key_kind == PATH_NUMBER) {
    spx_numeric_index_v2 number = path_numeric_index(s->number(e, key));
    s->release(e, key);
    if (number.is_nan) {
      s->release(e, value);
      return s->null_value(e);
    }
    int32_t index = number.index;
    if (index < 0) index += (int32_t)s->length(e, s->copy(e, value));
    result = s->array_get(e, value, index);
  } else if ((kind == PATH_ARRAY || kind == PATH_STRING) && key_kind == PATH_OBJECT) {
    spx_slice_range_v2 range = s->slice_bounds(e, s->copy(e, value), key);
    if (!s->valid(e, range.status)) {
      s->release(e, value);
      return range.status;
    }
    s->release(e, range.status);
    return kind == PATH_ARRAY ? s->array_slice(e, value, range.start, range.end)
                             : s->string_slice(e, value, range.start, range.end);
  } else if (kind == PATH_ARRAY && key_kind == PATH_ARRAY) {
    return s->indexes(e, value, key);
  } else if (kind == PATH_NULL && (key_kind == PATH_STRING ||
             key_kind == PATH_NUMBER || key_kind == PATH_OBJECT)) {
    s->release(e, value); s->release(e, key);
    return s->null_value(e);
  } else {
    return s->index_error(e, value, key);
  }
  if (!s->valid(e, result)) {
    s->release(e, result);
    result = s->null_value(e);
  }
  return result;
}
