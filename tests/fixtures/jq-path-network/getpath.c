#include "portable-component-implementation.h"
#include "path-contract.h"

/* Preserve each consumed path view and its allocation/failure behavior while
 * replacing the original tail recursion with an ordinary C loop. */
spx_jv_value_v2 lifted_path_get(spx_path_get_context_v5 *context,
                               spx_jv_value_v2 root, spx_jv_value_v2 path) {
  const spx_path_get_services_v5 *s = context->services;
  void *e = s->context;
  if (s->kind(e, path) != PATH_ARRAY) {
    s->release(e, root);
    s->release(e, path);
    return s->error(e, PATH_NOT_ARRAY);
  }
  uint32_t length = s->length(e, s->copy(e, path));
  if (length > 10000U) {
    s->release(e, root);
    s->release(e, path);
    return s->error(e, PATH_TOO_DEEP);
  }
  for (uint32_t index = 0; index < length && s->valid(e, root); ++index) {
    spx_jv_value_v2 key = s->array_get(e, s->copy(e, path), 0);
    spx_jv_value_v2 rest = s->array_slice(e, path, 1, (int32_t)(length - index));
    root = s->get(e, root, key);
    path = rest;
  }
  s->release(e, path);
  return root;
}
