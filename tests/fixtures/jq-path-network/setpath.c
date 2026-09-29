#include "portable-component-implementation.h"
#include "path-contract.h"

spx_jv_value_v2 lifted_path_set(spx_path_set_context_v5 *context,
    spx_jv_value_v2 root, spx_jv_value_v2 path, spx_jv_value_v2 value) {
  const spx_path_set_services_v5 *s = context->services;
  void *e = s->context;
  if (s->kind(e, path) != PATH_ARRAY) {
    s->release(e, root); s->release(e, path); s->release(e, value);
    return s->error(e, PATH_NOT_ARRAY);
  }
  uint32_t length = s->length(e, s->copy(e, path));
  if (length > 10000U) {
    s->release(e, root); s->release(e, path); s->release(e, value);
    return s->error(e, PATH_TOO_DEEP);
  }
  if (!s->valid(e, root)) {
    s->release(e, path); s->release(e, value);
    return root;
  }
  if (length == 0U) {
    s->release(e, root); s->release(e, path);
    return value;
  }
  spx_jv_value_v2 key = s->array_get(e, s->copy(e, path), 0);
  spx_jv_value_v2 rest = s->array_slice(e, path, 1, (int32_t)length);
  spx_jv_value_v2 child = s->get(e, s->copy(e, root), s->copy(e, key));
  if (s->kind(e, key) != PATH_OBJECT) {
    if (!s->valid(e, child)) {
      s->release(e, root); s->release(e, key);
      s->release(e, rest); s->release(e, value);
      return child;
    }
    /* Detach the child before recursion to avoid quadratic copy-on-write. */
    root = s->set(e, root, s->copy(e, key), s->null_value(e));
    if (!s->valid(e, root)) {
      s->release(e, child); s->release(e, key);
      s->release(e, rest); s->release(e, value);
      return root;
    }
  }
  child = lifted_path_set(context, child, rest, value);
  return s->set(e, root, key, child);
}
