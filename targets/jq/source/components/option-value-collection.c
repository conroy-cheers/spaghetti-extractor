#include "implementation.h"

uint32_t collect_constant_strings(constant_string_collection_services *services,
                                  uint32_t selector,
                                  opaque_value4 *result) {
  opaque_value4 strings[3], collection, next;

  if (selector != UINT32_C(1))
    return 0U;

  services->make_string(services->context, &strings[0], "$ORIGIN/../lib");
  services->make_string(services->context, &strings[1], "$ORIGIN/../lib/jq");
  services->make_string(services->context, &strings[2], "~/.jq");
  services->make_collection(services->context, &collection);

  services->append(services->context, &next, collection, strings[2]);
  collection = next;
  services->append(services->context, &next, collection, strings[1]);
  collection = next;
  services->append(services->context, result, collection, strings[0]);
  return 1U;
}
