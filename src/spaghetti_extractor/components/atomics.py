"""Architecture-independent checked-atomics API for portable components."""

from __future__ import annotations


ATOMIC_OBJECT_RESOURCE_KIND = "atomic_object"


def interface_uses_atomics(types: object) -> bool:
    return any(
        getattr(row, "kind", None) == "resource"
        and getattr(row, "resource_kind", None) == ATOMIC_OBJECT_RESOURCE_KIND
        for row in types  # type: ignore[union-attr]
    )


def spx_atomics_header() -> str:
    """Return the public API seen by lifted portable C."""

    return """#ifndef SPX_ATOMICS_H
#define SPX_ATOMICS_H

#include <stdint.h>

/* Atomic objects are capabilities supplied by the generated adapter.  Lifted
 * source cannot manufacture one or recover its machine address. */
typedef struct spx_atomic_object spx_atomic_object;

typedef struct spx_atomic_observation {
  uint32_t observed;
  uint32_t written;
  uint32_t exchanged;
} spx_atomic_observation;

typedef enum spx_atomic_status {
  SPX_ATOMIC_OK = 0,
  SPX_ATOMIC_FAULT = 1,
  SPX_ATOMIC_UNSUPPORTED = 2
} spx_atomic_status;

spx_atomic_status spx_atomic_compare_exchange(
    spx_atomic_object *object,
    uint32_t expected,
    uint32_t desired,
    spx_atomic_observation *observation);
spx_atomic_status spx_atomic_exchange(
    spx_atomic_object *object,
    uint32_t desired,
    spx_atomic_observation *observation);

#endif
"""


def spx_atomics_validation_source() -> str:
    """Return a callback-backed implementation used only for host validation.

    Production adapters bind the same public ABI to their runtime atomic
    backend.  Keeping validation callback-backed lets component compilation
    prove symbol and type conformance without embedding a machine address or a
    host-language atomic into portable source.
    """

    return """#include "spx-atomics.h"

typedef spx_atomic_status (*spx_atomic_compare_exchange_callback)(
    void *, uint32_t, uint32_t, spx_atomic_observation *);
typedef spx_atomic_status (*spx_atomic_exchange_callback)(
    void *, uint32_t, spx_atomic_observation *);

struct spx_atomic_object {
  void *context;
  spx_atomic_compare_exchange_callback compare_exchange;
  spx_atomic_exchange_callback exchange;
};

spx_atomic_status spx_atomic_compare_exchange(
    spx_atomic_object *object,
    uint32_t expected,
    uint32_t desired,
    spx_atomic_observation *observation) {
  if (object == 0 || object->compare_exchange == 0 || observation == 0)
    return SPX_ATOMIC_UNSUPPORTED;
  return object->compare_exchange(
      object->context, expected, desired, observation);
}

spx_atomic_status spx_atomic_exchange(
    spx_atomic_object *object,
    uint32_t desired,
    spx_atomic_observation *observation) {
  if (object == 0 || object->exchange == 0 || observation == 0)
    return SPX_ATOMIC_UNSUPPORTED;
  return object->exchange(object->context, desired, observation);
}
"""


__all__ = [
    "ATOMIC_OBJECT_RESOURCE_KIND",
    "interface_uses_atomics",
    "spx_atomics_header",
    "spx_atomics_validation_source",
]
