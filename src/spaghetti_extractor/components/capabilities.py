"""Shared state machine for opaque, backend-bound component capabilities.

Public component interfaces remain strongly typed.  This module owns only the
lifecycle machinery shared by those typed facades; it deliberately does not
erase the domain semantics of atomics, callbacks, or future capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum

from ..semantic_objects.references import (
    CapabilityStatus,
    CheckedReference,
    ReferencePermission,
)


class CapabilityLifecycle(IntEnum):
    UNBOUND = 0
    LIVE = 1
    EXPIRED = 2


@dataclass(frozen=True)
class CheckedCapabilityState:
    """Architecture-neutral observable state for one opaque capability."""

    type_tag: int
    backend_kind: int
    instance_id: int
    generation: int
    lifecycle: CapabilityLifecycle = CapabilityLifecycle.LIVE
    action_count: int = 0
    last_status: CapabilityStatus = CapabilityStatus.OK

    def begin_action(
        self, *, expected_type_tag: int, generation: int | None = None
    ) -> tuple["CheckedCapabilityState", CapabilityStatus]:
        status = self._validate(expected_type_tag, generation)
        if status is not CapabilityStatus.OK:
            return replace(self, last_status=status), status
        return replace(self, action_count=self.action_count + 1), status

    def finish_action(self, status: CapabilityStatus) -> "CheckedCapabilityState":
        return replace(self, last_status=status)

    def expire(self) -> "CheckedCapabilityState":
        return replace(
            self,
            lifecycle=CapabilityLifecycle.EXPIRED,
            last_status=CapabilityStatus.EXPIRED,
        )

    def next_generation(self) -> "CheckedCapabilityState":
        return replace(
            self,
            generation=self.generation + 1,
            lifecycle=CapabilityLifecycle.LIVE,
            last_status=CapabilityStatus.OK,
        )

    def _validate(
        self, expected_type_tag: int, generation: int | None
    ) -> CapabilityStatus:
        if self.type_tag != expected_type_tag:
            return CapabilityStatus.TYPE_MISMATCH
        if self.lifecycle is not CapabilityLifecycle.LIVE:
            return CapabilityStatus.EXPIRED
        if generation is not None and generation != self.generation:
            return CapabilityStatus.EXPIRED
        if self.backend_kind == 0:
            return CapabilityStatus.UNSUPPORTED
        return CapabilityStatus.OK


def spx_capability_backend_header() -> str:
    """Return the private C state shared by typed runtime facades."""

    return """#ifndef SPX_CAPABILITY_BACKEND_H
#define SPX_CAPABILITY_BACKEND_H

#include <stdint.h>

typedef enum spx_capability_status {
  SPX_CAPABILITY_OK = 0,
  SPX_CAPABILITY_FAULT = 1,
  SPX_CAPABILITY_EXPIRED = 2,
  SPX_CAPABILITY_UNSUPPORTED = 3,
  SPX_CAPABILITY_TYPE_MISMATCH = 4
} spx_capability_status;

typedef enum spx_capability_lifecycle {
  SPX_CAPABILITY_UNBOUND = 0,
  SPX_CAPABILITY_LIVE = 1,
  SPX_CAPABILITY_DEAD = 2
} spx_capability_lifecycle;

typedef struct spx_capability_core {
  uint32_t type_tag;
  uint32_t backend_kind;
  uint64_t instance_id;
  uint64_t generation;
  uint32_t lifecycle;
  uint32_t action_count;
  spx_capability_status last_status;
} spx_capability_core;

void spx_capability_bind(
    spx_capability_core *capability,
    uint32_t type_tag,
    uint32_t backend_kind,
    uint64_t instance_id,
    uint64_t generation);
spx_capability_status spx_capability_begin(
    spx_capability_core *capability,
    uint32_t expected_type_tag,
    uint64_t expected_generation);
void spx_capability_finish(
    spx_capability_core *capability,
    spx_capability_status status);
void spx_capability_expire(spx_capability_core *capability);

#endif
"""


def spx_capability_backend_source() -> str:
    return """#include "spx-capability-backend.h"

void spx_capability_bind(
    spx_capability_core *capability,
    uint32_t type_tag,
    uint32_t backend_kind,
    uint64_t instance_id,
    uint64_t generation) {
  if (capability == 0) return;
  capability->type_tag = type_tag;
  capability->backend_kind = backend_kind;
  capability->instance_id = instance_id;
  capability->generation = generation;
  capability->lifecycle = backend_kind == 0U
      ? SPX_CAPABILITY_UNBOUND : SPX_CAPABILITY_LIVE;
  capability->action_count = 0U;
  capability->last_status = backend_kind == 0U
      ? SPX_CAPABILITY_UNSUPPORTED : SPX_CAPABILITY_OK;
}

spx_capability_status spx_capability_begin(
    spx_capability_core *capability,
    uint32_t expected_type_tag,
    uint64_t expected_generation) {
  spx_capability_status status;
  if (capability == 0 || capability->backend_kind == 0U)
    status = SPX_CAPABILITY_UNSUPPORTED;
  else if (capability->type_tag != expected_type_tag)
    status = SPX_CAPABILITY_TYPE_MISMATCH;
  else if (capability->lifecycle != SPX_CAPABILITY_LIVE ||
           capability->generation != expected_generation)
    status = SPX_CAPABILITY_EXPIRED;
  else {
    capability->action_count++;
    return SPX_CAPABILITY_OK;
  }
  if (capability != 0) capability->last_status = status;
  return status;
}

void spx_capability_finish(
    spx_capability_core *capability,
    spx_capability_status status) {
  if (capability != 0) capability->last_status = status;
}

void spx_capability_expire(spx_capability_core *capability) {
  if (capability == 0) return;
  capability->lifecycle = SPX_CAPABILITY_DEAD;
  capability->last_status = SPX_CAPABILITY_EXPIRED;
}
"""


def spx_reference_runtime_header() -> str:
    """Return the architecture-neutral checked reference runtime API."""

    return """#ifndef SPX_REFERENCE_RUNTIME_H
#define SPX_REFERENCE_RUNTIME_H

#include <stdint.h>

#ifndef SPX_REF_V1_DEFINED
typedef struct spx_ref_v1 {
  uint64_t domain;
  uint64_t object;
  uint64_t generation;
  uint64_t offset;
  uint64_t extent;
  uint32_t permissions;
} spx_ref_v1;
#define SPX_REF_V1_DEFINED 1
#endif

#ifndef SPX_VIEW_V1_DEFINED
typedef struct spx_view_v1 {
  void *context;
  uint32_t (*read_u8)(void *, uint32_t, uint8_t *);
  uint32_t (*write_u8)(void *, uint32_t, uint8_t);
  spx_ref_v1 base;
  uint64_t extent;
  uint32_t element_width;
  void *access_context;
  uint32_t (*read)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t *);
  uint32_t (*write)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t);
} spx_view_v1;
#define SPX_VIEW_V1_DEFINED 1
#endif

typedef uint32_t spx_ref_status;
enum {
  SPX_REF_OK = 0,
  SPX_REF_FAULT = 1,
  SPX_REF_EXPIRED = 2,
  SPX_REF_WRONG_ORIGIN = 3,
  SPX_REF_PERMISSION = 4
};

spx_ref_status spx_ref_validate(
    spx_ref_v1 reference,
    uint64_t domain,
    uint64_t object,
    uint64_t generation,
    uint64_t extent,
    uint32_t required_permissions,
    uint32_t nullable,
    uint32_t allow_one_past);
spx_ref_status spx_ref_derive(
    spx_ref_v1 reference,
    uint64_t delta,
    uint32_t allow_one_past,
    spx_ref_v1 *result);
spx_ref_status spx_ref_difference(
    spx_ref_v1 left,
    spx_ref_v1 right,
    int64_t *result);
spx_ref_status spx_view_reference_at(
    const spx_view_v1 *view,
    uint64_t index,
    uint32_t allow_one_past,
    spx_ref_v1 *result);
spx_ref_status spx_view_read_u8(
    const spx_view_v1 *view,
    uint64_t index,
    uint8_t *result);
spx_ref_status spx_view_write_u8(
    spx_view_v1 *view,
    uint64_t index,
    uint8_t value);

#endif
"""


def spx_reference_runtime_source() -> str:
    return """#include "spx-reference-runtime.h"

static uint32_t spx_ref_is_null(spx_ref_v1 value) {
  return value.domain == 0U && value.object == 0U &&
      value.generation == 0U && value.offset == 0U &&
      value.extent == 0U && value.permissions == 0U;
}

spx_ref_status spx_ref_validate(
    spx_ref_v1 reference,
    uint64_t domain,
    uint64_t object,
    uint64_t generation,
    uint64_t extent,
    uint32_t required_permissions,
    uint32_t nullable,
    uint32_t allow_one_past) {
  if (spx_ref_is_null(reference))
    return nullable != 0U ? SPX_REF_OK : SPX_REF_FAULT;
  if (reference.domain != domain || reference.object != object)
    return SPX_REF_WRONG_ORIGIN;
  if (reference.generation != generation)
    return SPX_REF_EXPIRED;
  if (reference.extent != extent || reference.offset > extent ||
      (reference.offset == extent && allow_one_past == 0U))
    return SPX_REF_FAULT;
  if ((reference.permissions & required_permissions) != required_permissions)
    return SPX_REF_PERMISSION;
  return SPX_REF_OK;
}

spx_ref_status spx_ref_derive(
    spx_ref_v1 reference,
    uint64_t delta,
    uint32_t allow_one_past,
    spx_ref_v1 *result) {
  uint64_t offset;
  if (result == 0 || spx_ref_is_null(reference) ||
      UINT64_MAX - reference.offset < delta)
    return SPX_REF_FAULT;
  offset = reference.offset + delta;
  if (offset > reference.extent ||
      (offset == reference.extent && allow_one_past == 0U))
    return SPX_REF_FAULT;
  *result = reference;
  result->offset = offset;
  return SPX_REF_OK;
}

spx_ref_status spx_ref_difference(
    spx_ref_v1 left,
    spx_ref_v1 right,
    int64_t *result) {
  if (result == 0 || spx_ref_is_null(left) || spx_ref_is_null(right) ||
      left.domain != right.domain || left.object != right.object ||
      left.generation != right.generation || left.extent != right.extent ||
      left.offset > INT64_MAX || right.offset > INT64_MAX)
    return SPX_REF_WRONG_ORIGIN;
  *result = (int64_t)left.offset - (int64_t)right.offset;
  return SPX_REF_OK;
}

static spx_ref_status spx_view_byte_offset(
    const spx_view_v1 *view,
    uint64_t index,
    uint32_t allow_one_past,
    uint64_t *result) {
  if (view == 0 || result == 0 || view->element_width == 0U ||
      index > view->extent ||
      (index == view->extent && allow_one_past == 0U) ||
      index > UINT64_MAX / view->element_width)
    return SPX_REF_FAULT;
  *result = index * view->element_width;
  return SPX_REF_OK;
}

spx_ref_status spx_view_reference_at(
    const spx_view_v1 *view,
    uint64_t index,
    uint32_t allow_one_past,
    spx_ref_v1 *result) {
  uint64_t byte_offset;
  spx_ref_status status = spx_view_byte_offset(
      view, index, allow_one_past, &byte_offset);
  if (status != SPX_REF_OK) return status;
  return spx_ref_derive(view->base, byte_offset, allow_one_past, result);
}

spx_ref_status spx_view_read_u8(
    const spx_view_v1 *view,
    uint64_t index,
    uint8_t *result) {
  uint64_t byte_offset, value = 0U;
  spx_ref_status status;
  if (result == 0 || view == 0 || view->element_width != 1U ||
      view->read == 0)
    return SPX_REF_FAULT;
  status = spx_view_byte_offset(view, index, 0U, &byte_offset);
  if (status != SPX_REF_OK) return status;
  if (view->read(view->access_context, view->base, byte_offset, 1U, &value) != 0U)
    return SPX_REF_FAULT;
  *result = (uint8_t)value;
  return SPX_REF_OK;
}

spx_ref_status spx_view_write_u8(
    spx_view_v1 *view,
    uint64_t index,
    uint8_t value) {
  uint64_t byte_offset;
  spx_ref_status status;
  if (view == 0 || view->element_width != 1U || view->write == 0)
    return SPX_REF_PERMISSION;
  status = spx_view_byte_offset(view, index, 0U, &byte_offset);
  if (status != SPX_REF_OK) return status;
  return view->write(
      view->access_context, view->base, byte_offset, 1U, value) == 0U
      ? SPX_REF_OK : SPX_REF_FAULT;
}
"""


def spx_portable_reference_runtime_v5_source() -> str:
    """Reviewed shared implementation of the portable component reference ABI."""

    return r'''
#ifndef SPX_REF_V1_DEFINED
typedef struct spx_ref_v1 {
  uint64_t domain;
  uint64_t object;
  uint64_t generation;
  uint64_t offset;
  uint64_t extent;
  uint32_t permissions;
} spx_ref_v1;
typedef spx_ref_v1 spx_ref_v5;

typedef struct spx_view_v1 {
  void *context;
  uint32_t (*read_u8)(void *, uint32_t, uint8_t *);
  uint32_t (*write_u8)(void *, uint32_t, uint8_t);
  spx_ref_v5 base;
  uint64_t extent;
  uint32_t element_width;
  void *access_context;
  uint32_t (*read)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t *);
  uint32_t (*write)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t);
} spx_view_v1;
typedef spx_view_v1 spx_view_v5;
#define SPX_REF_V1_DEFINED 1
#endif

static uint32_t spx_component_ref_is_null(spx_ref_v5 value) {
  return value.domain == 0U && value.object == 0U &&
      value.generation == 0U && value.offset == 0U &&
      value.extent == 0U && value.permissions == 0U;
}

uint32_t spx_ref_derive(
    spx_ref_v5 reference, uint64_t delta, uint32_t allow_one_past,
    spx_ref_v5 *result) {
  uint64_t offset;
  if (result == 0 || spx_component_ref_is_null(reference) ||
      UINT64_MAX - reference.offset < delta)
    return 1U; /* SPX_REF_FAULT */
  offset = reference.offset + delta;
  if (offset > reference.extent ||
      (offset == reference.extent && allow_one_past == 0U))
    return 1U; /* SPX_REF_FAULT */
  *result = reference;
  result->offset = offset;
  return 0U;
}

uint32_t spx_ref_difference(
    spx_ref_v5 left, spx_ref_v5 right, int64_t *result) {
  if (result == 0 || spx_component_ref_is_null(left) ||
      spx_component_ref_is_null(right) || left.domain != right.domain ||
      left.object != right.object || left.generation != right.generation ||
      left.extent != right.extent || left.offset > INT64_MAX ||
      right.offset > INT64_MAX)
    return 3U; /* SPX_REF_WRONG_ORIGIN */
  *result = (int64_t)left.offset - (int64_t)right.offset;
  return 0U;
}

uint32_t spx_view_read_u8(
    const spx_view_v5 *view, uint64_t index, uint8_t *result) {
  uint64_t value;
  if (view == 0 || result == 0 || index >= view->extent)
    return 1U; /* SPX_REF_FAULT */
  if (view->read_u8 != 0) {
    if (index > UINT32_MAX)
      return 1U; /* SPX_REF_FAULT */
    return view->read_u8(view->context, (uint32_t)index, result) == 0U
        ? 0U : 1U;
  }
  if (view->element_width != 1U || view->read == 0 ||
      view->base.offset > UINT64_MAX - index)
    return 4U; /* SPX_REF_PERMISSION */
  if (view->read(
          view->access_context, view->base, index, 1U, &value) != 0U)
    return 1U; /* SPX_REF_FAULT */
  *result = (uint8_t)value;
  return 0U;
}

uint32_t spx_view_write_u8(
    const spx_view_v5 *view, uint64_t index, uint8_t value) {
  if (view == 0 || index >= view->extent)
    return 1U; /* SPX_REF_FAULT */
  if (view->write_u8 != 0) {
    if (index > UINT32_MAX)
      return 1U;
    return view->write_u8(view->context, (uint32_t)index, value) == 0U ? 0U : 1U;
  }
  if (view->element_width != 1U || view->write == 0 ||
      view->base.offset > UINT64_MAX - index)
    return 4U; /* SPX_REF_PERMISSION */
  return view->write(view->access_context, view->base, index, 1U, value) == 0U
      ? 0U : 1U;
}
'''


__all__ = [
    "CapabilityLifecycle",
    "CapabilityStatus",
    "CheckedReference",
    "CheckedCapabilityState",
    "ReferencePermission",
    "spx_capability_backend_header",
    "spx_capability_backend_source",
    "spx_reference_runtime_header",
    "spx_reference_runtime_source",
    "spx_portable_reference_runtime_v5_source",
]
