"""Runtime backend for the shared checked-atomics component API."""

from __future__ import annotations

from ..components.atomics import spx_atomics_header


def spx_atomics_backend_header() -> str:
    return """#ifndef SPX_ATOMICS_BACKEND_H
#define SPX_ATOMICS_BACKEND_H

#include "spx-atomics.h"
#include "spx-capability-backend.h"
#include "state-machine-runtime.h"

struct spx_atomic_object {
  spx_capability_core capability;
  spx_runtime *runtime;
  uint32_t address;
  uint32_t width;
  spx_atomic_status last_status;
  spx_atomic_observation last_observation;
  uint32_t call_count;
};

void spx_atomic_object_bind(
    spx_atomic_object *object,
    spx_runtime *runtime,
    uint32_t address,
    uint32_t width);

spx_atomic_status spx_atomic_object_status(const spx_atomic_object *object);
const spx_atomic_observation *spx_atomic_object_observation(
    const spx_atomic_object *object);
uint32_t spx_atomic_object_call_count(const spx_atomic_object *object);

#endif
"""


def spx_atomics_source() -> str:
    return """#include "spx-atomics-backend.h"

#define SPX_CAPABILITY_TYPE_ATOMIC_OBJECT 0x41544f4dU
#define SPX_CAPABILITY_BACKEND_RUNTIME 1U

void spx_atomic_object_bind(
    spx_atomic_object *object,
    spx_runtime *runtime,
    uint32_t address,
    uint32_t width) {
  if (object == 0) return;
  spx_capability_bind(
      &object->capability, SPX_CAPABILITY_TYPE_ATOMIC_OBJECT,
      SPX_CAPABILITY_BACKEND_RUNTIME, address, 1U);
  object->runtime = runtime;
  object->address = address;
  object->width = width;
  object->last_status = SPX_ATOMIC_OK;
  object->last_observation = (spx_atomic_observation){0};
  object->call_count = 0U;
}

spx_atomic_status spx_atomic_object_status(const spx_atomic_object *object) {
  return object == 0 ? SPX_ATOMIC_UNSUPPORTED : object->last_status;
}

const spx_atomic_observation *spx_atomic_object_observation(
    const spx_atomic_object *object) {
  return object == 0 ? 0 : &object->last_observation;
}

uint32_t spx_atomic_object_call_count(const spx_atomic_object *object) {
  return object == 0 ? 0U : object->call_count;
}

spx_atomic_status spx_atomic_compare_exchange(
    spx_atomic_object *object,
    uint32_t expected,
    uint32_t desired,
    spx_atomic_observation *observation) {
  uint32_t fault = 1U;
  uint32_t observed = 0U;
  uint32_t exchanged = 0U;
  uint32_t mask;
  spx_capability_status capability_status;
  if (object == 0) return SPX_ATOMIC_UNSUPPORTED;
  capability_status = spx_capability_begin(
      &object->capability, SPX_CAPABILITY_TYPE_ATOMIC_OBJECT,
      object->capability.generation);
  if (capability_status != SPX_CAPABILITY_OK) {
    object->last_status = capability_status == SPX_CAPABILITY_EXPIRED
        ? SPX_ATOMIC_FAULT : SPX_ATOMIC_UNSUPPORTED;
    return object->last_status;
  }
  if (object->runtime == 0 || observation == 0 ||
      (object->width != 1U && object->width != 2U && object->width != 4U)) {
    object->last_status = SPX_ATOMIC_UNSUPPORTED;
    spx_capability_finish(
        &object->capability, SPX_CAPABILITY_UNSUPPORTED);
    return SPX_ATOMIC_UNSUPPORTED;
  }
  object->call_count++;
  spx_runtime_atomic_compare_exchange(
      object->runtime, object->address, object->width, expected, desired,
      &observed, &exchanged, &fault);
  if (fault != 0U) {
    object->last_status = SPX_ATOMIC_FAULT;
    spx_capability_finish(&object->capability, SPX_CAPABILITY_FAULT);
    return SPX_ATOMIC_FAULT;
  }
  mask = object->width == 4U
      ? 0xffffffffU : ((1U << (object->width * 8U)) - 1U);
  observation->observed = observed & mask;
  observation->written = (exchanged != 0U ? desired : observed) & mask;
  observation->exchanged = exchanged != 0U;
  object->last_observation = *observation;
  object->last_status = SPX_ATOMIC_OK;
  spx_capability_finish(&object->capability, SPX_CAPABILITY_OK);
  return SPX_ATOMIC_OK;
}

spx_atomic_status spx_atomic_exchange(
    spx_atomic_object *object,
    uint32_t desired,
    spx_atomic_observation *observation) {
  uint32_t fault = 1U;
  uint32_t observed = 0U;
  uint32_t mask;
  spx_capability_status capability_status;
  if (object == 0) return SPX_ATOMIC_UNSUPPORTED;
  capability_status = spx_capability_begin(
      &object->capability, SPX_CAPABILITY_TYPE_ATOMIC_OBJECT,
      object->capability.generation);
  if (capability_status != SPX_CAPABILITY_OK) {
    object->last_status = capability_status == SPX_CAPABILITY_EXPIRED
        ? SPX_ATOMIC_FAULT : SPX_ATOMIC_UNSUPPORTED;
    return object->last_status;
  }
  if (object->runtime == 0 || observation == 0 ||
      (object->width != 1U && object->width != 2U && object->width != 4U)) {
    object->last_status = SPX_ATOMIC_UNSUPPORTED;
    spx_capability_finish(&object->capability, SPX_CAPABILITY_UNSUPPORTED);
    return SPX_ATOMIC_UNSUPPORTED;
  }
  object->call_count++;
  spx_runtime_atomic_exchange(
      object->runtime, object->address, object->width, desired, &observed, &fault);
  if (fault != 0U) {
    object->last_status = SPX_ATOMIC_FAULT;
    spx_capability_finish(&object->capability, SPX_CAPABILITY_FAULT);
    return SPX_ATOMIC_FAULT;
  }
  mask = object->width == 4U
      ? 0xffffffffU : ((1U << (object->width * 8U)) - 1U);
  observation->observed = observed & mask;
  observation->written = desired & mask;
  observation->exchanged = 1U;
  object->last_observation = *observation;
  object->last_status = SPX_ATOMIC_OK;
  spx_capability_finish(&object->capability, SPX_CAPABILITY_OK);
  return SPX_ATOMIC_OK;
}
"""


__all__ = [
    "spx_atomics_backend_header",
    "spx_atomics_header",
    "spx_atomics_source",
]
