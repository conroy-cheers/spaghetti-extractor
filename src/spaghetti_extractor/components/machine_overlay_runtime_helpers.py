"""Runtime C helpers for bounded view access and atomic overlay calls."""
from __future__ import annotations

from .machine_overlay_logical_views_v5 import VIEW_CONTEXT_DECLARATION

def _view_runtime_helpers(*, need_read: bool, need_write: bool) -> list[str]:
    lines = [
        *VIEW_CONTEXT_DECLARATION.splitlines(),
        "",
    ]
    if need_read:
        lines.extend(
            [
                "static uint32_t spx_component_view_read(",
                "    void *opaque, uint32_t offset, uint8_t *result) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  if (view == 0 || result == 0 || view->runtime == 0 ||",
                "      view->runtime->read == 0 || (view->permissions & UINT32_C(1)) == 0U ||",
                "      (uint64_t)offset >= view->extent || offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  *result = (uint8_t)view->runtime->read(",
                "      view->runtime->context, view->address + (uint32_t)offset, UINT32_C(1), &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
                "static uint32_t spx_component_view_read_span(",
                "    void *opaque, spx_ref_v1 base, uint64_t offset, uint32_t width,",
                "    uint64_t *result) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  (void)base;",
                "  if (view == 0 || result == 0 || view->runtime == 0 ||",
                "      view->runtime->read == 0 || (view->permissions & UINT32_C(1)) == 0U ||",
                "      width == UINT32_C(0) || width > UINT32_C(4) ||",
                "      offset > view->extent || (uint64_t)width > view->extent - offset ||",
                "      offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  *result = (uint64_t)view->runtime->read(",
                "      view->runtime->context, view->address + (uint32_t)offset, width, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
            ]
        )
    if need_write:
        lines.extend(
            [
                "static uint32_t spx_component_view_write(",
                "    void *opaque, uint32_t offset, uint8_t value) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  if (view == 0 || view->runtime == 0 || view->runtime->write == 0 ||",
                "      (view->permissions & UINT32_C(2)) == 0U ||",
                "      (uint64_t)offset >= view->extent || offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  view->runtime->write(view->runtime->context,",
                "      view->address + (uint32_t)offset, UINT32_C(1), value, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
                "static uint32_t spx_component_view_write_span(",
                "    void *opaque, spx_ref_v1 base, uint64_t offset, uint32_t width,",
                "    uint64_t value) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  (void)base;",
                "  if (view == 0 || view->runtime == 0 || view->runtime->write == 0 ||",
                "      (view->permissions & UINT32_C(2)) == 0U ||",
                "      width == UINT32_C(0) || width > UINT32_C(4) ||",
                "      offset > view->extent || (uint64_t)width > view->extent - offset ||",
                "      offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  view->runtime->write(",
                "      view->runtime->context, view->address + (uint32_t)offset, width,",
                "      (uint32_t)value, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
            ]
        )
    return lines


def _atomic_runtime_helpers() -> list[str]:
    return [
        "struct spx_atomic_object {",
        "  spx_runtime *runtime;",
        "  uint32_t address;",
        "  uint32_t width;",
        "};",
        "",
        "spx_atomic_status spx_atomic_compare_exchange(",
        "    spx_atomic_object *object, uint32_t expected, uint32_t desired,",
        "    spx_atomic_observation *observation) {",
        "  uint32_t fault = 0U;",
        "  if (object == 0 || object->runtime == 0 || observation == 0)",
        "    return SPX_ATOMIC_UNSUPPORTED;",
        "  spx_runtime_atomic_compare_exchange(object->runtime, object->address,",
        "      object->width, expected, desired, &observation->observed,",
        "      &observation->exchanged, &fault);",
        "  observation->written = observation->exchanged != 0U",
        "      ? desired : observation->observed;",
        "  return fault == 0U ? SPX_ATOMIC_OK : SPX_ATOMIC_FAULT;",
        "}",
        "",
        "spx_atomic_status spx_atomic_exchange(",
        "    spx_atomic_object *object, uint32_t desired,",
        "    spx_atomic_observation *observation) {",
        "  uint32_t fault = 0U;",
        "  if (object == 0 || object->runtime == 0 || observation == 0)",
        "    return SPX_ATOMIC_UNSUPPORTED;",
        "  spx_runtime_atomic_exchange(object->runtime, object->address, object->width,",
        "      desired, &observation->observed, &fault);",
        "  observation->written = desired;",
        "  observation->exchanged = fault == 0U;",
        "  return fault == 0U ? SPX_ATOMIC_OK : SPX_ATOMIC_FAULT;",
        "}",
        "",
    ]
