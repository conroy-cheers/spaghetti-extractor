"""Compact callback lowering shared by native-ingress C emission."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import BOUNDARY_LIFECYCLE_V1_FORMAT
from ..errors import ToolkitInputError
from .native_ingress_runtime_model import (
    CompactCallbackRuntimeV1,
    _capability_lifetime,
    boundary_lifecycle_transducer_v1,
    compact_callback_runtime_v1,
    physical_frame_transducer_v1,
)


@dataclass(frozen=True)
class PreparedCompactCallbackSourceV1:
    runtime: CompactCallbackRuntimeV1
    bridge_rows: tuple[Mapping[str, Any], ...]
    target_descriptor_indexes: tuple[int, ...]
    lifetimes: Mapping[str, tuple[str, str | None]]


def prepare_compact_callback_source_v1(
    plan: Mapping[str, Any],
    static_bridges: Sequence[Mapping[str, Any]],
) -> PreparedCompactCallbackSourceV1:
    """Lower compact domains to dense descriptor inputs exactly once."""

    runtime = compact_callback_runtime_v1(plan)
    publications_by_domain: dict[str, list[Mapping[str, Any]]] = {}
    for publication in runtime.publications:
        publications_by_domain.setdefault(
            str(publication["domain_id"]), []
        ).append(publication)
    compact_rows: list[Mapping[str, Any]] = []
    compact_row_indexes: dict[str, int] = {}
    target_descriptor_indexes: list[int] = []
    lifetimes: dict[str, tuple[str, str | None]] = {}
    for domain in runtime.domains:
        raw = domain.payload
        physical_transducer = raw.get("physical_transducer")
        if physical_transducer is None:
            physical_core, issues = physical_frame_transducer_v1(
                raw["physical_frame"]
            )
            if issues:
                raise ToolkitInputError(
                    "compact callback physical transducer is incomplete"
                )
            physical_transducer = {
                **physical_core,
                "transducer_sha256": canonical_sha256_v3(physical_core),
            }
        lifecycle_transducer = raw.get("lifecycle_transducer")
        if lifecycle_transducer is None:
            lifecycle = raw.get("lifecycle_protocol", {})
            if lifecycle.get("format") == BOUNDARY_LIFECYCLE_V1_FORMAT:
                lifecycle_core, issues = boundary_lifecycle_transducer_v1(
                    raw["physical_frame"], lifecycle
                )
                if issues:
                    raise ToolkitInputError(
                        "compact callback lifecycle transducer is incomplete"
                    )
            else:
                lifecycle_core = {
                    "kind": "reviewed-pe32-loader-lifecycle-transducer-v1",
                    "physical_frame_id": domain.physical_frame_id,
                    "lifecycle_sha256": canonical_sha256_v3(lifecycle),
                    "bindings": [],
                }
            lifecycle_transducer = {
                **lifecycle_core,
                "transducer_sha256": canonical_sha256_v3(lifecycle_core),
            }
        domain_lifetimes = {
            _capability_lifetime(str(row["lifetime"]))
            for row in publications_by_domain[domain.identity]
        }
        if len(domain_lifetimes) != 1:
            raise ToolkitInputError(
                "compact callback domain has conflicting capability lifetimes"
            )
        lifetime = next(iter(domain_lifetimes))
        for target in domain.targets:
            lifetimes[target.capability_id] = lifetime
            # A callback target varies only by target RVA and capability.
            # Keep those in the existing dense flat-target tables and emit
            # one descriptor for each genuinely distinct frame/lifecycle/
            # outcome class.  The former per-target descriptor expansion was
            # lossless but multiplied large C initializers by every admitted
            # target in every callback domain.
            descriptor_row = {
                "symbol": domain.bridge_family_id,
                "descriptor": {
                    "role": "callback",
                    "target_rva": 0,
                    "physical_frame": raw["physical_frame"],
                    "physical_transducer": physical_transducer,
                    "lifecycle_protocol": raw.get("lifecycle_protocol", {}),
                    "lifecycle_transducer": lifecycle_transducer,
                    "outcome_protocol_id": target.outcome_protocol_id,
                },
                "capability_ids": [],
                "permanently_callable": False,
                "process_root": False,
                "cleanup_bytes": domain.cleanup_bytes,
                "physical_frame_ids": [domain.physical_frame_id],
            }
            row_sha256 = canonical_sha256_v3(descriptor_row)
            descriptor_index = compact_row_indexes.get(row_sha256)
            if descriptor_index is None:
                descriptor_index = len(static_bridges) + len(compact_rows)
                compact_row_indexes[row_sha256] = descriptor_index
                compact_rows.append(descriptor_row)
            target_descriptor_indexes.append(descriptor_index)
    if len(target_descriptor_indexes) != len(runtime.targets):
        raise ToolkitInputError(
            "compact callback descriptor map does not cover flat targets"
        )
    return PreparedCompactCallbackSourceV1(
        runtime=runtime,
        bridge_rows=tuple([*static_bridges, *compact_rows]),
        target_descriptor_indexes=tuple(target_descriptor_indexes),
        lifetimes=lifetimes,
    )


def compact_callback_capability_source_v1() -> str:
    """Emit the target-stable capability facade over the base registry."""

    return r'''uint32_t spx_native_compact_callback_activate(
    uint32_t flat_target_index, uint32_t escaped) {
  uint32_t global_target_index, assigned, expected;
  if (flat_target_index >= spx_native_compact_callback_target_count)
    return 0U;
  global_target_index =
      spx_native_compact_global_target_indexes[flat_target_index];
  if (global_target_index >= spx_native_compact_global_target_count)
    return 0U;
  assigned = __atomic_load_n(
      &spx_native_compact_target_assignments[global_target_index],
      __ATOMIC_ACQUIRE);
  if (assigned == 0xffffffffU) {
    expected = 0xffffffffU;
    if (__atomic_compare_exchange_n(
            &spx_native_compact_target_assignments[global_target_index],
            &expected, flat_target_index, 0, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE))
      assigned = flat_target_index;
    else
      assigned = expected;
  }
  if (assigned != flat_target_index) return 0U;
  return spx_native_capability_activate(
      spx_native_compact_capability_indexes[flat_target_index], escaped);
}

uint32_t spx_native_compact_callback_is_active(uint32_t flat_target_index) {
  if (flat_target_index >= spx_native_compact_callback_target_count)
    return 0U;
  return spx_native_capability_is_active(
      spx_native_compact_capability_indexes[flat_target_index]);
}

uint32_t spx_native_compact_callback_commit(
    uint32_t flat_target_index, uint32_t generation) {
  if (flat_target_index >= spx_native_compact_callback_target_count)
    return 0U;
  return spx_native_capability_commit(
      spx_native_compact_capability_indexes[flat_target_index], generation);
}

uint32_t spx_native_compact_callback_revoke(
    uint32_t flat_target_index, uint32_t generation) {
  if (flat_target_index >= spx_native_compact_callback_target_count)
    return 0U;
  return spx_native_capability_revoke(
      spx_native_compact_capability_indexes[flat_target_index], generation);
}'''


def compact_callback_entry_source_v1() -> str:
    """Emit the dense-index entry facade used by the assembly gateways."""

    return r'''void *spx_native_callback_prepare(
    uint32_t flat_target_index, spx_native_physical_capture *capture) {
  if (flat_target_index >= spx_native_compact_callback_target_count)
    return 0;
  return spx_native_ingress_prepare(
      spx_native_static_ingress_descriptor_count + flat_target_index,
      capture);
}

uint32_t spx_native_callback_dispatch(void) {
  uint8_t *base = spx_native_thread_base();
  spx_native_thread_header *header;
  spx_native_ingress_frame *frame;
  if (base == 0) return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  header = (spx_native_thread_header *)(void *)base;
  if (header->depth == 0U) return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  frame = spx_native_frame_at(base, header->depth - 1U);
  if (frame->bridge_index < spx_native_static_ingress_descriptor_count)
    return (uint32_t)SPX_CALL_UNIMPLEMENTED;
  return spx_native_ingress_dispatch(frame->bridge_index);
}'''


def compact_callback_table_values_v1(
    runtime: CompactCallbackRuntimeV1,
    capability_index: Mapping[str, int],
    target_descriptor_indexes: Sequence[int],
) -> tuple[str, str, str, int, str, str, int]:
    capability_rows = "\n".join(
        f"  {capability_index[target.capability_id]}U,"
        for target in runtime.targets
    ) or "  0U,"
    global_rows = "\n".join(
        f"  {target.global_target_index}U," for target in runtime.targets
    ) or "  0U,"
    target_rva_rows = "\n".join(
        f"  0x{target.target_rva:08x}U," for target in runtime.targets
    ) or "  0U,"
    global_count = len({target.global_target_index for target in runtime.targets})
    assignments = "\n".join(
        "  0xffffffffU," for _ in range(global_count)
    ) or "  0xffffffffU,"
    if (
        len(target_descriptor_indexes) != len(runtime.targets)
        or any(
            not isinstance(index, int) or isinstance(index, bool) or index < 0
            for index in target_descriptor_indexes
        )
    ):
        raise ToolkitInputError(
            "compact callback target descriptor indexes are malformed"
        )
    descriptor_ranges: list[tuple[int, int, int]] = []
    for flat_index, descriptor_index in enumerate(target_descriptor_indexes):
        if (
            descriptor_ranges
            and descriptor_ranges[-1][0] + descriptor_ranges[-1][1]
            == flat_index
            and descriptor_ranges[-1][2] == descriptor_index
        ):
            first, count, observed = descriptor_ranges[-1]
            descriptor_ranges[-1] = (first, count + 1, observed)
        else:
            descriptor_ranges.append((flat_index, 1, descriptor_index))
    descriptor_rows = "\n".join(
        f"  {{ {first}U, {count}U, {index}U }},"
        for first, count, index in descriptor_ranges
    ) or "  { 0U, 0U, 0U },"
    return (
        capability_rows, global_rows, target_rva_rows, global_count, assignments,
        descriptor_rows, len(descriptor_ranges),
    )


def merge_compact_callback_lifetimes_v1(
    existing: dict[str, tuple[str, str | None]],
    compact: Mapping[str, tuple[str, str | None]],
) -> None:
    for identity, lifetime in compact.items():
        prior = existing.setdefault(identity, lifetime)
        if prior != lifetime:
            raise ToolkitInputError(
                f"native ingress capability {identity!r} has conflicting lifetimes"
            )


def compact_callback_table_declarations_v1(
    *, capability_rows: str, global_rows: str,
    target_rva_rows: str, assignment_rows: str, descriptor_rows: str,
    descriptor_range_count: int, global_count: int,
) -> str:
    return f'''static const uint32_t spx_native_compact_capability_indexes[] = {{
{capability_rows}
}};
static const uint32_t spx_native_compact_global_target_indexes[] = {{
{global_rows}
}};
static const uint32_t spx_native_compact_target_rvas[] = {{
{target_rva_rows}
}};
static volatile uint32_t spx_native_compact_target_assignments[] = {{
{assignment_rows}
}};
static const spx_native_compact_descriptor_range
spx_native_compact_descriptor_ranges[] = {{
{descriptor_rows}
}};
static const uint32_t spx_native_compact_descriptor_range_count =
    {descriptor_range_count}U;
static const uint32_t spx_native_compact_global_target_count = {global_count}U;'''


def compact_callback_capture_prefix_source_v1() -> str:
    return r'''static uint32_t spx_native_compact_capture_prefix(
    const spx_native_physical_capture *capture) {
  return capture != 0 && capture->entry_esp ==
      (uint32_t)(uintptr_t)((const uint8_t *)(const void *)capture +
                            sizeof(*capture)) ? 4U : 0U;
}'''
