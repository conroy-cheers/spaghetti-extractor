"""Checked original write footprints at the input of an existing proof segment.

Write and cut-transport facts are checked separately. Neither establishes
callee entry, heap lifetime, or authorization to omit a callee body.
"""
from __future__ import annotations

from pathlib import Path

from .bisimulation_exact_frame import PhysicalFrameSpec, run_physical_frame_probe, validate_physical_frame, MUTABLE_ACTIVE
from .bisimulation_view_extent import view_extent_expressions
from .bisimulation_mutable_machine_frame import mutable_machine_frame_declarations, mutable_machine_frame_probes
from . import bisimulation_private_frame as private_frame
from . import bisimulation_clobber_frame as clobber_frame
from .bisimulation_support import BisimulationRefinementError


FRAME = PhysicalFrameSpec("exact_mutable_memory_frame", "original-physical-view-write-frame-v1",
    "__CPROVER_spx_exact_view_memory_frame", "spx-bisimulation-exact-view-memory-frame",
    "__CPROVER_spx_exact_mutable_frame_", "exact-mutable-frame")
CUT_FRAME = PhysicalFrameSpec("exact_mutable_cut_frame", "original-fixed-writable-cut-transport-v1",
    "__CPROVER_spx_exact_writable_cut_frame", "spx-bisimulation-exact-writable-cut-frame",
    "__CPROVER_spx_exact_mutable_cut_frame_", "exact-mutable-cut-frame")
ACTIVE = MUTABLE_ACTIVE
ENTRY_PREFIX = "__CPROVER_spx_mutable_entry_"
BASES = "__CPROVER_spx_mutable_frame_bases"


def authored_frame_configuration(authored, logical_projection, *, mutable_views, image_frame):
    """Validate authored frame requests against the supported proof probes."""
    if authored.private_stack_accesses is not None and not image_frame:
        raise BisimulationRefinementError("private access footprint requires a supported image/shared leaf operation")
    clobbers = authored.machine_clobbers
    results = clobber_frame.result_registers(logical_projection) if clobbers else ()
    private_writes = authored.private_stack_writes
    if (clobbers or private_writes) and not mutable_views:
        raise BisimulationRefinementError("checked clobber/private frames require a supported mutable operation and checked memory dependencies")
    return clobbers, results, private_writes


def mutable_frame_views(interface, operation_id, connected):
    operation = interface.operation_index()[operation_id]
    # A checked body-free child exposes its writes through the same original
    # runtime, so the enclosing footprint guard checks them too. External
    # service ranges also pass through that guard. This selects a probe; it
    # does not qualify a service or authorize body-free composition.
    if any(row.get("summary_strategy") not in {
            "image-readable-body-free-v1", "image-mutable-body-free-v1"} for row in connected):
        return ()
    types = interface.type_index()
    views = []
    for value in interface.state:
        typ = types[value.type_id]
        if (value.initial_value.to_value() is not None or typ.kind != "view" or typ.nullable
                or typ.extent_kind != "fixed" or not 0 < typ.fixed_extent <= 0xffffffff):
            return ()
        if typ.access in {"write", "read_write"}:
            views.append(("state:" + value.identity, typ.fixed_extent))
    if any(effect.kind != "memory" for effect in interface.effects
           if effect.identity in operation.effect_ids):
        return ()
    for value in operation.parameters:
        typ = types[value.type_id]
        if typ.kind != "view" or typ.access not in {"write", "read_write"}:
            continue
        if typ.nullable or typ.extent_kind != "fixed" or not 0 < typ.fixed_extent <= 0xffffffff:
            return ()
        views.append((value.identity, typ.fixed_extent))
    return tuple(sorted(views))


def mutable_frame_declarations(views, private_stack_writes=()):
    if not views:
        return ""
    transported = " || ".join(f"(index == {i}U && address == {BASES}[{i}] && "
        f"requested == UINT64_C({size}) && visible == UINT64_C({size}))" for i, (_, size) in enumerate(views))
    lines = [f"static uint32_t {ACTIVE};", f"static uint32_t {BASES}[{len(views)}];",
             f"void {CUT_FRAME.guard}(uint32_t index, uint64_t address, uint64_t requested, uint64_t visible) {{",
             f'  __CPROVER_assert(({ACTIVE} != 2U && {ACTIVE} != 3U && {ACTIVE} != 4U) || ({transported}), "{CUT_FRAME.description}");', "}",
             f"void {FRAME.guard}(uint32_t permitted) {{",
             f'  __CPROVER_assert({ACTIVE} == 0U || ' + (f'{private_frame.ACTIVE} != 0U || ' if private_stack_writes else '') + f'permitted, "{FRAME.description}");', "}",
             "static uint32_t spx_proof_mutable_write_permitted(uint32_t address, uint32_t width) {",
             "  uint32_t permitted = width >= 1U && width <= 4U && (uint64_t)address + width <= UINT64_C(4294967296);"]
    # A write may cross adjacent grants. Every byte must be in their union;
    # neither an origin's larger extent nor a private-stack classification grants writes.
    for byte in range(4):
        tests = [f"((uint64_t)address + {byte}U >= {BASES}[{index}] && "
                 f"(uint64_t)address + {byte}U < (uint64_t){BASES}[{index}] + UINT64_C({size}))"
                 for index, (_, size) in enumerate(views)]
        lines.append(f"  if (width > {byte}U) permitted = permitted && ({' || '.join(tests)});")
    return "\n".join([*lines, "  return permitted;", "}", "", mutable_machine_frame_declarations()])


def mutable_frame_write_check(views):
    return (f"  {FRAME.guard}(world != &spx_exact_world || spx_proof_mutable_write_permitted(address, width));\n"
            if views else "")


def _frame_projections(views, operation_projection, sync):
    projections = ({row["id"]: row["projection"] for row in operation_projection["parameters"]}
                   if sync is None else {c.identity: c.projection for c in sync.captures if c.mode == "machine_codec"})
    state = {row["id"]: row for row in operation_projection.get("state", [])}
    for identity, size in views:
        if not identity.startswith("state:"):
            continue
        row = state.get(identity.removeprefix("state:"), {})
        entry = row.get("entry", {})
        # Only fixed image bindings transport shared state without a capture.
        # A register-derived or changed binding needs an explicit relation and
        # is deliberately outside this frame rule.
        constant = {"kind": "constant", "width": 32, "value": size}
        base = entry.get("base", {})
        if (entry.get("kind") != "view" or entry.get("at") != "entry"
                or row.get("exit") != {**entry, "at": "exit"}
                or entry.get("extent") != constant or entry.get("requested_extent") != constant
                or base.get("kind") != "constant" or base.get("width") != 32
                or type(base.get("value")) is not int or not 0 < base["value"] <= (1 << 32) - size
                or entry.get("authority", {}).get("kind") != "image"
                or entry["authority"].get("lifetime") != "image"):
            raise BisimulationRefinementError("shared writable frame requires unchanged fixed image state bindings")
        projections[identity] = entry
    return projections


def mutable_frame_initialization(views, operation_projection, sync):
    projections = _frame_projections(views, operation_projection, sync)
    lines = []
    for index, (identity, size) in enumerate(views):
        extents = view_extent_expressions(projections=projections, identity=identity,
            nul_view_ids=frozenset(), state="initial_state", read="spx_proof_exact_input_read")
        lines += [f"  {BASES}[{index}] = (uint32_t)({extents['address']});",
                  f"  {FRAME.guard}((uint64_t)({extents['requested']}) == UINT64_C({size}) && "
                  f"(uint64_t)({extents['visible']}) == UINT64_C({size}) && "
                  f"(uint64_t)({extents['address']}) + UINT64_C({size}) <= UINT64_C(4294967296));"]
    if views:
        size = views[0][1]
        # Keep a named property even on final segments with no outgoing cuts.
        lines.append(f"  {CUT_FRAME.guard}(0U, {BASES}[0], UINT64_C({size}), UINT64_C({size}));")
    return lines


def mutable_cut_frame_checks(views, sync, operation_projection=None):
    projections = _frame_projections(views, operation_projection or {}, sync)
    lines = []
    for index, (identity, _) in enumerate(views):
        extents = view_extent_expressions(projections=projections, identity=identity,
            nul_view_ids=frozenset(), state="spx_proof_exact_output", read="spx_proof_exact_output_read")
        lines.append(f"    {CUT_FRAME.guard}({index}U, (uint64_t)({extents['address']}), "
                     f"(uint64_t)({extents['requested']}), (uint64_t)({extents['visible']}));")
    return lines


def mutable_frame_probe_source(proof_function, private_stack_writes=()):
    return "".join(f"\nvoid {spec.entry(proof_function)}(void) {{\n  {ACTIVE} = {mode}U;\n  {proof_function}();\n}}\n"
                   for spec, mode in ((FRAME, 1), (CUT_FRAME, 2))) + (
        f"\nvoid {ENTRY_PREFIX}{proof_function}(void) {{\n  {ACTIVE} = 3U;\n  {proof_function}();\n}}\n") + mutable_machine_frame_probes(proof_function, private_stack_writes)


def run_mutable_frame_probe(**kwargs):
    ranges = private_frame.parse_stack_writes(kwargs["task"].get("private_stack_writes", []))
    return {**run_physical_frame_probe(**kwargs, spec=FRAME),
            **run_physical_frame_probe(**kwargs, spec=CUT_FRAME),
            **{key: value for spec in (private_frame.specs(ranges) if ranges else ())
               for key, value in run_physical_frame_probe(**kwargs, spec=spec).items()}}


def validate_mutable_frame(value, **kwargs):
    return validate_physical_frame(value, **kwargs, spec=FRAME)


def validate_mutable_cut_frame(value, **kwargs):
    return validate_physical_frame(value, **kwargs, spec=CUT_FRAME)


def checked_fixed_writable_frame_operations(proof, *, artifacts, runtime_assurance=None):
    """Export physical write confinement after ordinary supplier validation.

    Both facts must cover every segment. The cut relation in the ordinary proof
    transports state; the additional theorem keeps its projected writable
    footprint fixed. This says nothing about caller entry or allocation lifetime.
    """
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(proof, runtime_assurance)
    if proof.get("status") != "satisfied":
        return ()
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    complete = []
    for operation_index, operation in enumerate(proof["models"]["operation_models"]):
        covered = bool(operation["obligation_models"])
        for index, model in enumerate(operation["obligation_models"]):
            shard = shards[(operation["operation_id"], model["obligation_id"])]
            for spec in (FRAME, CUT_FRAME):
                value = shard.get(spec.field)
                if value is None or value["result"]["status"] != "satisfied":
                    covered = False
                    continue
                validate_physical_frame(value, model=model, shard=shard, checker=proof["checker"], runtime_assurance=runtime_assurance, spec=spec,
                    artifacts=Path(artifacts) / f"operation-{operation_index:04d}-obligation-{index:04d}")
        if covered:
            complete.append(operation["operation_id"])
    return tuple(complete)

