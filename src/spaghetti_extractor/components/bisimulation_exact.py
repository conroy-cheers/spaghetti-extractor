"""Exact-C obligation slicing and proof-header rendering."""

from __future__ import annotations

from .bisimulation_exact_header import _render_proof_header as _render_proof_header

import hashlib
import re
from pathlib import Path
from typing import Mapping, Sequence


from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation import BisimulationOperationV1
from .bisimulation_continuation import continuation_model
from .bisimulation_support import (
    BisimulationRefinementError,
    PROOF_PRIVATE_STACK_ABOVE,
    PROOF_PRIVATE_STACK_BELOW,
    UINT32_BYTES,
    mapping as _mapping,
    rows as _rows,
    strings as _strings,
    unit_rva as _unit_rva,
)
from .bisimulation_lifetime_admission import admitted_call_specs
from .interface_ir import ProofKernelComponentInterface
from .semantic_induction import build_inductive_machine_shape


def _obligation_exact_compilation_files(
    *,
    out_dir: Path,
    exact_files: Sequence[Path],
    exact_root: Path,
    exact_c_slice: Mapping[str, object],
    operation: Mapping[str, object],
    authored: BisimulationOperationV1,
    start_unit_id: str,
    connected: bool,
    summarized_entry_rvas: frozenset[int] = frozenset(),
) -> tuple[list[Path], dict[str, object]]:
    """Materialize only the exact units reachable before the next barrier.

    Older hand-written exact-C fixtures do not carry source maps.  They retain
    the full-operation model as a compatibility path; generated exact-C slices
    are mapped and therefore must specialize successfully or fail closed.
    """

    raw_source_map = exact_c_slice.get("source_map")
    raw_functions = exact_c_slice.get("functions")
    if not isinstance(raw_source_map, list) or not raw_source_map:
        copied = _copy_exact_files(
            out_dir=out_dir,
            exact_files=exact_files,
            connected=connected,
        )
        unit_ids = list(
            _strings(exact_c_slice.get("unit_ids", []), "exact-C unit ids")
        )
        model_core: dict[str, object] = {
            "scope": "full_operation_compatibility",
            "start_unit_id": start_unit_id,
            "selected_unit_ids": unit_ids,
            "selected_unit_count": len(unit_ids),
            "files_sha256": canonical_sha256_v3(
                [hashlib.sha256(path.read_bytes()).hexdigest() for path in copied]
            ),
        }
        return copied, {
            **model_core,
            "model_sha256": canonical_sha256_v3(model_core),
        }
    if not isinstance(raw_functions, list) or not raw_functions:
        raise BisimulationRefinementError(
            "mapped exact-C slice omits its function inventory"
        )
    policy = _mapping(exact_c_slice.get("policy"), "exact-C slice policy")
    if policy.get("forced_labels_are_step_barriers") is not True:
        raise BisimulationRefinementError(
            "mapped exact-C slice does not make proof labels step barriers"
        )

    selected = _segment_exact_unit_ids(
        operation=operation,
        authored=authored,
        start_unit_id=start_unit_id,
    )
    continuation = continuation_model(operation)
    if continuation is not None:
        if not set(continuation["unit_rvas"]) <= set(exact_c_slice.get("forced_label_rvas", [])):
            raise BisimulationRefinementError("exact continuation units must be real proof barriers")
        selected.update(continuation["unit_ids"])
    source_rows = [
        _mapping(row, "exact-C source-map row") for row in raw_source_map
    ]
    source_by_unit: dict[str, Mapping[str, object]] = {}
    for row in source_rows:
        unit_id = str(row.get("unit_id", ""))
        if not unit_id or unit_id in source_by_unit:
            raise BisimulationRefinementError(
                "exact-C source map has a missing or duplicate unit"
            )
        source_by_unit[unit_id] = row
    missing = selected - set(source_by_unit)
    if missing:
        raise BisimulationRefinementError(
            "exact-C source map omits selected proof units: "
            + ", ".join(sorted(missing))
        )
    initial_selected = set(selected)
    selected = _expand_exact_direct_call_closure(
        selected_unit_ids=selected,
        exact_c_slice=exact_c_slice,
        exact_root=exact_root,
        source_by_unit=source_by_unit,
        summarized_entry_rvas=summarized_entry_rvas,
    )
    call_closure_units = selected - initial_selected

    mapped_files = {str(row.get("file", "")) for row in source_rows}
    selected_rows_by_file: dict[str, list[Mapping[str, object]]] = {}
    for unit_id in selected:
        row = source_by_unit[unit_id]
        selected_rows_by_file.setdefault(str(row.get("file", "")), []).append(row)
    selected_rvas: set[int] = set()
    for unit_id in selected:
        rva = source_by_unit[unit_id].get("rva")
        if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
            raise BisimulationRefinementError(
                f"exact-C source map has an invalid RVA for unit {unit_id!r}"
            )
        selected_rvas.add(rva)
    copied: list[Path] = []
    file_digests: list[dict[str, object]] = []
    for index, path in enumerate(exact_files):
        relative = path.relative_to(exact_root).as_posix()
        selected_rows = selected_rows_by_file.get(relative)
        if relative in mapped_files and not selected_rows:
            continue
        source = path.read_text(encoding="ascii")
        if selected_rows:
            file_selected_rvas = {
                int(row["rva"])
                for row in selected_rows
            }
            source = _specialize_exact_function_source(
                source=source,
                rows=selected_rows,
                all_rows=[row for row in source_rows if row.get("file") == relative],
                selected_rvas=file_selected_rvas,
            )
        elif path.name == "behavioral-dispatch.c":
            source = _specialize_exact_dispatch_source(
                source=source,
                selected_rvas=selected_rvas,
            )
        source = _prepare_exact_source(
            source,
            connected=connected and path.name == "behavioral-dispatch.c",
        )
        copied_path = out_dir / f"exact-{index:04d}-{path.name}"
        copied_path.write_text(source, encoding="ascii")
        copied.append(copied_path)
        file_digests.append(
            {
                "source_file": relative,
                "sha256": hashlib.sha256(source.encode("ascii")).hexdigest(),
            }
        )
    if not copied or not selected_rows_by_file:
        raise BisimulationRefinementError(
            "obligation-local exact-C slice has no compilation files"
        )
    ordered_units = [
        str(row["unit_id"])
        for row in sorted(
            (source_by_unit[unit_id] for unit_id in selected),
            key=lambda row: (str(row.get("file", "")), int(row.get("line_start", -1))),
        )
    ]
    model_core = {
        "scope": "cutpoint_segment",
        "start_unit_id": start_unit_id,
        "selected_unit_ids": ordered_units,
        "selected_unit_count": len(ordered_units),
        "files": file_digests,
        "files_sha256": canonical_sha256_v3(file_digests),
    }
    return copied, {
        **model_core,
        **({"continuation": continuation} if continuation is not None else {}),
        "internal_direct_call_unit_ids": sorted(call_closure_units),
        "internal_direct_call_unit_count": len(call_closure_units),
        "model_sha256": canonical_sha256_v3(model_core),
    }


_INTERNAL_DIRECT_CALL_EVENT = re.compile(
    r"\{\s*SPX_CALL_INTERNAL_DIRECT,\s*"
    r"0x([0-9a-fA-F]{8})U,\s*0x([0-9a-fA-F]{8})U,\s*"
    r"([0-9]+)U,\s*0x([0-9a-fA-F]{8})U,\s*"
    r"0x([0-9a-fA-F]{8})U,"
)


def _expand_exact_direct_call_closure(
    *,
    selected_unit_ids: set[str],
    exact_c_slice: Mapping[str, object],
    exact_root: Path,
    source_by_unit: Mapping[str, Mapping[str, object]],
    summarized_entry_rvas: frozenset[int] = frozenset(),
) -> set[str]:
    """Add authenticated generated functions called by one proof segment."""

    raw_closure = exact_c_slice.get("internal_direct_call_closure")
    if not isinstance(raw_closure, Mapping):
        raise BisimulationRefinementError(
            "mapped exact-C slice omits its internal direct-call closure"
        )
    closure_units = set(
        _strings(
            raw_closure.get("unit_ids"),
            "exact-C internal direct-call closure units",
        )
    )
    owned_units = set(
        _strings(exact_c_slice.get("unit_ids"), "exact-C owned/context units")
    )
    if closure_units & owned_units:
        raise BisimulationRefinementError(
            "exact-C internal direct-call closure widens component ownership"
        )
    if set(source_by_unit) != owned_units | closure_units:
        raise BisimulationRefinementError(
            "exact-C source map differs from owned and direct-call closure units"
        )

    source_by_rva: dict[int, str] = {}
    for unit_id, row in source_by_unit.items():
        rva = row.get("rva")
        if (
            not isinstance(rva, int)
            or isinstance(rva, bool)
            or not 0 <= rva <= 0xFFFFFFFF
            or rva in source_by_rva
        ):
            raise BisimulationRefinementError(
                "exact-C source map has duplicate or malformed RVAs"
            )
        source_by_rva[rva] = unit_id

    function_by_unit: dict[str, frozenset[str]] = {}
    for raw in _rows(exact_c_slice.get("functions"), "exact-C functions"):
        function = _mapping(raw, "exact-C function")
        unit_rvas = function.get("unit_rvas")
        if not isinstance(unit_rvas, list) or not unit_rvas:
            raise BisimulationRefinementError(
                "exact-C function omits its unit RVA inventory"
            )
        function_units: set[str] = set()
        for rva in unit_rvas:
            if (
                not isinstance(rva, int)
                or isinstance(rva, bool)
                or rva not in source_by_rva
            ):
                raise BisimulationRefinementError(
                    "exact-C function references an unknown unit RVA"
                )
            function_units.add(source_by_rva[rva])
        if len(function_units) != len(unit_rvas):
            raise BisimulationRefinementError(
                "exact-C function repeats a unit RVA"
            )
        frozen_units = frozenset(function_units)
        for unit_id in frozen_units:
            if unit_id in function_by_unit:
                raise BisimulationRefinementError(
                    "exact-C functions overlap in unit ownership"
                )
            function_by_unit[unit_id] = frozen_units
    if set(function_by_unit) != set(source_by_unit):
        raise BisimulationRefinementError(
            "exact-C function inventory does not partition its source map"
        )

    raw_edges = _rows(
        raw_closure.get("call_edges"), "exact-C internal direct-call edges"
    )
    edges_by_source: dict[str, set[str]] = {}
    encoded_edges: set[tuple[str, int, int, int, str, int, int]] = set()
    for raw in raw_edges:
        edge = _mapping(raw, "exact-C internal direct-call edge")
        source_unit_id = str(edge.get("source_unit_id", ""))
        target_unit_id = str(edge.get("target_unit_id", ""))
        integers = tuple(
            edge.get(field)
            for field in (
                "source_rva",
                "instruction_rva",
                "call_index",
                "target_rva",
                "return_rva",
            )
        )
        if (
            source_unit_id not in source_by_unit
            or target_unit_id not in source_by_unit
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 0xFFFFFFFF
                for value in integers
            )
            or integers[0] != source_by_unit[source_unit_id].get("rva")
            or integers[3] != source_by_unit[target_unit_id].get("rva")
        ):
            raise BisimulationRefinementError(
                "exact-C internal direct-call edge is malformed or stale"
            )
        encoded = (
            source_unit_id,
            integers[0],
            integers[1],
            integers[2],
            target_unit_id,
            integers[3],
            integers[4],
        )
        if encoded in encoded_edges:
            raise BisimulationRefinementError(
                "exact-C internal direct-call edge is duplicated"
            )
        encoded_edges.add(encoded)
        edges_by_source.setdefault(source_unit_id, set()).add(target_unit_id)

    closure_entries = raw_closure.get("entry_rvas")
    if (
        not isinstance(closure_entries, list)
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value not in source_by_rva
            for value in closure_entries
        )
        or closure_entries
        != sorted({encoded[5] for encoded in encoded_edges})
    ):
        raise BisimulationRefinementError(
            "exact-C internal direct-call entry inventory is malformed or stale"
        )

    observed_edges: set[tuple[str, int, int, int, str, int, int]] = set()
    source_cache: dict[str, list[str]] = {}
    for unit_id, row in source_by_unit.items():
        relative = str(row.get("file", ""))
        start = int(row.get("line_start", -1))
        end = int(row.get("line_end", -1))
        lines = source_cache.setdefault(
            relative,
            (exact_root / relative).read_text(encoding="ascii").splitlines(),
        )
        if start <= 0 or end < start or end > len(lines):
            raise BisimulationRefinementError(
                "exact-C source-map range is stale while checking calls"
            )
        source = "\n".join(lines[start - 1 : end])
        for match in _INTERNAL_DIRECT_CALL_EVENT.finditer(source):
            source_rva, instruction_rva, call_index, target_rva, return_rva = (
                int(value, 16 if index != 2 else 10)
                for index, value in enumerate(match.groups())
            )
            target_unit_id = source_by_rva.get(target_rva)
            if target_unit_id is None:
                raise BisimulationRefinementError(
                    f"exact-C unit {unit_id!r} calls unresolved internal target "
                    f"0x{target_rva:08x}"
                )
            observed_edges.add(
                (
                    unit_id,
                    source_rva,
                    instruction_rva,
                    call_index,
                    target_unit_id,
                    target_rva,
                    return_rva,
                )
            )
    if observed_edges != encoded_edges:
        raise BisimulationRefinementError(
            "exact-C rendered internal direct calls differ from the checked closure"
        )

    selected = set(selected_unit_ids)
    pending = list(sorted(selected, reverse=True))
    visited: set[str] = set()
    while pending:
        source_unit_id = pending.pop()
        if source_unit_id in visited:
            continue
        visited.add(source_unit_id)
        for target_unit_id in sorted(edges_by_source.get(source_unit_id, ())):
            if source_by_unit[target_unit_id]["rva"] in summarized_entry_rvas:
                continue
            called_function = function_by_unit[target_unit_id]
            added = set(called_function) - selected
            selected.update(added)
            pending.extend(sorted(added, reverse=True))
    return selected


def _copy_exact_files(
    *, out_dir: Path, exact_files: Sequence[Path], connected: bool
) -> list[Path]:
    copied: list[Path] = []
    for index, path in enumerate(exact_files):
        destination = out_dir / f"exact-{index:04d}-{path.name}"
        destination.write_text(
            _prepare_exact_source(
                path.read_text(encoding="ascii"),
                connected=connected and path.name == "behavioral-dispatch.c",
            ),
            encoding="ascii",
        )
        copied.append(destination)
    return copied


def _prepare_exact_source(source: str, *, connected: bool) -> str:
    # The deployment overlay owns the public override registry.  Private hook
    # names keep the exact side from routing through the Portable-C candidate.
    result = source.replace(
        "spx_region_override_lookup",
        "spx_proof_exact_region_override_lookup",
    ).replace(
        "spx_native_machine_fallback_allowed",
        "spx_proof_exact_native_machine_fallback_allowed",
    )
    if connected:
        result = result.replace(
            "spx_invoke_call(",
            "spx_proof_exact_invoke_call_fallback(",
        )
    return result.replace(" __attribute__((weak))", "")


def _segment_exact_unit_ids(
    *,
    operation: Mapping[str, object],
    authored: BisimulationOperationV1,
    start_unit_id: str,
) -> set[str]:
    shape = build_inductive_machine_shape(operation)
    units = {
        str(_mapping(row, "exact semantic unit").get("unit_id", ""))
        for row in _rows(shape.get("semantic_units"), "exact semantic units")
    }
    if not start_unit_id or start_unit_id not in units:
        raise BisimulationRefinementError(
            "proof obligation starts outside the exact semantic operation"
        )
    successors: dict[str, list[str]] = {}
    for raw in _rows(shape.get("control_edges"), "exact control edges"):
        edge = _mapping(raw, "exact control edge")
        source = str(edge.get("source_unit_id", ""))
        target = str(edge.get("target_unit_id", ""))
        if source not in units or target not in units:
            raise BisimulationRefinementError(
                "exact control edge leaves the semantic operation"
            )
        successors.setdefault(source, []).append(target)
    barriers = {sync.exact_unit_id for sync in authored.syncs}
    selected: set[str] = set()

    def visit(unit_id: str, active: frozenset[str]) -> None:
        if unit_id in active:
            raise BisimulationRefinementError(
                "proof barrier inventory leaves a cyclic exact-C segment"
            )
        if unit_id in selected:
            return
        selected.add(unit_id)
        nested = active | {unit_id}
        for target in successors.get(unit_id, []):
            if target in barriers:
                continue
            visit(target, nested)

    visit(start_unit_id, frozenset())
    return selected


def _specialize_exact_function_source(
    *,
    source: str,
    rows: Sequence[Mapping[str, object]],
    all_rows: Sequence[Mapping[str, object]],
    selected_rvas: set[int],
) -> str:
    if not rows or not all_rows:
        raise BisimulationRefinementError("exact-C function source map is empty")
    symbols = {str(row.get("symbol", "")) for row in all_rows}
    if len(symbols) != 1 or "" in symbols:
        raise BisimulationRefinementError(
            "obligation-local slicing requires one generated function per file"
        )
    lines = source.splitlines()
    normalized_rows = sorted(all_rows, key=lambda row: int(row.get("line_start", -1)))
    first_line = int(normalized_rows[0].get("line_start", -1))
    if first_line <= 1 or int(normalized_rows[-1].get("line_end", -1)) > len(lines):
        raise BisimulationRefinementError("exact-C source-map line range is stale")
    declaration = re.compile(r"\s*uint32_t w_([0-9a-fA-F]{8})_[0-9]+ = 0U;\Z")
    dispatch_case = re.compile(
        r"\s*case 0x([0-9a-fA-F]{8})U: goto spx_unit_[0-9a-fA-F]{8};\Z"
    )
    prefix: list[str] = []
    for line in lines[: first_line - 1]:
        match = declaration.fullmatch(line) or dispatch_case.fullmatch(line)
        if match is not None and int(match.group(1), 16) not in selected_rvas:
            continue
        prefix.append(line)
    selected_rows = sorted(rows, key=lambda row: int(row.get("line_start", -1)))
    body: list[str] = []
    for row in selected_rows:
        start = int(row.get("line_start", -1))
        end = int(row.get("line_end", -1))
        if start < first_line or end < start or end > len(lines):
            raise BisimulationRefinementError("exact-C source-map line range is stale")
        body.extend(lines[start - 1 : end])
    rendered = "\n".join([*prefix, *body])
    selected_labels = {
        int(value, 16)
        for value in re.findall(r"(?m)^spx_unit_([0-9a-fA-F]{8}):$", rendered)
    }
    if selected_labels != selected_rvas:
        raise BisimulationRefinementError(
            "obligation-local exact-C labels differ from selected units"
        )
    dangling = {
        int(value, 16)
        for value in re.findall(
            r"goto spx_unit_([0-9a-fA-F]{8});", rendered
        )
        if int(value, 16) not in selected_rvas
    }
    if dangling:
        raise BisimulationRefinementError(
            "forced proof barrier left an exact-C goto outside its segment"
        )
    last_selected_end = int(selected_rows[-1].get("line_end", -1))
    last_mapped_end = int(normalized_rows[-1].get("line_end", -1))
    if last_selected_end == last_mapped_end:
        suffix = lines[last_mapped_end:]
        if suffix:
            rendered += "\n" + "\n".join(suffix)
        elif not rendered.rstrip().endswith("}"):
            rendered += "\n}"
    else:
        rendered += "\n}"
    return _compact_exact_temporaries(rendered) + "\n"


def _compact_exact_temporaries(source: str) -> str:
    """Represent generated SSA temporaries as one proof-local word object."""

    declaration = re.compile(
        r"(?m)^  uint32_t (w_[0-9a-fA-F]{8}_[0-9]+) = 0U;$"
    )
    names = declaration.findall(source)
    if not names:
        return source
    if len(names) != len(set(names)):
        raise BisimulationRefinementError(
            "exact-C proof temporary inventory is duplicated"
        )
    first = declaration.search(source)
    if first is None:
        raise BisimulationRefinementError(
            "exact-C proof temporary inventory has no declaration"
        )
    without_declarations = declaration.sub("", source)
    insertion = (
        f"  uint32_t spx_proof_words[{len(names)}] = {{0U}};"
    )
    without_declarations = (
        without_declarations[: first.start()]
        + insertion
        + without_declarations[first.start() :]
    )
    for index, name in enumerate(names):
        without_declarations = re.sub(
            rf"\b{re.escape(name)}\b",
            f"spx_proof_words[{index}]",
            without_declarations,
        )
    return without_declarations


def _exact_stack_accesses(
    *,
    exact_files: Sequence[Path],
    service_bindings: Sequence[Mapping[str, object]],
    selected_unit_rvas: set[int] | None = None,
    reference_authority: Mapping[str, object] | None = None,
    allocation_requirements: list[Mapping[str, object]] | None = None,
) -> list[tuple[int, int]]:
    """Recover constant entry-stack accesses from generated exact SSA.

    The cache is an optimization only: accesses that cannot be established as
    affine entry-ESP addresses keep using the generic sparse memory. Admitted
    external call sites transport ESP using their checked ABI cleanup. Unknown
    calls invalidate the post-call ESP relation; earlier slots remain cacheable.
    Cache slots grant no memory permissions or stack-entry assumptions.
    """

    specs = admitted_call_specs(service_bindings, reference_authority=reference_authority,
                                allocation_requirements=allocation_requirements)
    cleanups: dict[tuple[str, int], set[int]] = {}
    for spec in specs:
        cleanups.setdefault((spec["event_kind"], int(spec["instruction_rva"])), set()).add(int(spec["callee_cleanup"]))
    call_event = re.compile(r"\b(SPX_CALL_[A-Z_]+),\s+(0x[0-9a-fA-F]+|[0-9]+)U,")
    analysis_sources = [
        _exact_stack_analysis_source(path, selected_unit_rvas=selected_unit_rvas)
        for path in exact_files
    ]
    word = r"spx_proof_words\[([0-9]+)\]"
    constant = re.compile(rf"^  {word} = (0x[0-9a-fA-F]+|[0-9]+)U;$")
    stack = re.compile(rf"^  {word} = state->esp;$")
    register_read = re.compile(
        rf"^  {word} = state->(eax|ebx|ecx|edx|esi|edi|ebp);$"
    )
    register_write = re.compile(
        rf"^  state->(eax|ebx|ecx|edx|esi|edi|ebp) = {word};$"
    )
    call_output_stack = re.compile(rf"^  {word} = call_output\.esp;$")
    binary = re.compile(
        rf"^  {word} = \(?\({word}\) ([+-]) \({word}\)\)?;$"
    )
    state_stack = re.compile(rf"^  state->esp = {word};$")
    call_input_stack = re.compile(rf"^    call_input\.esp = {word};$")
    write = re.compile(
        rf"spx_write\(rt, {word}, ([1-4])U, {word},"
    )
    read = re.compile(rf"spx_read\(rt, {word}, ([1-4])U,")
    result: set[tuple[int, int]] = set()
    affine_stack_values_written: set[int] = set()
    for source in analysis_sources:
        values: dict[int, tuple[int, int]] = {}
        registers: dict[str, tuple[int, int]] = {}
        current_stack: tuple[int, int] | None = (1, 0)
        call_stack: tuple[int, int] | None = None
        for line in source.splitlines():
            if "SPX_CALL_INTERNAL_DIRECT" in line:
                # The separately qualified callee may use an unknown ret
                # cleanup. Keep earlier affine facts, but do not project its
                # output ESP back into this caller without an explicit ABI.
                call_stack = None
                continue
            event = call_event.search(line)
            if event is not None:
                choices = cleanups.get((event.group(1), int(event.group(2), 0)), set())
                if call_stack is None or len(choices) != 1:
                    call_stack = None
                else:
                    call_stack = (call_stack[0], call_stack[1] + next(iter(choices)))
                continue
            match = constant.fullmatch(line)
            if match is not None:
                values[int(match.group(1))] = (0, int(match.group(2), 0))
                continue
            match = stack.fullmatch(line)
            if match is not None:
                if current_stack is not None:
                    values[int(match.group(1))] = current_stack
                continue
            match = register_read.fullmatch(line)
            if match is not None:
                value = registers.get(match.group(2))
                if value is not None:
                    values[int(match.group(1))] = value
                continue
            match = register_write.fullmatch(line)
            if match is not None:
                value = values.get(int(match.group(2)))
                if value is None:
                    registers.pop(match.group(1), None)
                else:
                    registers[match.group(1)] = value
                continue
            match = call_output_stack.fullmatch(line)
            if match is not None:
                if call_stack is not None:
                    values[int(match.group(1))] = call_stack
                continue
            match = binary.fullmatch(line)
            if match is not None:
                target, left, operator, right = match.groups()
                left_value = values.get(int(left))
                right_value = values.get(int(right))
                if left_value is not None and right_value is not None:
                    coefficient = (
                        left_value[0] + right_value[0]
                        if operator == "+"
                        else left_value[0] - right_value[0]
                    )
                    offset = (
                        left_value[1] + right_value[1]
                        if operator == "+"
                        else left_value[1] - right_value[1]
                    )
                    if coefficient in {0, 1}:
                        values[int(target)] = (coefficient, offset)
                continue
            match = state_stack.fullmatch(line)
            if match is not None:
                current_stack = values.get(int(match.group(1)))
                continue
            match = call_input_stack.fullmatch(line)
            if match is not None:
                call_stack = values.get(int(match.group(1)))
                continue
            match = write.search(line)
            if match is not None:
                address = values.get(int(match.group(1)))
                width = int(match.group(2))
                written = values.get(int(match.group(3)))
                if (
                    address is not None
                    and address[0] == 1
                    and -PROOF_PRIVATE_STACK_BELOW <= address[1]
                    and address[1] + width <= PROOF_PRIVATE_STACK_ABOVE
                ):
                    result.add((address[1], width))
                    if written is not None and written[0] == 1:
                        affine_stack_values_written.add(written[1])
                continue
            match = read.search(line)
            if match is not None:
                address = values.get(int(match.group(1)))
                width = int(match.group(2))
                if (
                    address is not None
                    and address[0] == 1
                    and -PROOF_PRIVATE_STACK_BELOW <= address[1]
                    and address[1] + width <= PROOF_PRIVATE_STACK_ABOVE
                ):
                    result.add((address[1], width))
                continue
    # Additional cache candidates for decoder reads. These keys need not be
    # reached: every hit still checks the actual address, width and validity.
    for spec in specs:
        result.update((int(offset), UINT32_BYTES) for offset in spec["offsets"])
        for output in spec["outputs"]:
            word_index = int(output["word_index"])
            result.update(
                (base + word_index * UINT32_BYTES, UINT32_BYTES)
                for base in affine_stack_values_written
            )
    if any(width != UINT32_BYTES or offset % UINT32_BYTES != 0
           for offset, width in result):
        return []
    return sorted(result)


_EXACT_UNIT_LABEL = re.compile(r"^spx_unit_([0-9a-fA-F]{8}):$")


def _exact_stack_analysis_source(
    path: Path, *, selected_unit_rvas: set[int] | None
) -> str:
    """Keep stack SSA only for units that execute in this obligation.

    Generated function files contain every unit in the owning definition, so
    an internal call after the next proof barrier must not disable the cache
    for an earlier call-free segment.  A resumed unit starts with its own
    arbitrary entry state, which is exactly the affine origin used by the
    analysis.
    """

    source = path.read_text(encoding="ascii")
    if selected_unit_rvas is None:
        return source
    selected: list[str] = []
    active = False
    saw_unit = False
    for line in source.splitlines():
        match = _EXACT_UNIT_LABEL.fullmatch(line)
        if match is not None:
            saw_unit = True
            active = int(match.group(1), 16) in selected_unit_rvas
        if active:
            selected.append(line)
    return "\n".join(selected) + ("\n" if saw_unit and selected else "")


def _specialize_machine_overlay_for_proof(
    source: str,
    *,
    interface: ProofKernelComponentInterface | None = None,
    service_bindings: Sequence[Mapping[str, object]] = (),
) -> str:
    """Return the exact production overlay used by native realization.

    Private-frame and typed-service rewrites used to reduce solver cost here,
    but they created an unproved semantic gap between the CBMC subject and the
    linked object.  Scaling optimizations must now happen in the shared world
    model or carry their own checked equivalence receipt.
    """

    del interface, service_bindings
    return source


def _specialize_exact_dispatch_source(
    *, source: str, selected_rvas: set[int]
) -> str:
    case = re.compile(r"(\s*)case 0x([0-9a-fA-F]{8})U:.*\Z")
    lines: list[str] = []
    for line in source.splitlines():
        match = case.fullmatch(line)
        if match is not None and int(match.group(2), 16) not in selected_rvas:
            continue
        lines.append(line)
    rendered = "\n".join(lines) + "\n"
    return re.sub(
        r"const uint32_t spx_behavioral_transfer_count = [0-9]+U;",
        f"const uint32_t spx_behavioral_transfer_count = {len(selected_rvas)}U;",
        rendered,
        count=1,
    )


def _validate_exact_slice(
    value: Mapping[str, object], root: Path, component_id: str, *, intent_sha256: str
) -> None:
    core = dict(value)
    digest = core.pop("slice_sha256", None)
    if digest != canonical_sha256_v3(core) or value.get("component_id") != component_id:
        raise BisimulationRefinementError("exact-C slice is stale or names another component")
    if _mapping(value.get("bindings"), "exact-C slice bindings").get("bisimulation_intent_sha256") != intent_sha256:
        raise BisimulationRefinementError("exact-C slice was produced for a different bisimulation intent; regenerate the slice")
    for row in _rows(value.get("files"), "exact-C files"):
        path = root / str(row.get("path", ""))
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row.get(
            "sha256"
        ):
            raise BisimulationRefinementError("exact-C slice file binding is stale")


def _exact_unit_costs(
    *, exact_c_slice: Mapping[str, object], exact_root: Path
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    """Bound byte writes, calls and internal calls per exact semantic unit."""

    writes: dict[str, int] = {}
    calls: dict[str, int] = {}
    internal_calls: dict[str, int] = {}
    source_cache: dict[str, list[str]] = {}
    for raw in _rows(exact_c_slice.get("source_map", []), "exact-C source map"):
        row = _mapping(raw, "exact-C source-map entry")
        unit_id = str(row.get("unit_id", ""))
        relative = str(row.get("file", ""))
        start = int(row.get("line_start", 0))
        end = int(row.get("line_end", 0))
        if not unit_id or start <= 0 or end < start:
            raise BisimulationRefinementError("exact-C source-map entry is malformed")
        lines = source_cache.setdefault(
            relative,
            (exact_root / relative).read_text(encoding="ascii").splitlines(),
        )
        if end > len(lines):
            raise BisimulationRefinementError("exact-C source-map range is stale")
        source = "\n".join(lines[start - 1 : end])
        writes[unit_id] = UINT32_BYTES * source.count("spx_write(")
        calls[unit_id] = source.count("spx_invoke_call(")
        internal_calls[unit_id] = source.count("SPX_CALL_INTERNAL_")
    return writes, calls, internal_calls


def _maximum_acyclic_path_cost(
    *,
    start_unit_id: str,
    selected_unit_ids: set[str],
    control_edges: Sequence[Mapping[str, object]],
    costs: Mapping[str, object],
    barrier_unit_ids: frozenset[str] = frozenset(),
) -> int:
    """Return the largest reachable unit cost before the next proof barrier."""

    if not start_unit_id or start_unit_id not in selected_unit_ids:
        raise BisimulationRefinementError(
            "acyclic proof cost starts outside its selected exact segment"
        )
    if any(
        not isinstance(cost, int) or isinstance(cost, bool) or cost < 0
        for cost in costs.values()
    ):
        raise BisimulationRefinementError("acyclic proof unit cost is malformed")
    successors: dict[str, set[str]] = {
        unit_id: set() for unit_id in selected_unit_ids
    }
    for raw in control_edges:
        edge = _mapping(raw, "exact control edge while deriving proof cost")
        source = str(edge.get("source_unit_id", ""))
        target = str(edge.get("target_unit_id", ""))
        if (source in selected_unit_ids and target in selected_unit_ids
                and target not in barrier_unit_ids):
            successors[source].add(target)

    visiting: set[str] = set()
    memo: dict[str, int] = {}

    def maximum_from(unit_id: str) -> int:
        if unit_id in memo:
            return memo[unit_id]
        if unit_id in visiting:
            raise BisimulationRefinementError(
                "proof barrier inventory leaves a cyclic cost segment"
            )
        visiting.add(unit_id)
        suffix = max(
            (maximum_from(target) for target in successors[unit_id]),
            default=0,
        )
        visiting.remove(unit_id)
        result = int(costs.get(unit_id, 0)) + suffix
        memo[unit_id] = result
        return result

    return maximum_from(start_unit_id)


def _c_function_call_site_count(source: str, symbol: str, call: str) -> int:
    """Count generated call sites in one top-level C function."""

    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None:
        raise BisimulationRefinementError("generated C function symbol is malformed")
    match = re.search(
        rf"\b{re.escape(symbol)}\s*\([^;{{}}]*\)\s*\{{",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise BisimulationRefinementError(
            f"generated C function {symbol!r} is absent"
        )
    closing = re.search(r"(?m)^}", source[match.end() :])
    if closing is None:
        raise BisimulationRefinementError(
            f"generated C function {symbol!r} is unterminated"
        )
    body = source[match.start() : match.end() + closing.end()]
    return body.count(call)


def _service_output_unit_costs(
    overlay_entry: Mapping[str, object],
    *, reference_authority: Mapping[str, object] | None = None,
    allocation_requirements: list[Mapping[str, object]] | None = None,
) -> dict[str, int]:
    result: dict[str, int] = {}
    for raw in _rows(
        overlay_entry.get("service_bindings", []), "overlay services"
    ):
        binding = _mapping(raw, "overlay service")
        specs = admitted_call_specs((binding,), reference_authority=reference_authority,
                                    allocation_requirements=allocation_requirements)
        output_cost = UINT32_BYTES * max(
            (len(spec["outputs"]) for spec in specs), default=0
        )
        for event in _rows(binding.get("events"), "overlay service events"):
            unit_id = str(event.get("unit_id", ""))
            if not unit_id:
                raise BisimulationRefinementError(
                    "overlay service event omits its exact unit"
                )
            result[unit_id] = result.get(unit_id, 0) + output_cost
    return result


def _source_service_unit_costs(
    *, overlay_sources: Sequence[str], overlay_entry: Mapping[str, object]
) -> tuple[dict[str, int], dict[str, int]]:
    writes: dict[str, int] = {}
    calls: dict[str, int] = {}
    for raw in _rows(
        overlay_entry.get("service_bindings", []), "overlay services"
    ):
        binding = _mapping(raw, "overlay service")
        symbol = str(binding.get("symbol", ""))
        defining_sources = [
            source
            for source in overlay_sources
            if _c_function_definition_present(source, symbol)
        ]
        if len(defining_sources) != 1:
            raise BisimulationRefinementError(
                f"generated C function {symbol!r} must have exactly one "
                "definition in the proof overlay closure"
            )
        defining_source = defining_sources[0]
        direct_write_cost = UINT32_BYTES * _c_function_call_site_count(
            defining_source, symbol, "spx_component_write("
        )
        call_cost = max(
            1,
            _c_function_call_site_count(
                defining_source, symbol, "spx_invoke_call("
            ),
        )
        for event in _rows(binding.get("events"), "overlay service events"):
            unit_id = str(event.get("unit_id", ""))
            if not unit_id:
                raise BisimulationRefinementError(
                    "overlay service event omits its exact unit"
                )
            writes[unit_id] = writes.get(unit_id, 0) + direct_write_cost
            calls[unit_id] = calls.get(unit_id, 0) + call_cost
    return writes, calls


def _connected_service_unit_costs(overlay_entry: Mapping[str, object], *,
                                exact_internal_calls: Mapping[str, int] | None = None) -> dict[str, int]:
    """Count caller-owned component CALL sites for region-local summary budgets.

    External services have their own path costs. Calls after the next barrier
    and callee bodies cannot inflate this region's added summary effects.
    The resulting capacities remain asserted by both proof-world histories.
    """
    costs: dict[str, int] = {}
    for raw in _rows(overlay_entry.get("service_bindings", []), "overlay services"):
        binding = _mapping(raw, "overlay service")
        if binding.get("provider_kind") != "component_operation":
            continue
        for raw_event in _rows(binding.get("events"), "connected service events"):
            event = _mapping(raw_event, "connected service event")
            unit_id = event.get("unit_id")
            if not isinstance(unit_id, str) or not unit_id:
                raise BisimulationRefinementError("connected service event omits its exact unit")
            costs[unit_id] = costs.get(unit_id, 0) + 1
    # Direct internal calls can enter a connected summary even when no typed
    # service binding exists (ordinary C calls the component's logical symbol).
    # Count those caller-owned sites too, without double-counting typed calls.
    for unit_id, count in (exact_internal_calls or {}).items():
        costs[unit_id] = max(costs.get(unit_id, 0), count)
    return costs


def _c_function_definition_present(source: str, symbol: str) -> bool:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None:
        raise BisimulationRefinementError("generated C function symbol is malformed")
    return (
        re.search(
            rf"\b{re.escape(symbol)}\s*\([^;{{}}]*\)\s*\{{",
            source,
            flags=re.DOTALL,
        )
        is not None
    )


def _obligation_functions(
    authored: BisimulationOperationV1,
    operation: Mapping[str, object],
    *,
    entry_rva: int,
    unit_rvas: Mapping[str, int] | None = None,
) -> list[dict[str, object]]:
    entry_ids = _strings(operation.get("entry_unit_ids"), "operation entries")
    if len(entry_ids) != 1 or entry_rva < 0:
        raise BisimulationRefinementError("direct bisimulation requires one operation entry")
    result: list[dict[str, object]] = [
        {
            "obligation_id": f"entry:{entry_ids[0]}",
            "start_unit_id": entry_ids[0],
            "symbol": "spx_bisimulation_check_0000",
            "start_rva": entry_rva,
            "start_code": 0,
            "sync_id": None,
        }
    ]
    resolved_unit_rvas = unit_rvas or {}
    result.extend(
        {
            "obligation_id": f"sync:{sync.identity}",
            "start_unit_id": sync.exact_unit_id,
            "symbol": f"spx_bisimulation_check_{index:04d}",
            "start_rva": (
                resolved_unit_rvas[sync.exact_unit_id]
                if sync.exact_unit_id in resolved_unit_rvas
                else _unit_rva(sync.exact_unit_id)
            ),
            "start_code": index,
            "sync_id": sync.identity,
        }
        for index, sync in enumerate(authored.syncs, 1)
    )
    return result


def _next_barrier_sync_ids(
    *,
    operation: Mapping[str, object],
    authored: BisimulationOperationV1,
    selected_unit_ids: set[str],
) -> set[str]:
    barrier_by_unit = {
        sync.exact_unit_id: sync.identity for sync in authored.syncs
    }
    result: set[str] = set()
    shape = build_inductive_machine_shape(operation)
    for raw in _rows(shape.get("control_edges"), "operation control edges"):
        edge = _mapping(raw, "operation control edge")
        if str(edge.get("source_unit_id", "")) not in selected_unit_ids:
            continue
        identity = barrier_by_unit.get(str(edge.get("target_unit_id", "")))
        if identity is not None:
            result.add(identity)
    return result
