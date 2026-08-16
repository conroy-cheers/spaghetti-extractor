"""Static target-signature extraction from canonical machine IR."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.formats import (
    LIBRARY_PROCEDURE_CANDIDATES_V3_FORMAT as PROCEDURE_CANDIDATES_V3_FORMAT,
)
from ..pe32.image import parse_pe_image
from ..util import sha256_file
from .abi_records import (
    TARGET_SIGNATURE_GRAPH_V3_FORMAT,
    LibraryAbiError,
    LibraryAbiProfileV3,
    LibraryIssueV3,
    StrictCodec,
    TargetFunctionSignatureV3,
    _array,
    _integer,
    _object,
    _sha256,
    _text,
    canonical_sha256,
    phase_status,
    stable_id,
)
from .matching_support import _load_machine_package

@dataclass(frozen=True, order=True)
class ProcedureCandidateV3:
    candidate_id: str
    unit_ids: tuple[str, ...]

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.candidate_id, "unit_ids": list(self.unit_ids)}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "ProcedureCandidateV3":
        row = _object(value, {"id", "unit_ids"}, {}, location)
        units = tuple(
            sorted(
                {
                    _text(item, f"{location}.unit_ids[{index}]")
                    for index, item in enumerate(
                        _array(row["unit_ids"], f"{location}.unit_ids")
                    )
                }
            )
        )
        if not units:
            raise LibraryAbiError(
                "procedure_candidate_empty",
                "procedure candidate contains no exact units",
                location=f"{location}.unit_ids",
            )
        return cls(_text(row["id"], f"{location}.id"), units)


@dataclass(frozen=True)
class ProcedureCandidateSetV3:
    machine_ir_sha256: str
    candidates: tuple[ProcedureCandidateV3, ...]
    candidates_sha256: str

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": PROCEDURE_CANDIDATES_V3_FORMAT,
            "machine_ir_sha256": self.machine_ir_sha256,
            "candidates": [item.to_payload() for item in self.candidates],
        }

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "candidates_sha256": self.candidates_sha256}

    @classmethod
    def create(
        cls,
        *,
        machine_ir_sha256: str,
        candidates: Iterable[ProcedureCandidateV3],
    ) -> "ProcedureCandidateSetV3":
        rows = tuple(sorted(candidates, key=lambda item: item.candidate_id))
        core = {
            "format": PROCEDURE_CANDIDATES_V3_FORMAT,
            "machine_ir_sha256": machine_ir_sha256,
            "candidates": [item.to_payload() for item in rows],
        }
        return cls(machine_ir_sha256, rows, canonical_sha256(core))

    @classmethod
    def from_payload(cls, value: object, location: str) -> "ProcedureCandidateSetV3":
        row = _object(value, {"format", "machine_ir_sha256", "candidates", "candidates_sha256"}, {}, location)
        if row["format"] != PROCEDURE_CANDIDATES_V3_FORMAT:
            raise LibraryAbiError("wrong_artifact_format", "not a v3 procedure-candidate set", location=f"{location}.format")
        result = cls(
            machine_ir_sha256=_sha256(row["machine_ir_sha256"], f"{location}.machine_ir_sha256"),
            candidates=tuple(ProcedureCandidateV3.from_payload(item, f"{location}.candidates[{index}]") for index, item in enumerate(_array(row["candidates"], f"{location}.candidates"))),
            candidates_sha256=_sha256(row["candidates_sha256"], f"{location}.candidates_sha256"),
        )
        ids = tuple(item.candidate_id for item in result.candidates)
        if tuple(sorted(set(ids))) != ids:
            raise LibraryAbiError("procedure_candidate_identity_conflict", "procedure candidate IDs must be sorted and unique", location=f"{location}.candidates")
        if canonical_sha256(result.core_payload) != result.candidates_sha256:
            raise LibraryAbiError("stale_procedure_candidates_hash", "procedure-candidate SHA-256 does not bind its contents", location=f"{location}.candidates_sha256")
        return result


PROCEDURE_CANDIDATE_SET_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), ProcedureCandidateSetV3.from_payload
)


@dataclass(frozen=True)
class TargetUnitSpanV3:
    unit_id: str
    rva_start: int
    rva_end: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.unit_id,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "TargetUnitSpanV3":
        row = _object(value, {"id", "rva_start", "rva_end"}, {}, location)
        start = _integer(row["rva_start"], f"{location}.rva_start", minimum=0)
        end = _integer(row["rva_end"], f"{location}.rva_end", minimum=1)
        if end <= start:
            raise LibraryAbiError(
                "target_unit_span_invalid",
                "unit span must be a nonempty RVA interval",
                location=location,
            )
        return cls(_text(row["id"], f"{location}.id"), start, end)


@dataclass(frozen=True)
class TargetSignatureGraphV3:
    status: str
    binary_sha256: str
    machine_ir_sha256: str
    machine_ir_manifest_sha256: str
    procedure_candidates_sha256: str | None
    original_pe_sha256: str | None
    unit_spans: tuple[TargetUnitSpanV3, ...]
    functions: tuple[TargetFunctionSignatureV3, ...]
    issues: tuple[LibraryIssueV3, ...]
    graph_sha256: str

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": TARGET_SIGNATURE_GRAPH_V3_FORMAT,
            "status": self.status,
            "executes_original_binary": False,
            "bindings": {
                "binary_sha256": self.binary_sha256,
                "machine_ir_sha256": self.machine_ir_sha256,
                "machine_ir_manifest_sha256": self.machine_ir_manifest_sha256,
                "procedure_candidates_sha256": self.procedure_candidates_sha256,
                "original_pe_sha256": self.original_pe_sha256,
            },
            "unit_spans": [item.to_payload() for item in self.unit_spans],
            "functions": [item.to_payload() for item in self.functions],
            "issues": [item.to_payload() for item in self.issues],
        }

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "graph_sha256": self.graph_sha256}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "TargetSignatureGraphV3":
        row = _object(
            value,
            {
                "format",
                "status",
                "executes_original_binary",
                "bindings",
                "unit_spans",
                "functions",
                "issues",
                "graph_sha256",
            },
            {},
            location,
        )
        if row["format"] != TARGET_SIGNATURE_GRAPH_V3_FORMAT:
            raise LibraryAbiError(
                "wrong_artifact_format",
                "not a v3 target signature graph",
                location=f"{location}.format",
            )
        if row["executes_original_binary"] is not False:
            raise LibraryAbiError(
                "original_execution_forbidden",
                "target signature graph claims original execution",
                location=f"{location}.executes_original_binary",
            )
        bindings = _object(
            row["bindings"],
            {
                "binary_sha256",
                "machine_ir_sha256",
                "machine_ir_manifest_sha256",
                "procedure_candidates_sha256",
                "original_pe_sha256",
            },
            {},
            f"{location}.bindings",
        )
        result = cls(
            status=_text(row["status"], f"{location}.status"),
            binary_sha256=_sha256(
                bindings["binary_sha256"], f"{location}.bindings.binary_sha256"
            ),
            machine_ir_sha256=_sha256(
                bindings["machine_ir_sha256"],
                f"{location}.bindings.machine_ir_sha256",
            ),
            machine_ir_manifest_sha256=_sha256(
                bindings["machine_ir_manifest_sha256"],
                f"{location}.bindings.machine_ir_manifest_sha256",
            ),
            procedure_candidates_sha256=(None if bindings["procedure_candidates_sha256"] is None else _sha256(bindings["procedure_candidates_sha256"], f"{location}.bindings.procedure_candidates_sha256")),
            original_pe_sha256=(None if bindings["original_pe_sha256"] is None else _sha256(bindings["original_pe_sha256"], f"{location}.bindings.original_pe_sha256")),
            unit_spans=tuple(
                TargetUnitSpanV3.from_payload(
                    item, f"{location}.unit_spans[{index}]"
                )
                for index, item in enumerate(
                    _array(row["unit_spans"], f"{location}.unit_spans")
                )
            ),
            functions=tuple(
                TargetFunctionSignatureV3.from_payload(
                    item, f"{location}.functions[{index}]"
                )
                for index, item in enumerate(
                    _array(row["functions"], f"{location}.functions")
                )
            ),
            issues=tuple(
                LibraryIssueV3.from_payload(
                    item, f"{location}.issues[{index}]"
                )
                for index, item in enumerate(
                    _array(row["issues"], f"{location}.issues")
                )
            ),
            graph_sha256=_sha256(
                row["graph_sha256"], f"{location}.graph_sha256"
            ),
        )
        if result.status != phase_status(result.issues):
            raise LibraryAbiError(
                "status_contradiction",
                "target graph status disagrees with its issues",
                location=f"{location}.status",
            )
        function_ids = tuple(item.function_id for item in result.functions)
        if tuple(sorted(set(function_ids))) != function_ids:
            raise LibraryAbiError(
                "target_function_identity_conflict",
                "target functions must have sorted unique IDs",
                location=f"{location}.functions",
            )
        unit_ids = tuple(item.unit_id for item in result.unit_spans)
        if tuple(sorted(set(unit_ids))) != unit_ids:
            raise LibraryAbiError(
                "target_unit_span_identity_conflict",
                "target unit spans must have sorted unique IDs",
                location=f"{location}.unit_spans",
            )
        if canonical_sha256(result.core_payload) != result.graph_sha256:
            raise LibraryAbiError(
                "stale_graph_hash",
                "target graph SHA-256 does not bind its contents",
                location=f"{location}.graph_sha256",
            )
        return result


TARGET_SIGNATURE_GRAPH_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), TargetSignatureGraphV3.from_payload
)


def _direct_control(unit: Any) -> tuple[str, tuple[int, ...]]:
    control = unit.payload.get("control")
    if not isinstance(control, Mapping):
        return "unknown", ()
    kind = str(control.get("kind", "unknown"))
    raw_targets = control.get("direct_targets", [])
    targets = tuple(
        sorted(
            {
                item
                for item in raw_targets
                if isinstance(item, int) and not isinstance(item, bool)
            }
        )
    ) if isinstance(raw_targets, list) else ()
    return kind, targets


def _structural_candidates(machine: Any) -> tuple[ProcedureCandidateV3, ...]:
    """Propose procedure-shaped CFG regions without claiming a partition."""

    by_start = {unit.start: unit for unit in machine.units}
    call_targets: set[str] = set()
    branch_edges: dict[str, set[str]] = {unit.identity: set() for unit in machine.units}
    incoming: dict[str, set[str]] = {unit.identity: set() for unit in machine.units}
    for unit in machine.units:
        kind, targets = _direct_control(unit)
        is_call = "call" in kind
        for target in targets:
            destination = by_start.get(target)
            if destination is None:
                continue
            if is_call:
                call_targets.add(destination.identity)
            else:
                branch_edges[unit.identity].add(destination.identity)
                incoming[destination.identity].add(unit.identity)
    roots = set(call_targets)
    roots.update(identity for identity, predecessors in incoming.items() if not predecessors)
    if not roots and machine.units:
        roots.add(machine.units[0].identity)

    candidates: list[ProcedureCandidateV3] = []
    covered: set[str] = set()
    for root in sorted(roots):
        pending = [root]
        membership: set[str] = set()
        while pending:
            current = pending.pop()
            if current in membership:
                continue
            membership.add(current)
            pending.extend(
                target
                for target in branch_edges[current]
                if target == root or target not in roots
            )
        covered.update(membership)
        candidates.append(
            ProcedureCandidateV3(
                stable_id(
                    "structural-procedure-candidate-v3",
                    {"root": root, "unit_ids": sorted(membership)},
                ),
                tuple(sorted(membership)),
            )
        )
    # Preserve structurally isolated or indirect-only regions as explicit weak
    # candidates instead of silently treating every block as a function.
    for unit in machine.units:
        if unit.identity in covered:
            continue
        pending = [unit.identity]
        membership: set[str] = set()
        while pending:
            current = pending.pop()
            if current in membership or current in covered:
                continue
            membership.add(current)
            pending.extend(branch_edges[current])
        covered.update(membership)
        candidates.append(
            ProcedureCandidateV3(
                stable_id(
                    "structural-procedure-candidate-v3",
                    {"root": unit.identity, "unit_ids": sorted(membership)},
                ),
                tuple(sorted(membership)),
            )
        )
    return tuple(sorted(candidates, key=lambda item: item.candidate_id))


def _load_procedure_candidates(
    source: Path | str | ProcedureCandidateSetV3 | Mapping[str, Any],
) -> ProcedureCandidateSetV3:
    if isinstance(source, ProcedureCandidateSetV3):
        return source
    if isinstance(source, Mapping):
        return PROCEDURE_CANDIDATE_SET_CODEC_V3.decode(source, "procedure-candidates")
    return PROCEDURE_CANDIDATE_SET_CODEC_V3.read(source)


def _abi_payload(unit: Mapping[str, Any]) -> object | None:
    source = unit.get("source")
    semantics = unit.get("semantics")
    for candidate in (
        unit.get("abi_envelope"),
        source.get("abi_envelope") if isinstance(source, Mapping) else None,
        semantics.get("abi_envelope") if isinstance(semantics, Mapping) else None,
    ):
        if candidate is not None:
            return candidate
    return None


def _explicit_text_features(
    value: object, names: frozenset[str]
) -> set[str]:
    result: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in names:
                if isinstance(item, str) and item:
                    result.add(item)
                elif isinstance(item, list):
                    result.update(
                        entry for entry in item if isinstance(entry, str) and entry
                    )
            if isinstance(item, (Mapping, list)):
                result.update(_explicit_text_features(item, names))
    elif isinstance(value, list):
        for item in value:
            result.update(_explicit_text_features(item, names))
    return result


def _constant_features(value: object) -> set[int]:
    result: set[int] = set()
    if isinstance(value, Mapping):
        op = value.get("op")
        if op in {"const", "constant", "bv", "literal"}:
            raw = value.get("value")
            if isinstance(raw, int) and not isinstance(raw, bool):
                result.add(raw)
        explicit = value.get("constants")
        if isinstance(explicit, list):
            result.update(
                item
                for item in explicit
                if isinstance(item, int) and not isinstance(item, bool)
            )
        for item in value.values():
            if isinstance(item, (Mapping, list)):
                result.update(_constant_features(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_constant_features(item))
    return result


def _import_features(unit: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    semantics = unit.get("semantics")
    events = semantics.get("external_events", []) if isinstance(semantics, Mapping) else []
    if not isinstance(events, list):
        return result
    for event in events:
        if not isinstance(event, Mapping):
            continue
        dll = event.get("dll")
        symbol = event.get("symbol")
        ordinal = event.get("ordinal")
        if isinstance(dll, str) and dll:
            identity = (
                symbol
                if isinstance(symbol, str) and symbol
                else f"#{ordinal}" if isinstance(ordinal, int) else "?"
            )
            result.add(f"{dll.lower()}!{identity}")
    return result


def _unit_hash(unit: Mapping[str, Any]) -> str:
    source = unit.get("source")
    if not isinstance(source, Mapping):
        raise LibraryAbiError(
            "machine_ir_source_missing",
            "machine-IR unit lacks an exact source binding",
            location=f"machine-ir:{unit.get('id', '?')}.source",
        )
    digest = source.get("instruction_bytes_sha256")
    return _sha256(
        digest,
        f"machine-ir:{unit.get('id', '?')}.source.instruction_bytes_sha256",
    )


def _contiguous_pe_bytes(
    parsed: Any, data: bytes, units: list[Any]
) -> bytes | None:
    if any(left.end != right.start for left, right in zip(units, units[1:])):
        return None
    start = units[0].start
    end = units[-1].end
    if start < parsed.size_of_headers and end <= parsed.size_of_headers:
        return data[start:end] if end <= len(data) else None
    sections = [
        section
        for section in parsed.sections
        if section.rva_start <= start and end <= section.rva_end
    ]
    if len(sections) != 1:
        return None
    section = sections[0]
    relative = start - section.rva_start
    size = end - start
    if relative + size > section.raw_size:
        return None
    offset = section.raw_pointer + relative
    return data[offset : offset + size] if offset + size <= len(data) else None


def build_target_signature_graph(
    machine_ir: Path | str,
    out: Path | str,
    *,
    procedure_candidates: (
        Path | str | ProcedureCandidateSetV3 | Mapping[str, Any] | None
    ) = None,
    original_pe: Path | str | None = None,
) -> TargetSignatureGraphV3:
    """Extract one root-independent signature graph without executing a binary."""

    machine = _load_machine_package(Path(machine_ir))
    binary = machine.manifest.get("binary")
    if not isinstance(binary, Mapping):
        raise LibraryAbiError(
            "machine_ir_binary_binding_missing",
            "machine-IR manifest has no binary binding",
            location=str(machine.manifest_path),
        )
    binary_sha256 = _sha256(
        binary.get("sha256"), f"{machine.manifest_path}.binary.sha256"
    )
    issues: list[LibraryIssueV3] = []
    procedure_binding: str | None = None
    candidate_kind = "structural_cfg"
    if procedure_candidates is None:
        candidates = _structural_candidates(machine)
        issues.append(
            LibraryIssueV3(
                "incomplete",
                "procedure_partition_missing",
                "using conservative CFG procedure candidates without a supplied partition artifact",
                "target-signature-graph.procedure-candidates",
            )
        )
    else:
        candidate_set = _load_procedure_candidates(procedure_candidates)
        procedure_binding = candidate_set.candidates_sha256
        candidate_kind = "explicit_partition"
        if candidate_set.machine_ir_sha256 != machine.ir_sha256:
            issues.append(
                LibraryIssueV3(
                    "violated",
                    "procedure_partition_machine_ir_contradiction",
                    "procedure candidates bind another machine-IR artifact",
                    "target-signature-graph.procedure-candidates",
                )
            )
        candidates = candidate_set.candidates
    known_ids = set(machine.by_id)
    membership_count: dict[str, int] = {identity: 0 for identity in known_ids}
    for candidate in candidates:
        unknown = sorted(set(candidate.unit_ids) - known_ids)
        if unknown:
            issues.append(
                LibraryIssueV3(
                    "violated",
                    "procedure_candidate_unit_unknown",
                    f"candidate names unknown exact units {unknown!r}",
                    f"procedure-candidate:{candidate.candidate_id}",
                )
            )
        for identity in set(candidate.unit_ids).intersection(known_ids):
            membership_count[identity] += 1
    uncovered = sorted(identity for identity, count in membership_count.items() if count == 0)
    overlapping = sorted(identity for identity, count in membership_count.items() if count > 1)
    if uncovered:
        issues.append(
            LibraryIssueV3(
                "incomplete",
                "procedure_partition_incomplete",
                f"exact units have no procedure candidate {uncovered!r}",
                "target-signature-graph.procedure-candidates",
            )
        )
    if overlapping:
        issues.append(
            LibraryIssueV3(
                "incomplete",
                "procedure_partition_ambiguous",
                f"exact units occur in overlapping candidates {overlapping!r}",
                "target-signature-graph.procedure-candidates",
            )
        )
    parsed_pe = None
    pe_data: bytes | None = None
    pe_binding: str | None = None
    if original_pe is not None:
        pe_path = Path(original_pe)
        pe_binding = sha256_file(pe_path)
        if pe_binding != binary_sha256:
            issues.append(
                LibraryIssueV3(
                    "violated",
                    "target_pe_machine_ir_contradiction",
                    "static original PE does not match the machine-IR binary binding",
                    "target-signature-graph.original-pe",
                )
            )
        else:
            try:
                parsed_pe = parse_pe_image(pe_path)
                pe_data = pe_path.read_bytes()
            except Exception as error:
                raise LibraryAbiError(
                    "target_pe_parse_failed",
                    str(error),
                    location=str(pe_path),
                ) from error
    functions: list[TargetFunctionSignatureV3] = []
    for candidate in candidates:
        units = [machine.by_id[item] for item in candidate.unit_ids if item in machine.by_id]
        if not units:
            continue
        units.sort(key=lambda item: (item.start, item.end, item.identity))
        location = f"target-function:{candidate.candidate_id}"
        abi_rows: list[LibraryAbiProfileV3] = []
        for unit in units:
            raw_abi = _abi_payload(unit.payload)
            if raw_abi is not None:
                abi_rows.append(
                    LibraryAbiProfileV3.from_payload(
                        raw_abi, f"machine-ir:{unit.identity}.abi_envelope"
                    )
                )
        abi_profile: LibraryAbiProfileV3 | None = None
        if not abi_rows:
            issues.append(
                LibraryIssueV3(
                    "incomplete",
                    "target_function_abi_missing",
                    "function has no complete ABI envelope",
                    location,
                )
            )
        else:
            unique_abis = {canonical_sha256(item.to_payload()): item for item in abi_rows}
            if len(unique_abis) != 1:
                issues.append(
                    LibraryIssueV3(
                        "violated",
                        "target_function_abi_contradiction",
                        "machine-IR units disagree on the function ABI envelope",
                        location,
                    )
                )
            else:
                abi_profile = next(iter(unique_abis.values()))
        unit_merkle_digest = canonical_sha256(
            {
                "scheme": "machine-ir-unit-merkle-v3",
                "units": [
                    {
                        "id": unit.identity,
                        "rva_start": unit.start,
                        "rva_end": unit.end,
                        "source_sha256": _unit_hash(unit.payload),
                    }
                    for unit in units
                ],
            }
        )
        contiguous = (
            _contiguous_pe_bytes(parsed_pe, pe_data, units)
            if parsed_pe is not None and pe_data is not None
            else None
        )
        exact_digest = sha256(contiguous).hexdigest() if contiguous is not None else None
        if parsed_pe is not None and exact_digest is None:
            issues.append(
                LibraryIssueV3(
                    "incomplete",
                    "procedure_contiguous_bytes_unavailable",
                    "candidate membership is not one exact gap-free PE byte span",
                    location,
                )
            )
        direct_calls: set[int] = set()
        cfg_rows: list[dict[str, Any]] = []
        imports: set[str] = set()
        constants: set[int] = set()
        strings: set[str] = set()
        data_refs: set[str] = set()
        for ordinal, unit in enumerate(units):
            payload = unit.payload
            control = payload.get("control")
            direct_targets = []
            kind = "unknown"
            indirect = False
            if isinstance(control, Mapping):
                kind = str(control.get("kind", "unknown"))
                raw_targets = control.get("direct_targets", [])
                if isinstance(raw_targets, list):
                    direct_targets = [
                        target
                        for target in raw_targets
                        if isinstance(target, int) and not isinstance(target, bool)
                    ]
                indirect = bool(control.get("has_indirect_target", False))
            if kind in {"call", "direct_call", "internal_call"}:
                direct_calls.update(direct_targets)
            internal_indexes = []
            external_deltas = []
            for target in sorted(set(direct_targets)):
                destination = next(
                    (
                        index
                        for index, candidate in enumerate(units)
                        if candidate.start == target
                    ),
                    None,
                )
                if destination is None:
                    external_deltas.append(target - units[0].start)
                else:
                    internal_indexes.append(destination)
            cfg_rows.append(
                {
                    "ordinal": ordinal,
                    "kind": kind,
                    "internal_targets": internal_indexes,
                    "external_target_deltas": external_deltas,
                    "indirect": indirect,
                }
            )
            imports.update(_import_features(payload))
            constants.update(_constant_features(payload))
            strings.update(
                _explicit_text_features(
                    payload,
                    frozenset({"strings", "string_literals", "literal_strings"}),
                )
            )
            data_refs.update(
                _explicit_text_features(
                    payload,
                    frozenset({"data_refs", "data_references", "global_refs"}),
                )
            )
        function_id = stable_id(
            "target-function-v3",
            {
                "machine_ir_sha256": machine.ir_sha256,
                "procedure_candidate_id": candidate.candidate_id,
                "unit_ids": sorted(unit.identity for unit in units),
            },
        )
        functions.append(
            TargetFunctionSignatureV3(
                function_id=function_id,
                candidate_kind=candidate_kind,
                unit_ids=tuple(sorted(unit.identity for unit in units)),
                rva_start=min(unit.start for unit in units),
                rva_end=max(unit.end for unit in units),
                normalized_bytes_sha256=None,
                exact_bytes_sha256=exact_digest,
                unit_merkle_sha256=unit_merkle_digest,
                cfg_sha256=canonical_sha256(cfg_rows),
                direct_call_rvas=tuple(sorted(direct_calls)),
                imports=tuple(sorted(imports)),
                constants=tuple(sorted(constants)),
                strings=tuple(sorted(strings)),
                data_refs=tuple(sorted(data_refs)),
                abi_profile=abi_profile,
                bytes_hex=None if contiguous is None else contiguous.hex(),
            )
        )
    functions.sort(key=lambda item: item.function_id)
    issues.sort()
    placeholder = TargetSignatureGraphV3(
        status=phase_status(issues),
        binary_sha256=binary_sha256,
        machine_ir_sha256=machine.ir_sha256,
        machine_ir_manifest_sha256=machine.manifest_sha256,
        procedure_candidates_sha256=procedure_binding,
        original_pe_sha256=pe_binding,
        unit_spans=tuple(
            TargetUnitSpanV3(unit.identity, unit.start, unit.end)
            for unit in sorted(machine.units, key=lambda item: item.identity)
        ),
        functions=tuple(functions),
        issues=tuple(issues),
        graph_sha256="0" * 64,
    )
    result = TargetSignatureGraphV3(
        **{
            **placeholder.__dict__,
            "graph_sha256": canonical_sha256(placeholder.core_payload),
        }
    )
    TARGET_SIGNATURE_GRAPH_CODEC_V3.write(out, result)
    return result


__all__ = [
    "TARGET_SIGNATURE_GRAPH_CODEC_V3",
    "PROCEDURE_CANDIDATE_SET_CODEC_V3",
    "PROCEDURE_CANDIDATES_V3_FORMAT",
    "ProcedureCandidateSetV3",
    "ProcedureCandidateV3",
    "TargetSignatureGraphV3",
    "TargetUnitSpanV3",
    "build_target_signature_graph",
]
