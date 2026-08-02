"""Generate Lean-checked static machine contracts for PE import boundaries.

Profile JSON and state-machine JSONL are proposal inputs.  The generated Lean
module reparses the exact PE imports and re-decodes each direct or import-thunk
route before exposing a boundary-indexed ``MachineImportCallContract``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ...artifact_formats import STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
from ...errors import StageAInputError
from ...machine_import_profiles import (
    MachineImportProfileError,
    load_machine_import_profile_graph,
)
from ...stage_binary import StageABinary, _parse_stage_a_pe
from ..contract import _machine_import_call_contracts
from .expressions import (
    _lean_external_target,
    _lean_machine_call_memory_footprint,
    _lean_machine_call_memory_size,
)


STATIC_MACHINE_IMPORT_FORMAT = STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
STATIC_MACHINE_IMPORT_MODULE = "GeneratedStaticMachineImportContracts"
_ABI_NAMES = {
    "pe32-cdecl-v1": "cdecl",
    "pe32-stdcall-v1": "stdcall",
}
_CALLBACK_MODES = {
    "none": "none",
    "registration": "registration",
    "nested_frames": "nestedFrames",
}
_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_MODULE = re.compile(r"StageA\.[A-Za-z_][A-Za-z0-9_']*\Z")


class StaticMachineImportContractError(StageAInputError):
    """The static machine-import proposal is malformed."""


@dataclass(frozen=True, order=True)
class StaticImportIdentity:
    dll: str
    symbol: str | None = None
    ordinal: int | None = None

    def __post_init__(self) -> None:
        if not self.dll or not self.dll.isascii():
            raise StaticMachineImportContractError(
                "import DLL identities must be nonempty ASCII"
            )
        if (self.symbol is None) == (self.ordinal is None):
            raise StaticMachineImportContractError(
                "import identity requires exactly one symbol or ordinal"
            )
        if self.symbol is not None and (
            not self.symbol or not self.symbol.isascii()
        ):
            raise StaticMachineImportContractError(
                "import symbols must be nonempty ASCII"
            )
        if self.ordinal is not None and not 0 <= self.ordinal <= 0xFFFF:
            raise StaticMachineImportContractError(
                "import ordinal is outside the PE16 range"
            )
        object.__setattr__(self, "dll", self.dll.lower())

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], *, context: str
    ) -> "StaticImportIdentity":
        dll = value.get("dll")
        symbol = value.get("symbol")
        ordinal = value.get("ordinal")
        if not isinstance(dll, str):
            raise StaticMachineImportContractError(f"{context}.dll must be a string")
        if symbol is not None and not isinstance(symbol, str):
            raise StaticMachineImportContractError(
                f"{context}.symbol must be a string"
            )
        if ordinal is not None and not isinstance(ordinal, int):
            raise StaticMachineImportContractError(
                f"{context}.ordinal must be an integer"
            )
        return cls(dll=dll, symbol=symbol, ordinal=ordinal)

    @property
    def display(self) -> str:
        name = self.symbol if self.symbol is not None else f"#{self.ordinal}"
        return f"{self.dll}!{name}"

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {"dll": self.dll}
        if self.symbol is not None:
            result["symbol"] = self.symbol
        else:
            result["ordinal"] = self.ordinal
        return result


@dataclass(frozen=True)
class StaticMachineImportLeanBindings:
    module: str
    namespace: str
    pe: str = "originalPe"
    import_certificate: str = "originalImportCertificate"

    def validate(self) -> None:
        if not _MODULE.fullmatch(self.module):
            raise StaticMachineImportContractError(
                "exact PE binding module must be one local StageA module"
            )
        if not _IDENTIFIER.fullmatch(self.namespace):
            raise StaticMachineImportContractError(
                "exact PE binding namespace is not a Lean identifier"
            )
        for field, value in (
            ("pe", self.pe),
            ("import_certificate", self.import_certificate),
        ):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_']*", value):
                raise StaticMachineImportContractError(
                    f"exact PE binding {field} is not a local Lean identifier"
                )

    def qualified(self, symbol: str) -> str:
        return f"{self.namespace}.{symbol}"


@dataclass(frozen=True)
class StaticMachineImportSignature:
    id: int
    identity: StaticImportIdentity
    abi: str
    arity_kind: str
    minimum_words: int
    format_argument: int | None
    format_unit_bytes: int | None
    callback_mode: str
    contract: Mapping[str, Any]
    profile_id: str

    @property
    def bridgeable(self) -> bool:
        return (
            self.callback_mode != "nestedFrames"
            and self.contract["disposition"] != "protocol"
        )

    def argument_words(self, recovered_offsets: Sequence[int]) -> int | None:
        if self.arity_kind == "fixed":
            return self.minimum_words
        if not recovered_offsets:
            return None
        unique = sorted(set(recovered_offsets))
        if unique != list(range(0, (unique[-1] // 4 + 1) * 4, 4)):
            return None
        words = unique[-1] // 4 + 1
        return words if words >= self.minimum_words else None

    def to_json(self) -> dict[str, Any]:
        arity: dict[str, Any]
        if self.arity_kind == "fixed":
            arity = {"kind": "fixed", "words": self.minimum_words}
        else:
            arity = {
                "kind": "variadic",
                "minimum_words": self.minimum_words,
                "format_argument": self.format_argument,
                "format_unit_bytes": self.format_unit_bytes,
            }
        return {
            "id": self.id,
            "import": self.identity.to_json(),
            "abi": self.abi,
            "arity": arity,
            "callback_mode": self.callback_mode,
            "bridgeable": self.bridgeable,
            "profile_id": self.profile_id,
            "disposition": self.contract["disposition"],
            "memory_effect": self.contract["memory_effect"],
            "memory_footprints": self.contract["memory_footprints"],
            "world_effect": self.contract["world_effect"],
        }


@dataclass(frozen=True)
class StaticMachineImportBoundary:
    id: int
    signature_id: int
    identity: StaticImportIdentity
    source_rva: int
    source_size: int
    instruction_rva: int
    execution_source_rva: int
    continuation_rva: int
    argument_words: int
    route: str
    thunk_rva: int | None = None
    thunk_size: int | None = None
    frame_entry_rva: int | None = None
    frame_entry_size: int | None = None
    tail_rva: int | None = None
    tail_size: int | None = None
    dispatch_register: str | None = None
    iat_rva: int | None = None
    seed_rva: int | None = None
    seed_size: int | None = None
    restore_rva: int | None = None
    restore_size: int | None = None
    saved_stack_offset: int | None = None
    argument_evidence: str = "profile_fixed"

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "signature_id": self.signature_id,
            "import": self.identity.to_json(),
            "source_rva": self.source_rva,
            "source_size": self.source_size,
            "instruction_rva": self.instruction_rva,
            "execution_source_rva": self.execution_source_rva,
            "continuation_rva": self.continuation_rva,
            "argument_words": self.argument_words,
            "route": self.route,
            "thunk_rva": self.thunk_rva,
            "thunk_size": self.thunk_size,
            "frame_entry_rva": self.frame_entry_rva,
            "frame_entry_size": self.frame_entry_size,
            "tail_rva": self.tail_rva,
            "tail_size": self.tail_size,
            "dispatch_register": self.dispatch_register,
            "iat_rva": self.iat_rva,
            "seed_rva": self.seed_rva,
            "seed_size": self.seed_size,
            "restore_rva": self.restore_rva,
            "restore_size": self.restore_size,
            "saved_stack_offset": self.saved_stack_offset,
            "argument_evidence": self.argument_evidence,
        }


@dataclass(frozen=True, order=True)
class StaticMachineImportBlocker:
    reason_code: str
    identity: str
    source_rva: int | None
    instruction_rva: int | None
    detail: str
    next_action: str

    @property
    def blocker_id(self) -> str:
        location = "global" if self.source_rva is None else f"{self.source_rva:08x}"
        digest = hashlib.sha256(
            f"{self.reason_code}\0{self.identity}\0{location}\0{self.detail}".encode()
        ).hexdigest()[:16]
        return f"machine-import:{self.reason_code}:{location}:{digest}"

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.blocker_id,
            "reason_code": self.reason_code,
            "import": self.identity,
            "source_rva": self.source_rva,
            "instruction_rva": self.instruction_rva,
            "detail": self.detail,
            "next_action": self.next_action,
        }


@dataclass(frozen=True)
class StaticMachineImportPlan:
    original_pe: Path
    original_sha256: str
    reference_contract_sha256: str
    state_machine_sha256: str
    exact_import_count: int
    required: tuple[StaticImportIdentity, ...]
    signatures: tuple[StaticMachineImportSignature, ...]
    boundaries: tuple[StaticMachineImportBoundary, ...]
    blockers: tuple[StaticMachineImportBlocker, ...]
    diagnostics: tuple[Mapping[str, Any], ...]
    exact_inventory_matches: bool

    @property
    def profile_ready(self) -> bool:
        profile_codes = {
            "exact_import_inventory_mismatch",
            "missing_machine_import_profile",
            "ambiguous_machine_import_profile",
            "invalid_machine_import_profile",
        }
        return self.exact_inventory_matches and len(self.signatures) == len(
            self.required
        ) and not any(item.reason_code in profile_codes for item in self.blockers)

    @property
    def complete(self) -> bool:
        return self.profile_ready and not self.blockers

    @property
    def global_contracts_ready(self) -> bool:
        return self.profile_ready and all(
            signature.arity_kind == "fixed" and signature.bridgeable
            for signature in self.signatures
        )

    @property
    def global_contract_residuals(self) -> tuple[Mapping[str, Any], ...]:
        residuals: list[Mapping[str, Any]] = []
        for signature in self.signatures:
            if signature.arity_kind == "variadic":
                reason = "variadic_requires_boundary_contract"
            elif not signature.bridgeable:
                reason = "nested_frames_require_boundary_contract"
            else:
                continue
            residuals.append({
                "import": signature.identity.display,
                "reason_code": reason,
            })
        return tuple(residuals)

    def to_json(self) -> dict[str, Any]:
        covered = {item.identity for item in self.boundaries}
        return {
            "format": STATIC_MACHINE_IMPORT_FORMAT,
            "status": "ready" if self.complete else "incomplete",
            "authority": {
                "profile_status_fields_trusted": False,
                "lean_reparses_exact_pe_imports": True,
                "lean_redecodes_boundary_routes": True,
                "whole_path_evidence_accepted": False,
            },
            "inputs": {
                "original_pe": str(self.original_pe),
                "original_sha256": self.original_sha256,
                "reference_contract_sha256": self.reference_contract_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "counts": {
                "exact_pe_imports": self.exact_import_count,
                "required_reachable_imports": len(self.required),
                "lean_profile_signatures": len(self.signatures),
                "checked_boundary_proposals": len(self.boundaries),
                "imports_with_boundary_proposals": len(covered),
                "blockers": len(self.blockers),
                "diagnostics": len(self.diagnostics),
            },
            "global_contract_export": {
                "status": "ready" if self.global_contracts_ready else "incomplete",
                "residuals": list(self.global_contract_residuals),
            },
            "exact_inventory_matches": self.exact_inventory_matches,
            "required_imports": [item.to_json() for item in self.required],
            "signatures": [item.to_json() for item in self.signatures],
            "boundaries": [item.to_json() for item in self.boundaries],
            "blockers": [item.to_json() for item in self.blockers],
            "diagnostics": list(self.diagnostics),
            "remaining_premises": sorted(
                {item.reason_code for item in self.blockers}
            ),
        }


@dataclass(frozen=True)
class _Control:
    rva: int
    size: int
    mnemonic: str
    iat_identity: StaticImportIdentity | None = None
    direct_target_rva: int | None = None
    dispatch_register: str | None = None
    register_iat_identity: StaticImportIdentity | None = None
    register_iat_rva: int | None = None
    register_load_rva: int | None = None
    restored_register_iat: "_RestoredRegisterIATRoute | None" = None


@dataclass(frozen=True)
class _RegisterIATLoad:
    rva: int
    register: str
    identity: StaticImportIdentity
    iat_rva: int


@dataclass(frozen=True)
class _RestoredRegisterIATRoute:
    seed_rva: int
    seed_size: int
    restore_rva: int
    restore_size: int
    saved_stack_offset: int


@dataclass(frozen=True)
class _StateMachineRow:
    rva: int
    size: int
    control: _Control | None
    event_offsets: Mapping[StaticImportIdentity, tuple[int, ...]]
    reachable: bool
    function_key: str | None
    register_iat_loads: tuple[_RegisterIATLoad, ...] = ()
    control_rvas: tuple[int, ...] = ()


def plan_static_machine_import_contracts(
    *,
    original_pe: Path | str,
    reference_contract: Path | str,
    state_machine: Path | str,
    required_imports: Iterable[StaticImportIdentity | Mapping[str, Any]],
    reachable_source_rvas: Iterable[int],
    profile_paths: Sequence[Path | str],
) -> StaticMachineImportPlan:
    """Build a deterministic proposal; no JSON status can authorize a proof."""

    pe_path = Path(original_pe)
    reference_path = Path(reference_contract)
    state_path = Path(state_machine)
    required = tuple(sorted({_identity(item) for item in required_imports}))
    reachable = set(reachable_source_rvas)
    if not reachable:
        raise StaticMachineImportContractError("reachable source inventory is empty")

    binary = _parse_stage_a_pe(pe_path)
    try:
        exact = tuple(
            StaticImportIdentity(
                dll=item.dll, symbol=item.symbol, ordinal=item.ordinal
            )
            for item in binary.imports
        )
        exact_rows = tuple(
            (identity, item.thunk_rva)
            for identity, item in zip(exact, binary.imports, strict=True)
        )
        reference_rows = _reference_import_inventory(reference_path)
        inventory_matches = exact_rows == reference_rows
        blockers: list[StaticMachineImportBlocker] = []
        if not inventory_matches:
            blockers.append(_blocker(
                "exact_import_inventory_mismatch",
                None,
                None,
                None,
                "reference_contract.json original imports differ from the parsed PE",
                "regenerate the static export from this exact original PE",
            ))

        rows = _load_state_machine_rows(
            binary, state_path, reachable, exact_rows
        )
        rows = _promote_cross_region_register_imports(rows)
        discovered_register_imports = {
            row.control.register_iat_identity
            for row in rows
            if (
                row.reachable
                and row.control is not None
                and row.control.register_iat_identity is not None
            )
        }
        required = tuple(sorted(set(required) | discovered_register_imports))
        if not required:
            raise StaticMachineImportContractError(
                "required import inventory is empty"
            )

        exact_set = set(exact)
        for identity in required:
            if identity not in exact_set:
                blockers.append(_blocker(
                    "required_import_absent_from_exact_pe",
                    identity,
                    None,
                    None,
                    "required reachable identity is absent from the exact PE import table",
                    "repair reachable-import extraction or provide the matching original PE",
                ))

        signatures, profile_blockers = _load_signatures(
            binary, required, profile_paths
        )
        blockers.extend(profile_blockers)
        signature_by_identity = {item.identity: item for item in signatures}
        rows = _promote_stack_restored_register_imports(
            binary, rows, signature_by_identity
        )
        boundaries, boundary_blockers, diagnostics = _propose_boundaries(
            rows, required, signature_by_identity
        )
        blockers.extend(boundary_blockers)

        return StaticMachineImportPlan(
            original_pe=pe_path,
            original_sha256=_sha256_file(pe_path),
            reference_contract_sha256=_sha256_file(reference_path),
            state_machine_sha256=_sha256_file(state_path),
            exact_import_count=len(exact),
            required=required,
            signatures=tuple(signatures),
            boundaries=tuple(boundaries),
            blockers=tuple(sorted(set(blockers))),
            diagnostics=tuple(diagnostics),
            exact_inventory_matches=inventory_matches,
        )
    finally:
        binary.pe.close()


def write_static_machine_import_contracts(
    out: Path | str,
    plan: StaticMachineImportPlan,
    bindings: StaticMachineImportLeanBindings,
    *,
    output_module: str = STATIC_MACHINE_IMPORT_MODULE,
    namespace: str = "StageA.GeneratedRelational.StaticMachineImports",
) -> tuple[Path, Path]:
    """Write generated Lean data and the actionable blocker report."""

    bindings.validate()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_']*", output_module):
        raise StaticMachineImportContractError("output module is not a Lean name")
    if not _IDENTIFIER.fullmatch(namespace):
        raise StaticMachineImportContractError("output namespace is not a Lean name")
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    lean_path = stage_a / f"{output_module}.lean"
    lean_path.write_text(
        _lean_source(plan, bindings, namespace), encoding="utf-8"
    )
    report_path = root / "machine-import-contract-report.json"
    report_path.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return lean_path, report_path


def _identity(
    value: StaticImportIdentity | Mapping[str, Any]
) -> StaticImportIdentity:
    if isinstance(value, StaticImportIdentity):
        return value
    if not isinstance(value, Mapping):
        raise StaticMachineImportContractError(
            "required imports must be identities or mappings"
        )
    return StaticImportIdentity.from_mapping(value, context="required import")


def _reference_import_inventory(
    path: Path,
) -> tuple[tuple[StaticImportIdentity, int | None], ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticMachineImportContractError(
            f"cannot read reference contract {path}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping) or not isinstance(payload.get("original"), Mapping):
        raise StaticMachineImportContractError(
            "reference contract has no original object"
        )
    rows = payload["original"].get("imports")
    if not isinstance(rows, list):
        raise StaticMachineImportContractError(
            "reference contract original.imports must be a list"
        )
    result: list[tuple[StaticImportIdentity, int | None]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise StaticMachineImportContractError(
                f"reference original.imports[{index}] must be an object"
            )
        thunk = row.get("thunk_rva")
        if thunk is not None and not isinstance(thunk, int):
            raise StaticMachineImportContractError(
                f"reference original.imports[{index}].thunk_rva must be an integer"
            )
        result.append((
            StaticImportIdentity.from_mapping(
                row, context=f"reference original.imports[{index}]"
            ),
            thunk,
        ))
    return tuple(result)


def _load_signatures(
    binary: StageABinary,
    required: Sequence[StaticImportIdentity],
    profile_paths: Sequence[Path | str],
) -> tuple[list[StaticMachineImportSignature], list[StaticMachineImportBlocker]]:
    selected: dict[StaticImportIdentity, tuple[Mapping[str, Any], str]] = {}
    ambiguous: set[StaticImportIdentity] = set()

    for path, payload in _load_profile_graph(profile_paths):
        profile_id = payload["id"]
        assert isinstance(profile_id, str)
        entries: list[Any] = []
        for key in ("machine_import_call_contracts", "machine_import_signatures"):
            value = payload.get(key, [])
            if not isinstance(value, list):
                raise StaticMachineImportContractError(
                    f"{path} {key} must be a list"
                )
            entries.extend(value)
        for index, entry in enumerate(entries):
            if not isinstance(entry, Mapping) or not isinstance(entry.get("import"), Mapping):
                raise StaticMachineImportContractError(
                    f"{path} profile entry {index} must contain an import object"
                )
            identity = StaticImportIdentity.from_mapping(
                entry["import"], context=f"{path} entry {index}.import"
            )
            if identity not in required:
                continue
            prior = selected.get(identity)
            if prior is None or entry.get("override") is True:
                selected[identity] = (entry, profile_id)
                ambiguous.discard(identity)
            elif prior[0].get("override") is not True:
                ambiguous.add(identity)

    blockers: list[StaticMachineImportBlocker] = []
    signatures: list[StaticMachineImportSignature] = []
    for signature_id, identity in enumerate(required):
        if identity in ambiguous:
            blockers.append(_blocker(
                "ambiguous_machine_import_profile", identity, None, None,
                "more than one profile declares this exact import identity",
                "retain one declarative profile or mark one explicit override",
            ))
            continue
        selected_entry = selected.get(identity)
        if selected_entry is None:
            blockers.append(_blocker(
                "missing_machine_import_profile", identity, None, None,
                "no ABI/argument/memory/world profile covers this reachable import",
                "add a generic platform or CRT machine signature with explicit effects",
            ))
            continue
        entry, profile_id = selected_entry
        try:
            signatures.append(_normalize_signature(
                binary, identity, signature_id, entry, profile_id
            ))
        except StaticMachineImportContractError as exc:
            blockers.append(_blocker(
                "invalid_machine_import_profile", identity, None, None,
                str(exc),
                "repair the declarative ABI, argument, memory, result, and world fields",
            ))
    return signatures, blockers


def _load_profile_graph(
    profile_paths: Sequence[Path | str],
) -> tuple[tuple[Path, Mapping[str, Any]], ...]:
    """Compatibility shape over the canonical shared profile-graph loader."""

    try:
        loaded = load_machine_import_profile_graph(profile_paths)
    except MachineImportProfileError as exc:
        raise StaticMachineImportContractError(str(exc)) from exc
    return tuple((profile.path, profile.payload) for profile in loaded)


def _normalize_signature(
    binary: StageABinary,
    identity: StaticImportIdentity,
    signature_id: int,
    entry: Mapping[str, Any],
    profile_id: str,
) -> StaticMachineImportSignature:
    abi_template = entry.get("abi_template")
    abi = _ABI_NAMES.get(abi_template) if isinstance(abi_template, str) else None
    if abi is None:
        raise StaticMachineImportContractError("unknown or missing machine ABI")

    if "arity" in entry:
        arity = entry.get("arity")
        if not isinstance(arity, Mapping):
            raise StaticMachineImportContractError("arity must be an object")
        kind = arity.get("kind")
        if kind == "fixed":
            words = arity.get("words")
            format_argument = None
            format_unit_bytes = None
        elif kind == "variadic":
            words = arity.get("minimum_words")
            format_argument = arity.get("format_argument")
            format_unit_bytes = arity.get("format_unit_bytes")
            if (
                not isinstance(words, int)
                or not isinstance(format_argument, int)
                or not isinstance(format_unit_bytes, int)
                or format_argument < 0
                or format_argument >= words
                or format_unit_bytes not in {1, 2}
            ):
                raise StaticMachineImportContractError(
                    "variadic arity requires a bounded format argument and unit width"
                )
        else:
            raise StaticMachineImportContractError("unknown arity kind")
    else:
        kind = "fixed"
        words = entry.get("argument_words")
        format_argument = None
        format_unit_bytes = None
    if not isinstance(words, int) or not 0 <= words <= 256:
        raise StaticMachineImportContractError(
            "argument arity must contain between 0 and 256 words"
        )

    disposition = entry.get("disposition", "returns")
    callback_raw = entry.get("callback_behavior")
    world_effect = entry.get("world_effect")
    if callback_raw is None:
        callback_raw = (
            "nested_frames" if disposition == "protocol"
            else "registration" if world_effect == "callbackRegistration"
            else "none"
        )
    callback_mode = _CALLBACK_MODES.get(callback_raw)
    if callback_mode is None:
        raise StaticMachineImportContractError("unknown callback behavior")

    raw = dict(entry)
    for key in ("arity", "callback_behavior", "override"):
        raw.pop(key, None)
    raw["id"] = signature_id
    raw["argument_words"] = words
    raw["import"] = identity.to_json()
    # The legacy shape forbids protocol+relationalState.  Normalize the common
    # ABI/effect fields as a returning transition, then retain the explicit
    # nested-frame protocol in the richer signature.
    if callback_mode == "nestedFrames":
        raw["disposition"] = "returns"
    issues: list[dict[str, Any]] = []
    normalized = _machine_import_call_contracts(
        [raw], binary, binary, issues
    )
    if issues or len(normalized) != 1:
        categories = sorted({str(item.get("category")) for item in issues})
        raise StaticMachineImportContractError(
            "machine contract normalization failed"
            + (f" ({', '.join(categories)})" if categories else "")
        )
    contract = dict(normalized[0])
    contract["disposition"] = disposition
    return StaticMachineImportSignature(
        id=signature_id,
        identity=identity,
        abi=abi,
        arity_kind=str(kind),
        minimum_words=words,
        format_argument=format_argument,
        format_unit_bytes=format_unit_bytes,
        callback_mode=callback_mode,
        contract=contract,
        profile_id=profile_id,
    )


def _load_state_machine_rows(
    binary: StageABinary,
    path: Path,
    reachable: set[int],
    exact_imports: Sequence[tuple[StaticImportIdentity, int | None]],
) -> tuple[_StateMachineRow, ...]:
    iat_by_va = {
        binary.image_base + thunk: identity
        for identity, thunk in exact_imports
        if thunk is not None
    }
    rows: list[_StateMachineRow] = []
    seen: set[int] = set()
    try:
        source = path.open(encoding="utf-8")
    except OSError as exc:
        raise StaticMachineImportContractError(
            f"cannot read state machine {path}: {exc}"
        ) from exc
    with source:
        for line_number, line in enumerate(source, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StaticMachineImportContractError(
                    f"invalid state-machine JSON on line {line_number}: {exc}"
                ) from exc
            if not isinstance(value, Mapping) or not isinstance(value.get("original"), Mapping):
                raise StaticMachineImportContractError(
                    f"state-machine line {line_number} has no original span"
                )
            original = value["original"]
            rva = original.get("rva_start")
            size = original.get("size")
            end = original.get("rva_end")
            if not all(isinstance(item, int) for item in (rva, size, end)):
                raise StaticMachineImportContractError(
                    f"state-machine line {line_number} has a non-integer span"
                )
            assert isinstance(rva, int) and isinstance(size, int) and isinstance(end, int)
            if size <= 0 or rva + size != end or rva in seen:
                raise StaticMachineImportContractError(
                    f"state-machine line {line_number} has an invalid or duplicate span"
                )
            seen.add(rva)
            events = _event_offsets(value.get("external_events", []), line_number)
            control, ordered_identity, ordered_offsets = _exact_control(
                binary,
                value.get("instructions", []),
                value.get("ordered_events", []),
                iat_by_va,
            )
            if ordered_identity is not None:
                events.setdefault(ordered_identity, ordered_offsets)
            register_iat_loads = _exact_register_iat_loads(
                binary, value.get("instructions", []), iat_by_va
            )
            control_rvas = _exact_control_rvas(
                binary, value.get("instructions", [])
            )
            function_key = value.get("function")
            if not isinstance(function_key, str) or not function_key:
                function_key = None
            rows.append(_StateMachineRow(
                rva, size, control, events, rva in reachable, function_key,
                register_iat_loads, control_rvas,
            ))
    missing = sorted(reachable - {row.rva for row in rows})
    if missing:
        raise StaticMachineImportContractError(
            f"reachable source inventory contains {len(missing)} absent state-machine RVAs"
        )
    return tuple(sorted(rows, key=lambda item: item.rva))


def _exact_register_iat_loads(
    binary: StageABinary,
    instructions: Any,
    iat_by_va: Mapping[int, StaticImportIdentity],
) -> tuple[_RegisterIATLoad, ...]:
    if not isinstance(instructions, list):
        return ()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    result: list[_RegisterIATLoad] = []
    for item in instructions:
        if not isinstance(item, Mapping):
            continue
        rva = item.get("rva")
        size = item.get("size")
        raw_hex = item.get("bytes")
        if not isinstance(rva, int) or not isinstance(size, int) or not isinstance(raw_hex, str):
            continue
        try:
            proposed = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        if not proposed or len(proposed) != size:
            continue
        exact = bytes(binary.pe.get_data(rva, size))
        if exact != proposed:
            continue
        decoded = list(decoder.disasm(exact, binary.image_base + rva, count=1))
        if len(decoded) != 1 or decoded[0].size != size:
            continue
        instruction = decoded[0]
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (
            destination.type != X86_OP_REG
            or source.type != X86_OP_MEM
            or source.mem.base != 0
            or source.mem.index != 0
        ):
            continue
        address = int(source.mem.disp) & 0xFFFFFFFF
        identity = iat_by_va.get(address)
        if identity is None or address < binary.image_base:
            continue
        result.append(_RegisterIATLoad(
            rva=rva,
            register=instruction.reg_name(destination.reg),
            identity=identity,
            iat_rva=address - binary.image_base,
        ))
    return tuple(result)


def _exact_control_rvas(
    binary: StageABinary, instructions: Any
) -> tuple[int, ...]:
    if not isinstance(instructions, list):
        return ()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    result: list[int] = []
    for item in instructions:
        if not isinstance(item, Mapping):
            continue
        rva = item.get("rva")
        size = item.get("size")
        raw_hex = item.get("bytes")
        if not isinstance(rva, int) or not isinstance(size, int) or not isinstance(raw_hex, str):
            continue
        try:
            proposed = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        if not proposed or len(proposed) != size:
            continue
        exact = bytes(binary.pe.get_data(rva, size))
        if exact != proposed:
            continue
        decoded = list(decoder.disasm(exact, binary.image_base + rva, count=1))
        if len(decoded) != 1 or decoded[0].size != size:
            continue
        instruction = decoded[0]
        if any(
            instruction.group(group)
            for group in (
                capstone.CS_GRP_JUMP,
                capstone.CS_GRP_CALL,
                capstone.CS_GRP_RET,
                capstone.CS_GRP_INT,
                capstone.CS_GRP_IRET,
            )
        ):
            result.append(rva)
    return tuple(result)


def _promote_cross_region_register_imports(
    rows: Sequence[_StateMachineRow],
) -> tuple[_StateMachineRow, ...]:
    loads = tuple(
        load
        for row in rows
        for load in row.register_iat_loads
        if row.reachable
    )
    control_rvas = tuple(
        control_rva for row in rows for control_rva in row.control_rvas
    )
    promoted: list[_StateMachineRow] = []
    for row in rows:
        control = row.control
        if (
            not row.reachable
            or control is None
            or control.dispatch_register is None
            or control.register_iat_identity is not None
        ):
            promoted.append(row)
            continue
        candidates = [
            load
            for load in loads
            if load.register == control.dispatch_register
            and load.rva < control.rva
            and control.rva - load.rva <= 256
            and not any(
                load.rva < intervening < control.rva
                for intervening in control_rvas
            )
        ]
        if not candidates:
            promoted.append(row)
            continue
        nearest_rva = max(load.rva for load in candidates)
        nearest = [load for load in candidates if load.rva == nearest_rva]
        if len(nearest) != 1:
            promoted.append(row)
            continue
        load = nearest[0]
        promoted.append(replace(
            row,
            control=replace(
                control,
                register_iat_identity=load.identity,
                register_iat_rva=load.iat_rva,
                register_load_rva=load.rva,
            ),
        ))
    return tuple(promoted)


def _decode_exact_row(
    binary: StageABinary, row: _StateMachineRow
) -> tuple[Any, ...]:
    data = bytes(binary.pe.get_data(row.rva, row.size))
    if len(data) != row.size:
        return ()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = tuple(decoder.disasm(data, binary.image_base + row.rva))
    if (
        not instructions
        or sum(instruction.size for instruction in instructions) != row.size
    ):
        return ()
    return instructions


def _stack_store_offset(instruction: Any, register: str) -> int | None:
    if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
        return None
    destination, source = instruction.operands
    if (
        destination.type != X86_OP_MEM
        or destination.size != 4
        or destination.mem.base == 0
        or instruction.reg_name(destination.mem.base) != "esp"
        or destination.mem.index != 0
        or source.type != X86_OP_REG
        or instruction.reg_name(source.reg) != register
    ):
        return None
    displacement = int(destination.mem.disp)
    return displacement if 0 <= displacement < 2 ^ 32 else None


def _stack_write_offset(instruction: Any) -> int | None:
    if len(instruction.operands) < 1:
        return None
    destination = instruction.operands[0]
    if (
        destination.type != X86_OP_MEM
        or destination.size != 4
        or destination.mem.base == 0
        or instruction.reg_name(destination.mem.base) != "esp"
        or destination.mem.index != 0
    ):
        return None
    displacement = int(destination.mem.disp)
    return displacement if 0 <= displacement < 2 ^ 32 else None


def _stack_load_offset(instruction: Any, register: str) -> int | None:
    if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
        return None
    destination, source = instruction.operands
    if (
        destination.type != X86_OP_REG
        or instruction.reg_name(destination.reg) != register
        or source.type != X86_OP_MEM
        or source.size != 4
        or source.mem.base == 0
        or instruction.reg_name(source.mem.base) != "esp"
        or source.mem.index != 0
    ):
        return None
    displacement = int(source.mem.disp)
    return displacement if 0 <= displacement < 2 ^ 32 else None


def _writes_register(instruction: Any, register: str) -> bool:
    try:
        _reads, writes = instruction.regs_access()
    except capstone.CsError:
        return True
    return register in {
        instruction.reg_name(register_id) for register_id in writes
    }


def _esp_adjustment_before(
    instructions: Sequence[Any], stop_index: int
) -> int | None:
    adjustment = 0
    for instruction in instructions[:stop_index]:
        if not _writes_register(instruction, "esp"):
            continue
        if instruction.mnemonic not in {"add", "sub"} or len(
            instruction.operands
        ) != 2:
            return None
        destination, amount = instruction.operands
        if (
            destination.type != X86_OP_REG
            or instruction.reg_name(destination.reg) != "esp"
            or amount.type != X86_OP_IMM
        ):
            return None
        value = int(amount.imm) & 0xFFFFFFFF
        adjustment += value if instruction.mnemonic == "add" else -value
    return adjustment


def _stack_result_delta(signature: StaticMachineImportSignature) -> int:
    return signature.minimum_words * 4 if signature.abi == "stdcall" else 0


def _row_reaches(
    binary: StageABinary, row: _StateMachineRow, target_rva: int
) -> bool:
    control = row.control
    if control is None:
        instructions = _decode_exact_row(binary, row)
        if not instructions:
            return False
        terminal = instructions[-1]
        if (
            terminal.group(capstone.CS_GRP_JUMP)
            and terminal.operands
            and terminal.operands[0].type == X86_OP_IMM
        ):
            target = int(terminal.operands[0].imm) & 0xFFFFFFFF
            target_rva_value = (
                target - binary.image_base
                if target >= binary.image_base
                else target
            )
            return (
                target_rva_value == target_rva
                or terminal.address - binary.image_base + terminal.size
                == target_rva
            )
        return row.rva + row.size == target_rva
    if control.mnemonic.startswith("j"):
        return (
            control.direct_target_rva == target_rva
            or control.rva + control.size == target_rva
        )
    return row.rva + row.size == target_rva


def _restored_register_route(
    binary: StageABinary,
    rows: Sequence[_StateMachineRow],
    dispatch: _StateMachineRow,
    signatures: Mapping[
        StaticImportIdentity, StaticMachineImportSignature
    ],
) -> tuple[_RegisterIATLoad, _RestoredRegisterIATRoute] | None:
    control = dispatch.control
    if (
        not dispatch.reachable
        or control is None
        or control.mnemonic != "call"
        or control.dispatch_register is None
        or control.register_iat_identity is not None
    ):
        return None
    dispatch_instructions = _decode_exact_row(binary, dispatch)
    if not dispatch_instructions:
        return None
    dispatch_call_index = next(
        (
            index
            for index, instruction in enumerate(dispatch_instructions)
            if instruction.address - binary.image_base == control.rva
        ),
        None,
    )
    if dispatch_call_index is None or any(
        _writes_register(instruction, control.dispatch_register)
        for instruction in dispatch_instructions[:dispatch_call_index]
    ):
        return None

    candidates: list[tuple[_RegisterIATLoad, _RestoredRegisterIATRoute]] = []
    rows_by_rva = {row.rva: row for row in rows}
    for seed in rows:
        seed_control = seed.control
        if (
            not seed.reachable
            or seed.rva >= dispatch.rva
            or dispatch.rva - seed.rva > 1024
            or seed_control is None
            or seed_control.mnemonic != "call"
            or seed_control.dispatch_register != control.dispatch_register
            or seed_control.register_iat_identity is None
            or seed_control.register_iat_rva is None
            or seed_control.register_load_rva is None
            or seed_control.rva + seed_control.size != seed.rva + seed.size
        ):
            continue
        signature = signatures.get(seed_control.register_iat_identity)
        if signature is None or signature.contract["memory_effect"] not in {
            "none",
            "readOnly",
        }:
            continue
        stack_delta = _stack_result_delta(signature)
        seed_instructions = _decode_exact_row(binary, seed)
        save_rows = [
            (index, offset)
            for index, instruction in enumerate(seed_instructions)
            if (offset := _stack_store_offset(
                instruction, control.dispatch_register
            )) is not None
            and instruction.address - binary.image_base < seed_control.rva
        ]
        if not save_rows:
            continue
        save_index, save_offset = save_rows[-1]
        if save_offset < max(stack_delta, signature.minimum_words * 4):
            continue
        if any(
            _stack_write_offset(instruction) == save_offset
            for instruction in seed_instructions[save_index + 1 :]
        ):
            continue

        restore = rows_by_rva.get(seed.rva + seed.size)
        if restore is None or not restore.reachable or not _row_reaches(
            binary, restore, dispatch.rva
        ):
            continue
        restore_instructions = _decode_exact_row(binary, restore)
        restore_rows = [
            (index, offset)
            for index, instruction in enumerate(restore_instructions)
            if (offset := _stack_load_offset(
                instruction, control.dispatch_register
            )) is not None
        ]
        if len(restore_rows) != 1:
            continue
        restore_index, restore_offset = restore_rows[0]
        adjustment = _esp_adjustment_before(
            restore_instructions, restore_index
        )
        if adjustment is None or (
            stack_delta + adjustment + restore_offset
        ) % (2 ^ 32) != save_offset:
            continue
        if any(
            _writes_register(instruction, control.dispatch_register)
            for instruction in restore_instructions[restore_index + 1 :]
        ):
            continue
        load = _RegisterIATLoad(
            rva=seed_control.register_load_rva,
            register=control.dispatch_register,
            identity=seed_control.register_iat_identity,
            iat_rva=seed_control.register_iat_rva,
        )
        candidates.append((
            load,
            _RestoredRegisterIATRoute(
                seed_rva=seed.rva,
                seed_size=seed.size,
                restore_rva=restore.rva,
                restore_size=restore.size,
                saved_stack_offset=save_offset,
            ),
        ))
    return candidates[0] if len(candidates) == 1 else None


def _promote_stack_restored_register_imports(
    binary: StageABinary,
    rows: Sequence[_StateMachineRow],
    signatures: Mapping[
        StaticImportIdentity, StaticMachineImportSignature
    ],
) -> tuple[_StateMachineRow, ...]:
    promoted: list[_StateMachineRow] = []
    for row in rows:
        route = _restored_register_route(binary, rows, row, signatures)
        if route is None or row.control is None:
            promoted.append(row)
            continue
        load, restored = route
        promoted.append(replace(
            row,
            control=replace(
                row.control,
                register_iat_identity=load.identity,
                register_iat_rva=load.iat_rva,
                register_load_rva=load.rva,
                restored_register_iat=restored,
            ),
        ))
    return tuple(promoted)


def _event_offsets(value: Any, line_number: int) -> dict[StaticImportIdentity, tuple[int, ...]]:
    if not isinstance(value, list):
        raise StaticMachineImportContractError(
            f"state-machine line {line_number} external_events must be a list"
        )
    result: dict[StaticImportIdentity, tuple[int, ...]] = {}
    for index, event in enumerate(value):
        if not isinstance(event, Mapping) or not isinstance(event.get("dll"), str):
            continue
        symbol = event.get("symbol")
        ordinal = event.get("ordinal")
        if symbol is None and ordinal is None:
            continue
        identity = StaticImportIdentity(
            dll=event["dll"],
            symbol=symbol if isinstance(symbol, str) else None,
            ordinal=ordinal if isinstance(ordinal, int) else None,
        )
        stack = event.get("stack_inputs", [])
        if not isinstance(stack, list):
            raise StaticMachineImportContractError(
                f"state-machine line {line_number} event {index} stack_inputs must be a list"
            )
        offsets = tuple(
            int(item["offset"])
            for item in stack
            if isinstance(item, Mapping)
            and isinstance(item.get("offset"), int)
            and item.get("width") == 4
        )
        result[identity] = offsets
    return result


def _exact_register_iat_load_rva(
    binary: StageABinary,
    instructions: Any,
    *,
    dispatch_register: str,
    iat_rva: int,
    control_rva: int,
) -> int | None:
    """Find the final exact absolute-IAT load feeding a register call.

    Returning the load RVA lets Lean check the smallest contiguous route.  It
    avoids importing unrelated earlier stack writes into the static route
    certificate while retaining all intervening instructions for re-decoding.
    """

    if not isinstance(instructions, list):
        return None
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    expected_next = control_rva
    for item in reversed(instructions):
        if not isinstance(item, Mapping):
            return None
        rva = item.get("rva")
        size = item.get("size")
        raw_hex = item.get("bytes")
        if not isinstance(rva, int) or not isinstance(size, int) or not isinstance(raw_hex, str):
            return None
        if rva >= control_rva:
            continue
        try:
            proposed = bytes.fromhex(raw_hex)
        except ValueError:
            return None
        if size != len(proposed) or rva + size != expected_next:
            return None
        exact = bytes(binary.pe.get_data(rva, size))
        if not exact or exact != proposed:
            return None
        decoded = list(decoder.disasm(exact, binary.image_base + rva, count=1))
        if len(decoded) != 1 or decoded[0].size != size:
            return None
        instruction = decoded[0]
        expected_next = rva
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (
            destination.type != X86_OP_REG
            or instruction.reg_name(destination.reg) != dispatch_register
            or source.type != X86_OP_MEM
            or source.mem.base != 0
            or source.mem.index != 0
            or (int(source.mem.disp) & 0xFFFFFFFF)
            != binary.image_base + iat_rva
        ):
            continue
        return rva
    return None


def _exact_control(
    binary: StageABinary,
    instructions: Any,
    ordered_events: Any,
    iat_by_va: Mapping[int, StaticImportIdentity],
) -> tuple[_Control | None, StaticImportIdentity | None, tuple[int, ...]]:
    if not isinstance(instructions, list):
        return None, None, ()
    control_row: Mapping[str, Any] | None = None
    for item in reversed(instructions):
        if isinstance(item, Mapping) and item.get("mnemonic") in {"call", "jmp"}:
            control_row = item
            break
    if control_row is None:
        return None, None, ()
    rva = control_row.get("rva")
    raw_hex = control_row.get("bytes")
    if not isinstance(rva, int) or not isinstance(raw_hex, str):
        return None, None, ()
    try:
        proposed = bytes.fromhex(raw_hex)
    except ValueError:
        return None, None, ()
    exact = bytes(binary.pe.get_data(rva, len(proposed)))
    if not proposed or exact != proposed:
        return None, None, ()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = list(decoder.disasm(exact, binary.image_base + rva, count=1))
    if len(decoded) != 1 or decoded[0].size != len(exact):
        return None, None, ()
    instruction = decoded[0]
    if instruction.mnemonic not in {"call", "jmp"} or len(instruction.operands) != 1:
        return None, None, ()
    operand = instruction.operands[0]
    if operand.type == X86_OP_MEM:
        memory = operand.mem
        if memory.base == 0 and memory.index == 0:
            target = int(memory.disp) & 0xFFFFFFFF
            return _Control(
                rva=rva,
                size=instruction.size,
                mnemonic=instruction.mnemonic,
                iat_identity=iat_by_va.get(target),
            ), None, ()
    if operand.type == X86_OP_IMM:
        target_va = int(operand.imm) & 0xFFFFFFFF
        target_rva = target_va - binary.image_base
        if 0 <= target_rva < binary.size_of_image:
            return _Control(
                rva=rva,
                size=instruction.size,
                mnemonic=instruction.mnemonic,
                direct_target_rva=target_rva,
            ), None, ()
    register = None
    if operand.type == X86_OP_REG:
        register = instruction.reg_name(operand.reg)
    ordered_identity, ordered_iat_rva, ordered_offsets = _ordered_iat_call(
        ordered_events, iat_by_va, binary.image_base, instruction.address - binary.image_base
    )
    register_load_rva = None
    if register is not None and ordered_iat_rva is not None:
        register_load_rva = _exact_register_iat_load_rva(
            binary,
            instructions,
            dispatch_register=register,
            iat_rva=ordered_iat_rva,
            control_rva=rva,
        )
    return _Control(
        rva=rva,
        size=instruction.size,
        mnemonic=instruction.mnemonic,
        dispatch_register=register,
        register_iat_identity=ordered_identity if register is not None else None,
        register_iat_rva=ordered_iat_rva if register is not None else None,
        register_load_rva=register_load_rva,
    ), ordered_identity if register is not None else None, ordered_offsets


def _ordered_iat_call(
    events: Any,
    iat_by_va: Mapping[int, StaticImportIdentity],
    image_base: int,
    instruction_rva: int,
) -> tuple[StaticImportIdentity | None, int | None, tuple[int, ...]]:
    if not isinstance(events, list):
        return None, None, ()
    for event in events:
        if (
            not isinstance(event, Mapping)
            or event.get("kind") != "indirect_call"
            or event.get("instruction_rva") != instruction_rva
        ):
            continue
        target = event.get("target")
        if not isinstance(target, Mapping) or target.get("op") != "load":
            continue
        address = target.get("address")
        if not isinstance(address, Mapping) or address.get("op") != "const":
            continue
        value = address.get("value")
        if not isinstance(value, int):
            continue
        identity = iat_by_va.get(value)
        if identity is None or not image_base <= value < 2**32:
            continue
        stack = event.get("stack_inputs", [])
        offsets = tuple(
            int(item["offset"])
            for item in stack
            if isinstance(item, Mapping)
            and isinstance(item.get("offset"), int)
            and item.get("width") == 4
        ) if isinstance(stack, list) else ()
        return identity, value - image_base, offsets
    return None, None, ()


def _propose_boundaries(
    rows: Sequence[_StateMachineRow],
    required: Sequence[StaticImportIdentity],
    signatures: Mapping[StaticImportIdentity, StaticMachineImportSignature],
) -> tuple[
    list[StaticMachineImportBoundary],
    list[StaticMachineImportBlocker],
    list[Mapping[str, Any]],
]:
    required_set = set(required)
    thunk_rows = {
        row.rva: row
        for row in rows
        if row.control is not None
        and row.control.mnemonic == "jmp"
        and row.control.iat_identity in required_set
    }
    function_entries = {
        function_key: min(
            (row for row in rows if row.function_key == function_key),
            key=lambda row: row.rva,
        )
        for function_key in {
            row.function_key for row in rows if row.function_key is not None
        }
    }
    callers_by_target: dict[int, list[_StateMachineRow]] = {}
    for caller in rows:
        if (
            caller.reachable
            and caller.control is not None
            and caller.control.mnemonic == "call"
            and caller.control.direct_target_rva is not None
        ):
            callers_by_target.setdefault(
                caller.control.direct_target_rva, []
            ).append(caller)
    boundaries: list[StaticMachineImportBoundary] = []
    boundary_keys: set[tuple[int, int, StaticImportIdentity, int]] = set()
    blockers: list[StaticMachineImportBlocker] = []
    diagnostics: list[Mapping[str, Any]] = []
    covered: set[StaticImportIdentity] = set()
    explicit_frontiers: set[StaticImportIdentity] = set()

    for row in rows:
        if not row.reachable:
            continue
        control = row.control
        if control is None:
            for identity in row.event_offsets:
                if identity in required_set:
                    blockers.append(_blocker(
                        "unreduced_import_control", identity, row.rva, None,
                        "static evidence names an import but exact control decoding did not recover a route",
                        "recover an exact IAT target or checked finite import-thunk path",
                    ))
                    explicit_frontiers.add(identity)
            continue
        identity = control.iat_identity
        route = "direct"
        thunk: _StateMachineRow | None = None
        if identity is None and control.register_iat_identity is not None:
            identity = control.register_iat_identity
            route = (
                "restored_register_indirect"
                if control.restored_register_iat is not None
                else "register_indirect"
            )
        if identity is None and control.direct_target_rva is not None:
            thunk = thunk_rows.get(control.direct_target_rva)
            if thunk is not None and thunk.control is not None:
                identity = thunk.control.iat_identity
                route = "via_thunk"
        if identity not in required_set:
            for event_identity in row.event_offsets:
                if event_identity in required_set:
                    blockers.append(_blocker(
                        "unreduced_import_control", event_identity, row.rva,
                        control.rva,
                        "exact control does not resolve to the event's declared IAT identity",
                        "recover an exact IAT target or checked finite import-thunk path",
                    ))
                    explicit_frontiers.add(event_identity)
            continue
        assert identity is not None
        if route in {
            "register_indirect",
            "restored_register_indirect",
        } and control.register_load_rva is None:
            blockers.append(_blocker(
                "register_import_seed_not_exact",
                identity,
                row.rva,
                control.rva,
                "the register-dispatched import has no exact contiguous absolute-IAT load",
                "recover the final exact IAT load and all instructions through the call",
            ))
            explicit_frontiers.add(identity)
            continue
        signature = signatures.get(identity)
        if signature is None:
            continue
        offsets = row.event_offsets.get(identity, ())
        argument_words = signature.argument_words(offsets)
        if argument_words is None:
            # A generic variadic IAT thunk has no call-site arity.  Concrete
            # caller-to-thunk paths are emitted separately and cover it.
            if row.rva in thunk_rows and signature.arity_kind == "variadic":
                diagnostics.append({
                    "category": "generic_variadic_thunk",
                    "import": identity.display,
                    "source_rva": row.rva,
                    "detail": "arity is supplied by each checked caller-to-thunk path",
                })
                continue
            blockers.append(_blocker(
                "variadic_argument_inventory_incomplete", identity, row.rva,
                control.rva,
                "static call-boundary evidence does not contain a contiguous argument-word inventory",
                "recover the concrete variadic call-site stack arguments",
            ))
            explicit_frontiers.add(identity)
            continue
        if control.mnemonic == "jmp" and (
            row.rva in thunk_rows or route == "via_thunk"
        ):
            entry = (
                function_entries.get(row.function_key)
                if row.function_key is not None else None
            )
            callers = (
                callers_by_target.get(entry.rva, []) if entry is not None else []
            )
            added = 0
            for caller in callers:
                assert caller.control is not None
                execution_source_rva = (
                    thunk.rva if route == "via_thunk" and thunk is not None
                    else row.rva
                )
                continuation_rva = caller.control.rva + caller.control.size
                key = (
                    execution_source_rva, continuation_rva, identity,
                    argument_words,
                )
                if key in boundary_keys:
                    continue
                boundary_keys.add(key)
                boundaries.append(StaticMachineImportBoundary(
                    id=len(boundaries),
                    signature_id=signature.id,
                    identity=identity,
                    source_rva=caller.rva,
                    source_size=caller.size,
                    instruction_rva=caller.control.rva,
                    execution_source_rva=execution_source_rva,
                    continuation_rva=continuation_rva,
                    argument_words=argument_words,
                    route=(
                        "framed_thunk_tail" if route == "via_thunk"
                        else "framed_direct_tail"
                    ),
                    thunk_rva=thunk.rva if thunk is not None else None,
                    thunk_size=thunk.size if thunk is not None else None,
                    frame_entry_rva=entry.rva,
                    frame_entry_size=entry.size,
                    tail_rva=row.rva,
                    tail_size=row.size,
                    argument_evidence=(
                        "static_contiguous_variadic_words"
                        if signature.arity_kind == "variadic"
                        else "declarative_fixed_abi_plus_exact_decode"
                    ),
                ))
                added += 1
            if added:
                covered.add(identity)
            elif any(
                key_identity == identity and key_words == argument_words
                for _source, _continuation, key_identity, key_words
                in boundary_keys
            ):
                covered.add(identity)
            else:
                blockers.append(_blocker(
                    "external_tail_continuation_unbound", identity, row.rva,
                    control.rva,
                    "the external tail has no checked direct caller for its enclosing function entry",
                    "recover each incoming call-frame continuation or its checked indirect-call provenance",
                ))
                explicit_frontiers.add(identity)
            diagnostics.append({
                "category": "external_tail_call_frame",
                "import": identity.display,
                "source_rva": row.rva,
                "detail": f"recovered {added} checked enclosing continuation(s)",
            })
            continue
        continuation_rva = control.rva + control.size
        source_rva = (
            row.rva
            if route == "restored_register_indirect"
            else control.register_load_rva
            if route == "register_indirect"
            else row.rva
        )
        assert source_rva is not None
        execution_source_rva = thunk.rva if thunk is not None else source_rva
        boundary_keys.add((
            execution_source_rva, continuation_rva, identity, argument_words
        ))
        boundaries.append(StaticMachineImportBoundary(
            id=len(boundaries),
            signature_id=signature.id,
            identity=identity,
            source_rva=source_rva,
            source_size=(
                row.size
                if route == "restored_register_indirect"
                else continuation_rva - source_rva
                if route == "register_indirect"
                else row.size
            ),
            instruction_rva=control.rva,
            execution_source_rva=execution_source_rva,
            continuation_rva=continuation_rva,
            argument_words=argument_words,
            route=route,
            thunk_rva=thunk.rva if thunk is not None else None,
            thunk_size=thunk.size if thunk is not None else None,
            dispatch_register=(
                control.dispatch_register
                if route in {
                    "register_indirect",
                    "restored_register_indirect",
                }
                else None
            ),
            iat_rva=(
                control.register_iat_rva
                if route in {
                    "register_indirect",
                    "restored_register_indirect",
                }
                else None
            ),
            seed_rva=(
                control.restored_register_iat.seed_rva
                if control.restored_register_iat is not None
                else None
            ),
            seed_size=(
                control.restored_register_iat.seed_size
                if control.restored_register_iat is not None
                else None
            ),
            restore_rva=(
                control.restored_register_iat.restore_rva
                if control.restored_register_iat is not None
                else None
            ),
            restore_size=(
                control.restored_register_iat.restore_size
                if control.restored_register_iat is not None
                else None
            ),
            saved_stack_offset=(
                control.restored_register_iat.saved_stack_offset
                if control.restored_register_iat is not None
                else None
            ),
            argument_evidence=(
                "static_contiguous_variadic_words"
                if signature.arity_kind == "variadic"
                else "declarative_fixed_abi_plus_exact_decode"
            ),
        ))
        covered.add(identity)

    for identity in required:
        signature = signatures.get(identity)
        if signature is None:
            continue
        if identity not in covered and identity not in explicit_frontiers:
            blockers.append(_blocker(
                "reachable_import_has_no_checked_boundary", identity, None, None,
                "no reachable direct-IAT or caller-to-IAT-thunk boundary was proposed",
                "recover the exact reachable control route and call-site argument inventory",
            ))
    diagnostics.sort(key=lambda item: (
        str(item.get("category")), str(item.get("import")),
        int(item.get("source_rva") or 0),
    ))
    return boundaries, blockers, diagnostics


def _lean_source(
    plan: StaticMachineImportPlan,
    bindings: StaticMachineImportLeanBindings,
    namespace: str,
) -> str:
    required = ",\n  ".join(
        _lean_external_target(item.to_json()) for item in plan.required
    )
    signatures = ",\n  ".join(_lean_signature(item) for item in plan.signatures)
    boundaries = ",\n  ".join(_lean_boundary(item) for item in plan.boundaries)
    pe = bindings.qualified(bindings.pe)
    imports = f"{bindings.qualified(bindings.import_certificate)}.imports"
    profile_certificate = ""
    axiom_audits: list[str] = []
    if plan.profile_ready:
        profile_certificate = f"""
theorem generatedStaticMachineImportProfilesChecked :
    staticMachineImportProfilesValid {pe} {imports}
      generatedRequiredImports generatedMachineImportSignatures = true := by
  decide

def generatedStaticMachineImportProfileCertificate :
    StaticMachineImportProfileCertificate {pe} {imports}
      generatedRequiredImports generatedMachineImportSignatures := {{
  checked := generatedStaticMachineImportProfilesChecked
}}
"""
        axiom_audits.append(
            "#print axioms generatedStaticMachineImportProfilesChecked"
        )
    boundary_certificate = ""
    if plan.boundaries:
        boundary_certificate = f"""
theorem generatedStaticMachineImportBoundariesChecked :
    staticMachineImportBoundariesValid {pe} {imports}
      generatedMachineImportSignatures generatedMachineImportBoundaries = true := by
  decide

def generatedStaticMachineImportBoundaryCertificate :
    StaticMachineImportBoundaryCertificate {pe} {imports}
      generatedMachineImportSignatures generatedMachineImportBoundaries := {{
  checked := generatedStaticMachineImportBoundariesChecked
}}

def generatedMachineImportBoundaryContractCertificate :
    CheckedStaticMachineImportBoundaryContracts {pe} {imports}
      generatedMachineImportSignatures generatedMachineImportBoundaries := {{
  routes := generatedStaticMachineImportBoundaryCertificate
  inventory :=
    (staticMachineImportBoundaryContracts? generatedMachineImportSignatures
      generatedMachineImportBoundaries).get (by decide)
  resolved := by decide
}}

def generatedMachineImportBoundaryCallContracts :
    List StaticMachineImportResolvedBoundary :=
  generatedMachineImportBoundaryContractCertificate.inventory

def generatedMachineImportBoundaryContracts :
    List MachineImportCallContract :=
  generatedMachineImportBoundaryCallContracts.map (fun resolved => resolved.contract)

theorem generatedMachineImportBoundaryCallContractsResolved :
    staticMachineImportBoundaryContracts? generatedMachineImportSignatures
      generatedMachineImportBoundaries =
        some generatedMachineImportBoundaryCallContracts :=
  generatedMachineImportBoundaryContractCertificate.resolved
"""
        axiom_audits.extend((
            "#print axioms generatedStaticMachineImportBoundariesChecked",
            "#print axioms generatedMachineImportBoundaryCallContractsResolved",
        ))
    coverage_certificate = ""
    if plan.complete:
        coverage_certificate = """
theorem generatedStaticMachineImportBoundaryCoverageChecked :
    staticMachineImportBoundaryCoverageValid generatedRequiredImports
      generatedMachineImportSignatures generatedMachineImportBoundaries = true := by
  decide
"""
    global_contract_certificate = ""
    if plan.global_contracts_ready:
        global_contract_certificate = f"""
def generatedMachineImportGlobalContractCertificate :
    CheckedStaticMachineImportGlobalProfile {pe} {imports}
      generatedRequiredImports generatedMachineImportSignatures := {{
  profile := generatedStaticMachineImportProfileCertificate
  global := {{
    contracts := generatedMachineImportSignatures.map fun signature =>
      signature.contract signature.arity.minimumWords
    resolved := by decide
  }}
}}

def generatedMachineImportCallContracts : List MachineImportCallContract :=
  generatedMachineImportGlobalContractCertificate.global.contracts

theorem generatedMachineImportCallContractsResolved :
    staticMachineImportGlobalContracts? generatedMachineImportSignatures =
      some generatedMachineImportCallContracts :=
  generatedMachineImportGlobalContractCertificate.global.resolved
"""
        axiom_audits.append(
            "#print axioms generatedMachineImportCallContractsResolved"
        )
    return f"""import StageA.RelationalStaticMachineImportContracts
import {bindings.module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedRequiredImports : List ExternalTarget := [
  {required}
]

def generatedMachineImportSignatures : List StaticMachineImportSignature := [
  {signatures}
]

def generatedMachineImportBoundaries : List StaticMachineImportBoundary := [
  {boundaries}
]

{profile_certificate}
{boundary_certificate}
{coverage_certificate}
def generatedMachineImportCallContracts? :
    Option (List MachineImportCallContract) :=
  staticMachineImportGlobalContracts? generatedMachineImportSignatures

{global_contract_certificate}
{chr(10).join(axiom_audits)}

end {namespace}
"""


def _lean_signature(signature: StaticMachineImportSignature) -> str:
    contract = signature.contract
    results = ", ".join(_lean_result_relation(item) for item in contract[
        "result_register_relations"
    ])
    footprints = ", ".join(
        _lean_machine_call_memory_footprint(item)
        for item in contract["memory_footprints"]
    )
    world = f".{contract['world_effect']}"
    if contract["world_effect"] in {
        "dynamicRangeRelease", "callbackRegistration",
    }:
        world += f" {int(contract['world_effect_argument'])}"
    arity = (
        f".fixed {signature.minimum_words}"
        if signature.arity_kind == "fixed"
        else f".variadic {signature.minimum_words}"
    )
    return (
        "{ "
        f"id := {signature.id}, "
        f"imported := {_lean_external_target(signature.identity.to_json())}, "
        f"abi := .{signature.abi}, arity := {arity}, "
        f"resultRegisterRelations := [{results}], "
        f"disposition := .{contract['disposition']}, "
        f"memoryEffect := .{contract['memory_effect']}, "
        f"memoryFootprints := [{footprints}], "
        f"worldEffect := {world}, "
        f"callbackMode := .{signature.callback_mode} "
        "}"
    )


def _lean_result_relation(relation: Mapping[str, Any]) -> str:
    kind = relation["relation"]
    if kind == "dynamic_range_base":
        word_kinds = {
            "related_word": "relatedWord",
            "code_pointer": "codePointer",
            "data_pointer": "dataPointer",
            "nullable_dynamic_pointer": "nullableDynamicPointer",
        }
        words = ", ".join(
            "{ offset := " + str(int(word["offset"]))
            + ", kind := ." + word_kinds[str(word["relation"])] + " }"
            for word in relation["required_words"]
        )
        relation_term = (
            ".dynamicRangeBase "
            f"({_lean_machine_call_memory_size(relation['size'])}) "
            f"{int(relation['minimum_size'])} [{words}] "
            f"{str(bool(relation['nullable'])).lower()}"
        )
    else:
        relation_term = ".relatedWord" if kind == "related_word" else f".{kind}"
    return (
        "{ register := ." + str(relation["register"])
        + ", relation := " + relation_term + " }"
    )


def _lean_boundary(boundary: StaticMachineImportBoundary) -> str:
    if boundary.route == "direct":
        route = (
            f".direct {{ start := {boundary.source_rva}, "
            f"size := {boundary.source_size} }}"
        )
    elif boundary.route == "via_thunk":
        assert boundary.thunk_rva is not None and boundary.thunk_size is not None
        route = (
            f".viaThunk {{ start := {boundary.source_rva}, size := {boundary.source_size} }} "
            f"{{ start := {boundary.thunk_rva}, size := {boundary.thunk_size} }}"
        )
    elif boundary.route == "framed_direct_tail":
        assert all(item is not None for item in (
            boundary.frame_entry_rva, boundary.frame_entry_size,
            boundary.tail_rva, boundary.tail_size,
        ))
        route = (
            f".framedDirectTail {{ start := {boundary.source_rva}, "
            f"size := {boundary.source_size} }} "
            f"{{ start := {boundary.frame_entry_rva}, "
            f"size := {boundary.frame_entry_size} }} "
            f"{{ start := {boundary.tail_rva}, size := {boundary.tail_size} }}"
        )
    elif boundary.route == "framed_thunk_tail":
        assert all(item is not None for item in (
            boundary.frame_entry_rva, boundary.frame_entry_size,
            boundary.tail_rva, boundary.tail_size,
            boundary.thunk_rva, boundary.thunk_size,
        ))
        route = (
            f".framedThunkTail {{ start := {boundary.source_rva}, "
            f"size := {boundary.source_size} }} "
            f"{{ start := {boundary.frame_entry_rva}, "
            f"size := {boundary.frame_entry_size} }} "
            f"{{ start := {boundary.tail_rva}, size := {boundary.tail_size} }} "
            f"{{ start := {boundary.thunk_rva}, size := {boundary.thunk_size} }}"
        )
    elif boundary.route == "register_indirect":
        assert boundary.dispatch_register is not None and boundary.iat_rva is not None
        route = (
            f".registerIndirect {{ start := {boundary.source_rva}, "
            f"size := {boundary.source_size} }} .{boundary.dispatch_register} "
            f"{boundary.iat_rva}"
        )
    else:
        assert boundary.route == "restored_register_indirect"
        assert boundary.dispatch_register is not None
        assert boundary.iat_rva is not None
        assert boundary.seed_rva is not None and boundary.seed_size is not None
        assert boundary.restore_rva is not None and boundary.restore_size is not None
        assert boundary.saved_stack_offset is not None
        route = (
            f".restoredRegisterIndirect "
            f"{{ start := {boundary.seed_rva}, size := {boundary.seed_size} }} "
            f"{{ start := {boundary.restore_rva}, "
            f"size := {boundary.restore_size} }} "
            f"{{ start := {boundary.source_rva}, "
            f"size := {boundary.source_size} }} "
            f".{boundary.dispatch_register} {boundary.iat_rva} "
            f"{boundary.saved_stack_offset}"
        )
    return (
        "{ "
        f"id := {boundary.id}, signatureId := {boundary.signature_id}, "
        f"instructionRva := {boundary.instruction_rva}, "
        f"executionSourceRva := {boundary.execution_source_rva}, "
        f"continuationRva := {boundary.continuation_rva}, "
        f"argumentWords := {boundary.argument_words}, route := {route} "
        "}"
    )


def _blocker(
    reason: str,
    identity: StaticImportIdentity | None,
    source_rva: int | None,
    instruction_rva: int | None,
    detail: str,
    next_action: str,
) -> StaticMachineImportBlocker:
    return StaticMachineImportBlocker(
        reason_code=reason,
        identity=identity.display if identity is not None else "<inventory>",
        source_rva=source_rva,
        instruction_rva=instruction_rva,
        detail=detail,
        next_action=next_action,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "STATIC_MACHINE_IMPORT_FORMAT",
    "STATIC_MACHINE_IMPORT_MODULE",
    "StaticImportIdentity",
    "StaticMachineImportBlocker",
    "StaticMachineImportBoundary",
    "StaticMachineImportContractError",
    "StaticMachineImportLeanBindings",
    "StaticMachineImportPlan",
    "StaticMachineImportSignature",
    "plan_static_machine_import_contracts",
    "write_static_machine_import_contracts",
]
