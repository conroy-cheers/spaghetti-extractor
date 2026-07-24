"""Typed evidence for semantic-interpreter relational macro segments.

This module deliberately stops before acceptance.  It binds untrusted Stage B
artifacts to exact candidate bytes and emits the obligations a later Lean
checker must discharge.  Neither a successful parse nor ``evidence_ready`` is
authority for a Stage A pass.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import capstone
from capstone import x86_const

from ..stage_b_engine_layout import (
    EngineLayout,
    EngineLayoutFormatError,
    parse_stage_b_engine_layout_payload,
)
from ..stage_b_interpreter_backend import (
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PROGRAM_FORMAT,
)
from ..stage_b_state_machine import normalize_stage_a_semantic_transfer
from ..stage_binary import (
    StageABinary,
    StageAInputError,
    _parse_linker_map_functions,
    _parse_stage_a_pe,
)
from ..util import sha256_bytes, sha256_file
from .x86_instruction_profile import is_reviewed_x87_frame_instruction


ENGINE_SEGMENT_EVIDENCE_FORMAT = "stage-a-engine-segment-evidence-v1"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GNU_SYMBOL = re.compile(
    r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$"
)
_MSVC_SYMBOL = re.compile(
    r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8,16}\s+"
    r"(\S+)\s+([0-9a-fA-F]{8,16})(?:\s+.*)?$"
)

_TRANSFER_RECORD_SIZE = 40
_WORD_NODE_SIZE = 36
_X87_NODE_SIZE = 36
_ACTION_SIZE = 32
_CALL_SIZE = 64
_X87_REPLAY_SIZE = 44
_STACK_INPUT_SIZE = 12
_MAX_CALL_ARGUMENTS = 64
_MAX_STRING_BYTES = 512

_REQUIRED_KERNEL_SYMBOLS = (
    "stage_b_program_lookup",
    "stage_b_interpreter_step",
    "stage_b_run_function",
    "stage_b_invoke_call",
)


class EngineSegmentEvidenceError(StageAInputError):
    """An engine-segment input is stale, ambiguous, or structurally invalid."""


@dataclass(frozen=True)
class EvidenceInput:
    role: str
    path: str
    sha256: str

    def to_payload(self) -> dict[str, Any]:
        return {"role": self.role, "path": self.path, "sha256": self.sha256}


@dataclass(frozen=True)
class ImmutableRange:
    role: str
    rva_start: int
    rva_end: int
    sha256: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ExecutableCoverageRange:
    classification: str
    required_for_kernel_closure: bool
    rva_start: int
    rva_end: int
    sha256: str
    owner: str | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "classification": self.classification,
            "required_for_kernel_closure": self.required_for_kernel_closure,
            "proof_authority": False,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "sha256": self.sha256,
        }
        if self.owner is not None:
            payload["owner"] = self.owner
        return payload


@dataclass(frozen=True)
class ExternalTailBinding:
    transfer_id: str
    contract_sha256: str
    dll: str
    symbol: str | None
    ordinal: int | None
    external_event_index: int
    static_evidence_sha256: str

    def to_payload(self) -> dict[str, Any]:
        identity: dict[str, Any] = {"dll": self.dll}
        if self.symbol is not None:
            identity["symbol"] = self.symbol
        if self.ordinal is not None:
            identity["ordinal"] = self.ordinal
        return {
            "transfer_id": self.transfer_id,
            "contract_sha256": self.contract_sha256,
            "classification": "static_external_tail_import_v1",
            "proof_authority": False,
            "import_identity": identity,
            "external_event_index": self.external_event_index,
            "static_evidence_sha256": self.static_evidence_sha256,
        }


@dataclass(frozen=True)
class X87ReplayObligation:
    transfer_id: str
    contract_sha256: str
    replay_sha256: str
    schedule_sha256: str
    instruction_count: int
    x87_singleton_count: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "contract_sha256": self.contract_sha256,
            "classification": "native_exact_x87_command_replay_obligation_v1",
            "proof_authority": False,
            "status": "pending_lean_check",
            "replay_sha256": self.replay_sha256,
            "schedule_sha256": self.schedule_sha256,
            "instruction_count": self.instruction_count,
            "x87_singleton_count": self.x87_singleton_count,
        }


@dataclass(frozen=True)
class SemanticTransferBinding:
    transfer_id: str
    contract_sha256: str
    instruction_bytes_sha256: str
    original_rva_start: int
    original_rva_end: int
    record_index: int
    record_rva: int
    record_sha256: str
    immutable_ranges: tuple[ImmutableRange, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "contract_sha256": self.contract_sha256,
            "instruction_bytes_sha256": self.instruction_bytes_sha256,
            "original_span": {
                "rva_start": self.original_rva_start,
                "rva_end": self.original_rva_end,
            },
            "program_record": {
                "index": self.record_index,
                "rva": self.record_rva,
                "sha256": self.record_sha256,
            },
            "immutable_ranges": [item.to_payload() for item in self.immutable_ranges],
        }


@dataclass(frozen=True)
class KernelRange:
    symbol: str
    rva_start: int
    rva_end: int
    sha256: str
    decoded_instruction_count: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "symbol": self.symbol,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "sha256": self.sha256,
            "decoded_instruction_count": self.decoded_instruction_count,
        }


@dataclass(frozen=True)
class ControlSite:
    kernel_symbol: str
    instruction_rva: int
    kind: str
    target_rva: int | None = None
    target_symbol: str | None = None
    target_rvas: tuple[int, ...] = ()
    capability_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kernel_symbol": self.kernel_symbol,
            "instruction_rva": self.instruction_rva,
            "kind": self.kind,
        }
        if self.target_rva is not None:
            payload["target_rva"] = self.target_rva
        if self.target_symbol is not None:
            payload["target_symbol"] = self.target_symbol
        if self.target_rvas:
            payload["target_rvas"] = list(self.target_rvas)
        if self.capability_id is not None:
            payload["capability_id"] = self.capability_id
        return payload


@dataclass(frozen=True)
class NativeIndirectCallABI:
    argument_offsets: tuple[int, ...]
    caller_stack_delta: int
    preserved_registers: tuple[str, ...]
    return_kind: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "calling_convention": "cdecl_x86_32",
            "argument_count": len(self.argument_offsets),
            "argument_offsets": list(self.argument_offsets),
            "caller_stack_delta": self.caller_stack_delta,
            "preserved_registers": list(self.preserved_registers),
            "return_kind": self.return_kind,
        }


@dataclass(frozen=True)
class NativeIndirectCallRuntimePointerField:
    offset: int
    target_id: int

    def to_payload(self) -> dict[str, int]:
        return {"offset": self.offset, "target_id": self.target_id}


@dataclass(frozen=True)
class NativeIndirectCallRuntimeLayout:
    instance_rva: int
    size: int
    initial_bytes_sha256: str
    pointer_fields: tuple[NativeIndirectCallRuntimePointerField, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": "stage-a-exact-runtime-layout-evidence-v1",
            "instance_rva": self.instance_rva,
            "size": self.size,
            "initial_bytes_sha256": self.initial_bytes_sha256,
            "pointer_fields": [item.to_payload() for item in self.pointer_fields],
        }


@dataclass(frozen=True)
class NativeIndirectCallPointerSlot:
    rva: int
    stored_word: int
    target_rva: int
    section: str
    writable: bool
    relocation_type: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "stored_word": self.stored_word,
            "target_rva": self.target_rva,
            "section": self.section,
            "writable": self.writable,
            "relocation_type": self.relocation_type,
        }


@dataclass(frozen=True)
class NativeIndirectCallTarget:
    target_id: int
    rva: int
    entry_bytes: bytes
    pointer_slots: tuple[NativeIndirectCallPointerSlot, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.target_id,
            "rva": self.rva,
            "entry_bytes": self.entry_bytes.hex(),
            "entry_sha256": sha256_bytes(self.entry_bytes),
            "pointer_slots": [item.to_payload() for item in self.pointer_slots],
        }


@dataclass(frozen=True)
class NativeIndirectCallCapability:
    capability_id: str
    call_site_rva: int
    instruction_bytes: bytes
    continuation_rva: int
    target_operand: Mapping[str, Any]
    provenance: str
    abi: NativeIndirectCallABI
    targets: tuple[NativeIndirectCallTarget, ...]
    dynamic_requirements: tuple[str, ...]
    source_artifact_sha256: str
    runtime_layout: NativeIndirectCallRuntimeLayout | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.capability_id,
            "classification": "bounded_native_indirect_call_capability_v1",
            "status": "pending_lean_check",
            "proof_authority": False,
            "call_site_rva": self.call_site_rva,
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_sha256": sha256_bytes(self.instruction_bytes),
            "continuation_rva": self.continuation_rva,
            "target_operand": dict(self.target_operand),
            "target_provenance": self.provenance,
            "abi": self.abi.to_payload(),
            "targets": [item.to_payload() for item in self.targets],
            "dynamic_requirements": list(self.dynamic_requirements),
            "source_artifact_sha256": self.source_artifact_sha256,
        }
        if self.runtime_layout is not None:
            payload["runtime_layout"] = self.runtime_layout.to_payload()
        return payload


@dataclass(frozen=True)
class ProductCutpointOwner:
    rva: int
    transfer_id: str
    offset: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "transfer_id": self.transfer_id,
            "offset": self.offset,
        }


@dataclass(frozen=True)
class EvidenceIssue:
    code: str
    message: str
    rva_start: int | None = None
    rva_end: int | None = None
    transfer_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.rva_start is not None:
            payload["rva_start"] = self.rva_start
        if self.rva_end is not None:
            payload["rva_end"] = self.rva_end
        if self.transfer_id is not None:
            payload["transfer_id"] = self.transfer_id
        return payload


@dataclass(frozen=True)
class ProofObligation:
    obligation_id: str
    family: str
    subject: str
    status: str = "pending_lean_check"

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.obligation_id,
            "family": self.family,
            "subject": self.subject,
            "status": self.status,
        }


@dataclass(frozen=True)
class EngineSegmentEvidence:
    status: str
    inputs: tuple[EvidenceInput, ...]
    candidate_pe_sha256: str
    program_table_rva: int
    engine_layout_rva: int
    engine_layout_sha256: str
    engine_layout: EngineLayout
    transfers: tuple[SemanticTransferBinding, ...]
    external_tail_bindings: tuple[ExternalTailBinding, ...]
    x87_replay_obligations: tuple[X87ReplayObligation, ...]
    kernel_ranges: tuple[KernelRange, ...]
    control_sites: tuple[ControlSite, ...]
    native_indirect_call_capabilities: tuple[NativeIndirectCallCapability, ...]
    cutpoint_owners: tuple[ProductCutpointOwner, ...]
    executable_coverage: tuple[ExecutableCoverageRange, ...]
    obligations: tuple[ProofObligation, ...]
    issues: tuple[EvidenceIssue, ...]

    @property
    def acceptance_authority(self) -> bool:
        return False

    def to_payload(self) -> dict[str, Any]:
        core = {
            "format": ENGINE_SEGMENT_EVIDENCE_FORMAT,
            "status": self.status,
            "acceptance_authority": False,
            "inputs": [item.to_payload() for item in self.inputs],
            "candidate": {
                "pe_sha256": self.candidate_pe_sha256,
                "machine": "i386",
                "bitness": 32,
            },
            "program_table_rva": self.program_table_rva,
            "engine_layout": {
                "rva": self.engine_layout_rva,
                "sha256": self.engine_layout_sha256,
                "version": self.engine_layout.version,
                "state_size": self.engine_layout.state_size,
                "x87_slot_count": self.engine_layout.x87_slot_count,
                "features": int(self.engine_layout.features),
                "fields": [
                    {
                        "name": field.field.name,
                        "offset": field.offset,
                        "size": field.size,
                    }
                    for field in self.engine_layout.fields
                ],
            },
            "transfers": [item.to_payload() for item in self.transfers],
            "external_tail_bindings": [
                item.to_payload() for item in self.external_tail_bindings
            ],
            "x87_replay_obligations": [
                item.to_payload() for item in self.x87_replay_obligations
            ],
            "kernel_ranges": [item.to_payload() for item in self.kernel_ranges],
            "control_sites": [item.to_payload() for item in self.control_sites],
            "native_indirect_call_capabilities": [
                item.to_payload() for item in self.native_indirect_call_capabilities
            ],
            "product_cutpoints": [item.to_payload() for item in self.cutpoint_owners],
            "executable_coverage": [
                item.to_payload() for item in self.executable_coverage
            ],
            "proof_obligations": [item.to_payload() for item in self.obligations],
            "issues": [item.to_payload() for item in self.issues],
        }
        return {**core, "artifact_sha256": _canonical_sha256(core)}


@dataclass(frozen=True)
class _SemanticTransfer:
    identity: str
    contract_sha256: str
    instruction_sha256: str
    start: int
    end: int
    row: Mapping[str, Any]


@dataclass(frozen=True)
class _ProgramTransfer:
    identity: str
    rva_start: int
    contract_sha256: str
    instruction_sha256: str
    word_count: int
    x87_count: int
    action_count: int
    call_count: int
    x87_replay_count: int


@dataclass(frozen=True)
class _FunctionRange:
    name: str
    aliases: tuple[str, ...]
    start: int
    end: int
    section: str


def build_engine_segment_evidence(
    *,
    semantic_transfers: Path | str,
    interpreter_program_manifest: Path | str,
    interpreter_package_manifest: Path | str,
    candidate_pe: Path | str,
    linker_map: Path | str,
    engine_layout: Path | str,
    kernel_callback_plan: Path | str | None = None,
    product_cutpoints: Iterable[int] = (),
) -> EngineSegmentEvidence:
    """Bind semantic transfers to exact interpreter data and kernel bytes."""

    paths = {
        "semantic_transfers": _regular_file(semantic_transfers, "semantic transfers"),
        "interpreter_program_manifest": _regular_file(
            interpreter_program_manifest, "interpreter program manifest"
        ),
        "interpreter_package_manifest": _regular_file(
            interpreter_package_manifest, "interpreter package manifest"
        ),
        "candidate_pe": _regular_file(candidate_pe, "candidate PE"),
        "linker_map": _regular_file(linker_map, "candidate linker map"),
        "engine_layout": _regular_file(engine_layout, "engine layout"),
    }
    if kernel_callback_plan is not None:
        paths["kernel_callback_plan"] = _regular_file(
            kernel_callback_plan, "kernel callback plan"
        )
    inputs = tuple(
        EvidenceInput(role=role, path=path.name, sha256=sha256_file(path))
        for role, path in paths.items()
    )

    rows = _load_semantic_transfers(paths["semantic_transfers"])
    program_payload = _json_object(
        paths["interpreter_program_manifest"], "interpreter program manifest"
    )
    package_payload = _json_object(
        paths["interpreter_package_manifest"], "interpreter package manifest"
    )
    program = _validate_interpreter_manifests(
        semantic_path=paths["semantic_transfers"],
        program_path=paths["interpreter_program_manifest"],
        package_path=paths["interpreter_package_manifest"],
        program=program_payload,
        package=package_payload,
    )
    _bind_transfer_inventories(rows, program)

    try:
        layout_bytes = paths["engine_layout"].read_bytes()
        layout = parse_stage_b_engine_layout_payload(layout_bytes)
    except (OSError, EngineLayoutFormatError) as exc:
        raise EngineSegmentEvidenceError(f"invalid engine layout: {exc}") from exc

    binary = _parse_stage_a_pe(paths["candidate_pe"])
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise EngineSegmentEvidenceError("engine-segment candidate must be i386 PE32")
        symbols = _load_linker_symbols(paths["linker_map"], binary)
        functions = _load_function_ranges(paths["linker_map"], binary)
        layout_rva = _locate_exact_read_only_bytes(binary, layout_bytes, "engine layout")
        transfer_bindings, table_rva = _bind_program_records(
            binary, symbols, rows, program
        )
        semantic_issues, external_tails, x87_replays = _classify_semantic_evidence(
            rows
        )
        issues = list(semantic_issues)
        callback_capabilities = (
            _load_kernel_callback_capabilities(
                paths["kernel_callback_plan"], binary
            )
            if "kernel_callback_plan" in paths
            else {}
        )
        kernel_ranges, control_sites, decoded_by_function, control_issues = (
            _decode_kernel_ranges(binary, functions, callback_capabilities)
        )
        issues.extend(control_issues)
        coverage, coverage_issues = _engine_executable_coverage(
            binary, kernel_ranges, decoded_by_function
        )
        issues.extend(coverage_issues)
        cutpoint_owners, cutpoint_issues = _bind_cutpoints(rows, product_cutpoints)
        issues.extend(cutpoint_issues)
        obligations = _proof_obligations(
            transfer_bindings,
            external_tails,
            x87_replays,
            kernel_ranges,
            control_sites,
            tuple(callback_capabilities.values()),
            cutpoint_owners,
            issues,
        )
        issues = sorted(
            _deduplicate_issues(issues),
            key=lambda item: (
                item.code,
                -1 if item.rva_start is None else item.rva_start,
                item.transfer_id or "",
            ),
        )
        return EngineSegmentEvidence(
            status="evidence_ready" if not issues else "incomplete",
            inputs=inputs,
            candidate_pe_sha256=binary.sha256,
            program_table_rva=table_rva,
            engine_layout_rva=layout_rva,
            engine_layout_sha256=sha256_bytes(layout_bytes),
            engine_layout=layout,
            transfers=transfer_bindings,
            external_tail_bindings=external_tails,
            x87_replay_obligations=x87_replays,
            kernel_ranges=kernel_ranges,
            control_sites=control_sites,
            native_indirect_call_capabilities=tuple(
                callback_capabilities[rva]
                for rva in sorted(callback_capabilities)
            ),
            cutpoint_owners=cutpoint_owners,
            executable_coverage=coverage,
            obligations=obligations,
            issues=tuple(issues),
        )
    finally:
        binary.pe.close()


def write_engine_segment_evidence(
    *, out: Path | str, **kwargs: Any
) -> EngineSegmentEvidence:
    evidence = build_engine_segment_evidence(**kwargs)
    output = Path(out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(evidence.to_payload(), sort_keys=True, indent=2) + "\n",
        encoding="ascii",
    )
    return evidence


def _load_kernel_callback_capabilities(
    path: Path, binary: StageABinary
) -> dict[int, NativeIndirectCallCapability]:
    payload = _json_object(path, "kernel callback plan")
    if payload.get("format") != (
        "stage-a-relational-interpreter-kernel-callback-plan-v1"
    ):
        raise EngineSegmentEvidenceError(
            "kernel callback plan has an unsupported format"
        )
    candidate = _mapping(payload.get("candidate"), "kernel callback candidate")
    if candidate.get("sha256") != binary.sha256:
        raise EngineSegmentEvidenceError(
            "kernel callback plan binds a different candidate PE"
        )
    if _u32(candidate.get("size"), "kernel callback candidate size") != binary.size:
        raise EngineSegmentEvidenceError(
            "kernel callback plan records a different candidate PE size"
        )
    artifact_sha256 = _digest(
        payload.get("artifact_sha256"), "kernel callback artifact SHA-256"
    )
    artifact_core = dict(payload)
    del artifact_core["artifact_sha256"]
    if artifact_sha256 != _canonical_sha256(artifact_core):
        raise EngineSegmentEvidenceError("kernel callback plan has a stale artifact SHA-256")

    result: dict[int, NativeIndirectCallCapability] = {}
    seen_slot_targets: dict[int, int] = {}
    relocations = _highlow_relocations(binary)
    for site_index, raw_site in enumerate(
        _list(payload.get("sites"), "kernel callback sites")
    ):
        site = _mapping(raw_site, f"kernel callback site {site_index}")
        rva = _u32(site.get("rva"), f"kernel callback site {site_index} RVA")
        if rva in result:
            raise EngineSegmentEvidenceError(
                f"duplicate kernel callback site RVA 0x{rva:x}"
            )
        instruction_hex = _string(
            site.get("instruction_bytes"),
            f"kernel callback site {site_index} instruction bytes",
        )
        try:
            instruction = bytes.fromhex(instruction_hex)
        except ValueError as exc:
            raise EngineSegmentEvidenceError(
                f"kernel callback site {site_index} has invalid instruction bytes"
            ) from exc
        if _digest(
            site.get("instruction_sha256"),
            f"kernel callback site {site_index} instruction SHA-256",
        ) != sha256_bytes(instruction):
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has a stale instruction SHA-256"
            )
        if not instruction or _read_executable(
            binary, rva, rva + len(instruction),
            f"kernel callback site {site_index}",
        ) != instruction:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} bytes disagree with candidate"
            )
        decoded_operand = _decode_exact_indirect_call_operand(
            binary, rva, instruction
        )

        continuation_rva = _u32(
            site.get("continuation_rva"),
            f"kernel callback site {site_index} continuation RVA",
        )
        if continuation_rva != rva + len(instruction):
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has a non-contiguous continuation"
            )
        provenance = _string(
            site.get("target_provenance"),
            f"kernel callback site {site_index} target provenance",
        )
        if provenance not in {
            "immutable_finite_bridge_table",
            "relocation_backed_initialized_pointer_slots",
            "relocation_backed_runtime_cell",
            "exact_runtime_layout",
        }:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has unsupported target provenance {provenance}"
            )
        target_operand = _mapping(
            site.get("target_operand"),
            f"kernel callback site {site_index} target operand",
        )
        if target_operand != decoded_operand:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} target operand disagrees with candidate"
            )
        cdecl = _mapping(
            site.get("cdecl"), f"kernel callback site {site_index} cdecl ABI"
        )
        argument_count = _u32(
            cdecl.get("argument_count"),
            f"kernel callback site {site_index} argument count",
        )
        argument_offsets = tuple(
            _u32(value, f"kernel callback site {site_index} argument offset")
            for value in _list(
                cdecl.get("argument_offsets"),
                f"kernel callback site {site_index} argument offsets",
            )
        )
        if len(argument_offsets) != argument_count or argument_offsets != tuple(
            index * 4 for index in range(argument_count)
        ):
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has an unsupported cdecl argument layout"
            )
        caller_stack_delta = _u32(
            cdecl.get("caller_stack_delta"),
            f"kernel callback site {site_index} caller stack delta",
        )
        if caller_stack_delta != 0:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has an unsupported caller stack delta"
            )
        preserved_registers = tuple(
            _string(value, f"kernel callback site {site_index} preserved register")
            for value in _list(
                cdecl.get("preserved_registers"),
                f"kernel callback site {site_index} preserved registers",
            )
        )
        if preserved_registers != ("ebx", "esi", "edi", "ebp"):
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has an unsupported preserved-register ABI"
            )
        return_kind = _string(
            cdecl.get("return_kind"),
            f"kernel callback site {site_index} return kind",
        )
        if return_kind not in {"void", "word_in_eax"}:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has unsupported return kind {return_kind}"
            )

        targets: list[NativeIndirectCallTarget] = []
        target_ids: set[int] = set()
        target_rvas: set[int] = set()
        for target_index, raw_target in enumerate(
            _list(site.get("targets"), f"kernel callback site {site_index} targets")
        ):
            target = _mapping(
                raw_target,
                f"kernel callback site {site_index} target {target_index}",
            )
            target_rva = _u32(
                target.get("rva"),
                f"kernel callback site {site_index} target {target_index} RVA",
            )
            target_id = _u32(
                target.get("id"),
                f"kernel callback site {site_index} target {target_index} id",
            )
            if target_id in target_ids or target_rva in target_rvas:
                raise EngineSegmentEvidenceError(
                    f"kernel callback site 0x{rva:x} has duplicate target identity"
                )
            target_ids.add(target_id)
            target_rvas.add(target_rva)
            entry_hex = _string(
                target.get("entry_bytes"),
                f"kernel callback site {site_index} target {target_index} bytes",
            )
            try:
                entry = bytes.fromhex(entry_hex)
            except ValueError as exc:
                raise EngineSegmentEvidenceError(
                    f"kernel callback target 0x{target_rva:x} has invalid bytes"
                ) from exc
            if _digest(
                target.get("entry_sha256"),
                f"kernel callback target 0x{target_rva:x} entry SHA-256",
            ) != sha256_bytes(entry):
                raise EngineSegmentEvidenceError(
                    f"kernel callback target 0x{target_rva:x} has a stale entry SHA-256"
                )
            if not entry or _read_executable(
                binary,
                target_rva,
                target_rva + len(entry),
                f"kernel callback target {target_index}",
            ) != entry:
                raise EngineSegmentEvidenceError(
                    f"kernel callback target 0x{target_rva:x} bytes disagree with candidate"
                )
            pointer_cells = tuple(
                _u32(
                    value,
                    f"kernel callback target 0x{target_rva:x} pointer cell",
                )
                for value in _list(
                    target.get("pointer_cells"),
                    f"kernel callback target 0x{target_rva:x} pointer cells",
                )
            )
            if not pointer_cells or len(set(pointer_cells)) != len(pointer_cells):
                raise EngineSegmentEvidenceError(
                    f"kernel callback target 0x{target_rva:x} has no unique pointer cells"
                )
            pointer_slots: list[NativeIndirectCallPointerSlot] = []
            for cell_rva in pointer_cells:
                previous_target = seen_slot_targets.get(cell_rva)
                if previous_target is not None and previous_target != target_rva:
                    raise EngineSegmentEvidenceError(
                        "kernel callback pointer cell RVA "
                        f"0x{cell_rva:x} ambiguously names targets"
                    )
                seen_slot_targets[cell_rva] = target_rva
                if cell_rva not in relocations:
                    raise EngineSegmentEvidenceError(
                        "kernel callback pointer cell RVA "
                        f"0x{cell_rva:x} lacks a PE32 HIGHLOW relocation"
                    )
                pointer = struct.unpack(
                    "<I",
                    _read_image_bytes(
                        binary, cell_rva, 4, "kernel callback pointer cell"
                    ),
                )[0]
                if pointer != binary.image_base + target_rva:
                    raise EngineSegmentEvidenceError(
                        "kernel callback pointer cell RVA "
                        f"0x{cell_rva:x} does not name RVA 0x{target_rva:x}"
                    )
                sections = [
                    section
                    for section in binary.sections
                    if section.rva_start <= cell_rva
                    and cell_rva + 4 <= section.rva_start + section.raw_size
                ]
                if len(sections) != 1:
                    raise EngineSegmentEvidenceError(
                        "kernel callback pointer cell RVA "
                        f"0x{cell_rva:x} has ambiguous section ownership"
                    )
                section = sections[0]
                if section.executable:
                    raise EngineSegmentEvidenceError(
                        "kernel callback pointer cell RVA "
                        f"0x{cell_rva:x} lies in executable memory"
                    )
                pointer_slots.append(
                    NativeIndirectCallPointerSlot(
                        rva=cell_rva,
                        stored_word=pointer,
                        target_rva=target_rva,
                        section=section.name,
                        writable=section.writable,
                        relocation_type="PE32_HIGHLOW",
                    )
                )
            targets.append(
                NativeIndirectCallTarget(
                    target_id=target_id,
                    rva=target_rva,
                    entry_bytes=entry,
                    pointer_slots=tuple(pointer_slots),
                )
            )
        if not targets:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has no unique finite target set"
            )
        dynamic_requirements = tuple(
            _string(
                value, f"kernel callback site {site_index} dynamic requirement"
            )
            for value in _list(
                site.get("dynamic_requirements"),
                f"kernel callback site {site_index} dynamic requirements",
            )
        )
        if not dynamic_requirements or len(set(dynamic_requirements)) != len(
            dynamic_requirements
        ):
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} hides or duplicates dynamic requirements"
            )
        if "callback_target_execution_refinement" not in dynamic_requirements:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} omits target-execution refinement"
            )
        writable_slots = any(
            slot.writable for target in targets for slot in target.pointer_slots
        )
        if provenance == "immutable_finite_bridge_table" and writable_slots:
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} claims mutable slots are immutable"
            )
        if writable_slots and not {
            "pointer_slot_preserved",
            "runtime_target_cell_preserved",
        }.intersection(dynamic_requirements):
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} has mutable target provenance "
                "without a preservation obligation"
            )
        if provenance == "relocation_backed_runtime_cell" and (
            "runtime_pointer_identity" not in dynamic_requirements
        ):
            raise EngineSegmentEvidenceError(
                f"kernel callback site 0x{rva:x} omits runtime-pointer identity"
            )
        runtime_layout = None
        if provenance == "exact_runtime_layout":
            runtime_layout = _validate_exact_runtime_layout(
                binary=binary,
                site=site,
                targets=targets,
                site_rva=rva,
            )
        result[rva] = NativeIndirectCallCapability(
            capability_id=f"native-indirect-call:{rva:08x}",
            call_site_rva=rva,
            instruction_bytes=instruction,
            continuation_rva=continuation_rva,
            target_operand=target_operand,
            provenance=provenance,
            abi=NativeIndirectCallABI(
                argument_offsets=argument_offsets,
                caller_stack_delta=caller_stack_delta,
                preserved_registers=preserved_registers,
                return_kind=return_kind,
            ),
            targets=tuple(targets),
            dynamic_requirements=dynamic_requirements,
            source_artifact_sha256=artifact_sha256,
            runtime_layout=runtime_layout,
        )
    return result


def _decode_exact_indirect_call_operand(
    binary: StageABinary, rva: int, instruction_bytes: bytes
) -> dict[str, Any]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = list(
        decoder.disasm(instruction_bytes, binary.image_base + rva, count=1)
    )
    if (
        len(instructions) != 1
        or bytes(instructions[0].bytes) != instruction_bytes
        or not instructions[0].group(capstone.CS_GRP_CALL)
        or len(instructions[0].operands) != 1
        or instructions[0].operands[0].type == x86_const.X86_OP_IMM
    ):
        raise EngineSegmentEvidenceError(
            f"kernel callback site 0x{rva:x} is not one exact indirect call"
        )
    instruction = instructions[0]
    operand = instruction.operands[0]
    if operand.type == x86_const.X86_OP_REG:
        return {
            "kind": "register",
            "register": instruction.reg_name(operand.reg).lower(),
        }
    if operand.type != x86_const.X86_OP_MEM:
        raise EngineSegmentEvidenceError(
            f"kernel callback site 0x{rva:x} has an unsupported target operand"
        )
    memory = operand.mem
    scale = int(memory.scale) if memory.index else 1
    if scale not in {1, 2, 4, 8}:
        raise EngineSegmentEvidenceError(
            f"kernel callback site 0x{rva:x} has an unsupported target scale"
        )
    return {
        "kind": "memory",
        "base": instruction.reg_name(memory.base).lower() if memory.base else None,
        "index": instruction.reg_name(memory.index).lower() if memory.index else None,
        "scale_shift": {1: 0, 2: 1, 4: 2, 8: 3}[scale],
        "displacement": int(memory.disp) & 0xFFFFFFFF,
    }


def _validate_exact_runtime_layout(
    *,
    binary: StageABinary,
    site: Mapping[str, Any],
    targets: Sequence[NativeIndirectCallTarget],
    site_rva: int,
) -> NativeIndirectCallRuntimeLayout:
    layout = _mapping(site.get("runtime_layout"), "exact runtime layout")
    if layout.get("format") != "stage-a-exact-runtime-layout-evidence-v1":
        raise EngineSegmentEvidenceError(
            f"kernel callback site 0x{site_rva:x} lacks exact runtime-layout evidence"
        )
    instance_rva = _u32(layout.get("instance_rva"), "runtime instance RVA")
    instance_size = _u32(layout.get("size"), "runtime instance size")
    if instance_size == 0:
        raise EngineSegmentEvidenceError("exact runtime instance has zero size")
    instance = _read_image_bytes(
        binary, instance_rva, instance_size, "exact runtime instance"
    )
    if _digest(
        layout.get("initial_bytes_sha256"), "runtime instance SHA-256"
    ) != sha256_bytes(instance):
        raise EngineSegmentEvidenceError("exact runtime instance byte hash is stale")
    submitted: set[tuple[int, int]] = set()
    pointer_fields: list[NativeIndirectCallRuntimePointerField] = []
    for index, raw_field in enumerate(
        _list(layout.get("pointer_fields"), "runtime pointer fields")
    ):
        field = _mapping(raw_field, f"runtime pointer field {index}")
        offset = _u32(field.get("offset"), f"runtime pointer field {index} offset")
        target_id = _u32(
            field.get("target_id"), f"runtime pointer field {index} target ID"
        )
        if offset + 4 > instance_size or (offset, target_id) in submitted:
            raise EngineSegmentEvidenceError("exact runtime pointer fields are invalid")
        submitted.add((offset, target_id))
        pointer_fields.append(
            NativeIndirectCallRuntimePointerField(
                offset=offset,
                target_id=target_id,
            )
        )
    expected: set[tuple[int, int]] = set()
    for target in targets:
        for slot in target.pointer_slots:
            if not instance_rva <= slot.rva < instance_rva + instance_size:
                raise EngineSegmentEvidenceError(
                    f"kernel callback site 0x{site_rva:x} pointer slot lies "
                    "outside its exact runtime instance"
                )
            expected.add((slot.rva - instance_rva, target.target_id))
    if submitted != expected:
        raise EngineSegmentEvidenceError(
            f"kernel callback site 0x{site_rva:x} runtime layout does not "
            "exactly inventory pointer slots"
        )
    return NativeIndirectCallRuntimeLayout(
        instance_rva=instance_rva,
        size=instance_size,
        initial_bytes_sha256=sha256_bytes(instance),
        pointer_fields=tuple(pointer_fields),
    )


def _load_semantic_transfers(path: Path) -> tuple[_SemanticTransfer, ...]:
    result: list[_SemanticTransfer] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, ValueError) as exc:
            raise EngineSegmentEvidenceError(
                f"semantic transfer line {line_number} is invalid JSON: {exc}"
            ) from exc
        row = _mapping(raw, f"semantic transfer line {line_number}")
        identity = _string(row.get("id"), "semantic transfer id")
        if identity in seen_ids:
            raise EngineSegmentEvidenceError(f"duplicate semantic transfer id {identity}")
        seen_ids.add(identity)
        contract_sha = _digest(row.get("contract_sha256"), "transfer contract SHA-256")
        expected_contract = normalize_stage_a_semantic_transfer(dict(row)).get(
            "contract_sha256"
        )
        if contract_sha != expected_contract:
            raise EngineSegmentEvidenceError(
                f"semantic transfer {identity} has a stale contract SHA-256"
            )
        instruction_sha = _digest(
            row.get("instruction_bytes_sha256"), "instruction bytes SHA-256"
        )
        span = _mapping(row.get("original"), f"semantic transfer {identity} span")
        start = _u32(span.get("rva_start"), "original.rva_start")
        end = _u32(span.get("rva_end"), "original.rva_end")
        size = _u32(span.get("size"), "original.size")
        if end <= start or end - start != size:
            raise EngineSegmentEvidenceError(
                f"semantic transfer {identity} has an invalid original span"
            )
        instructions = row.get("instructions")
        if not isinstance(instructions, list) or not instructions:
            raise EngineSegmentEvidenceError(
                f"semantic transfer {identity} has no exact instruction inventory"
            )
        encoded = bytearray()
        cursor = start
        for index, raw_instruction in enumerate(instructions):
            instruction = _mapping(
                raw_instruction, f"semantic transfer {identity} instruction {index}"
            )
            rva = _u32(instruction.get("rva"), "instruction rva")
            if rva != cursor:
                raise EngineSegmentEvidenceError(
                    f"semantic transfer {identity} instruction inventory is not contiguous"
                )
            raw_bytes = instruction.get("bytes")
            if not isinstance(raw_bytes, str):
                raise EngineSegmentEvidenceError(
                    f"semantic transfer {identity} instruction bytes are missing"
                )
            try:
                instruction_bytes = bytes.fromhex(raw_bytes)
            except ValueError as exc:
                raise EngineSegmentEvidenceError(
                    f"semantic transfer {identity} instruction bytes are malformed"
                ) from exc
            if not instruction_bytes:
                raise EngineSegmentEvidenceError(
                    f"semantic transfer {identity} contains an empty instruction"
                )
            encoded.extend(instruction_bytes)
            cursor += len(instruction_bytes)
        if cursor != end or sha256_bytes(bytes(encoded)) != instruction_sha:
            raise EngineSegmentEvidenceError(
                f"semantic transfer {identity} instruction hash/span binding changed"
            )
        result.append(
            _SemanticTransfer(
                identity=identity,
                contract_sha256=contract_sha,
                instruction_sha256=instruction_sha,
                start=start,
                end=end,
                row=row,
            )
        )
    if not result:
        raise EngineSegmentEvidenceError("semantic transfer inventory is empty")
    result.sort(key=lambda item: (item.start, item.end, item.identity))
    for previous, current in zip(result, result[1:]):
        if current.start < previous.end:
            raise EngineSegmentEvidenceError(
                f"semantic transfer spans overlap: {previous.identity} and {current.identity}"
            )
    return tuple(result)


def _validate_interpreter_manifests(
    *,
    semantic_path: Path,
    program_path: Path,
    package_path: Path,
    program: Mapping[str, Any],
    package: Mapping[str, Any],
) -> tuple[_ProgramTransfer, ...]:
    if package.get("format") != STAGE_B_INTERPRETER_PACKAGE_FORMAT:
        raise EngineSegmentEvidenceError("unsupported interpreter package format")
    if package.get("status") != "ready":
        raise EngineSegmentEvidenceError("interpreter package is not ready")
    state_binding = _mapping(package.get("state_machine"), "package state machine")
    if _digest(state_binding.get("sha256"), "package state machine SHA-256") != sha256_file(
        semantic_path
    ):
        raise EngineSegmentEvidenceError("interpreter package binds stale semantic transfers")
    program_binding = _mapping(package.get("program"), "package program")
    declared_program = _relative_file(
        package_path.parent,
        program_binding.get("path"),
        "package program path",
    )
    if declared_program.resolve() != program_path.resolve():
        raise EngineSegmentEvidenceError("package binds a different program manifest")
    if _digest(program_binding.get("sha256"), "package program SHA-256") != sha256_file(
        program_path
    ):
        raise EngineSegmentEvidenceError("interpreter program manifest changed after packaging")
    sources = package.get("sources")
    if not isinstance(sources, list) or not sources:
        raise EngineSegmentEvidenceError("interpreter package has no source inventory")
    source_roles: set[str] = set()
    for index, raw in enumerate(sources):
        binding = _mapping(raw, f"package source {index}")
        role = _string(binding.get("role"), "package source role")
        if role in source_roles:
            raise EngineSegmentEvidenceError(f"duplicate interpreter source role {role}")
        source_roles.add(role)
        source = _relative_file(
            package_path.parent, binding.get("path"), f"package source {role}"
        )
        if _digest(binding.get("sha256"), "package source SHA-256") != sha256_file(source):
            raise EngineSegmentEvidenceError(f"interpreter source {role} changed after packaging")

    if program.get("format") != STAGE_B_INTERPRETER_PROGRAM_FORMAT:
        raise EngineSegmentEvidenceError("unsupported interpreter program format")
    if _digest(program.get("state_machine_sha256"), "program state machine SHA-256") != sha256_file(
        semantic_path
    ):
        raise EngineSegmentEvidenceError("interpreter program binds stale semantic transfers")
    raw_transfers = program.get("transfers")
    if not isinstance(raw_transfers, list) or not raw_transfers:
        raise EngineSegmentEvidenceError("interpreter program has no transfer records")
    parsed: list[_ProgramTransfer] = []
    seen_ids: set[str] = set()
    seen_rvas: set[int] = set()
    for index, raw in enumerate(raw_transfers):
        row = _mapping(raw, f"program transfer {index}")
        identity = _string(row.get("id"), "program transfer id")
        rva = _u32(row.get("rva_start"), "program transfer RVA")
        if identity in seen_ids or rva in seen_rvas:
            raise EngineSegmentEvidenceError("interpreter program has duplicate transfer records")
        seen_ids.add(identity)
        seen_rvas.add(rva)
        counts = _mapping(row.get("counts"), "program transfer counts")
        parsed.append(
            _ProgramTransfer(
                identity=identity,
                rva_start=rva,
                contract_sha256=_digest(
                    row.get("contract_sha256"), "program contract SHA-256"
                ),
                instruction_sha256=_digest(
                    row.get("instruction_bytes_sha256"),
                    "program instruction SHA-256",
                ),
                word_count=_bounded_count(counts.get("word_nodes"), "word nodes", 1024),
                x87_count=_bounded_count(counts.get("x87_nodes"), "x87 nodes", 256),
                action_count=_bounded_count(counts.get("actions"), "actions", 8192),
                call_count=_bounded_count(counts.get("calls"), "calls", 1024),
                x87_replay_count=_bounded_count(
                    counts.get("x87_replays", 0), "x87 replays", 1024
                ),
            )
        )
    expected_order = sorted(parsed, key=lambda item: item.rva_start)
    if parsed != expected_order:
        raise EngineSegmentEvidenceError("interpreter program transfers are not canonical")
    counts = _mapping(program.get("counts"), "program counts")
    if _bounded_count(counts.get("transfers"), "program transfers", 1_000_000) != len(parsed):
        raise EngineSegmentEvidenceError("interpreter program transfer count does not match")
    package_counts = _mapping(package.get("counts"), "package counts")
    if dict(package_counts) != dict(counts):
        raise EngineSegmentEvidenceError("package and program counts differ")
    return tuple(parsed)


def _bind_transfer_inventories(
    semantic: Sequence[_SemanticTransfer], program: Sequence[_ProgramTransfer]
) -> None:
    if len(semantic) != len(program):
        raise EngineSegmentEvidenceError("semantic and program transfer counts differ")
    for source, record in zip(semantic, program, strict=True):
        observed = (
            record.identity,
            record.rva_start,
            record.contract_sha256,
            record.instruction_sha256,
        )
        expected = (
            source.identity,
            source.start,
            source.contract_sha256,
            source.instruction_sha256,
        )
        if observed != expected:
            raise EngineSegmentEvidenceError(
                f"program transfer binding differs at {source.identity}"
            )


def _bind_program_records(
    binary: StageABinary,
    symbols: Mapping[str, tuple[int, ...]],
    semantic: Sequence[_SemanticTransfer],
    program: Sequence[_ProgramTransfer],
) -> tuple[tuple[SemanticTransferBinding, ...], int]:
    table_rva = _unique_symbol(symbols, "stage_b_program_transfers")
    count_rva = _unique_symbol(symbols, "stage_b_program_transfer_count")
    count_bytes = _read_immutable(binary, count_rva, 4, "program transfer count")
    if struct.unpack("<I", count_bytes)[0] != len(program):
        raise EngineSegmentEvidenceError("compiled program transfer count differs from manifest")
    table_size = len(program) * _TRANSFER_RECORD_SIZE
    table = _read_immutable(binary, table_rva, table_size, "program transfer table")

    all_primary_ranges: list[tuple[int, int, str]] = [
        (table_rva, table_rva + table_size, "program transfer table")
    ]
    bindings: list[SemanticTransferBinding] = []
    for index, (source, declared) in enumerate(zip(semantic, program, strict=True)):
        record_rva = table_rva + index * _TRANSFER_RECORD_SIZE
        record = table[index * _TRANSFER_RECORD_SIZE : (index + 1) * _TRANSFER_RECORD_SIZE]
        (
            source_rva,
            word_count,
            x87_count,
            action_count,
            x87_replay_count,
            nodes_va,
            x87_nodes_va,
            actions_va,
            calls_va,
            x87_replays_va,
        ) = struct.unpack("<10I", record)
        if (source_rva, word_count, x87_count, action_count, x87_replay_count) != (
            source.start,
            declared.word_count,
            declared.x87_count,
            declared.action_count,
            declared.x87_replay_count,
        ):
            raise EngineSegmentEvidenceError(
                f"compiled program descriptor differs for {source.identity}"
            )
        ranges: list[ImmutableRange] = [
            ImmutableRange(
                role="transfer_descriptor",
                rva_start=record_rva,
                rva_end=record_rva + _TRANSFER_RECORD_SIZE,
                sha256=sha256_bytes(record),
            )
        ]
        specifications = (
            ("word_nodes", nodes_va, max(word_count, 1) * _WORD_NODE_SIZE),
            ("x87_nodes", x87_nodes_va, max(x87_count, 1) * _X87_NODE_SIZE),
            ("actions", actions_va, action_count * _ACTION_SIZE),
            ("calls", calls_va, max(declared.call_count, 1) * _CALL_SIZE),
            (
                "x87_replays",
                x87_replays_va,
                max(x87_replay_count, 1) * _X87_REPLAY_SIZE,
            ),
        )
        for role, va, size in specifications:
            if size <= 0:
                raise EngineSegmentEvidenceError(
                    f"compiled {role} range is empty for {source.identity}"
                )
            rva = _preferred_pointer_rva(binary, va, f"{source.identity} {role}")
            data = _read_immutable(binary, rva, size, f"{source.identity} {role}")
            ranges.append(
                ImmutableRange(role=role, rva_start=rva, rva_end=rva + size, sha256=sha256_bytes(data))
            )
            all_primary_ranges.append((rva, rva + size, f"{source.identity} {role}"))
        _validate_call_records(
            binary,
            next(item for item in ranges if item.role == "calls"),
            declared.call_count,
            source.identity,
        )
        _validate_x87_replay_records(
            binary,
            next(item for item in ranges if item.role == "x87_replays"),
            declared.x87_replay_count,
            source.identity,
        )
        combined = b"".join(
            item.role.encode("ascii")
            + struct.pack("<II", item.rva_start, item.rva_end)
            + bytes.fromhex(item.sha256)
            for item in ranges
        )
        bindings.append(
            SemanticTransferBinding(
                transfer_id=source.identity,
                contract_sha256=source.contract_sha256,
                instruction_bytes_sha256=source.instruction_sha256,
                original_rva_start=source.start,
                original_rva_end=source.end,
                record_index=index,
                record_rva=record_rva,
                record_sha256=sha256_bytes(combined),
                immutable_ranges=tuple(ranges),
            )
        )
    _reject_overlapping_ranges(all_primary_ranges)
    return tuple(bindings), table_rva


def _validate_call_records(
    binary: StageABinary, calls_range: ImmutableRange, count: int, transfer_id: str
) -> None:
    if count == 0:
        return
    data = _read_immutable(
        binary, calls_range.rva_start, count * _CALL_SIZE, f"{transfer_id} calls"
    )
    for index in range(count):
        fields = struct.unpack_from("<16I", data, index * _CALL_SIZE)
        kind = fields[0]
        if kind not in {0, 1, 2}:
            raise EngineSegmentEvidenceError(
                f"{transfer_id} compiled call {index} has an unknown kind"
            )
        dll_va, symbol_va = fields[6], fields[7]
        argument_count, stack_va, stack_count = fields[13], fields[14], fields[15]
        if argument_count > _MAX_CALL_ARGUMENTS or stack_count > _MAX_CALL_ARGUMENTS:
            raise EngineSegmentEvidenceError(
                f"{transfer_id} compiled call {index} exceeds the bounded ABI inventory"
            )
        for role, va, size in (
            ("register inputs", fields[10], 8 * 4),
            ("flag inputs", fields[11], 6 * 4),
            ("argument inputs", fields[12], argument_count * 4),
            ("stack inputs", stack_va, stack_count * _STACK_INPUT_SIZE),
        ):
            if size:
                rva = _preferred_pointer_rva(binary, va, f"{transfer_id} {role}")
                _read_immutable(binary, rva, size, f"{transfer_id} {role}")
        for role, va in (("DLL", dll_va), ("symbol", symbol_va)):
            if va:
                rva = _preferred_pointer_rva(binary, va, f"{transfer_id} {role}")
                _read_c_string(binary, rva, f"{transfer_id} {role}")


def _validate_x87_replay_records(
    binary: StageABinary,
    replay_range: ImmutableRange,
    count: int,
    transfer_id: str,
) -> None:
    if count == 0:
        return
    data = _read_immutable(
        binary,
        replay_range.rva_start,
        count * _X87_REPLAY_SIZE,
        f"{transfer_id} x87 replays",
    )
    string_roles = (
        "instruction SHA-256",
        "transfer SHA-256",
        "contract SHA-256",
        "checked decoder",
        "checked executor",
    )
    for index in range(count):
        fields = struct.unpack_from("<11I", data, index * _X87_REPLAY_SIZE)
        byte_count = fields[4]
        if not 1 <= byte_count <= 15:
            raise EngineSegmentEvidenceError(
                f"{transfer_id} compiled x87 replay {index} has an invalid instruction size"
            )
        instruction_rva = _preferred_pointer_rva(
            binary,
            fields[5],
            f"{transfer_id} compiled x87 replay {index} instruction bytes",
        )
        _read_immutable(
            binary,
            instruction_rva,
            byte_count,
            f"{transfer_id} compiled x87 replay {index} instruction bytes",
        )
        for role, pointer in zip(string_roles, fields[6:], strict=True):
            string_rva = _preferred_pointer_rva(
                binary,
                pointer,
                f"{transfer_id} compiled x87 replay {index} {role}",
            )
            _read_c_string(
                binary,
                string_rva,
                f"{transfer_id} compiled x87 replay {index} {role}",
            )


def _decode_kernel_ranges(
    binary: StageABinary,
    functions: Sequence[_FunctionRange],
    checked_indirect_targets: Mapping[int, NativeIndirectCallCapability],
) -> tuple[
    tuple[KernelRange, ...],
    tuple[ControlSite, ...],
    Mapping[str, frozenset[int]],
    tuple[EvidenceIssue, ...],
]:
    by_name: dict[str, list[_FunctionRange]] = {}
    for function in functions:
        for name in {function.name, *function.aliases}:
            by_name.setdefault(_symbol_key(name), []).append(function)
    required: list[_FunctionRange] = []
    for symbol in _REQUIRED_KERNEL_SYMBOLS:
        matches = _unique_functions(by_name.get(symbol, []))
        if len(matches) != 1:
            raise EngineSegmentEvidenceError(
                f"linker map has {len(matches)} ranges for required kernel symbol {symbol}"
            )
        required.append(matches[0])

    all_function_by_start: dict[int, _FunctionRange] = {}
    for function in functions:
        previous = all_function_by_start.get(function.start)
        if previous is not None and previous != function:
            raise EngineSegmentEvidenceError(
                f"linker map ambiguously owns function start RVA 0x{function.start:x}"
            )
        all_function_by_start[function.start] = function

    closure_symbols: dict[int, str] = {
        function.start: symbol
        for symbol, function in zip(_REQUIRED_KERNEL_SYMBOLS, required, strict=True)
    }
    known_symbols: dict[int, str] = {
        start: _symbol_key(function.name)
        for start, function in all_function_by_start.items()
    }
    known_symbols.update(closure_symbols)
    pending = sorted(closure_symbols)
    processed: set[int] = set()
    kernel: list[KernelRange] = []
    sites: list[ControlSite] = []
    issues: list[EvidenceIssue] = []
    decoded_by_function: dict[str, frozenset[int]] = {}
    while pending:
        start = pending.pop(0)
        if start in processed:
            continue
        processed.add(start)
        symbol = closure_symbols[start]
        section = _raw_executable_section_for_rva(binary, start)
        if section is None:
            issues.append(
                EvidenceIssue(
                    "unsupported_native_escape",
                    f"{symbol} starts outside a unique raw-backed executable payload range",
                    start,
                    start + 1,
                )
            )
            continue
        section_end = section.rva_start + section.raw_size
        declared = all_function_by_start.get(start)
        upper_bounds = [
            value
            for value in known_symbols
            if start < value <= section_end
        ]
        end = min(upper_bounds, default=section_end)
        if declared is not None:
            end = min(end, declared.end)
        decoded, function_sites, function_issues, discovered_targets = _decode_function_cfg(
            binary=binary,
            symbol=symbol,
            start=start,
            end=end,
            function_symbols=known_symbols,
            checked_indirect_targets=checked_indirect_targets,
        )
        if not decoded:
            issues.extend(function_issues)
            continue
        actual_end = max(
            instruction_start + instruction_size
            for instruction_start, instruction_size in decoded.items()
        )
        overlaps = [
            item
            for item in kernel
            if start < item.rva_end and item.rva_start < actual_end
        ]
        if overlaps:
            issues.append(
                EvidenceIssue(
                    "ambiguous_kernel_ownership",
                    f"{symbol} overlaps required kernel {overlaps[0].symbol}",
                    max(start, overlaps[0].rva_start),
                    min(actual_end, overlaps[0].rva_end),
                )
            )
            issues.extend(function_issues)
            continue

        data = _read_executable(binary, start, actual_end, symbol)
        decoded_by_function[symbol] = frozenset(decoded)
        sites.extend(function_sites)
        issues.extend(function_issues)
        kernel.append(
            KernelRange(
                symbol=symbol,
                rva_start=start,
                rva_end=actual_end,
                sha256=sha256_bytes(data),
                decoded_instruction_count=len(decoded),
            )
        )
        newly_required: list[int] = []
        for target in sorted(discovered_targets):
            if target in closure_symbols:
                continue
            owner = next(
                (
                    item
                    for item in kernel
                    if item.rva_start < target < item.rva_end
                ),
                None,
            )
            if owner is not None:
                issues.append(
                    EvidenceIssue(
                        "ambiguous_kernel_ownership",
                        (
                            f"{symbol} targets RVA 0x{target:x} inside "
                            f"required kernel {owner.symbol}"
                        ),
                        target,
                        target + 1,
                    )
                )
                continue
            target_function = all_function_by_start.get(target)
            target_symbol = (
                _symbol_key(target_function.name)
                if target_function is not None
                else _synthetic_helper_symbol(target)
            )
            closure_symbols[target] = target_symbol
            known_symbols[target] = target_symbol
            newly_required.append(target)
        pending.extend(newly_required)
        pending.sort()

    _reject_overlapping_ranges(
        [(item.rva_start, item.rva_end, item.symbol) for item in kernel]
    )
    return (
        tuple(sorted(kernel, key=lambda item: item.rva_start)),
        tuple(sorted(sites, key=lambda item: (item.instruction_rva, item.kind))),
        decoded_by_function,
        tuple(issues),
    )


def _decode_function_cfg(
    *,
    binary: StageABinary,
    symbol: str,
    start: int,
    end: int,
    function_symbols: Mapping[int, str],
    checked_indirect_targets: Mapping[int, NativeIndirectCallCapability],
) -> tuple[dict[int, int], list[ControlSite], list[EvidenceIssue], set[int]]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    pending = [start]
    decoded: dict[int, Any] = {}
    occupied: dict[int, int] = {}
    sites: list[ControlSite] = []
    issues: list[EvidenceIssue] = []
    discovered_targets: set[int] = set()
    import_thunks = {item.thunk_rva for item in binary.imports if item.thunk_rva is not None}
    while pending:
        cursor = pending.pop()
        while start <= cursor < end:
            if cursor != start and cursor in function_symbols:
                issues.append(
                    EvidenceIssue(
                        "ambiguous_kernel_ownership",
                        (
                            f"{symbol} reaches distinct function start "
                            f"{function_symbols[cursor]} at RVA 0x{cursor:x}"
                        ),
                        cursor,
                        cursor + 1,
                    )
                )
                break
            if cursor in decoded:
                break
            raw = binary.pe.get_data(cursor, min(15, end - cursor))
            instructions = list(
                decoder.disasm(raw, binary.image_base + cursor, count=1)
            )
            if not instructions:
                issues.append(
                    EvidenceIssue(
                        "kernel_decode_failure",
                        f"{symbol} does not decode at RVA 0x{cursor:x}",
                        cursor,
                        min(cursor + 1, end),
                    )
                )
                break
            instruction = instructions[0]
            instruction_rva = int(instruction.address) - binary.image_base
            instruction_end = instruction_rva + int(instruction.size)
            if instruction_rva != cursor or instruction_end > end:
                issues.append(
                    EvidenceIssue(
                        "kernel_decode_crosses_range",
                        f"{symbol} instruction crosses its linker-map range",
                        cursor,
                        min(instruction_end, end),
                    )
                )
                break
            if any(byte in occupied for byte in range(cursor, instruction_end)):
                issues.append(
                    EvidenceIssue(
                        "overlapping_kernel_decode",
                        f"{symbol} has overlapping instruction decodes",
                        cursor,
                        instruction_end,
                    )
                )
                break
            decoded[cursor] = instruction
            for byte in range(cursor, instruction_end):
                occupied[byte] = cursor
            if instruction.group(capstone.x86.X86_GRP_FPU) and not (
                is_reviewed_x87_frame_instruction(instruction)
            ):
                issues.append(
                    EvidenceIssue(
                        "unsupported_x87_kernel_instruction",
                        f"{symbol} contains unqualified x87 instruction {instruction.mnemonic}",
                        cursor,
                        instruction_end,
                    )
                )
            mnemonic = instruction.mnemonic.lower()
            if mnemonic in {"int", "int1", "int3", "into", "syscall", "sysenter", "iret", "iretd"}:
                issues.append(
                    EvidenceIssue(
                        "unsupported_native_escape",
                        f"{symbol} contains native escape {mnemonic}",
                        cursor,
                        instruction_end,
                    )
                )
            if instruction.group(capstone.CS_GRP_RET):
                sites.append(ControlSite(symbol, cursor, "return"))
                break
            if instruction.group(capstone.CS_GRP_CALL):
                target = _direct_target(binary, instruction)
                if target is not None:
                    if _raw_executable_section_for_rva(binary, target) is None:
                        issues.append(
                            EvidenceIssue(
                                "unsupported_native_escape",
                                (
                                    f"{symbol} calls target RVA 0x{target:x} outside "
                                    "a unique raw-backed executable payload range"
                                ),
                                cursor,
                                instruction_end,
                            )
                        )
                        sites.append(ControlSite(symbol, cursor, "native_call", target))
                    else:
                        target_symbol = function_symbols.get(
                            target, _synthetic_helper_symbol(target)
                        )
                        discovered_targets.add(target)
                        sites.append(
                            ControlSite(
                                symbol,
                                cursor,
                                "helper_call",
                                target,
                                target_symbol,
                            )
                        )
                else:
                    iat = _iat_indirect_target(binary, instruction)
                    if iat is not None and iat in import_thunks:
                        sites.append(ControlSite(symbol, cursor, "external_call", iat))
                    else:
                        checked_capability = checked_indirect_targets.get(cursor)
                        if checked_capability is None:
                            sites.append(
                                ControlSite(symbol, cursor, "helper_indirect_call")
                            )
                            issues.append(
                                EvidenceIssue(
                                    "unsupported_native_escape",
                                    f"{symbol} has an indirect call without a checked target set",
                                    cursor,
                                    instruction_end,
                                )
                            )
                        else:
                            sites.append(
                                ControlSite(
                                    symbol,
                                    cursor,
                                    "checked_helper_indirect_call",
                                    target_rvas=tuple(
                                        target.rva
                                        for target in checked_capability.targets
                                    ),
                                    capability_id=checked_capability.capability_id,
                                )
                            )
                            discovered_targets.update(
                                target.rva for target in checked_capability.targets
                            )
                cursor = instruction_end
                continue
            if instruction.group(capstone.CS_GRP_JUMP):
                target = _direct_target(binary, instruction)
                conditional = instruction.id != x86_const.X86_INS_JMP
                if target is None:
                    sites.append(ControlSite(symbol, cursor, "unclassified_indirect_exit"))
                    issues.append(
                        EvidenceIssue(
                            "unclassified_kernel_exit",
                            f"{symbol} has an indirect jump without a checked target set",
                            cursor,
                            instruction_end,
                        )
                    )
                    break
                sites.append(
                    ControlSite(
                        symbol,
                        cursor,
                        "conditional_branch" if conditional else "direct_jump",
                        target,
                    )
                )
                if (
                    start <= target < end
                    and (target == start or target not in function_symbols)
                ):
                    pending.append(target)
                elif _raw_executable_section_for_rva(binary, target) is not None:
                    target_symbol = function_symbols.get(
                        target, _synthetic_helper_symbol(target)
                    )
                    discovered_targets.add(target)
                    sites[-1] = ControlSite(
                        symbol,
                        cursor,
                        "helper_tail_jump",
                        target,
                        target_symbol,
                    )
                else:
                    issues.append(
                        EvidenceIssue(
                            "unsupported_native_escape",
                            (
                                f"{symbol} jumps to target RVA 0x{target:x} outside "
                                "a unique raw-backed executable payload range"
                            ),
                            cursor,
                            instruction_end,
                        )
                    )
                if conditional:
                    cursor = instruction_end
                    continue
                break
            cursor = instruction_end
        else:
            issue_code = (
                "ambiguous_kernel_ownership"
                if end in function_symbols and end != start
                else "unclassified_kernel_exit"
            )
            message = (
                f"{symbol} falls through into distinct function start "
                f"{function_symbols[end]} at RVA 0x{end:x}"
                if issue_code == "ambiguous_kernel_ownership"
                else f"{symbol} falls through its bounded executable range"
            )
            issues.append(
                EvidenceIssue(
                    issue_code,
                    message,
                    end - 1 if end else end,
                    end,
                )
            )
    return (
        {
            instruction_rva: int(instruction.size)
            for instruction_rva, instruction in decoded.items()
        },
        sites,
        issues,
        discovered_targets,
    )


def _engine_executable_coverage(
    binary: StageABinary,
    kernels: Sequence[KernelRange],
    decoded_by_function: Mapping[str, frozenset[int]],
) -> tuple[tuple[ExecutableCoverageRange, ...], tuple[EvidenceIssue, ...]]:
    kernel_sections = {
        (
            section.rva_start,
            section.rva_end,
        )
        for kernel in kernels
        for section in (_section_for_range(binary, kernel.rva_start, kernel.rva_end),)
    }
    owned = sorted(
        (kernel.rva_start, kernel.rva_end, kernel.symbol) for kernel in kernels
    )
    _reject_overlapping_ranges(owned)
    coverage: list[ExecutableCoverageRange] = []
    issues: list[EvidenceIssue] = []
    for start, end, owner in owned:
        data = _read_executable(binary, start, end, owner)
        coverage.append(
            ExecutableCoverageRange(
                classification="required_kernel_function",
                required_for_kernel_closure=True,
                rva_start=start,
                rva_end=end,
                sha256=sha256_bytes(data),
                owner=owner,
            )
        )
    for section in binary.sections:
        if not section.executable or (section.rva_start, section.rva_end) not in kernel_sections:
            continue
        cursor = section.rva_start
        section_owned = [row for row in owned if section.rva_start <= row[0] < section.rva_end]
        for start, end, _owner in section_owned:
            if cursor < start:
                _classify_unowned_gap(binary, cursor, start, coverage, issues)
            cursor = max(cursor, end)
        if cursor < section.rva_end:
            _classify_unowned_gap(binary, cursor, section.rva_end, coverage, issues)

    kernel_by_name = {item.symbol: item for item in kernels}
    for symbol, starts in decoded_by_function.items():
        kernel = kernel_by_name[symbol]
        decoded_bytes: set[int] = set()
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        for start in starts:
            raw = binary.pe.get_data(start, min(15, kernel.rva_end - start))
            instruction = next(
                iter(decoder.disasm(raw, binary.image_base + start, count=1)), None
            )
            if instruction is not None:
                decoded_bytes.update(range(start, start + int(instruction.size)))
        gaps = _missing_ranges(kernel.rva_start, kernel.rva_end, decoded_bytes)
        for start, end in gaps:
            data = bytes(binary.pe.get_data(start, end - start))
            if not _padding_bytes(data):
                issues.append(
                    EvidenceIssue(
                        "unowned_kernel_bytes",
                        f"{symbol} has non-padding bytes outside its reachable decoded CFG",
                        start,
                        end,
                    )
                )
    return tuple(coverage), tuple(issues)


def _classify_semantic_evidence(
    transfers: Sequence[_SemanticTransfer],
) -> tuple[
    tuple[EvidenceIssue, ...],
    tuple[ExternalTailBinding, ...],
    tuple[X87ReplayObligation, ...],
]:
    issues: list[EvidenceIssue] = []
    external_tails: list[ExternalTailBinding] = []
    x87_replays: list[X87ReplayObligation] = []
    required_x87 = {
        "stack",
        "tags",
        "control",
        "status",
        "pending_exception",
        "last_opcode",
        "instruction_pointer",
        "code_selector",
        "data_pointer",
        "data_selector",
    }
    for transfer in transfers:
        status = transfer.row.get("status")
        replay_obligation, replay_error = _exact_x87_replay_obligation(transfer)
        replay_is_declared_frontier = (
            status == "incomplete"
            and transfer.row.get("blocker_category")
            == "x87_physical_state_requires_native_exact_command_replay"
            and replay_obligation is not None
        )
        if status != "reimplementable" and not replay_is_declared_frontier:
            issues.append(
                EvidenceIssue(
                    "semantic_transfer_not_reimplementable",
                    f"{transfer.identity} has Stage A status {status!r}",
                    transfer.start,
                    transfer.end,
                    transfer.identity,
                )
            )
        fpu = transfer.row.get("fpu_state")
        if replay_obligation is not None:
            x87_replays.append(replay_obligation)
        elif isinstance(fpu, Mapping) and fpu.get("model") == (
            "native_exact_x87_command_replay_obligation_v1"
        ):
            issues.append(
                EvidenceIssue(
                    "unsupported_x87_transfer",
                    f"{transfer.identity} has malformed exact x87 replay evidence: "
                    f"{replay_error or 'unknown validation failure'}",
                    transfer.start,
                    transfer.end,
                    transfer.identity,
                )
            )
        elif fpu is not None:
            if not isinstance(fpu, Mapping) or fpu.get("model") != "symbolic_x87_stack_v1":
                missing = set(required_x87)
            else:
                missing = required_x87 - set(fpu)
                if not isinstance(fpu.get("stack"), list) or len(fpu.get("stack", [])) != 8:
                    missing.add("stack[8]")
                if not isinstance(fpu.get("tags"), list) or len(fpu.get("tags", [])) != 8:
                    missing.add("tags[8]")
            if missing:
                issues.append(
                    EvidenceIssue(
                        "unsupported_x87_transfer",
                        f"{transfer.identity} lacks physical x87 evidence: "
                        + ", ".join(sorted(missing)),
                        transfer.start,
                        transfer.end,
                        transfer.identity,
                    )
                )
        outcome = transfer.row.get("outcome")
        if isinstance(outcome, Mapping) and outcome.get("kind") == "external_jump":
            binding, error = _external_tail_binding(transfer, outcome)
            if binding is None:
                issues.append(
                    EvidenceIssue(
                        "external_tail_identity_unmaterialized",
                        f"{transfer.identity} external tail is not uniquely materialized: "
                        f"{error}",
                        transfer.start,
                        transfer.end,
                        transfer.identity,
                    )
                )
            else:
                external_tails.append(binding)
    return tuple(issues), tuple(external_tails), tuple(x87_replays)


def _exact_x87_replay_obligation(
    transfer: _SemanticTransfer,
) -> tuple[X87ReplayObligation | None, str | None]:
    fpu = transfer.row.get("fpu_state")
    if not isinstance(fpu, Mapping) or fpu.get("model") != (
        "native_exact_x87_command_replay_obligation_v1"
    ):
        return None, None
    if fpu.get("authoritative_state_type") != "StageA.X87.PhysicalState":
        return None, "authoritative physical state type is missing"
    replay = fpu.get("replay")
    if not isinstance(replay, Mapping) or replay.get("format") != (
        "stage-a-native-exact-x87-command-replay-obligation-v1"
    ):
        return None, "exact replay record is missing or has the wrong format"
    if replay.get("checked_decoder") != "StageA.Relational.X87.decodeSingletonCommand":
        return None, "checked singleton decoder identity differs"
    if replay.get("checked_executor") != "StageA.Relational.X87.executeSingletonCommand":
        return None, "checked singleton executor identity differs"
    raw_bytes = replay.get("bytes")
    if not isinstance(raw_bytes, str):
        return None, "exact replay bytes are missing"
    try:
        replay_bytes = bytes.fromhex(raw_bytes)
    except ValueError:
        return None, "exact replay bytes are malformed"
    instruction_bytes = b"".join(
        bytes.fromhex(str(instruction["bytes"]))
        for instruction in transfer.row["instructions"]
    )
    if replay_bytes != instruction_bytes:
        return None, "exact replay bytes differ from the transfer inventory"
    if replay.get("bytes_sha256") != transfer.instruction_sha256:
        return None, "exact replay hash differs from the transfer hash"
    if sha256_bytes(replay_bytes) != transfer.instruction_sha256:
        return None, "exact replay bytes do not satisfy their SHA-256"

    schedule = replay.get("instruction_effect_schedule")
    if not isinstance(schedule, Mapping) or schedule.get("format") != (
        "stage-a-instruction-ordered-effect-schedule-v1"
    ):
        return None, "instruction effect schedule is missing or has the wrong format"
    if schedule.get("proof_authority") is not False:
        return None, "instruction effect schedule claims proof authority"
    if schedule.get("blockers") != []:
        return None, "instruction effect schedule has unresolved blockers"
    records = schedule.get("records")
    if not isinstance(records, list) or not records:
        return None, "instruction effect schedule is empty"
    cursor = transfer.start
    scheduled_bytes = bytearray()
    x87_count = 0
    for index, raw_record in enumerate(records):
        if not isinstance(raw_record, Mapping) or raw_record.get("index") != index:
            return None, "instruction effect records are not canonically indexed"
        start = raw_record.get("rva_start")
        end = raw_record.get("rva_end")
        if start != cursor or isinstance(end, bool) or not isinstance(end, int) or end <= start:
            return None, "instruction effect records are not contiguous"
        encoded = raw_record.get("bytes")
        if not isinstance(encoded, str):
            return None, "instruction effect record bytes are missing"
        try:
            record_bytes = bytes.fromhex(encoded)
        except ValueError:
            return None, "instruction effect record bytes are malformed"
        if len(record_bytes) != end - start:
            return None, "instruction effect record span differs from its bytes"
        if raw_record.get("bytes_sha256") != sha256_bytes(record_bytes):
            return None, "instruction effect record hash differs"
        if raw_record.get("transfer_bytes_sha256") != transfer.instruction_sha256:
            return None, "instruction effect record is bound to a different transfer"
        if raw_record.get("instruction_class") == "x87_singleton_checked_replay":
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            decoder.detail = True
            decoded = list(decoder.disasm(record_bytes, start))
            if (
                len(decoded) != 1
                or int(decoded[0].size) != len(record_bytes)
            ):
                return None, "x87 command bytes do not decode as one instruction"
            singleton = raw_record.get("x87_singleton_replay")
            if not isinstance(singleton, Mapping):
                return None, "x87 singleton replay record is missing"
            if singleton.get("checked_decoder") != replay.get("checked_decoder"):
                return None, "x87 singleton decoder identity differs"
            if singleton.get("checked_executor") != replay.get("checked_executor"):
                return None, "x87 singleton executor identity differs"
            if singleton.get("rva_start") != start or singleton.get("rva_end") != end:
                return None, "x87 singleton span differs from its schedule record"
            if singleton.get("bytes_sha256") != sha256_bytes(record_bytes):
                return None, "x87 singleton hash differs from its schedule record"
            x87_count += 1
        scheduled_bytes.extend(record_bytes)
        cursor = end
    if cursor != transfer.end or bytes(scheduled_bytes) != instruction_bytes:
        return None, "instruction effect schedule does not cover the transfer exactly"
    if x87_count == 0:
        return None, "exact x87 replay schedule has no x87 singleton"
    counts = schedule.get("counts")
    if not isinstance(counts, Mapping):
        return None, "instruction effect schedule counts are missing"
    if counts.get("instructions") != len(records) or counts.get("x87_singletons") != x87_count:
        return None, "instruction effect schedule counts differ from its records"
    return (
        X87ReplayObligation(
            transfer_id=transfer.identity,
            contract_sha256=transfer.contract_sha256,
            replay_sha256=_canonical_sha256(dict(replay)),
            schedule_sha256=_canonical_sha256(dict(schedule)),
            instruction_count=len(records),
            x87_singleton_count=x87_count,
        ),
        None,
    )


def _external_tail_binding(
    transfer: _SemanticTransfer, outcome: Mapping[str, Any]
) -> tuple[ExternalTailBinding | None, str]:
    identity, error = _static_import_identity(outcome)
    if identity is None:
        return None, f"outcome {error}"
    events = transfer.row.get("external_events")
    if not isinstance(events, list):
        return None, "external event inventory is missing"
    matches: list[tuple[int, Mapping[str, Any]]] = []
    for index, raw_event in enumerate(events):
        if not isinstance(raw_event, Mapping) or raw_event.get("kind") != "external_call":
            continue
        event_identity, _event_error = _static_import_identity(raw_event)
        if event_identity is not None and _same_import_identity(identity, event_identity):
            matches.append((index, raw_event))
    if len(matches) != 1:
        return None, f"has {len(matches)} matching external-call events"
    index, event = matches[0]
    dll, symbol, ordinal = identity
    evidence = {"outcome": dict(outcome), "external_event": dict(event)}
    return (
        ExternalTailBinding(
            transfer_id=transfer.identity,
            contract_sha256=transfer.contract_sha256,
            dll=dll,
            symbol=symbol,
            ordinal=ordinal,
            external_event_index=index,
            static_evidence_sha256=_canonical_sha256(evidence),
        ),
        "",
    )


def _static_import_identity(
    value: Mapping[str, Any],
) -> tuple[tuple[str, str | None, int | None] | None, str]:
    dll = value.get("dll")
    if not isinstance(dll, str) or not dll:
        return None, "has no DLL identity"
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    if symbol is not None and (not isinstance(symbol, str) or not symbol):
        return None, "has an invalid symbol identity"
    if ordinal is not None and (
        isinstance(ordinal, bool) or not isinstance(ordinal, int) or not 0 <= ordinal <= 0xFFFF
    ):
        return None, "has an invalid ordinal identity"
    if (symbol is None) == (ordinal is None):
        return None, "must identify exactly one symbol or ordinal"
    return (dll, symbol, ordinal), ""


def _same_import_identity(
    left: tuple[str, str | None, int | None],
    right: tuple[str, str | None, int | None],
) -> bool:
    return left[0].casefold() == right[0].casefold() and left[1:] == right[1:]


def _bind_cutpoints(
    transfers: Sequence[_SemanticTransfer], cutpoints: Iterable[int]
) -> tuple[tuple[ProductCutpointOwner, ...], tuple[EvidenceIssue, ...]]:
    values: list[int] = []
    seen: set[int] = set()
    for raw in cutpoints:
        rva = _u32(raw, "product cutpoint")
        if rva in seen:
            raise EngineSegmentEvidenceError(f"duplicate product cutpoint RVA 0x{rva:x}")
        seen.add(rva)
        values.append(rva)
    owners: list[ProductCutpointOwner] = []
    issues: list[EvidenceIssue] = []
    for rva in sorted(values):
        matches = [item for item in transfers if item.start <= rva < item.end]
        if len(matches) != 1:
            issues.append(
                EvidenceIssue(
                    "product_cutpoint_unowned",
                    f"product cutpoint RVA 0x{rva:x} lies in {len(matches)} transfer spans",
                    rva,
                    rva + 1,
                )
            )
            continue
        owner = matches[0]
        owners.append(ProductCutpointOwner(rva, owner.identity, rva - owner.start))
    return tuple(owners), tuple(issues)


def _proof_obligations(
    transfers: Sequence[SemanticTransferBinding],
    external_tails: Sequence[ExternalTailBinding],
    x87_replays: Sequence[X87ReplayObligation],
    kernels: Sequence[KernelRange],
    sites: Sequence[ControlSite],
    native_indirect_calls: Sequence[NativeIndirectCallCapability],
    cutpoints: Sequence[ProductCutpointOwner],
    issues: Sequence[EvidenceIssue],
) -> tuple[ProofObligation, ...]:
    obligations = [
        ProofObligation(
            f"engine-transfer:{index:06d}",
            "semantic_transfer_refinement",
            transfer.transfer_id,
        )
        for index, transfer in enumerate(transfers)
    ]
    obligations.extend(
        ProofObligation(
            f"engine-x87-replay:{index:06d}",
            "exact_x87_command_replay",
            replay.transfer_id,
        )
        for index, replay in enumerate(x87_replays)
    )
    obligations.extend(
        ProofObligation(
            f"engine-external-tail:{index:06d}",
            "external_tail_import_refinement",
            (
                f"{tail.transfer_id}:"
                f"{tail.dll}!{tail.symbol if tail.symbol is not None else '#' + str(tail.ordinal)}"
            ),
        )
        for index, tail in enumerate(external_tails)
    )
    obligations.extend(
        ProofObligation(
            f"engine-kernel:{index:04d}",
            "interpreter_kernel_semantics",
            kernel.symbol,
        )
        for index, kernel in enumerate(kernels)
    )
    obligations.extend(
        ProofObligation(
            f"engine-call:{index:06d}",
            "kernel_call_refinement",
            f"{site.kernel_symbol}@0x{site.instruction_rva:x}:{site.kind}",
        )
        for index, site in enumerate(sites)
        if "call" in site.kind
    )
    obligations.extend(
        ProofObligation(
            f"engine-native-indirect-exact:{index:06d}",
            "native_indirect_call_exact_candidate_evidence",
            capability.capability_id,
        )
        for index, capability in enumerate(native_indirect_calls)
    )
    obligations.extend(
        ProofObligation(
            f"engine-native-indirect-flow:{index:06d}",
            "native_indirect_call_target_flow",
            capability.capability_id,
        )
        for index, capability in enumerate(native_indirect_calls)
    )
    obligations.extend(
        ProofObligation(
            f"engine-native-indirect-abi:{index:06d}",
            "native_indirect_call_abi_refinement",
            capability.capability_id,
        )
        for index, capability in enumerate(native_indirect_calls)
    )
    obligations.extend(
        ProofObligation(
            f"engine-native-indirect-preservation:{index:06d}",
            "native_indirect_call_pointer_slot_preservation",
            capability.capability_id,
        )
        for index, capability in enumerate(native_indirect_calls)
        if any(
            slot.writable
            for target in capability.targets
            for slot in target.pointer_slots
        )
    )
    obligations.extend(
        ProofObligation(
            f"engine-native-indirect-execution:{index:06d}",
            "native_indirect_call_target_execution",
            f"{capability.capability_id}:{','.join(capability.dynamic_requirements)}",
        )
        for index, capability in enumerate(native_indirect_calls)
    )
    obligations.extend(
        ProofObligation(
            f"engine-cutpoint:{index:06d}",
            "interior_cutpoint_composition",
            f"{owner.transfer_id}+0x{owner.offset:x}",
        )
        for index, owner in enumerate(cutpoints)
        if owner.offset != 0
    )
    obligations.extend(
        ProofObligation(
            f"engine-blocker:{index:06d}",
            "frontier_resolution",
            issue.code,
            status="blocked",
        )
        for index, issue in enumerate(issues)
    )
    return tuple(obligations)


def _load_linker_symbols(path: Path, binary: StageABinary) -> dict[str, tuple[int, ...]]:
    result: dict[str, set[int]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _GNU_SYMBOL.match(line)
        if match is not None:
            address, name = int(match.group(1), 16), match.group(2)
        else:
            msvc = _MSVC_SYMBOL.match(line)
            if msvc is None:
                continue
            name, address = msvc.group(1), int(msvc.group(2), 16)
        if name.startswith("."):
            continue
        rva = address - binary.image_base if address >= binary.image_base else address
        if not 0 <= rva < binary.size_of_image:
            continue
        result.setdefault(_symbol_key(name), set()).add(rva)
    return {key: tuple(sorted(values)) for key, values in result.items()}


def _load_function_ranges(path: Path, binary: StageABinary) -> tuple[_FunctionRange, ...]:
    rows = _parse_linker_map_functions(path, binary)
    result = tuple(
        _FunctionRange(
            name=_string(row.get("name"), "linker function name"),
            aliases=tuple(str(value) for value in row.get("aliases", [])),
            start=_u32(row.get("rva_start"), "linker function start"),
            end=_u32(row.get("rva_end"), "linker function end"),
            section=_string(row.get("section"), "linker function section"),
        )
        for row in rows
    )
    if not result:
        raise EngineSegmentEvidenceError("candidate linker map has no executable functions")
    return result


def _locate_exact_read_only_bytes(binary: StageABinary, data: bytes, label: str) -> int:
    matches: list[int] = []
    image = binary.path.read_bytes()
    for section in binary.sections:
        if section.writable or section.executable or section.raw_size < len(data):
            continue
        raw = image[section.raw_pointer : section.raw_pointer + section.raw_size]
        cursor = 0
        while True:
            found = raw.find(data, cursor)
            if found < 0:
                break
            matches.append(section.rva_start + found)
            cursor = found + 1
    if len(matches) != 1:
        raise EngineSegmentEvidenceError(
            f"candidate contains {len(matches)} exact read-only {label} payloads"
        )
    return matches[0]


def _unique_symbol(symbols: Mapping[str, tuple[int, ...]], name: str) -> int:
    matches = symbols.get(name, ())
    if len(matches) != 1:
        raise EngineSegmentEvidenceError(
            f"linker map has {len(matches)} addresses for required symbol {name}"
        )
    return matches[0]


def _read_immutable(binary: StageABinary, rva: int, size: int, label: str) -> bytes:
    if size <= 0:
        raise EngineSegmentEvidenceError(f"{label} has a non-positive size")
    matches = [
        section
        for section in binary.sections
        if not section.writable
        and section.rva_start <= rva
        and rva + size <= section.rva_start + section.raw_size
    ]
    if len(matches) != 1:
        raise EngineSegmentEvidenceError(
            f"{label} is not contained by exactly one immutable raw-backed section"
        )
    data = bytes(binary.pe.get_data(rva, size))
    if len(data) != size:
        raise EngineSegmentEvidenceError(f"{label} bytes are truncated")
    return data


def _read_executable(binary: StageABinary, start: int, end: int, label: str) -> bytes:
    matches = [
        section
        for section in binary.sections
        if section.executable
        and section.rva_start <= start
        and end <= section.rva_start + section.raw_size
    ]
    if end <= start or len(matches) != 1:
        raise EngineSegmentEvidenceError(
            f"{label} is not contained by exactly one raw-backed executable section"
        )
    data = bytes(binary.pe.get_data(start, end - start))
    if len(data) != end - start:
        raise EngineSegmentEvidenceError(f"{label} executable bytes are truncated")
    return data


def _read_image_bytes(
    binary: StageABinary, rva: int, size: int, label: str
) -> bytes:
    if size <= 0:
        raise EngineSegmentEvidenceError(f"{label} size must be positive")
    matches = [
        section
        for section in binary.sections
        if section.rva_start <= rva
        and rva + size <= section.rva_start + section.raw_size
    ]
    if len(matches) != 1:
        raise EngineSegmentEvidenceError(
            f"{label} does not lie in one raw-backed PE section"
        )
    data = bytes(binary.pe.get_data(rva, size))
    if len(data) != size:
        raise EngineSegmentEvidenceError(f"cannot read exact {label} bytes")
    return data


def _highlow_relocations(binary: StageABinary) -> frozenset[int]:
    result: set[int] = set()
    for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", ()) or ():
        for entry in block.entries:
            if int(entry.type) == 3:
                result.add(int(entry.rva))
    return frozenset(result)


def _raw_executable_section_for_rva(binary: StageABinary, rva: int) -> Any | None:
    matches = [
        section
        for section in binary.sections
        if section.executable
        and section.rva_start <= rva < section.rva_start + section.raw_size
    ]
    return matches[0] if len(matches) == 1 else None


def _read_c_string(binary: StageABinary, rva: int, label: str) -> bytes:
    section = next(
        (
            item
            for item in binary.sections
            if not item.writable
            and item.rva_start <= rva < item.rva_start + item.raw_size
        ),
        None,
    )
    if section is None:
        raise EngineSegmentEvidenceError(f"{label} string is outside immutable data")
    bound = min(_MAX_STRING_BYTES, section.rva_start + section.raw_size - rva)
    data = bytes(binary.pe.get_data(rva, bound))
    terminator = data.find(b"\0")
    if terminator < 0:
        raise EngineSegmentEvidenceError(f"{label} string is not bounded and terminated")
    return data[: terminator + 1]


def _preferred_pointer_rva(binary: StageABinary, value: int, label: str) -> int:
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        return value - binary.image_base
    raise EngineSegmentEvidenceError(f"{label} pointer is outside the preferred image")


def _direct_target(binary: StageABinary, instruction: Any) -> int | None:
    if not instruction.operands or instruction.operands[0].type != x86_const.X86_OP_IMM:
        return None
    address = int(instruction.operands[0].imm) & 0xFFFFFFFF
    return address - binary.image_base if address >= binary.image_base else address


def _iat_indirect_target(binary: StageABinary, instruction: Any) -> int | None:
    if not instruction.operands or instruction.operands[0].type != x86_const.X86_OP_MEM:
        return None
    memory = instruction.operands[0].mem
    if memory.base or memory.index:
        return None
    address = int(memory.disp) & 0xFFFFFFFF
    return address - binary.image_base if address >= binary.image_base else address


def _classify_unowned_gap(
    binary: StageABinary,
    start: int,
    end: int,
    coverage: list[ExecutableCoverageRange],
    issues: list[EvidenceIssue],
) -> None:
    data = bytes(binary.pe.get_data(start, end - start))
    if len(data) == end - start and _padding_bytes(data):
        coverage.append(
            ExecutableCoverageRange(
                classification="payload_padding_outside_required_kernel",
                required_for_kernel_closure=False,
                rva_start=start,
                rva_end=end,
                sha256=sha256_bytes(data),
            )
        )
    else:
        coverage.append(
            ExecutableCoverageRange(
                classification="unclassified_payload_outside_required_kernel",
                required_for_kernel_closure=False,
                rva_start=start,
                rva_end=end,
                sha256=sha256_bytes(data),
            )
        )


def _padding_bytes(data: bytes) -> bool:
    if not data or all(byte in {0x00, 0x90} for byte in data):
        return True
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoded = list(decoder.disasm(data, 0))
    return sum(int(item.size) for item in decoded) == len(data) and all(
        item.mnemonic == "nop" for item in decoded
    )


def _missing_ranges(start: int, end: int, present: set[int]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    cursor = start
    while cursor < end:
        if cursor in present:
            cursor += 1
            continue
        gap_start = cursor
        while cursor < end and cursor not in present:
            cursor += 1
        result.append((gap_start, cursor))
    return result


def _reject_overlapping_ranges(ranges: Sequence[tuple[int, int, str]]) -> None:
    ordered = sorted(ranges)
    for previous, current in zip(ordered, ordered[1:]):
        if current[0] < previous[1]:
            raise EngineSegmentEvidenceError(
                f"immutable/owned ranges overlap: {previous[2]} and {current[2]}"
            )


def _section_for_range(binary: StageABinary, start: int, end: int) -> Any:
    matches = [
        section
        for section in binary.sections
        if section.rva_start <= start and end <= section.rva_end
    ]
    if len(matches) != 1:
        raise EngineSegmentEvidenceError("kernel range has no unique candidate section")
    return matches[0]


def _unique_functions(values: Sequence[_FunctionRange]) -> list[_FunctionRange]:
    by_range = {(item.start, item.end): item for item in values}
    return list(by_range.values())


def _deduplicate_issues(issues: Sequence[EvidenceIssue]) -> list[EvidenceIssue]:
    return list(
        {
            (item.code, item.message, item.rva_start, item.rva_end, item.transfer_id): item
            for item in issues
        }.values()
    )


def _symbol_key(name: str) -> str:
    return name.lstrip("_")


def _synthetic_helper_symbol(rva: int) -> str:
    return f"synthetic_kernel_helper_{rva:08x}"


def _regular_file(value: Path | str, label: str) -> Path:
    path = Path(value).resolve()
    if not path.is_file() or path.is_symlink():
        raise EngineSegmentEvidenceError(f"{label} must be a regular non-symlink file")
    return path


def _relative_file(root: Path, value: Any, label: str) -> Path:
    relative = _string(value, label)
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise EngineSegmentEvidenceError(f"{label} must be package-relative")
    resolved = (root / path).resolve()
    if root.resolve() not in resolved.parents or not resolved.is_file() or resolved.is_symlink():
        raise EngineSegmentEvidenceError(f"{label} does not name a regular package file")
    return resolved


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise EngineSegmentEvidenceError(f"cannot read {label}: {exc}") from exc
    return _mapping(value, label)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EngineSegmentEvidenceError(f"{label} must be an object")
    return dict(value)


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EngineSegmentEvidenceError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EngineSegmentEvidenceError(f"{label} must be a non-empty string")
    return value


def _digest(value: Any, label: str) -> str:
    result = _string(value, label)
    if _SHA256.fullmatch(result) is None:
        raise EngineSegmentEvidenceError(f"{label} must be a lowercase SHA-256")
    return result


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise EngineSegmentEvidenceError(f"{label} must be a uint32")
    return value


def _bounded_count(value: Any, label: str, maximum: int) -> int:
    result = _u32(value, label)
    if result > maximum:
        raise EngineSegmentEvidenceError(f"{label} exceeds its bound {maximum}")
    return result


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "ENGINE_SEGMENT_EVIDENCE_FORMAT",
    "EngineSegmentEvidence",
    "EngineSegmentEvidenceError",
    "ExecutableCoverageRange",
    "ExternalTailBinding",
    "EvidenceIssue",
    "KernelRange",
    "NativeIndirectCallABI",
    "NativeIndirectCallCapability",
    "NativeIndirectCallPointerSlot",
    "NativeIndirectCallRuntimeLayout",
    "NativeIndirectCallRuntimePointerField",
    "NativeIndirectCallTarget",
    "ProductCutpointOwner",
    "ProofObligation",
    "SemanticTransferBinding",
    "X87ReplayObligation",
    "build_engine_segment_evidence",
    "write_engine_segment_evidence",
]
