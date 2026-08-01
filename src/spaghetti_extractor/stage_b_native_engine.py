"""Generate the freestanding wrapper for a Stage B semantic engine.

This module is candidate-generation machinery.  Its output has no proof
authority: Stage A must decode the linked PE and prove the EngineRep macro
steps before the candidate can be accepted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifact_formats import INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT
from .stage_binary import StageAInputError
from .stage_b_engine_layout import (
    render_stage_b_engine_layout_c,
)
from .util import sha256_bytes, sha256_file, write_json


NATIVE_ENGINE_PLAN_FORMAT = "stage-b-native-engine-plan-v1"
NATIVE_ENGINE_PACKAGE_FORMAT = "stage-b-native-engine-package-v1"
_CALL_KINDS = frozenset({"external_call", "indirect_call"})
_SEMANTIC_RUNTIME_EVENT_KINDS = frozenset({"rep_movsd"})
_HEX_BYTES = re.compile(r"(?:[0-9a-fA-F]{2})+")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_X87_REPLAY_MODEL = "native_exact_x87_command_replay_obligation_v1"
_X87_REPLAY_FORMAT = "stage-a-native-exact-x87-command-replay-obligation-v1"
_X87_REPLAY_PROGRAM_FORMAT = "stage-b-native-exact-x87-command-replay-program-v1"
_X87_CHECKED_DECODER = "StageA.Relational.X87.decodeSingletonCommand"
_X87_CHECKED_EXECUTOR = "StageA.Relational.X87.executeSingletonCommand"
PE32_BASE_RELOCATION_EVIDENCE_FORMAT = "stage-b-pe32-base-relocation-evidence-v1"
_X87_PHYSICAL_FIELDS = (
    "stack", "tags", "control", "status", "pending_exception", "last_opcode",
    "instruction_pointer", "code_selector", "data_pointer", "data_selector",
)
_FNSAVE_IMAGE_SIZE = 108
_MACHINE_STATE_SIZE = 252


class _X87ReplayASLRUnsafe(StageAInputError):
    """Exact replay bytes would embed an unrelocated absolute address."""


@dataclass(frozen=True)
class NativeTerminationImport:
    """Exact imported tail boundary used when the native engine cannot return."""

    dll: str
    symbol: str | None
    ordinal: int | None
    iat_va: int

    def payload(self) -> dict[str, Any]:
        return {
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "iat_va": self.iat_va,
            "transfer": "tail_jump",
            "argument_source": "cdecl-stack-word-0-from-eax",
            "required_disposition": "terminates",
        }

# The assembly bridge is deliberately coupled to the canonical PE32 runtime
# structure.  The emitted C static assertions make any backend layout drift a
# compile-time error rather than silently corrupting physical state.
_STATE_OFFSETS = {
    "eax": 0,
    "ebx": 4,
    "ecx": 8,
    "edx": 12,
    "esi": 16,
    "edi": 20,
    "ebp": 24,
    "esp": 28,
    "cf": 32,
    "zf": 36,
    "sf": 40,
    "of": 44,
    "pf": 48,
    "df": 52,
    "x87_stack": 56,
    "x87_control": 216,
    "x87_status": 218,
    "x87_pending_exception": 220,
    "x87_last_opcode": 222,
    "x87_instruction_pointer": 224,
    "x87_code_selector": 228,
    "x87_data_pointer": 232,
    "x87_data_selector": 236,
    "eflags": 240,
    "fs_base": 244,
    "original_rva": 248,
}
_X87_VALUE_SIZE = 20
_X87_VALUE_EMPTY_OFFSET = 12
_X87_VALUE_TAG_OFFSET = 16
_FRAME_OFFSETS = {
    "parent": 0,
    "input": 4,
    "output": 8,
    "private_esp": 12,
    "call_target": 16,
    "status": 20,
    "saved_continuation": 24,
    "continuation_replaced": 28,
    "input_x87": 32,
    "output_x87": 32 + _FNSAVE_IMAGE_SIZE,
}
_CALLBACK_FRAME_OFFSETS = {
    "parent": 0,
    "parent_bridge": 4,
    "physical_esp": 8,
    "return_target": 12,
    "status": 16,
    "input": 20,
    "output": 20 + _MACHINE_STATE_SIZE,
    "input_x87": 20 + 2 * _MACHINE_STATE_SIZE,
    "output_x87": 20 + 2 * _MACHINE_STATE_SIZE + _FNSAVE_IMAGE_SIZE,
}
_CALLBACK_FRAME_SIZE = 20 + 2 * _MACHINE_STATE_SIZE + 2 * _FNSAVE_IMAGE_SIZE
_X87_FRAME_OFFSETS = {
    "parent": 0,
    "input": 4,
    "output": 8,
    "private_esp": 12,
    "status": 16,
    "input_x87": 20,
    "output_x87": 20 + _FNSAVE_IMAGE_SIZE,
}
_X87_REPLAY_INLINE_INSTRUCTION_OFFSET = 52
_X87_REPLAY_INLINE_CAPTURE_OFFSET = 72
_X87_REPLAY_INLINE_RETURN_OFFSET = 171
_X87_REPLAY_INLINE_BODY_SIZE = 176


@dataclass(frozen=True)
class NativeExternalSite:
    id: int
    transfer_id: str
    event_index: int
    instruction_rva: int
    return_rva: int
    instruction_bytes: bytes
    site_kind: str
    dll: str | None
    symbol: str | None
    ordinal: int | None
    disposition: str
    iat_va: int | None
    transfer_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "transfer_id": self.transfer_id,
            "event_index": self.event_index,
            "instruction_rva": self.instruction_rva,
            "return_rva": self.return_rva,
            "instruction_bytes": self.instruction_bytes.hex(),
            "disposition": self.disposition,
            "transfer_sha256": self.transfer_sha256,
            "continuation_evidence": (
                {
                    "kind": "replace-saved-caller-return",
                    "stack_offset": 0,
                    "width": 4,
                    "restored_at_capture": True,
                    "normal_call_frame_shift": False,
                }
                if self.disposition == "tail_jump"
                else None
            ),
            "site_kind": self.site_kind,
            "iat_va": self.iat_va,
            "import": (
                {
                    "dll": self.dll,
                    "symbol": self.symbol,
                    "ordinal": self.ordinal,
                }
                if self.site_kind == "direct_import"
                else None
            ),
        }


@dataclass(frozen=True)
class NativeCallbackTarget:
    id: int
    rva: int
    transfer_id: str
    transfer_sha256: str
    kind: str
    stack_cleanup_bytes: int

    @property
    def symbol(self) -> str:
        return f"stage_b_payload_callback_{self.rva:08x}"

    @property
    def dispatch_return_symbol(self) -> str:
        return f"stage_b_native_callback_dispatch_return_{self.rva:08x}"

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rva": self.rva,
            "transfer_id": self.transfer_id,
            "transfer_sha256": self.transfer_sha256,
            "kind": self.kind,
            "stack_cleanup_bytes": self.stack_cleanup_bytes,
            "symbol": self.symbol,
            "dispatch_return_symbol": self.dispatch_return_symbol,
        }


@dataclass(frozen=True)
class NativeX87Replay:
    id: int
    transfer_id: str
    contract_sha256: str
    instruction_bytes_sha256: str
    transfer_instruction_bytes_sha256: str
    image_base: int
    rva_start: int
    rva_end: int
    instruction_bytes: bytes
    relocation_source_rva: int | None = None
    operand_byte_offset: int | None = None
    preferred_value: int | None = None
    target_rva: int | None = None
    relocation_type: int | None = None
    relocation_width: int | None = None
    relocation_pe_sha256: str | None = None
    relocation_reference_contract_sha256: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "format": _X87_REPLAY_PROGRAM_FORMAT,
            "transfer_id": self.transfer_id,
            "contract_sha256": self.contract_sha256,
            "instruction_bytes_sha256": self.instruction_bytes_sha256,
            "transfer_instruction_bytes_sha256": (
                self.transfer_instruction_bytes_sha256
            ),
            "image_base": self.image_base,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "instruction_count": 1,
            "instruction_bytes": self.instruction_bytes.hex(),
            "checked_decoder": _X87_CHECKED_DECODER,
            "checked_executor": _X87_CHECKED_EXECUTOR,
            "base_relocation": (
                {
                    "source_rva": self.relocation_source_rva,
                    "operand_byte_offset": self.operand_byte_offset,
                    "preferred_value": self.preferred_value,
                    "target_rva": self.target_rva,
                    "type": self.relocation_type,
                    "kind": "highlow",
                    "width": self.relocation_width,
                    "pe_sha256": self.relocation_pe_sha256,
                    "reference_contract_sha256": (
                        self.relocation_reference_contract_sha256
                    ),
                }
                if self.relocation_source_rva is not None
                else None
            ),
        }


@dataclass(frozen=True)
class _PEBaseRelocation:
    source_rva: int
    type: int
    width: int
    preferred_value: int


@dataclass(frozen=True)
class _PEBaseRelocationEvidence:
    pe_sha256: str
    reference_contract_sha256: str
    image_base: int
    relocations: tuple[_PEBaseRelocation, ...]


@dataclass(frozen=True)
class NativeEnginePlan:
    entry_rva: int
    transfer_count: int
    external_sites: tuple[NativeExternalSite, ...]
    indirect_call_count: int
    callback_targets: tuple[NativeCallbackTarget, ...]
    x87_replays: tuple[NativeX87Replay, ...]
    termination_import: NativeTerminationImport | None
    blockers: tuple[dict[str, Any], ...]

    @property
    def status(self) -> str:
        return "ready" if not self.blockers else "incomplete"

    def payload(self, *, state_machine_sha256: str) -> dict[str, Any]:
        return {
            "format": NATIVE_ENGINE_PLAN_FORMAT,
            "status": self.status,
            "state_machine_sha256": state_machine_sha256,
            "entry_rva": self.entry_rva,
            "counts": {
                "transfers": self.transfer_count,
                "external_sites": len(self.external_sites),
                "indirect_calls": self.indirect_call_count,
                "callback_targets": len(self.callback_targets),
                "blockers": len(self.blockers),
            },
            "external_sites": [site.payload() for site in self.external_sites],
            "callback_targets": [target.rva for target in self.callback_targets],
            "callback_abis": [target.payload() for target in self.callback_targets],
            "x87_replays": [replay.payload() for replay in self.x87_replays],
            "termination_import": (
                self.termination_import.payload()
                if self.termination_import is not None
                else None
            ),
            "launch_wrapper_symbols": {
                "entry_dispatch_return": "stage_b_native_entry_dispatch_return",
                "entry_return": "stage_b_native_entry_return",
                "termination": "stage_b_native_termination",
                "callback_dispatch_returns": [
                    target.dispatch_return_symbol
                    for target in self.callback_targets
                ],
            },
            "relocation_policy": {
                "original_evidence": "complete-hash-bound-pe32-inventory-when-required",
                "payload_evidence": "complete-pe32-highlow-inventory-required",
                "raw_absolute_operands": "forbidden",
            },
            "blockers": list(self.blockers),
            "authority": (
                "candidate generation only; final acceptance requires the "
                "Lean-checked whole-program theorem"
            ),
        }


def _parse_native_termination_import(
    value: Mapping[str, Any] | None,
    import_iat_vas: Mapping[tuple[str, str | int], int],
) -> NativeTerminationImport | None:
    if value is None:
        return None
    dll = _required_string(value.get("dll"), "termination import DLL").lower()
    symbol_value = value.get("symbol")
    ordinal_value = value.get("ordinal")
    if (symbol_value is None) == (ordinal_value is None):
        raise StageAInputError(
            "termination import must provide exactly one symbol or ordinal"
        )
    symbol = (
        _required_string(symbol_value, "termination import symbol")
        if symbol_value is not None
        else None
    )
    ordinal = (
        _required_u32(ordinal_value, "termination import ordinal")
        if ordinal_value is not None
        else None
    )
    if value.get("disposition") != "terminates":
        raise StageAInputError(
            "termination import must be selected from a modeled terminates contract"
        )
    if symbol is not None:
        identity: str | int = symbol
    else:
        assert ordinal is not None
        identity = ordinal
    iat_va = import_iat_vas.get((dll, identity))
    if iat_va is None:
        raise StageAInputError(
            "termination import has no unique IAT cell in the load-image contract"
        )
    return NativeTerminationImport(
        dll=dll,
        symbol=symbol,
        ordinal=ordinal,
        iat_va=_required_u32(iat_va, "termination import IAT VA"),
    )


def plan_stage_b_native_engine(
    *,
    state_machine: Path,
    entry_rva: int,
    callback_targets: Iterable[int | Mapping[str, Any]] = (),
    import_iat_vas: Mapping[tuple[str, str | int], int] | None = None,
    termination_import: Mapping[str, Any] | None = None,
    base_relocation_evidence: Mapping[str, Any] | None = None,
) -> NativeEnginePlan:
    """Plan exact machine-level external bridges from an opaque state machine."""

    rows = _read_jsonl_objects(Path(state_machine), "state machine")
    sites: list[NativeExternalSite] = []
    import_iat_vas = import_iat_vas or {}
    blockers: list[dict[str, Any]] = []
    checked_termination_import = _parse_native_termination_import(
        termination_import, import_iat_vas
    )
    indirect_calls = 0
    seen_sites: dict[int, NativeExternalSite] = {}
    seen_returns: dict[int, NativeExternalSite] = {}
    transfer_rvas: set[int] = set()
    transfer_rows: dict[int, tuple[str, str]] = {}
    x87_replays: list[NativeX87Replay] = []
    relocation_evidence = _parse_pe_base_relocation_evidence(
        base_relocation_evidence
    )
    for row_index, row in enumerate(rows):
        transfer_id = _required_string(row.get("id"), f"transfer {row_index} id")
        original = row.get("original")
        if not isinstance(original, dict):
            raise StageAInputError(f"{transfer_id} has no original span")
        transfer_rva = _required_u32(
            original.get("rva_start"), f"{transfer_id} original.rva_start"
        )
        if transfer_rva in transfer_rvas:
            raise StageAInputError(f"duplicate state-machine transfer RVA {transfer_rva:#x}")
        transfer_rvas.add(transfer_rva)
        transfer_rows[transfer_rva] = (
            transfer_id,
            sha256_bytes(
                json.dumps(
                    row,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ),
        )
        ordered = row.get("ordered_events")
        if not isinstance(ordered, list):
            raise StageAInputError(f"{transfer_id} ordered_events must be a list")
        instructions = row.get("instructions")
        if not isinstance(instructions, list):
            raise StageAInputError(f"{transfer_id} instructions must be a list")
        instruction_by_rva = _instruction_inventory(transfer_id, instructions)

        fpu_state = row.get("fpu_state")
        if fpu_state is not None:
            if relocation_evidence is not None:
                export = row.get("stage_a_export")
                if not isinstance(export, Mapping):
                    raise StageAInputError(
                        f"transfer {row_index} lacks its Stage A export binding"
                    )
                bound_contract = _required_sha256(
                    export.get("reference_contract_sha256"),
                    f"transfer {row_index} Stage A reference-contract SHA-256",
                )
                if (
                    bound_contract
                    != relocation_evidence.reference_contract_sha256
                ):
                    raise StageAInputError(
                        f"transfer {row_index} and PE relocation evidence bind "
                        "different reference contracts"
                    )
            try:
                qualified = _qualified_x87_replays(
                    row=row,
                    transfer_id=transfer_id,
                    first_id=len(x87_replays),
                    relocation_evidence=relocation_evidence,
                )
            except StageAInputError as exc:
                aslr_unsafe = isinstance(exc, _X87ReplayASLRUnsafe)
                blockers.append(_blocker(
                    (
                        "x87_replay_aslr_unsafe"
                        if aslr_unsafe
                        else "x87_physical_state_unqualified"
                    ),
                    transfer_id=transfer_id,
                    observed=str(exc),
                    next_action=(
                        "supply exact HIGHLOW relocation evidence and emit a relocated "
                        "operand, or use a stack/register-relative x87 memory form"
                        if aslr_unsafe
                        else "export a complete exact singleton x87 replay binding; mixed "
                        "ordinary/x87 effects and symbolic-only state remain unsupported"
                    ),
                ))
            else:
                x87_replays.extend(qualified)

        event_index = 0
        for event in ordered:
            if not isinstance(event, dict) or event.get("family") != "external":
                continue
            kind = str(event.get("kind") or "")
            if kind == "internal_call":
                event_index += 1
                continue
            if kind in _SEMANTIC_RUNTIME_EVENT_KINDS:
                event_index += 1
                continue
            if kind not in _CALL_KINDS:
                blockers.append(_blocker(
                    "unsupported_external_event_kind",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    observed=kind,
                    next_action="add and qualify a machine-level bridge for this event kind",
                ))
                event_index += 1
                continue
            instruction_rva = _required_u32(
                event.get("instruction_rva"),
                f"{transfer_id} external event instruction_rva",
            )
            return_rva = _required_u32(
                event.get("return_rva"), f"{transfer_id} external event return_rva"
            )
            instruction = instruction_by_rva.get(instruction_rva)
            if instruction is None:
                blockers.append(_blocker(
                    "external_instruction_missing",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    next_action="regenerate exact instruction evidence for the external event",
                ))
                event_index += 1
                continue
            mnemonic = str(instruction.get("mnemonic") or "").lower()
            raw_hex = instruction.get("bytes")
            outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
            disposition = (
                "tail_jump"
                if mnemonic == "jmp" and outcome.get("kind") == "external_jump"
                else "returns_here"
            )
            if (
                mnemonic not in {"call", "jmp"}
                or (mnemonic == "jmp" and disposition != "tail_jump")
                or not isinstance(raw_hex, str)
                or not _HEX_BYTES.fullmatch(raw_hex)
            ):
                blockers.append(_blocker(
                    "external_call_instruction_unsupported",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    observed={"mnemonic": mnemonic, "bytes": raw_hex},
                    next_action="supply a decoded direct or IAT call instruction with exact bytes",
                ))
                event_index += 1
                continue
            raw = bytes.fromhex(raw_hex)
            if disposition == "returns_here" and instruction_rva + len(raw) != return_rva:
                blockers.append(_blocker(
                    "external_return_rva_mismatch",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    expected=instruction_rva + len(raw),
                    observed=return_rva,
                    next_action="repair the call boundary before generating a physical bridge",
                ))
                event_index += 1
                continue
            dynamic_target = kind == "indirect_call"
            iat_va: int | None = None
            if dynamic_target:
                indirect_calls += 1
                dll = None
                symbol = None
                ordinal = None
                if not _indirect_call_encoding(raw):
                    blockers.append(_blocker(
                        "indirect_call_encoding_unsupported",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        observed=raw.hex(),
                        next_action=(
                            "supply an exact i686 FF /2 indirect CALL instruction "
                            "whose evaluated target is present in the semantic event"
                        ),
                    ))
                    event_index += 1
                    continue
            else:
                dll = _required_string(
                    event.get("dll"), f"{transfer_id} external dll"
                )
                symbol = event.get("symbol")
                ordinal = event.get("ordinal")
                if (isinstance(symbol, str) and symbol) == (
                    isinstance(ordinal, int) and not isinstance(ordinal, bool)
                ):
                    raise StageAInputError(
                        f"{transfer_id} external event must name exactly one symbol or ordinal"
                    )
                identity: str | int = symbol if isinstance(symbol, str) else int(ordinal)
                supplied_iat = import_iat_vas.get((dll.lower(), identity))
                encoded_iat = _absolute_iat_va(raw, mnemonic)
                if supplied_iat is not None:
                    supplied_iat = _required_u32(supplied_iat, "import IAT VA")
                if encoded_iat is not None and supplied_iat not in {None, encoded_iat}:
                    blockers.append(_blocker(
                        "external_import_iat_evidence_mismatch",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        expected=encoded_iat,
                        observed=supplied_iat,
                        next_action="regenerate the IAT identity map from the exact load-image contract",
                    ))
                    event_index += 1
                    continue
                iat_va = encoded_iat if encoded_iat is not None else supplied_iat
                if iat_va is None:
                    blockers.append(_blocker(
                        "external_import_iat_evidence_missing",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        observed=raw.hex(),
                        next_action=(
                            "bind this import identity to one exact original IAT cell "
                            "from the load-image contract"
                        ),
                    ))
                    event_index += 1
                    continue
                if disposition == "tail_jump" and (
                    str(outcome.get("dll") or "").lower() != dll.lower()
                    or outcome.get("symbol") != symbol
                    or outcome.get("ordinal") != ordinal
                ):
                    blockers.append(_blocker(
                        "external_tail_jump_identity_mismatch",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        expected={
                            "dll": dll.lower(),
                            "symbol": symbol,
                            "ordinal": ordinal,
                        },
                        observed={
                            "dll": outcome.get("dll"),
                            "symbol": outcome.get("symbol"),
                            "ordinal": outcome.get("ordinal"),
                        },
                        next_action=(
                            "bind the external_jump outcome to the exact ordered "
                            "tail-import event identity"
                        ),
                    ))
                    event_index += 1
                    continue
            site = NativeExternalSite(
                id=len(sites),
                transfer_id=transfer_id,
                event_index=event_index,
                instruction_rva=instruction_rva,
                return_rva=return_rva,
                instruction_bytes=raw,
                site_kind="dynamic_target" if dynamic_target else "direct_import",
                dll=dll.lower() if dll is not None else None,
                symbol=symbol if isinstance(symbol, str) else None,
                ordinal=int(ordinal) if isinstance(ordinal, int) else None,
                disposition=disposition,
                iat_va=iat_va,
                transfer_sha256=transfer_rows[transfer_rva][1],
            )
            prior_site = seen_sites.get(instruction_rva)
            if prior_site is not None and prior_site != site:
                raise StageAInputError(
                    f"ambiguous external bridge at RVA {instruction_rva:#x}"
                )
            prior_return = seen_returns.get(return_rva)
            if (
                disposition == "returns_here"
                and prior_return is not None
                and prior_return.instruction_rva != instruction_rva
            ):
                blockers.append(_blocker(
                    "ambiguous_external_return_bridge",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    return_rva=return_rva,
                    observed=[prior_return.instruction_rva, instruction_rva],
                    next_action="split the physical return continuations with checked callsite state",
                ))
                event_index += 1
                continue
            seen_sites[instruction_rva] = site
            if disposition == "returns_here":
                seen_returns[return_rva] = site
            sites.append(site)
            event_index += 1

    callback_specs: dict[int, tuple[str, str, str, int]] = {}
    for index, value in enumerate(callback_targets):
        try:
            callback_rva, callback_kind, stack_cleanup = _callback_spec(value, index)
        except StageAInputError as exc:
            blockers.append(_blocker(
                "callback_abi_ambiguous",
                callback_index=index,
                observed=value,
                detail=str(exc),
                next_action=(
                    "encode callback kind and exact stack cleanup; TLS callbacks require "
                    "kind=tls_callback and stack_cleanup_bytes=12"
                ),
            ))
            continue
        binding = transfer_rows.get(callback_rva)
        if binding is None:
            blockers.append(_blocker(
                "callback_transfer_missing",
                callback_rva=callback_rva,
                next_action="export a checked semantic transfer for every callback root",
            ))
            continue
        if callback_rva in callback_specs:
            raise StageAInputError(f"duplicate callback target RVA {callback_rva:#x}")
        transfer_id, transfer_sha256 = binding
        callback_specs[callback_rva] = (
            transfer_id, transfer_sha256, callback_kind, stack_cleanup
        )
    callbacks = tuple(
        NativeCallbackTarget(
            id=index,
            rva=rva,
            transfer_id=callback_specs[rva][0],
            transfer_sha256=callback_specs[rva][1],
            kind=callback_specs[rva][2],
            stack_cleanup_bytes=callback_specs[rva][3],
        )
        for index, rva in enumerate(sorted(callback_specs))
    )
    if entry_rva not in transfer_rvas:
        blockers.append(_blocker(
            "entry_transfer_missing",
            entry_rva=entry_rva,
            next_action="export the semantic transfer beginning at the PE entrypoint",
        ))
    return NativeEnginePlan(
        entry_rva=_required_u32(entry_rva, "entry RVA"),
        transfer_count=len(rows),
        external_sites=tuple(sorted(sites, key=lambda item: item.instruction_rva)),
        indirect_call_count=indirect_calls,
        callback_targets=callbacks,
        x87_replays=tuple(x87_replays),
        termination_import=checked_termination_import,
        blockers=tuple(blockers),
    )


def write_stage_b_native_engine_package(
    *,
    state_machine: Path,
    entry_rva: int,
    out: Path,
    callback_targets: Iterable[int | Mapping[str, Any]] = (),
    import_iat_vas: Mapping[tuple[str, str | int], int] | None = None,
    termination_import: Mapping[str, Any] | None = None,
    base_relocation_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Write deterministic wrapper sources and a fail-closed build plan."""

    state_machine = Path(state_machine)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    plan = plan_stage_b_native_engine(
        state_machine=state_machine,
        entry_rva=entry_rva,
        callback_targets=callback_targets,
        import_iat_vas=import_iat_vas,
        termination_import=termination_import,
        base_relocation_evidence=base_relocation_evidence,
    )
    plan_path = out / "native-engine-plan.json"
    write_json(plan_path, plan.payload(state_machine_sha256=sha256_file(state_machine)))
    header = out / "native-engine-wrapper.h"
    source = out / "native-engine-wrapper.c"
    assembly = out / "native-engine-bridges.S"
    layout_source = out / "native-engine-layout.c"
    header.write_text(_wrapper_header(), encoding="ascii")
    source.write_text(_wrapper_source(plan), encoding="ascii")
    assembly.write_text(_bridge_assembly(plan), encoding="ascii")
    layout_source.write_text(
        render_stage_b_engine_layout_c(
            flag_storage="split-and-packed",
            include_fs_base=True,
            include_original_rva=True,
        ),
        encoding="ascii",
    )
    result = {
        "format": NATIVE_ENGINE_PACKAGE_FORMAT,
        "status": plan.status,
        "plan": {"path": plan_path.name, "sha256": sha256_file(plan_path)},
        "sources": [
            {"path": path.name, "sha256": sha256_file(path)}
            for path in (header, source, assembly, layout_source)
        ],
        "counts": plan.payload(state_machine_sha256="")["counts"],
        "callback_abis": [target.payload() for target in plan.callback_targets],
        "blockers": list(plan.blockers),
        "policy": {
            "dynamic_base": True,
            "base_relocations": "complete-pe32-highlow-inventory-required",
            "raw_absolute_x87_replay_operands": "forbidden",
            "root_callback_engine_buffers": "fixed-launch-buffers",
            "nested_callback_engine_buffers": "stack-local-requires-checked-runtime-frame",
            "terminal_control": (
                "modeled-environment-refined-import"
                if plan.termination_import is not None
                else "unsupported-native-halt"
            ),
        },
        "authority": "candidate generation only; Stage A proof required",
    }
    write_json(out / "native-engine-package.json", result)
    return result


def _wrapper_header() -> str:
    return """#ifndef STAGE_B_NATIVE_ENGINE_WRAPPER_H
#define STAGE_B_NATIVE_ENGINE_WRAPPER_H

#include <stddef.h>
#include "state-machine-runtime.h"

/* Intel 32-bit protected-mode FNSAVE/FRSTOR image.  The register array is
 * physical R0..R7 and tag_word is the complete architectural tag word. */
typedef struct __attribute__((packed, aligned(4))) stage_b_x87_fnsave_image {
  uint16_t control_word, reserved_02;
  uint16_t status_word, reserved_06;
  uint16_t tag_word, reserved_0a;
  uint32_t instruction_pointer;
  uint16_t code_selector, last_opcode;
  uint32_t data_pointer;
  uint16_t data_selector, reserved_1a;
  uint8_t physical_registers[8][10];
} stage_b_x87_fnsave_image;

typedef struct stage_b_native_bridge_frame {
  struct stage_b_native_bridge_frame *parent;
  const stage_b_machine_state *input;
  stage_b_machine_state *output;
  uint32_t private_esp;
  uint32_t call_target;
  stage_b_call_status status;
  uint32_t saved_continuation;
  uint32_t continuation_replaced;
  stage_b_x87_fnsave_image input_x87;
  stage_b_x87_fnsave_image output_x87;
} stage_b_native_bridge_frame;

typedef struct stage_b_native_callback_frame {
  struct stage_b_native_callback_frame *parent;
  stage_b_native_bridge_frame *parent_bridge;
  uint32_t physical_esp;
  uint32_t return_target;
  stage_b_call_status status;
  stage_b_machine_state input;
  stage_b_machine_state output;
  stage_b_x87_fnsave_image input_x87;
  stage_b_x87_fnsave_image output_x87;
} stage_b_native_callback_frame;

typedef struct stage_b_native_x87_frame {
  struct stage_b_native_x87_frame *parent;
  const stage_b_machine_state *input;
  stage_b_machine_state *output;
  uint32_t private_esp;
  stage_b_call_status status;
  stage_b_x87_fnsave_image input_x87;
  stage_b_x87_fnsave_image output_x87;
} stage_b_native_x87_frame;

extern stage_b_native_bridge_frame *stage_b_native_active_bridge;
extern stage_b_native_callback_frame *stage_b_native_active_callback;
extern stage_b_native_x87_frame *stage_b_native_active_x87;
extern stage_b_machine_state stage_b_native_launch_state;
extern stage_b_machine_state stage_b_native_launch_output;
extern uint32_t stage_b_native_launch_return;
extern stage_b_x87_fnsave_image stage_b_native_launch_x87;
extern stage_b_x87_fnsave_image stage_b_native_launch_output_x87;
extern uint8_t stage_b_native_callback_stack[65536];
extern volatile stage_b_call_status stage_b_native_root_callback_fault;
extern stage_b_runtime stage_b_native_runtime_instance;

stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output);
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output);
stage_b_call_status stage_b_native_run_entry(
    stage_b_machine_state *input, stage_b_machine_state *output);
stage_b_call_status stage_b_native_run_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    stage_b_machine_state *input, stage_b_machine_state *output,
    const stage_b_x87_fnsave_image *input_x87,
    stage_b_x87_fnsave_image *output_x87);

#endif
"""


def _wrapper_source(plan: NativeEnginePlan) -> str:
    declarations = ["extern void stage_b_native_bridge(void);"]
    callback_declarations = [
        f"extern void {target.symbol}(void);"
        for target in plan.callback_targets
    ]
    x87_declarations = [
        f"extern void stage_b_native_x87_bridge_{replay.id:04d}(void);"
        for replay in plan.x87_replays
    ]
    table = [
        (
            f"  {{ 0x{site.instruction_rva:08x}U, "
            f"0x{(site.iat_va or 0):08x}U, "
            f"{1 if site.site_kind == 'dynamic_target' else 0}U, "
            f"{1 if site.disposition == 'tail_jump' else 0}U }},"
        )
        for site in plan.external_sites
    ]
    state_assertions = [
        f'_Static_assert(offsetof(stage_b_machine_state, {field}) == {offset}U, '
        f'"assembly offset for {field} is stale");'
        for field, offset in _STATE_OFFSETS.items()
        if field != "x87_stack"
    ]
    state_assertions.extend([
        f'_Static_assert(offsetof(stage_b_machine_state, x87_stack) == '
        f'{_STATE_OFFSETS["x87_stack"]}U, '
        '"assembly offset for x87_stack is stale");',
        f'_Static_assert(sizeof(stage_b_x87_value) == {_X87_VALUE_SIZE}U, '
        '"assembly x87-value stride is stale");',
        f'_Static_assert(offsetof(stage_b_x87_value, empty) == '
        f'{_X87_VALUE_EMPTY_OFFSET}U, '
        '"assembly x87 empty offset is stale");',
        f'_Static_assert(offsetof(stage_b_x87_value, tag) == '
        f'{_X87_VALUE_TAG_OFFSET}U, '
        '"assembly x87 tag offset is stale");',
    ])
    frame_assertions = [
        f'_Static_assert(offsetof(stage_b_native_bridge_frame, {field}) == {offset}U, '
        f'"assembly bridge-frame offset for {field} is stale");'
        for field, offset in _FRAME_OFFSETS.items()
    ]
    callback_frame_assertions = [
        f'_Static_assert(offsetof(stage_b_native_callback_frame, {field}) == {offset}U, '
        f'"assembly callback-frame offset for {field} is stale");'
        for field, offset in _CALLBACK_FRAME_OFFSETS.items()
    ]
    x87_frame_assertions = [
        f'_Static_assert(offsetof(stage_b_native_x87_frame, {field}) == {offset}U, '
        f'"assembly x87-frame offset for {field} is stale");'
        for field, offset in _X87_FRAME_OFFSETS.items()
    ]
    callback_table = [
        (
            f"  {{ 0x{target.rva:08x}U, {target.stack_cleanup_bytes}U, "
            f"{json.dumps(target.kind)}, {json.dumps(target.transfer_id)}, "
            f"{json.dumps(target.transfer_sha256)}, "
            f"{target.symbol} }},"
        )
        for target in plan.callback_targets
    ]
    x87_table = [
        (
            f"  {{ 0x{replay.image_base:08x}U, 0x{replay.rva_start:08x}U, "
            f"0x{replay.rva_end:08x}U, {len(replay.instruction_bytes)}U, "
            f"stage_b_native_x87_bytes_{replay.id:04d}, "
            f"{json.dumps(replay.instruction_bytes_sha256)}, "
            f"{json.dumps(replay.transfer_instruction_bytes_sha256)}, "
            f"{json.dumps(replay.contract_sha256)}, "
            f"stage_b_native_x87_bridge_{replay.id:04d} }},"
        )
        for replay in plan.x87_replays
    ]
    x87_bytes = [
        (
            f"static const uint8_t stage_b_native_x87_bytes_{replay.id:04d}[] = {{ "
            + ", ".join(f"0x{byte:02x}U" for byte in replay.instruction_bytes)
            + " };"
        )
        for replay in plan.x87_replays
    ]
    bridge_dispatch = [
        "static void stage_b_native_dispatch_bridge(void) {",
        "  stage_b_native_bridge();",
        "}",
    ]
    return "\n".join([
        '#include "native-engine-wrapper.h"',
        "",
        *declarations,
        *callback_declarations,
        *x87_declarations,
        "",
        "extern const unsigned char __ImageBase[];",
        "",
        "stage_b_native_bridge_frame *stage_b_native_active_bridge;",
        "stage_b_native_callback_frame *stage_b_native_active_callback;",
        "stage_b_native_x87_frame *stage_b_native_active_x87;",
        "stage_b_machine_state stage_b_native_launch_state;",
        "stage_b_machine_state stage_b_native_launch_output;",
        "uint32_t stage_b_native_launch_return;",
        "stage_b_x87_fnsave_image stage_b_native_launch_x87;",
        "stage_b_x87_fnsave_image stage_b_native_launch_output_x87;",
        "uint8_t stage_b_native_callback_stack[65536] __attribute__((aligned(16)));",
        "volatile stage_b_call_status stage_b_native_root_callback_fault = STAGE_B_CALL_OK;",
        "",
        *state_assertions,
        *frame_assertions,
        *callback_frame_assertions,
        *x87_frame_assertions,
        f'_Static_assert(sizeof(stage_b_machine_state) == {_MACHINE_STATE_SIZE}U, '
        '"assembly machine-state size is stale");',
        f'_Static_assert(sizeof(stage_b_native_callback_frame) == {_CALLBACK_FRAME_SIZE}U, '
        '"assembly callback-frame size is stale");',
        f'_Static_assert(sizeof(stage_b_x87_fnsave_image) == {_FNSAVE_IMAGE_SIZE}U, '
        '"FNSAVE image must be 108 bytes in i686 mode");',
        '_Static_assert(offsetof(stage_b_x87_fnsave_image, control_word) == 0U, '
        '"FNSAVE control offset changed");',
        '_Static_assert(offsetof(stage_b_x87_fnsave_image, status_word) == 4U, '
        '"FNSAVE status offset changed");',
        '_Static_assert(offsetof(stage_b_x87_fnsave_image, tag_word) == 8U, '
        '"FNSAVE tag offset changed");',
        '_Static_assert(offsetof(stage_b_x87_fnsave_image, physical_registers) == 28U, '
        '"FNSAVE physical-register offset changed");',
        '_Static_assert(STAGE_B_CALL_OK == 0, "assembly status encoding is stale");',
        "",
        "typedef void (*stage_b_native_assembly_fn)(void);",
        "typedef struct stage_b_native_bridge_entry {",
        "  uint32_t instruction_rva;",
        "  uint32_t iat_va;",
        "  uint32_t dynamic_target, tail_jump;",
        "} stage_b_native_bridge_entry;",
        "typedef struct stage_b_native_callback_entry {",
        "  uint32_t rva, stack_cleanup_bytes;",
        "  const char *kind, *transfer_id, *transfer_sha256;",
        "  stage_b_native_assembly_fn bridge;",
        "} stage_b_native_callback_entry;",
        "typedef struct stage_b_native_x87_entry {",
        "  uint32_t image_base, rva_start, rva_end, byte_count;",
        "  const uint8_t *instruction_bytes;",
        "  const char *instruction_bytes_sha256;",
        "  const char *transfer_instruction_bytes_sha256;",
        "  const char *contract_sha256;",
        "  stage_b_native_assembly_fn bridge;",
        "} stage_b_native_x87_entry;",
        "",
        "static const stage_b_native_bridge_entry stage_b_native_bridges[] = {",
        *table,
        "};",
        f"static const uint32_t stage_b_native_bridge_count = {len(table)}U;",
        "",
        "static const stage_b_native_callback_entry stage_b_native_callbacks[] = {",
        *callback_table,
        "};",
        f"static const uint32_t stage_b_native_callback_count = {len(callback_table)}U;",
        "",
        *x87_bytes,
        "static const stage_b_native_x87_entry stage_b_native_x87_entries[] = {",
        *x87_table,
        "};",
        f"static const uint32_t stage_b_native_x87_count = {len(x87_table)}U;",
        "",
        "static const stage_b_native_bridge_entry *stage_b_native_bridge_entry_for(",
        "    uint32_t instruction_rva) {",
        "  uint32_t i;",
        "  for (i = 0; i < stage_b_native_bridge_count; ++i)",
        "    if (stage_b_native_bridges[i].instruction_rva == instruction_rva)",
        "      return &stage_b_native_bridges[i];",
        "  return (const stage_b_native_bridge_entry *)0;",
        "}",
        "",
        "static const stage_b_native_callback_entry *stage_b_native_callback_entry_for(",
        "    uint32_t rva) {",
        "  uint32_t i;",
        "  for (i = 0; i < stage_b_native_callback_count; ++i)",
        "    if (stage_b_native_callbacks[i].rva == rva)",
        "      return &stage_b_native_callbacks[i];",
        "  return (const stage_b_native_callback_entry *)0;",
        "}",
        "",
        "static __attribute__((unused)) const stage_b_native_x87_entry *",
        "stage_b_native_x87_entry_for(",
        "    uint32_t rva) {",
        "  uint32_t i;",
        "  for (i = 0; i < stage_b_native_x87_count; ++i)",
        "    if (stage_b_native_x87_entries[i].rva_start == rva)",
        "      return &stage_b_native_x87_entries[i];",
        "  return (const stage_b_native_x87_entry *)0;",
        "}",
        "",
        *bridge_dispatch,
        "",
        "static __attribute__((unused)) uint32_t stage_b_native_bytes_equal(",
        "    const uint8_t *left, const uint8_t *right, uint32_t count) {",
        "  uint32_t i;",
        "  if (left == 0 || right == 0) return 0U;",
        "  for (i = 0; i < count; ++i) if (left[i] != right[i]) return 0U;",
        "  return 1U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t stage_b_native_string_equal(",
        "    const char *left, const char *right) {",
        "  if (left == 0 || right == 0) return 0U;",
        "  while (*left != '\\0' && *right != '\\0')",
        "    if (*left++ != *right++) return 0U;",
        "  return *left == *right;",
        "}",
        "",
        "static uint32_t stage_b_native_fixed_flat_read_u32(",
        "    uint32_t address, uint32_t *value) {",
        "  const volatile uint8_t *bytes;",
        "  if (value == 0 || address > 0xffffffffU - 3U) return 0U;",
        "  bytes = (const volatile uint8_t *)(uintptr_t)address;",
        "  *value = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |",
        "      ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);",
        "  return 1U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t stage_b_native_state_to_fnsave(",
        "    const stage_b_machine_state *state, stage_b_x87_fnsave_image *image) {",
        "  uint32_t i, j, top; uint16_t tags = 0U;",
        "  if (state == 0 || image == 0 || state->x87_last_opcode > 0x7ffU)",
        "    return 1U;",
        "  top = (state->x87_status >> 11U) & 7U;",
        "  if (((state->x87_status >> 7) & 1U) !=",
        "      (uint32_t)(state->x87_pending_exception & 1U)) return 1U;",
        "  for (i = 0; i < 8U; ++i) {",
        "    const uint32_t physical = (top + i) & 7U;",
        "    const uint32_t tag = state->x87_stack[i].tag;",
        "    const uint32_t empty = state->x87_stack[i].empty;",
        "    if (tag > 3U || empty > 1U || ((tag == 3U) != (empty != 0U)))",
        "      return 1U;",
        "    tags = (uint16_t)(tags | (uint16_t)(tag << (2U * physical)));",
        "  }",
        "  for (i = 0; i < sizeof(*image); ++i) ((uint8_t *)image)[i] = 0U;",
        "  image->control_word = state->x87_control;",
        "  image->status_word = state->x87_status;",
        "  image->tag_word = tags;",
        "  image->instruction_pointer = state->x87_instruction_pointer;",
        "  image->code_selector = state->x87_code_selector;",
        "  image->last_opcode = state->x87_last_opcode;",
        "  image->data_pointer = state->x87_data_pointer;",
        "  image->data_selector = state->x87_data_selector;",
        "  for (i = 0; i < 8U; ++i) for (j = 0; j < 10U; ++j)",
        "    image->physical_registers[(top + i) & 7U][j] =",
        "      state->x87_stack[i].value_bytes[j];",
        "  return 0U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t stage_b_native_fnsave_to_state(",
        "    const stage_b_x87_fnsave_image *image, stage_b_machine_state *state) {",
        "  uint32_t i, j, top;",
        "  if (image == 0 || state == 0 || image->last_opcode > 0x7ffU) return 1U;",
        "  top = (image->status_word >> 11U) & 7U;",
        "  state->x87_control = image->control_word;",
        "  state->x87_status = image->status_word;",
        "  state->x87_pending_exception = (uint8_t)((image->status_word >> 7) & 1U);",
        "  state->x87_last_opcode = image->last_opcode;",
        "  state->x87_instruction_pointer = image->instruction_pointer;",
        "  state->x87_code_selector = image->code_selector;",
        "  state->x87_data_pointer = image->data_pointer;",
        "  state->x87_data_selector = image->data_selector;",
        "  for (i = 0; i < 8U; ++i) {",
        "    const uint32_t physical = (top + i) & 7U;",
        "    const uint8_t tag =",
        "      (uint8_t)((image->tag_word >> (2U * physical)) & 3U);",
        "    state->x87_stack[i].tag = tag;",
        "    state->x87_stack[i].empty = tag == 3U ? 1U : 0U;",
        "    for (j = 0; j < 10U; ++j)",
        "      state->x87_stack[i].value_bytes[j] =",
        "        image->physical_registers[physical][j];",
        "  }",
        "  return 0U;",
        "}",
        "",
        "static void stage_b_native_unpack_flags(stage_b_machine_state *state) {",
        "  const uint32_t flags = state->eflags;",
        "  state->cf = (flags >> 0) & 1U;",
        "  state->pf = (flags >> 2) & 1U;",
        "  state->zf = (flags >> 6) & 1U;",
        "  state->sf = (flags >> 7) & 1U;",
        "  state->df = (flags >> 10) & 1U;",
        "  state->of = (flags >> 11) & 1U;",
        "}",
        "",
        "static void stage_b_native_pack_flags(stage_b_machine_state *state) {",
        "  const uint32_t represented =",
        "      (1U << 0) | (1U << 2) | (1U << 6) | (1U << 7) |",
        "      (1U << 10) | (1U << 11);",
        "  state->eflags = (state->eflags & ~represented) |",
        "      ((state->cf & 1U) << 0) | ((state->pf & 1U) << 2) |",
        "      ((state->zf & 1U) << 6) | ((state->sf & 1U) << 7) |",
        "      ((state->df & 1U) << 10) | ((state->of & 1U) << 11);",
        "}",
        "",
        "static uint32_t stage_b_native_original_iat_target(uint32_t iat_va) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  uint32_t nt_offset, preferred_base, iat_address;",
        "  if (image_base == 0U ||",
        "      *(volatile const uint16_t *)(uintptr_t)image_base != 0x5a4dU)",
        "    return 0U;",
        "  nt_offset = *(volatile const uint32_t *)(uintptr_t)(image_base + 0x3cU);",
        "  if (nt_offset > 0x100000U ||",
        "      *(volatile const uint32_t *)(uintptr_t)(image_base + nt_offset) !=",
        "          0x00004550U ||",
        "      *(volatile const uint16_t *)(uintptr_t)(image_base + nt_offset + 0x18U) !=",
        "          0x010bU)",
        "    return 0U;",
        "  preferred_base = *(volatile const uint32_t *)(uintptr_t)(",
        "      image_base + nt_offset + 0x34U);",
        "  iat_address = iat_va + (image_base - preferred_base);",
        "  return *(volatile const uint32_t *)(uintptr_t)iat_address;",
        "}",
        "",
        "stage_b_call_status stage_b_native_run_entry(",
        "    stage_b_machine_state *input, stage_b_machine_state *output) {",
        "  stage_b_call_status status;",
        "  if (input == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;",
        "  if (stage_b_native_root_callback_fault != STAGE_B_CALL_OK)",
        "    return stage_b_native_root_callback_fault;",
        *(
            [
                "  if (stage_b_native_fnsave_to_state(",
                "          &stage_b_native_launch_x87, input) != 0U)",
                "    return STAGE_B_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_replays
            else []
        ),
        "  stage_b_native_unpack_flags(input);",
        f"  input->original_rva = 0x{plan.entry_rva:08x}U;",
        "  *output = *input;",
        "  status = stage_b_native_runtime_run_at_rva(",
        f"      0x{plan.entry_rva:08x}U, input, output);",
        "  if (status != STAGE_B_CALL_OK) return status;",
        "  stage_b_native_pack_flags(output);",
        *(
            [
                "  if (stage_b_native_state_to_fnsave(",
                "          output, &stage_b_native_launch_output_x87) != 0U)",
                "    return STAGE_B_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_replays
            else []
        ),
        "  return STAGE_B_CALL_OK;",
        "}",
        "",
        "stage_b_call_status stage_b_native_run_callback(",
        "    uint32_t callback_rva, uint32_t stack_cleanup_bytes,",
        "    stage_b_machine_state *input, stage_b_machine_state *output,",
        "    const stage_b_x87_fnsave_image *input_x87,",
        "    stage_b_x87_fnsave_image *output_x87) {",
        "  const stage_b_native_callback_entry *entry =",
        "      stage_b_native_callback_entry_for(callback_rva);",
        "  stage_b_call_status status;",
        "  if (entry == 0 || input == 0 || output == 0 ||",
        "      entry->stack_cleanup_bytes != stack_cleanup_bytes)",
        "    return STAGE_B_CALL_UNIMPLEMENTED;",
        *(
            [
                "  if (stage_b_native_fnsave_to_state(input_x87, input) != 0U)",
                "    return STAGE_B_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_replays
            else ["  (void)input_x87;", "  (void)output_x87;"]
        ),
        "  stage_b_native_unpack_flags(input);",
        "  input->original_rva = callback_rva;",
        "  *output = *input;",
        "  status = stage_b_native_active_bridge != 0",
        "      ? stage_b_native_runtime_run_nested_callback(",
        "          callback_rva, stack_cleanup_bytes, input, output)",
        "      : stage_b_native_runtime_run_at_rva(callback_rva, input, output);",
        "  if (status != STAGE_B_CALL_OK) return status;",
        "  if (output->esp != input->esp + 4U + stack_cleanup_bytes)",
        "    return STAGE_B_CALL_UNIMPLEMENTED;",
        "  stage_b_native_pack_flags(output);",
        *(
            [
                "  if (stage_b_native_state_to_fnsave(output, output_x87) != 0U)",
                "    return STAGE_B_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_replays
            else []
        ),
        "  return STAGE_B_CALL_OK;",
        "}",
        "",
        *(
            _x87_handler_source_lines()
            if plan.x87_replays
            else []
        ),
        "stage_b_call_status stage_b_dispatch_external_call(",
        "    stage_b_runtime *runtime,",
        "    const stage_b_call_event *event,",
        "    const stage_b_machine_state *input,",
        "    stage_b_machine_state *output) {",
        "  stage_b_native_bridge_frame frame;",
        "  const stage_b_native_bridge_entry *entry;",
        "  if (runtime != &stage_b_native_runtime_instance ||",
        "      event == 0 || input == 0 || output == 0)",
        "    return STAGE_B_CALL_UNIMPLEMENTED;",
        "  entry = stage_b_native_bridge_entry_for(event->instruction_rva);",
        "  if (entry == 0) return STAGE_B_CALL_UNIMPLEMENTED;",
        "  if ((entry->dynamic_target && event->kind != STAGE_B_CALL_INDIRECT) ||",
        "      (!entry->dynamic_target && event->kind != STAGE_B_CALL_EXTERNAL_IMPORT))",
        "    return STAGE_B_CALL_UNIMPLEMENTED;",
        "  frame.parent = stage_b_native_active_bridge;",
        "  frame.output = output;",
        "  frame.private_esp = 0U;",
        "  frame.call_target = entry->dynamic_target",
        "      ? event->target_rva : stage_b_native_original_iat_target(entry->iat_va);",
        "  frame.status = STAGE_B_CALL_UNIMPLEMENTED;",
        "  frame.saved_continuation = 0U;",
        "  frame.continuation_replaced = entry->tail_jump != 0U;",
        "  if (frame.call_target == 0U) return STAGE_B_CALL_UNIMPLEMENTED;",
        "  if (entry->tail_jump != 0U) {",
        "    if (runtime->context == 0)",
        "      return STAGE_B_CALL_UNIMPLEMENTED;",
        "    if (stage_b_native_fixed_flat_read_u32(",
        "            input->esp, &frame.saved_continuation) == 0U ||",
        "        frame.saved_continuation == 0U)",
        "      return STAGE_B_CALL_MEMORY_FAULT;",
        "  }",
        "  *output = *input;",
        "  stage_b_native_pack_flags(output);",
        *(
            [
                "  if (stage_b_native_state_to_fnsave(input, &frame.input_x87) != 0U)",
                "    return STAGE_B_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_replays
            else []
        ),
        "  frame.input = output;",
        "  stage_b_native_active_bridge = &frame;",
        "  stage_b_native_dispatch_bridge();",
        "  if (stage_b_native_active_bridge != &frame)",
        "    frame.status = STAGE_B_CALL_UNIMPLEMENTED;",
        "  stage_b_native_active_bridge = frame.parent;",
        "  if (entry->tail_jump != 0U && frame.continuation_replaced != 0U)",
        "    frame.status = STAGE_B_CALL_UNIMPLEMENTED;",
        *(
            [
                "  if (frame.status == STAGE_B_CALL_OK &&",
                "      stage_b_native_fnsave_to_state(&frame.output_x87, output) != 0U)",
                "    frame.status = STAGE_B_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_replays
            else []
        ),
        "  return frame.status;",
        "}",
        "",
    ])


def _x87_handler_source_lines() -> list[str]:
    return [
        "stage_b_call_status stage_b_native_replay_checked_x87_command(",
        "    stage_b_runtime *runtime, const stage_b_x87_replay_program *program,",
        "    const stage_b_machine_state *input, stage_b_machine_state *output) {",
        "  const stage_b_native_x87_entry *entry;",
        "  stage_b_native_x87_frame frame;",
        "  if (runtime != &stage_b_native_runtime_instance || program == 0 ||",
        "      input == 0 || output == 0 || program->instruction_count != 1U)",
        "    return STAGE_B_CALL_UNIMPLEMENTED;",
        "  entry = stage_b_native_x87_entry_for(program->rva_start);",
        "  if (entry == 0 || entry->image_base != program->image_base ||",
        "      entry->rva_end != program->rva_end ||",
        "      entry->byte_count != program->byte_count ||",
        "      !stage_b_native_bytes_equal(entry->instruction_bytes,",
        "          program->instruction_bytes, entry->byte_count) ||",
        "      !stage_b_native_string_equal(entry->instruction_bytes_sha256,",
        "          program->instruction_bytes_sha256) ||",
        "      !stage_b_native_string_equal(entry->transfer_instruction_bytes_sha256,",
        "          program->transfer_instruction_bytes_sha256) ||",
        "      !stage_b_native_string_equal(entry->contract_sha256,",
        "          program->contract_sha256) ||",
        f"      !stage_b_native_string_equal(program->checked_decoder, {json.dumps(_X87_CHECKED_DECODER)}) ||",
        f"      !stage_b_native_string_equal(program->checked_executor, {json.dumps(_X87_CHECKED_EXECUTOR)}))",
        "    return STAGE_B_CALL_UNIMPLEMENTED;",
        "  frame.parent = stage_b_native_active_x87;",
        "  frame.input = output;",
        "  frame.output = output;",
        "  frame.private_esp = 0U;",
        "  frame.status = STAGE_B_CALL_UNIMPLEMENTED;",
        "  *output = *input;",
        "  stage_b_native_pack_flags(output);",
        "  if (stage_b_native_state_to_fnsave(input, &frame.input_x87) != 0U)",
        "    return STAGE_B_CALL_UNIMPLEMENTED;",
        "  stage_b_native_active_x87 = &frame;",
        "  entry->bridge();",
        "  if (stage_b_native_active_x87 != &frame)",
        "    frame.status = STAGE_B_CALL_UNIMPLEMENTED;",
        "  stage_b_native_active_x87 = frame.parent;",
        "  if (frame.status == STAGE_B_CALL_OK &&",
        "      stage_b_native_fnsave_to_state(&frame.output_x87, output) != 0U)",
        "    frame.status = STAGE_B_CALL_UNIMPLEMENTED;",
        "  return frame.status;",
        "}",
        "",
    ]


def _bridge_assembly(plan: NativeEnginePlan) -> str:
    termination_iat = (
        f"0x{plan.termination_import.iat_va:08x}"
        if plan.termination_import is not None
        else None
    )
    lines = [
        "    .intel_syntax noprefix",
        "    .text",
        "",
        "/* The PE entry snapshot is made before C code can disturb launch state. */",
        "    .globl _stage_b_payload_entry",
        "    .globl stage_b_payload_entry",
        "_stage_b_payload_entry:",
        "stage_b_payload_entry:",
        "    pushfd",
        "    pushad",
        "    mov edx, OFFSET FLAT:_stage_b_native_launch_state",
        *_capture_pushad_registers("edx"),
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['esp']}], ecx",
        "    mov eax, DWORD PTR [esp + 32]",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], eax",
        *_capture_split_flags("edx"),
        "    mov eax, DWORD PTR fs:[0x18]",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['fs_base']}], eax",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['original_rva']}], "
        f"0x{plan.entry_rva:08x}",
        "    lea eax, [esp + 36]",
        "    mov eax, DWORD PTR [eax]",
        "    mov DWORD PTR [_stage_b_native_launch_return], eax",
        *(
            [
                "    fnsave [_stage_b_native_launch_x87]",
                "    frstor [_stage_b_native_launch_x87]",
                "    mov esi, OFFSET FLAT:_stage_b_native_launch_x87",
                *_capture_fnsave_state("esi", "edx", "eax", "ecx"),
            ]
            if plan.x87_replays
            else []
        ),
        "    cld",
        "    mov eax, OFFSET FLAT:_stage_b_native_launch_output",
        "    push eax",
        "    push edx",
        "    call _stage_b_native_run_entry",
        "    .globl _stage_b_native_entry_dispatch_return",
        "_stage_b_native_entry_dispatch_return:",
        "    add esp, 8",
        "    test eax, eax",
        "    jne _stage_b_native_termination",
        "    .globl _stage_b_native_entry_return",
        "_stage_b_native_entry_return:",
        *(
            ["    frstor [_stage_b_native_launch_output_x87]"]
            if plan.x87_replays
            else []
        ),
        "    mov ecx, OFFSET FLAT:_stage_b_native_launch_output",
        f"    mov esp, DWORD PTR [ecx + {_STATE_OFFSETS['esp']}]",
        "    push DWORD PTR [_stage_b_native_launch_return]",
        *_restore_pushes("ecx"),
        "    popad",
        "    popfd",
        "    ret",
        "",
        "_stage_b_native_halt:",
        "    .globl _stage_b_native_termination",
        "_stage_b_native_termination:",
        *(
            [
                "    push eax",
                "    push 0",
                f"    jmp DWORD PTR ds:{termination_iat}",
            ]
            if termination_iat is not None
            else [
                "    ud2",
                "    jmp _stage_b_native_halt",
            ]
        ),
        "",
        "    .globl _stage_b_native_terminate",
        "_stage_b_native_terminate:",
        *(
            [f"    jmp DWORD PTR ds:{termination_iat}"]
            if termination_iat is not None
            else [
                "    ud2",
                "    jmp _stage_b_native_terminate",
            ]
        ),
        "",
        "/* The data-driven bridge preserves its private C frame, restores the",
        " * complete logical ABI state, enters the checked target with CALL stack",
        " * semantics, captures the result, and resumes C dispatch. */",
        "    .globl _stage_b_native_bridge",
        "_stage_b_native_bridge:",
        "    push ebp",
        "    push ebx",
        "    push esi",
        "    push edi",
        "    mov eax, DWORD PTR [_stage_b_native_active_bridge]",
        "    test eax, eax",
        "    je _stage_b_native_bridge_unavailable",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}], esp",
        f"    mov ecx, DWORD PTR [eax + {_FRAME_OFFSETS['input']}]",
        f"    mov edx, DWORD PTR [eax + {_FRAME_OFFSETS['call_target']}]",
        *(
            [f"    frstor [eax + {_FRAME_OFFSETS['input_x87']}]" ]
            if plan.x87_replays
            else []
        ),
        f"    mov esp, DWORD PTR [ecx + {_STATE_OFFSETS['esp']}]",
        f"    cmp DWORD PTR [eax + {_FRAME_OFFSETS['continuation_replaced']}], 0",
        "    jne _stage_b_native_bridge_tail",
        "    sub esp, 8",
        "    mov DWORD PTR [esp], edx",
        "    mov DWORD PTR [esp + 4], OFFSET FLAT:_stage_b_native_capture",
        "    jmp _stage_b_native_bridge_restore",
        "_stage_b_native_bridge_tail:",
        "    mov ebx, DWORD PTR [esp]",
        f"    cmp ebx, DWORD PTR [eax + {_FRAME_OFFSETS['saved_continuation']}]",
        "    jne _stage_b_native_bridge_tail_unavailable",
        "    mov DWORD PTR [esp], OFFSET FLAT:_stage_b_native_capture",
        "    sub esp, 4",
        "    mov DWORD PTR [esp], edx",
        "_stage_b_native_bridge_restore:",
        *_restore_pushes("ecx"),
        "    popad",
        "    popfd",
        "    ret",
        "_stage_b_native_bridge_tail_unavailable:",
        f"    mov esp, DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}]",
        "_stage_b_native_bridge_unavailable:",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
        "",
        "    .globl _stage_b_native_capture",
        "_stage_b_native_capture:",
        "    pushfd",
        "    pushad",
        "    mov eax, DWORD PTR [_stage_b_native_active_bridge]",
        "    test eax, eax",
        "    je _stage_b_native_halt",
        *(
            [f"    fnsave [eax + {_FRAME_OFFSETS['output_x87']}]" ]
            if plan.x87_replays
            else []
        ),
        f"    mov edx, DWORD PTR [eax + {_FRAME_OFFSETS['output']}]",
        *_capture_pushad_registers("edx"),
        f"    cmp DWORD PTR [eax + {_FRAME_OFFSETS['continuation_replaced']}], 0",
        "    je _stage_b_native_capture_continuation_ready",
        f"    mov ebx, DWORD PTR [eax + {_FRAME_OFFSETS['saved_continuation']}]",
        "    mov DWORD PTR [ecx - 4], ebx",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['continuation_replaced']}], 0",
        "_stage_b_native_capture_continuation_ready:",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['esp']}], ecx",
        "    mov ecx, DWORD PTR [esp + 32]",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], ecx",
        *_capture_split_flags("edx"),
        f"    cmp DWORD PTR [eax + {_FRAME_OFFSETS['call_target']}], 0",
        "    je _stage_b_native_capture_preserve_status",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['status']}], 0",
        "_stage_b_native_capture_preserve_status:",
        f"    mov esp, DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}]",
        "    cld",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
    ]
    if plan.callback_targets:
        lines.extend([
            "",
            "/* Callback roots use an explicit checked ABI record.  A nested callback",
            " * reuses the suspended bridge's private stack; a loader TLS callback",
            " * uses the dedicated engine stack. */",
        ])
    for target in plan.callback_targets:
        canonical = target.symbol
        decorated = "_" + canonical
        lines.extend([
            "",
            f"    .globl {canonical}",
            f"    .globl {decorated}",
            f"{canonical}:",
            f"{decorated}:",
            "    pushfd",
            "    pushad",
            "    mov esi, esp",
            "    mov eax, DWORD PTR [_stage_b_native_active_bridge]",
            "    test eax, eax",
            f"    je _stage_b_native_callback_root_stack_{target.id:04d}",
            f"    mov esp, DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}]",
            f"    jmp _stage_b_native_callback_stack_ready_{target.id:04d}",
            f"_stage_b_native_callback_root_stack_{target.id:04d}:",
            "    mov esp, OFFSET FLAT:_stage_b_native_callback_stack + 65536",
            f"_stage_b_native_callback_stack_ready_{target.id:04d}:",
            "    and esp, -16",
            f"    sub esp, {_CALLBACK_FRAME_SIZE}",
            "    mov ebp, esp",
            "    mov edi, ebp",
            "    xor eax, eax",
            f"    mov ecx, {_CALLBACK_FRAME_SIZE // 4}",
            "    cld",
            "    rep stosd",
            "    mov eax, DWORD PTR [_stage_b_native_active_callback]",
            f"    mov DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent']}], eax",
            "    mov eax, DWORD PTR [_stage_b_native_active_bridge]",
            f"    mov DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent_bridge']}], eax",
            "    lea edi, [esi + 36]",
            f"    mov DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['physical_esp']}], edi",
            "    mov eax, DWORD PTR [edi]",
            f"    mov DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['return_target']}], eax",
            "    mov DWORD PTR [_stage_b_native_active_callback], ebp",
            f"    mov eax, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent_bridge']}]",
            "    test eax, eax",
            f"    je _stage_b_native_callback_root_buffers_{target.id:04d}",
            f"    lea edx, [ebp + {_CALLBACK_FRAME_OFFSETS['input']}]",
            f"    lea ebx, [ebp + {_CALLBACK_FRAME_OFFSETS['output']}]",
            f"    jmp _stage_b_native_callback_buffers_ready_{target.id:04d}",
            f"_stage_b_native_callback_root_buffers_{target.id:04d}:",
            "    mov edx, OFFSET FLAT:_stage_b_native_launch_state",
            "    mov ebx, OFFSET FLAT:_stage_b_native_launch_output",
            f"_stage_b_native_callback_buffers_ready_{target.id:04d}:",
            *_capture_pushad_registers_from("esi", "edx"),
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['esp']}], edi",
            "    mov eax, DWORD PTR [esi + 32]",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], eax",
            *_capture_split_flags_from("esi", "edx", "eax"),
            "    mov eax, DWORD PTR fs:[0x18]",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['fs_base']}], eax",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['original_rva']}], "
            f"0x{target.rva:08x}",
            *(
                [
                    f"    mov eax, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent_bridge']}]",
                    "    test eax, eax",
                    f"    je _stage_b_native_callback_root_x87_buffers_{target.id:04d}",
                    f"    lea ecx, [ebp + {_CALLBACK_FRAME_OFFSETS['input_x87']}]",
                    f"    lea eax, [ebp + {_CALLBACK_FRAME_OFFSETS['output_x87']}]",
                    f"    jmp _stage_b_native_callback_x87_buffers_ready_{target.id:04d}",
                    f"_stage_b_native_callback_root_x87_buffers_{target.id:04d}:",
                    "    mov ecx, OFFSET FLAT:_stage_b_native_launch_x87",
                    "    mov eax, OFFSET FLAT:_stage_b_native_launch_output_x87",
                    f"_stage_b_native_callback_x87_buffers_ready_{target.id:04d}:",
                    "    fnsave [ecx]",
                    "    frstor [ecx]",
                    "    mov esi, ecx",
                    *_capture_fnsave_state("esi", "edx", "eax", "ecx"),
                    f"    mov eax, DWORD PTR [ebp + "
                    f"{_CALLBACK_FRAME_OFFSETS['parent_bridge']}]",
                    "    test eax, eax",
                    f"    je _stage_b_native_callback_root_output_x87_{target.id:04d}",
                    f"    lea eax, [ebp + "
                    f"{_CALLBACK_FRAME_OFFSETS['output_x87']}]",
                    f"    jmp _stage_b_native_callback_output_x87_ready_{target.id:04d}",
                    f"_stage_b_native_callback_root_output_x87_{target.id:04d}:",
                    "    mov eax, OFFSET FLAT:_stage_b_native_launch_output_x87",
                    f"_stage_b_native_callback_output_x87_ready_{target.id:04d}:",
                ]
                if plan.x87_replays
                else []
            ),
            *(
                ["    push eax", "    push esi"]
                if plan.x87_replays
                else ["    push 0", "    push 0"]
            ),
            "    push ebx",
            "    push edx",
            f"    push {target.stack_cleanup_bytes}",
            f"    push 0x{target.rva:08x}",
            "    call _stage_b_native_run_callback",
            f"    .globl _{target.dispatch_return_symbol}",
            f"_{target.dispatch_return_symbol}:",
            "    add esp, 24",
            f"    mov DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['status']}], eax",
            "    test eax, eax",
            f"    jne _stage_b_native_callback_failure_{target.id:04d}",
            "    cmp DWORD PTR [_stage_b_native_active_callback], ebp",
            f"    jne _stage_b_native_callback_failure_{target.id:04d}",
            f"    jmp _stage_b_native_callback_success_{target.id:04d}",
            f"_stage_b_native_callback_failure_{target.id:04d}:",
            f"    mov eax, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['status']}]",
            "    test eax, eax",
            f"    jne _stage_b_native_callback_failure_status_{target.id:04d}",
            "    mov eax, 1",
            f"_stage_b_native_callback_failure_status_{target.id:04d}:",
            f"    mov edx, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent_bridge']}]",
            "    test edx, edx",
            f"    je _stage_b_native_callback_root_failure_{target.id:04d}",
            f"    mov DWORD PTR [edx + {_FRAME_OFFSETS['status']}], eax",
            f"    mov DWORD PTR [edx + {_FRAME_OFFSETS['call_target']}], 0",
            f"    jmp _stage_b_native_callback_failure_recorded_{target.id:04d}",
            f"_stage_b_native_callback_root_failure_{target.id:04d}:",
            "    mov DWORD PTR [_stage_b_native_root_callback_fault], eax",
            f"_stage_b_native_callback_failure_recorded_{target.id:04d}:",
            f"    mov eax, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent']}]",
            "    mov DWORD PTR [_stage_b_native_active_callback], eax",
            f"    mov eax, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent_bridge']}]",
            "    test eax, eax",
            f"    je _stage_b_native_callback_root_failure_buffers_{target.id:04d}",
            f"    lea ecx, [ebp + {_CALLBACK_FRAME_OFFSETS['input']}]",
            *(
                [f"    lea ebx, [ebp + {_CALLBACK_FRAME_OFFSETS['input_x87']}]"]
                if plan.x87_replays
                else []
            ),
            f"    jmp _stage_b_native_callback_failure_buffers_ready_{target.id:04d}",
            f"_stage_b_native_callback_root_failure_buffers_{target.id:04d}:",
            "    mov ecx, OFFSET FLAT:_stage_b_native_launch_state",
            *(
                ["    mov ebx, OFFSET FLAT:_stage_b_native_launch_x87"]
                if plan.x87_replays
                else []
            ),
            f"_stage_b_native_callback_failure_buffers_ready_{target.id:04d}:",
            *(
                ["    frstor [ebx]"]
                if plan.x87_replays
                else []
            ),
            f"    mov edx, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['return_target']}]",
            f"    mov esp, DWORD PTR [ecx + {_STATE_OFFSETS['esp']}]",
            f"    add esp, {4 + target.stack_cleanup_bytes}",
            "    push edx",
            *_restore_pushes("ecx"),
            "    popad",
            "    popfd",
            "    ret",
            f"_stage_b_native_callback_success_{target.id:04d}:",
            f"    mov eax, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent']}]",
            "    mov DWORD PTR [_stage_b_native_active_callback], eax",
            f"    mov eax, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['parent_bridge']}]",
            "    test eax, eax",
            f"    je _stage_b_native_callback_root_success_buffers_{target.id:04d}",
            f"    lea ecx, [ebp + {_CALLBACK_FRAME_OFFSETS['output']}]",
            *(
                [f"    lea ebx, [ebp + {_CALLBACK_FRAME_OFFSETS['output_x87']}]"]
                if plan.x87_replays
                else []
            ),
            f"    jmp _stage_b_native_callback_success_buffers_ready_{target.id:04d}",
            f"_stage_b_native_callback_root_success_buffers_{target.id:04d}:",
            "    mov ecx, OFFSET FLAT:_stage_b_native_launch_output",
            *(
                ["    mov ebx, OFFSET FLAT:_stage_b_native_launch_output_x87"]
                if plan.x87_replays
                else []
            ),
            f"_stage_b_native_callback_success_buffers_ready_{target.id:04d}:",
            *(
                ["    frstor [ebx]"]
                if plan.x87_replays
                else []
            ),
            f"    mov edx, DWORD PTR [ebp + {_CALLBACK_FRAME_OFFSETS['return_target']}]",
            f"    mov esp, DWORD PTR [ecx + {_STATE_OFFSETS['esp']}]",
            "    push edx",
            *_restore_pushes("ecx"),
            "    popad",
            "    popfd",
            "    ret",
        ])
    if plan.x87_replays:
        lines.extend([
            "",
            "/* Qualified singleton x87 commands run from exact bound bytes. */",
        ])
    for replay in plan.x87_replays:
        replay_padding = (
            _X87_REPLAY_INLINE_CAPTURE_OFFSET
            - _X87_REPLAY_INLINE_INSTRUCTION_OFFSET
            - len(replay.instruction_bytes)
        )
        if replay_padding < 0:
            raise StageAInputError(
                f"x87 replay {replay.id} does not fit the fixed bridge slot"
            )
        lines.extend([
            "",
            f"    .globl _stage_b_native_x87_bridge_{replay.id:04d}",
            f"_stage_b_native_x87_bridge_{replay.id:04d}:",
            "    push ebp",
            "    push ebx",
            "    push esi",
            "    push edi",
            "    mov eax, DWORD PTR [_stage_b_native_active_x87]",
            f"    mov DWORD PTR [eax + {_X87_FRAME_OFFSETS['private_esp']}], esp",
            f"    frstor [eax + {_X87_FRAME_OFFSETS['input_x87']}]",
            f"    mov eax, DWORD PTR [eax + {_X87_FRAME_OFFSETS['input']}]",
            f"    mov ebx, DWORD PTR [eax + {_STATE_OFFSETS['ebx']}]",
            f"    mov ecx, DWORD PTR [eax + {_STATE_OFFSETS['ecx']}]",
            f"    mov esi, DWORD PTR [eax + {_STATE_OFFSETS['esi']}]",
            f"    mov edi, DWORD PTR [eax + {_STATE_OFFSETS['edi']}]",
            f"    mov ebp, DWORD PTR [eax + {_STATE_OFFSETS['ebp']}]",
            f"    mov esp, DWORD PTR [eax + {_STATE_OFFSETS['esp']}]",
            f"    push DWORD PTR [eax + {_STATE_OFFSETS['eflags']}]",
            f"    push DWORD PTR [eax + {_STATE_OFFSETS['eax']}]",
            f"    mov edx, DWORD PTR [eax + {_STATE_OFFSETS['edx']}]",
            "    pop eax",
            "    popfd",
            "    nop",
            "    nop",
            "    nop",
            f"    .if (. - _stage_b_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_INSTRUCTION_OFFSET}",
            '    .error "x87 replay instruction offset changed"',
            "    .endif",
            f"    .globl _stage_b_native_x87_instruction_{replay.id:04d}",
            f"_stage_b_native_x87_instruction_{replay.id:04d}:",
            *_x87_replay_instruction_lines(replay),
            *(["    nop"] * replay_padding),
            f"    .if (. - _stage_b_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_CAPTURE_OFFSET}",
            '    .error "x87 replay capture offset changed"',
            "    .endif",
            f"_stage_b_native_x87_capture_{replay.id:04d}:",
            "    pushfd",
            "    push eax",
            "    mov eax, DWORD PTR [_stage_b_native_active_x87]",
            f"    fnsave [eax + {_X87_FRAME_OFFSETS['output_x87']}]",
            f"    mov edx, DWORD PTR [eax + {_X87_FRAME_OFFSETS['output']}]",
            "    mov ecx, DWORD PTR [esp]",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eax']}], ecx",
            f"    setc BYTE PTR [edx + {_STATE_OFFSETS['cf']}]",
            f"    setp BYTE PTR [edx + {_STATE_OFFSETS['pf']}]",
            f"    setz BYTE PTR [edx + {_STATE_OFFSETS['zf']}]",
            f"    sets BYTE PTR [edx + {_STATE_OFFSETS['sf']}]",
            f"    seto BYTE PTR [edx + {_STATE_OFFSETS['of']}]",
            "    mov ebx, DWORD PTR [esp + 4]",
            f"    mov ecx, DWORD PTR [eax + {_X87_FRAME_OFFSETS['input']}]",
            f"    mov ecx, DWORD PTR [ecx + {_STATE_OFFSETS['eflags']}]",
            "    and ecx, 0xfffff32a",
            "    and ebx, 0x00000cd5",
            "    or ecx, ebx",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], ecx",
            *(["    nop"] * 10),
            f"    mov DWORD PTR [eax + {_X87_FRAME_OFFSETS['status']}], 0",
            f"    mov esp, DWORD PTR [eax + {_X87_FRAME_OFFSETS['private_esp']}]",
            "    cld",
            "    pop edi",
            "    pop esi",
            "    pop ebx",
            "    pop ebp",
            f"    .if (. - _stage_b_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_RETURN_OFFSET}",
            '    .error "x87 replay return offset changed"',
            "    .endif",
            f"_stage_b_native_x87_return_{replay.id:04d}:",
            "    ret",
            "    nop",
            "    nop",
            "    nop",
            "    nop",
            f"    .if (. - _stage_b_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_BODY_SIZE}",
            '    .error "x87 replay bridge size changed"',
            "    .endif",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _x87_replay_instruction_lines(replay: NativeX87Replay) -> list[str]:
    offset = replay.operand_byte_offset
    if offset is None:
        return [
            "    .byte " + ", ".join(
                f"0x{byte:02x}" for byte in replay.instruction_bytes
            )
        ]
    if replay.target_rva is None or replay.relocation_width != 4:
        raise StageAInputError("relocated x87 replay lacks its checked target binding")
    lines: list[str] = []
    leading = replay.instruction_bytes[:offset]
    trailing = replay.instruction_bytes[offset + 4 :]
    if leading:
        lines.append("    .byte " + ", ".join(f"0x{byte:02x}" for byte in leading))
    lines.append(f"    .long ___ImageBase + 0x{replay.target_rva:08x}")
    if trailing:
        lines.append("    .byte " + ", ".join(f"0x{byte:02x}" for byte in trailing))
    return lines


def _restore_pushes(state_register: str) -> list[str]:
    """Build a PUSHAD/POPAD-compatible restore record below logical ESP."""

    return [
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['eflags']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['eax']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ecx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['edx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ebx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['esp']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ebp']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['esi']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['edi']}]",
    ]


def _capture_pushad_registers(output_register: str) -> list[str]:
    """Capture the PUSHFD/PUSHAD record without losing its logical ESP."""

    return _capture_pushad_registers_from("esp", output_register)


def _capture_pushad_registers_from(
    stack_register: str, output_register: str
) -> list[str]:
    """Capture a PUSHFD/PUSHAD record addressed by ``stack_register``."""

    stack_offsets = {
        "edi": 0,
        "esi": 4,
        "ebp": 8,
        "ebx": 16,
        "edx": 20,
        "ecx": 24,
        "eax": 28,
    }
    lines: list[str] = []
    for field, stack_offset in stack_offsets.items():
        lines.extend([
            f"    mov ecx, DWORD PTR [{stack_register} + {stack_offset}]",
            f"    mov DWORD PTR [{output_register} + {_STATE_OFFSETS[field]}], ecx",
        ])
    lines.append(f"    lea ecx, [{stack_register} + 36]")
    return lines


def _absolute_iat_va(raw: bytes, mnemonic: str) -> int | None:
    """Return the absolute IAT cell encoded by ``call/jmp [imm32]``."""

    expected = b"\xff\x15" if mnemonic == "call" else b"\xff\x25"
    if mnemonic not in {"call", "jmp"} or len(raw) != 6 or raw[:2] != expected:
        return None
    return int.from_bytes(raw[2:], "little")


def _indirect_call_encoding(raw: bytes) -> bool:
    """Accept exact unprefixed 32-bit FF /2 indirect CALL encodings."""

    if len(raw) < 2 or raw[0] != 0xFF or ((raw[1] >> 3) & 7) != 2:
        return False
    mod = raw[1] >> 6
    rm = raw[1] & 7
    if mod == 3:
        return len(raw) == 2
    if rm == 4:
        if len(raw) < 3:
            return False
    absolute_sib = rm == 4 and mod == 0 and (raw[2] & 7) == 5
    displacement_size = (
        4 if (mod == 0 and rm == 5) or absolute_sib or mod == 2
        else 1 if mod == 1
        else 0
    )
    expected_size = 2 + (1 if rm == 4 else 0) + displacement_size
    return len(raw) == expected_size


def _uses_x87_state(row: Mapping[str, Any]) -> bool:
    if row.get("fpu_state") is not None:
        return True

    def walk(value: Any) -> bool:
        if isinstance(value, Mapping):
            operation = value.get("op")
            if isinstance(operation, str) and operation.startswith(("fpu_", "x87_")):
                return True
            return any(walk(item) for item in value.values())
        if isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    return walk(row)


def _qualified_x87_replays(
    *,
    row: Mapping[str, Any],
    transfer_id: str,
    first_id: int,
    relocation_evidence: _PEBaseRelocationEvidence | None,
) -> tuple[NativeX87Replay, ...]:
    fpu = row.get("fpu_state")
    if not isinstance(fpu, Mapping) or fpu.get("model") != _X87_REPLAY_MODEL:
        raise StageAInputError("x87 state is not an exact native replay obligation")
    if fpu.get("status") != "required":
        raise StageAInputError("x87 replay obligation status must be required")
    if fpu.get("authoritative_state_type") != "StageA.X87.PhysicalState":
        raise StageAInputError("x87 replay does not bind StageA.X87.PhysicalState")
    if fpu.get("required_fields") != list(_X87_PHYSICAL_FIELDS):
        raise StageAInputError("x87 replay physical-field inventory changed")
    missing = fpu.get("missing_or_invalid_fields")
    if (
        not isinstance(missing, list)
        or not missing
        or any(item not in _X87_PHYSICAL_FIELDS for item in missing)
        or len(set(item for item in missing if isinstance(item, str))) != len(missing)
    ):
        raise StageAInputError("x87 replay missing-field inventory is malformed")
    unexpected = [
        field for field in _X87_PHYSICAL_FIELDS
        if field != "status" and field in fpu
    ]
    if unexpected:
        raise StageAInputError(
            "x87 replay contains unqualified physical fields: " + ", ".join(unexpected)
        )
    replay = fpu.get("replay")
    if not isinstance(replay, Mapping):
        raise StageAInputError("x87 replay binding must be an object")
    expected_literals = {
        "format": _X87_REPLAY_FORMAT,
        "checked_decoder": _X87_CHECKED_DECODER,
        "checked_executor": _X87_CHECKED_EXECUTOR,
        "architecture": "x86",
        "bitness": 32,
    }
    for field, expected in expected_literals.items():
        if replay.get(field) != expected:
            raise StageAInputError(f"x87 replay {field} must be {expected!r}")
    original = row.get("original")
    if not isinstance(original, Mapping):
        raise StageAInputError("x87 replay has no original span")
    rva_start = _required_u32(original.get("rva_start"), "x87 original start")
    rva_end = _required_u32(original.get("rva_end"), "x87 original end")
    if rva_end <= rva_start:
        raise StageAInputError("x87 replay span must be nonempty")
    if replay.get("rva_start") != rva_start or replay.get("rva_end") != rva_end:
        raise StageAInputError("x87 replay span differs from its transfer")
    raw_hex = replay.get("bytes")
    if not isinstance(raw_hex, str) or not _HEX_BYTES.fullmatch(raw_hex):
        raise StageAInputError("x87 replay bytes must be canonical hexadecimal")
    raw = bytes.fromhex(raw_hex)
    if len(raw) != rva_end - rva_start:
        raise StageAInputError("x87 replay bytes do not cover the transfer")
    transfer_digest = _required_sha256(
        row.get("instruction_bytes_sha256"), "x87 transfer instruction digest"
    )
    replay_digest = _required_sha256(
        replay.get("bytes_sha256"), "x87 replay instruction digest"
    )
    if sha256_bytes(raw) != replay_digest or replay_digest != transfer_digest:
        raise StageAInputError("x87 replay digest does not bind the transfer bytes")
    contract_digest = _required_sha256(
        row.get("contract_sha256"), "x87 transfer contract digest"
    )
    image_base = _required_u32(replay.get("image_base"), "x87 replay image base")
    outer_instructions = row.get("instructions")
    replay_instructions = replay.get("instructions")
    schedule = replay.get("instruction_effect_schedule")
    if (
        not isinstance(outer_instructions, list)
        or not isinstance(replay_instructions, list)
        or not replay_instructions
        or len(outer_instructions) != len(replay_instructions)
    ):
        raise StageAInputError("x87 replay instruction inventories differ")
    cursor = rva_start
    reconstructed = bytearray()
    result: list[NativeX87Replay] = []
    schedule_records: list[Any] | None = None
    if schedule is not None:
        if not isinstance(schedule, Mapping):
            raise StageAInputError("x87 instruction effect schedule must be an object")
        if (
            schedule.get("format")
            != INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT
            or schedule.get("status") != "complete"
            or schedule.get("proof_authority") is not False
            or schedule.get("transfer_bytes_sha256") != transfer_digest
            or schedule.get("blockers") != []
            or row.get("instruction_effect_schedule") != schedule
        ):
            raise StageAInputError("x87 instruction effect schedule is not qualified")
        _verify_embedded_sha256(schedule, "schedule_sha256", "x87 effect schedule")
        raw_records = schedule.get("records")
        if not isinstance(raw_records, list) or len(raw_records) != len(replay_instructions):
            raise StageAInputError("x87 instruction effect schedule coverage differs")
        schedule_records = raw_records
    for index, (outer, bound) in enumerate(
        zip(outer_instructions, replay_instructions, strict=True)
    ):
        if not isinstance(outer, Mapping) or not isinstance(bound, Mapping):
            raise StageAInputError(f"x87 replay instruction {index} is malformed")
        instruction_rva = _required_u32(bound.get("rva"), "x87 instruction RVA")
        size = bound.get("size")
        encoded_hex = bound.get("bytes")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or not isinstance(encoded_hex, str)
            or not _HEX_BYTES.fullmatch(encoded_hex)
        ):
            raise StageAInputError(f"x87 replay instruction {index} is malformed")
        encoded = bytes.fromhex(encoded_hex)
        if len(encoded) != size or instruction_rva != cursor:
            raise StageAInputError("x87 replay instructions are not exact and contiguous")
        if any(
            outer.get(field) != value
            for field, value in {
                "rva": instruction_rva,
                "size": size,
                "bytes": encoded_hex,
            }.items()
        ):
            raise StageAInputError("x87 replay outer instruction binding differs")
        is_x87 = _x87_singleton_candidate(encoded, outer)
        if schedule_records is None:
            if not is_x87:
                raise StageAInputError(
                    "mixed ordinary/x87 replay requires instruction-ordered lowering"
                )
        else:
            record = schedule_records[index]
            if not isinstance(record, Mapping):
                raise StageAInputError(f"x87 schedule record {index} is malformed")
            _verify_embedded_sha256(
                record, "record_sha256", f"x87 schedule record {index}"
            )
            if (
                record.get("index") != index
                or record.get("rva_start") != instruction_rva
                or record.get("rva_end") != instruction_rva + size
                or record.get("bytes") != encoded_hex
                or record.get("bytes_sha256") != sha256_bytes(encoded)
                or record.get("transfer_bytes_sha256") != transfer_digest
            ):
                raise StageAInputError(
                    f"x87 schedule record {index} differs from exact instruction bytes"
                )
            expected_class = (
                "x87_singleton_checked_replay"
                if is_x87 else "ordinary_symbolic_instruction"
            )
            if record.get("instruction_class") != expected_class:
                raise StageAInputError(
                    f"x87 schedule record {index} classification differs"
                )
            classification = record.get("classification")
            if (
                not isinstance(classification, Mapping)
                or classification.get("status")
                != "proposal_requires_lean_exact_byte_replay"
                or classification.get("proof_authority") is not False
            ):
                raise StageAInputError(
                    f"x87 schedule record {index} lacks checked classification"
                )
        if is_x87:
            operand_offset = _x87_absolute_operand_offset(encoded)
            relocation: _PEBaseRelocation | None = None
            if operand_offset is not None:
                source_rva = instruction_rva + operand_offset
                matches = (
                    [
                        item
                        for item in relocation_evidence.relocations
                        if item.source_rva == source_rva
                    ]
                    if relocation_evidence is not None
                    else []
                )
                if len(matches) != 1:
                    raise _X87ReplayASLRUnsafe(
                        "absolute x87 disp32 does not have exactly one bound PE relocation"
                    )
                relocation = matches[0]
                if relocation_evidence is None or relocation_evidence.image_base != image_base:
                    raise _X87ReplayASLRUnsafe(
                        "x87 relocation evidence preferred image base differs from replay"
                    )
                if relocation.type != 3 or relocation.width != 4:
                    raise _X87ReplayASLRUnsafe(
                        "x87 absolute operand relocation is not PE32 HIGHLOW width 4"
                    )
                if source_rva < instruction_rva or source_rva + 4 > instruction_rva + size:
                    raise _X87ReplayASLRUnsafe(
                        "x87 relocation target span is outside its exact instruction"
                    )
                raw_preferred = int.from_bytes(
                    encoded[operand_offset : operand_offset + 4], "little"
                )
                if relocation.preferred_value != raw_preferred:
                    raise _X87ReplayASLRUnsafe(
                        "x87 relocation preferred value differs from exact operand bytes"
                    )
                if raw_preferred < image_base:
                    raise _X87ReplayASLRUnsafe(
                        "x87 relocation preferred value is below the preferred image base"
                    )
            elif not _x87_replay_relocation_safe(encoded):
                raise _X87ReplayASLRUnsafe(
                    "x87 singleton uses an absolute or unqualified addressing form "
                    "whose raw .byte replay has no PE HIGHLOW relocation"
                )
            elif relocation_evidence is not None and any(
                item.source_rva < instruction_rva + size
                and item.source_rva + item.width > instruction_rva
                for item in relocation_evidence.relocations
            ):
                raise _X87ReplayASLRUnsafe(
                    "position-independent x87 instruction overlaps unexpected relocation evidence"
                )
            result.append(NativeX87Replay(
                id=first_id + len(result),
                transfer_id=transfer_id,
                contract_sha256=contract_digest,
                instruction_bytes_sha256=sha256_bytes(encoded),
                transfer_instruction_bytes_sha256=transfer_digest,
                image_base=image_base,
                rva_start=instruction_rva,
                rva_end=instruction_rva + size,
                instruction_bytes=encoded,
                relocation_source_rva=(
                    relocation.source_rva if relocation is not None else None
                ),
                operand_byte_offset=operand_offset,
                preferred_value=(
                    relocation.preferred_value if relocation is not None else None
                ),
                target_rva=(
                    relocation.preferred_value - image_base
                    if relocation is not None
                    else None
                ),
                relocation_type=relocation.type if relocation is not None else None,
                relocation_width=relocation.width if relocation is not None else None,
                relocation_pe_sha256=(
                    relocation_evidence.pe_sha256
                    if relocation is not None and relocation_evidence is not None
                    else None
                ),
                relocation_reference_contract_sha256=(
                    relocation_evidence.reference_contract_sha256
                    if relocation is not None and relocation_evidence is not None
                    else None
                ),
            ))
        reconstructed.extend(encoded)
        cursor += size
    if cursor != rva_end or bytes(reconstructed) != raw:
        raise StageAInputError("x87 replay instructions do not reconstruct the span")
    if schedule_records is None:
        outcome = row.get("outcome")
        if (
            not isinstance(outcome, Mapping)
            or outcome.get("kind") != "fallthrough"
            or outcome.get("target_rva") != rva_end
        ):
            raise StageAInputError("x87 replay transfer is not an exact fallthrough")
    return tuple(result)


def _verify_embedded_sha256(
    payload: Mapping[str, Any], field: str, context: str
) -> None:
    expected = _required_sha256(payload.get(field), f"{context} SHA-256")
    body = dict(payload)
    del body[field]
    actual = sha256_bytes(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )
    if actual != expected:
        raise StageAInputError(f"{context} SHA-256 mismatch")


def _x87_singleton_candidate(
    instruction_bytes: bytes, instruction: Mapping[str, Any]
) -> bool:
    mnemonic = instruction.get("mnemonic")
    if not isinstance(mnemonic, str):
        return False
    mnemonic = mnemonic.lower()
    if mnemonic == "wait":
        return instruction_bytes == b"\x9b"
    return mnemonic.startswith("f") and any(
        0xD8 <= byte <= 0xDF for byte in instruction_bytes[:4]
    )


def _x87_replay_relocation_safe(encoded: bytes) -> bool:
    """Accept only exact unprefixed x87 forms with no absolute disp32 operand."""

    if encoded == b"\x9b":
        return True
    if len(encoded) < 2 or not 0xD8 <= encoded[0] <= 0xDF:
        return False
    modrm = encoded[1]
    mod = modrm >> 6
    rm = modrm & 7
    if mod == 3:
        return len(encoded) == 2
    cursor = 2
    absolute = mod == 0 and rm == 5
    if rm == 4:
        if len(encoded) <= cursor:
            return False
        sib = encoded[cursor]
        cursor += 1
        absolute = absolute or (mod == 0 and (sib & 7) == 5)
    displacement_size = 1 if mod == 1 else 4 if mod == 2 or absolute else 0
    return not absolute and len(encoded) == cursor + displacement_size


def _x87_absolute_operand_offset(encoded: bytes) -> int | None:
    """Locate the sole unprefixed x87 absolute disp32 operand, if present."""

    if len(encoded) < 6 or not 0xD8 <= encoded[0] <= 0xDF:
        return None
    modrm = encoded[1]
    if modrm >> 6 != 0:
        return None
    rm = modrm & 7
    if rm == 5 and len(encoded) == 6:
        return 2
    if rm == 4 and len(encoded) == 7 and (encoded[2] & 7) == 5:
        return 3
    return None


def _parse_pe_base_relocation_evidence(
    value: Mapping[str, Any] | None,
) -> _PEBaseRelocationEvidence | None:
    if value is None:
        return None
    expected_fields = {
        "format", "complete", "pe_sha256", "reference_contract_sha256",
        "image_base", "relocations"
    }
    if set(value) != expected_fields:
        raise StageAInputError(
            "PE base-relocation evidence fields do not match the v1 schema"
        )
    if value.get("format") != PE32_BASE_RELOCATION_EVIDENCE_FORMAT:
        raise StageAInputError("unsupported PE base-relocation evidence format")
    if value.get("complete") is not True:
        raise StageAInputError("PE base-relocation evidence must be complete")
    pe_sha256 = _required_sha256(
        value.get("pe_sha256"), "PE base-relocation evidence PE SHA-256"
    )
    reference_contract_sha256 = _required_sha256(
        value.get("reference_contract_sha256"),
        "PE base-relocation evidence reference-contract SHA-256",
    )
    image_base = _required_u32(
        value.get("image_base"), "PE base-relocation evidence image base"
    )
    raw_rows = value.get("relocations")
    if not isinstance(raw_rows, list):
        raise StageAInputError("PE base-relocation evidence relocations must be a list")
    rows: list[_PEBaseRelocation] = []
    seen_sources: set[int] = set()
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, Mapping) or set(raw) != {
            "source_rva", "type", "kind", "width", "preferred_value"
        }:
            raise StageAInputError(
                f"PE base relocation {index} fields do not match the v1 schema"
            )
        source_rva = _required_u32(
            raw.get("source_rva"), f"PE base relocation {index} source RVA"
        )
        relocation_type = _required_u32(
            raw.get("type"), f"PE base relocation {index} type"
        )
        width = _required_u32(
            raw.get("width"), f"PE base relocation {index} width"
        )
        if width == 0:
            raise StageAInputError(
                f"PE base relocation {index} width must be nonzero"
            )
        preferred_value = _required_u32(
            raw.get("preferred_value"),
            f"PE base relocation {index} preferred value",
        )
        kind = raw.get("kind")
        if (relocation_type == 3) != (kind == "highlow"):
            raise StageAInputError(
                f"PE base relocation {index} type/kind disagree"
            )
        if source_rva in seen_sources:
            raise StageAInputError("PE base-relocation evidence has duplicate sources")
        seen_sources.add(source_rva)
        rows.append(_PEBaseRelocation(
            source_rva=source_rva,
            type=relocation_type,
            width=width,
            preferred_value=preferred_value,
        ))
    rows.sort(key=lambda item: item.source_rva)
    for previous, current in zip(rows, rows[1:]):
        if current.source_rva < previous.source_rva + previous.width:
            raise StageAInputError("PE base-relocation evidence ranges overlap")
    return _PEBaseRelocationEvidence(
        pe_sha256=pe_sha256,
        reference_contract_sha256=reference_contract_sha256,
        image_base=image_base,
        relocations=tuple(rows),
    )


def _callback_spec(
    value: int | Mapping[str, Any], index: int
) -> tuple[int, str, int]:
    if not isinstance(value, Mapping):
        raise StageAInputError(
            f"callback {index} is only an RVA and has no checked ABI kind"
        )
    expected_fields = {"rva", "kind", "stack_cleanup_bytes"}
    if set(value) != expected_fields:
        raise StageAInputError(
            f"callback {index} must contain exactly {sorted(expected_fields)}"
        )
    rva = _required_u32(value.get("rva"), f"callback {index} RVA")
    kind = _required_string(value.get("kind"), f"callback {index} kind")
    cleanup = value.get("stack_cleanup_bytes")
    if (
        isinstance(cleanup, bool)
        or not isinstance(cleanup, int)
        or not 0 <= cleanup <= 0xFFFF
    ):
        raise StageAInputError(f"callback {index} cleanup must be a uint16")
    if kind == "tls_callback":
        if cleanup != 12:
            raise StageAInputError("PE32 TLS callbacks require stdcall cleanup of 12 bytes")
    elif kind != "generic_callback":
        raise StageAInputError(
            "callback kind must be tls_callback or generic_callback"
        )
    return rva, kind, cleanup


def _capture_split_flags(output_register: str) -> list[str]:
    return _capture_split_flags_from("esp", output_register, "ecx")


def _capture_x87_result_flags(output_register: str) -> list[str]:
    return _capture_split_flags_from(
        "esp",
        output_register,
        "ecx",
        fields=("cf", "pf", "zf"),
        flags_offset=4,
    )


def _capture_split_flags_from(
    stack_register: str,
    output_register: str,
    scratch_register: str,
    *,
    fields: tuple[str, ...] = ("cf", "pf", "zf", "sf", "df", "of"),
    flags_offset: int = 32,
) -> list[str]:
    bits = {"cf": 0, "pf": 2, "zf": 6, "sf": 7, "df": 10, "of": 11}
    lines: list[str] = []
    for field in fields:
        bit = bits[field]
        lines.extend([
            f"    mov {scratch_register}, DWORD PTR "
            f"[{stack_register} + {flags_offset}]",
            f"    shr {scratch_register}, {bit}",
            f"    and {scratch_register}, 1",
            f"    mov DWORD PTR [{output_register} + {_STATE_OFFSETS[field]}], "
            f"{scratch_register}",
        ])
    return lines


def _capture_fnsave_state(
    image_register: str,
    state_register: str,
    scratch_register: str,
    index_register: str,
) -> list[str]:
    """Unroll the reviewed FNSAVE-to-engine-state representation conversion."""

    register_parts = {
        "eax": ("ax", "al"),
        "ebx": ("bx", "bl"),
        "ecx": ("cx", "cl"),
        "edx": ("dx", "dl"),
    }
    try:
        scratch_word, scratch_byte = register_parts[scratch_register]
    except KeyError as exc:
        raise ValueError(
            f"unsupported FNSAVE conversion scratch register {scratch_register}"
        ) from exc
    if len({
        image_register, state_register, scratch_register, index_register
    }) != 4:
        raise ValueError("FNSAVE conversion registers must be distinct")
    if index_register != "ecx":
        raise ValueError("FNSAVE conversion index register must be ecx")

    lines = [
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 0]",
        f"    mov WORD PTR [{state_register} + {_STATE_OFFSETS['x87_control']}], "
        f"{scratch_word}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 4]",
        f"    mov WORD PTR [{state_register} + {_STATE_OFFSETS['x87_status']}], "
        f"{scratch_word}",
        f"    shr {scratch_register}, 7",
        f"    and {scratch_register}, 1",
        f"    mov BYTE PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_pending_exception']}], {scratch_byte}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 16]",
        f"    shr {scratch_register}, 16",
        f"    and {scratch_register}, 0x7ff",
        f"    mov WORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_last_opcode']}], {scratch_word}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 12]",
        f"    mov DWORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_instruction_pointer']}], {scratch_register}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 16]",
        f"    mov WORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_code_selector']}], {scratch_word}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 20]",
        f"    mov DWORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_data_pointer']}], {scratch_register}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 24]",
        f"    mov WORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_data_selector']}], {scratch_word}",
    ]
    for index in range(8):
        state_value = _STATE_OFFSETS["x87_stack"] + _X87_VALUE_SIZE * index
        lines.extend([
            f"    mov {index_register}, DWORD PTR [{image_register} + 4]",
            f"    shr {index_register}, 11",
            f"    and {index_register}, 7",
            f"    add {index_register}, {index}",
            f"    and {index_register}, 7",
            f"    imul {index_register}, {index_register}, 10",
            f"    mov {scratch_register}, DWORD PTR "
            f"[{image_register} + {index_register} + 28]",
            f"    mov DWORD PTR [{state_register} + {state_value}], "
            f"{scratch_register}",
            f"    mov {scratch_register}, DWORD PTR "
            f"[{image_register} + {index_register} + 32]",
            f"    mov DWORD PTR [{state_register} + {state_value + 4}], "
            f"{scratch_register}",
            f"    movzx {scratch_register}, WORD PTR "
            f"[{image_register} + {index_register} + 36]",
            f"    mov WORD PTR [{state_register} + {state_value + 8}], "
            f"{scratch_word}",
            f"    mov {index_register}, DWORD PTR [{image_register} + 4]",
            f"    shr {index_register}, 11",
            f"    and {index_register}, 7",
            f"    add {index_register}, {index}",
            f"    and {index_register}, 7",
            f"    shl {index_register}, 1",
            f"    mov {scratch_register}, DWORD PTR [{image_register} + 8]",
            f"    shr {scratch_register}, cl",
            f"    and {scratch_register}, 3",
            f"    mov BYTE PTR [{state_register} + "
            f"{state_value + _X87_VALUE_TAG_OFFSET}], {scratch_byte}",
            f"    cmp {scratch_register}, 3",
            f"    sete {scratch_byte}",
            f"    movzx {scratch_register}, {scratch_byte}",
            f"    mov DWORD PTR [{state_register} + "
            f"{state_value + _X87_VALUE_EMPTY_OFFSET}], {scratch_register}",
        ])
    return lines


def _instruction_inventory(
    transfer_id: str, instructions: list[Any]
) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for index, instruction in enumerate(instructions):
        if not isinstance(instruction, dict):
            raise StageAInputError(f"{transfer_id} instruction {index} must be an object")
        rva = _required_u32(instruction.get("rva"), f"{transfer_id} instruction RVA")
        if rva in result:
            raise StageAInputError(f"{transfer_id} has duplicate instruction RVA {rva:#x}")
        result[rva] = instruction
    return result


def _read_jsonl_objects(path: Path, label: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StageAInputError(f"cannot read {label}: {path}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(f"invalid {label} line {line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise StageAInputError(f"{label} line {line_number} must be an object")
        result.append(row)
    if not result:
        raise StageAInputError(f"{label} is empty")
    return result


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{field} must be a non-empty string")
    return value


def _required_sha256(value: Any, field: str) -> str:
    text = _required_string(value, field)
    if _SHA256.fullmatch(text) is None:
        raise StageAInputError(f"{field} must be a lowercase SHA-256")
    return text


def _required_u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageAInputError(f"{field} must be a 32-bit unsigned integer")
    return value


def _blocker(category: str, **fields: Any) -> dict[str, Any]:
    return {"category": category, "severity": "hard", **fields}


__all__ = [
    "NATIVE_ENGINE_PACKAGE_FORMAT",
    "NATIVE_ENGINE_PLAN_FORMAT",
    "PE32_BASE_RELOCATION_EVIDENCE_FORMAT",
    "NativeEnginePlan",
    "NativeCallbackTarget",
    "NativeExternalSite",
    "NativeTerminationImport",
    "NativeX87Replay",
    "plan_stage_b_native_engine",
    "write_stage_b_native_engine_package",
]
