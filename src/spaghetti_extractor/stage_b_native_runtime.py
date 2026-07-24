"""Generate the fail-closed native runtime for the Stage B interpreter.

The emitted sources are candidate-generation inputs only.  They bind the
semantic interpreter and native engine packages by hash, but they do not add
acceptance authority to the resulting native candidate.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import StageAInputError
from .stage_b_interpreter_backend import (
    STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT,
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PROGRAM_FORMAT,
)
from .stage_b_native_engine import (
    NATIVE_ENGINE_PACKAGE_FORMAT,
    NATIVE_ENGINE_PLAN_FORMAT,
)
from .util import sha256_bytes, sha256_file, write_json


NATIVE_RUNTIME_PACKAGE_FORMAT = "stage-b-native-runtime-package-v1"
NATIVE_RUNTIME_HEADER_FILENAME = "native-runtime.h"
NATIVE_RUNTIME_SOURCE_FILENAME = "native-runtime.c"
NATIVE_RUNTIME_MANIFEST_FILENAME = "native-runtime-package.json"
DEFINEDNESS_USE_FORMAT = STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT

_INTERPRETER_MANIFEST_FILENAME = "state-machine-interpreter-package.json"
_NATIVE_ENGINE_MANIFEST_FILENAME = "native-engine-package.json"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class StageBNativeRuntimeError(StageAInputError):
    """A native-runtime package input failed closed validation."""


@dataclass(frozen=True)
class NativeUndefinedPolicy:
    slot: int
    undefined_id: str
    classification: str
    witness_policy: str | None
    choice_kind: str
    input_location: str | None
    obligation_count: int
    use_count: int

    @property
    def faults(self) -> bool:
        return self.choice_kind == "unsupported"

    @property
    def policy_code(self) -> int:
        return {
            "noninterfering_zero": 0,
            "related_machine_input": 1,
            "unsupported": 2,
        }[self.choice_kind]

    @property
    def input_location_code(self) -> int:
        if self.input_location is None:
            return 0
        return {
            "eax": 0,
            "ebx": 1,
            "ecx": 2,
            "edx": 3,
            "esi": 4,
            "edi": 5,
            "ebp": 6,
            "esp": 7,
        }[self.input_location]

    def payload(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "undefined_id": self.undefined_id,
            "classification": self.classification,
            "witness_policy": self.witness_policy,
            "choice_kind": self.choice_kind,
            "input_location": self.input_location,
            "obligation_count": self.obligation_count,
            "use_count": self.use_count,
        }


@dataclass(frozen=True)
class NativeRuntimePlan:
    """Checked immutable inputs used to render one native runtime."""

    entry_rva: int
    transfer_rvas: tuple[int, ...]
    callback_abis: tuple[tuple[int, int], ...]
    undefined_policies: tuple[NativeUndefinedPolicy, ...]
    definedness_metadata_sha256: str | None
    state_machine_sha256: str
    interpreter_manifest_path: Path
    interpreter_manifest_sha256: str
    interpreter_program_path: Path
    interpreter_program_sha256: str
    native_engine_manifest_path: Path
    native_engine_manifest_sha256: str
    native_engine_plan_path: Path
    native_engine_plan_sha256: str
    has_x87_replay_handler: bool
    has_modeled_termination: bool

    def payload(self) -> dict[str, Any]:
        return {
            "entry_rva": self.entry_rva,
            "transfer_rvas": list(self.transfer_rvas),
            "callback_abis": [
                {"rva": rva, "stack_cleanup_bytes": cleanup}
                for rva, cleanup in self.callback_abis
            ],
            "definedness_use": {
                "format": DEFINEDNESS_USE_FORMAT,
                "metadata_sha256": self.definedness_metadata_sha256,
                "candidate_witness_scope": (
                    "candidate-only; Stage A must separately prove the original/candidate "
                    "undefined-value relation"
                ),
                "slots": [policy.payload() for policy in self.undefined_policies],
            },
            "state_machine_sha256": self.state_machine_sha256,
            "interpreter_manifest": {
                "path": self.interpreter_manifest_path.name,
                "sha256": self.interpreter_manifest_sha256,
            },
            "interpreter_program": {
                "path": self.interpreter_program_path.name,
                "sha256": self.interpreter_program_sha256,
            },
            "native_engine_manifest": {
                "path": self.native_engine_manifest_path.name,
                "sha256": self.native_engine_manifest_sha256,
            },
            "native_engine_plan": {
                "path": self.native_engine_plan_path.name,
                "sha256": self.native_engine_plan_sha256,
            },
            "runtime_abi": {
                "checked_x87_replay_handler": self.has_x87_replay_handler,
                "modeled_environment_termination":
                    self.has_modeled_termination,
            },
        }


def plan_stage_b_native_runtime(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
) -> NativeRuntimePlan:
    """Validate and bind exact interpreter and native-engine packages."""

    interpreter_manifest_path = _manifest_path(
        interpreter_package,
        _INTERPRETER_MANIFEST_FILENAME,
        "interpreter package",
    )
    native_manifest_path = _manifest_path(
        native_engine_package,
        _NATIVE_ENGINE_MANIFEST_FILENAME,
        "native-engine package",
    )
    interpreter = _read_json_object(
        interpreter_manifest_path, "interpreter package manifest"
    )
    native = _read_json_object(native_manifest_path, "native-engine package manifest")

    if interpreter.get("format") != STAGE_B_INTERPRETER_PACKAGE_FORMAT:
        raise StageBNativeRuntimeError(
            "interpreter package has an unsupported format"
        )
    if interpreter.get("status") != "ready":
        raise StageBNativeRuntimeError("interpreter package is not ready")
    interpreter_state = _required_object(
        interpreter.get("state_machine"), "interpreter state_machine"
    )
    state_machine_sha256 = _required_sha256(
        interpreter_state.get("sha256"), "interpreter state-machine SHA-256"
    )
    interpreter_sources = _verify_artifact_inventory(
        interpreter_manifest_path.parent,
        interpreter.get("sources"),
        "interpreter source",
        require_role=True,
    )
    runtime_header_path = interpreter_sources.get("runtime_header")
    if runtime_header_path is None:
        raise StageBNativeRuntimeError(
            "interpreter source inventory has no runtime_header role"
        )
    try:
        runtime_header = runtime_header_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise StageBNativeRuntimeError(
            "cannot read the bound interpreter runtime header"
        ) from exc
    interpreter_has_x87_replay_abi = "replay_checked_x87_command" in runtime_header
    program_ref = _required_object(interpreter.get("program"), "interpreter program")
    program_path = _bound_artifact(
        interpreter_manifest_path.parent, program_ref, "interpreter program"
    )
    program = _read_json_object(program_path, "interpreter program manifest")
    transfer_rvas, undefined_policies, definedness_metadata_sha256 = (
        _validate_program_manifest(program, state_machine_sha256)
    )

    if native.get("format") != NATIVE_ENGINE_PACKAGE_FORMAT:
        raise StageBNativeRuntimeError(
            "native-engine package has an unsupported format"
        )
    if native.get("status") != "ready":
        raise StageBNativeRuntimeError("native-engine package is not ready")
    _verify_artifact_inventory(
        native_manifest_path.parent,
        native.get("sources"),
        "native-engine source",
        require_role=False,
    )
    plan_ref = _required_object(native.get("plan"), "native-engine plan")
    native_plan_path = _bound_artifact(
        native_manifest_path.parent, plan_ref, "native-engine plan"
    )
    native_plan = _read_json_object(native_plan_path, "native-engine plan")
    native_x87_replays = _required_list(
        native_plan.get("x87_replays"), "native-engine x87 replay sites"
    )
    has_x87_replay_handler = bool(native_x87_replays)
    if has_x87_replay_handler and not interpreter_has_x87_replay_abi:
        raise StageBNativeRuntimeError(
            "native-engine x87 replay sites require the interpreter replay ABI"
        )
    entry_rva, callback_abis = _validate_native_plan(
        native_plan,
        state_machine_sha256=state_machine_sha256,
        transfer_rvas=transfer_rvas,
    )
    has_modeled_termination = _validate_native_termination(
        native_plan.get("termination_import")
    )

    return NativeRuntimePlan(
        entry_rva=entry_rva,
        transfer_rvas=transfer_rvas,
        callback_abis=callback_abis,
        undefined_policies=undefined_policies,
        definedness_metadata_sha256=definedness_metadata_sha256,
        state_machine_sha256=state_machine_sha256,
        interpreter_manifest_path=interpreter_manifest_path,
        interpreter_manifest_sha256=sha256_file(interpreter_manifest_path),
        interpreter_program_path=program_path,
        interpreter_program_sha256=sha256_file(program_path),
        native_engine_manifest_path=native_manifest_path,
        native_engine_manifest_sha256=sha256_file(native_manifest_path),
        native_engine_plan_path=native_plan_path,
        native_engine_plan_sha256=sha256_file(native_plan_path),
        has_x87_replay_handler=has_x87_replay_handler,
        has_modeled_termination=has_modeled_termination,
    )


def write_stage_b_native_runtime_package(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    out: Path | str,
) -> dict[str, Any]:
    """Write deterministic freestanding runtime sources and their manifest."""

    plan = plan_stage_b_native_runtime(
        interpreter_package=interpreter_package,
        native_engine_package=native_engine_package,
    )
    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    header_path = out_path / NATIVE_RUNTIME_HEADER_FILENAME
    source_path = out_path / NATIVE_RUNTIME_SOURCE_FILENAME
    header_path.write_text(_native_runtime_header(), encoding="ascii")
    source_path.write_text(_native_runtime_source(plan), encoding="ascii")

    result = {
        "format": NATIVE_RUNTIME_PACKAGE_FORMAT,
        "status": "ready",
        "acceptance_authority": False,
        "inputs": plan.payload(),
        "sources": [
            {
                "role": "native_runtime_header",
                "path": header_path.name,
                "sha256": sha256_file(header_path),
            },
            {
                "role": "native_runtime_source",
                "path": source_path.name,
                "sha256": sha256_file(source_path),
            },
        ],
        "counts": {"transfers": len(plan.transfer_rvas)},
        "policy": {
            "architecture": "i686-pe32",
            "freestanding": True,
            "flat_memory": "exact-little-endian-widths-1-2-4",
            "undefined_values": (
                "hash-bound-zero-only-after-semantic-noninterference; "
                "synchronized-slots-use-a-checked-instruction-local-input-expression; "
                "unknown-or-unsupported-slots-latch-unimplemented"
            ),
            "code_targets": "absolute-image-va-in-checked-transfer-table-only",
            "threads": "fail-closed-on-concurrent-entry",
            "executable_writes": (
                "only-checked-nonexecuting-image-sections-or-captured-stack"
            ),
            "terminal_control": (
                "record-status-and-modeled-environment-termination"
                if plan.has_modeled_termination
                else "record-status-and-unsupported-native-halt"
            ),
        },
        "authority": (
            "candidate generation only; final acceptance requires the Stage A "
            "whole-program proof"
        ),
    }
    write_json(out_path / NATIVE_RUNTIME_MANIFEST_FILENAME, result)
    return result


def _validate_program_manifest(
    payload: dict[str, Any], state_machine_sha256: str
) -> tuple[tuple[int, ...], tuple[NativeUndefinedPolicy, ...], str | None]:
    if payload.get("format") != STAGE_B_INTERPRETER_PROGRAM_FORMAT:
        raise StageBNativeRuntimeError("interpreter program has an unsupported format")
    if payload.get("state_machine_sha256") != state_machine_sha256:
        raise StageBNativeRuntimeError(
            "interpreter package and program bind different state machines"
        )
    transfers = _required_list(payload.get("transfers"), "interpreter transfers")
    rvas: list[int] = []
    for index, raw in enumerate(transfers):
        transfer = _required_object(raw, f"interpreter transfer {index}")
        _required_string(transfer.get("id"), f"interpreter transfer {index} id")
        _required_sha256(
            transfer.get("contract_sha256"),
            f"interpreter transfer {index} contract SHA-256",
        )
        _required_sha256(
            transfer.get("instruction_bytes_sha256"),
            f"interpreter transfer {index} instruction SHA-256",
        )
        rvas.append(
            _required_u32(
                transfer.get("rva_start"), f"interpreter transfer {index} RVA"
            )
        )
    if not rvas:
        raise StageBNativeRuntimeError("interpreter transfer table is empty")
    if rvas != sorted(rvas) or len(set(rvas)) != len(rvas):
        raise StageBNativeRuntimeError(
            "interpreter transfer table must be strictly sorted and unique"
        )
    counts = _required_object(payload.get("counts"), "interpreter counts")
    if _required_count(counts.get("transfers"), "interpreter transfer count") != len(rvas):
        raise StageBNativeRuntimeError(
            "interpreter transfer count does not match its inventory"
        )
    capability = _required_object(payload.get("capability"), "interpreter capability")
    word_ops = _required_list(capability.get("word_ops"), "interpreter word ops")
    has_undefined = any(op in {"undefined_bv", "undefined_flag"} for op in word_ops)
    policies, metadata_sha256 = _validate_definedness_use(
        payload,
        state_machine_sha256=state_machine_sha256,
        transfer_rows=transfers,
        transfer_ids={
            _required_string(
                _required_object(raw, f"interpreter transfer {index}").get("id"),
                f"interpreter transfer {index} id",
            )
            for index, raw in enumerate(transfers)
        },
        required=has_undefined,
    )
    return tuple(rvas), policies, metadata_sha256


def _validate_definedness_use(
    payload: dict[str, Any],
    *,
    state_machine_sha256: str,
    transfer_rows: list[Any],
    transfer_ids: set[str],
    required: bool,
) -> tuple[tuple[NativeUndefinedPolicy, ...], str | None]:
    raw_metadata = payload.get("definedness_use")
    if raw_metadata is None:
        if required:
            raise StageBNativeRuntimeError(
                "interpreter program uses undefined_bv/undefined_flag but has no "
                f"complete {DEFINEDNESS_USE_FORMAT} metadata"
            )
        return (), None
    metadata = _required_object(raw_metadata, "interpreter definedness_use")
    expected_fields = {
        "format",
        "status",
        "proof_authority",
        "state_machine_sha256",
        "definedness_evidence_sha256",
        "transfer_inventory_sha256",
        "undefined_node_count",
        "slots",
        "metadata_sha256",
    }
    if set(metadata) != expected_fields:
        raise StageBNativeRuntimeError(
            "interpreter definedness_use fields do not match the v1 schema"
        )
    if (
        metadata.get("format") != DEFINEDNESS_USE_FORMAT
        or metadata.get("status") != "complete"
        or metadata.get("proof_authority") is not False
        or metadata.get("state_machine_sha256") != state_machine_sha256
    ):
        raise StageBNativeRuntimeError(
            "interpreter definedness_use metadata is not complete and hash-bound"
        )
    _required_sha256(
        metadata.get("definedness_evidence_sha256"),
        "definedness evidence SHA-256",
    )
    transfer_digest = sha256_bytes(
        json.dumps(
            transfer_rows,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )
    if metadata.get("transfer_inventory_sha256") != transfer_digest:
        raise StageBNativeRuntimeError(
            "interpreter definedness_use transfer inventory SHA-256 mismatch"
        )
    metadata_digest = _required_sha256(
        metadata.get("metadata_sha256"), "definedness metadata SHA-256"
    )
    metadata_body = dict(metadata)
    del metadata_body["metadata_sha256"]
    actual_metadata_digest = sha256_bytes(
        json.dumps(
            metadata_body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )
    if metadata_digest != actual_metadata_digest:
        raise StageBNativeRuntimeError("definedness metadata SHA-256 mismatch")
    undefined_node_count = _required_count(
        metadata.get("undefined_node_count"), "definedness undefined-node count"
    )
    counts = _required_object(payload.get("counts"), "interpreter counts")
    if "undefined_nodes" not in counts:
        raise StageBNativeRuntimeError(
            "interpreter counts omit undefined_nodes required for completeness"
        )
    if _required_count(counts.get("undefined_nodes"), "interpreter undefined-node count") != (
        undefined_node_count
    ):
        raise StageBNativeRuntimeError(
            "definedness metadata does not cover the interpreter undefined-node count"
        )
    raw_slots = _required_list(metadata.get("slots"), "definedness slots")
    policies: list[NativeUndefinedPolicy] = []
    seen_slots: set[int] = set()
    seen_uses: set[tuple[str, int]] = set()
    use_count = 0
    for index, raw in enumerate(raw_slots):
        slot_row = _required_object(raw, f"definedness slot {index}")
        if set(slot_row) != {
            "slot",
            "undefined_id",
            "classification",
            "witness_policy",
            "choice_source",
            "proof_obligations",
            "uses",
        }:
            raise StageBNativeRuntimeError(
                f"definedness slot {index} fields do not match the v1 schema"
            )
        slot = _required_u32(slot_row.get("slot"), f"definedness slot {index} id")
        if slot in seen_slots:
            raise StageBNativeRuntimeError("definedness metadata contains duplicate slots")
        seen_slots.add(slot)
        undefined_id = _required_string(
            slot_row.get("undefined_id"), f"definedness slot {index} undefined id"
        )
        classification = _required_string(
            slot_row.get("classification"), f"definedness slot {index} classification"
        )
        witness_policy = slot_row.get("witness_policy")
        raw_choice_source = slot_row.get("choice_source")
        obligations = _required_list(
            slot_row.get("proof_obligations"),
            f"definedness slot {index} proof obligations",
        )
        choice_kind = "unsupported"
        input_location: str | None = None
        if classification in {
            "unconstrained_noninterfering",
            "unconstrained_conditionally_noninterfering",
        }:
            choice_source = _required_object(
                raw_choice_source, f"definedness slot {index} choice source"
            )
            expected_choice_fields = {
                "format",
                "kind",
                "slot",
                "undefined_id",
                "requires_semantic_obligations",
            }
            if set(choice_source) != expected_choice_fields or (
                choice_source.get("format") != "stage-a-definedness-choice-source-v1"
                or choice_source.get("kind") != "noninterfering_zero"
                or choice_source.get("slot") != slot
                or choice_source.get("undefined_id") != undefined_id
                or choice_source.get("requires_semantic_obligations")
                is not bool(obligations)
            ):
                raise StageBNativeRuntimeError(
                    "noninterfering undefined slot has invalid zero-choice evidence"
                )
            if witness_policy != "zero":
                raise StageBNativeRuntimeError(
                    "noninterfering undefined slots require the checked zero witness policy"
                )
            if (
                classification == "unconstrained_noninterfering" and obligations
            ) or (
                classification == "unconstrained_conditionally_noninterfering"
                and not obligations
            ):
                raise StageBNativeRuntimeError(
                    "definedness conditional classification disagrees with obligations"
                )
            choice_kind = "noninterfering_zero"
        elif classification == "synchronized_behavior_relevant":
            choice_source = _required_object(
                raw_choice_source, f"definedness slot {index} choice source"
            )
            if set(choice_source) != {
                "format",
                "kind",
                "slot",
                "undefined_id",
                "profile",
                "instruction_rva",
                "instruction_bytes",
                "location",
                "input_expression",
                "input_expression_sha256",
            } or (
                choice_source.get("format") != "stage-a-definedness-choice-source-v3"
                or choice_source.get("kind") != "related_machine_input"
                or choice_source.get("slot") != slot
                or choice_source.get("undefined_id") != undefined_id
                or choice_source.get("profile")
                != "ia32-bsr-zero-preserves-destination-v1"
            ):
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot has invalid machine-input evidence"
                )
            _required_u32(
                choice_source.get("instruction_rva"),
                f"definedness slot {index} BSR instruction RVA",
            )
            instruction_bytes = choice_source.get("instruction_bytes")
            if (
                not isinstance(instruction_bytes, str)
                or re.fullmatch(r"[0-9a-f]+", instruction_bytes) is None
                or len(instruction_bytes) % 2
            ):
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot has invalid BSR instruction bytes"
                )
            input_expression = _required_object(
                choice_source.get("input_expression"),
                f"definedness slot {index} input expression",
            )
            expected_expression_sha256 = _required_sha256(
                choice_source.get("input_expression_sha256"),
                f"definedness slot {index} input expression SHA-256",
            )
            if sha256_bytes(
                json.dumps(
                    input_expression,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ) != expected_expression_sha256:
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot input expression digest differs"
                )
            location = _required_object(
                choice_source.get("location"),
                f"definedness slot {index} input location",
            )
            if set(location) != {"family", "name"} or location.get("family") != "register":
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot input location is not a register"
                )
            input_location = _required_string(
                location.get("name"),
                f"definedness slot {index} input register",
            )
            if input_location not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot input register is unsupported"
                )
            if witness_policy != "synchronized":
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot requires an input-derived witness policy"
                )
            choice_kind = "related_machine_input"
        elif classification == "unknown":
            if witness_policy is not None:
                raise StageBNativeRuntimeError(
                    "unknown slots cannot declare a candidate witness"
                )
            if raw_choice_source is not None or obligations:
                raise StageBNativeRuntimeError(
                    "unknown slots cannot declare choice or semantic evidence"
                )
        else:
            raise StageBNativeRuntimeError(
                f"definedness slot {index} has an unsupported classification"
            )
        uses = _required_list(slot_row.get("uses"), f"definedness slot {index} uses")
        if not uses:
            raise StageBNativeRuntimeError(f"definedness slot {index} has no uses")
        for use_index, raw_use in enumerate(uses):
            use = _required_object(
                raw_use, f"definedness slot {index} use {use_index}"
            )
            expected_use_fields = {"transfer_id", "node_index", "op"}
            if choice_kind == "related_machine_input":
                expected_use_fields.add("defined_value_node")
            if set(use) != expected_use_fields:
                raise StageBNativeRuntimeError(
                    f"definedness slot {index} use {use_index} fields are invalid"
                )
            transfer_id = _required_string(
                use.get("transfer_id"), "definedness use transfer id"
            )
            node_index = _required_count(
                use.get("node_index"), "definedness use node index"
            )
            if choice_kind == "related_machine_input":
                _required_count(
                    use.get("defined_value_node"),
                    "definedness use input-expression node index",
                )
            if transfer_id not in transfer_ids:
                raise StageBNativeRuntimeError(
                    "definedness use references an unknown interpreter transfer"
                )
            if use.get("op") not in {"undefined_bv", "undefined_flag"}:
                raise StageBNativeRuntimeError(
                    "definedness use must identify undefined_bv or undefined_flag"
                )
            if (transfer_id, node_index) in seen_uses:
                raise StageBNativeRuntimeError(
                    "definedness metadata contains a duplicate transfer/node use"
                )
            seen_uses.add((transfer_id, node_index))
            use_count += 1
        policies.append(
            NativeUndefinedPolicy(
                slot=slot,
                undefined_id=undefined_id,
                classification=classification,
                witness_policy=witness_policy,
                choice_kind=choice_kind,
                input_location=input_location,
                obligation_count=len(obligations),
                use_count=len(uses),
            )
        )
    if use_count != undefined_node_count or required != (undefined_node_count != 0):
        raise StageBNativeRuntimeError(
            "definedness metadata is incomplete for the interpreter undefined nodes"
        )
    return tuple(sorted(policies, key=lambda item: item.slot)), metadata_digest


def _validate_native_plan(
    payload: dict[str, Any],
    *,
    state_machine_sha256: str,
    transfer_rvas: tuple[int, ...],
) -> tuple[int, tuple[tuple[int, int], ...]]:
    if payload.get("format") != NATIVE_ENGINE_PLAN_FORMAT:
        raise StageBNativeRuntimeError("native-engine plan has an unsupported format")
    if payload.get("status") != "ready":
        raise StageBNativeRuntimeError("native-engine plan is not ready")
    if payload.get("state_machine_sha256") != state_machine_sha256:
        raise StageBNativeRuntimeError(
            "interpreter and native-engine packages bind different state machines"
        )
    if _required_list(payload.get("blockers"), "native-engine blockers"):
        raise StageBNativeRuntimeError("ready native-engine plan contains blockers")
    callback_targets = tuple(
        _required_u32(value, "native-engine callback RVA")
        for value in _required_list(
            payload.get("callback_targets"), "native-engine callbacks"
        )
    )
    if callback_targets != tuple(sorted(set(callback_targets))):
        raise StageBNativeRuntimeError(
            "native-engine callback RVAs must be sorted and unique"
        )
    if any(target not in transfer_rvas for target in callback_targets):
        raise StageBNativeRuntimeError(
            "native-engine callback lacks a checked interpreter transfer"
        )
    callback_abis = _required_list(
        payload.get("callback_abis"), "native-engine callback ABIs"
    )
    if len(callback_abis) != len(callback_targets):
        raise StageBNativeRuntimeError(
            "native-engine callback ABI inventory differs from callback targets"
        )
    for index, (raw, target) in enumerate(
        zip(callback_abis, callback_targets, strict=True)
    ):
        callback = _required_object(raw, f"native-engine callback ABI {index}")
        if _required_u32(callback.get("rva"), "callback ABI RVA") != target:
            raise StageBNativeRuntimeError(
                "native-engine callback ABI RVA differs from its target"
            )
        expected_symbol = f"stage_b_payload_callback_{target:08x}"
        if _required_string(callback.get("symbol"), "callback ABI symbol") != expected_symbol:
            raise StageBNativeRuntimeError(
                "native-engine callback ABI symbol is not the canonical RVA anchor"
            )
        _required_string(callback.get("transfer_id"), "callback ABI transfer id")
        _required_sha256(
            callback.get("transfer_sha256"), "callback ABI transfer SHA-256"
        )
        kind = _required_string(callback.get("kind"), "callback ABI kind")
        cleanup = _required_count(
            callback.get("stack_cleanup_bytes"), "callback ABI stack cleanup"
        )
        if kind == "tls_callback":
            if cleanup != 12:
                raise StageBNativeRuntimeError(
                    "PE32 TLS callback ABI must clean exactly 12 stack bytes"
                )
        elif kind != "generic_callback":
            raise StageBNativeRuntimeError(
                "native-engine callback ABI kind is unsupported"
            )
    entry_rva = _required_u32(payload.get("entry_rva"), "native-engine entry RVA")
    if entry_rva not in transfer_rvas:
        raise StageBNativeRuntimeError(
            "native-engine entry RVA is absent from the interpreter transfer table"
        )
    counts = _required_object(payload.get("counts"), "native-engine counts")
    if _required_count(counts.get("transfers"), "native-engine transfer count") != len(
        transfer_rvas
    ):
        raise StageBNativeRuntimeError(
            "native-engine and interpreter transfer counts differ"
        )
    return entry_rva, tuple(
        (
            _required_u32(
                _required_object(raw, f"native-engine callback ABI {index}").get("rva"),
                "callback ABI RVA",
            ),
            _required_count(
                _required_object(raw, f"native-engine callback ABI {index}").get(
                    "stack_cleanup_bytes"
                ),
                "callback ABI stack cleanup",
            ),
        )
        for index, raw in enumerate(callback_abis)
    )


def _validate_native_termination(value: Any) -> bool:
    if value is None:
        return False
    payload = _required_object(value, "native-engine termination import")
    _required_string(payload.get("dll"), "termination import DLL")
    symbol = payload.get("symbol")
    ordinal = payload.get("ordinal")
    if (symbol is None) == (ordinal is None):
        raise StageBNativeRuntimeError(
            "termination import must provide exactly one symbol or ordinal"
        )
    if symbol is not None:
        _required_string(symbol, "termination import symbol")
    else:
        _required_u32(ordinal, "termination import ordinal")
    _required_u32(payload.get("iat_va"), "termination import IAT VA")
    if (
        payload.get("transfer") != "tail_jump"
        or payload.get("argument_source") != "cdecl-stack-word-0-from-eax"
        or payload.get("required_disposition") != "terminates"
    ):
        raise StageBNativeRuntimeError(
            "native-engine termination import policy is unsupported"
        )
    return True


def _native_runtime_header() -> str:
    return r'''#ifndef STAGE_B_NATIVE_RUNTIME_H
#define STAGE_B_NATIVE_RUNTIME_H

#include "state-machine-interpreter.h"

typedef enum stage_b_native_terminal_kind {
  STAGE_B_NATIVE_TERMINAL_RETURNED = 0,
  STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED = 1,
  STAGE_B_NATIVE_TERMINAL_DIVIDE_ERROR = 2,
  STAGE_B_NATIVE_TERMINAL_MEMORY_FAULT = 3,
  STAGE_B_NATIVE_TERMINAL_EXTERNAL_FAULT = 4,
  STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE = 5,
  STAGE_B_NATIVE_TERMINAL_INVALID_IMAGE = 6,
  STAGE_B_NATIVE_TERMINAL_CONCURRENT_ENTRY = 7
} stage_b_native_terminal_kind;

extern const char stage_b_native_interpreter_manifest_sha256[65];
extern const char stage_b_native_engine_manifest_sha256[65];
extern const char stage_b_native_state_machine_sha256[65];
extern volatile stage_b_native_terminal_kind stage_b_native_terminal_status;
extern volatile stage_b_call_status stage_b_native_terminal_call_status;
extern stage_b_machine_state stage_b_native_terminal_state;
extern stage_b_runtime stage_b_native_runtime_instance;
void stage_b_native_terminate(stage_b_native_terminal_kind status)
    __attribute__((noreturn));

stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output);
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output);
stage_b_call_status stage_b_native_runtime_run_captured(
    const stage_b_machine_state *captured, stage_b_machine_state *output);
void stage_b_native_runtime_coordinate(
    const stage_b_machine_state *captured) __attribute__((noreturn));

#endif
'''


def _native_runtime_source(plan: NativeRuntimePlan) -> str:
    transfer_rows = "\n".join(
        f"  0x{rva:08x}U," for rva in plan.transfer_rvas
    )
    callback_rows = "\n".join(
        f"  {{ 0x{rva:08x}U, {cleanup}U }},"
        for rva, cleanup in plan.callback_abis
    ) or "  { 0U, 0U },"
    undefined_rows = "\n".join(
        f"  {{ 0x{policy.slot:08x}U, {policy.policy_code}U, "
        f"{policy.input_location_code}U }},"
        for policy in plan.undefined_policies
    ) or "  { 0U, 2U, 0U },"
    x87_declaration = (
        r'''extern stage_b_call_status stage_b_native_replay_checked_x87_command(
    stage_b_runtime *runtime, const stage_b_x87_replay_program *program,
    const stage_b_machine_state *input, stage_b_machine_state *output);
'''
        if plan.has_x87_replay_handler
        else ""
    )
    x87_initializer = (
        ",\n  .replay_checked_x87_command = "
        "stage_b_native_replay_checked_x87_command"
        if plan.has_x87_replay_handler
        else ""
    )
    return f'''#include "native-runtime.h"

#include <stdint.h>

#define STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE 0x20000000U
#define STAGE_B_NATIVE_MAX_PE_SECTIONS 96U

extern const unsigned char __ImageBase[];
extern stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output);
{x87_declaration}

_Static_assert(sizeof(uintptr_t) == 4U, "native runtime requires i686 pointers");

const char stage_b_native_interpreter_manifest_sha256[65] =
    "{plan.interpreter_manifest_sha256}";
const char stage_b_native_engine_manifest_sha256[65] =
    "{plan.native_engine_manifest_sha256}";
const char stage_b_native_state_machine_sha256[65] =
    "{plan.state_machine_sha256}";

volatile stage_b_native_terminal_kind stage_b_native_terminal_status =
    STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
volatile stage_b_call_status stage_b_native_terminal_call_status =
    STAGE_B_CALL_UNIMPLEMENTED;
stage_b_machine_state stage_b_native_terminal_state;

static const uint32_t stage_b_native_transfer_rvas[] = {{
{transfer_rows}
}};
static const uint32_t stage_b_native_transfer_count = {len(plan.transfer_rvas)}U;

typedef struct stage_b_native_callback_abi {{
  uint32_t rva, stack_cleanup_bytes;
}} stage_b_native_callback_abi;
static const stage_b_native_callback_abi stage_b_native_callback_abis[] = {{
{callback_rows}
}};
static const uint32_t stage_b_native_callback_abi_count = {len(plan.callback_abis)}U;

typedef struct stage_b_native_undefined_policy {{
  uint32_t slot, policy, input_location;
}} stage_b_native_undefined_policy;
static const stage_b_native_undefined_policy stage_b_native_undefined_policies[] = {{
{undefined_rows}
}};
static const uint32_t stage_b_native_undefined_policy_count = {len(plan.undefined_policies)}U;

typedef struct stage_b_native_context {{
  uint32_t image_base;
  uint32_t image_size;
  uint32_t section_table;
  uint32_t section_count;
  uint32_t stack_low;
  uint32_t stack_high;
  volatile uint32_t active;
  uint32_t initialized;
  uint32_t owner_fs_base;
  uint32_t nested_depth;
  uint32_t undefined_fault;
  uint32_t last_undefined_fault;
}} stage_b_native_context;

static stage_b_native_context stage_b_native_context_value;

static uint16_t stage_b_native_u16(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}}

static uint32_t stage_b_native_u32(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}}

static uint32_t stage_b_native_range_end(
    uint32_t start, uint32_t width, uint32_t *end) {{
  if (width == 0U || start > 0xffffffffU - width) return 0U;
  *end = start + width;
  return 1U;
}}

static uint32_t stage_b_native_inside(
    uint32_t start, uint32_t end, uint32_t region_start, uint32_t region_size) {{
  uint32_t region_end;
  if (region_size == 0U ||
      !stage_b_native_range_end(region_start, region_size, &region_end))
    return 0U;
  return start >= region_start && end <= region_end;
}}

static uint32_t stage_b_native_validate_image(stage_b_native_context *context) {{
  uint32_t base = (uint32_t)(uintptr_t)&__ImageBase;
  uint32_t pe_offset, pe, optional, section_table, section_bytes, section_end;
  uint32_t image_size, headers_size;
  uint16_t section_count, optional_size;
  if (base == 0U || base > 0xffffffffU - 0x40U ||
      stage_b_native_u16(base) != 0x5a4dU)
    return 0U;
  pe_offset = stage_b_native_u32(base + 0x3cU);
  if (pe_offset < 0x40U || pe_offset > 0x00100000U ||
      base > 0xffffffffU - pe_offset ||
      base + pe_offset > 0xffffffffU - 24U)
    return 0U;
  pe = base + pe_offset;
  if (stage_b_native_u32(pe) != 0x00004550U) return 0U;
  section_count = stage_b_native_u16(pe + 6U);
  optional_size = stage_b_native_u16(pe + 20U);
  if (section_count == 0U || section_count > STAGE_B_NATIVE_MAX_PE_SECTIONS ||
      optional_size < 64U)
    return 0U;
  optional = pe + 24U;
  if (optional > 0xffffffffU - 64U) return 0U;
  if (stage_b_native_u16(optional) != 0x010bU) return 0U;
  image_size = stage_b_native_u32(optional + 56U);
  headers_size = stage_b_native_u32(optional + 60U);
  if (image_size == 0U || headers_size == 0U || headers_size > image_size ||
      base > 0xffffffffU - image_size)
    return 0U;
  if (optional > 0xffffffffU - optional_size) return 0U;
  section_table = optional + optional_size;
  section_bytes = (uint32_t)section_count * 40U;
  if (!stage_b_native_range_end(section_table, section_bytes, &section_end) ||
      section_end > base + headers_size)
    return 0U;
  context->image_base = base;
  context->image_size = image_size;
  context->section_table = section_table;
  context->section_count = section_count;
  return 1U;
}}

static uint32_t stage_b_native_validate_stack(
    stage_b_native_context *context, const stage_b_machine_state *captured) {{
  uint32_t teb = captured->fs_base;
  uint32_t stack_high, stack_low;
  if (teb == 0U || teb > 0xffffffffU - 12U) return 0U;
  stack_high = stage_b_native_u32(teb + 4U);
  stack_low = stage_b_native_u32(teb + 8U);
  if (stack_low >= stack_high || captured->esp < stack_low ||
      captured->esp > stack_high)
    return 0U;
  context->stack_low = stack_low;
  context->stack_high = stack_high;
  return 1U;
}}

static uint32_t stage_b_native_transfer_table_valid(void) {{
  uint32_t i;
  if (stage_b_native_transfer_count == 0U) return 0U;
  for (i = 0U; i < stage_b_native_transfer_count; ++i) {{
    uint32_t rva = stage_b_native_transfer_rvas[i];
    if ((i != 0U && stage_b_native_transfer_rvas[i - 1U] >= rva) ||
        rva >= stage_b_native_context_value.image_size ||
        stage_b_program_lookup(rva) == 0)
      return 0U;
  }}
  return stage_b_program_lookup(0x{plan.entry_rva:08x}U) != 0;
}}

static uint32_t stage_b_native_write_allowed(uint32_t address, uint32_t width) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t end, image_end, i, matched = 0U;
  if (!stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (end <= context->image_base || address >= image_end)
    return address >= context->stack_low && end <= context->stack_high;
  for (i = 0U; i < context->section_count; ++i) {{
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = stage_b_native_u32(section + 8U);
    uint32_t raw_size = stage_b_native_u32(section + 16U);
    uint32_t rva = stage_b_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (stage_b_native_inside(address, end, section_start, size)) {{
      if ((stage_b_native_u32(section + 36U) &
          STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE) != 0U)
        return 0U;
      matched = 1U;
    }}
  }}
  return matched;
}}

static uint32_t stage_b_native_flat_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  const volatile uint8_t *p;
  uint32_t end, value = 0U, i;
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  if (fault == 0) return 0U;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_range_end(address, width, &end))
    return 0U;
  (void)end;
  p = (const volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) value |= (uint32_t)p[i] << (i * 8U);
  *fault = 0U;
  return value;
}}

static void stage_b_native_flat_write(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {{
  volatile uint8_t *p;
  uint32_t i;
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  if (fault == 0) return;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_write_allowed(address, width))
    return;
  p = (volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) p[i] = (uint8_t)(value >> (i * 8U));
  *fault = 0U;
}}

static uint32_t stage_b_native_undefined_value(
    void *opaque, uint32_t slot, const stage_b_machine_state *input,
    uint32_t defined_value) {{
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  uint32_t low = 0U, high = stage_b_native_undefined_policy_count;
  (void)input;
  if (context == 0 || context->initialized == 0U) return 0U;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_undefined_policies[middle].slot < slot) low = middle + 1U;
    else high = middle;
  }}
  if (low == stage_b_native_undefined_policy_count ||
      stage_b_native_undefined_policies[low].slot != slot) {{
    context->undefined_fault = 1U;
    return 0U;
  }}
  if (stage_b_native_undefined_policies[low].policy == 0U) return 0U;
  if (stage_b_native_undefined_policies[low].policy == 1U)
    return defined_value;
  context->undefined_fault = 1U;
  return 0U;
}}

static uint32_t stage_b_native_resolve_code_target(
    stage_b_runtime *runtime, uint32_t target_word, uint32_t *target_rva) {{
  stage_b_native_context *context;
  uint32_t rva, low = 0U, high = stage_b_native_transfer_count;
  if (runtime == 0 || target_rva == 0 || runtime->context == 0) return 1U;
  context = (stage_b_native_context *)runtime->context;
  if (context->initialized == 0U || target_word < context->image_base)
    return 1U;
  rva = target_word - context->image_base;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  if (low == stage_b_native_transfer_count ||
      stage_b_native_transfer_rvas[low] != rva || stage_b_program_lookup(rva) == 0)
    return 1U;
  *target_rva = rva;
  return 0U;
}}

stage_b_runtime stage_b_native_runtime_instance = {{
  .context = &stage_b_native_context_value,
  .read = stage_b_native_flat_read,
  .write = stage_b_native_flat_write,
  .undefined_value = stage_b_native_undefined_value,
  .external_call_fallback = stage_b_dispatch_external_call,
  .resolve_code_target = stage_b_native_resolve_code_target{x87_initializer}
}};

static void stage_b_native_unpack_flags(stage_b_machine_state *state) {{
  uint32_t flags = state->eflags;
  state->cf = (flags >> 0) & 1U;
  state->pf = (flags >> 2) & 1U;
  state->zf = (flags >> 6) & 1U;
  state->sf = (flags >> 7) & 1U;
  state->df = (flags >> 10) & 1U;
  state->of = (flags >> 11) & 1U;
}}

static stage_b_native_terminal_kind stage_b_native_terminal_for(
    stage_b_call_status status, uint32_t undefined_fault) {{
  if (undefined_fault != 0U)
    return STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE;
  if (status == STAGE_B_CALL_OK) return STAGE_B_NATIVE_TERMINAL_RETURNED;
  if (status == STAGE_B_CALL_DIVIDE_ERROR)
    return STAGE_B_NATIVE_TERMINAL_DIVIDE_ERROR;
  if (status == STAGE_B_CALL_MEMORY_FAULT)
    return STAGE_B_NATIVE_TERMINAL_MEMORY_FAULT;
  if (status == STAGE_B_CALL_EXTERNAL_FAULT)
    return STAGE_B_NATIVE_TERMINAL_EXTERNAL_FAULT;
  return STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
}}

static uint32_t stage_b_native_has_transfer(uint32_t rva) {{
  uint32_t low = 0U, high = stage_b_native_transfer_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  return low != stage_b_native_transfer_count &&
      stage_b_native_transfer_rvas[low] == rva && stage_b_program_lookup(rva) != 0;
}}

static uint32_t stage_b_native_callback_matches(
    uint32_t rva, uint32_t stack_cleanup_bytes) {{
  uint32_t i;
  for (i = 0U; i < stage_b_native_callback_abi_count; ++i)
    if (stage_b_native_callback_abis[i].rva == rva &&
        stage_b_native_callback_abis[i].stack_cleanup_bytes == stack_cleanup_bytes)
      return 1U;
  return 0U;
}}

static stage_b_call_status stage_b_native_run_initialized(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {{
  stage_b_call_status status;
  stage_b_native_context *context = &stage_b_native_context_value;
  if (input == 0 || output == 0 || context->initialized == 0U ||
      !stage_b_native_has_transfer(entry_rva))
    return STAGE_B_CALL_UNIMPLEMENTED;
  *output = *input;
  stage_b_native_unpack_flags(output);
  output->original_rva = entry_rva;
  status = stage_b_run_function(
      &stage_b_native_runtime_instance, entry_rva, output, output);
  if (context->undefined_fault != 0U) return STAGE_B_CALL_UNIMPLEMENTED;
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {{
  stage_b_call_status status = STAGE_B_CALL_UNIMPLEMENTED;
  stage_b_native_context *context = &stage_b_native_context_value;
  if (input == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;
  *output = *input;
  if (__sync_lock_test_and_set(&context->active, 1U) != 0U) {{
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  context->initialized = 0U;
  context->undefined_fault = 0U;
  context->last_undefined_fault = 0U;
  context->nested_depth = 0U;
  if (!stage_b_native_validate_image(context) ||
      !stage_b_native_validate_stack(context, input) ||
      !stage_b_native_transfer_table_valid() || !stage_b_native_has_transfer(entry_rva))
    goto release;
  context->owner_fs_base = input->fs_base;
  context->initialized = 1U;
  status = stage_b_native_run_initialized(entry_rva, input, output);
release:
  context->last_undefined_fault = context->undefined_fault;
  context->owner_fs_base = 0U;
  context->nested_depth = 0U;
  context->initialized = 0U;
  __sync_lock_release(&context->active);
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output) {{
  stage_b_call_status status;
  stage_b_native_context *context = &stage_b_native_context_value;
  if (input == 0 || output == 0 || context->active != 1U ||
      context->initialized == 0U || input->fs_base != context->owner_fs_base ||
      context->nested_depth == 0xffffffffU ||
      !stage_b_native_callback_matches(callback_rva, stack_cleanup_bytes))
    return STAGE_B_CALL_UNIMPLEMENTED;
  ++context->nested_depth;
  status = stage_b_native_run_initialized(callback_rva, input, output);
  --context->nested_depth;
  if (status == STAGE_B_CALL_OK &&
      output->esp != input->esp + 4U + stack_cleanup_bytes)
    return STAGE_B_CALL_UNIMPLEMENTED;
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_captured(
    const stage_b_machine_state *captured, stage_b_machine_state *output) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  stage_b_call_status status;
  stage_b_native_terminal_call_status = STAGE_B_CALL_UNIMPLEMENTED;
  stage_b_native_terminal_status = STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
  if (captured == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;
  status = stage_b_native_runtime_run_at_rva(
      0x{plan.entry_rva:08x}U, captured, output);
  stage_b_native_terminal_call_status = status;
  stage_b_native_terminal_status = stage_b_native_terminal_for(
      status, context->last_undefined_fault);
  stage_b_native_terminal_state = *output;
  return status;
}}

void stage_b_native_runtime_coordinate(
    const stage_b_machine_state *captured) {{
  stage_b_machine_state output;
  stage_b_call_status status =
      stage_b_native_runtime_run_captured(captured, &output);
  stage_b_native_terminal_call_status = status;
  if (captured != 0) stage_b_native_terminal_state = output;
  stage_b_native_terminate(stage_b_native_terminal_status);
}}
'''


def _manifest_path(
    value: Path | str, filename: str, label: str
) -> Path:
    path = Path(value)
    if path.is_dir():
        path = path / filename
    if not path.is_file():
        raise StageBNativeRuntimeError(f"{label} manifest does not exist: {path}")
    return path


def _bound_artifact(root: Path, value: dict[str, Any], label: str) -> Path:
    name = _required_relative_path(value.get("path"), f"{label} path")
    expected = _required_sha256(value.get("sha256"), f"{label} SHA-256")
    path = root / name
    if not path.is_file():
        raise StageBNativeRuntimeError(f"{label} does not exist: {path}")
    if sha256_file(path) != expected:
        raise StageBNativeRuntimeError(f"{label} SHA-256 mismatch")
    return path


def _verify_artifact_inventory(
    root: Path, value: Any, label: str, *, require_role: bool
) -> dict[str, Path]:
    rows = _required_list(value, f"{label} inventory")
    if not rows:
        raise StageBNativeRuntimeError(f"{label} inventory is empty")
    seen: set[str] = set()
    result: dict[str, Path] = {}
    for index, raw in enumerate(rows):
        row = _required_object(raw, f"{label} {index}")
        key: str
        if require_role:
            key = _required_string(row.get("role"), f"{label} {index} role")
            if key in result:
                raise StageBNativeRuntimeError(
                    f"{label} inventory has duplicate roles"
                )
        name = _required_relative_path(row.get("path"), f"{label} {index} path")
        if name in seen:
            raise StageBNativeRuntimeError(f"{label} inventory has duplicate paths")
        seen.add(name)
        path = _bound_artifact(root, row, f"{label} {index}")
        result[key if require_role else name] = path
    return result


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageBNativeRuntimeError(f"cannot read {label}: {path}") from exc
    return _required_object(value, label)


def _required_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageBNativeRuntimeError(f"{field} must be an object")
    return value


def _required_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageBNativeRuntimeError(f"{field} must be a list")
    return value


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageBNativeRuntimeError(f"{field} must be a non-empty string")
    return value


def _required_relative_path(value: Any, field: str) -> str:
    text = _required_string(value, field)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
        raise StageBNativeRuntimeError(f"{field} must be a local artifact name")
    return text


def _required_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageBNativeRuntimeError(f"{field} must be a lowercase SHA-256")
    return value


def _required_u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageBNativeRuntimeError(f"{field} must be a 32-bit unsigned integer")
    return value


def _required_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageBNativeRuntimeError(f"{field} must be a nonnegative integer")
    return value


__all__ = [
    "DEFINEDNESS_USE_FORMAT",
    "NATIVE_RUNTIME_HEADER_FILENAME",
    "NATIVE_RUNTIME_MANIFEST_FILENAME",
    "NATIVE_RUNTIME_PACKAGE_FORMAT",
    "NATIVE_RUNTIME_SOURCE_FILENAME",
    "NativeRuntimePlan",
    "NativeUndefinedPolicy",
    "StageBNativeRuntimeError",
    "plan_stage_b_native_runtime",
    "write_stage_b_native_runtime_package",
]
