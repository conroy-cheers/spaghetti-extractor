"""Interpreter program validation for native runtime planning."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from ..artifacts.formats import STAGE_B_INTERPRETER_PROGRAM_FORMAT
from ..util import sha256_bytes
from .interpreter_model import (
    STAGE_B_INTERPRETER_DEFINEDNESS_USE_FIELDS,
)
from .runtime_model import (
    DEFINEDNESS_USE_FORMAT,
    NativeUndefinedPolicy,
    StageBNativeRuntimeError,
    _InterpreterTransferBinding,
    _MACHINE_IR_INPUT_MODE,
)
from .runtime_values import (
    _required_count,
    _required_list,
    _required_object,
    _required_sha256,
    _required_string,
    _required_u32,
)


def _validate_program_manifest(
    payload: dict[str, Any], state_machine_sha256: str
) -> tuple[
    tuple[int, ...],
    tuple[_InterpreterTransferBinding, ...],
    tuple[NativeUndefinedPolicy, ...],
    str | None,
]:
    if payload.get("format") != STAGE_B_INTERPRETER_PROGRAM_FORMAT:
        raise StageBNativeRuntimeError("interpreter program has an unsupported format")
    if payload.get("state_machine_sha256") != state_machine_sha256:
        raise StageBNativeRuntimeError(
            "interpreter package and program bind different state machines"
        )
    if payload.get("status") != "ready" or payload.get("blockers") != []:
        raise StageBNativeRuntimeError("interpreter program is not runnable")
    _validate_complete_semantic_coverage(payload, label="interpreter program")
    transfers = _required_list(payload.get("transfers"), "interpreter transfers")
    rvas: list[int] = []
    bindings: list[_InterpreterTransferBinding] = []
    for index, raw in enumerate(transfers):
        transfer = _required_object(raw, f"interpreter transfer {index}")
        unit_id = _required_string(
            transfer.get("id"), f"interpreter transfer {index} id"
        )
        _required_sha256(
            transfer.get("contract_sha256"),
            f"interpreter transfer {index} contract SHA-256",
        )
        source_digest = transfer.get("source_span_sha256")
        if source_digest is None:
            source_digest = transfer.get("instruction_bytes_sha256")
        _required_sha256(
            source_digest,
            f"interpreter transfer {index} source-span SHA-256",
        )
        rva = _required_u32(
            transfer.get("rva_start"), f"interpreter transfer {index} RVA"
        )
        rvas.append(rva)
        bindings.append(_InterpreterTransferBinding(unit_id=unit_id, rva=rva))
    if not rvas:
        raise StageBNativeRuntimeError("interpreter transfer table is empty")
    if (
        rvas != sorted(rvas)
        or len(set(rvas)) != len(rvas)
        or len({binding.unit_id for binding in bindings}) != len(bindings)
    ):
        raise StageBNativeRuntimeError(
            "interpreter transfer table must be strictly sorted and unique"
        )
    counts = _required_object(payload.get("counts"), "interpreter counts")
    if _required_count(counts.get("transfers"), "interpreter transfer count") != len(rvas):
        raise StageBNativeRuntimeError(
            "interpreter transfer count does not match its inventory"
        )
    if (
        _required_count(
            counts.get("input_transfers"), "interpreter input-transfer count"
        )
        != len(rvas)
        or _required_count(
            counts.get("blocked_transfers"), "interpreter blocked-transfer count"
        )
        != 0
    ):
        raise StageBNativeRuntimeError(
            "interpreter transfer scope does not match its inventory"
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
    return tuple(rvas), tuple(bindings), policies, metadata_sha256


def _validate_complete_semantic_coverage(
    payload: Mapping[str, Any],
    *,
    label: str,
) -> None:
    coverage = _required_object(payload.get("semantic_coverage"), f"{label} coverage")
    if (
        coverage.get("status") != "complete"
        or coverage.get("acceptance_authority") is not False
        or payload.get("execution_policy") != "complete_transfer_inventory_v1"
    ):
        raise StageBNativeRuntimeError(
            f"{label} does not require complete semantic coverage"
        )


def _semantic_input_binding(
    payload: dict[str, Any], label: str
) -> tuple[str, dict[str, Any]]:
    mode = payload.get("input_mode")
    state_machine = payload.get("state_machine")
    machine_ir = payload.get("machine_ir")
    if (
        mode != _MACHINE_IR_INPUT_MODE
        or state_machine is not None
        or machine_ir is None
    ):
        raise StageBNativeRuntimeError(
            f"{label} must bind strict machine IR"
        )
    return str(mode), _required_object(machine_ir, f"{label} machine_ir")


def _validate_typed_x87_operations(rows: list[Any]) -> None:
    rvas: list[int] = []
    for index, raw in enumerate(rows):
        row = _required_object(raw, f"typed x87 operation {index}")
        if _contains_key(row, "instruction_bytes"):
            raise StageBNativeRuntimeError(
                "typed x87 operation contains a forbidden instruction payload"
            )
        if row.get("format") != "stage-b-typed-native-x87-operation-v1":
            raise StageBNativeRuntimeError("typed x87 operation has an unsupported format")
        start = _required_u32(row.get("rva_start"), f"typed x87 operation {index} RVA")
        end = _required_u32(row.get("rva_end"), f"typed x87 operation {index} end RVA")
        if end <= start:
            raise StageBNativeRuntimeError("typed x87 operation has an empty source span")
        operation = _required_object(
            row.get("operation"), f"typed x87 operation {index} descriptor"
        )
        if operation.get("format") != "stage-b-typed-native-x87-operation-v1":
            raise StageBNativeRuntimeError("typed x87 descriptor has an unsupported format")
        identity = _required_sha256(
            operation.get("identity"), f"typed x87 operation {index} identity"
        )
        source_size = _required_count(
            operation.get("source_size"), f"typed x87 operation {index} source size"
        )
        if source_size == 0 or source_size != end - start:
            raise StageBNativeRuntimeError("typed x87 operation source span is inconsistent")
        _required_string(operation.get("mnemonic"), "typed x87 mnemonic")
        _required_object(operation.get("operand"), "typed x87 operand")
        address_binding = _required_object(
            row.get("address_binding"), f"typed x87 operation {index} address binding"
        )
        binding_kind = address_binding.get("kind")
        if binding_kind == "fixed_image_base":
            if (
                _required_u32(
                    address_binding.get("image_base"), "fixed x87 image base"
                )
                != _required_u32(row.get("image_base"), "typed x87 image base")
            ):
                raise StageBNativeRuntimeError(
                    "fixed x87 address binding differs from its operation image base"
                )
            _required_u32(address_binding.get("target_rva"), "fixed x87 target RVA")
            if row.get("base_relocation") is not None:
                raise StageBNativeRuntimeError(
                    "fixed x87 address binding unexpectedly carries relocation evidence"
                )
        elif binding_kind == "pe32_highlow_relocation":
            _required_object(row.get("base_relocation"), "typed x87 base relocation")
            _required_u32(address_binding.get("target_rva"), "relocated x87 target RVA")
        elif binding_kind == "position_independent":
            if row.get("base_relocation") is not None:
                raise StageBNativeRuntimeError(
                    "position-independent x87 operation carries relocation evidence"
                )
        else:
            raise StageBNativeRuntimeError(
                "typed x87 operation has an unsupported address binding"
            )
        if not identity:
            raise StageBNativeRuntimeError("typed x87 operation identity is empty")
        rvas.append(start)
    if rvas != sorted(rvas) or len(set(rvas)) != len(rvas):
        raise StageBNativeRuntimeError(
            "typed x87 operation RVAs must be strictly sorted and unique"
        )


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


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
    if set(metadata) != STAGE_B_INTERPRETER_DEFINEDNESS_USE_FIELDS:
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
    evidence_slot_count = _required_count(
        metadata.get("evidence_slot_count"), "definedness evidence-slot count"
    )
    unused_evidence_slot_count = _required_count(
        metadata.get("unused_evidence_slot_count"),
        "definedness unused-evidence-slot count",
    )
    if evidence_slot_count != len(raw_slots) + unused_evidence_slot_count:
        raise StageBNativeRuntimeError(
            "definedness evidence-slot accounting is inconsistent"
        )
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
            common_choice_fields = {
                "format",
                "kind",
                "slot",
                "undefined_id",
                "profile",
                "instruction_rva",
                "location",
                "input_expression",
                "input_expression_sha256",
            }
            choice_format = choice_source.get("format")
            exact_bytes_fields = common_choice_fields | {"instruction_bytes"}
            typed_ir_fields = common_choice_fields | {
                "instruction_sha256",
                "instruction_model",
            }
            if (
                (choice_format == "stage-a-definedness-choice-source-v3"
                 and set(choice_source) != exact_bytes_fields)
                or (choice_format == "stage-a-definedness-choice-source-v4"
                    and set(choice_source) != typed_ir_fields)
                or choice_format not in {
                    "stage-a-definedness-choice-source-v3",
                    "stage-a-definedness-choice-source-v4",
                }
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
            if choice_format == "stage-a-definedness-choice-source-v3":
                instruction_bytes = choice_source.get("instruction_bytes")
                if (
                    not isinstance(instruction_bytes, str)
                    or re.fullmatch(r"[0-9a-f]+", instruction_bytes) is None
                    or len(instruction_bytes) % 2
                ):
                    raise StageBNativeRuntimeError(
                        "synchronized undefined slot has invalid BSR instruction bytes"
                    )
            elif (
                choice_source.get("instruction_model")
                != "sanitized_typed_machine_ir_v2"
            ):
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot has invalid typed instruction model"
                )
            else:
                _required_sha256(
                    choice_source.get("instruction_sha256"),
                    f"definedness slot {index} BSR instruction SHA-256",
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
            base_use_fields = {"transfer_id", "node_index", "op"}
            use_fields = frozenset(use)
            if use_fields not in {
                frozenset(base_use_fields),
                frozenset((*base_use_fields, "defined_value_node")),
            }:
                raise StageBNativeRuntimeError(
                    f"definedness slot {index} use {use_index} fields are invalid"
                )
            transfer_id = _required_string(
                use.get("transfer_id"), "definedness use transfer id"
            )
            node_index = _required_count(
                use.get("node_index"), "definedness use node index"
            )
            if choice_kind == "related_machine_input" and "defined_value_node" not in use:
                raise StageBNativeRuntimeError(
                    "synchronized definedness use omits its input-expression node"
                )
            if "defined_value_node" in use:
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
