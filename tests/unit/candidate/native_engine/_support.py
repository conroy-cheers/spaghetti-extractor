from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pefile

from spaghetti_extractor.external.contracts import (
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
)
from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    CanonicalExternalSiteRecordV3,
    CanonicalExternalSiteV3,
    CallbackRequirementV3,
    ExternalContractV3,
    external_site_id_v3,
)
from spaghetti_extractor.pe32.stage_binary import StageAInputError
from spaghetti_extractor.candidate.engine import (
    plan_stage_b_native_engine,
    write_stage_b_native_engine_package,
)
from spaghetti_extractor.util import sha256_bytes


def _transfer(*, event: dict | None = None) -> dict:
    instructions = []
    ordered = []
    if event is not None:
        instructions = [{
            "rva": event["instruction_rva"],
            "size": 6,
            "bytes": "ff159c214300",
            "mnemonic": "call",
            "op_str": "dword ptr [0x43219c]",
        }]
        ordered = [{"family": "external", **event}]
    return {
        "id": "semantic-transfer:entry",
        "original": {"rva_start": 0x1420, "rva_end": 0x1430},
        "instructions": instructions,
        "ordered_events": ordered,
        "fpu_state": None,
    }


def _machine_ir_transfer(
    *,
    event: dict | None = None,
    rva: int = 0x142A,
    size: int = 6,
    mnemonic: str = "call",
    instruction_sha256: str | None = None,
) -> dict:
    instruction_digest = instruction_sha256 or sha256_bytes(b"typed-call")
    registers = {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    ordered: list[dict] = []
    if event is not None:
        ordered = [{
            "family": "external",
            "arguments": [],
            "register_inputs": registers,
            "flag_inputs": flags,
            "stack_inputs": [],
            **event,
        }]
    end = rva + size
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": f"semantic-transfer:typed-{rva:08x}",
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": end, "size": size},
            "contract_sha256": "a" * 64,
            "instruction_bytes_sha256": sha256_bytes(
                f"unit:{rva:08x}:{size}".encode("ascii")
            ),
            "semantic_export": None,
        },
        "instructions": [{
            "rva_start": rva,
            "rva_end": end,
            "size": size,
            "instruction_sha256": instruction_digest,
            "mnemonic": mnemonic,
            "operands": [],
            "registers_read": [],
            "registers_written": [],
            "groups": ["call"] if mnemonic == "call" else [],
        }],
        "x87_micro_ops": [],
        "control": {
            "kind": "return" if mnemonic == "ret" else "fallthrough",
            "direct_targets": [] if mnemonic == "ret" else [end],
            "has_indirect_target": False,
        },
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": ordered,
            "faults": [],
            "ordered_events": ordered,
            "edge_conditions": [],
            "outcome": {"kind": "fallthrough", "target_rva": end},
            "stack_delta": 0,
            "counts": {},
            "fpu_state": None,
            "instruction_effect_schedule": None,
        },
    }


def _implementation_manifest(
    machine_ir: Path,
    *,
    roots: list[str],
    reachable: list[str],
    potential: list[str] | None = None,
    unreachable: list[str] | None = None,
    resolutions: list[dict] | None = None,
    summaries: list[dict] | None = None,
) -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "artifacts": {
            "machine_ir": {
                "format": "stage-a-machine-ir-v2",
                "sha256": sha256_bytes(machine_ir.read_bytes()),
            },
        },
        "control": {
            "reachability": {
                "status": "complete" if not potential else "incomplete",
                "roots": roots,
                "reachable_units": reachable,
                "potential_units": potential or [],
                "confirmed_unreachable_units": unreachable or [],
                "frontiers": [],
            },
            "internal_call_preservation": {
                "fixed_point_complete": True,
                "summaries": summaries or [],
            },
            "external_interface_provenance": {
                "resolutions": resolutions or [],
                "callback_registrations": [],
            },
        },
    }


def _canonical_external_sites(
    root: Path,
    *,
    unit: dict,
    event_index: int,
    identity: dict,
    contract,
    callback_target_rvas: tuple[int, ...] = (),
    event: dict | None = None,
    unit_sha256: str | None = None,
) -> Path:
    event = (
        unit["semantics"]["external_events"][event_index]
        if event is None
        else event
    )
    target_sha256 = canonical_sha256_v3(identity)
    site_id = external_site_id_v3(
        unit["id"], event_index, 0, identity
    )
    callbacks = tuple(
        CallbackRequirementV3.create(
            site_id=site_id,
            ordinal=ordinal,
            target_unit_id=f"semantic-transfer:typed-{rva:08x}",
            target_rva=rva,
            abi_sha256=canonical_sha256_v3(contract.callback_adapter.abi),
            lifetime=str(contract.callback_adapter.lifetime),
        )
        for ordinal, rva in enumerate(callback_target_rvas)
    )
    machine_contract = {
        "abi_template": contract.abi_template,
        "result_register_relations": list(contract.result_register_relations),
        "memory_footprints": list(contract.memory_footprints),
        "out_pointer_relations": list(contract.out_pointer_relations),
        "out_interface_relations": list(contract.out_interface_relations),
    }
    if contract.callback_adapter is not None:
        machine_contract.update({
            "callback_source": contract.callback_adapter.source,
            "callback_abi": contract.callback_adapter.abi,
            "callback_lifetime": contract.callback_adapter.lifetime,
            "callback_behavior": contract.callback_adapter.behavior,
            "callback_activation": contract.callback_adapter.activation,
            "resource_binding": contract.callback_adapter.resource_binding,
            "instance_binding": contract.callback_adapter.instance_binding,
        })
    authority_contract = ExternalContractV3.create(
        identity=identity,
        transfer_kind=contract.transfer_kind,
        disposition=(
            "tail_jump"
            if contract.disposition == "tail_jump"
            else (
                "noreturn"
                if contract.profile_disposition == "terminates"
                else "returns"
            )
        ),
        profile_id=str(contract.profile_binding["profile_id"]),
        profile_sha256=str(contract.profile_binding["profile_sha256"]),
        argument_words=contract.argument_words,
        arguments=list(contract.arguments),
        memory_effect=contract.memory_effect,
        world_effect=contract.world_effect,
        callback_effect=(
            "registers" if contract.callback_effect == "explicit" else "none"
        ),
        machine_contract=machine_contract,
        callbacks=callbacks,
    )
    site = CanonicalExternalSiteV3(
        site_id=site_id,
        unit_id=unit["id"],
        event_index=event_index,
        alternative_index=0,
        event_sha256=canonical_sha256_v3(event),
        target_sha256=target_sha256,
        identity=CanonicalValueV3.of(identity),
        status="complete",
        authorizing=True,
        contract=authority_contract,
        primary_blocker=None,
    )
    record = CanonicalExternalSiteRecordV3(
        record_id=unit["id"],
        unit_sha256=(canonical_sha256_v3(unit) if unit_sha256 is None else unit_sha256),
        status="complete",
        authorizing=True,
        sites=(site,),
        primary_blocker=None,
        dependencies=(),
    )
    output = root / "canonical-external-sites"
    ArtifactSetWriterV3(
        artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        bindings=(),
    ).write(
        output,
        [ArtifactRecordV3.create(
            unit["id"], CANONICAL_EXTERNAL_SITE_CODEC_V3.encode(record)
        )],
    )
    return output


def _machine_ir_x87_transfer(
    *, rva: int, mnemonic: str, encoded: bytes
) -> dict:
    unit = _machine_ir_transfer(
        rva=rva,
        size=len(encoded),
        mnemonic=mnemonic,
        instruction_sha256=sha256_bytes(encoded),
    )
    unit["instructions"][0].update({
        "operands": [{
            "kind": "register",
            "name": "st(1)",
            "width_bits": 80,
            "access": "read",
        }],
        "registers_read": ["st(0)", "st(1)"],
        "registers_written": ["eflags"],
        "groups": ["fpu"],
    })
    unit["source"]["instruction_bytes_sha256"] = sha256_bytes(encoded)
    transfer_digest = unit["source"]["instruction_bytes_sha256"]
    micro_id = f"{unit['id']}:x87:{rva:08x}"
    unit["x87_micro_ops"] = [{
        "format": "stage-a-x87-micro-op-v1",
        "id": micro_id,
        "unit_id": unit["id"],
        "rva_start": rva,
        "rva_end": rva + len(encoded),
        "size": len(encoded),
        "instruction_sha256": sha256_bytes(encoded),
        "transfer_instruction_sha256": transfer_digest,
        "mnemonic": mnemonic,
        "operands": unit["instructions"][0]["operands"],
        "implicit_registers_read": ["st(0)", "st(1)"],
        "implicit_registers_written": ["eflags"],
        "checked_decoder": "StageA.Formal.decodeInstructionExact",
        "checked_executor": "StageA.Formal.executeInstruction",
        "physical_state_effect": "defined_by_checked_typed_x87_executor",
    }]
    unit["semantics"]["fpu_state"] = {
        "typed_replay": {
            "source_format": "stage-a-native-exact-x87-command-replay-obligation-v1",
            "architecture": "x86",
            "bitness": 32,
            "image_base": 0x400000,
            "rva_start": rva,
            "rva_end": rva + len(encoded),
            "instruction_bytes_sha256": transfer_digest,
            "checked_decoder": "StageA.Formal.decodeInstructionExact",
            "checked_executor": "StageA.Formal.executeInstruction",
            "micro_op_ids": [micro_id],
        }
    }
    return unit


def _x87_replay_transfer() -> dict:
    encoded = bytes.fromhex("d9e8")
    digest = sha256_bytes(encoded)
    row = _transfer()
    row.update({
        "contract_sha256": "a" * 64,
        "instruction_bytes_sha256": digest,
        "original": {"rva_start": 0x1420, "rva_end": 0x1422, "size": 2},
        "instructions": [{
            "rva": 0x1420,
            "size": 2,
            "bytes": encoded.hex(),
            "mnemonic": "fld1",
            "op_str": "",
        }],
        "outcome": {"kind": "fallthrough", "target_rva": 0x1422},
        "fpu_state": {
            "model": "native_exact_x87_command_replay_obligation_v1",
            "status": "required",
            "authoritative_state_type": "StageA.X87.PhysicalState",
            "required_fields": [
                "stack", "tags", "control", "status", "pending_exception",
                "last_opcode", "instruction_pointer", "code_selector",
                "data_pointer", "data_selector",
            ],
            "missing_or_invalid_fields": [
                "tags", "pending_exception", "last_opcode",
                "instruction_pointer", "code_selector", "data_pointer",
                "data_selector",
            ],
            "logical_state_guidance": {},
            "replay": {
                "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
                "architecture": "x86",
                "bitness": 32,
                "image_base": 0x400000,
                "rva_start": 0x1420,
                "rva_end": 0x1422,
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{
                    "rva": 0x1420, "size": 2, "bytes": encoded.hex()
                }],
            },
        },
    })
    return row


def _absolute_x87_replay_transfer() -> dict:
    row = _x87_replay_transfer()
    encoded = bytes.fromhex("d90534124000")
    digest = sha256_bytes(encoded)
    row["static_program_export"] = {"static_program_contract_sha256": "c" * 64}
    row["instruction_bytes_sha256"] = digest
    row["original"] = {
        "rva_start": 0x1420,
        "rva_end": 0x1420 + len(encoded),
        "size": len(encoded),
    }
    row["instructions"] = [{
        "rva": 0x1420,
        "size": len(encoded),
        "bytes": encoded.hex(),
        "mnemonic": "fld",
        "op_str": "dword ptr [0x401234]",
    }]
    row["outcome"] = {
        "kind": "fallthrough",
        "target_rva": 0x1420 + len(encoded),
    }
    replay = row["fpu_state"]["replay"]
    replay.update({
        "rva_end": 0x1420 + len(encoded),
        "bytes": encoded.hex(),
        "bytes_sha256": digest,
        "instructions": [{
            "rva": 0x1420,
            "size": len(encoded),
            "bytes": encoded.hex(),
        }],
    })
    return row


def _relocation_evidence(
    relocations: list[dict] | None = None,
    *,
    static_program_contract_sha256: str = "c" * 64,
) -> dict:
    return {
        "format": "stage-b-pe32-base-relocation-evidence-v1",
        "complete": True,
        "pe_sha256": "d" * 64,
        "static_program_contract_sha256": static_program_contract_sha256,
        "image_base": 0x400000,
        "relocations": relocations if relocations is not None else [{
            "source_rva": 0x1422,
            "type": 3,
            "kind": "highlow",
            "width": 4,
            "preferred_value": 0x401234,
        }],
    }


_RUNTIME_HEADER = r"""#ifndef STAGE_B_STATE_MACHINE_RUNTIME_H
#define STAGE_B_STATE_MACHINE_RUNTIME_H
#include <stdint.h>
typedef struct stage_b_x87_value {
  uint8_t value_bytes[10];
  uint32_t empty;
  uint8_t tag;
} stage_b_x87_value;
typedef struct stage_b_machine_state {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t cf, zf, sf, of, pf, df;
  stage_b_x87_value x87_stack[8];
  uint16_t x87_control;
  uint16_t x87_status;
  uint8_t x87_pending_exception;
  uint16_t x87_last_opcode;
  uint32_t x87_instruction_pointer;
  uint16_t x87_code_selector;
  uint32_t x87_data_pointer;
  uint16_t x87_data_selector;
  uint32_t eflags;
  uint32_t fs_base;
  uint32_t original_rva;
} stage_b_machine_state;
typedef struct stage_b_stack_input {
  uint32_t offset, width, value;
} stage_b_stack_input;
typedef enum stage_b_call_event_kind {
  STAGE_B_CALL_EXTERNAL_IMPORT = 0,
  STAGE_B_CALL_INTERNAL_DIRECT = 1,
  STAGE_B_CALL_INDIRECT = 2
} stage_b_call_event_kind;
typedef struct stage_b_call_event {
  stage_b_call_event_kind kind;
  uint32_t instruction_rva, call_index, target_rva, return_rva;
  const char *dll, *symbol;
  uint32_t ordinal, has_ordinal;
  const uint32_t *arguments;
  uint32_t argument_count;
  const stage_b_stack_input *stack_inputs;
  uint32_t stack_input_count;
} stage_b_call_event;
#define STAGE_B_MAX_EXTERNAL_ARGUMENTS 256U
typedef struct stage_b_external_call_snapshot {
  uint32_t instruction_rva;
  uint32_t target_iat_rva;
  uint32_t argument_base_offset;
  uint32_t argument_count;
  uint32_t arguments[STAGE_B_MAX_EXTERNAL_ARGUMENTS];
} stage_b_external_call_snapshot;
typedef struct stage_b_runtime stage_b_runtime;
typedef enum stage_b_call_status {
  STAGE_B_CALL_OK = 0,
  STAGE_B_CALL_UNIMPLEMENTED = 1,
  STAGE_B_CALL_DIVIDE_ERROR = 2,
  STAGE_B_CALL_MEMORY_FAULT = 3,
  STAGE_B_CALL_EXTERNAL_FAULT = 4
} stage_b_call_status;
typedef stage_b_call_status (*stage_b_external_call_handler)(
    stage_b_runtime *, const stage_b_call_event *,
    const stage_b_machine_state *, stage_b_machine_state *);
typedef uint32_t (*stage_b_code_target_resolver)(
    stage_b_runtime *, uint32_t, uint32_t *);
typedef void (*stage_b_transfer_trace_handler)(
    void *, uint32_t, const stage_b_machine_state *);
struct stage_b_runtime {
  void *context;
  uint32_t (*read)(void *, uint32_t, uint32_t, uint32_t *);
  void (*write)(void *, uint32_t, uint32_t, uint32_t, uint32_t *);
  uint32_t (*undefined_value)(
      void *, uint32_t, const stage_b_machine_state *, uint32_t);
  stage_b_external_call_handler external_call_fallback;
  stage_b_transfer_trace_handler trace_transfer;
  stage_b_code_target_resolver resolve_code_target;
  void *replay_checked_x87_command;
};
#endif
"""


def _x87_runtime_header() -> str:
    header = _RUNTIME_HEADER.replace(
        "typedef struct stage_b_runtime stage_b_runtime;",
        """typedef struct stage_b_typed_x87_operation {
  uint32_t image_base, rva_start, rva_end, source_size;
  const char *operation_identity;
  const char *contract_sha256;
  const char *checked_decoder;
  const char *checked_executor;
} stage_b_typed_x87_operation;
typedef struct stage_b_runtime stage_b_runtime;""",
    )
    header = header.replace(
        "typedef uint32_t (*stage_b_code_target_resolver)(",
        """typedef stage_b_call_status (*stage_b_typed_x87_handler)(
    stage_b_runtime *, const stage_b_typed_x87_operation *,
    const stage_b_machine_state *, stage_b_machine_state *);
typedef uint32_t (*stage_b_code_target_resolver)(""",
    )
    return header.replace(
        "  void *replay_checked_x87_command;",
        "  stage_b_typed_x87_handler execute_typed_x87_operation;",
    )


class NativeEngineTestCase(unittest.TestCase):
    def _write(self, root: Path, rows: list[dict]) -> Path:
        path = root / "state-machine.jsonl"
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        return path

    def _strict_inputs(
        self,
        root: Path,
        units: list[dict],
        *,
        roots: list[str] | None = None,
        reachable: list[str] | None = None,
        potential: list[str] | None = None,
    ) -> tuple[Path, Path, Path]:
        machine_ir = root / "machine-ir.jsonl"
        machine_ir.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in units),
            encoding="utf-8",
        )
        unit_ids = [str(row["id"]) for row in units]
        manifest = root / "machine-ir-manifest.json"
        manifest.write_text(
            json.dumps(
                _implementation_manifest(
                    machine_ir,
                    roots=unit_ids[:1] if roots is None else roots,
                    reachable=unit_ids if reachable is None else reachable,
                    potential=potential,
                ),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        sites = root / "canonical-external-sites"
        ArtifactSetWriterV3(
            artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
            bindings=(),
        ).write(sites, [])
        return machine_ir, manifest, sites


__all__ = tuple(name for name in globals() if not name.startswith("__"))
