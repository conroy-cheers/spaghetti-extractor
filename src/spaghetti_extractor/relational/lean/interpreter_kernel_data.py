"""Generate Lean-checked bindings for the compiled interpreter data table.

The linker map is only a locator.  Generated Lean re-parses the exact PE,
decodes every C record and pointer target, checks the relocation inventory,
and connects the resulting records to the semantic interpreter lookup.
"""

from __future__ import annotations

import json
import re
import shutil
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ...stage_b_interpreter_backend import (
    _ACTIONS,
    _WORD_OPS,
    _X87_OPS,
    compile_stage_b_interpreter_program,
)
from ...stage_binary import StageAInputError, _parse_stage_a_pe
from ...util import sha256_bytes, sha256_file, write_json
from .common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
)
from .interpreter_kernel import _load_symbols, _unique_symbol


INTERPRETER_KERNEL_DATA_FORMAT = "stage-a-interpreter-kernel-data-inventory-v9"
INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT = (
    "GeneratedInterpreterKernelDataLocalContext"
)
INTERPRETER_KERNEL_DATA_BASE = "GeneratedInterpreterKernelDataBase"
INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY = (
    "GeneratedInterpreterKernelCandidateAuthority"
)
INTERPRETER_KERNEL_DATA_AUTHORITY = "GeneratedInterpreterKernelDataAuthority"
INTERPRETER_KERNEL_DATA_AUTHORITY_PACK_PREFIX = (
    "GeneratedInterpreterKernelDataAuthorityPack"
)
INTERPRETER_KERNEL_DATA_NATIVE_PROJECTION_PACK_PREFIX = (
    "GeneratedInterpreterKernelDataNativeProjectionPack"
)
INTERPRETER_KERNEL_DATA_SHARD_FACADE_PREFIX = (
    "GeneratedInterpreterKernelDataShard"
)
INTERPRETER_KERNEL_DATA_BUNDLE = "GeneratedInterpreterKernelDataBundle"
INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_PACK_PREFIX = (
    "GeneratedInterpreterKernelSemanticRecordPack"
)
INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_BUNDLE = (
    "GeneratedInterpreterKernelSemanticRecordBundle"
)
INTERPRETER_KERNEL_DATA_ACTION_CURSOR_PACK_PREFIX = (
    "GeneratedInterpreterKernelActionCursorPack"
)
INTERPRETER_KERNEL_DATA_ACTION_CURSOR_BUNDLE = (
    "GeneratedInterpreterKernelActionCursorBundle"
)
INTERPRETER_KERNEL_DATA_BYTE_PACK_PREFIX = (
    "GeneratedInterpreterKernelDataBytePack"
)
INTERPRETER_KERNEL_DATA_BYTE_PACK_SIZE = 64 * 1024
INTERPRETER_KERNEL_DATA_BYTE_CHUNK_SIZE = 1024
INTERPRETER_KERNEL_DATA_RELOCATION_PACK_PREFIX = (
    "GeneratedInterpreterKernelDataRelocationPack"
)
INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE = (
    "GeneratedInterpreterKernelDataRelocationBundle"
)
INTERPRETER_KERNEL_DATA_RELOCATION_BLOCK_PREFIX = (
    "GeneratedInterpreterKernelDataRelocationBlock"
)
INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PREFIX = (
    "GeneratedInterpreterKernelDataRelocationChain"
)
INTERPRETER_KERNEL_DATA_POINTER_FIELD_PREFIX = (
    "GeneratedInterpreterKernelDataPointerField"
)
INTERPRETER_KERNEL_DATA_DESCRIPTOR_PREFIX = (
    "GeneratedInterpreterKernelDataDescriptor"
)
INTERPRETER_KERNEL_DATA_COMPONENT_PREFIX = (
    "GeneratedInterpreterKernelDataComponent"
)
INTERPRETER_KERNEL_DATA_RECORD_PREFIX = "GeneratedInterpreterKernelDataRecord"
INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX = (
    "GeneratedInterpreterKernelDataCertificatePack"
)
INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE = 16
INTERPRETER_KERNEL_DATA_RELOCATION_PACK_SIZE = 512
INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PACK_SIZE = 64
_TRANSFER_RECORD_SIZE = 40
_ACTION_SIZE = 32
_CALL_SIZE = 64
_X87_REPLAY_SIZE = 44
_LEAN_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)

_COMPONENTS = ("WordNodes", "X87Nodes", "Actions", "Calls", "X87Replays")

_LIGHT_RESOURCES = ("light", 768)
_MEDIUM_RESOURCES = ("medium", 2048)
_HIGH_MEMORY_RESOURCES = ("high-memory", 8192)
_PE_ROOT_RESOURCES = ("high-memory", 12288)
_BYTE_PACK_RESOURCES = ("medium", 4096)
_RELOCATION_BUNDLE_RESOURCES = ("high-memory", 16384)
_COMPONENT_RESOURCES = ("high-memory", 8192)
_CERTIFICATE_PACK_RESOURCES = ("medium", 4096)
_AUTHORITY_RESOURCES = ("high-memory", 24576)
_AUTHORITY_PACK_RESOURCES = ("high-memory", 12288)
_BYTE_RANGE_LEAF_CAPACITY = 256
# Keep the exact-byte authority layer aligned with the independently checked
# transfer packs.  Larger authority modules repeatedly elaborate dozens of
# byte-binding and relocation certificates in one process; for full programs
# that creates non-linear memory use and prevents useful incremental caching.
_AUTHORITY_TRANSFER_LIMIT = INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE


class InterpreterKernelDataGenerationError(StageAInputError):
    """The candidate table cannot be bound without an unchecked assumption."""


@dataclass(frozen=True)
class _RelocationBlock:
    offset: int
    page_rva: int
    block_size: int
    entry_count: int
    raw_entries: tuple[int, ...]
    relocations: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class _RelocationChunk:
    block_index: int
    entry_offset: int
    raw_entries: tuple[int, ...]
    relocations: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class _TransferDescriptor:
    source_rva: int
    word_count: int
    x87_count: int
    action_count: int
    replay_count: int
    word_pointer: int
    x87_pointer: int
    action_pointer: int
    call_pointer: int
    replay_pointer: int


@dataclass(frozen=True)
class _TraceProposal:
    relocated: tuple[int, ...]
    zero: tuple[int, ...]


@dataclass(frozen=True)
class _TransferProofPlan:
    descriptor: _TransferDescriptor
    component_traces: tuple[_TraceProposal, ...]


@dataclass(frozen=True)
class _PointerFieldProof:
    index: int
    field_rva: int
    present: bool


@dataclass(frozen=True)
class _ByteSlicePlan:
    pack_index: int
    pack_offset: int
    chunk_index: int
    chunk_offset: int
    chunk_size: int
    leaf_offset: int
    chunk_path: tuple[str, ...]
    size: int


@dataclass(frozen=True)
class _ByteRangePlan:
    rva: int
    size: int
    section_index: int
    section_virtual_size: int
    section_virtual_address: int
    section_raw_size: int
    section_raw_pointer: int
    section_characteristics: int
    raw_offset: int
    raw_count: int
    raw_bytes: bytes
    expected_bytes: bytes
    slices: tuple[_ByteSlicePlan, ...]


@dataclass(frozen=True)
class InterpreterKernelDataInventory:
    candidate_sha256: str
    candidate_size: int
    state_machine_sha256: str
    table_rva: int
    count_rva: int
    transfer_count: int
    shard_size: int
    transfer_shard_count: int
    byte_pack_size: int
    byte_pack_count: int
    relocation_pack_size: int
    relocation_pack_count: int
    relocation_block_count: int
    relocation_chain_count: int
    pointer_field_count: int
    descriptor_count: int
    component_count: int
    record_count: int
    certificate_pack_count: int
    authority_pack_count: int
    native_projection_pack_count: int
    action_cursor_pack_count: int
    standalone_module_count: int
    modules: tuple[dict[str, Any], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_DATA_FORMAT,
            "candidate_sha256": self.candidate_sha256,
            "candidate_bytes": self.candidate_size,
            "state_machine_sha256": self.state_machine_sha256,
            "table_rva": self.table_rva,
            "count_rva": self.count_rva,
            "counts": {
                "transfers": self.transfer_count,
                "shards": self.transfer_shard_count,
                "byte_packs": self.byte_pack_count,
                "relocation_packs": self.relocation_pack_count,
                "relocation_blocks": self.relocation_block_count,
                "relocation_chains": self.relocation_chain_count,
                "pointer_fields": self.pointer_field_count,
                "descriptors": self.descriptor_count,
                "components": self.component_count,
                "records": self.record_count,
                "certificate_packs": self.certificate_pack_count,
                "authority_packs": self.authority_pack_count,
                "native_projection_packs": self.native_projection_pack_count,
                "action_cursor_packs": self.action_cursor_pack_count,
                "generated_modules": len(self.modules),
                "standalone_modules": self.standalone_module_count,
            },
            "shard_size": self.shard_size,
            "byte_pack_size": self.byte_pack_size,
            "relocation_pack_size": self.relocation_pack_size,
            "authority_transfer_limit": _AUTHORITY_TRANSFER_LIMIT,
            "modules": list(self.modules),
            "candidate_authority": {
                "module": INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY,
                "namespace": (
                    "StageA.GeneratedRelational.CandidatePEAuthority"
                ),
                "exports": [
                    "candidateBytes",
                    "candidatePe",
                    "importCertificate",
                    "imports",
                    "candidateMetadataParsed",
                    "candidateParsed",
                    "importsChecked",
                    "candidateDataLayout",
                    "candidateDataLayoutExact",
                    "candidateBytePackCatalog",
                    "candidateBytePackCatalogChecked",
                ],
            },
            "acceptance_authority": False,
            "authority": (
                "Lean-decoded candidate PE layout; whole-program acceptance still "
                "requires compiled-kernel and relational composition theorems"
            ),
        }


def _lean_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _lean_option_string(value: str | None) -> str:
    return "none" if value is None else f"some {_lean_string(value)}"


def _lean_option_nat(value: int | None) -> str:
    return "none" if value is None else f"some {value}"


def _lean_nat_list(values: Iterable[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _lean_bytes(values: bytes) -> str:
    return _lean_nat_list(values)


def _lean_node(node: Any, inventory: Sequence[str]) -> str:
    try:
        opcode = inventory.index(node.op)
    except ValueError as exc:
        raise InterpreterKernelDataGenerationError(
            f"compiled node uses unknown opcode {node.op!r}"
        ) from exc
    return (
        "{ op := "
        f"{opcode}, arity := {len(node.args)}, aux := {node.aux}, "
        f"immediate := {node.immediate & 0xFFFFFFFF}, "
        f"args := {_lean_nat_list(node.args)} }}"
    )


def _lean_action(action: Any) -> str:
    try:
        opcode = _ACTIONS.index(action.op)
    except ValueError as exc:
        raise InterpreterKernelDataGenerationError(
            f"compiled action uses unknown opcode {action.op!r}"
        ) from exc
    return (
        "{ op := "
        f"{opcode}, arity := {len(action.args)}, aux := {action.aux}, "
        f"args := {_lean_nat_list(action.args)} }}"
    )


def _lean_stack_input(value: tuple[int, int, int]) -> str:
    offset, width, node = value
    return f"{{ offset := {offset}, width := {width}, valueNode := {node} }}"


def _lean_call(call: Any) -> str:
    kind = {"external_call": 0, "internal_call": 1, "indirect_call": 2}.get(
        call.kind
    )
    if kind is None:
        raise InterpreterKernelDataGenerationError(
            f"compiled call uses unknown kind {call.kind!r}"
        )
    stack = ", ".join(_lean_stack_input(item) for item in call.stack_inputs)
    return (
        "{ kind := "
        f"{kind}, instructionRva := {call.instruction_rva}, "
        f"callIndex := {call.call_index}, "
        f"targetNode := {_lean_option_nat(call.target_node)}, "
        f"targetRva := {call.target_rva}, returnRva := {call.return_rva}, "
        f"dll := {_lean_option_string(call.dll)}, "
        f"symbol := {_lean_option_string(call.symbol)}, "
        f"ordinal := {_lean_option_nat(call.ordinal)}, "
        f"registerNodes := {_lean_nat_list(call.register_nodes)}, "
        f"flagNodes := {_lean_nat_list(call.flag_nodes)}, "
        f"argumentNodes := {_lean_nat_list(call.argument_nodes)}, "
        f"stackInputs := [{stack}] }}"
    )


def _lean_replay(replay: Any) -> str:
    return (
        "{ imageBase := "
        f"{replay.image_base}, rvaStart := {replay.rva_start}, "
        f"rvaEnd := {replay.rva_end}, instructionCount := 1, "
        f"instructionBytes := {_lean_bytes(replay.instruction_bytes)}, "
        f"instructionBytesSha256 := {_lean_string(replay.instruction_bytes_sha256)}, "
        "transferInstructionBytesSha256 := "
        f"{_lean_string(replay.transfer_instruction_bytes_sha256)}, "
        f"contractSha256 := {_lean_string(replay.contract_sha256)}, "
        f"checkedDecoder := {_lean_string(replay.checked_decoder)}, "
        f"checkedExecutor := {_lean_string(replay.checked_executor)} }}"
    )


def _lean_list(values: Iterable[Any], render: Any) -> str:
    return "[\n    " + ",\n    ".join(render(value) for value in values) + "\n  ]"


def _lean_descriptor(descriptor: _TransferDescriptor) -> str:
    return """{
  sourceRva := %d
  wordCount := %d
  x87Count := %d
  actionCount := %d
  replayCount := %d
  wordPointer := %d
  x87Pointer := %d
  actionPointer := %d
  callPointer := %d
  replayPointer := %d
}""" % (
        descriptor.source_rva,
        descriptor.word_count,
        descriptor.x87_count,
        descriptor.action_count,
        descriptor.replay_count,
        descriptor.word_pointer,
        descriptor.x87_pointer,
        descriptor.action_pointer,
        descriptor.call_pointer,
        descriptor.replay_pointer,
    )


def _lean_trace(trace: _TraceProposal) -> str:
    return (
        "{ relocatedPointerFields := "
        f"{_lean_nat_list(trace.relocated)}, zeroPointerFields := "
        f"{_lean_nat_list(trace.zero)} }}"
    )


def _lean_certificate_data(
    transfer: Any,
    plan: _TransferProofPlan,
) -> str:
    word_trace, x87_trace, action_trace, call_trace, replay_trace = (
        plan.component_traces
    )
    return f"""{{
  descriptor := {_lean_descriptor(plan.descriptor)}
  wordNodes := {_lean_list(transfer.nodes, lambda node: _lean_node(node, _WORD_OPS))}
  x87Nodes := {_lean_list(transfer.x87_nodes, lambda node: _lean_node(node, _X87_OPS))}
  actions := {_lean_list(transfer.actions, _lean_action)}
  calls := {_lean_list(transfer.calls, _lean_call)}
  x87Replays := {_lean_list(transfer.x87_replays, _lean_replay)}
  wordTrace := {_lean_trace(word_trace)}
  x87Trace := {_lean_trace(x87_trace)}
  actionTrace := {_lean_trace(action_trace)}
  callTrace := {_lean_trace(call_trace)}
  replayTrace := {_lean_trace(replay_trace)}
}}"""


def _certificate_pack_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX}{index:04d}"


def _certificate_pack_definition(index: int) -> str:
    return f"generatedInterpreterKernelDataCertificatePack{index:04d}"


def _authority_pack_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_AUTHORITY_PACK_PREFIX}{index:04d}"


def _authority_pack_definition(index: int) -> str:
    return f"generatedInterpreterKernelDataAuthorityPack{index:04d}Shards"


def _authority_pack_included_theorem(index: int) -> str:
    return (
        f"generatedInterpreterKernelDataAuthorityPack{index:04d}"
        "Included"
    )


def _native_projection_pack_name(index: int) -> str:
    return (
        f"{INTERPRETER_KERNEL_DATA_NATIVE_PROJECTION_PACK_PREFIX}{index:04d}"
    )


def _native_projection_pack_checked_theorem(index: int) -> str:
    return (
        f"generatedInterpreterKernelDataNativeProjectionPack{index:04d}"
        "Checked"
    )


def _shard_facade_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_SHARD_FACADE_PREFIX}{index:04d}"


def _shard_facade_source(index: int, authority_pack_index: int) -> str:
    entries = _certificate_pack_compiled_entries_definition(index)
    shard = _certificate_pack_shard_definition(index)
    return f"""import StageA.{_authority_pack_name(authority_pack_index)}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.InterpreterKernelData

/-!
Compatibility facade for proof phases that consume one checked table shard.
The packed authority remains the sole source of decoding evidence; these
definitions only preserve the granular module boundary.
-/

noncomputable abbrev generatedInterpreterKernelDataEntries{index:04d} :=
  {entries}

noncomputable abbrev generatedInterpreterKernelDataShard{index:04d} :=
  {shard}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _certificate_entry_stem(pack_index: int, entry_offset: int) -> str:
    return (
        f"generatedInterpreterKernelDataCertificatePack{pack_index:04d}"
        f"Entry{entry_offset:04d}"
    )


def _certificate_pack_compiled_entries_definition(index: int) -> str:
    return f"{_certificate_pack_definition(index)}CompiledEntries"


def _certificate_pack_shard_definition(index: int) -> str:
    return f"{_certificate_pack_definition(index)}Shard"


def _certificate_pack_source_rvas_definition(index: int) -> str:
    return f"{_certificate_pack_definition(index)}SourceRvas"


def _certificate_pack_metadata_definition(index: int) -> str:
    return f"{_certificate_pack_definition(index)}MetadataCertificate"


def _semantic_record_pack_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_PACK_PREFIX}{index:04d}"


def _semantic_record_definition(pack_index: int, entry_offset: int) -> str:
    return (
        f"generatedInterpreterKernelSemanticRecordPack{pack_index:04d}"
        f"Entry{entry_offset:04d}"
    )


def _action_cursor_pack_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_ACTION_CURSOR_PACK_PREFIX}{index:04d}"


def _loaded_semantic_transfer_definition(
    pack_index: int, entry_offset: int
) -> str:
    return (
        f"generatedInterpreterKernelActionCursorPack{pack_index:04d}"
        f"Entry{entry_offset:04d}LoadedSemanticTransfer"
    )


def _descriptor_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_DESCRIPTOR_PREFIX}{index:04d}"


def _descriptor_definition(index: int) -> str:
    return f"generatedInterpreterKernelDataDescriptor{index:04d}"


def _component_name(index: int, component: str) -> str:
    return f"{INTERPRETER_KERNEL_DATA_COMPONENT_PREFIX}{index:04d}{component}"


def _component_stem(index: int, component: str) -> str:
    return f"generatedInterpreterKernelData{component}{index:04d}"


def _record_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_RECORD_PREFIX}{index:04d}"


def _record_definition(index: int) -> str:
    return f"generatedInterpreterKernelDataRecord{index:04d}"


def _pointer_field_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_POINTER_FIELD_PREFIX}{index:06d}"


def _pointer_field_theorem(index: int) -> str:
    return f"generatedInterpreterKernelDataPointerField{index:06d}Checked"


def _pointer_target_rva(pointer: int, image_base: int, label: str) -> int:
    if pointer < image_base or pointer - image_base >= 2**32:
        raise InterpreterKernelDataGenerationError(
            f"{label} is not a nonzero PE32 image pointer"
        )
    return pointer - image_base


def _transfer_proof_plan(
    *,
    index: int,
    table_rva: int,
    image_base: int,
    transfer: Any,
    descriptor_bytes: bytes,
) -> _TransferProofPlan:
    values = struct.unpack("<10I", descriptor_bytes)
    descriptor = _TransferDescriptor(*values)
    record_rva = table_rva + index * _TRANSFER_RECORD_SIZE

    word_trace = _TraceProposal((record_rva + 20,), ())
    x87_trace = _TraceProposal((record_rva + 24,), ())
    action_trace = _TraceProposal((record_rva + 28,), ())

    call_rva = _pointer_target_rva(
        descriptor.call_pointer, image_base, f"transfer {index} call array"
    )
    call_relocated = [record_rva + 32]
    call_zero: list[int] = []
    for call_index, call in enumerate(transfer.calls):
        base = call_rva + call_index * _CALL_SIZE
        for field_offset, value in ((24, call.dll), (28, call.symbol)):
            if value is None:
                call_zero.append(base + field_offset)
            else:
                call_relocated.append(base + field_offset)
        call_relocated.extend((base + 40, base + 44, base + 48, base + 56))
    call_trace = _TraceProposal(tuple(call_relocated), tuple(call_zero))

    replay_rva = _pointer_target_rva(
        descriptor.replay_pointer, image_base, f"transfer {index} x87 replay array"
    )
    replay_relocated = [record_rva + 36]
    for replay_index, _replay in enumerate(transfer.x87_replays):
        base = replay_rva + replay_index * _X87_REPLAY_SIZE
        replay_relocated.extend(
            (base + 20, base + 24, base + 28, base + 32, base + 36, base + 40)
        )
    replay_trace = _TraceProposal(tuple(replay_relocated), ())

    return _TransferProofPlan(
        descriptor=descriptor,
        component_traces=(
            word_trace,
            x87_trace,
            action_trace,
            call_trace,
            replay_trace,
        ),
    )


def _pointer_field_proofs(
    plans: Sequence[_TransferProofPlan],
) -> tuple[tuple[_PointerFieldProof, ...], dict[tuple[int, bool], _PointerFieldProof]]:
    ordered: list[_PointerFieldProof] = []
    by_key: dict[tuple[int, bool], _PointerFieldProof] = {}
    expectation_by_field: dict[int, bool] = {}
    for plan in plans:
        for trace in plan.component_traces:
            for present, fields in ((True, trace.relocated), (False, trace.zero)):
                for field_rva in fields:
                    prior = expectation_by_field.get(field_rva)
                    if prior is not None and prior != present:
                        raise InterpreterKernelDataGenerationError(
                            f"pointer field 0x{field_rva:x} is proposed both zero and relocated"
                        )
                    expectation_by_field[field_rva] = present
                    key = (field_rva, present)
                    if key not in by_key:
                        proof = _PointerFieldProof(len(ordered), field_rva, present)
                        ordered.append(proof)
                        by_key[key] = proof
    sorted_fields = tuple(
        _PointerFieldProof(index, proof.field_rva, proof.present)
        for index, proof in enumerate(
            sorted(ordered, key=lambda proof: (proof.field_rva, proof.present))
        )
    )
    return sorted_fields, {
        (proof.field_rva, proof.present): proof for proof in sorted_fields
    }


def _component_value_source(component: str, transfer: Any) -> tuple[str, str]:
    if component == "WordNodes":
        return (
            "List RawWordNode",
            _lean_list(transfer.nodes, lambda node: _lean_node(node, _WORD_OPS)),
        )
    if component == "X87Nodes":
        return (
            "List RawWordNode",
            _lean_list(transfer.x87_nodes, lambda node: _lean_node(node, _X87_OPS)),
        )
    if component == "Actions":
        return "List RawAction", _lean_list(transfer.actions, _lean_action)
    if component == "Calls":
        return "List RawCall", _lean_list(transfer.calls, _lean_call)
    if component == "X87Replays":
        return "List RawX87Replay", _lean_list(transfer.x87_replays, _lean_replay)
    raise AssertionError(f"unknown generated component {component}")


def _component_decode_expression(index: int, component: str) -> str:
    descriptor = _descriptor_definition(index)
    record_rva = (
        f"(generatedInterpreterKernelTableRva + {index} * transferRecordSize)"
    )
    prefix = (
        "generatedInterpreterKernelCandidatePe "
        "generatedInterpreterKernelImports"
    )
    if component == "WordNodes":
        return (
            f"decodeNodeArray {prefix} ({record_rva} + 20) "
            f"{descriptor}.wordPointer {descriptor}.wordCount "
            "wordNodeSize maxWordNodes"
        )
    if component == "X87Nodes":
        return (
            f"decodeNodeArray {prefix} ({record_rva} + 24) "
            f"{descriptor}.x87Pointer {descriptor}.x87Count "
            "x87NodeSize maxX87Nodes"
        )
    if component == "Actions":
        return (
            f"decodeActionArray {prefix} ({record_rva} + 28) "
            f"{descriptor}.actionPointer {descriptor}.actionCount"
        )
    if component == "Calls":
        actions = _component_stem(index, "Actions")
        return (
            f"decodeCallArray {prefix} ({record_rva} + 32) "
            f"{descriptor}.callPointer (callCountFromActions {actions})"
        )
    if component == "X87Replays":
        return (
            f"decodeX87ReplayArray {prefix} ({record_rva} + 36) "
            f"{descriptor}.replayPointer {descriptor}.replayCount"
        )
    raise AssertionError(f"unknown generated component {component}")


def _byte_pack_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_BYTE_PACK_PREFIX}{index:04d}"


def _byte_pack_definition(index: int) -> str:
    return f"generatedInterpreterKernelCandidateBytesPack{index:04d}"


def _byte_pack_chunk_definition(pack_index: int, chunk_index: int) -> str:
    return f"{_byte_pack_definition(pack_index)}Chunk{chunk_index}"


def _byte_pack_length_theorem(index: int) -> str:
    return f"generatedInterpreterKernelCandidateBytesPack{index:04d}Length"


def _byte_pack_valid_theorem(index: int) -> str:
    return f"generatedInterpreterKernelCandidateBytesPack{index:04d}Valid"


def _byte_pack_certificate_definition(index: int) -> str:
    return f"generatedInterpreterKernelCandidateBytesPack{index:04d}Certificate"


def _relocation_pack_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_RELOCATION_PACK_PREFIX}{index:04d}"


def _relocation_pack_definition(index: int) -> str:
    return f"generatedInterpreterKernelRelocationsPack{index:04d}"


def _relocation_chain_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PREFIX}{index:04d}"


def _relocation_block_name(index: int) -> str:
    return f"{INTERPRETER_KERNEL_DATA_RELOCATION_BLOCK_PREFIX}{index:04d}"


def _relocation_block_definition(index: int) -> str:
    return f"generatedInterpreterKernelRelocationsBlock{index:04d}"


def _relocation_block_theorem(index: int) -> str:
    return f"generatedInterpreterKernelRelocationsBlock{index:04d}Parsed"


def _relocation_suffix_definition(index: int) -> str:
    return f"generatedInterpreterKernelRelocationsFrom{index:04d}"


def _relocation_suffix_theorem(index: int) -> str:
    return f"generatedInterpreterKernelRelocationBlocksFrom{index:04d}Parsed"


def _byte_pack_ranges(byte_count: int, pack_size: int) -> tuple[tuple[int, int], ...]:
    return tuple(
        (offset, min(pack_size, byte_count - offset))
        for offset in range(0, byte_count, pack_size)
    )


def _byte_pack_chunk_layout(
    pack_size: int,
) -> tuple[tuple[int, int, tuple[str, ...]], ...]:
    chunks = tuple(
        (
            offset,
            min(
                INTERPRETER_KERNEL_DATA_BYTE_CHUNK_SIZE,
                pack_size - offset,
            ),
        )
        for offset in range(
            0,
            pack_size,
            INTERPRETER_KERNEL_DATA_BYTE_CHUNK_SIZE,
        )
    )
    _tree, paths = _lean_byte_tree_composition_with_paths(
        [(size, str(index)) for index, (_offset, size) in enumerate(chunks)]
    )
    return tuple(
        (offset, size, path)
        for (offset, size), path in zip(chunks, paths, strict=True)
    )


def _candidate_section_for_range(binary: Any, rva: int, size: int) -> tuple[int, Any]:
    matches: list[tuple[int, Any]] = []
    for index, section in enumerate(binary.pe.sections):
        virtual_size = int(section.Misc_VirtualSize)
        raw_size = int(section.SizeOfRawData)
        mapped_size = virtual_size if virtual_size else raw_size
        virtual_address = int(section.VirtualAddress)
        writable = bool(int(section.Characteristics) & (1 << 31))
        if (
            not writable
            and virtual_address <= rva
            and rva + size <= virtual_address + mapped_size
        ):
            matches.append((index, section))
    if len(matches) != 1:
        raise InterpreterKernelDataGenerationError(
            f"immutable RVA range 0x{rva:x}+0x{size:x} has {len(matches)} sections"
        )
    return matches[0]


def _byte_range_plan(
    binary: Any,
    candidate_bytes: bytes,
    byte_pack_ranges: Sequence[tuple[int, int]],
    rva: int,
    size: int,
) -> _ByteRangePlan:
    if size <= 0 or rva + size > int(binary.pe.OPTIONAL_HEADER.SizeOfImage):
        raise InterpreterKernelDataGenerationError(
            f"invalid immutable RVA range 0x{rva:x}+0x{size:x}"
        )
    section_index, section = _candidate_section_for_range(binary, rva, size)
    section_rva = int(section.VirtualAddress)
    section_offset = rva - section_rva
    raw_size = int(section.SizeOfRawData)
    raw_count = min(size, raw_size - section_offset) if section_offset < raw_size else 0
    raw_offset = int(section.PointerToRawData) + section_offset
    if raw_offset < 0 or raw_offset + raw_count > len(candidate_bytes):
        raise InterpreterKernelDataGenerationError(
            f"immutable RVA range 0x{rva:x}+0x{size:x} exceeds candidate bytes"
        )
    raw_bytes = candidate_bytes[raw_offset : raw_offset + raw_count]
    expected = raw_bytes + bytes(size - raw_count)
    slices: list[_ByteSlicePlan] = []
    cursor = raw_offset
    remaining = raw_count
    while remaining:
        for pack_index, (pack_offset, pack_size) in enumerate(byte_pack_ranges):
            if pack_offset <= cursor < pack_offset + pack_size:
                relative_offset = cursor - pack_offset
                for chunk_index, (
                    chunk_offset,
                    chunk_size,
                    chunk_path,
                ) in enumerate(_byte_pack_chunk_layout(pack_size)):
                    if (
                        chunk_offset
                        <= relative_offset
                        < chunk_offset + chunk_size
                    ):
                        leaf_offset = relative_offset - chunk_offset
                        count = min(
                            remaining,
                            chunk_size - leaf_offset,
                        )
                        break
                else:
                    raise InterpreterKernelDataGenerationError(
                        "raw byte offset "
                        f"0x{cursor:x} is outside candidate pack {pack_index} chunks"
                    )
                slices.append(
                    _ByteSlicePlan(
                        pack_index=pack_index,
                        pack_offset=relative_offset,
                        chunk_index=chunk_index,
                        chunk_offset=chunk_offset,
                        chunk_size=chunk_size,
                        leaf_offset=leaf_offset,
                        chunk_path=chunk_path,
                        size=count,
                    )
                )
                cursor += count
                remaining -= count
                break
        else:
            raise InterpreterKernelDataGenerationError(
                f"raw byte offset 0x{cursor:x} is outside candidate packs"
            )
    return _ByteRangePlan(
        rva=rva,
        size=size,
        section_index=section_index,
        section_virtual_size=int(section.Misc_VirtualSize),
        section_virtual_address=int(section.VirtualAddress),
        section_raw_size=int(section.SizeOfRawData),
        section_raw_pointer=int(section.PointerToRawData),
        section_characteristics=int(section.Characteristics),
        raw_offset=raw_offset,
        raw_count=raw_count,
        raw_bytes=raw_bytes,
        expected_bytes=expected,
        slices=tuple(slices),
    )


def _transfer_byte_range_plans(
    binary: Any,
    candidate_bytes: bytes,
    byte_pack_ranges: Sequence[tuple[int, int]],
    table_rva: int,
    count_rva: int,
    transfers: Sequence[Any],
    plans: Sequence[_TransferProofPlan],
) -> tuple[tuple[_ByteRangePlan, ...], ...]:
    image_base = int(binary.pe.OPTIONAL_HEADER.ImageBase)
    per_transfer: list[tuple[_ByteRangePlan, ...]] = []
    for index, (transfer, plan) in enumerate(zip(transfers, plans, strict=True)):
        requested: dict[tuple[int, int], _ByteRangePlan] = {}

        def add(rva: int, size: int) -> None:
            key = (rva, size)
            if key not in requested:
                requested[key] = _byte_range_plan(
                    binary, candidate_bytes, byte_pack_ranges, rva, size
                )

        def add_pointer(pointer: int, size: int, label: str) -> int:
            target = _pointer_target_rva(pointer, image_base, label)
            add(target, size)
            return target

        def add_cstring(pointer: int, label: str) -> None:
            target = _pointer_target_rva(pointer, image_base, label)
            _section_index, section = _candidate_section_for_range(binary, target, 1)
            mapped_size = int(section.Misc_VirtualSize) or int(section.SizeOfRawData)
            available = min(
                512,
                int(section.VirtualAddress) + mapped_size - target,
            )
            add(target, available)

        descriptor = plan.descriptor
        record_rva = table_rva + index * _TRANSFER_RECORD_SIZE
        add(record_rva, _TRANSFER_RECORD_SIZE)
        add_pointer(
            descriptor.word_pointer,
            max(1, descriptor.word_count) * 36,
            f"transfer {index} word array",
        )
        add_pointer(
            descriptor.x87_pointer,
            max(1, descriptor.x87_count) * 36,
            f"transfer {index} x87 array",
        )
        if descriptor.action_count:
            add_pointer(
                descriptor.action_pointer,
                descriptor.action_count * 32,
                f"transfer {index} action array",
            )

        call_count = len(transfer.calls)
        call_rva = add_pointer(
            descriptor.call_pointer,
            max(1, call_count) * _CALL_SIZE,
            f"transfer {index} call array",
        )
        call_bytes = bytes(binary.pe.get_data(call_rva, call_count * _CALL_SIZE))
        if len(call_bytes) != call_count * _CALL_SIZE:
            raise InterpreterKernelDataGenerationError(
                f"transfer {index} call array is truncated"
            )
        for call_index in range(call_count):
            values = struct.unpack_from("<16I", call_bytes, call_index * _CALL_SIZE)
            base = f"transfer {index} call {call_index}"
            if values[6]:
                add_cstring(values[6], f"{base} DLL")
            if values[7]:
                add_cstring(values[7], f"{base} symbol")
            add_pointer(values[10], 8 * 4, f"{base} register array")
            add_pointer(values[11], 6 * 4, f"{base} flag array")
            add_pointer(values[12], max(1, values[13]) * 4, f"{base} argument array")
            add_pointer(values[14], max(1, values[15]) * 12, f"{base} stack array")

        replay_count = descriptor.replay_count
        replay_rva = add_pointer(
            descriptor.replay_pointer,
            max(1, replay_count) * _X87_REPLAY_SIZE,
            f"transfer {index} replay array",
        )
        replay_bytes = bytes(
            binary.pe.get_data(replay_rva, replay_count * _X87_REPLAY_SIZE)
        )
        if len(replay_bytes) != replay_count * _X87_REPLAY_SIZE:
            raise InterpreterKernelDataGenerationError(
                f"transfer {index} replay array is truncated"
            )
        for replay_index in range(replay_count):
            values = struct.unpack_from(
                "<11I", replay_bytes, replay_index * _X87_REPLAY_SIZE
            )
            base = f"transfer {index} replay {replay_index}"
            add_pointer(values[5], values[4], f"{base} instruction bytes")
            for pointer_index, label in zip(
                range(6, 11),
                ("instruction hash", "transfer hash", "contract hash", "decoder", "executor"),
                strict=True,
            ):
                add_cstring(values[pointer_index], f"{base} {label}")

        if index == 0:
            add(count_rva, 4)
        per_transfer.append(tuple(requested.values()))
    return tuple(per_transfer)


def _relocation_blocks(binary: Any) -> tuple[_RelocationBlock, ...]:
    directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    directory_rva = int(directory.VirtualAddress)
    directory_size = int(directory.Size)
    if directory_rva == 0 and directory_size == 0:
        return ()
    if directory_rva == 0 or directory_size < 8:
        raise InterpreterKernelDataGenerationError(
            "candidate relocation directory has an invalid PE32 shape"
        )
    blocks: list[_RelocationBlock] = []
    offset = 0
    while offset < directory_size:
        header = bytes(binary.pe.get_data(directory_rva + offset, 8))
        if len(header) != 8:
            raise InterpreterKernelDataGenerationError(
                "candidate relocation block header is truncated"
            )
        page_rva, block_size = struct.unpack("<II", header)
        if (
            block_size < 8
            or block_size % 2
            or offset + block_size > directory_size
        ):
            raise InterpreterKernelDataGenerationError(
                "candidate relocation block has an invalid size"
            )
        entry_count = (block_size - 8) // 2
        data = bytes(
            binary.pe.get_data(directory_rva + offset + 8, entry_count * 2)
        )
        if len(data) != entry_count * 2:
            raise InterpreterKernelDataGenerationError(
                "candidate relocation entries are truncated"
            )
        raw_entries = tuple(
            value for (value,) in struct.iter_unpack("<H", data)
        )
        relocations: list[tuple[int, int]] = []
        for value in raw_entries:
            kind = value // 4096
            entry_offset = value % 4096
            if kind == 0:
                continue
            if kind != 3:
                raise InterpreterKernelDataGenerationError(
                    f"unsupported PE32 base relocation kind {kind}"
                )
            relocations.append((page_rva + entry_offset, kind))
        blocks.append(
            _RelocationBlock(
                offset=offset,
                page_rva=page_rva,
                block_size=block_size,
                entry_count=entry_count,
                raw_entries=raw_entries,
                relocations=tuple(relocations),
            )
        )
        offset += block_size
    if offset != directory_size:
        raise InterpreterKernelDataGenerationError(
            "candidate relocation blocks do not cover the exact directory"
        )
    return tuple(blocks)


def _relocation_chunks(
    blocks: Sequence[_RelocationBlock], pack_size: int
) -> tuple[_RelocationChunk, ...]:
    chunks: list[_RelocationChunk] = []
    for block_index, block in enumerate(blocks):
        for entry_offset in range(0, block.entry_count, pack_size):
            raw_entries = block.raw_entries[entry_offset : entry_offset + pack_size]
            relocations: list[tuple[int, int]] = []
            for value in raw_entries:
                kind = value // 4096
                if kind == 3:
                    relocations.append((block.page_rva + value % 4096, kind))
            chunks.append(
                _RelocationChunk(
                    block_index=block_index,
                    entry_offset=entry_offset,
                    raw_entries=raw_entries,
                    relocations=tuple(relocations),
                )
            )
    return tuple(chunks)


def _relocation_chunk_packs(
    chunks: Sequence[_RelocationChunk], pack_size: int
) -> tuple[tuple[tuple[int, _RelocationChunk], ...], ...]:
    packs: list[list[tuple[int, _RelocationChunk]]] = []
    current: list[tuple[int, _RelocationChunk]] = []
    current_entries = 0
    for chunk_index, chunk in enumerate(chunks):
        entry_count = len(chunk.raw_entries)
        if current and current_entries + entry_count > pack_size:
            packs.append(current)
            current = []
            current_entries = 0
        current.append((chunk_index, chunk))
        current_entries += entry_count
    if current:
        packs.append(current)
    return tuple(tuple(pack) for pack in packs)


def _lean_byte_tree_composition(parts: Sequence[tuple[int, str]]) -> str:
    tree, _paths = _lean_byte_tree_composition_with_paths(parts)
    return tree


def _lean_byte_tree_composition_with_paths(
    parts: Sequence[tuple[int, str]],
) -> tuple[str, tuple[tuple[str, ...], ...]]:
    trees = [
        (size, expression, {index: ()})
        for index, (size, expression) in enumerate(parts)
    ]
    if not trees:
        return ".empty", ()
    while len(trees) > 1:
        merged: list[tuple[int, str, dict[int, tuple[str, ...]]]] = []
        for index in range(0, len(trees), 2):
            if index + 1 == len(trees):
                merged.append(trees[index])
                continue
            left_size, left, left_paths = trees[index]
            right_size, right, right_paths = trees[index + 1]
            merged.append(
                (
                    left_size + right_size,
                    f"(.node {left_size + right_size} {left_size} {left} {right})",
                    {
                        **{
                            leaf: ("left", *path)
                            for leaf, path in left_paths.items()
                        },
                        **{
                            leaf: ("right", *path)
                            for leaf, path in right_paths.items()
                        },
                    },
                )
            )
        trees = merged
    _size, expression, paths = trees[0]
    return expression, tuple(paths[index] for index in range(len(parts)))


def _lean_finite_index_composition(parts: Sequence[tuple[int, str]]) -> str:
    if not parts:
        return ".empty"
    if len(parts) == 1:
        return parts[0][1]
    midpoint = len(parts) // 2
    left_parts = parts[:midpoint]
    right_parts = parts[midpoint:]
    left_size = sum(size for size, _ in left_parts)
    right_size = sum(size for size, _ in right_parts)
    left = _lean_finite_index_composition(left_parts)
    right = _lean_finite_index_composition(right_parts)
    return f"(.branch {left_size + right_size} {left_size} {left} {right})"


def _lean_relocation_index_composition(
    parts: Sequence[tuple[int, int, str]],
) -> str:
    if not parts:
        return ".empty"
    if len(parts) == 1:
        return f"(.leaf {parts[0][2]})"
    midpoint = len(parts) // 2
    left_parts = parts[:midpoint]
    right_parts = parts[midpoint:]
    split_rva = right_parts[0][0]
    left = _lean_relocation_index_composition(left_parts)
    right = _lean_relocation_index_composition(right_parts)
    return f"(.branch {split_rva} {left} {right})"


def _byte_pack_source(index: int, candidate_bytes: bytes) -> str:
    definition = _byte_pack_definition(index)
    tree = _lean_byte_tree_definitions(
        definition,
        candidate_bytes,
        chunk_size=INTERPRETER_KERNEL_DATA_BYTE_CHUNK_SIZE,
    )
    return f"""import StageA.Formal

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal

set_option maxRecDepth 1000000
set_option compiler.extract_closed false

{tree}

theorem {_byte_pack_length_theorem(index)} :
    {definition}.length = {len(candidate_bytes)} := by
  decide +kernel

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _relocation_pack_source(
    chunks: Sequence[tuple[int, _RelocationBlock, _RelocationChunk]],
) -> str:
    declarations: list[str] = []
    for chunk_index, block, chunk in chunks:
        definition = _relocation_pack_definition(chunk_index)
        rows = ", ".join(
            f"{{ rva := {rva}, kind := {kind} }}"
            for rva, kind in chunk.relocations
        )
        declarations.append(f"""
def {definition} : List BaseRelocation :=
  [{rows}]

theorem {definition}Parsed :
    parseRelocationEntries generatedInterpreterKernelCandidatePe
      {block.page_rva}
      (generatedInterpreterKernelCandidatePe.relocationDirectoryRva +
        {block.offset} + 8 + {chunk.entry_offset * 2})
      {len(chunk.raw_entries)} = some {definition} := by
  decide +kernel
""")
    return f"""import StageA.{INTERPRETER_KERNEL_DATA_BASE}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelData
open StageA.Relational.PEBytePacks

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option compiler.extract_closed false

{''.join(declarations)}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _relocation_block_source(
    block_index: int,
    block: _RelocationBlock,
    chunks: Sequence[tuple[int, str, _RelocationChunk]],
) -> str:
    imports = "\n".join(
        f"import StageA.{module_name}"
        for module_name in dict.fromkeys(module_name for _, module_name, _ in chunks)
    )
    if not imports:
        imports = f"import StageA.{INTERPRETER_KERNEL_DATA_BASE}"
    definition = _relocation_block_definition(block_index)
    theorem = _relocation_block_theorem(block_index)
    entries_rva = (
        "(generatedInterpreterKernelCandidatePe.relocationDirectoryRva + "
        f"{block.offset} + 8)"
    )
    if not chunks:
        body = f"""
def {definition} : List BaseRelocation := []

theorem {theorem} :
    parseRelocationEntries generatedInterpreterKernelCandidatePe
      {block.page_rva} {entries_rva} {block.entry_count} =
        some {definition} := by
  decide +kernel
"""
    else:
        rows: list[str] = []
        suffix_names: list[str] = []
        suffix_theorems: list[str] = []
        for local_index in range(len(chunks) - 1, -1, -1):
            chunk_index, _module_name, chunk = chunks[local_index]
            suffix = (
                f"generatedInterpreterKernelRelocationsBlock{block_index:04d}"
                f"From{local_index:04d}"
            )
            suffix_theorem = f"{suffix}Parsed"
            suffix_names.append(suffix)
            suffix_theorems.append(suffix_theorem)
            pack = _relocation_pack_definition(chunk_index)
            pack_theorem = f"{pack}Parsed"
            remaining_count = block.entry_count - chunk.entry_offset
            start = f"({entries_rva} + {chunk.entry_offset * 2})"
            if local_index + 1 == len(chunks):
                value = pack
                proof = f"exact {pack_theorem}"
            else:
                next_suffix = suffix_names[-2]
                next_theorem = suffix_theorems[-2]
                value = f"{pack} ++ {next_suffix}"
                suffix_count = remaining_count - len(chunk.raw_entries)
                proof = f"""apply parseRelocationEntries_append_of_checked
      generatedInterpreterKernelCandidatePe {block.page_rva} {start}
      {len(chunk.raw_entries)} {suffix_count} {pack} {next_suffix}
  · exact {pack_theorem}
  · simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using {next_theorem}"""
            rows.append(
                f"""def {suffix} : List BaseRelocation :=
  {value}

theorem {suffix_theorem} :
    parseRelocationEntries generatedInterpreterKernelCandidatePe
      {block.page_rva} {start} {remaining_count} = some {suffix} := by
  {proof}
"""
            )
        first_suffix = suffix_names[-1]
        first_theorem = suffix_theorems[-1]
        body = "\n".join(rows) + f"""
def {definition} : List BaseRelocation := {first_suffix}

theorem {theorem} :
    parseRelocationEntries generatedInterpreterKernelCandidatePe
      {block.page_rva} {entries_rva} {block.entry_count} =
        some {definition} := by
  simpa [Nat.add_assoc] using {first_theorem}
"""
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000

{body}
end StageA.GeneratedRelational.InterpreterKernelData
"""


def _relocation_chain_source(
    chain_index: int,
    bindings: Sequence[tuple[int, _RelocationBlock, str, str, str]],
    *,
    block_count: int,
    relocation_directory_size: int,
) -> str:
    if not bindings:
        raise InterpreterKernelDataGenerationError(
            "relocation chain pack cannot be empty"
        )
    imports = [
        f"import StageA.{module_name}"
        for module_name in dict.fromkeys(item[4] for item in bindings)
    ]
    final_block_index = bindings[-1][0]
    if final_block_index + 1 < block_count:
        imports.append(
            f"import StageA.{_relocation_chain_name(chain_index + 1)}"
        )
    declarations: list[str] = []
    for block_index, block, definition, block_theorem, _module_name in reversed(
        bindings
    ):
        remaining_fuel = relocation_directory_size // 8 + 1 - block_index
        if remaining_fuel <= 1:
            raise InterpreterKernelDataGenerationError(
                "relocation block inventory exceeds parser fuel"
            )
        if block_index + 1 < block_count:
            tail_definition = _relocation_suffix_definition(block_index + 1)
            tail_theorem = _relocation_suffix_theorem(block_index + 1)
            tail_setup = ""
        else:
            tail_definition = "generatedInterpreterKernelRelocationsEnd"
            tail_theorem = "generatedInterpreterKernelRelocationBlocksEndParsed"
            tail_fuel = remaining_fuel - 1
            tail_setup = f"""
def generatedInterpreterKernelRelocationsEnd : List BaseRelocation := []

theorem generatedInterpreterKernelRelocationBlocksEndParsed :
    parseRelocationBlocks generatedInterpreterKernelCandidatePe
      {relocation_directory_size} {tail_fuel} =
        some generatedInterpreterKernelRelocationsEnd := by
  simp [parseRelocationBlocks,
    generatedInterpreterKernelCandidatePe,
    generatedInterpreterKernelRelocationsEnd]
"""
        suffix = _relocation_suffix_definition(block_index)
        theorem = _relocation_suffix_theorem(block_index)
        declarations.append(f"""{tail_setup}
def {suffix} : List BaseRelocation :=
  {definition} ++ {tail_definition}

theorem {theorem} :
    parseRelocationBlocks generatedInterpreterKernelCandidatePe
      {block.offset} {remaining_fuel} = some {suffix} := by
  apply parseRelocationBlocks_cons_of_checked
      generatedInterpreterKernelCandidatePe {block.offset} {remaining_fuel - 1}
      {block.page_rva} {block.block_size} {definition} {tail_definition}
  · decide +kernel
  · decide +kernel
  · decide +kernel
  · decide +kernel
  · decide +kernel
  · exact {block_theorem}
  · exact {tail_theorem}
""")
    return f"""{chr(10).join(imports)}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000

{chr(10).join(declarations)}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _relocation_bundle_source(
    block_count: int,
    relocation_index_parts: Sequence[tuple[int, int, str]],
    relocation_leaf_capacity: int,
    relocation_directory_size: int,
) -> str:
    relocation_index = _lean_relocation_index_composition(relocation_index_parts)
    if block_count == 0:
        import_line = f"import StageA.{INTERPRETER_KERNEL_DATA_BASE}"
        proof = "by decide +kernel"
    else:
        import_line = f"import StageA.{_relocation_chain_name(0)}"
        proof = f"""by
  simp only [parseRelocations]
  change parseRelocationBlocks generatedInterpreterKernelCandidatePe 0
    {relocation_directory_size // 8 + 1} = some generatedInterpreterKernelRelocations
  rw [{_relocation_suffix_theorem(0)}]
  decide +kernel"""
    return f"""{import_line}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelData
open StageA.Relational.PEBytePacks

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedInterpreterKernelRelocationIndex : RelocationRvaIndex :=
  {relocation_index}

def generatedInterpreterKernelRelocations : List BaseRelocation :=
  generatedInterpreterKernelRelocationIndex.toList

theorem generatedInterpreterKernelRelocationsParsed :
    parseRelocations generatedInterpreterKernelCandidatePe =
      some generatedInterpreterKernelRelocations := {proof}

theorem generatedInterpreterKernelRelocationsLinearChecked :
    relocationInventoryLinearChecked generatedInterpreterKernelRelocations =
      true := by
  decide +kernel

theorem generatedInterpreterKernelRelocationInventoryUnique :
    relocationInventoryUnique generatedInterpreterKernelRelocations = true :=
  relocationInventoryUnique_of_linearChecked
    generatedInterpreterKernelRelocations
    generatedInterpreterKernelRelocationsLinearChecked

theorem generatedInterpreterKernelRelocationIndexStructurallyValid :
    generatedInterpreterKernelRelocationIndex.structurallyValid
      {relocation_leaf_capacity} = true := by
  decide +kernel

theorem generatedInterpreterKernelRelocationIndexRangesChecked :
    generatedInterpreterKernelRelocationIndex.rangesChecked 0 (2 ^ 32) = true := by
  decide +kernel

def generatedInterpreterKernelRelocationIndexCertificate :
    RelocationRvaIndexCertificate generatedInterpreterKernelRelocations := {{
  index := generatedInterpreterKernelRelocationIndex
  leafCapacity := {relocation_leaf_capacity}
  structurallyValid :=
    generatedInterpreterKernelRelocationIndexStructurallyValid
  rangesChecked := generatedInterpreterKernelRelocationIndexRangesChecked
  authoritative := rfl
}}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _base_source(
    binary: Any,
    byte_pack_ranges: Sequence[tuple[int, int]],
    table_rva: int,
    count_rva: int,
) -> str:
    pack_imports = "\n".join(
        f"import StageA.{_byte_pack_name(index)}"
        for index in range(len(byte_pack_ranges))
    )
    tree, paths = _lean_byte_tree_composition_with_paths(
        [
            (size, _byte_pack_definition(index))
            for index, (_, size) in enumerate(byte_pack_ranges)
        ]
    )
    pack_certificates: list[str] = []
    pack_certificate_names: list[str] = []
    for index, ((raw_offset, size), path) in enumerate(
        zip(byte_pack_ranges, paths, strict=True)
    ):
        pack = _byte_pack_definition(index)
        located = f"ByteTreePackAt.here {pack}"
        for direction in reversed(path):
            located = (
                f"ByteTreePackAt.{direction} (by rfl) (by rfl) ({located})"
            )
        certificate = _byte_pack_certificate_definition(index)
        pack_certificate_names.append(certificate)
        pack_certificates.append(f"""
theorem {certificate}Located :
    ByteTreePackAt generatedInterpreterKernelCandidatePe.bytes
      {raw_offset} {pack} := by
  change ByteTreePackAt generatedInterpreterKernelCandidateBytes
    {raw_offset} {pack}
  unfold generatedInterpreterKernelCandidateBytes
  exact {located}

def {certificate} :
    PEBytePackCertificate generatedInterpreterKernelCandidatePe := {{
  rawOffset := {raw_offset}
  pack := {pack}
  nonempty := by
    rw [{_byte_pack_length_theorem(index)}]
    decide
  valid := by decide +kernel
  located := {certificate}Located
}}
""")
    catalog = _lean_finite_index_composition(
        [(1, f"(.leaf [{name}])") for name in pack_certificate_names]
    )
    return f"""import StageA.{INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT}
{pack_imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelData
open StageA.Relational.PEBytePacks

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedInterpreterKernelCandidateBytes : ByteTree :=
  {tree}

def generatedInterpreterKernelCandidatePe : PE32 :=
  {_lean_pe(binary, "generatedInterpreterKernelCandidateBytes")}

def generatedInterpreterKernelImportCertificate : ImportTableCertificate :=
  {_lean_import_certificate(binary)}

def generatedInterpreterKernelImports : List PEImport :=
  generatedInterpreterKernelImportCertificate.imports

theorem generatedInterpreterKernelMetadataParsed :
    parsePEMetadataTree generatedInterpreterKernelCandidateBytes =
      some generatedInterpreterKernelCandidatePe.metadata := by
  decide

theorem generatedInterpreterKernelCandidateParsed :
    parsePE32Tree generatedInterpreterKernelCandidateBytes =
      some generatedInterpreterKernelCandidatePe := by
  simp [parsePE32Tree, generatedInterpreterKernelMetadataParsed,
    PE32.metadata, PEMetadata.toPE32, generatedInterpreterKernelCandidatePe]

theorem generatedInterpreterKernelImportsChecked :
    importTableValid generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImportCertificate = true := by
  decide

theorem generatedInterpreterKernelCandidateDataLayoutExact :
    CandidateDataLayout.ofPE generatedInterpreterKernelCandidatePe =
      generatedInterpreterKernelCandidateDataLayout := by
  decide +kernel

{''.join(pack_certificates)}

def generatedInterpreterKernelCandidateBytePackCatalog :
    FiniteIndex
      (PEBytePackCertificate generatedInterpreterKernelCandidatePe) :=
  {catalog}

theorem generatedInterpreterKernelCandidateBytePackCatalogChecked :
    generatedInterpreterKernelCandidateBytePackCatalog.structurallyValid
      1 = true := by
  decide +kernel

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _candidate_authority_source() -> str:
    """Expose the exact candidate PE authority through a stable interface."""

    return f"""import StageA.{INTERPRETER_KERNEL_DATA_BASE}

namespace StageA.GeneratedRelational.CandidatePEAuthority

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelData
open StageA.Relational.PEBytePacks
open StageA.GeneratedRelational.InterpreterKernelData

abbrev candidateBytes : ByteTree :=
  generatedInterpreterKernelCandidateBytes

abbrev candidatePe : PE32 :=
  generatedInterpreterKernelCandidatePe

abbrev importCertificate : ImportTableCertificate :=
  generatedInterpreterKernelImportCertificate

abbrev imports : List PEImport :=
  generatedInterpreterKernelImports

theorem candidateMetadataParsed :
    parsePEMetadataTree candidateBytes = some candidatePe.metadata :=
  generatedInterpreterKernelMetadataParsed

theorem candidateParsed :
    parsePE32Tree candidateBytes = some candidatePe :=
  generatedInterpreterKernelCandidateParsed

theorem importsChecked :
    importTableValid candidatePe importCertificate = true :=
  generatedInterpreterKernelImportsChecked

abbrev candidateDataLayout : CandidateDataLayout :=
  generatedInterpreterKernelCandidateDataLayout

theorem candidateDataLayoutExact :
    CandidateDataLayout.ofPE candidatePe = candidateDataLayout :=
  generatedInterpreterKernelCandidateDataLayoutExact

abbrev candidateBytePackCatalog :
    FiniteIndex (PEBytePackCertificate candidatePe) :=
  generatedInterpreterKernelCandidateBytePackCatalog

theorem candidateBytePackCatalogChecked :
    candidateBytePackCatalog.structurallyValid 1 = true :=
  generatedInterpreterKernelCandidateBytePackCatalogChecked

end StageA.GeneratedRelational.CandidatePEAuthority
"""


def _lean_section_from_range(plan: _ByteRangePlan) -> str:
    return (
        "{ virtualSize := %d, virtualAddress := %d, rawSize := %d, "
        "rawPointer := %d, characteristics := %d }"
        % (
            plan.section_virtual_size,
            plan.section_virtual_address,
            plan.section_raw_size,
            plan.section_raw_pointer,
            plan.section_characteristics,
        )
    )


def _lean_candidate_data_layout(binary: Any) -> str:
    sections = ",\n    ".join(
        (
            "{ virtualSize := %d, virtualAddress := %d, rawSize := %d, "
            "rawPointer := %d, characteristics := %d }"
        )
        % (
            int(section.Misc_VirtualSize),
            int(section.VirtualAddress),
            int(section.SizeOfRawData),
            int(section.PointerToRawData),
            int(section.Characteristics),
        )
        for section in binary.pe.sections
    )
    return """{
  imageBase := %d
  sizeOfImage := %d
  sections := [
    %s
  ]
}""" % (
        int(binary.pe.OPTIONAL_HEADER.ImageBase),
        int(binary.pe.OPTIONAL_HEADER.SizeOfImage),
        sections,
    )


def _local_context_source(
    layout_source: str,
    table_rva: int,
    count_rva: int,
) -> str:
    return f"""import StageA.RelationalInterpreterKernelData

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.InterpreterKernelData

def generatedInterpreterKernelCandidateDataLayout : CandidateDataLayout :=
  {layout_source}

def generatedInterpreterKernelTableRva : Nat := {table_rva}
def generatedInterpreterKernelCountRva : Nat := {count_rva}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _unique_byte_range_plans(
    plans: Sequence[_ByteRangePlan],
) -> tuple[_ByteRangePlan, ...]:
    unique: dict[tuple[int, int], _ByteRangePlan] = {}
    for plan in plans:
        key = (plan.rva, plan.size)
        prior = unique.get(key)
        if prior is not None:
            if prior.expected_bytes != plan.expected_bytes:
                raise InterpreterKernelDataGenerationError(
                    "same immutable RVA range has conflicting expected bytes: "
                    f"0x{plan.rva:x}+0x{plan.size:x}"
                )
            continue
        unique[key] = plan
    return tuple(unique[key] for key in sorted(unique))


def _byte_slice_located_expression(slice_plan: _ByteSlicePlan) -> str:
    chunk = _byte_pack_chunk_definition(
        slice_plan.pack_index,
        slice_plan.chunk_index,
    )
    located = f"ByteTreePackAt.here (ByteTree.leaf {chunk})"
    for direction in reversed(slice_plan.chunk_path):
        located = (
            f"ByteTreePackAt.{direction} (by rfl) (by rfl) ({located})"
        )
    return located


def _local_byte_cache_source(
    pack_index: int,
    entry_offset: int,
    plans: Sequence[_ByteRangePlan],
) -> tuple[str, str, tuple[_ByteRangePlan, ...]]:
    ranges = _unique_byte_range_plans(plans)
    entry_stem = _certificate_entry_stem(pack_index, entry_offset)
    range_names: list[str] = []
    declarations: list[str] = []
    for range_index, plan in enumerate(ranges):
        name = f"{entry_stem}ByteRange{range_index:04d}"
        if plan.raw_count != len(plan.raw_bytes):
            raise InterpreterKernelDataGenerationError(
                "immutable byte range raw-count differs from its raw bytes: "
                f"0x{plan.rva:x}+0x{plan.size:x}"
            )
        expected = plan.raw_bytes + bytes(plan.size - plan.raw_count)
        if plan.expected_bytes != expected:
            raise InterpreterKernelDataGenerationError(
                "immutable byte range is not its exact raw bytes plus zero-fill: "
                f"0x{plan.rva:x}+0x{plan.size:x}"
            )
        cursor = 0
        slice_byte_names: list[str] = []
        for slice_index, slice_plan in enumerate(plan.slices):
            slice_stop = cursor + slice_plan.size
            slice_bytes = plan.raw_bytes[cursor:slice_stop]
            if len(slice_bytes) != slice_plan.size:
                raise InterpreterKernelDataGenerationError(
                    "immutable byte-range slice exceeds its raw-byte payload: "
                    f"0x{plan.rva:x}+0x{plan.size:x}"
                )
            slice_bytes_name = f"{name}RawSlice{slice_index:04d}Bytes"
            slice_exact_name = f"{name}RawSlice{slice_index:04d}Exact"
            slice_located_name = f"{name}RawSlice{slice_index:04d}ChunkLocated"
            pack = _byte_pack_definition(slice_plan.pack_index)
            chunk = _byte_pack_chunk_definition(
                slice_plan.pack_index,
                slice_plan.chunk_index,
            )
            if (
                slice_plan.pack_offset
                != slice_plan.chunk_offset + slice_plan.leaf_offset
                or slice_plan.leaf_offset + slice_plan.size
                > slice_plan.chunk_size
            ):
                raise InterpreterKernelDataGenerationError(
                    "immutable byte-range slice crosses its candidate byte chunk"
                )
            declarations.append(f"""
def {slice_bytes_name} : Bytes :=
  {_lean_bytes(slice_bytes)}

theorem {slice_located_name} :
    ByteTreePackAt {pack} {slice_plan.chunk_offset}
      (ByteTree.leaf {chunk}) := by
  unfold {pack}
  exact {_byte_slice_located_expression(slice_plan)}

theorem {slice_exact_name} :
    {pack}.readBytes {slice_plan.pack_offset} {slice_plan.size} =
      some {slice_bytes_name} := by
  have bounded :
      {slice_plan.leaf_offset} + {slice_plan.size} <= {chunk}.length := by
    decide +kernel
  calc
    {pack}.readBytes {slice_plan.pack_offset} {slice_plan.size} =
        (ByteTree.leaf {chunk}).readBytes
          {slice_plan.leaf_offset} {slice_plan.size} :=
      {slice_located_name}.readBytes_eq
        {slice_plan.leaf_offset} {slice_plan.size} bounded
    _ = some (
        ({chunk}.drop {slice_plan.leaf_offset}).take {slice_plan.size}) :=
      ByteTree.readBytes_leaf_eq_drop_take
        {chunk} {slice_plan.leaf_offset} {slice_plan.size} bounded
    _ = some {slice_bytes_name} := by
      decide +kernel
""")
            slice_byte_names.append(slice_bytes_name)
            cursor = slice_stop
        if cursor != plan.raw_count:
            raise InterpreterKernelDataGenerationError(
                "immutable byte-range slices do not cover its raw-byte payload: "
                f"0x{plan.rva:x}+0x{plan.size:x}"
            )
        raw_bytes_name = f"{name}RawBytes"
        raw_bytes = " ++ ".join([*slice_byte_names, "[]"])
        declarations.append(f"""
def {raw_bytes_name} : Bytes :=
  {raw_bytes}

noncomputable def {name} : ImmutableByteRange := {{
  rva := {plan.rva}
  size := {plan.size}
  bytes := {raw_bytes_name} ++
    List.replicate ({plan.size} - {plan.raw_count}) 0
}}
""")
        range_names.append(name)
    ranges_name = f"{entry_stem}ByteRanges"
    cache_name = f"{entry_stem}ByteCache"
    ranges_value = (
        f".leaf [{', '.join(range_names)}]" if range_names else ".empty"
    )
    declarations.append(f"""
noncomputable def {ranges_name} : FiniteIndex ImmutableByteRange :=
  {ranges_value}

noncomputable def {cache_name} : LocalImmutableByteCache := {{
  ranges := {ranges_name}
}}
""")
    return "".join(declarations), cache_name, ranges


def _byte_cache_source(
    pack_index: int,
    plans: Sequence[_ByteRangePlan],
) -> tuple[str, str]:
    unique: dict[tuple[int, int], _ByteRangePlan] = {}
    for plan in plans:
        unique.setdefault((plan.rva, plan.size), plan)
    ranges = tuple(unique.values())
    declarations: list[str] = []
    range_names: list[str] = []
    exact_names: list[str] = []
    for range_index, plan in enumerate(ranges):
        stem = (
            f"generatedInterpreterKernelDataCertificatePack{pack_index:04d}"
            f"ByteRange{range_index:04d}"
        )
        slice_names: list[str] = []
        cursor = plan.raw_offset
        for slice_index, slice_plan in enumerate(plan.slices):
            slice_name = f"{stem}Slice{slice_index:04d}"
            certificate = _byte_pack_certificate_definition(slice_plan.pack_index)
            pack = _byte_pack_definition(slice_plan.pack_index)
            length = _byte_pack_length_theorem(slice_plan.pack_index)
            declarations.append(f"""
def {slice_name} :
    PEBytePackSlice generatedInterpreterKernelCandidatePe := {{
  certificate := {certificate}
  offset := {slice_plan.pack_offset}
  size := {slice_plan.size}
  nonempty := by decide
  bounded := by
    change {slice_plan.pack_offset} + {slice_plan.size} <= {pack}.length
    rw [{length}]
    decide
}}
""")
            slice_names.append(slice_name)
            cursor += slice_plan.size
        slices_name = f"{stem}Slices"
        slices_value = "[" + ", ".join(slice_names) + "]"
        declarations.append(f"""
def {slices_name} : List
    (PEBytePackSlice generatedInterpreterKernelCandidatePe) :=
  {slices_value}
""")
        chain = f".nil {plan.raw_offset + plan.raw_count}"
        cursor = plan.raw_offset + plan.raw_count
        for slice_name, slice_plan in reversed(
            list(zip(slice_names, plan.slices, strict=True))
        ):
            cursor -= slice_plan.size
            chain = f".cons {slice_name} (by decide) ({chain})"
        chain_name = f"{stem}Chain"
        declarations.append(f"""
theorem {chain_name} :
    PEBytePackSliceChain generatedInterpreterKernelCandidatePe
      {plan.raw_offset} {plan.raw_count} {slices_name} := by
  unfold {slices_name}
  exact {chain}
""")
        range_name = stem
        exact_name = f"{stem}Exact"
        raw_bytes_name = f"{stem}RawBytes"
        slices_read_name = f"{stem}SlicesRead"
        declarations.append(f"""
def {raw_bytes_name} : Bytes :=
  (readPEBytePackSlices {slices_name}).getD []

def {range_name} : ImmutableByteRange := {{
  rva := {plan.rva}
  size := {plan.size}
  bytes := {raw_bytes_name} ++
    List.replicate {plan.size - plan.raw_count} 0
}}

theorem {slices_read_name} :
    readPEBytePackSlices {slices_name} = some {raw_bytes_name} := by
  decide +kernel

theorem {exact_name} :
    immutableRvaBytes generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports {plan.rva} {plan.size} =
        some {range_name}.bytes := by
  apply immutableRvaBytes_eq_slices
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    {_lean_section_from_range(plan)} {plan.rva} {plan.size} {plan.raw_count}
    {slices_name} {raw_bytes_name} {range_name}.bytes
  · decide +kernel
  · decide +kernel
  · decide +kernel
  · decide +kernel
  · exact {chain_name}
  · exact {slices_read_name}
  · rfl
""")
        range_names.append(range_name)
        exact_names.append(exact_name)

    ranges_name = (
        f"generatedInterpreterKernelDataCertificatePack{pack_index:04d}ByteRanges"
    )
    cache_name = (
        f"generatedInterpreterKernelDataCertificatePack{pack_index:04d}ByteCache"
    )
    authoritative_name = f"{ranges_name}Authoritative"
    ranges_list = ", ".join(range_names)
    alternatives = " | ".join(f"range = {name}" for name in range_names)
    cases = "\n  ".join(
        f"· subst range\n    exact {exact}" for exact in exact_names
    )
    if range_names:
        authoritative = f"""by
  intro range member
  change {alternatives} at member
  rcases member with {" | ".join("case" + str(i) for i in range(len(range_names)))}
  {cases}"""
        # Named rcases patterns are awkward for generated arity; a compact
        # simp disjunction keeps proof composition local and deterministic.
        authoritative = f"""by
  intro range member
  simp only [{ranges_name}, FiniteIndex.toList, List.mem_cons,
    List.not_mem_nil, or_false] at member
  rcases member with {" | ".join("h" + str(i) for i in range(len(range_names)))}
{chr(10).join(f'  · subst range\n    exact {exact}' for exact in exact_names)}"""
        ranges_value = f".leaf [{ranges_list}]"
    else:
        authoritative = "by intro range member; simp at member"
        ranges_value = ".empty"
    declarations.append(f"""
def {ranges_name} : FiniteIndex ImmutableByteRange :=
  {ranges_value}

theorem {authoritative_name} : forall range,
    range ∈ {ranges_name}.toList ->
      immutableRvaBytes generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports range.rva range.size =
          some range.bytes :=
  {authoritative}

def {cache_name} : ImmutableByteCache generatedInterpreterKernelCandidatePe
    generatedInterpreterKernelImports := {{
  ranges := {ranges_name}
  authoritative := {authoritative_name}
}}
""")
    return "".join(declarations), cache_name


def _certificate_pack_source(
    pack_index: int,
    start: int,
    shard_size: int,
    transfers: Sequence[Any],
    plans: Sequence[_TransferProofPlan],
    byte_ranges: Sequence[Sequence[_ByteRangePlan]],
) -> str:
    if (
        not transfers
        or len(transfers) != len(plans)
        or len(transfers) != len(byte_ranges)
    ):
        raise InterpreterKernelDataGenerationError(
            "certificate pack must contain matching nonempty transfer data"
        )
    byte_pack_indices = sorted(
        {
            slice_plan.pack_index
            for entry_ranges in byte_ranges
            for plan in entry_ranges
            for slice_plan in plan.slices
        }
    )
    byte_pack_imports = "\n".join(
        f"import StageA.{_byte_pack_name(index)}"
        for index in byte_pack_indices
    )
    definition = _certificate_pack_definition(pack_index)
    declarations: list[str] = []
    entry_names: list[str] = []
    for entry_offset, (transfer, plan, entry_ranges) in enumerate(
        zip(transfers, plans, byte_ranges, strict=True)
    ):
        entry_stem = _certificate_entry_stem(pack_index, entry_offset)
        data_name = f"{entry_stem}Data"
        entry_names.append(data_name)
        cache_source, cache, _ranges = _local_byte_cache_source(
            pack_index, entry_offset, entry_ranges
        )
        entry_index = start + entry_offset
        declarations.append(f"""{cache_source}

noncomputable def {data_name} : TransferCertificateData :=
  {_lean_certificate_data(transfer, plan)}

theorem {entry_stem}DescriptorDecoded
    (fallback : Nat -> Nat -> Option Bytes) :
    decodeTransferDescriptorFrom ({cache}.readWith fallback)
      generatedInterpreterKernelTableRva {entry_index} =
        some {data_name}.descriptor := by
  rfl

theorem {entry_stem}DescriptorValid :
    ((generatedInterpreterKernelTableRva +
      {entry_index} * transferRecordSize) % 4 == 0 &&
      {data_name}.descriptor.sourceRva < 2 ^ 32) = true := by
  decide

theorem {entry_stem}WordNodesDecoded
    (fallback : Nat -> Nat -> Option Bytes) :
    decodeNodeArrayFrom generatedInterpreterKernelCandidateDataLayout.asPE
      ({cache}.readWith fallback)
      (generatedInterpreterKernelTableRva +
        {entry_index} * transferRecordSize + 20)
      {data_name}.descriptor.wordPointer {data_name}.descriptor.wordCount
      wordNodeSize maxWordNodes =
        .ok {data_name}.wordNodes {data_name}.wordTrace := by
  rfl

theorem {entry_stem}X87NodesDecoded
    (fallback : Nat -> Nat -> Option Bytes) :
    decodeNodeArrayFrom generatedInterpreterKernelCandidateDataLayout.asPE
      ({cache}.readWith fallback)
      (generatedInterpreterKernelTableRva +
        {entry_index} * transferRecordSize + 24)
      {data_name}.descriptor.x87Pointer {data_name}.descriptor.x87Count
      x87NodeSize maxX87Nodes =
        .ok {data_name}.x87Nodes {data_name}.x87Trace := by
  rfl

theorem {entry_stem}ActionsDecoded
    (fallback : Nat -> Nat -> Option Bytes) :
    decodeActionArrayFrom generatedInterpreterKernelCandidateDataLayout.asPE
      ({cache}.readWith fallback)
      (generatedInterpreterKernelTableRva +
        {entry_index} * transferRecordSize + 28)
      {data_name}.descriptor.actionPointer {data_name}.descriptor.actionCount =
        .ok {data_name}.actions {data_name}.actionTrace := by
  rfl

theorem {entry_stem}CallsDecoded
    (fallback : Nat -> Nat -> Option Bytes) :
    decodeCallArrayFrom generatedInterpreterKernelCandidateDataLayout.asPE
      ({cache}.readWith fallback)
      (generatedInterpreterKernelTableRva +
        {entry_index} * transferRecordSize + 32)
      {data_name}.descriptor.callPointer
      (callCountFromActions {data_name}.actions) =
        .ok {data_name}.calls {data_name}.callTrace := by
  rfl

theorem {entry_stem}X87ReplaysDecoded
    (fallback : Nat -> Nat -> Option Bytes) :
    decodeX87ReplayArrayFrom generatedInterpreterKernelCandidateDataLayout.asPE
      ({cache}.readWith fallback)
      (generatedInterpreterKernelTableRva +
        {entry_index} * transferRecordSize + 36)
      {data_name}.descriptor.replayPointer {data_name}.descriptor.replayCount =
        .ok {data_name}.x87Replays {data_name}.replayTrace := by
  rfl

noncomputable def {entry_stem}LocalCertificate :
    TransferCertificateData.LocalCertificate
    generatedInterpreterKernelCandidateDataLayout
    generatedInterpreterKernelTableRva {entry_index} {data_name} {cache} := {{
  descriptorDecoded := {entry_stem}DescriptorDecoded
  descriptorValid := {entry_stem}DescriptorValid
  wordNodesDecoded := {entry_stem}WordNodesDecoded
  x87NodesDecoded := {entry_stem}X87NodesDecoded
  actionsDecoded := {entry_stem}ActionsDecoded
  callsDecoded := {entry_stem}CallsDecoded
  x87ReplaysDecoded := {entry_stem}X87ReplaysDecoded
}}
""")
    rows = ",\n  ".join(entry_names)
    return f"""import StageA.{INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT}
{byte_pack_imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelData
open StageA.Relational.PEBytePacks

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option compiler.extract_closed false
set_option Elab.async false

{''.join(declarations)}

noncomputable def {definition} : TransferCertificatePack := {{
  startIndex := {start}
  entries := (#[
  {rows}
  ] : Array TransferCertificateData)
}}

theorem {definition}IndexChecked :
    {definition}.indexChecked {start} {len(transfers)} {shard_size} = true := by
  decide +kernel

noncomputable def {definition}IndexCertificate :
    TransferCertificatePack.IndexCertificate
      {definition} {start} {len(transfers)} {shard_size} :=
  TransferCertificatePack.IndexCertificate.of_checked
    {definition} {start} {len(transfers)} {shard_size}
    {definition}IndexChecked

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _authority_ranges_source(
    pack_index: int,
    entry_offset: int,
    plans: Sequence[_ByteRangePlan],
) -> tuple[str, str]:
    ranges = _unique_byte_range_plans(plans)
    declarations: list[str] = []
    exact_names: list[str] = []
    range_evidence: list[
        tuple[
            _ByteRangePlan,
            str,
            str,
            str,
            str,
            str,
            str,
            str,
            str,
        ]
    ] = []
    entry_stem = _certificate_entry_stem(pack_index, entry_offset)
    for range_index, plan in enumerate(ranges):
        local_range = f"{entry_stem}ByteRange{range_index:04d}"
        stem = f"{local_range}Authority"
        slice_names: list[str] = []
        slice_read_names: list[str] = []
        for slice_index, slice_plan in enumerate(plan.slices):
            slice_name = f"{stem}Slice{slice_index:04d}"
            slice_read_name = f"{slice_name}Read"
            certificate = _byte_pack_certificate_definition(slice_plan.pack_index)
            pack = _byte_pack_definition(slice_plan.pack_index)
            length = _byte_pack_length_theorem(slice_plan.pack_index)
            local_slice_bytes = (
                f"{local_range}RawSlice{slice_index:04d}Bytes"
            )
            local_slice_exact = (
                f"{local_range}RawSlice{slice_index:04d}Exact"
            )
            declarations.append(f"""
def {slice_name} :
    PEBytePackSlice generatedInterpreterKernelCandidatePe := {{
  certificate := {certificate}
  offset := {slice_plan.pack_offset}
  size := {slice_plan.size}
  nonempty := by decide
  bounded := by
    change {slice_plan.pack_offset} + {slice_plan.size} <= {pack}.length
    rw [{length}]
    decide
}}

theorem {slice_read_name} :
    {slice_name}.bytes = some {local_slice_bytes} := by
  change {pack}.readBytes {slice_plan.pack_offset} {slice_plan.size} =
    some {local_slice_bytes}
  exact {local_slice_exact}
""")
            slice_names.append(slice_name)
            slice_read_names.append(slice_read_name)
        slices_name = f"{stem}Slices"
        declarations.append(f"""
def {slices_name} : List
    (PEBytePackSlice generatedInterpreterKernelCandidatePe) :=
  [{', '.join(slice_names)}]
""")
        chain = f".nil {plan.raw_offset + plan.raw_count}"
        for slice_name, slice_plan in reversed(
            list(zip(slice_names, plan.slices, strict=True))
        ):
            chain = f".cons {slice_name} (by decide) ({chain})"
        chain_name = f"{stem}Chain"
        raw_bytes_name = f"{local_range}RawBytes"
        slices_read_name = f"{stem}SlicesRead"
        metadata_plan_name = f"{stem}MetadataPlan"
        metadata_checked_name = f"{stem}MetadataChecked"
        metadata_certificate_name = f"{stem}MetadataCertificate"
        exact_name = f"{stem}Exact"
        slice_read_simp = ", ".join(slice_read_names)
        declarations.append(f"""
theorem {chain_name} :
    PEBytePackSliceChain generatedInterpreterKernelCandidatePe
      {plan.raw_offset} {plan.raw_count} {slices_name} := by
  unfold {slices_name}
  exact {chain}

theorem {slices_read_name} :
    readPEBytePackSlices {slices_name} = some {raw_bytes_name} := by
  simp only [{slices_name}, readPEBytePackSlices, {slice_read_simp}]
  rfl

def {metadata_plan_name} : ImmutableRangeMetadataPlan := {{
  sectionIndex := {plan.section_index}
  rawOffset := {plan.raw_offset}
  rawCount := {plan.raw_count}
}}
""")
        range_evidence.append(
            (
                plan,
                local_range,
                slices_name,
                chain_name,
                raw_bytes_name,
                slices_read_name,
                metadata_plan_name,
                metadata_checked_name,
                metadata_certificate_name,
            )
        )
        exact_names.append(exact_name)
    metadata_requests_name = f"{entry_stem}MetadataRequests"
    metadata_batch_checked_name = f"{entry_stem}MetadataBatchChecked"
    metadata_batch_certificate_name = (
        f"{entry_stem}MetadataBatchCertificate"
    )
    request_rows = ",\n  ".join(
        "{ rva := %d, size := %d, plan := %s }"
        % (plan.rva, plan.size, metadata_plan_name)
        for (
            plan,
            _local_range,
            _slices_name,
            _chain_name,
            _raw_bytes_name,
            _slices_read_name,
            metadata_plan_name,
            _metadata_checked_name,
            _metadata_certificate_name,
        ) in range_evidence
    )
    declarations.append(f"""
def {metadata_requests_name} : List ImmutableRangeMetadataRequest := [
  {request_rows}
]

theorem {metadata_batch_checked_name} :
    immutableRangeMetadataBatchChecked
      generatedInterpreterKernelCandidateDataLayout
      generatedInterpreterKernelImports {metadata_requests_name} = true := by
  decide +kernel

def {metadata_batch_certificate_name} :
    ImmutableRangeMetadataBatchCertificate
      generatedInterpreterKernelCandidateDataLayout
      generatedInterpreterKernelImports {metadata_requests_name} :=
  ImmutableRangeMetadataBatchCertificate.of_checked
    generatedInterpreterKernelCandidateDataLayout
    generatedInterpreterKernelImports {metadata_requests_name}
    {metadata_batch_checked_name}
""")
    for range_index, (
        plan,
        local_range,
        slices_name,
        chain_name,
        raw_bytes_name,
        slices_read_name,
        metadata_plan_name,
        metadata_checked_name,
        metadata_certificate_name,
    ) in enumerate(range_evidence):
        exact_name = f"{local_range}AuthorityExact"
        declarations.append(f"""
theorem {metadata_checked_name} :
    immutableRangeMetadataChecked
      generatedInterpreterKernelCandidateDataLayout
      generatedInterpreterKernelImports {local_range}
      {metadata_plan_name} = true := by
  change immutableRangeMetadataRequestChecked
    generatedInterpreterKernelCandidateDataLayout
    generatedInterpreterKernelImports
    {{ rva := {plan.rva}, size := {plan.size}, plan := {metadata_plan_name} }} =
      true
  simpa [{metadata_requests_name}] using
    {metadata_batch_certificate_name}.checkedAt
      ⟨{range_index}, by decide⟩

noncomputable def {metadata_certificate_name} :
    ImmutableRangeMetadataCertificate
      generatedInterpreterKernelCandidateDataLayout
      generatedInterpreterKernelImports {local_range}
      {metadata_plan_name} :=
  ImmutableRangeMetadataCertificate.of_checked
    generatedInterpreterKernelCandidateDataLayout
    generatedInterpreterKernelImports {local_range}
    {metadata_plan_name} {metadata_checked_name}

theorem {exact_name} :
    immutableRvaBytes generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports {plan.rva} {plan.size} =
        some {local_range}.bytes := by
  exact {metadata_certificate_name}.exact_of_slices
    generatedInterpreterKernelCandidateDataLayoutExact
    {slices_name} {chain_name} {raw_bytes_name} {slices_read_name} rfl
""")
    ranges_name = (
        f"{entry_stem}ByteRanges"
    )
    authoritative_name = f"{ranges_name}Authoritative"
    if exact_names:
        alternatives = " | ".join(
            f"range = {entry_stem}ByteRange{index:04d}"
            for index in range(len(exact_names))
        )
        authoritative = f"""by
  intro range member
  simp only [{ranges_name}, FiniteIndex.toList, List.mem_cons,
    List.not_mem_nil, or_false] at member
  rcases member with {" | ".join("h" + str(i) for i in range(len(exact_names)))}
{chr(10).join(f'  · subst range\n    exact {exact}' for exact in exact_names)}"""
    else:
        alternatives = "False"
        _ = alternatives
        authoritative = "by intro range member; simp at member"
    declarations.append(f"""
theorem {authoritative_name} : forall range,
    range ∈ {ranges_name}.toList ->
      immutableRvaBytes generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports range.rva range.size =
          some range.bytes :=
  {authoritative}
""")
    return "".join(declarations), authoritative_name


def _reflective_authority_ranges_source(
    pack_index: int,
    plans: Sequence[_ByteRangePlan],
) -> tuple[str, str]:
    ranges = _unique_byte_range_plans(plans)
    plan_rows: list[str] = []
    for plan in ranges:
        slices = ", ".join(
            "{ packIndex := %d, offset := %d, size := %d }"
            % (slice_plan.pack_index, slice_plan.pack_offset, slice_plan.size)
            for slice_plan in plan.slices
        )
        plan_rows.append(
            "{ sectionIndex := %d, rawOffset := %d, rawCount := %d, "
            "slices := [%s] }"
            % (
                plan.section_index,
                plan.raw_offset,
                plan.raw_count,
                slices,
            )
        )
    definition = _certificate_pack_definition(pack_index)
    ranges_name = f"{definition}ByteRanges"
    plans_name = f"{definition}ByteRangeBindingPlans"
    checked_name = f"{definition}ByteRangeBindingsChecked"
    certificate_name = f"{definition}ByteRangeBindingsCertificate"
    authoritative_name = f"{ranges_name}Authoritative"
    source = f"""
def {plans_name} : List ImmutableRangeBindingPlan := [
  {',\n  '.join(plan_rows)}
]

theorem {checked_name} :
    immutableRangeBindingsChecked generatedInterpreterKernelCandidateDataLayout
      generatedInterpreterKernelImports
      generatedInterpreterKernelCandidateBytePackCatalog
      {ranges_name}.toList {plans_name} = true := by
  decide +kernel

noncomputable def {certificate_name} :
    ImmutableRangeBindingsCertificate
      generatedInterpreterKernelCandidateDataLayout
      generatedInterpreterKernelImports
      generatedInterpreterKernelCandidateBytePackCatalog
      {ranges_name}.toList {plans_name} :=
  ImmutableRangeBindingsCertificate.of_checked
    generatedInterpreterKernelCandidateDataLayout
    generatedInterpreterKernelImports
    generatedInterpreterKernelCandidateBytePackCatalog
    {ranges_name}.toList {plans_name} {checked_name}

theorem {authoritative_name} : forall range,
    range ∈ {ranges_name}.toList ->
      immutableRvaBytes generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports range.rva range.size =
          some range.bytes :=
  {certificate_name}.all_exact
    generatedInterpreterKernelCandidateDataLayoutExact
"""
    return source, authoritative_name


def _reflective_authority_ranges_source(
    pack_index: int,
    entry_offset: int,
    plans: Sequence[_ByteRangePlan],
) -> tuple[str, str]:
    ranges = _unique_byte_range_plans(plans)
    entry_stem = _certificate_entry_stem(pack_index, entry_offset)
    ranges_name = f"{entry_stem}ByteRanges"
    plans_name = f"{entry_stem}ByteBindingPlans"
    checked_name = f"{entry_stem}ByteBindingsChecked"
    certificate_name = f"{entry_stem}ByteBindingCertificate"
    authoritative_name = f"{entry_stem}ByteRangesAuthoritative"
    rows: list[str] = []
    for plan in ranges:
        slices = ", ".join(
            "{ packIndex := %d, offset := %d, size := %d }"
            % (item.pack_index, item.pack_offset, item.size)
            for item in plan.slices
        )
        rows.append(
            "{ sectionIndex := %d, rawOffset := %d, rawCount := %d, "
            "slices := [%s] }"
            % (
                plan.section_index,
                plan.raw_offset,
                plan.raw_count,
                slices,
            )
        )
    return (
        f"""
def {plans_name} : List ImmutableRangeBindingPlan := [
  {',\n  '.join(rows)}
]

theorem {checked_name} :
    immutableRangeBindingsChecked generatedInterpreterKernelCandidateDataLayout
      generatedInterpreterKernelImports
      generatedInterpreterKernelCandidateBytePackCatalog
      {ranges_name}.toList {plans_name} = true := by
  decide +kernel

noncomputable def {certificate_name} : ImmutableRangeBindingsCertificate
    generatedInterpreterKernelCandidateDataLayout
    generatedInterpreterKernelImports
    generatedInterpreterKernelCandidateBytePackCatalog
    {ranges_name}.toList {plans_name} :=
  ImmutableRangeBindingsCertificate.of_checked
    generatedInterpreterKernelCandidateDataLayout
    generatedInterpreterKernelImports
    generatedInterpreterKernelCandidateBytePackCatalog
    {ranges_name}.toList {plans_name} {checked_name}

theorem {authoritative_name} : forall range,
    range ∈ {ranges_name}.toList ->
      immutableRvaBytes generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports range.rva range.size =
          some range.bytes :=
  {certificate_name}.all_exact
    generatedInterpreterKernelCandidateDataLayoutExact
""",
        authoritative_name,
    )


def _authority_source(
    certificate_pack_count: int,
    shard_size: int,
    transfer_count: int,
    byte_ranges_by_pack: Sequence[Sequence[_ByteRangePlan]],
) -> str:
    imports = "\n".join(
        [
            f"import StageA.{INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE}",
            *(
                f"import StageA.{_certificate_pack_name(index)}"
                for index in range(certificate_pack_count)
            ),
        ]
    )
    bodies: list[str] = []
    shard_names: list[str] = []
    for index, ranges in enumerate(byte_ranges_by_pack):
        definition = _certificate_pack_definition(index)
        cache = f"{definition}ByteCache"
        range_source, ranges_authoritative = (
            _reflective_authority_ranges_source(index, ranges)
        )
        relocation_authoritative = f"{definition}RelocationsAuthoritative"
        exact_certificate = f"{definition}ExactCertificate"
        many_certificate = f"{definition}ManyCertificate"
        range_certificate = f"{definition}RangeCertificate"
        values = f"{definition}Values"
        relocations = f"{definition}Relocations"
        shard = f"{definition}Shard"
        shard_names.append(shard)
        bodies.append(f"""
{range_source}

theorem {relocation_authoritative} :
    (transferCertificateDataListTrace
      {definition}.entries.toList).relocationFieldsChecked
        generatedInterpreterKernelRelocations = true :=
  ({{
    relocated := RelocationPresenceCertificate.of_indexed
      generatedInterpreterKernelRelocationIndexCertificate
      (transferCertificateDataListTrace
        {definition}.entries.toList).relocatedPointerFields (by decide +kernel)
    zero := RelocationAbsenceCertificate.of_indexed
      generatedInterpreterKernelRelocationIndexCertificate
      (transferCertificateDataListTrace
        {definition}.entries.toList).zeroPointerFields (by decide +kernel)
  }} : LayoutTraceRelocationCertificate
    (transferCertificateDataListTrace {definition}.entries.toList)
      generatedInterpreterKernelRelocations).checked

noncomputable def {exact_certificate} :
    LayoutMExactCertificate
      (decodeManyAux (fun entryIndex => decodeTransferAt
        generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
        generatedInterpreterKernelTableRva entryIndex)
        {definition}.startIndex {definition}.entries.toList.length)
      ({definition}.entries.toList.map TransferCertificateData.compiled)
      generatedInterpreterKernelRelocations :=
  {definition}LocalCertificate.exactCertificate
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedInterpreterKernelRelocations
    generatedInterpreterKernelCandidateDataLayoutExact
    {ranges_authoritative} {relocation_authoritative}

noncomputable def {many_certificate} :
    LayoutMExactCertificate
      (decodeMany {definition}.entries.toList.length fun offset =>
        decodeTransferAt generatedInterpreterKernelCandidatePe
          generatedInterpreterKernelImports generatedInterpreterKernelTableRva
          ({definition}.startIndex + offset))
      ({definition}.entries.toList.map TransferCertificateData.compiled)
      generatedInterpreterKernelRelocations := by
  simpa only [decodeMany_shift] using {exact_certificate}

noncomputable def {range_certificate} :
    LayoutMExactCertificate
      (decodeProgramTableRange generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports generatedInterpreterKernelTableRva
        {definition}.startIndex {definition}.entries.toList.length)
      ({definition}.entries.toList.map TransferCertificateData.compiled)
      generatedInterpreterKernelRelocations :=
  decodeProgramTableRangeCertificate generatedInterpreterKernelCandidatePe
    generatedInterpreterKernelImports generatedInterpreterKernelTableRva
    {definition}.startIndex {definition}.entries.toList.length
    ({definition}.entries.toList.map TransferCertificateData.compiled)
    generatedInterpreterKernelRelocations (by decide) {many_certificate}

theorem {values} :
    (decodeProgramTableRange generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelTableRva
      {definition}.startIndex {definition}.entries.toList.length).value? =
        some ({definition}.entries.toList.map TransferCertificateData.compiled) :=
  {range_certificate}.value?_eq

theorem {relocations} :
    (match (decodeProgramTableRange generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelTableRva
      {definition}.startIndex {definition}.entries.toList.length).trace? with
    | none => false
    | some trace => trace.relocationsChecked
        generatedInterpreterKernelRelocations) = true :=
  {range_certificate}.relocationsChecked
    generatedInterpreterKernelRelocationsLinearChecked
    generatedInterpreterKernelRelocationInventoryUnique

def {shard} : ProgramTableShardCertificate
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedInterpreterKernelRelocations generatedInterpreterKernelTableRva := {{
  startIndex := {definition}.startIndex
  entries := {definition}.entries.toList.map TransferCertificateData.compiled
  nonempty := by decide
  decoded := {values}
  relocationFieldsChecked := {relocations}
}}
""")
    pack0 = _certificate_pack_definition(0)
    count_authority = f"{pack0}ByteRangesAuthoritative"
    shards = ",\n  ".join(shard_names)
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelData
open StageA.Relational.PEBytePacks

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option compiler.extract_closed false
set_option Elab.async false

{''.join(bodies)}

theorem generatedInterpreterKernelTransferCount :
    readCompiledTransferCount generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelCountRva =
        some {transfer_count} := by
  rw [readCompiledTransferCount]
  rw [<- {_certificate_pack_definition(0)}ByteCache.readWith_eq_fallback
    (immutableRvaBytes generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports) {count_authority}]
  decide +kernel

def generatedInterpreterKernelDataShards : List
    (ProgramTableShardCertificate generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva) := [
  {shards}
]

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _packed_authority_source(
    authority_pack_index: int,
    pack_indices: Sequence[int],
    shard_size: int,
    transfer_count: int,
    byte_ranges_by_pack: Sequence[Sequence[Sequence[_ByteRangePlan]]],
    source_rvas_by_pack: Sequence[Sequence[int]],
) -> str:
    imports = "\n".join(
        [
            f"import StageA.{INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE}",
            *(
                f"import StageA.{_certificate_pack_name(index)}"
                for index in pack_indices
            ),
        ]
    )
    bodies: list[str] = []
    shard_names: list[str] = []
    for pack_index in pack_indices:
        definition = _certificate_pack_definition(pack_index)
        start = pack_index * shard_size
        entry_ranges = byte_ranges_by_pack[pack_index]
        entry_count = len(entry_ranges)
        source_rvas = source_rvas_by_pack[pack_index]
        if len(source_rvas) != entry_count:
            raise InterpreterKernelDataGenerationError(
                "authority pack source-RVA inventory differs from its entries"
            )
        data_names = [
            f"{_certificate_entry_stem(pack_index, offset)}Data"
            for offset in range(entry_count)
        ]
        exact_names: list[str] = []
        for entry_offset, ranges in enumerate(entry_ranges):
            entry_stem = _certificate_entry_stem(pack_index, entry_offset)
            data_name = f"{entry_stem}Data"
            cache = f"{entry_stem}ByteCache"
            range_source, ranges_authoritative = (
                _authority_ranges_source(
                    pack_index, entry_offset, ranges
                )
            )
            relocation_authoritative = f"{entry_stem}RelocationsAuthoritative"
            exact_certificate = f"{entry_stem}ExactCertificate"
            exact_names.append(exact_certificate)
            entry_index = start + entry_offset
            bodies.append(f"""
{range_source}

theorem {relocation_authoritative} :
    {data_name}.trace.relocationFieldsChecked
      generatedInterpreterKernelRelocations = true :=
  ({{
    relocated := RelocationPresenceCertificate.of_indexed
      generatedInterpreterKernelRelocationIndexCertificate
      {data_name}.trace.relocatedPointerFields (by decide +kernel)
    zero := RelocationAbsenceCertificate.of_indexed
      generatedInterpreterKernelRelocationIndexCertificate
      {data_name}.trace.zeroPointerFields (by decide +kernel)
  }} : LayoutTraceRelocationCertificate {data_name}.trace
    generatedInterpreterKernelRelocations).checked

noncomputable def {exact_certificate} :
    LayoutMExactCertificate
      (decodeTransferAt generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports generatedInterpreterKernelTableRva
        {entry_index})
      {data_name}.compiled generatedInterpreterKernelRelocations :=
  {entry_stem}LocalCertificate.exactCertificate
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedInterpreterKernelRelocations
    generatedInterpreterKernelCandidateDataLayoutExact
    {ranges_authoritative} {relocation_authoritative}
""")

        decode = """(fun entryIndex => decodeTransferAt
        generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
        generatedInterpreterKernelTableRva entryIndex)"""
        tail = (
            "decodeManyAuxNilCertificate "
            f"{decode} {start + entry_count} generatedInterpreterKernelRelocations"
        )
        for entry_offset in reversed(range(entry_count)):
            remaining = entry_count - entry_offset - 1
            tail = (
                "decodeManyAuxConsCertificate "
                f"{decode} {start + entry_offset} {remaining} "
                "generatedInterpreterKernelRelocations "
                f"{exact_names[entry_offset]} ({tail})"
            )
        compiled_entries = _certificate_pack_compiled_entries_definition(
            pack_index
        )
        exact_certificate = f"{definition}ExactCertificate"
        many_certificate = f"{definition}ManyCertificate"
        range_certificate = f"{definition}RangeCertificate"
        values = f"{definition}Values"
        relocations = f"{definition}Relocations"
        shard = _certificate_pack_shard_definition(pack_index)
        source_rvas_definition = _certificate_pack_source_rvas_definition(
            pack_index
        )
        metadata_definition = _certificate_pack_metadata_definition(pack_index)
        shard_names.append(shard)
        bodies.append(f"""
noncomputable def {compiled_entries} : List CompiledProgramRecord := [
  {',\n  '.join(f'{name}.compiled' for name in data_names)}
]

theorem {definition}EntriesExact :
    {definition}.entries.toList.map TransferCertificateData.compiled =
      {compiled_entries} := by
  have _ := {definition}IndexCertificate.exact
  rfl

noncomputable def {exact_certificate} :
    LayoutMExactCertificate
      (decodeManyAux {decode} {start} {entry_count})
      {compiled_entries} generatedInterpreterKernelRelocations := by
  unfold {compiled_entries}
  exact {tail}

noncomputable def {many_certificate} :
    LayoutMExactCertificate
      (decodeMany {entry_count} fun offset =>
        decodeTransferAt generatedInterpreterKernelCandidatePe
          generatedInterpreterKernelImports generatedInterpreterKernelTableRva
          ({start} + offset))
      {compiled_entries} generatedInterpreterKernelRelocations := by
  simpa only [decodeMany_shift] using {exact_certificate}

noncomputable def {range_certificate} :
    LayoutMExactCertificate
      (decodeProgramTableRange generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports generatedInterpreterKernelTableRva
        {start} {entry_count})
      {compiled_entries} generatedInterpreterKernelRelocations :=
  decodeProgramTableRangeCertificate generatedInterpreterKernelCandidatePe
    generatedInterpreterKernelImports generatedInterpreterKernelTableRva
    {start} {entry_count} {compiled_entries}
    generatedInterpreterKernelRelocations (by decide) {many_certificate}

theorem {values} :
    (decodeProgramTableRange generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelTableRva
      {start} {entry_count}).value? = some {compiled_entries} :=
  {range_certificate}.value?_eq

theorem {relocations} :
    (match (decodeProgramTableRange generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelTableRva
      {start} {entry_count}).trace? with
    | none => false
    | some trace => trace.relocationsChecked
        generatedInterpreterKernelRelocations) = true :=
  {range_certificate}.relocationsChecked
    generatedInterpreterKernelRelocationsLinearChecked
    generatedInterpreterKernelRelocationInventoryUnique

noncomputable def {shard} : ProgramTableShardCertificate
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedInterpreterKernelRelocations generatedInterpreterKernelTableRva := {{
  startIndex := {start}
  entries := {compiled_entries}
  nonempty := by decide
  decoded := {values}
  relocationFieldsChecked := {relocations}
}}

def {source_rvas_definition} : List Nat :=
  {_lean_nat_list(source_rvas)}

theorem {definition}SourceRvasExact :
    {shard}.records.map (fun record => record.sourceRva) =
      {source_rvas_definition} := by
  rfl

def {metadata_definition} :
    ProgramTableShardMetadataCertificate {shard}
      {start} {entry_count} {source_rvas_definition} := {{
  startIndexExact := rfl
  entryCountExact := rfl
  sourceRvasExact := {definition}SourceRvasExact
}}
""")

    count_source = ""
    if pack_indices and pack_indices[0] == 0:
        entry_stem = _certificate_entry_stem(0, 0)
        count_source = f"""
theorem generatedInterpreterKernelTransferCount :
    readCompiledTransferCount generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelCountRva =
        some {transfer_count} := by
  rw [readCompiledTransferCount]
  rw [<- {entry_stem}ByteCache.readWith_eq_fallback
    (immutableRvaBytes generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports) {entry_stem}ByteRangesAuthoritative]
  decide +kernel
"""
    shards = ",\n  ".join(shard_names)
    authority_definition = _authority_pack_definition(authority_pack_index)
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelData
open StageA.Relational.PEBytePacks

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option compiler.extract_closed false
set_option Elab.async false

{''.join(bodies)}

{count_source}

noncomputable def {authority_definition} : List
    (ProgramTableShardCertificate generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva) := [
  {shards}
]

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _nested_and_projection(root: str, index: int, count: int) -> str:
    if not 0 <= index < count:
        raise InterpreterKernelDataGenerationError(
            "native projection index is outside its pack"
        )
    if count == 1:
        return root
    if index == count - 1:
        return root + ".2" * index
    return root + ".2" * index + ".1"


def _byte_range_index(
    plans: Sequence[_ByteRangePlan],
    *,
    rva: int,
    size: int,
    label: str,
) -> int:
    ranges = _unique_byte_range_plans(plans)
    matches = [
        index
        for index, plan in enumerate(ranges)
        if plan.rva == rva and plan.size == size
    ]
    if len(matches) != 1:
        raise InterpreterKernelDataGenerationError(
            f"{label} does not identify one local immutable byte range: "
            f"0x{rva:x}+0x{size:x}"
        )
    return matches[0]


def _finite_index_membership_proof(index: int, count: int) -> str:
    if not 0 <= index < count:
        raise InterpreterKernelDataGenerationError(
            "local immutable byte range index is outside its finite index"
        )
    proof = "True.intro" if index == count - 1 else "Or.inl True.intro"
    for _ in range(index):
        proof = f"Or.inr ({proof})"
    return proof


def _native_projection_pack_source(
    pack_index: int,
    authority_pack_index: int,
    start: int,
    table_rva: int,
    image_base: int,
    plans: Sequence[_TransferProofPlan],
    byte_ranges: Sequence[Sequence[_ByteRangePlan]],
) -> str:
    entry_count = len(plans)
    if entry_count <= 0:
        raise InterpreterKernelDataGenerationError(
            "native projection pack must contain at least one transfer"
        )
    if entry_count != len(byte_ranges):
        raise InterpreterKernelDataGenerationError(
            "native projection plans and byte ranges differ in length"
        )
    checks: list[str] = []
    entry_theorems: list[str] = []
    for entry_offset, (plan, entry_ranges) in enumerate(
        zip(plans, byte_ranges, strict=True)
    ):
        entry_index = start + entry_offset
        entry_stem = _certificate_entry_stem(pack_index, entry_offset)
        data_name = f"{entry_stem}Data"
        ranges_name = f"{entry_stem}ByteRanges"
        range_count = len(_unique_byte_range_plans(entry_ranges))
        descriptor_range_index = _byte_range_index(
            entry_ranges,
            rva=table_rva + entry_index * _TRANSFER_RECORD_SIZE,
            size=_TRANSFER_RECORD_SIZE,
            label=f"transfer {entry_index} descriptor",
        )
        if plan.descriptor.action_count <= 0:
            raise InterpreterKernelDataGenerationError(
                f"transfer {entry_index} has no native action array"
            )
        action_rva = _pointer_target_rva(
            plan.descriptor.action_pointer,
            image_base,
            f"transfer {entry_index} action array",
        )
        action_range_index = _byte_range_index(
            entry_ranges,
            rva=action_rva,
            size=plan.descriptor.action_count * _ACTION_SIZE,
            label=f"transfer {entry_index} action array",
        )
        descriptor_range = (
            f"{entry_stem}ByteRange{descriptor_range_index:04d}"
        )
        action_range = f"{entry_stem}ByteRange{action_range_index:04d}"
        authoritative = f"{entry_stem}ByteRangesAuthoritative"
        descriptor_exact = f"{entry_stem}NativeDescriptorRangeExact"
        action_exact = f"{entry_stem}NativeActionRangeExact"
        theorem_name = f"{entry_stem}NativeTransferActionsChecked"
        loaded_name = f"{entry_stem}LoadedTransferActions"
        check = (
            "transferActionsRangesChecked "
            "generatedInterpreterKernelCandidatePe "
            f"generatedInterpreterKernelTableRva {entry_index} {data_name}"
            f" {descriptor_range} {action_range}"
        )
        checks.append(f"{check} = true")
        descriptor_member = _finite_index_membership_proof(
            descriptor_range_index, range_count
        )
        action_member = _finite_index_membership_proof(
            action_range_index, range_count
        )
        entry_theorems.append(
            f"""
theorem {descriptor_exact} :
    immutableRvaBytes generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports {descriptor_range}.rva
        {descriptor_range}.size = some {descriptor_range}.bytes :=
  {authoritative} {descriptor_range} (by
    unfold {ranges_name}
    simp only [FiniteIndex.toList, List.mem_cons, List.not_mem_nil, or_false]
    exact {descriptor_member})

theorem {action_exact} :
    immutableRvaBytes generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports {action_range}.rva
        {action_range}.size = some {action_range}.bytes :=
  {authoritative} {action_range} (by
    unfold {ranges_name}
    simp only [FiniteIndex.toList, List.mem_cons, List.not_mem_nil, or_false]
    exact {action_member})

theorem {theorem_name} :
    {check} = true :=
  by rfl

noncomputable def {loaded_name} (memory : Memory)
    (loaded : LoadedCandidateImageMemory generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      memory) :
    LoadedTransferActionsAt generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelTableRva {entry_index} {data_name} memory :=
  LoadedTransferActionsAt.of_ranges_checked loaded {descriptor_exact}
    {action_exact} {theorem_name}
"""
        )
    conjunction = "\n    ∧ ".join(checks)
    checked_name = _native_projection_pack_checked_theorem(pack_index)
    theorem_names = [
        _certificate_entry_stem(pack_index, entry_offset)
        + "NativeTransferActionsChecked"
        for entry_offset in range(entry_count)
    ]
    conjunction_proof = theorem_names[-1]
    for theorem_name in reversed(theorem_names[:-1]):
        conjunction_proof = f"⟨{theorem_name}, {conjunction_proof}⟩"
    return f"""import StageA.RelationalInterpreterKernelProgramTableProjection
import StageA.{_authority_pack_name(authority_pack_index)}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelProgramTableProjection

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option compiler.extract_closed false
set_option Elab.async false

{''.join(entry_theorems)}

theorem {checked_name} :
    {conjunction} := by
  exact {conjunction_proof}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _global_authority_source(authority_pack_count: int) -> str:
    imports = "\n".join(
        f"import StageA.{_authority_pack_name(index)}"
        for index in range(authority_pack_count)
    )
    shards = " ++\n  ".join(
        _authority_pack_definition(index)
        for index in range(authority_pack_count)
    )
    inclusion_theorems: list[str] = []
    for index in range(authority_pack_count):
        if authority_pack_count == 1:
            membership = "member"
        else:
            alternatives = "Or.inl member"
            if index == authority_pack_count - 1:
                alternatives = "member"
            for _ in range(index):
                alternatives = f"Or.inr ({alternatives})"
            membership = alternatives
        inclusion_theorems.append(
            f"""
theorem {_authority_pack_included_theorem(index)}
    (shard : ProgramTableShardCertificate
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva)
    (member : shard ∈ {_authority_pack_definition(index)}) :
    shard ∈ generatedInterpreterKernelDataShards := by
  unfold generatedInterpreterKernelDataShards
  {"simp only [List.mem_append]" if authority_pack_count > 1 else ""}
  exact {membership}
"""
        )
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.InterpreterKernelData

noncomputable def generatedInterpreterKernelDataShards : List
    (ProgramTableShardCertificate generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva) :=
  {shards}

{''.join(inclusion_theorems)}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _pointer_field_source(proof: _PointerFieldProof) -> str:
    predicate = "relocationFieldPresent" if proof.present else "relocationFieldAbsent"
    return f"""import StageA.{INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {_pointer_field_theorem(proof.index)} :
    {predicate} generatedInterpreterKernelRelocations {proof.field_rva} = true := by
  decide +kernel

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _descriptor_source(index: int, descriptor: _TransferDescriptor) -> str:
    definition = _descriptor_definition(index)
    return f"""import StageA.{INTERPRETER_KERNEL_DATA_BASE}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def {definition} : TransferDescriptor :=
  {_lean_descriptor(descriptor)}

theorem {definition}Decoded :
    decodeTransferDescriptor generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelTableRva
      {index} = some {definition} := by
  decide +kernel

theorem {definition}Valid :
    ((generatedInterpreterKernelTableRva + {index} * transferRecordSize) % 4 == 0 &&
      {definition}.sourceRva < 2 ^ 32) = true := by
  decide

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _field_certificate_term(
    fields: Sequence[int],
    *,
    present: bool,
    pointer_fields: dict[tuple[int, bool], _PointerFieldProof],
) -> str:
    certificate = (
        "RelocationPresenceCertificate"
        if present
        else "RelocationAbsenceCertificate"
    )
    term = f"{certificate}.nil"
    for field_rva in reversed(fields):
        proof = pointer_fields[(field_rva, present)]
        term = (
            f"{certificate}.cons {_pointer_field_theorem(proof.index)} "
            f"({term})"
        )
    return term


def _component_source(
    index: int,
    component: str,
    transfer: Any,
    trace: _TraceProposal,
    pointer_fields: dict[tuple[int, bool], _PointerFieldProof],
) -> str:
    imports = [_descriptor_name(index)]
    if component == "Calls":
        imports.append(_component_name(index, "Actions"))
    imports.extend(
        _pointer_field_name(pointer_fields[(field_rva, present)].index)
        for present, fields in ((True, trace.relocated), (False, trace.zero))
        for field_rva in fields
    )
    import_lines = "\n".join(
        f"import StageA.{name}" for name in dict.fromkeys(imports)
    )
    stem = _component_stem(index, component)
    value_type, value_source = _component_value_source(component, transfer)
    decode = _component_decode_expression(index, component)
    relocated = _field_certificate_term(
        trace.relocated, present=True, pointer_fields=pointer_fields
    )
    zero = _field_certificate_term(
        trace.zero, present=False, pointer_fields=pointer_fields
    )
    return f"""{import_lines}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def {stem} : {value_type} :=
  {value_source}

def {stem}Trace : LayoutTrace :=
  {_lean_trace(trace)}

theorem {stem}Decoded :
    {decode} = .ok {stem} {stem}Trace := by
  decide +kernel

def {stem}RelocationFields :
    LayoutTraceRelocationCertificate {stem}Trace
      generatedInterpreterKernelRelocations := {{
  relocated := {relocated}
  zero := {zero}
}}

def {stem}Certificate :
    LayoutMExactCertificate ({decode}) {stem}
      generatedInterpreterKernelRelocations := {{
  trace := {stem}Trace
  decodedExact := {stem}Decoded
  relocationFields := {stem}RelocationFields
}}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _right_trace_append(names: Sequence[str]) -> str:
    if not names:
        return "({} : LayoutTrace)"
    if len(names) == 1:
        return names[0]
    return f"{names[0]}.append ({_right_trace_append(names[1:])})"


def _right_certificate_append(names: Sequence[str]) -> str:
    if not names:
        raise AssertionError("record composition requires component certificates")
    if len(names) == 1:
        return f"{names[0]}.relocationFields"
    return (
        f"{names[0]}.relocationFields.append "
        f"({_right_certificate_append(names[1:])})"
    )


def _record_source(index: int) -> str:
    import_lines = "\n".join(
        f"import StageA.{_component_name(index, component)}"
        for component in _COMPONENTS
    )
    descriptor = _descriptor_definition(index)
    stems = [_component_stem(index, component) for component in _COMPONENTS]
    word, x87, actions, calls, replays = stems
    record = _record_definition(index)
    trace = f"{record}Trace"
    trace_expression = _right_trace_append([f"{stem}Trace" for stem in stems])
    fields_expression = _right_certificate_append(
        [f"{stem}Certificate" for stem in stems]
    )
    return f"""{import_lines}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000

def {record} : CompiledProgramRecord := {{
  record := {{
    sourceRva := {descriptor}.sourceRva
    wordNodes := {word}
    x87Nodes := {x87}
    calls := {calls}
    actions := {actions}
  }}
  x87Replays := {replays}
}}

def {trace} : LayoutTrace :=
  {trace_expression}

theorem {record}Decoded :
    decodeTransferAt generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelTableRva
      {index} = .ok {record} {trace} := by
  exact decodeTransferAt_eq_of_components
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedInterpreterKernelTableRva {index} {descriptor}
    {word} {x87} {actions} {calls} {replays}
    {word}Trace {x87}Trace {actions}Trace {calls}Trace {replays}Trace
    {descriptor}Decoded {descriptor}Valid
    {word}Decoded {x87}Decoded {actions}Decoded {calls}Decoded {replays}Decoded

def {record}RelocationFields :
    LayoutTraceRelocationCertificate {trace}
      generatedInterpreterKernelRelocations :=
  {fields_expression}

def {record}Certificate :
    LayoutMExactCertificate
      (decodeTransferAt generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports generatedInterpreterKernelTableRva
        {index}) {record} generatedInterpreterKernelRelocations := {{
  trace := {trace}
  decodedExact := {record}Decoded
  relocationFields := {record}RelocationFields
}}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _shard_source(index: int, start: int, count: int) -> str:
    imports = "\n".join(
        f"import StageA.{_record_name(record_index)}"
        for record_index in range(start, start + count)
    )
    decode = (
        "fun offset => decodeTransferAt generatedInterpreterKernelCandidatePe "
        "generatedInterpreterKernelImports generatedInterpreterKernelTableRva "
        f"({start} + offset)"
    )
    entries_from = lambda local: (
        f"generatedInterpreterKernelDataEntries{index:04d}From{local:04d}"
    )
    certificate_from = lambda local: (
        f"generatedInterpreterKernelDataCertificate{index:04d}From{local:04d}"
    )
    declarations = [f"""def {entries_from(count)} : List CompiledProgramRecord := []

def {certificate_from(count)} :
    LayoutMExactCertificate (decodeManyAux ({decode}) {count} 0)
      {entries_from(count)} generatedInterpreterKernelRelocations :=
  decodeManyAuxNilCertificate ({decode}) {count}
    generatedInterpreterKernelRelocations
"""]
    for local in reversed(range(count)):
        remaining = count - local
        record_index = start + local
        record = _record_definition(record_index)
        declarations.append(f"""def {entries_from(local)} : List CompiledProgramRecord :=
  {record} :: {entries_from(local + 1)}

def {certificate_from(local)} :
    LayoutMExactCertificate (decodeManyAux ({decode}) {local} {remaining})
      {entries_from(local)} generatedInterpreterKernelRelocations :=
  decodeManyAuxConsCertificate ({decode}) {local} {remaining - 1}
    generatedInterpreterKernelRelocations {record}Certificate
    {certificate_from(local + 1)}
""")
    suffixes = "\n".join(declarations)
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{suffixes}

def generatedInterpreterKernelDataEntries{index:04d} :
    List CompiledProgramRecord := {entries_from(0)}

def generatedInterpreterKernelDataDecode{index:04d} :=
  decodeProgramTableRange generatedInterpreterKernelCandidatePe
    generatedInterpreterKernelImports generatedInterpreterKernelTableRva
    {start} {count}

def generatedInterpreterKernelDataManyCertificate{index:04d} :
    LayoutMExactCertificate
      (decodeMany {count} ({decode}))
      generatedInterpreterKernelDataEntries{index:04d}
      generatedInterpreterKernelRelocations := by
  simpa [decodeMany] using {certificate_from(0)}

def generatedInterpreterKernelDataCertificate{index:04d} :
    LayoutMExactCertificate generatedInterpreterKernelDataDecode{index:04d}
      generatedInterpreterKernelDataEntries{index:04d}
      generatedInterpreterKernelRelocations :=
  decodeProgramTableRangeCertificate generatedInterpreterKernelCandidatePe
    generatedInterpreterKernelImports generatedInterpreterKernelTableRva
    {start} {count} generatedInterpreterKernelDataEntries{index:04d}
    generatedInterpreterKernelRelocations (by decide)
    generatedInterpreterKernelDataManyCertificate{index:04d}

theorem generatedInterpreterKernelDataValues{index:04d} :
    generatedInterpreterKernelDataDecode{index:04d}.value? =
      some generatedInterpreterKernelDataEntries{index:04d} :=
  generatedInterpreterKernelDataCertificate{index:04d}.value?_eq

theorem generatedInterpreterKernelDataRelocations{index:04d} :
    (match generatedInterpreterKernelDataDecode{index:04d}.trace? with
    | none => false
    | some trace =>
        trace.relocationsChecked generatedInterpreterKernelRelocations) = true :=
  generatedInterpreterKernelDataCertificate{index:04d}.relocationsChecked
    generatedInterpreterKernelRelocationsLinearChecked
    generatedInterpreterKernelRelocationInventoryUnique

def generatedInterpreterKernelDataShard{index:04d} :
    ProgramTableShardCertificate generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva := {{
  startIndex := {start}
  entries := generatedInterpreterKernelDataEntries{index:04d}
  nonempty := by decide
  decoded := generatedInterpreterKernelDataValues{index:04d}
  relocationFieldsChecked := generatedInterpreterKernelDataRelocations{index:04d}
}}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _bundle_source(certificate_pack_count: int, transfer_count: int) -> str:
    shards = [
        _certificate_pack_shard_definition(index)
        for index in range(certificate_pack_count)
    ]
    metadata = [
        _certificate_pack_metadata_definition(index)
        for index in range(certificate_pack_count)
    ]
    source_rvas = [
        _certificate_pack_source_rvas_definition(index)
        for index in range(certificate_pack_count)
    ]
    source_rvas_expression = "[]"
    metadata_chain = f"ProgramTableShardMetadataChain.nil {transfer_count}"
    for source_rvas_definition, metadata_definition in reversed(
        list(zip(source_rvas, metadata, strict=True))
    ):
        source_rvas_expression = (
            f"{source_rvas_definition} ++ ({source_rvas_expression})"
        )
        metadata_chain = (
            "ProgramTableShardMetadataChain.cons "
            f"{metadata_definition} ({metadata_chain})"
        )
    direct_shards = ",\n  ".join(shards)
    return f"""import StageA.{INTERPRETER_KERNEL_DATA_AUTHORITY}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

/-- The semantic program is derived from the exact PE-decoded shard records,
not from a manifest hash or a generated status. -/
noncomputable def semanticInterpreterProgramRecords : List ProgramRecord :=
  decodedShardRecords generatedInterpreterKernelDataShards

/- The global carrier below composes compact shard metadata.  It intentionally
does not normalize all semantic record trees merely to recover starts, counts,
or source RVAs. -/
noncomputable def generatedInterpreterKernelDataDirectShards : List
    (ProgramTableShardCertificate generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva) := [
  {direct_shards}
]

theorem generatedInterpreterKernelDataDirectShardsExact :
    generatedInterpreterKernelDataShards =
      generatedInterpreterKernelDataDirectShards := by
  rfl

def generatedInterpreterKernelSourceRvas : List Nat :=
  {source_rvas_expression}

noncomputable def generatedInterpreterKernelShardMetadataChain :
    ProgramTableShardMetadataChain generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva 0
      generatedInterpreterKernelDataDirectShards
      generatedInterpreterKernelSourceRvas {transfer_count} := by
  unfold generatedInterpreterKernelDataDirectShards
    generatedInterpreterKernelSourceRvas
  exact {metadata_chain}

theorem semanticInterpreterProgramSourceRvasExact :
    semanticInterpreterProgramRecords.map (fun record => record.sourceRva) =
      generatedInterpreterKernelSourceRvas := by
  unfold semanticInterpreterProgramRecords
  rw [generatedInterpreterKernelDataDirectShardsExact]
  exact generatedInterpreterKernelShardMetadataChain.sourceRvasExact

theorem semanticInterpreterProgramSourceRvasIncreasing :
    strictlyIncreasing generatedInterpreterKernelSourceRvas = true := by
  decide +kernel

theorem semanticInterpreterProgramSourceRvasUnique :
    (semanticInterpreterProgramRecords.map
      (fun record => record.sourceRva)).Nodup := by
  rw [semanticInterpreterProgramSourceRvasExact]
  exact strictlyIncreasing_nodup
    semanticInterpreterProgramSourceRvasIncreasing

theorem generatedInterpreterKernelShardsCover :
    shardCoverageEnd 0 generatedInterpreterKernelDataShards =
      some {transfer_count} := by
  rw [generatedInterpreterKernelDataDirectShardsExact]
  exact generatedInterpreterKernelShardMetadataChain.coverage

noncomputable def generatedInterpreterKernelDataCertificate :
    ProgramTableCertificate generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
      semanticInterpreterProgramRecords := {{
  transferCount := {transfer_count}
  countDecoded := generatedInterpreterKernelTransferCount
  relocationsParsed := generatedInterpreterKernelRelocationsParsed
  shards := generatedInterpreterKernelDataShards
  shardsCover := generatedInterpreterKernelShardsCover
  semanticRecordsExact := rfl
  sourceRvasUnique := semanticInterpreterProgramSourceRvasUnique
}}

theorem semanticInterpreterProgramLookupAgreesWithCandidateTable
    (sourceRva : Nat) :
    lookupProgramRecord semanticInterpreterProgramRecords sourceRva =
      lookupProgramRecord
        (decodedShardRecords generatedInterpreterKernelDataShards) sourceRva :=
  generatedInterpreterKernelDataCertificate.semantic_lookup_is_compiled_lookup
    sourceRva

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _semantic_record_pack_source(
    pack_index: int,
    authority_pack_index: int,
    entries: Sequence[tuple[int, int]],
) -> str:
    shard = _certificate_pack_shard_definition(pack_index)
    authority_pack = _authority_pack_definition(authority_pack_index)
    shard_member = (
        f"generatedInterpreterKernelSemanticRecordPack{pack_index:04d}"
        "ShardMember"
    )
    records: list[str] = []
    for entry_offset, source_rva in entries:
        entry = f"{_certificate_entry_stem(pack_index, entry_offset)}Data.compiled.record"
        definition = _semantic_record_definition(pack_index, entry_offset)
        checked = f"{definition}Checked"
        records.append(
            f"""
theorem {checked} : {entry}.checked = true := by
  decide +kernel

noncomputable def {definition} :
    CheckedSemanticProgramRecord semanticInterpreterProgramRecords
      {source_rva} :=
  ProgramTableCertificate.checkedSemanticRecordOfShardMember
      generatedInterpreterKernelDataCertificate
      {shard} {entry} {source_rva}
      {shard_member}
      (by
        unfold ProgramTableShardCertificate.records {shard}
          {_certificate_pack_compiled_entries_definition(pack_index)}
        simp)
      (by rfl)
      {checked}
"""
        )
    return f"""import StageA.{INTERPRETER_KERNEL_DATA_BUNDLE}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {shard_member} :
    {shard} ∈ generatedInterpreterKernelDataCertificate.shards := by
  apply {_authority_pack_included_theorem(authority_pack_index)}
  unfold {authority_pack}
  simp

{''.join(records)}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _semantic_record_bundle_source(module_names: Sequence[str]) -> str:
    imports = "\n".join(
        f"import StageA.{name}" for name in module_names
    )
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelData

/-!
Stable import boundary for exact PE-backed, lookup-bound semantic records.
Every record was checked once in its local table shard; consumers compose the
opaque checked handles exported by the pack modules.
-/

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _action_cursor_pack_source(
    pack_index: int,
    start: int,
    entries: Sequence[tuple[int, int]],
) -> str:
    definitions: list[str] = []
    for entry_offset, _source_rva in entries:
        entry_stem = _certificate_entry_stem(pack_index, entry_offset)
        data_name = f"{entry_stem}Data"
        semantic_name = _semantic_record_definition(pack_index, entry_offset)
        loaded_name = f"{entry_stem}LoadedTransferActions"
        definition = _loaded_semantic_transfer_definition(
            pack_index, entry_offset
        )
        entry_index = start + entry_offset
        definitions.append(
            f"""
noncomputable def {definition} (memory : Memory)
    (loaded : LoadedCandidateImageMemory generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      memory) :
    CheckedLoadedSemanticTransfer generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelTableRva {entry_index} {data_name}
      semanticInterpreterProgramRecords memory := {{
  semantic := {semantic_name}
  recordExact := rfl
  sourceIndexExact := by
    rw [semanticInterpreterProgramSourceRvasExact]
    decide +kernel
  loaded := {loaded_name} memory loaded
}}
"""
        )
    return f"""import StageA.RelationalInterpreterKernelActionAlignment
import StageA.{_native_projection_pack_name(pack_index)}
import StageA.{_semantic_record_pack_name(pack_index)}

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelActionCursor

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option compiler.extract_closed false
set_option Elab.async false

{''.join(definitions)}

end StageA.GeneratedRelational.InterpreterKernelData
"""


def _named_module_bundle_source(module_names: Sequence[str]) -> str:
    return "\n".join(f"import StageA.{name}" for name in module_names) + "\n"


def _module_row(
    name: str,
    source: str,
    *,
    role: str,
    resources: tuple[str, int],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    encoded = source.encode("utf-8")
    row = {
        "name": name,
        "role": role,
        "imports": _LEAN_IMPORT.findall(source),
        "source_bytes": len(encoded),
        "source_sha256": sha256_bytes(encoded),
        "resource_class": resources[0],
        "estimated_memory_mb": resources[1],
    }
    if extra is not None:
        row.update(extra)
    return row


def _topological_pack_order(
    members: Sequence[str], imports: dict[str, tuple[str, ...]]
) -> list[str]:
    member_set = set(members)
    pending = {
        module: {dependency for dependency in imports[module]
                 if dependency in member_set}
        for module in members
    }
    ordered: list[str] = []
    while pending:
        ready = sorted(
            module for module, dependencies in pending.items()
            if not dependencies
        )
        if not ready:
            raise InterpreterKernelDataGenerationError(
                "generated Lean build pack contains an import cycle"
            )
        for module in ready:
            ordered.append(module)
            del pending[module]
        for dependencies in pending.values():
            dependencies.difference_update(ready)
    return ordered


def _write_module_build_packs(
    destination: Path,
    kernel_modules: Sequence[str],
    modules: Sequence[dict[str, Any]],
    certificate_packs_per_authority: int,
) -> None:
    rows = {str(row["name"]): row for row in modules}
    imports: dict[str, tuple[str, ...]] = {}
    for module in kernel_modules:
        source = destination / "StageA" / f"{module}.lean"
        imports[module] = tuple(_LEAN_IMPORT.findall(source.read_text()))
    for name, row in rows.items():
        imports[name] = tuple(str(value) for value in row["imports"])

    assignments: dict[str, str] = {
        module: f"kernel-{module}" for module in kernel_modules
    }
    for name, row in rows.items():
        role = str(row["role"])
        if role == "candidate-byte-pack":
            suffix = int(name.removeprefix(INTERPRETER_KERNEL_DATA_BYTE_PACK_PREFIX))
            pack = f"candidate-bytes-{suffix // 8:04d}"
        elif role == "candidate-local-data-context":
            pack = "candidate-local-context"
        elif role in {"candidate-pe-binding", "candidate-pe-authority-facade"}:
            pack = "candidate-pe-root"
        elif role == "candidate-relocation-entry-pack":
            suffix = int(
                name.removeprefix(INTERPRETER_KERNEL_DATA_RELOCATION_PACK_PREFIX)
            )
            pack = f"candidate-relocation-entries-{suffix // 8:04d}"
        elif role == "candidate-relocation-block":
            suffix = int(
                name.removeprefix(INTERPRETER_KERNEL_DATA_RELOCATION_BLOCK_PREFIX)
            )
            pack = f"candidate-relocation-blocks-{suffix // 8:04d}"
        elif role in {"candidate-relocation-chain", "candidate-relocation-bundle"}:
            pack = "candidate-relocation-closure"
        elif role == "transfer-certificate-pack":
            suffix = int(
                name.removeprefix(INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX)
            )
            pack = (
                "transfer-native-authority-"
                f"{suffix // certificate_packs_per_authority:04d}"
            )
        elif role == "candidate-data-authority-pack":
            suffix = int(
                name.removeprefix(INTERPRETER_KERNEL_DATA_AUTHORITY_PACK_PREFIX)
            )
            pack = f"transfer-native-authority-{suffix:04d}"
        elif role == "candidate-data-native-projection-pack":
            suffix = int(
                name.removeprefix(
                    INTERPRETER_KERNEL_DATA_NATIVE_PROJECTION_PACK_PREFIX
                )
            )
            pack = f"transfer-native-projection-{suffix:04d}"
        elif role == "candidate-data-shard-facade":
            suffix = int(
                name.removeprefix(INTERPRETER_KERNEL_DATA_SHARD_FACADE_PREFIX)
            )
            pack = f"transfer-shard-facade-{suffix // 16:04d}"
        elif role in {
            "candidate-data-global-authority",
            "transfer-table-bundle",
        }:
            pack = "transfer-table-global"
        elif role == "checked-semantic-record-pack":
            suffix = int(
                name.removeprefix(INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_PACK_PREFIX)
            )
            pack = f"semantic-records-{suffix // 8:04d}"
        elif role == "checked-semantic-record-bundle":
            pack = "semantic-records-global"
        elif role == "checked-action-cursor-pack":
            suffix = int(
                name.removeprefix(
                    INTERPRETER_KERNEL_DATA_ACTION_CURSOR_PACK_PREFIX
                )
            )
            pack = f"action-cursors-{suffix // 8:04d}"
        elif role == "checked-action-cursor-bundle":
            pack = "action-cursors-global"
        else:
            raise InterpreterKernelDataGenerationError(
                f"generated Lean module role lacks a build-pack policy: {role}"
            )
        assignments[name] = pack

    packs: dict[str, list[str]] = {}
    for module, pack in assignments.items():
        packs.setdefault(pack, []).append(module)
    ordered_packs = {
        pack: _topological_pack_order(members, imports)
        for pack, members in sorted(packs.items())
    }
    write_json(
        destination / "module-build-packs.json",
        {
            "format": "stage-a-lean-build-packs-v1",
            "modules": dict(sorted(assignments.items())),
            "packs": ordered_packs,
        },
    )


def _copy_kernel_closure(
    destination: Path, source_root: Path | None = None
) -> tuple[str, ...]:
    if source_root is None:
        source_root = Path(__file__).parents[2] / "lean/StageA"
    pending = [
        "RelationalInterpreterKernelActionAlignment",
        "RelationalInterpreterKernelData",
        "RelationalInterpreterKernelProgramTableProjection",
    ]
    copied: set[str] = set()
    while pending:
        module = pending.pop()
        if module in copied:
            continue
        source = source_root / f"{module}.lean"
        if not source.is_file():
            raise InterpreterKernelDataGenerationError(
                f"Lean kernel dependency is missing: {source}"
            )
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(module)
        pending.extend(_LEAN_IMPORT.findall(text))
    return tuple(sorted(copied))


def generate_interpreter_kernel_data_bundle(
    *,
    candidate_pe: Path | str,
    linker_map: Path | str,
    state_machine: Path | str,
    out_dir: Path | str,
    shard_size: int = INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE,
    byte_pack_size: int = INTERPRETER_KERNEL_DATA_BYTE_PACK_SIZE,
    relocation_pack_size: int = INTERPRETER_KERNEL_DATA_RELOCATION_PACK_SIZE,
    lean_source_root: Path | str | None = None,
) -> InterpreterKernelDataInventory:
    """Emit a cacheable exact-layout proof graph for one interpreter candidate."""

    candidate_path = Path(candidate_pe)
    map_path = Path(linker_map)
    state_machine_path = Path(state_machine)
    destination = Path(out_dir)
    if shard_size <= 0:
        raise InterpreterKernelDataGenerationError("shard size must be positive")
    if shard_size > _AUTHORITY_TRANSFER_LIMIT:
        raise InterpreterKernelDataGenerationError(
            "shard size exceeds the bounded authority transfer limit "
            f"({_AUTHORITY_TRANSFER_LIMIT})"
        )
    if byte_pack_size <= 0:
        raise InterpreterKernelDataGenerationError(
            "candidate byte pack size must be positive"
        )
    if relocation_pack_size <= 0:
        raise InterpreterKernelDataGenerationError(
            "candidate relocation pack size must be positive"
        )
    for path, label in (
        (candidate_path, "candidate PE"),
        (map_path, "linker map"),
        (state_machine_path, "state machine"),
    ):
        if not path.is_file() or path.is_symlink():
            raise InterpreterKernelDataGenerationError(
                f"{label} is not a regular file: {path}"
            )

    transfers = compile_stage_b_interpreter_program(state_machine_path)
    if not transfers:
        raise InterpreterKernelDataGenerationError("semantic interpreter program is empty")

    binary = _parse_stage_a_pe(candidate_path)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise InterpreterKernelDataGenerationError(
                "compiled interpreter data requires an i386 PE32 candidate"
            )
        symbols = _load_symbols(map_path, binary)
        table_rva = _unique_symbol(symbols, "stage_b_program_transfers")
        count_rva = _unique_symbol(symbols, "stage_b_program_transfer_count")
        if table_rva % 4 or count_rva % 4:
            raise InterpreterKernelDataGenerationError(
                "compiled interpreter table symbols are not uint32-aligned"
            )
        count_bytes = bytes(binary.pe.get_data(count_rva, 4))
        if len(count_bytes) != 4 or struct.unpack("<I", count_bytes)[0] != len(transfers):
            raise InterpreterKernelDataGenerationError(
                "candidate transfer count differs from the static semantic program"
            )
        table_bytes = bytes(
            binary.pe.get_data(table_rva, len(transfers) * _TRANSFER_RECORD_SIZE)
        )
        if len(table_bytes) != len(transfers) * _TRANSFER_RECORD_SIZE:
            raise InterpreterKernelDataGenerationError(
                "candidate transfer table is truncated"
            )
        image_base = int(binary.pe.OPTIONAL_HEADER.ImageBase)
        transfer_plans = tuple(
            _transfer_proof_plan(
                index=index,
                table_rva=table_rva,
                image_base=image_base,
                transfer=transfer,
                descriptor_bytes=table_bytes[
                    index * _TRANSFER_RECORD_SIZE :
                    (index + 1) * _TRANSFER_RECORD_SIZE
                ],
            )
            for index, transfer in enumerate(transfers)
        )
        pointer_field_proofs, _ = _pointer_field_proofs(transfer_plans)

        candidate_bytes = candidate_path.read_bytes()
        byte_pack_ranges = _byte_pack_ranges(len(candidate_bytes), byte_pack_size)
        transfer_byte_ranges = _transfer_byte_range_plans(
            binary,
            candidate_bytes,
            byte_pack_ranges,
            table_rva,
            count_rva,
            transfers,
            transfer_plans,
        )
        relocation_blocks = _relocation_blocks(binary)
        relocation_chunks = _relocation_chunks(
            relocation_blocks, relocation_pack_size
        )
        relocation_chunk_packs = _relocation_chunk_packs(
            relocation_chunks, relocation_pack_size
        )
        relocation_directory_size = int(
            binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
        )
        local_context = _local_context_source(
            _lean_candidate_data_layout(binary), table_rva, count_rva
        )
        base = _base_source(
            binary,
            byte_pack_ranges,
            table_rva,
            count_rva,
        )
    finally:
        binary.pe.close()

    stage_a = destination / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    kernel_modules = _copy_kernel_closure(
        stage_a,
        Path(lean_source_root) if lean_source_root is not None else None,
    )
    modules: list[dict[str, Any]] = []

    local_context_path = stage_a / f"{INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT}.lean"
    local_context_path.write_text(local_context, encoding="utf-8")
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT,
            local_context,
            role="candidate-local-data-context",
            resources=_LIGHT_RESOURCES,
        )
    )

    byte_pack_names: list[str] = []
    for index, (offset, size) in enumerate(byte_pack_ranges):
        name = _byte_pack_name(index)
        pack_bytes = candidate_bytes[offset : offset + size]
        source = _byte_pack_source(index, pack_bytes)
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        byte_pack_names.append(name)
        modules.append(
            _module_row(
                name,
                source,
                role="candidate-byte-pack",
                resources=_BYTE_PACK_RESOURCES,
                extra={
                    "candidate_offset": offset,
                    "candidate_bytes": size,
                    "candidate_sha256": sha256_bytes(pack_bytes),
                },
            )
        )

    relocation_pack_names: list[str] = []
    chunks_by_block: dict[int, list[tuple[int, str, _RelocationChunk]]] = {
        index: [] for index in range(len(relocation_blocks))
    }
    for pack_index, pack in enumerate(relocation_chunk_packs):
        name = _relocation_pack_name(pack_index)
        source = _relocation_pack_source(
            tuple(
                (
                    chunk_index,
                    relocation_blocks[chunk.block_index],
                    chunk,
                )
                for chunk_index, chunk in pack
            )
        )
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        relocation_pack_names.append(name)
        modules.append(
            _module_row(
                name,
                source,
                role="candidate-relocation-entry-pack",
                resources=_LIGHT_RESOURCES,
                extra={
                    "relocation_block_indices": sorted(
                        {chunk.block_index for _, chunk in pack}
                    ),
                    "relocation_chunk_count": len(pack),
                    "relocation_entry_count": sum(
                        len(chunk.raw_entries) for _, chunk in pack
                    ),
                    "relocation_count": sum(
                        len(chunk.relocations) for _, chunk in pack
                    ),
                },
            )
        )
        for chunk_index, chunk in pack:
            chunks_by_block[chunk.block_index].append(
                (chunk_index, name, chunk)
            )

    block_bindings: list[tuple[int, _RelocationBlock, str, str, str]] = []
    for index, block in enumerate(relocation_blocks):
        block_chunks = chunks_by_block[index]
        if len(block_chunks) == 1:
            chunk_index, module_name, _chunk = block_chunks[0]
            definition = _relocation_pack_definition(chunk_index)
            theorem = f"{definition}Parsed"
        else:
            module_name = _relocation_block_name(index)
            definition = _relocation_block_definition(index)
            theorem = _relocation_block_theorem(index)
            source = _relocation_block_source(
                index,
                block,
                block_chunks,
            )
            (stage_a / f"{module_name}.lean").write_text(
                source, encoding="utf-8"
            )
            modules.append(
                _module_row(
                    module_name,
                    source,
                    role="candidate-relocation-block",
                    resources=_LIGHT_RESOURCES,
                    extra={
                        "relocation_directory_offset": block.offset,
                        "relocation_block_size": block.block_size,
                        "relocation_entry_count": block.entry_count,
                        "relocation_count": len(block.relocations),
                        "relocation_chunk_count": len(block_chunks),
                    },
                )
            )
        block_bindings.append(
            (index, block, definition, theorem, module_name)
        )

    relocation_chain_names: list[str] = []
    for chain_index, start in enumerate(
        range(0, len(block_bindings), INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PACK_SIZE)
    ):
        bindings = block_bindings[
            start : start + INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PACK_SIZE
        ]
        name = _relocation_chain_name(chain_index)
        source = _relocation_chain_source(
            chain_index,
            bindings,
            block_count=len(relocation_blocks),
            relocation_directory_size=relocation_directory_size,
        )
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        modules.append(
            _module_row(
                name,
                source,
                role="candidate-relocation-chain",
                resources=_LIGHT_RESOURCES,
                extra={
                    "relocation_block_start": start,
                    "relocation_block_count": len(bindings),
                },
            )
        )
        relocation_chain_names.append(name)

    relocation_index_parts: list[tuple[int, int, str]] = []
    for pack in relocation_chunk_packs:
        relocations = tuple(
            relocation
            for _chunk_index, chunk in pack
            for relocation in chunk.relocations
        )
        if not relocations:
            continue
        definitions = [
            _relocation_pack_definition(chunk_index)
            for chunk_index, _chunk in pack
        ]
        value = " ++ ".join(definitions)
        if len(definitions) > 1:
            value = f"({value})"
        relocation_index_parts.append(
            (relocations[0][0], len(relocations), value)
        )
    relocation_bundle = _relocation_bundle_source(
        len(relocation_blocks), relocation_index_parts, relocation_pack_size,
        relocation_directory_size
    )
    (stage_a / f"{INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE}.lean").write_text(
        relocation_bundle, encoding="utf-8"
    )
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE,
            relocation_bundle,
            role="candidate-relocation-bundle",
            resources=_RELOCATION_BUNDLE_RESOURCES,
        )
    )

    base_path = stage_a / f"{INTERPRETER_KERNEL_DATA_BASE}.lean"
    base_path.write_text(base, encoding="utf-8")
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_BASE,
            base,
            role="candidate-pe-binding",
            resources=_PE_ROOT_RESOURCES,
        )
    )

    candidate_authority = _candidate_authority_source()
    candidate_authority_path = (
        stage_a / f"{INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY}.lean"
    )
    candidate_authority_path.write_text(
        candidate_authority, encoding="utf-8"
    )
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY,
            candidate_authority,
            role="candidate-pe-authority-facade",
            resources=_LIGHT_RESOURCES,
            extra={
                "candidate_sha256": sha256_bytes(candidate_bytes),
                "authority_namespace": (
                    "StageA.GeneratedRelational.CandidatePEAuthority"
                ),
            },
        )
    )

    certificate_pack_names: list[str] = []
    byte_ranges_by_pack: list[tuple[tuple[_ByteRangePlan, ...], ...]] = []
    source_rvas_by_pack: list[tuple[int, ...]] = []
    for index, start in enumerate(range(0, len(transfers), shard_size)):
        name = _certificate_pack_name(index)
        pack_transfers = transfers[start : start + shard_size]
        pack_plans = transfer_plans[start : start + shard_size]
        pack_byte_ranges = tuple(
            transfer_byte_ranges[start : start + shard_size]
        )
        source = _certificate_pack_source(
            index,
            start,
            shard_size,
            pack_transfers,
            pack_plans,
            pack_byte_ranges,
        )
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        certificate_pack_names.append(name)
        byte_ranges_by_pack.append(pack_byte_ranges)
        source_rvas_by_pack.append(
            tuple(plan.descriptor.source_rva for plan in pack_plans)
        )
        modules.append(
            _module_row(
                name,
                source,
                role="transfer-certificate-pack",
                resources=_CERTIFICATE_PACK_RESOURCES,
                extra={
                    "transfer_start": start,
                    "transfer_count": len(pack_transfers),
                    "boolean_certificate_count": len(pack_transfers) + 1,
                    "pack_boolean_certificate_count": 1,
                    "local_decode_certificate_count": len(pack_transfers),
                    "byte_range_count": len(
                        {
                            (plan.rva, plan.size)
                            for entry_ranges in pack_byte_ranges
                            for plan in entry_ranges
                        }
                    ),
                    "pointer_field_count": sum(
                        len(trace.relocated) + len(trace.zero)
                        for plan in pack_plans
                        for trace in plan.component_traces
                    ),
                },
            )
        )

    authority_pack_names: list[str] = []
    certificate_packs_per_authority = max(
        1, _AUTHORITY_TRANSFER_LIMIT // shard_size
    )
    for authority_index, pack_start in enumerate(
        range(
            0,
            len(certificate_pack_names),
            certificate_packs_per_authority,
        )
    ):
        pack_indices = tuple(
            range(
                pack_start,
                min(
                    pack_start + certificate_packs_per_authority,
                    len(certificate_pack_names),
                ),
            )
        )
        name = _authority_pack_name(authority_index)
        source = _packed_authority_source(
            authority_index,
            pack_indices,
            shard_size,
            len(transfers),
            byte_ranges_by_pack,
            source_rvas_by_pack,
        )
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        authority_pack_names.append(name)
        modules.append(
            _module_row(
                name,
                source,
                role="candidate-data-authority-pack",
                resources=_AUTHORITY_PACK_RESOURCES,
                extra={
                    "certificate_pack_start": pack_start,
                    "certificate_pack_count": len(pack_indices),
                    "metadata_certificate_count": len(pack_indices),
                    "authority_transfer_limit": _AUTHORITY_TRANSFER_LIMIT,
                    "transfer_start": pack_start * shard_size,
                    "transfer_count": sum(
                        len(byte_ranges_by_pack[index])
                        for index in pack_indices
                    ),
                    "source_rva_count": sum(
                        len(source_rvas_by_pack[index])
                        for index in pack_indices
                    ),
                    "byte_range_count": sum(
                        len(_unique_byte_range_plans(entry_ranges))
                        for index in pack_indices
                        for entry_ranges in byte_ranges_by_pack[index]
                    ),
                },
            )
        )

    native_projection_pack_names: list[str] = []
    for pack_index, pack_ranges in enumerate(byte_ranges_by_pack):
        authority_index = pack_index // certificate_packs_per_authority
        name = _native_projection_pack_name(pack_index)
        source = _native_projection_pack_source(
            pack_index,
            authority_index,
            pack_index * shard_size,
            table_rva,
            image_base,
            transfer_plans[
                pack_index * shard_size : pack_index * shard_size + len(pack_ranges)
            ],
            pack_ranges,
        )
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        native_projection_pack_names.append(name)
        modules.append(
            _module_row(
                name,
                source,
                role="candidate-data-native-projection-pack",
                resources=_AUTHORITY_PACK_RESOURCES,
                extra={
                    "certificate_pack_index": pack_index,
                    "authority_pack_index": authority_index,
                    "transfer_start": pack_index * shard_size,
                    "transfer_count": len(pack_ranges),
                    "boolean_certificate_count": len(pack_ranges),
                },
            )
        )

    for pack_index in range(len(certificate_pack_names)):
        authority_index = pack_index // certificate_packs_per_authority
        name = _shard_facade_name(pack_index)
        source = _shard_facade_source(pack_index, authority_index)
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        modules.append(
            _module_row(
                name,
                source,
                role="candidate-data-shard-facade",
                resources=_LIGHT_RESOURCES,
                extra={
                    "certificate_pack_index": pack_index,
                    "authority_pack_index": authority_index,
                    "proof_authority": False,
                },
            )
        )

    authority = _global_authority_source(len(authority_pack_names))
    (stage_a / f"{INTERPRETER_KERNEL_DATA_AUTHORITY}.lean").write_text(
        authority, encoding="utf-8"
    )
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_AUTHORITY,
            authority,
            role="candidate-data-global-authority",
            resources=_MEDIUM_RESOURCES,
            extra={
                "transfer_pack_count": len(certificate_pack_names),
                "authority_pack_count": len(authority_pack_names),
                "authority_transfer_limit": _AUTHORITY_TRANSFER_LIMIT,
                "metadata_certificate_count": len(certificate_pack_names),
                "byte_range_count": sum(
                    len(_unique_byte_range_plans(entry_ranges))
                    for pack_ranges in byte_ranges_by_pack
                    for entry_ranges in pack_ranges
                ),
                "candidate_sha256": sha256_bytes(candidate_bytes),
            },
        )
    )

    bundle = _bundle_source(len(certificate_pack_names), len(transfers))
    (stage_a / f"{INTERPRETER_KERNEL_DATA_BUNDLE}.lean").write_text(
        bundle, encoding="utf-8"
    )
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_BUNDLE,
            bundle,
            role="transfer-table-bundle",
            resources=_MEDIUM_RESOURCES,
        )
    )

    semantic_record_pack_names: list[str] = []
    semantic_entries_by_pack: dict[
        int, tuple[tuple[int, int], ...]
    ] = {}
    semantic_record_count = 0
    for pack_index, source_rvas in enumerate(source_rvas_by_pack):
        start = pack_index * shard_size
        pack_transfers = transfers[start : start + shard_size]
        semantic_entries = tuple(
            (entry_offset, source_rva)
            for entry_offset, (source_rva, transfer) in enumerate(
                zip(source_rvas, pack_transfers, strict=True)
            )
            if not transfer.x87_replays
        )
        if not semantic_entries:
            continue
        semantic_entries_by_pack[pack_index] = semantic_entries
        authority_index = pack_index // certificate_packs_per_authority
        name = _semantic_record_pack_name(pack_index)
        source = _semantic_record_pack_source(
            pack_index,
            authority_index,
            semantic_entries,
        )
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        semantic_record_pack_names.append(name)
        modules.append(
            _module_row(
                name,
                source,
                role="checked-semantic-record-pack",
                resources=_LIGHT_RESOURCES,
                extra={
                    "certificate_pack_index": pack_index,
                    "authority_pack_index": authority_index,
                    "semantic_record_count": len(semantic_entries),
                },
            )
        )
        semantic_record_count += len(semantic_entries)

    semantic_record_bundle = _semantic_record_bundle_source(
        semantic_record_pack_names
    )
    (
        stage_a / f"{INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_BUNDLE}.lean"
    ).write_text(semantic_record_bundle, encoding="utf-8")
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_BUNDLE,
            semantic_record_bundle,
            role="checked-semantic-record-bundle",
            resources=_LIGHT_RESOURCES,
            extra={
                "semantic_record_pack_count": len(
                    semantic_record_pack_names
                ),
                "semantic_record_count": semantic_record_count,
            },
        )
    )

    action_cursor_pack_names: list[str] = []
    action_cursor_count = 0
    for pack_index, semantic_entries in semantic_entries_by_pack.items():
        name = _action_cursor_pack_name(pack_index)
        source = _action_cursor_pack_source(
            pack_index,
            pack_index * shard_size,
            semantic_entries,
        )
        (stage_a / f"{name}.lean").write_text(source, encoding="utf-8")
        action_cursor_pack_names.append(name)
        modules.append(
            _module_row(
                name,
                source,
                role="checked-action-cursor-pack",
                resources=_LIGHT_RESOURCES,
                extra={
                    "certificate_pack_index": pack_index,
                    "action_cursor_count": len(semantic_entries),
                },
            )
        )
        action_cursor_count += len(semantic_entries)

    action_cursor_bundle = _named_module_bundle_source(
        action_cursor_pack_names
    )
    (
        stage_a / f"{INTERPRETER_KERNEL_DATA_ACTION_CURSOR_BUNDLE}.lean"
    ).write_text(action_cursor_bundle, encoding="utf-8")
    modules.append(
        _module_row(
            INTERPRETER_KERNEL_DATA_ACTION_CURSOR_BUNDLE,
            action_cursor_bundle,
            role="checked-action-cursor-bundle",
            resources=_LIGHT_RESOURCES,
            extra={
                "action_cursor_pack_count": len(action_cursor_pack_names),
                "action_cursor_count": action_cursor_count,
            },
        )
    )

    inventory = InterpreterKernelDataInventory(
        candidate_sha256=sha256_bytes(candidate_bytes),
        candidate_size=len(candidate_bytes),
        state_machine_sha256=sha256_file(state_machine_path),
        table_rva=table_rva,
        count_rva=count_rva,
        transfer_count=len(transfers),
        shard_size=shard_size,
        transfer_shard_count=len(certificate_pack_names),
        byte_pack_size=byte_pack_size,
        byte_pack_count=len(byte_pack_names),
        relocation_pack_size=relocation_pack_size,
        relocation_pack_count=len(relocation_pack_names),
        relocation_block_count=len(relocation_blocks),
        relocation_chain_count=len(relocation_chain_names),
        pointer_field_count=len(pointer_field_proofs),
        descriptor_count=len(transfer_plans),
        component_count=len(transfer_plans) * len(_COMPONENTS),
        record_count=len(transfer_plans),
        certificate_pack_count=len(certificate_pack_names),
        authority_pack_count=len(authority_pack_names),
        native_projection_pack_count=len(native_projection_pack_names),
        action_cursor_pack_count=len(action_cursor_pack_names),
        standalone_module_count=len(kernel_modules) + len(modules),
        modules=tuple(modules),
    )
    _write_module_build_packs(
        destination,
        kernel_modules,
        modules,
        certificate_packs_per_authority,
    )
    write_json(destination / "module-inventory.json", inventory.payload())
    write_json(
        destination / "standalone-modules.json",
        [*kernel_modules, *(row["name"] for row in modules)],
    )
    generated_resources = {
        row["name"]: {
            "resource_class": row["resource_class"],
            "estimated_memory_mb": row["estimated_memory_mb"],
        }
        for row in modules
    }
    write_json(
        destination / "module-resources.json",
        {
            **{
                module: {
                    "resource_class": _LIGHT_RESOURCES[0],
                    "estimated_memory_mb": _LIGHT_RESOURCES[1],
                }
                for module in kernel_modules
            },
            **generated_resources,
        },
    )
    return inventory


__all__ = [
    "INTERPRETER_KERNEL_DATA_ACTION_CURSOR_BUNDLE",
    "INTERPRETER_KERNEL_DATA_ACTION_CURSOR_PACK_PREFIX",
    "INTERPRETER_KERNEL_DATA_AUTHORITY",
    "INTERPRETER_KERNEL_DATA_AUTHORITY_PACK_PREFIX",
    "INTERPRETER_KERNEL_DATA_BASE",
    "INTERPRETER_KERNEL_DATA_BUNDLE",
    "INTERPRETER_KERNEL_DATA_CANDIDATE_AUTHORITY",
    "INTERPRETER_KERNEL_DATA_BYTE_CHUNK_SIZE",
    "INTERPRETER_KERNEL_DATA_BYTE_PACK_PREFIX",
    "INTERPRETER_KERNEL_DATA_BYTE_PACK_SIZE",
    "INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_PREFIX",
    "INTERPRETER_KERNEL_DATA_CERTIFICATE_PACK_SIZE",
    "INTERPRETER_KERNEL_DATA_COMPONENT_PREFIX",
    "INTERPRETER_KERNEL_DATA_DESCRIPTOR_PREFIX",
    "INTERPRETER_KERNEL_DATA_POINTER_FIELD_PREFIX",
    "INTERPRETER_KERNEL_DATA_RECORD_PREFIX",
    "INTERPRETER_KERNEL_DATA_RELOCATION_PACK_PREFIX",
    "INTERPRETER_KERNEL_DATA_RELOCATION_PACK_SIZE",
    "INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PACK_SIZE",
    "INTERPRETER_KERNEL_DATA_RELOCATION_BUNDLE",
    "INTERPRETER_KERNEL_DATA_RELOCATION_BLOCK_PREFIX",
    "INTERPRETER_KERNEL_DATA_RELOCATION_CHAIN_PREFIX",
    "INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_BUNDLE",
    "INTERPRETER_KERNEL_DATA_SEMANTIC_RECORD_PACK_PREFIX",
    "INTERPRETER_KERNEL_DATA_FORMAT",
    "INTERPRETER_KERNEL_DATA_LOCAL_CONTEXT",
    "INTERPRETER_KERNEL_DATA_NATIVE_PROJECTION_PACK_PREFIX",
    "InterpreterKernelDataGenerationError",
    "InterpreterKernelDataInventory",
    "generate_interpreter_kernel_data_bundle",
]
