from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from threading import Event
from typing import Any

import capstone

from .stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from .util import sha256_bytes, sha256_file, utc_now, write_json


STAGE_A_RELATIONAL_MODEL_ID = "x86-pe32-relational-v3"
STAGE_A_RELATIONAL_PROFILE_ID = "x86-pe32-lean-relational-v3"
RELATION_CONTRACT_FORMAT = "stage-a-relation-contract-v1"
RELATIONAL_PROOF_IR_FORMAT = "stage-a-relational-proof-ir-v1"
REGISTERS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
FLAG_BITS = {
    0: "CF",
    2: "PF",
    6: "ZF",
    7: "SF",
    10: "DF",
    11: "OF",
}
RELATIONAL_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
RELATIONAL_ENVIRONMENT_ID = "adversarial-pe32-external-v1"
RELATIONAL_OBSERVATIONS = ["external_call", "external_jump", "return", "fault"]


def _raw_base_relocations(binary: StageABinary) -> list[dict[str, int]]:
    directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    cursor = int(directory.VirtualAddress)
    stop = cursor + int(directory.Size)
    relocations: list[dict[str, int]] = []
    while cursor < stop:
        header = binary.pe.get_data(cursor, 8)
        if len(header) != 8:
            raise StageAInputError("truncated PE base-relocation block header")
        page_rva = int.from_bytes(header[0:4], "little")
        block_size = int.from_bytes(header[4:8], "little")
        if block_size < 8 or block_size % 2 != 0 or cursor + block_size > stop:
            raise StageAInputError("malformed PE base-relocation block size")
        entries = binary.pe.get_data(cursor + 8, block_size - 8)
        if len(entries) != block_size - 8:
            raise StageAInputError("truncated PE base-relocation entries")
        for offset in range(0, len(entries), 2):
            encoded = int.from_bytes(entries[offset:offset + 2], "little")
            relocations.append({
                "rva": page_rva + (encoded & 0x0FFF),
                "type": encoded >> 12,
            })
        cursor += block_size
    return relocations


def _semantic_cutpoint_spans(
    original: StageABinary,
    candidate: StageABinary,
    original_span: dict[str, int],
    candidate_span: dict[str, int],
    block_id: str,
) -> list[tuple[dict[str, int], dict[str, int]]]:
    def decode(binary: StageABinary, span: dict[str, int]) -> list[Any]:
        data = binary.pe.get_data(span["rva_start"], span["size"])
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        decoded = list(disassembler.disasm(data, binary.image_base + span["rva_start"]))
        if not decoded or sum(int(instruction.size) for instruction in decoded) != len(data):
            raise StageAInputError(f"mapping block {block_id} does not decode exactly for semantic cutpoint projection")
        return decoded

    original_decoded = decode(original, original_span)
    candidate_decoded = decode(candidate, candidate_span)
    periodic = len(original_decoded) == len(candidate_decoded)

    def boundaries(binary: StageABinary, span: dict[str, int], decoded: list[Any]) -> list[int]:
        result = [0]
        for instruction_index, instruction in enumerate(decoded, start=1):
            semantic = instruction.mnemonic in {"rep movsd", "movsd", "div", "lock cmpxchg"}
            bounded = periodic and instruction_index % 4 == 0
            if semantic or bounded:
                offset = int(instruction.address - binary.image_base - span["rva_start"] + instruction.size)
                if offset < span["size"] and offset != result[-1]:
                    result.append(offset)
        result.append(span["size"])
        return result

    original_boundaries = boundaries(original, original_span, original_decoded)
    candidate_boundaries = boundaries(candidate, candidate_span, candidate_decoded)
    if len(original_boundaries) != len(candidate_boundaries):
        raise StageAInputError(
            f"mapping block {block_id} has mismatched semantic cutpoint counts: "
            f"original={len(original_boundaries) - 2}, candidate={len(candidate_boundaries) - 2}"
        )
    result = []
    for index in range(len(original_boundaries) - 1):
        original_start = original_span["rva_start"] + original_boundaries[index]
        candidate_start = candidate_span["rva_start"] + candidate_boundaries[index]
        result.append((
            {"rva_start": original_start, "rva_end": original_span["rva_start"] + original_boundaries[index + 1], "size": original_boundaries[index + 1] - original_boundaries[index]},
            {"rva_start": candidate_start, "rva_end": candidate_span["rva_start"] + candidate_boundaries[index + 1], "size": candidate_boundaries[index + 1] - candidate_boundaries[index]},
        ))
    return result


def _assign_region_targets(
    regions: list[dict[str, Any]],
    code_targets: list[dict[str, int]],
    value_targets: list[dict[str, int]],
    padding: list[dict[str, Any]],
    original: StageABinary,
    candidate: StageABinary,
) -> None:
    value_target_ids_by_key: dict[tuple[int, int, int, int, int], int] = {
        (
            target["original_value"], target["candidate_value"],
            target["original_relocation_rva"], target["candidate_relocation_rva"],
            target.get("mapped_size", 0),
        ): target["id"]
        for target in value_targets
    }

    def intern_value_target(
        original_value: int,
        candidate_value: int,
        original_relocation_rva: int,
        candidate_relocation_rva: int,
        mapped_size: int,
    ) -> int:
        key = (
            original_value & 0xFFFFFFFF,
            candidate_value & 0xFFFFFFFF,
            original_relocation_rva,
            candidate_relocation_rva,
            mapped_size,
        )
        existing = value_target_ids_by_key.get(key)
        if existing is not None:
            return existing
        value_id = len(value_targets)
        value_targets.append({
            "id": value_id,
            "original_value": key[0],
            "candidate_value": key[1],
            "original_relocation_rva": original_relocation_rva,
            "candidate_relocation_rva": candidate_relocation_rva,
            "mapped_size": mapped_size,
        })
        value_target_ids_by_key[key] = value_id
        return value_id

    lookups = {
        "original": {target["original_rva"]: target["id"] for target in code_targets},
        "candidate": {target["candidate_rva"]: target["id"] for target in code_targets},
    }
    targets_by_id = {target["id"]: target for target in code_targets}
    starts = {
        side: sorted((region[side]["rva"], target["id"]) for region, target in zip(regions, code_targets, strict=True))
        for side in ("original", "candidate")
    }
    padding_by_side = {
        side: sorted(
            (item["rva"], item["rva"] + item["size"])
            for item in padding
            if item["side"] in {side, "both"}
        )
        for side in ("original", "candidate")
    }
    relocations = {}
    for side, binary in (("original", original), ("candidate", candidate)):
        relocations[side] = {
            relocation["rva"]
            for relocation in _raw_base_relocations(binary)
            if relocation["type"] == 3
        }

    def immutable_equal_span(original_value: int, candidate_value: int, size: int) -> bool:
        spans: list[bytes] = []
        for binary, absolute in ((original, original_value), (candidate, candidate_value)):
            if absolute < binary.image_base:
                return False
            rva = absolute - binary.image_base
            section = next((
                section for section in binary.sections
                if not section.writable and section.rva_start <= rva and rva + size <= section.rva_end
            ), None)
            if section is None:
                return False
            data = binary.pe.get_data(rva, size)
            if len(data) != size:
                return False
            spans.append(data)
        return spans[0] == spans[1]

    def resolve(side: str, rva: int) -> int | None:
        if rva in lookups[side]:
            return lookups[side][rva]
        for start, target_id in starts[side]:
            if start <= rva:
                continue
            cursor = rva
            for padding_start, padding_stop in padding_by_side[side]:
                if padding_stop <= cursor:
                    continue
                if padding_start != cursor:
                    break
                cursor = padding_stop
                if cursor == start:
                    aliases = targets_by_id[target_id].setdefault(f"{side}_aliases", [])
                    if rva not in aliases:
                        aliases.append(rva)
                    return target_id
                if cursor > start:
                    break
            return None
        return None

    def relocation_pointer_table(
        original_value: int,
        candidate_value: int,
    ) -> tuple[int, set[int], set[int]] | None:
        if original_value < original.image_base or candidate_value < candidate.image_base:
            return None
        original_rva = original_value - original.image_base
        candidate_rva = candidate_value - candidate.image_base
        target_ids: set[int] = set()
        value_ids: set[int] = set()
        offset = 0
        while offset < 65536:
            original_entry = original_rva + offset
            candidate_entry = candidate_rva + offset
            if original_entry not in relocations["original"] or candidate_entry not in relocations["candidate"]:
                break
            original_pointer = int(original.pe.get_dword_at_rva(original_entry) or 0)
            candidate_pointer = int(candidate.pe.get_dword_at_rva(candidate_entry) or 0)
            original_target = resolve("original", original_pointer - original.image_base)
            candidate_target = resolve("candidate", candidate_pointer - candidate.image_base)
            if original_target is not None and original_target == candidate_target:
                target_ids.add(original_target)
            elif original_pointer == candidate_pointer:
                pass
            else:
                original_pointer_rva = original_pointer - original.image_base
                candidate_pointer_rva = candidate_pointer - candidate.image_base
                original_section = next((
                    section for section in original.sections
                    if section.rva_start <= original_pointer_rva < section.rva_end
                ), None)
                candidate_section = next((
                    section for section in candidate.sections
                    if section.rva_start <= candidate_pointer_rva < section.rva_end
                ), None)
                if original_section is None or candidate_section is None:
                    break
                value_ids.add(intern_value_target(
                    original_pointer,
                    candidate_pointer,
                    original_entry,
                    candidate_entry,
                    0,
                ))
            offset += 4
        return (offset, target_ids, value_ids) if offset else None

    for region in regions:
        target_ids: set[int] = set()
        bounds: set[tuple[str, str, int]] = set()
        decoded_by_side: dict[str, list[Any]] = {}
        for side, binary in (("original", original), ("candidate", candidate)):
            span = region[side]
            continuation = span["rva"] + span["size"]
            if (target_id := resolve(side, continuation)) is not None:
                target_ids.add(target_id)
            data = binary.pe.get_data(span["rva"], span["size"])
            disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            disassembler.detail = True
            decoded = list(disassembler.disasm(data, binary.image_base + span["rva"]))
            decoded_by_side[side] = decoded
            for instruction in decoded:
                control_flow = instruction.mnemonic == "call" or instruction.mnemonic.startswith("j")
                for operand in instruction.operands:
                    if operand.type != capstone.x86.X86_OP_IMM:
                        continue
                    immediate_rva = int(instruction.address - binary.image_base + instruction.imm_offset)
                    if not control_flow and immediate_rva not in relocations[side]:
                        continue
                    target_rva = int(operand.imm) - binary.image_base
                    if (target_id := resolve(side, target_rva)) is not None:
                        target_ids.add(target_id)
        region["target_ids"] = sorted(target_ids)
        region_value_ids: set[int] = set()
        original_decoded = decoded_by_side.get("original", [])
        candidate_decoded = decoded_by_side.get("candidate", [])
        if len(original_decoded) == len(candidate_decoded):
            for original_instruction, candidate_instruction in zip(original_decoded, candidate_decoded, strict=True):
                original_immediates = {
                    operand_index: (int(operand.imm), int(original_instruction.address - original.image_base + original_instruction.imm_offset))
                    for operand_index, operand in enumerate(original_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_IMM
                    and int(original_instruction.address - original.image_base + original_instruction.imm_offset) in relocations["original"]
                }
                candidate_immediates = {
                    operand_index: (int(operand.imm), int(candidate_instruction.address - candidate.image_base + candidate_instruction.imm_offset))
                    for operand_index, operand in enumerate(candidate_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_IMM
                    and int(candidate_instruction.address - candidate.image_base + candidate_instruction.imm_offset) in relocations["candidate"]
                }
                for operand_index in sorted(original_immediates.keys() & candidate_immediates.keys()):
                    original_value, original_relocation_rva = original_immediates[operand_index]
                    candidate_value, candidate_relocation_rva = candidate_immediates[operand_index]
                    original_code = resolve("original", original_value - original.image_base)
                    candidate_code = resolve("candidate", candidate_value - candidate.image_base)
                    if original_code is not None and original_code == candidate_code:
                        target_ids.add(original_code)
                        continue
                    if original_value == candidate_value:
                        continue
                    region_value_ids.add(intern_value_target(
                        original_value,
                        candidate_value,
                        original_relocation_rva,
                        candidate_relocation_rva,
                        0,
                    ))

                original_memory = {
                    operand_index: (
                        int(operand.mem.disp) & 0xFFFFFFFF,
                        int(original_instruction.address - original.image_base + original_instruction.disp_offset),
                        int(operand.size),
                        original_instruction.reg_name(operand.mem.base) if operand.mem.base else None,
                        original_instruction.reg_name(operand.mem.index) if operand.mem.index else None,
                        int(operand.mem.scale),
                    )
                    for operand_index, operand in enumerate(original_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_MEM
                    and int(original_instruction.disp_offset) > 0
                    and int(original_instruction.address - original.image_base + original_instruction.disp_offset)
                        in relocations["original"]
                }
                candidate_memory = {
                    operand_index: (
                        int(operand.mem.disp) & 0xFFFFFFFF,
                        int(candidate_instruction.address - candidate.image_base + candidate_instruction.disp_offset),
                        int(operand.size),
                        candidate_instruction.reg_name(operand.mem.base) if operand.mem.base else None,
                        candidate_instruction.reg_name(operand.mem.index) if operand.mem.index else None,
                        int(operand.mem.scale),
                    )
                    for operand_index, operand in enumerate(candidate_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_MEM
                    and int(candidate_instruction.disp_offset) > 0
                    and int(candidate_instruction.address - candidate.image_base + candidate_instruction.disp_offset)
                        in relocations["candidate"]
                }
                for operand_index in sorted(original_memory.keys() & candidate_memory.keys()):
                    (
                        original_value, original_relocation_rva, original_size,
                        original_base, original_index, original_scale,
                    ) = original_memory[operand_index]
                    (
                        candidate_value, candidate_relocation_rva, candidate_size,
                        candidate_base, candidate_index, candidate_scale,
                    ) = candidate_memory[operand_index]
                    if original_size <= 0 or original_size != candidate_size or original_value == candidate_value:
                        continue
                    if immutable_equal_span(original_value, candidate_value, original_size):
                        continue
                    mapped_size = original_size
                    table = relocation_pointer_table(original_value, candidate_value)
                    if table is not None and table[0] >= original_size:
                        mapped_size, table_targets, table_values = table
                        target_ids.update(table_targets)
                        region_value_ids.update(table_values)
                        if (
                            original_base is None and candidate_base is None
                            and original_index in REGISTERS and candidate_index in REGISTERS
                            and original_scale == candidate_scale and original_scale > 0
                        ):
                            upper_exclusive = (mapped_size - original_size) // original_scale + 1
                            bounds.add((original_index, candidate_index, upper_exclusive))
                    region_value_ids.add(intern_value_target(
                        original_value,
                        candidate_value,
                        original_relocation_rva,
                        candidate_relocation_rva,
                        mapped_size,
                    ))
        region["target_ids"] = sorted(target_ids)
        region["value_target_ids"] = sorted(region_value_ids)
        region["bounds"] = [
            {"original": original_reg, "candidate": candidate_reg, "unsigned_lt": upper}
            for original_reg, candidate_reg, upper in sorted(bounds)
        ]


def stage_a_generate_relation_contract(
    *,
    original: Path,
    candidate: Path,
    mapping: Path,
    out: Path,
) -> dict[str, Any]:
    original_bin = _parse_stage_a_pe(Path(original))
    candidate_bin = _parse_stage_a_pe(Path(candidate))
    mapping_payload = _read_json(Path(mapping))
    blocks = mapping_payload.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        raise StageAInputError("block mapping must contain a non-empty blocks list")
    pairs = [{"original": register, "candidate": register} for register in sorted(REGISTERS)]
    code_targets: list[dict[str, int]] = []
    value_targets: list[dict[str, int]] = []
    regions: list[dict[str, Any]] = []
    padding: list[dict[str, Any]] = []
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            raise StageAInputError(f"mapping block {index} must be an object")
        block_id = str(block.get("id") or f"region-{index}")
        original_span = _span(block.get("original"))
        candidate_span = _span(block.get("candidate"))
        if original_span is None or candidate_span is None:
            raise StageAInputError(f"mapping block {block_id} has malformed spans")
        if block.get("kind", "code") == "code":
            split_spans = _semantic_cutpoint_spans(
                original_bin, candidate_bin, original_span, candidate_span, block_id
            )
            for split_index, (original_split, candidate_split) in enumerate(split_spans):
                target_id = len(code_targets)
                code_targets.append({
                    "id": target_id,
                    "original_rva": original_split["rva_start"],
                    "candidate_rva": candidate_split["rva_start"],
                })
                regions.append({
                    "id": block_id if len(split_spans) == 1 else f"{block_id}~cut-{split_index}",
                    "root": (
                        original_split["rva_start"] == original_bin.entrypoint_rva
                        and candidate_split["rva_start"] == candidate_bin.entrypoint_rva
                    ),
                    "original": {"rva": original_split["rva_start"], "size": original_split["size"]},
                    "candidate": {"rva": candidate_split["rva_start"], "size": candidate_split["size"]},
                    "inputs": pairs,
                    "outputs": pairs,
                })
        else:
            padding.extend([
                {"id": f"{block_id}-original", "side": "original", "rva": original_span["rva_start"], "size": original_span["size"]},
                {"id": f"{block_id}-candidate", "side": "candidate", "rva": candidate_span["rva_start"], "size": candidate_span["size"]},
            ])
    waivers = mapping_payload.get("waivers", [])
    if not isinstance(waivers, list):
        raise StageAInputError("mapping waivers must be a list")
    for index, waiver in enumerate(waivers):
        if not isinstance(waiver, dict):
            raise StageAInputError(f"mapping waiver {index} must be an object")
        span = _span(waiver)
        side = waiver.get("binary")
        if span is None or side not in {"original", "candidate", "both"}:
            raise StageAInputError(f"mapping waiver {index} has malformed span or binary side")
        padding.append({
            "id": str(waiver.get("id") or f"waiver-{index}"),
            "side": side,
            "rva": span["rva_start"],
            "size": span["size"],
        })
    _assign_region_targets(regions, code_targets, value_targets, padding, original_bin, candidate_bin)
    contract = {
        "format": RELATION_CONTRACT_FORMAT,
        "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
        "observations": RELATIONAL_OBSERVATIONS,
        "memory_relation": {"mode": "identity"},
        "code_targets": code_targets,
        "value_targets": value_targets,
        "regions": regions,
        "padding": padding,
        "provenance": {
            "kind": "untrusted_block_map_projection",
            "mapping_sha256": sha256_file(Path(mapping)),
        },
    }
    normalized, issues = _normalize_contract(contract, original_bin, candidate_bin)
    payload = contract if issues else normalized
    write_json(Path(out), payload)
    return {
        "format": "stage-a-relation-contract-generation-v1",
        "status": "generated" if not issues else "incomplete",
        "out": str(out),
        "counts": {"regions": len(regions), "code_targets": len(code_targets), "value_targets": len(value_targets), "padding": len(padding)},
        "issues": issues,
    }


def stage_a_prove_relational(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
    _prepare_only: bool = False,
) -> dict[str, Any]:
    started_at = utc_now()
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "artifacts").mkdir(parents=True)
    (out / "lean" / "StageA").mkdir(parents=True)
    (out / "certificates").mkdir(parents=True)

    try:
        original_bin = _parse_stage_a_pe(Path(original))
        candidate_bin = _parse_stage_a_pe(Path(candidate))
        contract = _load_contract(Path(relation_contract))
        normalized, issues = _normalize_contract(contract, original_bin, candidate_bin)
    except (OSError, StageAInputError, ValueError) as exc:
        return _write_incomplete(out, started_at, original, candidate, str(exc))

    if issues:
        return _write_incomplete(
            out,
            started_at,
            original,
            candidate,
            "relational contract failed structural validation",
            issues=issues,
        )

    original_artifact = out / "artifacts" / "original.pe"
    candidate_artifact = out / "artifacts" / "candidate.pe"
    shutil.copyfile(original, original_artifact)
    shutil.copyfile(candidate, candidate_artifact)
    write_json(out / "relation-contract.json", normalized)

    proof_ir = _proof_ir(original_bin, candidate_bin, normalized)
    write_json(out / "relational-proof-ir.json", proof_ir)
    trusted_base = {
        "format": "stage-a-relational-trusted-base-v1",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "logical_trusted_base": [
            "lean_kernel",
            "lean_std_bv_decide_bitblaster",
            "lean_std_lrat_checker",
            "reviewed_stage_a_x86_pe32_relational_specification",
        ],
        "untrusted_producers": ["python", "capstone", "pefile", "z3", "sat_solver", "mapping_inference"],
        "approved_axioms": ["propext", "Classical.choice", "Quot.sound"],
        "claim_scope": {
            "kind": "relational_region_certificate",
            "whole_program_observational_equivalence": False,
        },
        "hard_boundaries": [
            "pe32_i386_only",
            "identity_address_memory_relation",
            "explicit_register_and_code_target_relations",
            "translated_memory_objects_require_future_checked_lowering",
        ],
    }
    write_json(out / "trusted-base.json", trusted_base)

    semantic_preflight = _relational_semantic_preflight(original_artifact, candidate_artifact, normalized)
    write_json(out / "semantic-gaps.json", semantic_preflight)
    if semantic_preflight["status"] != "supported":
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            {
                "status": "semantic_preflight_incomplete",
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "issues": semantic_preflight["issues"],
            },
            certificates=[],
            blocker="x86 semantic preflight found regions outside the reviewed Lean decoder",
        )

    lean_root = Path(__file__).with_name("lean") / "StageA"
    _write_text_if_changed(
        out / "lean" / "StageA" / "Formal.lean",
        (lean_root / "Formal.lean").read_text(encoding="utf-8"),
    )
    _write_text_if_changed(
        out / "lean" / "StageA" / "Relational.lean",
        (lean_root / "Relational.lean").read_text(encoding="utf-8"),
    )
    behaviors, extraction = _extract_relational_behaviors(
        out / "lean",
        original_bin,
        candidate_bin,
        original_artifact.read_bytes(),
        candidate_artifact.read_bytes(),
        normalized,
        use_cache=True,
    )
    if behaviors is None:
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            extraction,
            certificates=[],
            blocker="Lean could not decode every relational region from the exact PE bytes",
        )
    bundle_path = out / "lean" / "StageA" / "RelationalBundle.lean"
    shard_threshold = max(
        1,
        int(os.environ.get("WINCR_STAGE_A_RELATIONAL_SHARD_THRESHOLD", "129")),
    )
    sharded = _prepare_only or len(normalized["regions"]) >= shard_threshold
    if sharded:
        shard_modules, _ = _write_sharded_relational_proof(
            out / "lean", original_bin, candidate_bin,
            original_artifact.read_bytes(), candidate_artifact.read_bytes(),
            normalized, behaviors, replay=False,
        )
        if _prepare_only:
            graph = _write_relational_module_graph(
                out,
                original_bin=original_bin,
                candidate_bin=candidate_bin,
                trusted_base=trusted_base,
            )
            for olean in (out / "lean").rglob("*.olean"):
                olean.unlink()
            prepared = {
                "format": "stage-a-prepared-relational-v1",
                "status": "prepared",
                "profile": STAGE_A_RELATIONAL_PROFILE_ID,
                "model": STAGE_A_RELATIONAL_MODEL_ID,
                "original_sha256": original_bin.sha256,
                "candidate_sha256": candidate_bin.sha256,
                "relation_contract_sha256": sha256_file(out / "relation-contract.json"),
                "proof_ir_sha256": sha256_file(out / "relational-proof-ir.json"),
                "module_graph_sha256": sha256_file(out / "module-graph.json"),
                "expected_final_theorem": graph["expected_final_theorem"],
                "approved_axioms": graph["approved_axioms"],
                "counts": graph["counts"],
            }
            write_json(out / "prepared-proof.json", prepared)
            return prepared
        production = _run_sharded_relational(out / "lean", shard_modules)
    else:
        production_source = _lean_bundle_source(
            original_bin,
            candidate_bin,
            original_artifact.read_bytes(),
            candidate_artifact.read_bytes(),
            normalized,
            behaviors,
            replay=False,
        )
        bundle_path.write_text(production_source, encoding="utf-8")
        production = _run_lean_relational(out / "lean")
    if production["status"] != "checked":
        counterexample = _check_relational_counterexample(
            out / "lean",
            original_bin,
            candidate_bin,
            original_artifact.read_bytes(),
            candidate_artifact.read_bytes(),
            normalized,
            behaviors,
            production,
        )
        if counterexample is not None:
            return _write_relational_verdict(
                out,
                started_at,
                original_bin,
                candidate_bin,
                normalized,
                proof_ir,
                trusted_base,
                "fail",
                counterexample,
                certificates=[],
                blocker="Lean checked a concrete relational counterexample",
            )
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            production,
            certificates=[],
            blocker="Lean did not close every relational obligation",
        )

    certificates = _collect_certificates(out / "lean", out / "certificates")
    covered_indices = {entry["region_index"] for entry in certificates}
    certificates.extend(
        {"region_index": index, "kind": "lean_normalization"}
        for index in range(len(normalized["regions"]))
        if index not in covered_indices
    )
    certificates.sort(key=lambda entry: entry["region_index"])
    for entry in certificates:
        index = entry.get("region_index")
        if isinstance(index, int) and 0 <= index < len(normalized["regions"]):
            entry["region_id"] = normalized["regions"][index]["id"]
    if len(certificates) != len(normalized["regions"]):
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            production,
            certificates=certificates,
            blocker="Lean proof production did not emit one LRAT certificate per region",
        )

    if sharded:
        shard_modules, _ = _write_sharded_relational_proof(
            out / "lean", original_bin, candidate_bin,
            original_artifact.read_bytes(), candidate_artifact.read_bytes(),
            normalized, behaviors, replay=True, certificates=certificates,
        )
        replay = _run_sharded_relational(out / "lean", shard_modules)
    else:
        replay_source = _lean_bundle_source(
            original_bin,
            candidate_bin,
            original_artifact.read_bytes(),
            candidate_artifact.read_bytes(),
            normalized,
            behaviors,
            replay=True,
            certificates=certificates,
        )
        bundle_path.write_text(replay_source, encoding="utf-8")
        replay = _run_lean_relational(out / "lean")
    verdict = "pass" if replay["status"] == "checked" else "incomplete"
    return _write_relational_verdict(
        out,
        started_at,
        original_bin,
        candidate_bin,
        normalized,
        proof_ir,
        trusted_base,
        verdict,
        replay,
        certificates=certificates,
        blocker=None if verdict == "pass" else "independent LRAT replay did not check",
    )


def stage_a_prepare_relational(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
) -> dict[str, Any]:
    return stage_a_prove_relational(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        out=out,
        _prepare_only=True,
    )


def stage_a_build_relational(
    *,
    prepared: Path,
    out: Path,
    executor: str = "nix",
    flake: Path | None = None,
    builders_file: Path | None = None,
) -> dict[str, Any]:
    prepared = Path(prepared).resolve()
    out = Path(out).resolve()
    if executor != "nix":
        raise StageAInputError(f"unsupported relational proof executor {executor!r}")
    graph = _validate_prepared_relational(prepared)
    evaluator = _relational_nix_evaluator()
    flake_root = _find_relational_flake_root(flake)
    if out == prepared or prepared in out.parents:
        raise StageAInputError("build output must not be inside the prepared proof directory")

    locked_nixpkgs = _locked_flake_input(flake_root / "flake.lock", "nixpkgs")
    expression = "\n".join([
        "let",
        f"  nixpkgs = builtins.fetchTree (builtins.fromJSON {json.dumps(json.dumps(locked_nixpkgs, sort_keys=True))});",
        "  pkgs = import nixpkgs { system = builtins.currentSystem; };",
        f"  prepared = builtins.path {{ path = builtins.toPath {json.dumps(str(prepared))}; name = \"stage-a-prepared-proof\"; }};",
        f"in import (builtins.toPath {json.dumps(str(evaluator))}) {{ inherit pkgs prepared; }}",
    ])
    command = [
        "nix", "build", "--no-link", "--json", "--impure", "--expr", expression,
    ]
    if builders_file is not None:
        builders_path = Path(builders_file).resolve()
        if not builders_path.is_file():
            raise StageAInputError(f"Nix builders file does not exist: {builders_path}")
        command[2:2] = ["--builders", f"@{builders_path}"]
    started = time.monotonic()
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = round(time.monotonic() - started, 3)
    if process.returncode != 0:
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        (out / "nix.stdout").write_text(process.stdout, encoding="utf-8")
        (out / "nix.stderr").write_text(process.stderr, encoding="utf-8")
        failure = {
            "format": "stage-a-relational-nix-build-v1",
            "status": "incomplete",
            "verdict": "incomplete",
            "diagnostic": {
                "category": "nix_graph_build_failed",
                "severity": "hard",
                "next_action": "inspect nix.stderr and the first failed derivation log",
            },
            "returncode": process.returncode,
            "elapsed_seconds": elapsed,
        }
        write_json(out / "verdict.json", failure)
        raise StageAInputError(
            f"Nix relational proof graph failed; complete logs are in {out / 'nix.stderr'}:\n"
            + process.stderr[:4000]
            + ("\n...\n" if len(process.stderr) > 12000 else "")
            + process.stderr[-8000:]
        )
    try:
        build_outputs = json.loads(process.stdout)
        result_path = Path(build_outputs[0]["outputs"]["out"])
    except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
        raise StageAInputError("Nix returned a malformed relational graph result") from exc
    audit = _read_json(result_path / "audit.json")
    node_paths_payload = _read_json(result_path / "node-store-paths.json")
    node_paths = node_paths_payload.get("nodes")
    if not isinstance(node_paths, list) or not all(
        isinstance(node, dict) and isinstance(node.get("out_path"), str)
        for node in node_paths
    ):
        raise StageAInputError("Nix relational graph omitted node store provenance")
    store_paths = [str(result_path), *(node["out_path"] for node in node_paths)]
    path_info_process = subprocess.run(
        ["nix", "path-info", "--json", *store_paths],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if path_info_process.returncode != 0:
        raise StageAInputError(
            "cannot query Nix proof provenance:\n" + path_info_process.stderr[-4000:]
        )
    try:
        path_info = json.loads(path_info_process.stdout)
    except json.JSONDecodeError as exc:
        raise StageAInputError("Nix returned malformed path provenance") from exc

    prepared_proof_ir = _read_json(prepared / "relational-proof-ir.json")
    approved_axioms = set(graph["approved_axioms"])
    observed_axioms = audit.get("observed_axioms")
    theorem_checked = (
        audit.get("status") == "checked"
        and audit.get("lean_trust") == 0
        and audit.get("theorem") == graph["expected_final_theorem"]
        and isinstance(observed_axioms, list)
        and set(observed_axioms).issubset(approved_axioms)
    )
    proof_ir = _finalize_nix_proof_ir(
        prepared_proof_ir,
        theorem_checked=theorem_checked,
        theorem=graph["expected_final_theorem"],
        result_path=result_path,
    )
    checks = {
        "prepared_graph_valid": True,
        "nix_graph_built": audit.get("status") == "checked",
        "lean_trust_zero": audit.get("lean_trust") == 0,
        "final_theorem_matches": audit.get("theorem") == graph["expected_final_theorem"],
        "axioms_approved": isinstance(observed_axioms, list)
        and set(observed_axioms).issubset(approved_axioms),
        "proof_ir_satisfied": proof_ir["status"] == "satisfied",
        "contract_families_closed": all(
            family.get("status") in {"satisfied", "not_applicable"}
            for family in proof_ir.get("families", [])
        ),
        "original_artifact_matches": sha256_file(prepared / graph["artifacts"]["original"]["path"])
        == graph["artifacts"]["original"]["sha256"],
        "candidate_artifact_matches": sha256_file(prepared / graph["artifacts"]["candidate"]["path"])
        == graph["artifacts"]["candidate"]["sha256"],
    }
    status = "pass" if all(checks.values()) else "incomplete"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in (
        "prepared-proof.json", "module-graph.json", "relation-contract.json",
        "relational-proof-ir.json", "trusted-base.json", "semantic-gaps.json",
    ):
        source = prepared / name
        if source.is_file():
            shutil.copyfile(source, out / name)
    shutil.copyfile(result_path / "audit.json", out / "lean-audit.json")
    shutil.copyfile(result_path / "lean.stdout", out / "lean.stdout")
    shutil.copyfile(result_path / "lean.stderr", out / "lean.stderr")
    write_json(out / "relational-proof-ir.json", proof_ir)
    provenance = {
        "format": "stage-a-relational-nix-provenance-v1",
        "executor": executor,
        "flake": str(flake_root),
        "builders_file": str(Path(builders_file).resolve()) if builders_file is not None else None,
        "flake_lock_sha256": sha256_file(flake_root / "flake.lock"),
        "evaluator_sha256": sha256_file(evaluator),
        "result_path": str(result_path),
        "nodes": node_paths,
        "nix_path_info": path_info,
        "elapsed_seconds": elapsed,
    }
    write_json(out / "nix-provenance.json", provenance)
    result = {
        "format": "stage-a-relational-nix-build-v1",
        "status": status,
        "verdict": status,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "checks": checks,
        "lean_audit": audit,
        "counts": graph["counts"],
        "elapsed_seconds": elapsed,
        "provenance": {
            "result_path": str(result_path),
            "nix_paths": len(path_info),
            "node_derivations": len(node_paths),
        },
    }
    write_json(out / "verdict.json", result)
    return result


def _finalize_nix_proof_ir(
    proof_ir: dict[str, Any],
    *,
    theorem_checked: bool,
    theorem: str,
    result_path: Path,
) -> dict[str, Any]:
    assumption_obligations = [
        obligation for obligation in proof_ir["obligations"]
        if obligation["kind"] != "relational_region_equivalence"
    ]
    finalized = dict(proof_ir)
    finalized["status"] = (
        "satisfied" if theorem_checked and not assumption_obligations else "incomplete"
    )
    finalized["families"] = [
        {"family": "exact_pe_decode", "status": "satisfied" if theorem_checked else "incomplete"},
        {"family": "x86_semantics", "status": "satisfied" if theorem_checked else "incomplete"},
        {"family": "executable_coverage", "status": "satisfied" if theorem_checked else "incomplete"},
        {"family": "roots_and_targets", "status": "satisfied" if theorem_checked else "incomplete"},
        {"family": "relational_regions", "status": "satisfied" if theorem_checked else "incomplete"},
        {
            "family": "cfg_invariants",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "cfg_bound_invariant", "cfg_address_separation_invariant",
                }
                for obligation in assumption_obligations
            ) else "not_applicable",
        },
        {
            "family": "memory_relation",
            "status": "incomplete" if any(
                obligation["kind"] == "relocation_aware_memory_relation"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {"family": "adversarial_environment", "status": "satisfied"},
    ]
    evidence = {
        "kind": "lean_trust_zero_nix_graph",
        "theorem": theorem,
        "lean_trust": 0,
        "nix_result_path": str(result_path),
    }
    finalized["obligations"] = [
        {
            **obligation,
            "status": "proved" if theorem_checked else "incomplete",
            "evidence": evidence if theorem_checked else None,
        }
        if obligation["kind"] == "relational_region_equivalence"
        else obligation
        for obligation in proof_ir["obligations"]
    ]
    return finalized


def stage_a_check_relational_proof(*, report: Path, out: Path | None = None) -> dict[str, Any]:
    report = Path(report)
    verdict = _read_json(report / "verdict.json")
    contract = _read_json(report / "relation-contract.json")
    proof_ir = _read_json(report / "relational-proof-ir.json")
    index = _read_json(report / "certificates" / "index.json")
    checks = {
        "report_pass": verdict.get("verdict") == "pass",
        "profile_matches": verdict.get("profile") == STAGE_A_RELATIONAL_PROFILE_ID,
        "proof_ir_satisfied": proof_ir.get("status") == "satisfied",
        "no_incomplete_assumptions": verdict.get("counts", {}).get("incomplete_assumptions") == 0,
        "contract_families_closed": all(
            family.get("status") in {"satisfied", "not_applicable"}
            for family in proof_ir.get("families", [])
        ),
        "proof_ir_hash_matches": sha256_file(report / "relational-proof-ir.json") == verdict.get("proof_ir_sha256"),
        "contract_hash_matches": sha256_file(report / "relation-contract.json") == verdict.get("relation_contract_sha256"),
        "original_matches": sha256_file(report / "artifacts" / "original.pe") == proof_ir.get("original", {}).get("sha256"),
        "candidate_matches": sha256_file(report / "artifacts" / "candidate.pe") == proof_ir.get("candidate", {}).get("sha256"),
        "certificate_index_complete": index.get("status") == "satisfied",
        "certificate_hashes_match": _certificate_hashes_match(report, index),
        "trusted_base_hash_matches": sha256_file(report / "trusted-base.json") == verdict.get("trusted_base_sha256"),
    }
    replay = {"status": "skipped_preflight", "stdout": "", "stderr": "", "returncode": None}
    if all(checks.values()):
        original_bin = _parse_stage_a_pe(report / "artifacts" / "original.pe")
        candidate_bin = _parse_stage_a_pe(report / "artifacts" / "candidate.pe")
        with tempfile.TemporaryDirectory(prefix="stage-a-relational-check-") as temporary:
            replay_root = Path(temporary)
            lean_dir = replay_root / "lean"
            (lean_dir / "StageA").mkdir(parents=True)
            (replay_root / "artifacts").mkdir()
            shutil.copyfile(report / "lean" / "StageA" / "Formal.lean", lean_dir / "StageA" / "Formal.lean")
            shutil.copyfile(report / "lean" / "StageA" / "Relational.lean", lean_dir / "StageA" / "Relational.lean")
            shutil.copyfile(report / "artifacts" / "original.pe", replay_root / "artifacts" / "original.pe")
            shutil.copyfile(report / "artifacts" / "candidate.pe", replay_root / "artifacts" / "candidate.pe")
            behaviors, behavior_check = _extract_relational_behaviors(
                lean_dir,
                original_bin,
                candidate_bin,
                (report / "artifacts" / "original.pe").read_bytes(),
                (report / "artifacts" / "candidate.pe").read_bytes(),
                contract,
                use_cache=False,
            )
        checks["behaviors_redecoded"] = behaviors is not None and behavior_check.get("status") == "checked"
        checks["bundle_reproduced"] = False
        if behaviors is not None:
            expected_source = _lean_bundle_source(
                original_bin,
                candidate_bin,
                (report / "artifacts" / "original.pe").read_bytes(),
                (report / "artifacts" / "candidate.pe").read_bytes(),
                contract,
                behaviors,
                replay=True,
                certificates=index.get("entries", []),
            )
            source_path = report / "lean" / "StageA" / "RelationalBundle.lean"
            checks["bundle_reproduced"] = source_path.read_text(encoding="utf-8") == expected_source
        canonical_relational = Path(__file__).with_name("lean") / "StageA" / "Relational.lean"
        canonical_formal = Path(__file__).with_name("lean") / "StageA" / "Formal.lean"
        checks["kernel_matches"] = (
            sha256_file(canonical_relational) == sha256_file(report / "lean" / "StageA" / "Relational.lean")
            and sha256_file(canonical_formal) == sha256_file(report / "lean" / "StageA" / "Formal.lean")
        )
        if all(checks.values()):
            replay = _run_lean_relational(report / "lean")
    checks["lean_lrat_replay_checked"] = replay.get("status") == "checked"
    status = "pass" if all(checks.values()) else "incomplete"
    result = {
        "format": "stage-a-relational-proof-check-v1",
        "status": status,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "claim_scope": {
            "kind": "relational_region_certificate",
            "whole_program_observational_equivalence": False,
        },
        "checks": checks,
        "lean_check": replay,
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def _load_contract(path: Path) -> dict[str, Any]:
    payload = _read_json(path)
    if payload.get("format") != RELATION_CONTRACT_FORMAT:
        raise StageAInputError(f"relation contract format must be {RELATION_CONTRACT_FORMAT}")
    return payload


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError(f"{path} must contain a JSON object")
    return payload


def _write_relational_module_graph(
    prepared: Path,
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    trusted_base: dict[str, Any],
) -> dict[str, Any]:
    stage_a = prepared / "lean" / "StageA"
    sources = {path.stem: path for path in stage_a.glob("*.lean")}
    root = "RelationalBundle"
    if root not in sources:
        raise StageAInputError("prepared proof is missing StageA.RelationalBundle")

    import_pattern = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
    imports = {
        module: import_pattern.findall(path.read_text(encoding="utf-8"))
        for module, path in sources.items()
    }
    reachable: set[str] = set()
    visiting: set[str] = set()

    def visit(module: str) -> None:
        if module in reachable:
            return
        if module in visiting:
            raise StageAInputError(f"generated Lean module graph contains a cycle at {module}")
        path = sources.get(module)
        if path is None:
            raise StageAInputError(f"generated Lean import StageA.{module} has no source")
        visiting.add(module)
        for dependency in imports[module]:
            visit(dependency)
        visiting.remove(module)
        reachable.add(module)

    visit(root)
    logical_modules = {
        module: {
            "source": f"lean/StageA/{module}.lean",
            "source_sha256": sha256_file(sources[module]),
            "imports": imports[module],
            "source_bytes": sources[module].stat().st_size,
        }
        for module in sorted(reachable)
    }

    def numbered(prefix: str) -> list[str]:
        return sorted(
            (module for module in reachable if module.startswith(prefix)),
            key=lambda module: int(module.removeprefix(prefix)),
        )

    pack_size = max(
        1, int(os.environ.get("WINCR_STAGE_A_RELATIONAL_NIX_PACK_MODULES", "8"))
    )
    packed: set[str] = set()
    raw_nodes: list[dict[str, Any]] = []
    for prefix, label in (
        ("RelationalDefinitionsShard", "definitions-pack"),
        ("RelationalProofShard", "local-proof-pack"),
    ):
        modules = numbered(prefix)
        for pack_index, offset in enumerate(range(0, len(modules), pack_size)):
            members = modules[offset : offset + pack_size]
            packed.update(members)
            raw_nodes.append({"id": f"{label}-{pack_index:03d}", "modules": members})
    for module in sorted(reachable - packed):
        node_id = re.sub(r"[^a-z0-9]+", "-", module.lower()).strip("-")
        raw_nodes.append({"id": node_id, "modules": [module]})

    module_node = {
        module: node["id"]
        for node in raw_nodes
        for module in node["modules"]
    }
    if len(module_node) != len(reachable):
        raise StageAInputError("generated build packs do not assign every Lean module exactly once")

    def resource_class(modules: list[str]) -> tuple[str, int]:
        names = " ".join(modules)
        source_bytes = sum(logical_modules[module]["source_bytes"] for module in modules)
        if "DecodeChunk" in names or "StructuralPadding" in names or "StructuralCoverage" in names:
            return "high-memory", max(4096, source_bytes // 1024 * 3)
        if "RelationalProofOriginal" in names or "RelationalProofCandidate" in names:
            return "high-memory", max(3072, source_bytes // 1024 * 3)
        if "DirectChunk" in names or any(
            module.startswith("RelationalProofShard") for module in modules
        ):
            return "medium", max(1536, source_bytes // 1024 * 2)
        return "light", max(512, source_bytes // 1024 + 256)

    nodes: list[dict[str, Any]] = []
    for raw in raw_nodes:
        dependencies = sorted({
            module_node[dependency]
            for module in raw["modules"]
            for dependency in logical_modules[module]["imports"]
            if module_node[dependency] != raw["id"]
        })
        classification, estimated_memory_mb = resource_class(raw["modules"])
        nodes.append({
            "id": raw["id"],
            "modules": raw["modules"],
            "dependencies": dependencies,
            "resource_class": classification,
            "estimated_memory_mb": estimated_memory_mb,
            "source_sha256": sha256_bytes("".join(
                logical_modules[module]["source_sha256"] for module in raw["modules"]
            ).encode("ascii")),
        })

    lean_version = None
    lean_githash = None
    lean = shutil.which("lean")
    if lean is not None:
        lean_version = subprocess.run(
            [lean, "--version"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        ).stdout.strip()
        lean_githash = subprocess.run(
            [lean, "--githash"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        ).stdout.strip()
    graph = {
        "format": "stage-a-lean-module-graph-v1",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "root_module": root,
        "final_node": module_node[root],
        "expected_final_theorem": "StageA.GeneratedRelational.candidateRelationalCertificate",
        "approved_axioms": trusted_base["approved_axioms"],
        "lean": {"version": lean_version, "githash": lean_githash, "trust": 0},
        "artifacts": {
            "original": {"path": "artifacts/original.pe", "sha256": original_bin.sha256},
            "candidate": {"path": "artifacts/candidate.pe", "sha256": candidate_bin.sha256},
        },
        "modules": logical_modules,
        "nodes": sorted(nodes, key=lambda node: node["id"]),
        "counts": {
            "logical_modules": len(logical_modules),
            "derivations": len(nodes),
            "definition_modules": len(numbered("RelationalDefinitionsShard")),
            "local_proof_modules": len(numbered("RelationalProofShard")),
            "decode_modules": sum("DecodeChunk" in module for module in logical_modules),
            "direct_modules": sum("DirectChunk" in module for module in logical_modules),
            "structural_modules": sum(module.startswith("RelationalProofStructural") for module in logical_modules),
        },
    }
    write_json(prepared / "module-graph.json", graph)
    _validate_relational_module_graph(prepared, graph)
    return graph


def _validate_relational_module_graph(
    prepared: Path, graph: dict[str, Any] | None = None
) -> dict[str, Any]:
    prepared = Path(prepared)
    graph = graph or _read_json(prepared / "module-graph.json")
    if graph.get("format") != "stage-a-lean-module-graph-v1":
        raise StageAInputError("unsupported prepared Lean module graph format")
    modules = graph.get("modules")
    nodes = graph.get("nodes")
    if not isinstance(modules, dict) or not modules or not isinstance(nodes, list) or not nodes:
        raise StageAInputError("prepared Lean module graph is empty or malformed")
    assigned: dict[str, str] = {}
    node_by_id: dict[str, dict[str, Any]] = {}
    import_pattern = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
    for module, metadata in modules.items():
        if not re.fullmatch(r"[A-Za-z0-9_]+", module) or not isinstance(metadata, dict):
            raise StageAInputError(f"invalid generated Lean module name {module!r}")
        relative = metadata.get("source")
        if relative != f"lean/StageA/{module}.lean":
            raise StageAInputError(f"module {module} has a noncanonical source path")
        source = prepared / relative
        if not source.is_file() or sha256_file(source) != metadata.get("source_sha256"):
            raise StageAInputError(f"module {module} source hash does not match")
        observed_imports = import_pattern.findall(source.read_text(encoding="utf-8"))
        if observed_imports != metadata.get("imports"):
            raise StageAInputError(f"module {module} import inventory does not match source")
        if any(dependency not in modules for dependency in observed_imports):
            raise StageAInputError(f"module {module} imports an undeclared StageA module")
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise StageAInputError("malformed Lean graph node")
        node_id = node["id"]
        if node_id in node_by_id:
            raise StageAInputError(f"duplicate Lean graph node {node_id}")
        node_by_id[node_id] = node
        for module in node.get("modules", []):
            if module not in modules or module in assigned:
                raise StageAInputError(f"module {module} has an invalid or duplicate build assignment")
            assigned[module] = node_id
    if set(assigned) != set(modules):
        raise StageAInputError("not every Lean module is assigned to a build node")
    for node_id, node in node_by_id.items():
        module_positions = {module: index for index, module in enumerate(node["modules"])}
        for module in node["modules"]:
            for dependency in modules[module]["imports"]:
                if assigned[dependency] == node_id and module_positions[dependency] >= module_positions[module]:
                    raise StageAInputError(
                        f"node {node_id} does not order internal import {dependency} before {module}"
                    )
        expected = sorted({
            assigned[dependency]
            for module in node["modules"]
            for dependency in modules[module]["imports"]
            if assigned[dependency] != node_id
        })
        if node.get("dependencies") != expected:
            raise StageAInputError(f"node {node_id} dependency inventory does not match imports")
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit_node(node_id: str) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            raise StageAInputError(f"Lean build graph contains a cycle at {node_id}")
        if node_id not in node_by_id:
            raise StageAInputError(f"Lean build graph references missing node {node_id}")
        visiting.add(node_id)
        for dependency in node_by_id[node_id]["dependencies"]:
            visit_node(dependency)
        visiting.remove(node_id)
        visited.add(node_id)
    visit_node(str(graph.get("final_node")))
    if visited != set(node_by_id):
        raise StageAInputError("Lean graph contains nodes outside the final theorem closure")
    theorem = graph.get("expected_final_theorem")
    if not isinstance(theorem, str) or not re.fullmatch(r"[A-Za-z0-9_.]+", theorem):
        raise StageAInputError("prepared Lean graph has an invalid final theorem name")
    approved_axioms = graph.get("approved_axioms")
    if not isinstance(approved_axioms, list) or not all(
        isinstance(axiom, str) and re.fullmatch(r"[A-Za-z0-9_.]+", axiom)
        for axiom in approved_axioms
    ):
        raise StageAInputError("prepared Lean graph has an invalid approved-axiom inventory")
    return graph


def _validate_prepared_relational(prepared: Path) -> dict[str, Any]:
    manifest = _read_json(prepared / "prepared-proof.json")
    if manifest.get("format") != "stage-a-prepared-relational-v1":
        raise StageAInputError("unsupported prepared relational proof format")
    if manifest.get("status") != "prepared":
        raise StageAInputError("relational proof preparation did not complete")
    graph = _validate_relational_module_graph(prepared)
    expected_hashes = {
        "relation_contract_sha256": prepared / "relation-contract.json",
        "proof_ir_sha256": prepared / "relational-proof-ir.json",
        "module_graph_sha256": prepared / "module-graph.json",
    }
    for field, path in expected_hashes.items():
        if not path.is_file() or manifest.get(field) != sha256_file(path):
            raise StageAInputError(f"prepared relational proof hash mismatch for {path.name}")
    if manifest.get("expected_final_theorem") != graph.get("expected_final_theorem"):
        raise StageAInputError("prepared relational theorem inventory does not match its graph")
    if manifest.get("approved_axioms") != graph.get("approved_axioms"):
        raise StageAInputError("prepared relational axiom inventory does not match its graph")
    if manifest.get("original_sha256") != graph["artifacts"]["original"]["sha256"]:
        raise StageAInputError("prepared original artifact inventory does not match its graph")
    if manifest.get("candidate_sha256") != graph["artifacts"]["candidate"]["sha256"]:
        raise StageAInputError("prepared candidate artifact inventory does not match its graph")
    for artifact in graph["artifacts"].values():
        path = prepared / artifact["path"]
        if not path.is_file() or sha256_file(path) != artifact["sha256"]:
            raise StageAInputError(f"prepared artifact hash mismatch for {artifact['path']}")
    if any(prepared.rglob("*.olean")):
        raise StageAInputError("prepared relational proof must not contain prebuilt Lean objects")
    return graph


def _relational_nix_evaluator() -> Path:
    candidates = [
        Path(__file__).parents[2] / "nix" / "stage-a-lean-graph.nix",
        Path(__file__).with_name("nix") / "stage-a-lean-graph.nix",
        *(
            parent / "share" / "wincr" / "nix" / "stage-a-lean-graph.nix"
            for parent in Path(__file__).resolve().parents
        ),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise StageAInputError("cannot locate nix/stage-a-lean-graph.nix")


def _find_relational_flake_root(explicit: Path | None) -> Path:
    if explicit is not None:
        root = Path(explicit).resolve()
        if not (root / "flake.nix").is_file() or not (root / "flake.lock").is_file():
            raise StageAInputError(f"{root} is not a locked Nix flake")
        return root
    starts = [Path.cwd().resolve(), Path(__file__).resolve()]
    for start in starts:
        for parent in (start, *start.parents):
            if (parent / "flake.nix").is_file() and (parent / "flake.lock").is_file():
                return parent
    raise StageAInputError("cannot locate the project flake; pass --flake")


def _locked_flake_input(lock_path: Path, input_name: str) -> dict[str, Any]:
    lock = _read_json(lock_path)
    nodes = lock.get("nodes")
    root_name = lock.get("root")
    if not isinstance(nodes, dict) or root_name not in nodes:
        raise StageAInputError(f"{lock_path} has no valid flake-lock node graph")
    root_inputs = nodes[root_name].get("inputs", {})
    node_name = root_inputs.get(input_name) if isinstance(root_inputs, dict) else None
    if not isinstance(node_name, str) or node_name not in nodes:
        raise StageAInputError(f"{lock_path} does not lock the {input_name} input directly")
    locked = nodes[node_name].get("locked")
    if not isinstance(locked, dict):
        raise StageAInputError(f"{lock_path} has no locked source for {input_name}")
    required = {"type", "narHash"}
    if not required.issubset(locked) or not all(
        isinstance(key, str) and isinstance(value, (str, int, bool))
        for key, value in locked.items()
    ):
        raise StageAInputError(f"{lock_path} contains an unsupported lock record for {input_name}")
    return locked


def _normalize_contract(contract: dict[str, Any], original: StageABinary, candidate: StageABinary) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if original.bitness != 32 or candidate.bitness != 32:
        issues.append({"category": "unsupported_bitness", "expected": 32})
    environment = contract.get("environment")
    if not isinstance(environment, dict) or environment.get("id") != RELATIONAL_ENVIRONMENT_ID:
        issues.append({
            "category": "environment_contract_missing",
            "severity": "hard",
            "expected": RELATIONAL_ENVIRONMENT_ID,
            "next_action": "declare the adversarial external environment contract",
        })
    observations = contract.get("observations")
    if observations != RELATIONAL_OBSERVATIONS:
        issues.append({
            "category": "observation_contract_mismatch",
            "severity": "hard",
            "expected": RELATIONAL_OBSERVATIONS,
            "observed": observations,
            "next_action": "use the complete v3 externally observable event set",
        })
        observations = RELATIONAL_OBSERVATIONS
    memory_relation = contract.get("memory_relation")
    if not isinstance(memory_relation, dict) or memory_relation.get("mode") not in {"identity", "mapped_objects"}:
        issues.append({
            "category": "memory_relation_missing",
            "severity": "hard",
            "expected": {"mode": "identity"},
            "next_action": "declare the relation between original and candidate data addresses",
        })
        memory_relation = {"mode": "identity"}
    if memory_relation.get("mode") != "identity":
        issues.append({
            "category": "memory_relation_out_of_model",
            "severity": "hard",
            "next_action": "lower mapped memory objects into checked relational memory obligations",
        })
    targets = contract.get("code_targets")
    value_targets = contract.get("value_targets", [])
    regions = contract.get("regions")
    padding = contract.get("padding", [])
    if not isinstance(targets, list) or not targets:
        issues.append({"category": "code_targets_missing"})
        targets = []
    if not isinstance(regions, list) or not regions:
        issues.append({"category": "regions_missing"})
        regions = []
    if not isinstance(value_targets, list):
        issues.append({"category": "value_targets_not_list"})
        value_targets = []
    if not isinstance(padding, list):
        issues.append({"category": "padding_not_list"})
        padding = []

    normalized_targets: list[dict[str, Any]] = []
    target_ids: set[int] = set()
    for index, item in enumerate(targets):
        if not isinstance(item, dict):
            issues.append({"category": "malformed_code_target", "index": index})
            continue
        target_id = _integer(item.get("id"))
        original_rva = _integer(item.get("original_rva"))
        candidate_rva = _integer(item.get("candidate_rva"))
        original_aliases = item.get("original_aliases", [])
        candidate_aliases = item.get("candidate_aliases", [])
        if (
            target_id is None or original_rva is None or candidate_rva is None or target_id in target_ids
            or not isinstance(original_aliases, list) or not isinstance(candidate_aliases, list)
            or any(_integer(alias) is None for alias in original_aliases)
            or any(_integer(alias) is None for alias in candidate_aliases)
        ):
            issues.append({"category": "malformed_code_target", "index": index})
            continue
        target_ids.add(target_id)
        normalized_targets.append({
            "id": target_id,
            "original_rva": original_rva,
            "candidate_rva": candidate_rva,
            "original_aliases": sorted({_integer(alias) for alias in original_aliases}),
            "candidate_aliases": sorted({_integer(alias) for alias in candidate_aliases}),
        })

    normalized_regions: list[dict[str, Any]] = []
    region_ids: set[str] = set()
    target_by_id = {target["id"]: target for target in normalized_targets}
    normalized_value_targets: list[dict[str, Any]] = []
    value_target_ids: set[int] = set()
    for index, item in enumerate(value_targets):
        if not isinstance(item, dict):
            issues.append({"category": "malformed_value_target", "index": index})
            continue
        fields = {
            field: _integer(item.get(field))
            for field in (
                "id", "original_value", "candidate_value",
                "original_relocation_rva", "candidate_relocation_rva",
                "mapped_size",
            )
        }
        if any(value is None for value in fields.values()) or fields["id"] in value_target_ids:
            issues.append({"category": "malformed_value_target", "index": index})
            continue
        value_target_ids.add(fields["id"])
        normalized_target = {field: int(value) for field, value in fields.items()}
        normalized_target["relocation_offsets"] = _mapped_relocation_offsets(
            original, candidate, normalized_target, issues,
        )
        normalized_value_targets.append(normalized_target)
    value_target_by_id = {target["id"]: target for target in normalized_value_targets}
    for index, item in enumerate(regions):
        if not isinstance(item, dict):
            issues.append({"category": "malformed_region", "index": index})
            continue
        region_id = str(item.get("id") or "")
        original_span = _span(item.get("original"))
        candidate_span = _span(item.get("candidate"))
        inputs = _register_pairs(item.get("inputs"), issues, region_id, "inputs")
        outputs = _register_pairs(item.get("outputs"), issues, region_id, "outputs")
        raw_bounds = item.get("bounds", [])
        bounds: list[dict[str, Any]] = []
        if not isinstance(raw_bounds, list):
            issues.append({"category": "malformed_region_bounds", "id": region_id})
            raw_bounds = []
        for bound in raw_bounds:
            upper = _integer(bound.get("unsigned_lt")) if isinstance(bound, dict) else None
            if (
                not isinstance(bound, dict)
                or bound.get("original") not in REGISTERS
                or bound.get("candidate") not in REGISTERS
                or upper is None or upper <= 0 or upper > 2 ** 32
            ):
                issues.append({"category": "malformed_region_bound", "id": region_id, "bound": bound})
                continue
            bounds.append({
                "original": str(bound["original"]),
                "candidate": str(bound["candidate"]),
                "unsigned_lt": upper,
            })
        if not region_id or region_id in region_ids or original_span is None or candidate_span is None:
            issues.append({"category": "malformed_region", "index": index, "id": region_id})
            continue
        region_ids.add(region_id)
        if not _inside_executable(original, original_span) or not _inside_executable(candidate, candidate_span):
            issues.append({"category": "region_outside_executable_section", "id": region_id})
        raw_target_ids = item.get("target_ids")
        if raw_target_ids is None and isinstance(item.get("code_targets"), list):
            raw_target_ids = [target.get("id") for target in item["code_targets"] if isinstance(target, dict)]
        if raw_target_ids is None:
            raw_target_ids = [target["id"] for target in normalized_targets]
        if not isinstance(raw_target_ids, list) or any(_integer(target_id) not in target_ids for target_id in raw_target_ids):
            issues.append({"category": "malformed_region_target_ids", "id": region_id})
            raw_target_ids = []
        region_targets = [
            target_by_id[target_id]
            for raw_target_id in raw_target_ids
            if (target_id := _integer(raw_target_id)) in target_by_id
        ]
        raw_value_target_ids = item.get("value_target_ids")
        if raw_value_target_ids is None and isinstance(item.get("values"), list):
            raw_value_target_ids = [target.get("id") for target in item["values"] if isinstance(target, dict)]
        if raw_value_target_ids is None:
            raw_value_target_ids = []
        if (
            not isinstance(raw_value_target_ids, list)
            or any(_integer(target_id) not in value_target_ids for target_id in raw_value_target_ids)
        ):
            issues.append({"category": "malformed_region_value_target_ids", "id": region_id})
            raw_value_target_ids = []
        region_values = [
            value_target_by_id[target_id]
            for raw_target_id in raw_value_target_ids
            if (target_id := _integer(raw_target_id)) in value_target_by_id
        ]
        address_separations = _infer_region_address_separations(
            original,
            candidate,
            original_span,
            candidate_span,
            region_values,
            inputs,
        )
        normalized_regions.append(
            {
                "id": region_id,
                "numeric_id": index,
                "original": original_span,
                "candidate": candidate_span,
                "inputs": inputs,
                "outputs": outputs,
                "bounds": bounds,
                "target_ids": [target["id"] for target in region_targets],
                "code_targets": region_targets,
                "value_target_ids": [target["id"] for target in region_values],
                "values": region_values,
                "address_separations": address_separations,
                "root": bool(item.get("root")),
            }
        )

    normalized_padding = _normalize_padding(padding, original, candidate, issues)
    padding_indices = {
        side: {
            span["rva_start"]: index
            for index, span in enumerate(
                item
                for item in normalized_padding
                if item["side"] in {side, "both"}
            )
        }
        for side in ("original", "candidate")
    }
    for target in normalized_targets:
        for side in ("original", "candidate"):
            canonical = target[f"{side}_rva"]
            alias_padding_indices: list[int] = []
            for alias in target[f"{side}_aliases"]:
                if not _padding_bridge_valid(side, alias, canonical, normalized_padding):
                    issues.append({
                        "category": "code_target_alias_not_verified_padding",
                        "severity": "hard",
                        "target_id": target["id"],
                        "side": side,
                        "alias_rva": alias,
                        "canonical_rva": canonical,
                    })
                padding_index = padding_indices[side].get(alias)
                if padding_index is None:
                    issues.append({
                        "category": "code_target_alias_padding_index_missing",
                        "severity": "hard",
                        "target_id": target["id"],
                        "side": side,
                        "alias_rva": alias,
                    })
                else:
                    alias_padding_indices.append(padding_index)
            target[f"{side}_alias_padding_indices"] = alias_padding_indices
    _check_span_overlap(normalized_regions, normalized_padding, issues)
    _check_coverage(original, candidate, normalized_regions, normalized_padding, issues)
    if not any(
        region.get("root")
        and region["original"]["rva_start"] == original.entrypoint_rva
        and region["candidate"]["rva_start"] == candidate.entrypoint_rva
        for region in normalized_regions
    ):
        issues.append({
            "category": "checked_entry_root_missing",
            "severity": "hard",
            "expected": {"original_rva": original.entrypoint_rva, "candidate_rva": candidate.entrypoint_rva},
            "next_action": "mark the region pairing both PE entrypoints as a checked root",
        })
    region_index_by_starts = {
        (region["original"]["rva_start"], region["candidate"]["rva_start"]): index
        for index, region in enumerate(normalized_regions)
    }
    for target in normalized_targets:
        target_starts = (target["original_rva"], target["candidate_rva"])
        region_index = region_index_by_starts.get(target_starts)
        if region_index is None:
            issues.append({
                "category": "unresolved_code_target",
                "severity": "hard",
                "target_id": target["id"],
                "expected": "a paired region beginning at both target RVAs",
                "observed": target,
                "next_action": "add or correct the target region relation",
            })
        else:
            target["region_index"] = region_index
    _annotate_flag_liveness(original, candidate, normalized_regions, issues)
    return {
        "format": RELATION_CONTRACT_FORMAT,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "code_targets": normalized_targets,
        "value_targets": normalized_value_targets,
        "regions": normalized_regions,
        "padding": normalized_padding,
        "environment": {
            "id": RELATIONAL_ENVIRONMENT_ID,
            "external_results": "universally_quantified_and_synchronized",
            "original_execution": "static_only",
        },
        "observations": observations,
        "memory_relation": memory_relation,
    }, issues


def _annotate_flag_liveness(
    original: StageABinary,
    candidate: StageABinary,
    regions: list[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> None:
    from capstone import x86_const

    read_masks = {
        bit: (
            getattr(x86_const, f"X86_EFLAGS_TEST_{name}")
            | getattr(x86_const, f"X86_EFLAGS_PRIOR_{name}")
        )
        for bit, name in FLAG_BITS.items()
    }
    write_masks = {
        bit: sum(
            getattr(x86_const, f"X86_EFLAGS_{kind}_{name}", 0)
            for kind in ("MODIFY", "RESET", "SET", "UNDEFINED")
        )
        for bit, name in FLAG_BITS.items()
    }

    def local(
        binary: StageABinary,
        span: dict[str, int],
        *,
        region_id: str,
        side: str,
    ) -> tuple[set[int], set[int]]:
        data = binary.pe.get_data(span["rva_start"], span["size"])
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        disassembler.detail = True
        used_before_definition: set[int] = set()
        defined: set[int] = set()
        decoded_size = 0
        for instruction in disassembler.disasm(
            data, binary.image_base + span["rva_start"]
        ):
            decoded_size += int(instruction.size)
            eflags = (
                0 if (
                    instruction.group(capstone.x86.X86_GRP_FPU)
                    or instruction.mnemonic.startswith("f")
                )
                else int(instruction.eflags)
            )
            unmodeled_reads = [
                name for name in ("AF", "IF", "TF", "NT", "RF")
                if eflags & (
                    getattr(x86_const, f"X86_EFLAGS_TEST_{name}", 0)
                    | getattr(x86_const, f"X86_EFLAGS_PRIOR_{name}", 0)
                )
            ]
            if unmodeled_reads:
                issues.append({
                    "category": "unmodeled_live_eflag",
                    "severity": "hard",
                    "region_id": region_id,
                    "side": side,
                    "instruction_rva": int(instruction.address) - binary.image_base,
                    "flags": unmodeled_reads,
                    "next_action": "extend the formal flag model before proving this instruction",
                })
            used_before_definition.update(
                bit for bit, mask in read_masks.items()
                if eflags & mask and bit not in defined
            )
            defined.update(
                bit for bit, mask in write_masks.items() if eflags & mask
            )
        if decoded_size != len(data):
            raise StageAInputError("flag-liveness analysis did not decode a region exactly")
        return used_before_definition, defined

    uses: list[set[int]] = []
    definitions: list[set[int]] = []
    successors: list[set[int]] = []
    for region in regions:
        original_uses, original_defs = local(
            original, region["original"], region_id=region["id"], side="original"
        )
        candidate_uses, candidate_defs = local(
            candidate, region["candidate"], region_id=region["id"], side="candidate"
        )
        uses.append(original_uses | candidate_uses)
        definitions.append(original_defs & candidate_defs)
        successors.append({
            int(target["region_index"])
            for target in region.get("code_targets", [])
            if "region_index" in target
        })

    live_in = [set(region_uses) for region_uses in uses]
    live_out = [set() for _ in regions]
    changed = True
    while changed:
        changed = False
        for index in range(len(regions) - 1, -1, -1):
            output = set().union(*(live_in[target] for target in successors[index])) \
                if successors[index] else set()
            entry = uses[index] | (output - definitions[index])
            if output != live_out[index] or entry != live_in[index]:
                live_out[index] = output
                live_in[index] = entry
                changed = True

    for index, region in enumerate(regions):
        region["flag_inputs"] = sorted(live_in[index])
        region["flag_outputs"] = sorted(live_out[index])


def _infer_region_address_separations(
    original: StageABinary,
    candidate: StageABinary,
    original_span: dict[str, int],
    candidate_span: dict[str, int],
    values: list[dict[str, int]],
    inputs: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not values:
        return []

    def accesses(
        binary: StageABinary,
        span: dict[str, int],
    ) -> tuple[list[tuple[str, int, int]], list[tuple[int, int]]]:
        data = binary.pe.get_data(span["rva_start"], span["size"])
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        disassembler.detail = True
        writes: list[tuple[str, int, int]] = []
        reads: list[tuple[int, int]] = []
        for instruction in disassembler.disasm(data, binary.image_base + span["rva_start"]):
            for operand in instruction.operands:
                if operand.type != capstone.x86.X86_OP_MEM:
                    continue
                base = instruction.reg_name(operand.mem.base) if operand.mem.base else ""
                index = instruction.reg_name(operand.mem.index) if operand.mem.index else ""
                if operand.access & capstone.CS_AC_WRITE and base in REGISTERS and not index:
                    writes.append((base, int(operand.mem.disp), int(operand.size)))
                if operand.access & capstone.CS_AC_READ and not base and not index:
                    reads.append((int(operand.mem.disp) & 0xFFFFFFFF, int(operand.size)))
        return writes, reads

    original_writes, original_reads = accesses(original, original_span)
    candidate_writes, candidate_reads = accesses(candidate, candidate_span)
    if len(original_writes) != len(candidate_writes) or len(original_reads) != len(candidate_reads):
        return []
    register_map = {pair["original"]: pair["candidate"] for pair in inputs}
    paired_writes = [
        (original_write, candidate_write)
        for original_write, candidate_write in zip(original_writes, candidate_writes)
        if (
            register_map.get(original_write[0]) == candidate_write[0]
            and original_write[2] == candidate_write[2]
        )
    ]
    if len(paired_writes) != len(original_writes):
        return []

    rows: set[tuple[str, str, int, int, int, int]] = set()
    for (original_address, original_width), (candidate_address, candidate_width) in zip(
        original_reads, candidate_reads
    ):
        if original_width != candidate_width:
            continue
        matching_target = next((
            target for target in values
            if (
                target["mapped_size"] > 0
                and target["original_value"] <= original_address
                and original_address + original_width <= target["original_value"] + target["mapped_size"]
                and target["candidate_value"] <= candidate_address
                and candidate_address + candidate_width <= target["candidate_value"] + target["mapped_size"]
                and original_address - target["original_value"]
                    == candidate_address - target["candidate_value"]
            )
        ), None)
        if matching_target is None:
            continue
        for original_write, candidate_write in paired_writes:
            for read_offset in range(original_width):
                for write_offset in range(original_write[2]):
                    rows.add((
                        original_write[0],
                        candidate_write[0],
                        (original_write[1] + write_offset) & 0xFFFFFFFF,
                        (candidate_write[1] + write_offset) & 0xFFFFFFFF,
                        (original_address + read_offset) & 0xFFFFFFFF,
                        (candidate_address + read_offset) & 0xFFFFFFFF,
                    ))
    return [
        {
            "original_register": original_register,
            "candidate_register": candidate_register,
            "original_offset": original_offset,
            "candidate_offset": candidate_offset,
            "original_address": original_address,
            "candidate_address": candidate_address,
        }
        for (
            original_register,
            candidate_register,
            original_offset,
            candidate_offset,
            original_address,
            candidate_address,
        ) in sorted(rows)
    ]


def _span(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    start = _integer(value.get("rva_start", value.get("rva")))
    size = _integer(value.get("size"))
    if start is None or size is None or size <= 0:
        return None
    return {"rva_start": start, "rva_end": start + size, "size": size}


def _register_pairs(value: Any, issues: list[dict[str, Any]], region: str, family: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        issues.append({"category": "register_relation_missing", "region": region, "family": family})
        return []
    result: list[dict[str, str]] = []
    original_seen: set[str] = set()
    candidate_seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or item.get("original") not in REGISTERS or item.get("candidate") not in REGISTERS:
            issues.append({"category": "register_relation_invalid", "region": region, "family": family, "item": item})
            continue
        original_register = str(item["original"])
        candidate_register = str(item["candidate"])
        if original_register in original_seen or candidate_register in candidate_seen:
            issues.append({
                "category": "register_relation_ambiguous",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        original_seen.add(original_register)
        candidate_seen.add(candidate_register)
        result.append({"original": original_register, "candidate": candidate_register})
    return result


def _mapped_relocation_offsets(
    original: StageABinary,
    candidate: StageABinary,
    target: dict[str, int],
    issues: list[dict[str, Any]],
) -> list[int]:
    mapped_size = target["mapped_size"]
    if mapped_size == 0:
        return []

    def offsets(binary: StageABinary, absolute: int) -> list[int]:
        base_rva = absolute - binary.image_base
        return [
            relocation["rva"] - base_rva
            for relocation in _raw_base_relocations(binary)
            if relocation["type"] == 3
            and base_rva <= relocation["rva"]
            and relocation["rva"] + 4 <= base_rva + mapped_size
        ]

    original_offsets = offsets(original, target["original_value"])
    candidate_offsets = offsets(candidate, target["candidate_value"])
    duplicate_offsets = {
        "original": sorted({offset for offset in original_offsets if original_offsets.count(offset) > 1}),
        "candidate": sorted({offset for offset in candidate_offsets if candidate_offsets.count(offset) > 1}),
    }
    if duplicate_offsets["original"] or duplicate_offsets["candidate"]:
        issues.append({
            "category": "mapped_object_relocation_duplicate",
            "severity": "hard",
            "value_target_id": target["id"],
            "duplicates": duplicate_offsets,
            "next_action": "remove duplicate PE32 HIGHLOW entries; each relocation cell must be applied once",
        })
        return []
    original_offsets = sorted(original_offsets)
    candidate_offsets = sorted(candidate_offsets)
    if original_offsets != candidate_offsets:
        issues.append({
            "category": "mapped_object_relocation_shape_mismatch",
            "severity": "hard",
            "value_target_id": target["id"],
            "original_offsets": original_offsets,
            "candidate_offsets": candidate_offsets,
            "next_action": "map objects with identical internal relocation-word structure",
        })
        return []
    ordered = original_offsets
    if any(offset % 4 != 0 for offset in ordered):
        issues.append({
            "category": "mapped_object_relocation_unaligned",
            "severity": "hard",
            "value_target_id": target["id"],
            "offsets": ordered,
            "next_action": "use non-overlapping aligned PE32 HIGHLOW relocation cells",
        })
        return []
    return ordered


def _normalize_padding(value: list[Any], original: StageABinary, candidate: StageABinary, issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or item.get("side") not in {"original", "candidate", "both"}:
            issues.append({"category": "padding_invalid", "index": index})
            continue
        span = _span(item)
        if span is None:
            issues.append({"category": "padding_invalid", "index": index})
            continue
        for side, binary in (("original", original), ("candidate", candidate)):
            if item["side"] not in {side, "both"}:
                continue
            data = binary.pe.get_data(span["rva_start"], span["size"])
            if len(data) != span["size"] or not _padding_bytes(data, binary, span["rva_start"]):
                issues.append({"category": "padding_bytes_invalid", "index": index, "side": side})
        result.append({"id": str(item.get("id") or f"padding-{index}"), "side": item["side"], **span})
    return result


def _padding_bytes(data: bytes, binary: StageABinary, rva: int) -> bool:
    del binary, rva
    patterns = (
        b"\x8d\x74\x26\x00",
        b"\x8d\x76\x00",
        b"\x2e\x8d\x74\x26\x00",
        b"\x2e\x8d\xb4\x26\x00\x00\x00\x00",
        b"\x8d\xb6\x00\x00\x00\x00",
        b"\x8d\xb4\x26\x00\x00\x00\x00",
        b"\x66\x90",
        b"\x00",
        b"\x90",
    )
    def checked(value: bytes) -> bool:
        offset = 0
        while offset < len(value):
            if value[offset] == 0xEB and offset + 2 <= len(value):
                tail = value[offset + 2 :]
                return value[offset + 1] == len(tail) and checked(tail)
            pattern = next((pattern for pattern in patterns if value.startswith(pattern, offset)), None)
            if pattern is None:
                return False
            offset += len(pattern)
        return True

    return checked(data)


def _inside_executable(binary: StageABinary, span: dict[str, int]) -> bool:
    return any(section.executable and section.rva_start <= span["rva_start"] and span["rva_end"] <= section.rva_end for section in binary.sections)


def _padding_bridge_valid(
    side: str,
    alias: int,
    canonical: int,
    padding: list[dict[str, Any]],
) -> bool:
    if alias >= canonical:
        return False
    cursor = alias
    for span in sorted(
        (item for item in padding if item["side"] in {side, "both"}),
        key=lambda item: item["rva_start"],
    ):
        if span["rva_end"] <= cursor:
            continue
        if span["rva_start"] != cursor:
            return False
        cursor = span["rva_end"]
        if cursor == canonical:
            return True
        if cursor > canonical:
            return False
    return False


def _check_span_overlap(regions: list[dict[str, Any]], padding: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for side in ("original", "candidate"):
        spans = [(region[side]["rva_start"], region[side]["rva_end"], region["id"]) for region in regions]
        spans += [(item["rva_start"], item["rva_end"], item["id"]) for item in padding if item["side"] in {side, "both"}]
        spans.sort()
        for left, right in zip(spans, spans[1:]):
            if left[1] > right[0]:
                issues.append({"category": "span_overlap", "side": side, "left": left[2], "right": right[2]})


def _check_coverage(original: StageABinary, candidate: StageABinary, regions: list[dict[str, Any]], padding: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for side, binary in (("original", original), ("candidate", candidate)):
        spans = [(region[side]["rva_start"], region[side]["rva_end"]) for region in regions]
        spans += [(item["rva_start"], item["rva_end"]) for item in padding if item["side"] in {side, "both"}]
        for section in (section for section in binary.sections if section.executable):
            cursor = section.rva_start
            for start, stop in sorted(span for span in spans if section.rva_start <= span[0] and span[1] <= section.rva_end):
                if start != cursor:
                    issues.append({"category": "executable_coverage_gap", "side": side, "rva_start": cursor, "rva_end": start})
                cursor = max(cursor, stop)
            if cursor != section.rva_end:
                issues.append({"category": "executable_coverage_gap", "side": side, "rva_start": cursor, "rva_end": section.rva_end})


def _proof_ir(original: StageABinary, candidate: StageABinary, contract: dict[str, Any]) -> dict[str, Any]:
    obligations = [
        {"id": f"relational:{region['id']}", "kind": "relational_region_equivalence", "status": "pending_lrat"}
        for region in contract["regions"]
    ]
    obligations.extend(
        {
            "id": f"invariant:{region['id']}:{bound_index}",
            "kind": "cfg_bound_invariant",
            "status": "incomplete",
            "region_id": region["id"],
            "original_register": bound["original"],
            "candidate_register": bound["candidate"],
            "unsigned_upper_exclusive": bound["unsigned_lt"],
            "blocker": "bound is a local region precondition and has not been proved inductive on incoming CFG edges",
            "next_action": "prove the bound at roots and preserve it across every reachable predecessor edge",
        }
        for region in contract["regions"]
        for bound_index, bound in enumerate(region.get("bounds", []))
    )
    obligations.extend(
        {
            "id": f"address-separation:{region['id']}",
            "kind": "cfg_address_separation_invariant",
            "status": "incomplete",
            "region_id": region["id"],
            "comparisons": len(region["address_separations"]),
            "blocker": "stack-derived writes are assumed disjoint from relocated image reads but the predicate has not been proved on incoming CFG edges",
            "next_action": "prove image/stack disjointness at roots and preserve each required address separation across reachable predecessor edges",
        }
        for region in contract["regions"]
        if region.get("address_separations")
    )
    obligations.extend(_mapped_relocation_memory_obligations(original, candidate, contract))
    return {
        "format": RELATIONAL_PROOF_IR_FORMAT,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "claim_scope": {
            "kind": "relational_region_certificate",
            "whole_program_observational_equivalence": False,
        },
        "original": _relational_loader_facts(original),
        "candidate": _relational_loader_facts(candidate),
        "environment": contract["environment"],
        "observations": contract["observations"],
        "memory_relation": contract["memory_relation"],
        "relation_contract_sha256": sha256_bytes(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()),
        "counts": {"regions": len(contract["regions"]), "code_targets": len(contract["code_targets"]), "padding": len(contract["padding"])},
        "obligations": obligations,
    }


def _mapped_relocation_memory_obligations(
    original: StageABinary,
    candidate: StageABinary,
    contract: dict[str, Any],
) -> list[dict[str, Any]]:
    relocation_rvas: dict[str, set[int]] = {}
    for side, binary in (("original", original), ("candidate", candidate)):
        relocation_rvas[side] = {
            relocation["rva"]
            for relocation in _raw_base_relocations(binary)
            if relocation["type"] == 3
        }
    obligations: list[dict[str, Any]] = []
    for region in contract["regions"]:
        for target in region.get("values", []):
            if target["mapped_size"] < 4:
                continue
            original_base = target["original_value"] - original.image_base
            candidate_base = target["candidate_value"] - candidate.image_base
            differing_cells = []
            for offset in range(0, target["mapped_size"] - 3):
                original_rva = original_base + offset
                candidate_rva = candidate_base + offset
                if (
                    original_rva not in relocation_rvas["original"]
                    or candidate_rva not in relocation_rvas["candidate"]
                ):
                    continue
                original_word = int(original.pe.get_dword_at_rva(original_rva) or 0)
                candidate_word = int(candidate.pe.get_dword_at_rva(candidate_rva) or 0)
                if original_word != candidate_word:
                    differing_cells.append({
                        "offset": offset,
                        "original_rva": original_rva,
                        "candidate_rva": candidate_rva,
                        "original_word": original_word,
                        "candidate_word": candidate_word,
                    })
            if not differing_cells:
                continue
            obligations.append({
                "id": f"memory:{region['id']}:{target['id']}",
                "kind": "relocation_aware_memory_relation",
                "status": "incomplete",
                "region_id": region["id"],
                "value_target_id": target["id"],
                "differing_relocation_cells": differing_cells,
                "blocker": "bytewise mapped-memory pullback cannot represent related but non-identical relocation words",
                "next_action": "use a checked relocation-word memory relation and prove its initialization and transition preservation",
            })
    return obligations


def _relational_semantic_preflight(original: Path, candidate: Path, contract: dict[str, Any]) -> dict[str, Any]:
    from .stage_a import _formal_profile_side_diagnostics

    mapping_contract = {
        "blocks": [
            {
                "id": region["id"],
                "kind": "code",
                "original": region["original"],
                "candidate": region["candidate"],
            }
            for region in contract["regions"]
        ]
    }
    issues = _formal_profile_side_diagnostics("original", original, mapping_contract, issue_limit=None)
    issues += _formal_profile_side_diagnostics("candidate", candidate, mapping_contract, issue_limit=None)
    for rank, issue in enumerate(issues, start=1):
        identity = {
            "category": issue.get("category"),
            "side": issue.get("side"),
            "block": issue.get("block"),
            "rva": issue.get("rva"),
            "bytes": issue.get("bytes"),
        }
        issue["id"] = "rel-gap-" + sha256_bytes(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        )[:16]
        issue["rank"] = rank
        issue["family"] = "x86_semantics"
        issue.setdefault("severity", "hard")
        if issue.get("category") == "formal_instruction_unsupported":
            issue.setdefault("cause_hint", "instruction form is outside the reviewed decoder/executor fragment")
            issue.setdefault("next_action", "add this instruction form to the reviewed Lean decoder and executor")
        elif issue.get("category") == "formal_region_does_not_terminate":
            issue.setdefault("cause_hint", "cutpoint does not end at a modeled control transfer")
            issue.setdefault("next_action", "repair the cutpoint so the region ends at a modeled control transfer")
        else:
            issue.setdefault("cause_hint", "region cannot be lowered into the current checked semantic fragment")
            issue.setdefault("next_action", "repair the region map or extend the checked semantic profile")
    by_category = {
        category: sum(1 for issue in issues if issue.get("category") == category)
        for category in sorted({str(issue.get("category")) for issue in issues})
    }
    next_work = [
        {
            "category": category,
            "count": count,
            "example_ids": [
                issue["id"] for issue in issues if issue.get("category") == category
            ][:3],
        }
        for category, count in sorted(by_category.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "format": "stage-a-relational-semantic-gaps-v1",
        "status": "supported" if not issues else "incomplete",
        "issues": issues,
        "next_work": next_work,
        "counts": {
            "issues": len(issues),
            "by_category": by_category,
            "diagnostic_limit_per_side": None,
            "possibly_truncated": False,
        },
    }


def _relational_loader_facts(binary: StageABinary) -> dict[str, Any]:
    relocations = [
        relocation for relocation in _raw_base_relocations(binary)
        if relocation["type"] != 0
    ]
    return {
        "sha256": binary.sha256,
        "bytes": binary.size,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "size_of_image": binary.size_of_image,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "characteristics": section.characteristics,
                "executable": section.executable,
                "readable": section.readable,
                "writable": section.writable,
            }
            for section in binary.sections
        ],
        "imports": [
            {
                "dll": imported.dll,
                "symbol": imported.symbol,
                "ordinal": imported.ordinal,
                "thunk_rva": imported.thunk_rva,
            }
            for imported in binary.imports
        ],
        "relocations": relocations,
    }


def _extract_relational_behaviors(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    *,
    use_cache: bool,
) -> tuple[list[dict[str, str]] | None, dict[str, Any]]:
    cache_dir = _relational_cache_dir() if use_cache else None
    values: dict[tuple[str, int], str] = {}
    cache_keys: dict[tuple[str, int], str] = {}
    binaries = {"original": original_bin, "candidate": candidate_bin}
    lean_root = Path(__file__).with_name("lean") / "StageA"
    formal_sha256 = sha256_file(lean_root / "Formal.lean")
    for index, region in enumerate(contract["regions"]):
        for side in ("original", "candidate"):
            key = _behavior_cache_key(
                binaries[side], region[side],
                formal_sha256=formal_sha256,
            )
            cache_keys[(side, index)] = key
            if cache_dir is not None:
                cached = _read_behavior_cache(cache_dir / f"{key}.json")
                if cached is not None:
                    values[(side, index)] = cached
    missing = {
        (side, index)
        for index in range(len(contract["regions"]))
        for side in ("original", "candidate")
        if (side, index) not in values
    }
    if not missing:
        return _behavior_rows(values, len(contract["regions"])), {
            "status": "checked",
            "source": "untrusted_cache_rechecked_by_bundle",
            "cache_hits": len(values),
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        }
    pattern = re.compile(
        r"STAGE_A_BEHAVIOR_BEGIN (original|candidate) (\d+)\n(.*?)\nSTAGE_A_BEHAVIOR_END",
        re.DOTALL,
    )
    batch_size = max(1, int(os.environ.get("WINCR_STAGE_A_RELATIONAL_EXTRACTION_BATCH", "128")))
    ordered_missing = sorted(missing, key=lambda item: (item[1], item[0]))
    batch_count = (len(ordered_missing) + batch_size - 1) // batch_size
    last_result: dict[str, Any] = {}
    batch_elapsed: dict[int, float] = {}
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)

    prelude_path = lean_dir / "StageA" / "RelationalExtractPrelude.lean"
    prelude_path.write_text("import StageA.Relational\n", encoding="utf-8")
    prelude = _run_lean_relational(lean_dir, bundle="RelationalExtractPrelude")
    if prelude.get("status") != "checked":
        return None, prelude

    batches = [
        (batch_index, set(ordered_missing[offset : offset + batch_size]))
        for batch_index, offset in enumerate(range(0, len(ordered_missing), batch_size), start=1)
    ]

    def run_batch(batch_index: int, batch: set[tuple[str, int]]) -> tuple[int, set[tuple[str, int]], dict[str, Any]]:
        bundle = f"RelationalExtract{batch_index}"
        source_path = lean_dir / "StageA" / f"{bundle}.lean"
        source = _lean_extraction_source(original_bin, candidate_bin, original, candidate, contract, requests=batch)
        source_path.write_text(source, encoding="utf-8")
        return batch_index, batch, _run_lean_extractor(lean_dir, bundle=bundle)

    jobs = max(1, int(os.environ.get("WINCR_STAGE_A_RELATIONAL_EXTRACTION_JOBS", "8")))
    with ThreadPoolExecutor(max_workers=min(jobs, batch_count)) as executor:
        futures = [executor.submit(run_batch, batch_index, batch) for batch_index, batch in batches]
        for future in as_completed(futures):
            batch_index, batch, result = future.result()
            last_result = result
            batch_elapsed[batch_index] = float(result.get("elapsed_seconds", 0.0))
            if result.get("status") != "checked":
                for pending in futures:
                    pending.cancel()
                return None, {
                    **result,
                    "batch": batch_index,
                    "batch_count": batch_count,
                    "batch_size": len(batch),
                }
            found: set[tuple[str, int]] = set()
            for side, index_text, value in pattern.findall(result.get("stdout", "")):
                location = (side, int(index_text))
                if location not in batch:
                    continue
                value = re.sub(r"\s+", " ", value).strip()
                if not value.startswith("some "):
                    for pending in futures:
                        pending.cancel()
                    return None, {**result, "status": "unsupported", "stderr": result.get("stderr", "") + f"\n{side} region {index_text} did not decode"}
                values[location] = value[len("some ") :]
                found.add(location)
            if found != batch:
                for pending in futures:
                    pending.cancel()
                return None, {
                    **result,
                    "status": "malformed_output",
                    "stderr": result.get("stderr", "") + f"\nmissing decoded behavior markers in batch {batch_index}",
                }
            if cache_dir is not None:
                for location in batch:
                    write_json(
                        cache_dir / f"{cache_keys[location]}.json",
                        {"format": "stage-a-relational-behavior-cache-v1", "behavior": values[location]},
                    )
    behaviors = _behavior_rows(values, len(contract["regions"]))
    if any(not row["original"] or not row["candidate"] for row in behaviors):
        return None, {**last_result, "status": "malformed_output", "stderr": last_result.get("stderr", "") + "\nmissing decoded behavior marker"}
    return behaviors, {
        **last_result,
        "source": "batched_exact_lean_extraction",
        "cache_hits": len(values) - len(missing),
        "cache_misses": len(missing),
        "batch_count": batch_count,
        "batch_size": batch_size,
        "jobs": min(jobs, batch_count),
        "batch_elapsed_seconds": batch_elapsed,
        "max_batch_elapsed_seconds": max(batch_elapsed.values(), default=0.0),
    }


def _behavior_rows(values: dict[tuple[str, int], str], count: int) -> list[dict[str, str]]:
    return [
        {"original": values.get(("original", index), ""), "candidate": values.get(("candidate", index), "")}
        for index in range(count)
    ]


def _relational_cache_dir() -> Path | None:
    configured = os.environ.get("WINCR_STAGE_A_RELATIONAL_CACHE")
    if configured == "off":
        return None
    if configured:
        return Path(configured).expanduser()
    cache_home = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_home / "wincr" / "stage-a-relational-v1"


def _behavior_cache_key(
    binary: StageABinary,
    span: dict[str, Any],
    *,
    formal_sha256: str | None = None,
) -> str:
    lean_root = Path(__file__).with_name("lean") / "StageA"
    payload = {
        "format": "stage-a-relational-behavior-cache-key-v2",
        "binary_sha256": binary.sha256,
        "span": {"rva_start": span["rva_start"], "size": span["size"]},
        "formal_sha256": formal_sha256 or sha256_file(lean_root / "Formal.lean"),
    }
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _read_behavior_cache(path: Path) -> str | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("format") != "stage-a-relational-behavior-cache-v1":
        return None
    behavior = payload.get("behavior")
    return behavior if isinstance(behavior, str) and behavior else None


def _lean_extraction_source(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    *,
    requests: set[tuple[str, int]],
) -> str:
    evaluations: list[str] = []
    for index, region in enumerate(contract["regions"]):
        if not any((side, index) in requests for side in ("original", "candidate")):
            continue
        for side in ("original", "candidate"):
            if (side, index) not in requests:
                continue
            span = region[side]
            span_literal = f"{{ start := {span['rva_start']}, size := {span['size']} }}"
            evaluations.append(
                f'  IO.println ("STAGE_A_BEHAVIOR_BEGIN {side} {index}\\n" ++ '
                f'reprStr (regionBehaviorWithImports {side}Pe {side}Imports {span_literal}) ++ '
                '"\\nSTAGE_A_BEHAVIOR_END")'
            )
    return (
        "import StageA.Relational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "def main : IO Unit := do\n"
        "  let originalData ← IO.FS.readBinFile \"../artifacts/original.pe\"\n"
        "  let candidateData ← IO.FS.readBinFile \"../artifacts/candidate.pe\"\n"
        "  let originalBytes : Bytes := originalData.toList.map (fun byte => byte.toNat)\n"
        "  let candidateBytes : Bytes := candidateData.toList.map (fun byte => byte.toNat)\n"
        "  let some originalPe := parsePE32 originalBytes | throw (IO.userError \"original PE parse failed\")\n"
        "  let some candidatePe := parsePE32 candidateBytes | throw (IO.userError \"candidate PE parse failed\")\n"
        "  let some originalImports := parseImports originalPe | throw (IO.userError \"original imports parse failed\")\n"
        "  let some candidateImports := parseImports candidatePe | throw (IO.userError \"candidate imports parse failed\")\n"
        + "\n".join(evaluations)
        + "\n"
    )


def _run_lean_extractor(lean_dir: Path, *, bundle: str) -> dict[str, Any]:
    started = time.monotonic()
    lean = shutil.which("lean")
    if lean is None:
        return {"status": "unavailable", "returncode": None, "stdout": "", "stderr": "", "elapsed_seconds": 0.0}
    source = lean_dir / "StageA" / f"{bundle}.lean"
    if re.search(r"\b(?:sorry|axiom|unsafe)\b", source.read_text(encoding="utf-8")):
        return {"status": "unchecked_marker", "returncode": 1, "stdout": "", "stderr": str(source), "elapsed_seconds": 0.0}
    command = [lean, "--run", str(source.relative_to(lean_dir))]
    try:
        completed = subprocess.run(
            command,
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout", "command": command, "returncode": None,
            "stdout": exc.stdout or "", "stderr": exc.stderr or "",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    return {
        "status": "checked" if completed.returncode == 0 else "failed",
        "command": [command],
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _check_relational_counterexample(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    behaviors: list[dict[str, str]],
    production: dict[str, Any],
) -> dict[str, Any] | None:
    output = str(production.get("stderr") or "") + "\n" + str(production.get("stdout") or "")
    if "abstracted the following unsupported expressions" in output:
        return None
    assignment = _counterexample_assignment(output)
    if not assignment:
        return None
    for index, region in enumerate(contract["regions"]):
        concrete_assignment = _complete_counterexample_assignment(region, assignment)
        source = _lean_counterexample_source(
            original_bin,
            candidate_bin,
            original,
            candidate,
            contract["code_targets"],
            region,
            index,
            behaviors[index],
            concrete_assignment,
        )
        path = lean_dir / "StageA" / "RelationalCounterexample.lean"
        path.write_text(source, encoding="utf-8")
        checked = _run_lean_relational(lean_dir, bundle="RelationalCounterexample")
        if checked.get("status") == "checked":
            return {
                **checked,
                "counterexample": concrete_assignment,
                "region_id": region["id"],
                "theorem": "StageA.GeneratedRelationalCounterexample.exactCounterexample",
            }
    return None


def _complete_counterexample_assignment(region: dict[str, Any], assignment: dict[str, int]) -> dict[str, int]:
    completed = {
        f"{side}{register}": assignment.get(f"{side}{register}", 0)
        for side in ("o", "c")
        for register in REGISTERS
    }
    for pair in region["inputs"]:
        completed[f"c{pair['candidate']}"] = completed[f"o{pair['original']}"]
    return completed


def _lean_counterexample_source(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    targets: list[dict[str, Any]],
    region: dict[str, Any],
    index: int,
    behaviors: dict[str, str],
    assignment: dict[str, int],
) -> str:
    def registers(side: str) -> str:
        fields = ", ".join(
            f"{register} := BitVec.ofNat 32 {assignment[f'{side}{register}']}"
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )
        return "{ " + fields + " }"

    return (
        "import StageA.Relational\n\n"
        "namespace StageA.GeneratedRelationalCounterexample\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + _lean_byte_tree_definitions("originalBytes", original)
        + "\n\n"
        + _lean_byte_tree_definitions("candidateBytes", candidate)
        + "\n\n"
        f"def originalPe : PE32 := {_lean_pe(original_bin, 'originalBytes')}\n\n"
        f"def candidatePe : PE32 := {_lean_pe(candidate_bin, 'candidateBytes')}\n\n"
        f"def originalImportCertificate : ImportTableCertificate := {_lean_import_certificate(original_bin)}\n\n"
        f"def candidateImportCertificate : ImportTableCertificate := {_lean_import_certificate(candidate_bin)}\n\n"
        "def originalImports : List PEImport := originalImportCertificate.imports\n\n"
        "def candidateImports : List PEImport := candidateImportCertificate.imports\n\n"
        "theorem originalMetadataParsed : parsePEMetadataTree originalBytes = some originalPe.metadata := by decide\n\n"
        "theorem candidateMetadataParsed : parsePEMetadataTree candidateBytes = some candidatePe.metadata := by decide\n\n"
        "theorem originalParsed : parsePE32Tree originalBytes = some originalPe := by\n  simp [parsePE32Tree, originalMetadataParsed, PE32.metadata, PEMetadata.toPE32, originalPe]\n\n"
        "theorem candidateParsed : parsePE32Tree candidateBytes = some candidatePe := by\n  simp [parsePE32Tree, candidateMetadataParsed, PE32.metadata, PEMetadata.toPE32, candidatePe]\n\n"
        "theorem originalImportsChecked : importTableValid originalPe originalImportCertificate = true := by decide\n\n"
        "theorem candidateImportsChecked : importTableValid candidatePe candidateImportCertificate = true := by decide\n\n"
        + _lean_region_definition(index, region)
        + "\n\n"
        + f"def originalBehavior : SymbolicBehavior := {behaviors['original']}\n\n"
        + f"def candidateBehavior : SymbolicBehavior := {behaviors['candidate']}\n\n"
        + f"def originalState : MachineState := {{ registers := {registers('o')}, memory := fun _ => BitVec.ofNat 8 0 }}\n\n"
        + f"def candidateState : MachineState := {{ registers := {registers('c')}, memory := fun _ => BitVec.ofNat 8 0 }}\n\n"
        + f"theorem originalBehaviorCachedDecoded : regionBehaviorWithImports originalPe originalImports region{index}.original = some originalBehavior := by decide\n\n"
        + f"theorem candidateBehaviorCachedDecoded : regionBehaviorWithImports candidatePe candidateImports region{index}.candidate = some candidateBehavior := by decide\n\n"
        + f"theorem inputsRelated : statesRelated region{index}.bounds region{index}.addressSeparations region{index}.values region{index}.inputs originalState candidateState := by\n"
        + "  constructor\n  · decide\n  · constructor\n    · decide\n    · constructor\n      · decide\n      · exact ⟨rfl, rfl, rfl, rfl, rfl⟩\n\n"
        + "def outputsMatch : Bool :=\n"
        + f"  match evalBehavior false region{index}.targets originalState originalBehavior,\n"
        + f"      evalBehavior true region{index}.targets candidateState candidateBehavior with\n"
        + "  | some originalResult, some candidateResult =>\n"
        + f"      registersRelatedValues originalPe.imageBase candidatePe.imageBase region{index}.targets region{index}.values region{index}.outputs originalResult.registers candidateResult.registers &&\n"
        + "      decide (originalResult.x87 = candidateResult.x87) &&\n"
        + f"      writesRelated originalPe.imageBase candidatePe.imageBase region{index}.targets region{index}.values originalResult.writes candidateResult.writes &&\n"
        + f"      outcomesRelated originalPe.imageBase candidatePe.imageBase region{index}.targets region{index}.values originalResult.outcome candidateResult.outcome\n"
        + "  | _, _ => false\n\n"
        + "theorem outputsMismatch : outputsMatch = false := by decide\n\n"
        + "theorem exactCounterexample :\n"
        + "    parsePE32Tree originalBytes = some originalPe ∧\n"
        + "    parsePE32Tree candidateBytes = some candidatePe ∧\n"
        + "    importTableValid originalPe originalImportCertificate = true ∧\n"
        + "    importTableValid candidatePe candidateImportCertificate = true ∧\n"
        + f"    regionBehaviorWithImports originalPe originalImports region{index}.original = some originalBehavior ∧\n"
        + f"    regionBehaviorWithImports candidatePe candidateImports region{index}.candidate = some candidateBehavior ∧\n"
        + f"    statesRelated region{index}.bounds region{index}.addressSeparations region{index}.values region{index}.inputs originalState candidateState ∧ outputsMatch = false :=\n"
        + "  ⟨originalParsed, candidateParsed, originalImportsChecked, candidateImportsChecked, originalBehaviorCachedDecoded, candidateBehaviorCachedDecoded, inputsRelated, outputsMismatch⟩\n\n"
        + "#print axioms exactCounterexample\n\nend StageA.GeneratedRelationalCounterexample\n"
    )


def _lean_code_aliases(target: dict[str, Any], side: str) -> str:
    aliases = target.get(f"{side}_aliases", [])
    indices = target.get(f"{side}_alias_padding_indices", [])
    if len(aliases) != len(indices):
        raise StageAInputError(
            f"{side} alias padding certificate length does not match target {target.get('id')}"
        )
    rows = ", ".join(
        f"{{ rva := {alias}, paddingIndex := {padding_index} }}"
        for alias, padding_index in zip(aliases, indices, strict=True)
    )
    return f"[{rows}]"


def _lean_targets_definition(targets: list[dict[str, Any]]) -> str:
    target_rows = ", ".join(
        f"{{ id := {target['id']}, regionIndex := {target['region_index']}, originalRva := {target['original_rva']}, candidateRva := {target['candidate_rva']}, "
        f"originalAliases := {_lean_code_aliases(target, 'original')}, candidateAliases := {_lean_code_aliases(target, 'candidate')} }}"
        for target in targets
    )
    return f"def allTargets : List CodeTargetPair := [{target_rows}]"


def _lean_region_definition(index: int, region: dict[str, Any]) -> str:
    input_rows = ", ".join(_lean_register_pair(pair) for pair in region["inputs"])
    output_rows = ", ".join(_lean_register_pair(pair) for pair in region["outputs"])
    bound_rows = ", ".join(
        f"{{ original := .{bound['original']}, candidate := .{bound['candidate']}, upperExclusive := {bound['unsigned_lt']} }}"
        for bound in region.get("bounds", [])
    )
    target_rows = ", ".join(
        f"{{ id := {target['id']}, regionIndex := {target['region_index']}, originalRva := {target['original_rva']}, candidateRva := {target['candidate_rva']}, "
        f"originalAliases := {_lean_code_aliases(target, 'original')}, candidateAliases := {_lean_code_aliases(target, 'candidate')} }}"
        for target in region.get("code_targets", [])
    )
    value_rows = _lean_region_value_targets(region)
    flag_inputs = ", ".join(str(bit) for bit in region.get("flag_inputs", []))
    flag_outputs = ", ".join(str(bit) for bit in region.get("flag_outputs", []))
    separation_rows = ", ".join(
        "{ originalRegister := ." + separation["original_register"]
        + ", candidateRegister := ." + separation["candidate_register"]
        + ", originalOffset := " + str(separation["original_offset"])
        + ", candidateOffset := " + str(separation["candidate_offset"])
        + ", originalAddress := " + str(separation["original_address"])
        + ", candidateAddress := " + str(separation["candidate_address"])
        + " }"
        for separation in region.get("address_separations", [])
    )
    return (
        f"def region{index} : RegionRelation := {{ id := {region['numeric_id']}, root := {_lean_bool(region['root'])}, "
        f"original := {{ start := {region['original']['rva_start']}, size := {region['original']['size']} }}, "
        f"candidate := {{ start := {region['candidate']['rva_start']}, size := {region['candidate']['size']} }}, "
        f"inputs := [{input_rows}], outputs := [{output_rows}], bounds := [{bound_rows}], "
        f"flagInputs := [{flag_inputs}], flagOutputs := [{flag_outputs}], "
        f"addressSeparations := [{separation_rows}], "
        f"targets := [{target_rows}], values := [{value_rows}] }}"
    )


def _lean_value_target(target: dict[str, Any]) -> str:
    return (
        "{ id := " + str(target["id"])
        + ", originalValue := " + str(target["original_value"])
        + ", candidateValue := " + str(target["candidate_value"])
        + ", originalRelocationRva := " + str(target["original_relocation_rva"])
        + ", candidateRelocationRva := " + str(target["candidate_relocation_rva"])
        + ", mappedSize := " + str(target["mapped_size"])
        + ", relocationOffsets := ["
        + ", ".join(str(offset) for offset in target.get("relocation_offsets", []))
        + "] }"
    )


def _lean_region_value_targets(region: dict[str, Any]) -> str:
    return ", ".join(
        _lean_value_target(target)
        for target in region.get("values", [])
    )


def _lean_region_memory_lemmas(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    name = f"region{index}"
    mapped = [target for target in region.get("values", []) if target["mapped_size"] > 0]
    if not mapped:
        return ""
    rows: list[str] = []
    lemma_index = 0
    for target, offset in _lean_region_static_memory_lemma_specs(region, behaviors):
        rows.append(
            f"theorem {name}MappedAddress{lemma_index} : "
            f"normalizeDataAddress {name}.values "
            f"(BitVec.ofNat 32 {target['candidate_value'] + offset}) = "
            f"BitVec.ofNat 32 {target['original_value'] + offset} := by decide"
        )
        lemma_index += 1
    for indexed_index, (target, upper, shift, offset) in enumerate(
        _lean_region_indexed_memory_lemma_specs(region)
    ):
        scaled = (
            "index"
            if shift == 0
            else f"(index <<< {shift})"
        )
        proof_scaled = (
            "index"
            if shift == 0
            else f"(BitVec.extractLsb' 0 {32 - shift} index ++ BitVec.ofNat {shift} 0)"
        )
        shift_rewrite = (
            "  · rw [BitVec.shiftLeft_eq_concat_of_lt (by decide)]\n    "
            if shift > 0 else "  · "
        )
        candidate_address = target["candidate_value"] + offset
        original_address = target["original_value"] + offset
        zero_prefix_rewrites = "".join(
            "  simp only [normalizeDataAddress_cons_zero (target := "
            + _lean_value_target(zero_target)
            + ") (zero := rfl)]\n"
            for zero_target in region.get("values", [])[:-1]
        )
        rows.append(
            f"theorem {name}MappedIndexedAddress{indexed_index} (index : Word) "
            f"(bounded : index < BitVec.ofNat 32 {upper}) :\n"
            f"    normalizeDataAddress {name}.values "
            f"({scaled} + BitVec.ofNat 32 {candidate_address}) =\n"
            f"      {scaled} + BitVec.ofNat 32 {original_address} := by\n"
            + f"  unfold {name}\n"
            + zero_prefix_rewrites
            + f"  rw [normalizeDataAddress_singleton_of_contains]\n"
            + shift_rewrite
            + f"change BitVec.ofNat 32 {target['original_value']} + "
            f"({proof_scaled} + BitVec.ofNat 32 {candidate_address} - "
            f"BitVec.ofNat 32 {target['candidate_value']}) = "
            f"{proof_scaled} + BitVec.ofNat 32 {original_address}\n"
            f"    bv_normalize\n"
            f"  · simp [valueTargetContainsCandidate]\n"
            f"    bv_omega"
        )
    for relocation_index, (target, offset, _) in enumerate(
        _lean_region_static_relocation_word_specs(region, behaviors)
    ):
        rows.append(
            f"theorem {name}RelocationWordStartStatic{relocation_index} : "
            f"relocationWordStartCandidate {name}.values "
            f"(BitVec.ofNat 32 {target['candidate_value'] + offset}) = true := by decide"
        )
    for relocation_index, (target, upper, shift, offset, _) in enumerate(
        _lean_region_indexed_relocation_word_specs(region)
    ):
        scaled = "index" if shift == 0 else f"(index <<< {shift})"
        rows.append(
            f"theorem {name}RelocationWordStartIndexed{relocation_index} "
            f"(index : Word) (bounded : index < BitVec.ofNat 32 {upper}) :\n"
            f"    relocationWordStartCandidate {name}.values "
            f"({scaled} + BitVec.ofNat 32 {target['candidate_value'] + offset}) = true := by\n"
            f"  simp [relocationWordStartCandidate, valueRelocationWordStartCandidate, {name}]\n"
            f"  bv_omega"
        )
    return "\n\n".join(rows)


def _lean_region_static_memory_lemma_specs(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[tuple[dict[str, Any], int]]:
    candidate_constants = {
        int(value)
        for value in re.findall(
            r"StageA\.Formal\.Expr\.constant (\d+)",
            behaviors["candidate"],
        )
    }
    return [
        (target, constant - target["candidate_value"])
        for target in region.get("values", [])
        if target["mapped_size"] > 0
        for constant in sorted(candidate_constants)
        if target["candidate_value"] <= constant < target["candidate_value"] + target["mapped_size"]
    ]


def _lean_region_indexed_memory_lemma_specs(
    region: dict[str, Any],
) -> list[tuple[dict[str, Any], int, int, int]]:
    values = region.get("values", [])
    mapped_indices = [
        value_index for value_index, target in enumerate(values)
        if target["mapped_size"] > 0
    ]
    if len(mapped_indices) != 1 or mapped_indices[0] != len(values) - 1:
        return []
    if any(target["mapped_size"] != 0 for target in values[:-1]):
        return []
    target = values[-1]
    specs: list[tuple[dict[str, Any], int, int, int]] = []
    for upper in sorted({bound["unsigned_lt"] for bound in region.get("bounds", [])}):
        if upper <= 0 or target["mapped_size"] % upper != 0:
            continue
        element_size = target["mapped_size"] // upper
        if element_size not in {1, 2, 4, 8}:
            continue
        shift = element_size.bit_length() - 1
        specs.extend((target, upper, shift, offset) for offset in range(element_size))
    return specs


def _lean_region_static_relocation_word_specs(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[tuple[dict[str, Any], int, int]]:
    return [
        (target, offset, address_index)
        for address_index, (target, offset) in enumerate(
            _lean_region_static_memory_lemma_specs(region, behaviors)
        )
        if offset in target.get("relocation_offsets", [])
    ]


def _lean_region_indexed_relocation_word_specs(
    region: dict[str, Any],
) -> list[tuple[dict[str, Any], int, int, int, int]]:
    address_specs = _lean_region_indexed_memory_lemma_specs(region)
    result: list[tuple[dict[str, Any], int, int, int, int]] = []
    seen: set[tuple[int, int, int, int]] = set()
    for target, upper, shift, _ in address_specs:
        element_size = 1 << shift
        for word_offset in range(0, element_size - 3, 4):
            key = (target["id"], upper, shift, word_offset)
            required = {
                index * element_size + word_offset for index in range(upper)
            }
            if key in seen or not required.issubset(set(target.get("relocation_offsets", []))):
                continue
            seen.add(key)
            address_index = next(
                index for index, spec in enumerate(address_specs)
                if spec == (target, upper, shift, word_offset)
            )
            result.append((target, upper, shift, word_offset, address_index))
    return result


def _lean_region_memory_lemma_names(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[str]:
    static = [
        f"region{index}MappedAddress{offset}"
        for offset in range(len(_lean_region_static_memory_lemma_specs(region, behaviors)))
    ]
    indexed = [
        f"region{index}MappedIndexedAddressFact{offset}"
        for offset in range(len(_lean_region_indexed_memory_lemma_specs(region)))
    ]
    static_relocations = [
        name
        for offset in range(len(_lean_region_static_relocation_word_specs(region, behaviors)))
        for name in (
            f"region{index}RelocationWordRelatedStatic{offset}",
            f"region{index}RelocationWordZeroStatic{offset}",
            f"region{index}RelocationOriginalRead32Static{offset}",
            f"region{index}RelocationCandidateRead32Static{offset}",
        )
    ]
    indexed_relocations = [
        name
        for offset in range(len(_lean_region_indexed_relocation_word_specs(region)))
        for name in (
            f"region{index}RelocationWordRelatedIndexed{offset}",
            f"region{index}RelocationWordZeroIndexed{offset}",
        )
    ]
    return static + indexed + static_relocations + indexed_relocations


def _lean_region_indexed_memory_fact_names(index: int, region: dict[str, Any]) -> list[str]:
    return [
        f"region{index}MappedIndexedAddressFact{offset}"
        for offset in range(len(_lean_region_indexed_memory_lemma_specs(region)))
    ]


def _lean_region_bound_setup(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    bounds = region.get("bounds", [])
    specs = _lean_region_indexed_memory_lemma_specs(region)
    if not specs:
        return ""
    rows: list[str] = []
    if len(bounds) > 1:
        hypotheses = ", ".join(f"boundSatisfied{bound_index}" for bound_index in range(len(bounds)))
        rows.append(f"  rcases boundsSatisfied with ⟨{hypotheses}⟩")
    for spec_index, (_, upper, _, _) in enumerate(specs):
        bound_index = next(
            bound_index for bound_index, bound in enumerate(bounds)
            if bound["unsigned_lt"] == upper
        )
        hypothesis = "boundsSatisfied" if len(bounds) == 1 else f"boundSatisfied{bound_index}"
        register = bounds[bound_index]["original"]
        rows.append(
            f"  have region{index}MappedIndexedAddressFact{spec_index} := "
            f"region{index}MappedIndexedAddress{spec_index} o{register} {hypothesis}"
        )
    for mask_index, (register, mask, upper) in enumerate(
        _lean_region_index_masks(region, behaviors)
    ):
        bound_index = next(
            bound_index for bound_index, bound in enumerate(bounds)
            if bound["original"] == register and bound["unsigned_lt"] == upper
        )
        hypothesis = "boundsSatisfied" if len(bounds) == 1 else f"boundSatisfied{bound_index}"
        mask_width = (mask + 1).bit_length() - 1
        rows.append(
            f"  have region{index}IndexMaskFact{mask_index} : "
            f"o{register} &&& BitVec.ofNat 32 {mask} = o{register} := by\n"
            f"    apply BitVec.eq_of_toNat_eq\n"
            f"    simp only [BitVec.toNat_and, BitVec.toNat_ofNat]\n"
            f"    change o{register}.toNat &&& 2 ^ {mask_width} - 1 = o{register}.toNat\n"
            f"    apply Nat.and_two_pow_sub_one_of_lt_two_pow (n := {mask_width})\n"
            f"    have boundedNat : o{register}.toNat < {upper} := by\n"
            f"      simpa [BitVec.lt_def] using {hypothesis}\n"
            f"    omega"
        )
    return "\n".join(rows) + "\n"


def _lean_region_index_masks(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[tuple[str, int, int]]:
    masks: set[tuple[str, int, int]] = set()
    for bound in region.get("bounds", []):
        register = bound["original"]
        upper = bound["unsigned_lt"]
        pattern = re.compile(
            rf"StageA\.Formal\.Expr\.bitAnd \(StageA\.Formal\.Expr\.inputReg "
            rf"\(StageA\.Formal\.Reg\.{re.escape(register)}\)\) "
            r"\(StageA\.Formal\.Expr\.constant (\d+)\)"
        )
        for side in ("original", "candidate"):
            for value in pattern.findall(behaviors[side]):
                mask = int(value)
                if mask > 0 and mask & (mask + 1) == 0 and upper <= mask + 1:
                    masks.add((register, mask, upper))
    return sorted(masks)


def _lean_region_separation_setup(index: int, region: dict[str, Any]) -> tuple[str, str]:
    count = len(region.get("address_separations", []))
    if count == 0:
        return (
            f"  simp [addressSeparationsRelated, StageA.Formal.Registers.get, region{index}] "
            "at separationsSatisfied\n",
            "",
        )
    hypotheses = [
        hypothesis
        for separation_index in range(count)
        for hypothesis in (
            f"originalSeparation{separation_index}",
            f"candidateSeparation{separation_index}",
            f"originalSeparationReverse{separation_index}",
            f"candidateSeparationReverse{separation_index}",
        )
    ]
    row_patterns = [
        f"⟨originalSeparation{separation_index}, candidateSeparation{separation_index}⟩"
        for separation_index in range(count)
    ]
    setup = (
        f"  simp [addressSeparationsRelated, StageA.Formal.Registers.get, region{index}] "
        "at separationsSatisfied\n"
        "  rcases separationsSatisfied with ⟨" + ", ".join(row_patterns) + "⟩\n"
        + "".join(
            f"  have originalSeparationReverse{separation_index} := "
            f"Ne.symm originalSeparation{separation_index}\n"
            f"  have candidateSeparationReverse{separation_index} := "
            f"Ne.symm candidateSeparation{separation_index}\n"
            for separation_index in range(count)
        )
    )
    return setup, ", ".join(hypotheses)


def _lean_region_flag_setup(index: int, region: dict[str, Any]) -> tuple[str, str]:
    bits = region.get("flag_inputs", [])
    setup = (
        f"  simp [StageA.Relational.flagsRelated, region{index}] at flagsRelated\n"
    )
    if not bits:
        return setup, ""
    if len(bits) == 1:
        hypothesis = f"flagInputRelated{bits[0]}"
        return setup + f"  have {hypothesis} := flagsRelated\n", hypothesis
    hypotheses = [f"flagInputRelated{bit}" for bit in bits]
    setup += "  rcases flagsRelated with \u27e8" + ", ".join(hypotheses) + "\u27e9\n"
    return setup, ", ".join(hypotheses)


def _lean_region_memory_setup(
    index: int,
    region: dict[str, Any],
    original_image_base: str,
    candidate_image_base: str,
) -> str:
    name = f"region{index}"
    has_relocations = any(
        target.get("relocation_offsets") for target in region.get("values", [])
    )
    if has_relocations:
        return (
            "  have relocatedMemory := memoryRelated_with_relocations "
            f"{original_image_base} {candidate_image_base} {name}.targets {name}.values "
            "originalMemory candidateMemory (by decide) memoryRelated\n"
            "  rcases relocatedMemory with "
            "\u27e8ordinaryMemoryRelated, relocationWordsRelated\u27e9\n"
        )
    return (
        "  have exactMemory := memoryRelated_without_relocations "
        f"{original_image_base} {candidate_image_base} {name}.targets {name}.values "
        "originalMemory candidateMemory (by decide) memoryRelated\n"
        f"  change candidateMemory = fun address => originalMemory "
        f"(normalizeDataAddress {name}.values address) at exactMemory\n"
        "  subst candidateMemory\n"
    )


def _lean_region_relocation_memory_setup(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    name = f"region{index}"
    rows: list[str] = []
    for relocation_index, (target, offset, address_index) in enumerate(
        _lean_region_static_relocation_word_specs(region, behaviors)
    ):
        fact = f"{name}RelocationWordRelatedStatic{relocation_index}"
        original_read = f"{name}RelocationOriginalRead32Static{relocation_index}"
        candidate_read = f"{name}RelocationCandidateRead32Static{relocation_index}"
        zero_fact = f"{name}RelocationWordZeroStatic{relocation_index}"
        rows.extend((
            f"  have {original_read} := assembledMemoryRead32OfNat_eq "
            f"originalMemory {target['original_value'] + offset}",
            f"  have {candidate_read} := assembledMemoryRead32OfNat_eq "
            f"candidateMemory {target['candidate_value'] + offset}",
            f"  have {fact} := relocationWordsRelated "
            f"(BitVec.ofNat 32 {target['candidate_value'] + offset}) "
            f"{name}RelocationWordStartStatic{relocation_index}",
            f"  rw [{name}MappedAddress{address_index}] at {fact}",
            f"  simp only [{name}] at {fact}",
            f"  have {zero_fact} := wordRelated_zero_equal {fact}",
        ))
    bounds = region.get("bounds", [])
    for relocation_index, (target, upper, shift, offset, address_index) in enumerate(
        _lean_region_indexed_relocation_word_specs(region)
    ):
        bound_index = next(
            bound_index for bound_index, bound in enumerate(bounds)
            if bound["unsigned_lt"] == upper
        )
        bound = bounds[bound_index]
        hypothesis = "boundsSatisfied" if len(bounds) == 1 else f"boundSatisfied{bound_index}"
        register = f"o{bound['original']}"
        scaled = register if shift == 0 else f"({register} <<< {shift})"
        fact = f"{name}RelocationWordRelatedIndexed{relocation_index}"
        zero_fact = f"{name}RelocationWordZeroIndexed{relocation_index}"
        rows.extend((
            f"  have {fact} := relocationWordsRelated "
            f"({scaled} + BitVec.ofNat 32 {target['candidate_value'] + offset}) "
            f"({name}RelocationWordStartIndexed{relocation_index} {register} {hypothesis})",
            f"  rw [{name}MappedIndexedAddressFact{address_index}] at {fact}",
            f"  simp only [{name}] at {fact}",
        ))
        if shift > 0:
            rows.append(
                f"  rw [BitVec.shiftLeft_eq_concat_of_lt (by decide)] at {fact}"
            )
        rows.append(f"  have {zero_fact} := wordRelated_zero_equal {fact}")
    return "\n".join(rows) + ("\n" if rows else "")


def _normalized_behavior_structure_matches(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> bool:
    registers = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
    for field in ("inputs", "outputs"):
        pairs = region.get(field, [])
        if {
            pair["original"] for pair in pairs
            if pair.get("original") == pair.get("candidate")
        } != registers or len(pairs) != len(registers):
            return False
    if region.get("bounds") or region.get("values"):
        return False

    marker = ", outcome := "
    try:
        original_core, original_outcome = behaviors["original"].rsplit(marker, 1)
        candidate_core, candidate_outcome = behaviors["candidate"].rsplit(marker, 1)
    except ValueError:
        return False
    if original_core != candidate_core:
        return False
    def target_id(side: str, rva: int) -> int | None:
        for target in region.get("code_targets", []):
            if rva == target[f"{side}_rva"] or rva in target.get(f"{side}_aliases", []):
                return target["id"]
        return None

    def outcome_key(side: str, outcome: str) -> tuple[Any, ...] | None:
        if side == "candidate" and outcome == original_outcome:
            return ("exact", outcome)
        jump = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.jump (\d+)\) \}",
            outcome,
        )
        if jump is not None:
            mapped = target_id(side, int(jump.group(1)))
            return ("jump", mapped) if mapped is not None else None

        branch = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.branch (.*) (\d+) (\d+)\) \}",
            outcome,
        )
        if branch is not None:
            taken = target_id(side, int(branch.group(2)))
            fallthrough = target_id(side, int(branch.group(3)))
            if taken is not None and fallthrough is not None:
                return ("branch", branch.group(1), taken, fallthrough)
            return None

        call = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.call (\d+) (\d+) \d+\) \}",
            outcome,
        )
        if call is not None:
            target = target_id(side, int(call.group(1)))
            continuation = target_id(side, int(call.group(2)))
            if target is not None and continuation is not None:
                return ("call", target, continuation)
            return None

        continuation_form = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.(externalCall|bulkCopy|checkedContinue|atomicCompareExchange) "
            r"(.*) (\d+)\) \}",
            outcome,
        )
        if continuation_form is not None:
            continuation = target_id(side, int(continuation_form.group(3)))
            if continuation is not None:
                return (
                    continuation_form.group(1),
                    continuation_form.group(2),
                    continuation,
                )
            return None

        indirect_call = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.indirectCall (.*) (\d+) \d+\) \}",
            outcome,
        )
        if indirect_call is not None:
            continuation = target_id(side, int(indirect_call.group(2)))
            if continuation is not None:
                return ("indirectCall", indirect_call.group(1), continuation)
        return None

    if original_outcome == candidate_outcome:
        return True
    original_key = outcome_key("original", original_outcome)
    candidate_key = outcome_key("candidate", candidate_outcome)
    return original_key is not None and original_key == candidate_key


def _normalized_behavior_fast_path(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> bool:
    all_flag_bits = list(FLAG_BITS)
    return (
        region.get("flag_inputs", all_flag_bits) == all_flag_bits
        and region.get("flag_outputs", all_flag_bits) == all_flag_bits
        and _normalized_behavior_structure_matches(region, behaviors)
    )


def _lean_behavior_field(source: str, field: str, next_field: str) -> str | None:
    end_marker = f", {next_field} := "
    for start_marker in (f", {field} := ", f"{{ {field} := "):
        try:
            return source.split(start_marker, 1)[1].split(end_marker, 1)[0]
        except (AttributeError, IndexError):
            continue
    return None


def _lean_behavior_fields_memory_free(
    behaviors: dict[str, str], field: str, next_field: str
) -> bool:
    values = [
        _lean_behavior_field(behaviors.get(side, ""), field, next_field)
        for side in ("original", "candidate")
    ]
    if any(value is None for value in values):
        return False
    memory_dependencies = (
        "StageA.Formal.X87Expr.load ",
        "StageA.Formal.Expr.read8 ",
        "StageA.Formal.Expr.read32 ",
        "StageA.Formal.Expr.read8AfterWrite ",
    )
    return all(
        not any(marker in value for marker in memory_dependencies)
        for value in values if value is not None
    )


def _lean_x87_state_only_pair(behaviors: dict[str, str]) -> bool:
    original = _lean_behavior_field(behaviors.get("original", ""), "x87", "writes")
    candidate = _lean_behavior_field(behaviors.get("candidate", ""), "x87", "writes")
    if original is None or original != candidate:
        return False
    external_dependencies = (
        "StageA.Formal.X87Expr.load ",
        "StageA.Formal.Expr.inputReg ",
        "StageA.Formal.Expr.inputFlagValue ",
        "StageA.Formal.Expr.inputFsBase",
        "StageA.Formal.Expr.read8 ",
        "StageA.Formal.Expr.read32 ",
        "StageA.Formal.Expr.read8AfterWrite ",
        "StageA.Formal.Expr.undefinedValue ",
    )
    return not any(marker in original for marker in external_dependencies)


def _lean_normalized_static_outcome(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str | None:
    try:
        outcome = behaviors["original"].rsplit(", outcome := ", 1)[1]
    except (KeyError, ValueError):
        return None

    def target_id(rva: int) -> int | None:
        for target in region.get("code_targets", []):
            if rva == target["original_rva"] or rva in target.get("original_aliases", []):
                return int(target["id"])
        return None

    jump = re.fullmatch(r"some \(StageA\.Formal\.OutcomeExpr\.jump (\d+)\) \}", outcome)
    if jump is not None:
        target = target_id(int(jump.group(1)))
        return (
            f"StageA.Relational.NormalizedOutcomeExpr.jump {target}"
            if target is not None else None
        )

    branch = re.fullmatch(
        r"some \(StageA\.Formal\.OutcomeExpr\.branch (.*) (\d+) (\d+)\) \}",
        outcome,
    )
    if branch is not None:
        taken = target_id(int(branch.group(2)))
        fallthrough = target_id(int(branch.group(3)))
        if taken is not None and fallthrough is not None:
            return (
                "StageA.Relational.NormalizedOutcomeExpr.branch "
                f"({branch.group(1)}) {taken} {fallthrough}"
            )
        return None

    call = re.fullmatch(
        r"some \(StageA\.Formal\.OutcomeExpr\.call (\d+) (\d+) \d+\) \}",
        outcome,
    )
    if call is not None:
        target = target_id(int(call.group(1)))
        continuation = target_id(int(call.group(2)))
        if target is not None and continuation is not None:
            return (
                "StageA.Relational.NormalizedOutcomeExpr.call "
                f"{target} {continuation}"
            )
    return None


def _lean_bundle_source(original_bin: StageABinary, candidate_bin: StageABinary, original: bytes, candidate: bytes, contract: dict[str, Any], behaviors: list[dict[str, str]], *, replay: bool, certificates: list[dict[str, Any]] | None = None) -> str:
    certificate_by_region = {entry.get("region_id"): entry for entry in certificates or []}
    region_defs: list[str] = []
    theorem_defs: list[str] = []
    theorem_names: list[str] = []
    for index, region in enumerate(contract["regions"]):
        name = f"region{index}"
        theorem_name = f"{name}Checked"
        memory_lemmas = ", ".join(
            _lean_region_memory_lemma_names(index, region, behaviors[index])
        )
        memory_lemma_line = f"    {memory_lemmas},\n" if memory_lemmas else ""
        memory_normalizer_line = (
            "    normalizeDataAddress, valueTargetContainsCandidate,\n"
            if region.get("values") and not _lean_region_indexed_memory_lemma_specs(region) else ""
        )
        bound_setup = _lean_region_bound_setup(index, region, behaviors[index])
        flag_setup, flag_hypotheses = _lean_region_flag_setup(index, region)
        flag_lemma_line = f"    {flag_hypotheses},\n" if flag_hypotheses else ""
        normalized_flag_simplifiers = f", {flag_hypotheses}" if flag_hypotheses else ""
        relocation_memory_setup = _lean_region_relocation_memory_setup(
            index, region, behaviors[index]
        )
        separation_setup, separation_hypotheses = _lean_region_separation_setup(index, region)
        separation_lemma_line = (
            f"    {separation_hypotheses},\n" if separation_hypotheses else ""
        )
        indexed_memory_facts = _lean_region_indexed_memory_fact_names(index, region)
        index_mask_facts = [
            f"region{index}IndexMaskFact{mask_index}"
            for mask_index in range(len(_lean_region_index_masks(region, behaviors[index])))
        ]
        indexed_memory_rewrite = (
            (
                f"  all_goals try simp only [{', '.join(index_mask_facts)}]\n"
                if index_mask_facts else ""
            )
            + f"  all_goals try simp only [{', '.join(indexed_memory_facts)}]\n"
            + "  all_goals try simp\n"
            if indexed_memory_facts else ""
        )
        has_relocation_word_facts = bool(
            _lean_region_static_relocation_word_specs(region, behaviors[index])
            or _lean_region_indexed_relocation_word_specs(region)
        )
        word_relation_simplifiers = (
            "wordRelated_self"
            if has_relocation_word_facts else
            "wordRelated, codePointerRelated, codeAddressMatches, mappedValueRelated"
        )
        image_simplifiers = "" if has_relocation_word_facts else "originalPe, candidatePe, "
        memory_read_simplifiers = (
            "machineStateRead32_eq_memoryRead32, assembledMemoryRead32_eq, "
            "assembledMemoryRead32OfNat_eq"
            if has_relocation_word_facts else
            "StageA.Formal.MachineState.read32, Memory.read32"
        )
        flag_eval_simplifiers = (
            "StageA.Formal.FlagsExpr.eval_extract_cf, "
            "StageA.Formal.FlagsExpr.eval_extract_pf, "
            "StageA.Formal.FlagsExpr.eval_extract_zf, "
            "StageA.Formal.FlagsExpr.eval_extract_sf, "
            "StageA.Formal.FlagsExpr.eval_extract_df, "
            "StageA.Formal.FlagsExpr.eval_extract_of, StageA.Formal.evalFlagBit"
        )
        theorem_names.append(theorem_name)
        region_defs.append(_lean_region_definition(index, region))
        region_defs.append(_lean_region_memory_lemmas(index, region, behaviors[index]))
        region_defs.append(f"def originalBehavior{index} : SymbolicBehavior := {behaviors[index]['original']}")
        region_defs.append(f"def candidateBehavior{index} : SymbolicBehavior := {behaviors[index]['candidate']}")
        if replay:
            certificate = certificate_by_region.get(region["id"])
            if certificate and certificate.get("kind") == "lrat":
                tactic = f"bv_check \"../../certificates/{certificate['path']}\""
            elif certificate and certificate.get("kind") == "lean_normalization":
                tactic = "bv_normalize"
            else:
                tactic = "fail_if_success trivial"
        else:
            tactic = "bv_decide? (config := { timeout := 120, trimProofs := false })"
        input_hypotheses = [f"inputRelated{pair_index}" for pair_index in range(len(region["inputs"]))]
        if len(input_hypotheses) > 1:
            relation_destructure = "  rcases related with ⟨" + ", ".join(input_hypotheses) + "⟩\n"
        else:
            relation_destructure = ""
        substitutions = "".join(
            f"  subst c{pair['candidate']}\n" for pair in region["inputs"]
        )
        normalized_fast_path = _normalized_behavior_fast_path(region, behaviors[index])
        normalized_theorem = (
            f"theorem {name}NormalizedBehavior : "
            f"normalizeSymbolicBehavior false {name}.targets originalBehavior{index} = "
            f"normalizeSymbolicBehavior true {name}.targets candidateBehavior{index} := by decide\n\n"
            f"theorem {name}NormalizedBehaviorExists : "
            f"(normalizeSymbolicBehavior false {name}.targets originalBehavior{index}).isSome := by decide\n\n"
            if normalized_fast_path else ""
        )
        proof_steps = (
            f"  unfold evalBehavior\n"
            f"  rw [← {name}NormalizedBehavior]\n"
            f"  cases normalized : normalizeSymbolicBehavior false {name}.targets originalBehavior{index} with\n"
            f"  | none => simpa [normalized] using {name}NormalizedBehaviorExists\n"
            "  | some behavior =>\n"
            f"    simp [normalized, NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
            f"registersRelatedValues, writesRelated_self, outcomesRelated_self, "
            f"StageA.Relational.flagsRelated, "
            f"wordRelated{normalized_flag_simplifiers}, {name}]\n"
            if normalized_fast_path else (
                "  simp [evalBehavior, evalBehaviorRegisters, evalBehaviorX87, evalBehaviorWrites, "
                "evalBehaviorFlags, evalBehaviorOutcome, normalizeSymbolicBehavior, normalizeOutcomeExpr, "
                "NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
                "evalNormalizedRegisters, evalNormalizedX87, evalNormalizedWrites, evalNormalizedFlags, "
                "StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval, "
                f"{flag_eval_simplifiers},\n"
                f"    {memory_read_simplifiers}, StageA.Formal.MachineState.readX87Word,\n"
                "    StageA.Formal.read8AfterWriteValue,\n"
                "    StageA.Formal.X87LoadFormat.byteWidth, registersRelated, registersRelatedValues,\n"
                "    StageA.Formal.Registers.get, StageA.Formal.Registers.set, normalizeCodeTarget, normalizeImport,\n"
                f"    writesRelated, wordsRelated, outcomesRelated, "
                f"StageA.Relational.flagsRelated, "
                f"{word_relation_simplifiers}, "
                f"{image_simplifiers}\n"
                + memory_normalizer_line
                + memory_lemma_line
                + separation_lemma_line
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                + indexed_memory_rewrite
                + f"  all_goals first | rfl | {tactic}\n"
            )
        )
        theorem_defs.append(
            f"theorem originalBehavior{index}CachedDecoded : regionBehaviorWithImports originalPe originalImports {name}.original = some originalBehavior{index} := by decide\n\n"
            + f"theorem candidateBehavior{index}CachedDecoded : regionBehaviorWithImports candidatePe candidateImports {name}.candidate = some candidateBehavior{index} := by decide\n\n"
            + normalized_theorem
            + f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent originalPe.imageBase candidatePe.imageBase originalBehavior{index} candidateBehavior{index} {name} := by\n"
            "  unfold behaviorsEquivalent\n"
            "  intro originalState candidateState related\n"
            "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
            "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
            "  unfold statesRelated at related\n"
            "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
            + _lean_region_memory_setup(
                index, region, "originalPe.imageBase", "candidatePe.imageBase",
            )
            + "  change originalUndefined = candidateUndefined at undefinedRelated\n"
            "  subst candidateUndefined\n"
            "  change originalX87 = candidateX87 at x87Related\n"
            "  subst candidateX87\n"
            + flag_setup
            + "  change originalFsBase = candidateFsBase at fsBaseRelated\n"
            "  subst candidateFsBase\n"
            "  simp [registersRelated, StageA.Formal.Registers.get, " + name + "] at related\n"
            + relation_destructure
            + substitutions
            + "  simp [StageA.Relational.boundsRelated, StageA.Formal.Registers.get, " + name + "] at boundsSatisfied\n"
            + bound_setup
            + relocation_memory_setup
            + separation_setup
            + proof_steps
            + f"\ntheorem {theorem_name}Direct : regionEquivalentWithImports originalPe candidatePe originalImports candidateImports {name} :=\n"
            f"  regionEquivalentWithImports_of_decoded originalPe candidatePe originalImports candidateImports {name} originalBehavior{index} candidateBehavior{index}\n"
            f"    originalBehavior{index}CachedDecoded candidateBehavior{index}CachedDecoded {theorem_name}DirectBehavior\n"
            f"\ntheorem {theorem_name} : regionGoal proofBundle {name} := by\n"
            "  unfold regionGoal parsedImages proofBundle\n"
            "  rw [originalParsed, candidateParsed]\n"
            f"  exact {theorem_name}Direct\n"
        )
    regions_literal = ", ".join(f"region{index}" for index in range(len(contract["regions"])))
    region_index_literal = _lean_index_tree(
        [f"region{index}" for index in range(len(contract["regions"]))]
    )
    original_padding = ", ".join(
        _lean_span(item) for item in contract["padding"] if item["side"] in {"original", "both"}
    )
    candidate_padding = ", ".join(
        _lean_span(item) for item in contract["padding"] if item["side"] in {"candidate", "both"}
    )
    original_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "original")
    )
    candidate_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "candidate")
    )
    original_alias_coverage = _lean_padding_alias_certificate(
        _side_padding(contract, "original")
    )
    candidate_alias_coverage = _lean_padding_alias_certificate(
        _side_padding(contract, "candidate")
    )
    all_proof = (
        "".join(f"And.intro {name} (" for name in theorem_names)
        + "True.intro"
        + ")" * len(theorem_names)
    )
    return (
        "import StageA.Relational\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + _lean_byte_tree_definitions("originalBytes", original)
        + "\n\n"
        + _lean_byte_tree_definitions("candidateBytes", candidate)
        + "\n\n"
        f"def originalPe : PE32 := {_lean_pe(original_bin, 'originalBytes')}\n\n"
        f"def candidatePe : PE32 := {_lean_pe(candidate_bin, 'candidateBytes')}\n\n"
        f"def originalImportCertificate : ImportTableCertificate := {_lean_import_certificate(original_bin)}\n\n"
        f"def candidateImportCertificate : ImportTableCertificate := {_lean_import_certificate(candidate_bin)}\n\n"
        "def originalImports : List PEImport := originalImportCertificate.imports\n\n"
        "def candidateImports : List PEImport := candidateImportCertificate.imports\n\n"
        + "\n\n"
        "theorem originalMetadataParsed : parsePEMetadataTree originalBytes = some originalPe.metadata := by decide\n\n"
        "theorem candidateMetadataParsed : parsePEMetadataTree candidateBytes = some candidatePe.metadata := by decide\n\n"
        "theorem originalParsed : parsePE32Tree originalBytes = some originalPe := by\n  simp [parsePE32Tree, originalMetadataParsed, PE32.metadata, PEMetadata.toPE32, originalPe]\n\n"
        "theorem candidateParsed : parsePE32Tree candidateBytes = some candidatePe := by\n  simp [parsePE32Tree, candidateMetadataParsed, PE32.metadata, PEMetadata.toPE32, candidatePe]\n\n"
        "theorem originalImportsChecked : importTableValid originalPe originalImportCertificate = true := by decide\n\n"
        "theorem candidateImportsChecked : importTableValid candidatePe candidateImportCertificate = true := by decide\n\n"
        + "\n\n".join(region_defs)
        + f"\n\ndef allRegionIndex : IndexTree RegionRelation := {region_index_literal}\n\n"
        + f"def proofBundle : StageA.Relational.ProofBundle := {{ originalBytes, candidateBytes, originalImports := originalImportCertificate, candidateImports := candidateImportCertificate, regions := allRegionIndex.toList, regionIndex := allRegionIndex, originalPadding := [{original_padding}], candidatePadding := [{candidate_padding}], originalCoverage := {original_coverage}, candidateCoverage := {candidate_coverage}, originalAliasCoverage := {original_alias_coverage}, candidateAliasCoverage := {candidate_alias_coverage} }}\n\n"
        + "\n".join(theorem_defs)
        + "\ntheorem structuralChecked : structuralEligible proofBundle = true := by decide\n\n"
        + "theorem importsChecked : importTablesCertified proofBundle := by\n  unfold importTablesCertified parsedImages proofBundle\n  rw [originalParsed, candidateParsed]\n  exact ⟨originalImportsChecked, candidateImportsChecked⟩\n\n"
        + "theorem allRegionsChecked : allRegionGoals proofBundle proofBundle.regions := by\n  change "
        + " ∧ ".join([f"regionGoal proofBundle region{index}" for index in range(len(contract["regions"]))] + ["True"])
        + "\n  exact "
        + all_proof
        + "\n\ntheorem candidateRelationalCertificate : RelationalImageCertificate proofBundle :=\n"
        "  relationalImageCertificate_intro proofBundle structuralChecked importsChecked allRegionsChecked\n\n"
        "#print axioms candidateRelationalCertificate\n\nend StageA.GeneratedRelational\n"
    )


def _write_sharded_relational_proof(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    behaviors: list[dict[str, str]],
    *,
    replay: bool,
    certificates: list[dict[str, Any]] | None = None,
) -> tuple[list[str], int]:
    certificate_by_region = {entry.get("region_id"): entry for entry in certificates or []}

    regions_literal = ", ".join(f"region{index}" for index in range(len(contract["regions"])))
    region_index_literal = _lean_index_tree(
        [f"region{index}" for index in range(len(contract["regions"]))]
    )
    required_inputs_literal = ", ".join(
        _lean_register_pair(pair) for pair in _required_input_pairs(contract["regions"])
    )
    original_padding_items = _side_padding(contract, "original")
    candidate_padding_items = _side_padding(contract, "candidate")
    original_padding = ", ".join(_lean_span(item) for item in original_padding_items)
    candidate_padding = ", ".join(_lean_span(item) for item in candidate_padding_items)
    original_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "original")
    )
    candidate_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "candidate")
    )
    original_alias_coverage = _lean_padding_alias_certificate(
        original_padding_items
    )
    candidate_alias_coverage = _lean_padding_alias_certificate(
        candidate_padding_items
    )
    for side, binary, data in (
        ("original", original_bin, original),
        ("candidate", candidate_bin, candidate),
    ):
        module_side = side.capitalize()
        _write_text_if_changed(
            lean_dir / "StageA" / f"RelationalProof{module_side}.lean",
            _lean_pe_side_source(side, binary, data),
        )
    base = (
        "import StageA.RelationalProofOriginal\n"
        "import StageA.RelationalProofCandidate\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(lean_dir / "StageA" / "RelationalProofBase.lean", base)

    shard_size = max(1, int(os.environ.get("WINCR_STAGE_A_RELATIONAL_PROOF_SHARD", "8")))
    shard_byte_target = max(
        1,
        int(os.environ.get("WINCR_STAGE_A_RELATIONAL_PROOF_SHARD_BYTES", "500000")),
    )
    estimated_region_bytes: list[int] = []
    for index, region in enumerate(contract["regions"]):
        estimated_region_bytes.append(
            len(behaviors[index]["original"])
            + len(behaviors[index]["candidate"])
            + len(_lean_region_definition(index, region))
            + len(_lean_region_memory_lemmas(index, region, behaviors[index]))
            + 16_384
        )
    shard_groups = _partition_proof_shards(
        estimated_region_bytes,
        max_regions=shard_size,
        target_bytes=shard_byte_target,
    )

    definition_modules: list[str] = []
    shard_modules: list[str] = []
    for shard_index, indices in enumerate(shard_groups):
        definition_module = f"RelationalDefinitionsShard{shard_index}"
        definition_modules.append(definition_module)
        module = f"RelationalProofShard{shard_index}"
        shard_modules.append(module)
        definitions = []
        theorems = []
        for index in indices:
            definitions.append(_lean_region_definition(index, contract["regions"][index]))
            definitions.append(
                _lean_region_memory_lemmas(
                    index, contract["regions"][index], behaviors[index]
                )
            )
            definitions.append(f"def originalBehavior{index} : SymbolicBehavior := {behaviors[index]['original']}")
            definitions.append(f"def candidateBehavior{index} : SymbolicBehavior := {behaviors[index]['candidate']}")
            theorems.append(_lean_region_theorem_source(
                index,
                contract["regions"][index],
                behaviors[index],
                original_image_base=original_bin.image_base,
                candidate_image_base=candidate_bin.image_base,
                replay=replay,
                certificate=certificate_by_region.get(contract["regions"][index]["id"]),
            ))
        definition_source = (
            "import StageA.Relational\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{definition_module}.lean", definition_source
        )
        proof_source = (
            f"import StageA.{definition_module}\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + "\n\n".join(theorems)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", proof_source)

    decode_chunk_count = min(
        len(shard_groups),
        max(1, int(os.environ.get("WINCR_STAGE_A_RELATIONAL_DECODE_CHUNKS", "32"))),
    )
    shards_per_decode_chunk = (
        len(shard_groups) + decode_chunk_count - 1
    ) // decode_chunk_count
    decode_modules: list[str] = []
    decode_chunk_regions: list[list[int]] = []
    decode_chunk_shards: list[list[int]] = []
    for chunk_index, shard_offset in enumerate(
        range(0, len(shard_groups), shards_per_decode_chunk)
    ):
        selected_shard_indices = list(range(
            shard_offset,
            min(len(shard_groups), shard_offset + shards_per_decode_chunk),
        ))
        selected_region_indices = [
            region_index
            for shard_index in selected_shard_indices
            for region_index in shard_groups[shard_index]
        ]
        decode_chunk_shards.append(selected_shard_indices)
        decode_chunk_regions.append(selected_region_indices)
        definition_imports = "\n".join(
            f"import StageA.{definition_modules[shard_index]}"
            for shard_index in selected_shard_indices
        )
        for side in ("original", "candidate"):
            module_side = side.capitalize()
            module = f"RelationalProof{module_side}DecodeChunk{chunk_index}"
            decode_modules.append(module)
            decode_theorems = "\n\n".join(
                f"theorem {side}Behavior{index}CheckedDecoded : "
                f"regionBehaviorWithImports {side}Pe {side}Imports region{index}.{side} = "
                f"some {side}Behavior{index} := by decide"
                for index in selected_region_indices
            )
            source = (
                f"import StageA.RelationalProof{module_side}\n"
                + definition_imports
                + "\n\nnamespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
                "set_option linter.unusedSimpArgs false\n\n"
                + decode_theorems
                + "\n\nend StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(
                lean_dir / "StageA" / f"{module}.lean",
                source,
            )

    region_chunk_names = [
        f"regionChunk{index}" for index in range(len(decode_chunk_regions))
    ]
    region_chunks_source = (
        "\n".join(f"import StageA.{module}" for module in definition_modules)
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + "\n\n".join(
            f"def {name} : List RegionRelation := ["
            + ", ".join(f"region{index}" for index in indices)
            + "]"
            for name, indices in zip(
                region_chunk_names, decode_chunk_regions, strict=True
            )
        )
        + "\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalRegionChunks.lean", region_chunks_source
    )

    direct_modules: list[str] = []
    for chunk_index, region_indices in enumerate(decode_chunk_regions):
        direct_module = f"RelationalProofDirectChunk{chunk_index}"
        direct_modules.append(direct_module)
        direct_region_chunk = region_chunk_names[chunk_index]
        direct_theorems = "\n\n".join(
            f"theorem region{index}CheckedDirect : regionEquivalentWithImports originalPe candidatePe "
            f"originalImports candidateImports region{index} :=\n"
            f"  regionEquivalentWithImports_of_decoded originalPe candidatePe originalImports candidateImports "
            f"region{index} originalBehavior{index} candidateBehavior{index}\n"
            f"    originalBehavior{index}CheckedDecoded candidateBehavior{index}CheckedDecoded "
            f"region{index}CheckedDirectBehavior"
            for index in region_indices
        )
        direct_chunk_goal = " ∧ ".join(
            [
                f"regionEquivalentWithImports originalPe candidatePe originalImports candidateImports region{index}"
                for index in region_indices
            ]
            + ["True"]
        )
        direct_chunk_proof = (
            "".join(
                f"And.intro region{index}CheckedDirect (" for index in region_indices
            )
            + "True.intro"
            + ")" * len(region_indices)
        )
        direct_source = (
            f"import StageA.RelationalProofOriginalDecodeChunk{chunk_index}\n"
            f"import StageA.RelationalProofCandidateDecodeChunk{chunk_index}\n\n"
            "import StageA.RelationalRegionChunks\n"
            + "\n".join(
                f"import StageA.{shard_modules[shard_index]}"
                for shard_index in decode_chunk_shards[chunk_index]
            )
            + "\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + direct_theorems
            + f"\n\ntheorem directRegionChunk{chunk_index}Checked :\n"
            f"    allDirectRegionGoals originalPe candidatePe originalImports candidateImports {direct_region_chunk} := by\n"
            f"  change {direct_chunk_goal}\n"
            f"  exact {direct_chunk_proof}"
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{direct_module}.lean",
            direct_source,
        )

    required_input_states: list[list[dict[str, str]]] = [[]]
    for indices in decode_chunk_regions:
        required_input_states.append(
            _required_input_pairs_from(
                required_input_states[-1],
                [contract["regions"][index] for index in indices],
            )
        )
    required_state_definitions = "\n\n".join(
        f"def requiredInputsState{index} : List RegisterPair := ["
        + ", ".join(_lean_register_pair(pair) for pair in state)
        + "]"
        for index, state in enumerate(required_input_states)
    )
    padding_chunk_size = max(
        1, int(os.environ.get("WINCR_STAGE_A_RELATIONAL_PADDING_CHUNK", "128"))
    )
    padding_groups = {
        "original": [
            original_padding_items[offset : offset + padding_chunk_size]
            for offset in range(0, len(original_padding_items), padding_chunk_size)
        ] or [[]],
        "candidate": [
            candidate_padding_items[offset : offset + padding_chunk_size]
            for offset in range(0, len(candidate_padding_items), padding_chunk_size)
        ] or [[]],
    }
    padding_chunk_names = {
        side: [f"{side}PaddingChunk{index}" for index in range(len(groups))]
        for side, groups in padding_groups.items()
    }
    padding_definitions = "\n\n".join(
        f"def {name} : List Span := ["
        + ", ".join(_lean_span(span) for span in group)
        + "]"
        for side in ("original", "candidate")
        for name, group in zip(
            padding_chunk_names[side], padding_groups[side], strict=True
        )
    )
    closure_data_source = (
        "import StageA.RelationalProofBase\n"
        "import StageA.RelationalRegionChunks\n"
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + required_state_definitions
        + "\n\n"
        + padding_definitions
        + "\n\n"
        f"def allRegionIndex : IndexTree RegionRelation := {region_index_literal}\n\n"
        f"def allRegions : List RegionRelation := {_lean_right_append(region_chunk_names)}\n\n"
        f"def originalPadding : List Span := {_lean_right_append(padding_chunk_names['original'])}\n\n"
        f"def candidatePadding : List Span := {_lean_right_append(padding_chunk_names['candidate'])}\n\n"
        f"def requiredInputsCertificate : List RegisterPair := requiredInputsState{len(region_chunk_names)}\n\n"
        f"def originalCoverage : SortedSpanCertificate := {original_coverage}\n\n"
        f"def candidateCoverage : SortedSpanCertificate := {candidate_coverage}\n\n"
        f"def originalAliasCoverage : PaddingAliasCertificate := {original_alias_coverage}\n\n"
        f"def candidateAliasCoverage : PaddingAliasCertificate := {candidate_alias_coverage}\n\n"
        "def proofBundle : StageA.Relational.ProofBundle := { originalBytes, candidateBytes, "
        "originalImports := originalImportCertificate, candidateImports := candidateImportCertificate, "
        "regions := allRegions, regionIndex := allRegionIndex, originalPadding, candidatePadding, "
        "originalCoverage, candidateCoverage, originalAliasCoverage, candidateAliasCoverage }\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProofClosureData.lean",
        closure_data_source,
    )

    structural_region_modules: list[str] = []
    for chunk_index, chunk_name in enumerate(region_chunk_names):
        module = f"RelationalProofStructuralRegionChunk{chunk_index}"
        structural_region_modules.append(module)
        source = (
            "import StageA.RelationalProofClosureData\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"theorem regionStructureItemsChunk{chunk_index}Checked :\n"
            f"    {chunk_name}.all (fun region =>\n"
            "      spanInExecutableSection originalPe region.original &&\n"
            "      spanInExecutableSection candidatePe region.candidate &&\n"
            "      region.inputs.length > 0 && region.outputs.length > 0) = true := by decide\n\n"
            f"theorem valueRegionsChunk{chunk_index}Checked :\n"
            f"    valueRegionsClosed originalPe candidatePe originalRelocations candidateRelocations {chunk_name} = true := by decide\n\n"
            f"theorem relationOutputsChunk{chunk_index}Checked :\n"
            f"    {chunk_name}.all (fun source => requiredInputsCertificate.all source.outputs.contains) = true := by decide\n\n"
            f"theorem flagRelationChunk{chunk_index}Checked :\n"
            f"    {chunk_name}.all (fun source => source.targets.all "
            f"(targetFlagRelationClosed allRegionIndex source)) = true := by decide\n\n"
            f"theorem requiredInputsChunk{chunk_index}Checked :\n"
            f"    requiredInputPairsFrom requiredInputsState{chunk_index} {chunk_name} = "
            f"requiredInputsState{chunk_index + 1} := by decide\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    structural_padding_modules: list[str] = []
    for side in ("original", "candidate"):
        for chunk_index, chunk_name in enumerate(padding_chunk_names[side]):
            module = f"RelationalProofStructuralPadding{side.capitalize()}Chunk{chunk_index}"
            structural_padding_modules.append(module)
            source = (
                "import StageA.RelationalProofClosureData\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                f"theorem {side}PaddingChunk{chunk_index}Checked :\n"
                f"    {chunk_name}.all (paddingSpanValid {side}Pe) = true := by decide\n\n"
                "end StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    coverage_modules: list[str] = []
    for side in ("original", "candidate"):
        module = f"RelationalProofStructuralCoverage{side.capitalize()}"
        coverage_modules.append(module)
        source = (
            "import StageA.RelationalProofClosureData\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"theorem {side}CoverageChecked : executableCoverageCertified {side}Pe\n"
            f"    (allRegions.map (fun region => region.{side}) ++ {side}Padding)\n"
            f"    {side}Coverage = true := by decide\n\n"
            f"theorem {side}AliasCoverageChecked :\n"
            f"    paddingAliasCertificateValid {side}Padding {side}AliasCoverage = true := by decide\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    independent_source = (
        "import StageA.RelationalProofClosureData\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem imagesChecked : imageStructureClosed originalPe candidatePe = true := by decide\n\n"
        "theorem indexChecked : regionIndexClosed allRegions allRegionIndex = true := by decide\n\n"
        "theorem entryChecked : entryRootClosed originalPe candidatePe allRegions = true := by decide\n\n"
        "theorem targetsChecked : targetCoverageClosed allRegionIndex allRegions = true := by decide\n\n"
        "theorem targetAliasesChecked : targetAliasesCertified allRegions originalAliasCoverage candidateAliasCoverage = true := by decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProofStructuralIndependent.lean",
        independent_source,
    )

    region_structure_proof = _lean_all_append_proof(
        "fun region => spanInExecutableSection originalPe region.original && "
        "spanInExecutableSection candidatePe region.candidate && "
        "region.inputs.length > 0 && region.outputs.length > 0",
        region_chunk_names,
        [f"regionStructureItemsChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    value_regions_proof = _lean_all_append_proof(
        "valueRegionClosed originalPe candidatePe originalRelocations candidateRelocations",
        region_chunk_names,
        [f"valueRegionsChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    relation_outputs_proof = _lean_all_append_proof(
        "fun source => requiredInputsCertificate.all source.outputs.contains",
        region_chunk_names,
        [f"relationOutputsChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    flag_relation_proof = _lean_all_append_proof(
        "fun source => source.targets.all (targetFlagRelationClosed allRegionIndex source)",
        region_chunk_names,
        [f"flagRelationChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    padding_proofs = {
        side: _lean_all_append_proof(
            f"paddingSpanValid {side}Pe",
            padding_chunk_names[side],
            [f"{side}PaddingChunk{index}Checked" for index in range(len(padding_chunk_names[side]))],
        )
        for side in ("original", "candidate")
    }
    required_input_rewrites = ", ".join(
        [
            item
            for index in range(len(region_chunk_names))
            for item in (
                (["requiredInputPairsFrom_append"] if index + 1 < len(region_chunk_names) else [])
                + [f"requiredInputsChunk{index}Checked"]
            )
        ]
    )
    aggregate_source = (
        "import StageA.RelationalProofStructuralIndependent\n"
        + "\n".join(
            f"import StageA.{module}"
            for module in structural_region_modules + structural_padding_modules
        )
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem allRegionsNonempty : allRegions.length > 0 := by decide\n\n"
        "theorem regionStructureItemsChecked : regionStructureItemsClosed originalPe candidatePe allRegions = true := by\n"
        "  unfold regionStructureItemsClosed allRegions\n"
        f"  exact {region_structure_proof}\n\n"
        "theorem regionStructureChecked : regionStructureClosed originalPe candidatePe allRegions = true := by\n"
        "  simp [regionStructureClosed, allRegionsNonempty, regionStructureItemsChecked]\n\n"
        "theorem valueRegionsChecked : valueRegionsClosed originalPe candidatePe originalRelocations candidateRelocations allRegions = true := by\n"
        "  unfold valueRegionsClosed allRegions\n"
        f"  exact {value_regions_proof}\n\n"
        "theorem valuesChecked : valueTargetsClosed originalPe candidatePe allRegions = true :=\n"
        "  valueTargetsClosed_of_parsed originalPe candidatePe originalRelocations candidateRelocations allRegions originalRelocationsParsed candidateRelocationsParsed valueRegionsChecked\n\n"
        "theorem relationOutputsChecked : allRegions.all (fun source => requiredInputsCertificate.all source.outputs.contains) = true := by\n"
        "  unfold allRegions\n"
        f"  exact {relation_outputs_proof}\n\n"
        "theorem requiredInputsChecked : requiredInputPairs allRegions = requiredInputsCertificate := by\n"
        "  unfold requiredInputPairs\n"
        "  change requiredInputPairsFrom requiredInputsState0 allRegions = requiredInputsCertificate\n"
        "  unfold allRegions\n"
        f"  rw [{required_input_rewrites}]\n"
        "  rfl\n\n"
        "theorem relationCompositionChecked : relationCompositionClosed allRegions = true :=\n"
        "  relationCompositionClosed_of_certificate allRegions requiredInputsCertificate requiredInputsChecked relationOutputsChecked\n\n"
        "theorem flagRelationCompositionChecked : flagRelationCompositionClosed allRegionIndex allRegions = true := by\n"
        "  unfold flagRelationCompositionClosed allRegions\n"
        f"  exact {flag_relation_proof}\n\n"
        "theorem originalPaddingChecked : paddingBytesClosed originalPe originalPadding = true := by\n"
        "  unfold paddingBytesClosed originalPadding\n"
        f"  exact {padding_proofs['original']}\n\n"
        "theorem candidatePaddingChecked : paddingBytesClosed candidatePe candidatePadding = true := by\n"
        "  unfold paddingBytesClosed candidatePadding\n"
        f"  exact {padding_proofs['candidate']}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProofStructuralAggregates.lean",
        aggregate_source,
    )

    closure_source = (
        "import StageA.RelationalProofStructuralAggregates\n"
        + "\n".join(f"import StageA.{module}" for module in coverage_modules)
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem structuralChecked : structuralEligible proofBundle = true :=\n"
        "  structuralEligible_of_checks proofBundle originalPe candidatePe originalParsed candidateParsed\n"
        "    imagesChecked indexChecked regionStructureChecked originalCoverageChecked candidateCoverageChecked\n"
        "    originalPaddingChecked candidatePaddingChecked entryChecked targetsChecked\n"
        "    originalAliasCoverageChecked candidateAliasCoverageChecked targetAliasesChecked\n"
        "    valuesChecked relationCompositionChecked flagRelationCompositionChecked\n\n"
        "theorem importsChecked : importTablesCertified proofBundle := by\n"
        "  unfold importTablesCertified parsedImages proofBundle\n"
        "  rw [originalParsed, candidateParsed]\n"
        "  exact ⟨originalImportsChecked, candidateImportsChecked⟩\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProofClosureBase.lean",
        closure_source,
    )

    direct_regions_proof = _lean_direct_append_proof(
        region_chunk_names,
        [f"directRegionChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    final = (
        "import StageA.RelationalProofClosureBase\n"
        + "\n".join(f"import StageA.{module}" for module in direct_modules)
        + "\n\nnamespace StageA.GeneratedRelational\n\nopen StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "theorem allDirectRegionsChecked : allDirectRegionGoals originalPe candidatePe originalImports candidateImports allRegions := by\n"
        "  unfold allRegions\n"
        f"  exact {direct_regions_proof}\n\n"
        "theorem allRegionsChecked : allRegionGoals proofBundle proofBundle.regions := by\n"
        "  apply allRegionGoals_of_direct proofBundle originalPe candidatePe originalParsed candidateParsed\n"
        "  exact allDirectRegionsChecked\n\n"
        "theorem candidateRelationalCertificate : RelationalImageCertificate proofBundle :=\n"
        "  relationalImageCertificate_intro proofBundle structuralChecked importsChecked allRegionsChecked\n\n"
        "#print axioms candidateRelationalCertificate\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(lean_dir / "StageA" / "RelationalBundle.lean", final)
    return shard_modules, shard_size


def _lean_pe_side_source(side: str, binary: StageABinary, data: bytes) -> str:
    return (
        "import StageA.Formal\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + _lean_byte_tree_definitions(f"{side}Bytes", data)
        + "\n\n"
        + f"def {side}Pe : PE32 := {_lean_pe(binary, f'{side}Bytes')}\n\n"
        + f"def {side}ImportCertificate : ImportTableCertificate := {_lean_import_certificate(binary)}\n\n"
        + f"def {side}Imports : List PEImport := {side}ImportCertificate.imports\n\n"
        + f"def {side}Relocations : List BaseRelocation := {_lean_relocations(binary)}\n\n"
        + f"theorem {side}MetadataParsed : parsePEMetadataTree {side}Bytes = some {side}Pe.metadata := by decide\n\n"
        + f"theorem {side}Parsed : parsePE32Tree {side}Bytes = some {side}Pe := by\n"
        + f"  simp [parsePE32Tree, {side}MetadataParsed, PE32.metadata, PEMetadata.toPE32, {side}Pe]\n\n"
        + f"theorem {side}ImportsChecked : importTableValid {side}Pe {side}ImportCertificate = true := by decide\n\n"
        + f"theorem {side}RelocationsParsed : parseRelocations {side}Pe = some {side}Relocations := by decide\n\n"
        + "end StageA.GeneratedRelational\n"
    )


def _partition_proof_shards(
    region_costs: list[int],
    *,
    max_regions: int,
    target_bytes: int,
) -> list[list[int]]:
    groups: list[list[int]] = []
    current: list[int] = []
    current_bytes = 0
    for index, cost in enumerate(region_costs):
        if current and (
            len(current) >= max_regions
            or current_bytes + cost > target_bytes
        ):
            groups.append(current)
            current = []
            current_bytes = 0
        current.append(index)
        current_bytes += cost
    if current:
        groups.append(current)
    return groups


def _lean_normalized_component_setup(
    index: int,
    region: dict[str, Any],
    *,
    original_image_base: int,
    candidate_image_base: int,
    preserve_flags: bool = False,
    preserve_states: bool = False,
) -> tuple[str, str]:
    name = f"region{index}"
    input_hypotheses = [f"inputRelated{pair_index}" for pair_index in range(len(region["inputs"]))]
    relation_destructure = (
        "  rcases related with ⟨" + ", ".join(input_hypotheses) + "⟩\n"
        if len(input_hypotheses) > 1 else ""
    )
    substitutions = "".join(
        f"  subst c{pair['candidate']}\n" for pair in region["inputs"]
    )
    flag_setup, flag_hypotheses = _lean_region_flag_setup(index, region)
    aliases = (
        "  let originalInput := originalState\n"
        "  let candidateInput := candidateState\n"
        if preserve_states else ""
    )
    flags_copy = "  have flagsRelatedAll := flagsRelated\n" if preserve_flags else ""
    return (
        aliases
        + "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
        "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
        "  unfold statesRelated at related\n"
        "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
        f"  have exactMemory := memoryRelated_without_relocations {original_image_base} {candidate_image_base} "
        f"{name}.targets {name}.values originalMemory candidateMemory (by decide) memoryRelated\n"
        f"  change candidateMemory = fun address => originalMemory (normalizeDataAddress {name}.values address) at exactMemory\n"
        "  subst candidateMemory\n"
        "  change originalUndefined = candidateUndefined at undefinedRelated\n"
        "  subst candidateUndefined\n"
        "  change originalX87 = candidateX87 at x87Related\n"
        "  subst candidateX87\n"
        + flags_copy
        + flag_setup
        + "  change originalFsBase = candidateFsBase at fsBaseRelated\n"
        "  subst candidateFsBase\n"
        f"  simp [registersRelated, StageA.Formal.Registers.get, {name}] at related\n"
        + relation_destructure
        + substitutions
        + f"  simp [StageA.Relational.boundsRelated, StageA.Formal.Registers.get, {name}] at boundsSatisfied\n"
        f"  simp [addressSeparationsRelated, StageA.Formal.Registers.get, {name}] at separationsSatisfied\n",
        flag_hypotheses,
    )


def _lean_compositional_normalized_theorem_source(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
    *,
    original_image_base: int,
    candidate_image_base: int,
) -> str | None:
    outcome = _lean_normalized_static_outcome(region, behaviors)
    if outcome is None or "flags := some" not in behaviors["original"]:
        return None

    name = f"region{index}"
    theorem_name = f"{name}Checked"
    state_relation = (
        f"statesRelated {original_image_base} {candidate_image_base} {name}.targets {name}.flagInputs "
        f"{name}.bounds {name}.addressSeparations {name}.values {name}.inputs "
        "originalState candidateState"
    )
    setup, flag_hypotheses = _lean_normalized_component_setup(
        index,
        region,
        original_image_base=original_image_base,
        candidate_image_base=candidate_image_base,
    )
    flag_lemma_line = f"    {flag_hypotheses},\n" if flag_hypotheses else ""
    common_simplifiers = (
        "StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval, "
        "StageA.Formal.MachineState.read32, Memory.read32, "
        "StageA.Formal.MachineState.readX87Word, StageA.Formal.read8AfterWriteValue, "
        "StageA.Formal.X87LoadFormat.byteWidth, StageA.Formal.Registers.get, "
        "normalizeCodeTarget, normalizeImport, wordsRelated, wordRelated, "
        "codePointerRelated, codeAddressMatches, mappedValueRelated"
    )

    definitions = (
        f"def {name}NormalizedBehavior : NormalizedSymbolicBehavior :=\n"
        f"  (normalizeSymbolicBehavior false {name}.targets originalBehavior{index}).get (by decide)\n\n"
        f"theorem {name}NormalizedRegisters : {name}NormalizedBehavior.registers = originalBehavior{index}.registers := by decide\n\n"
        f"theorem {name}NormalizedX87 : {name}NormalizedBehavior.x87 = originalBehavior{index}.x87 := by decide\n\n"
        f"theorem {name}NormalizedWrites : {name}NormalizedBehavior.writes = originalBehavior{index}.writes := by decide\n\n"
        f"def {name}CommonFlags : FlagsExpr := originalBehavior{index}.flags.get (by decide)\n\n"
        f"theorem {name}NormalizedFlags : {name}NormalizedBehavior.flags = some {name}CommonFlags := by decide\n\n"
        f"theorem {name}NormalizedOutcome : {name}NormalizedBehavior.outcome = {outcome} := by decide\n\n"
        f"theorem {name}OriginalNormalized : normalizeSymbolicBehavior false {name}.targets originalBehavior{index} = some {name}NormalizedBehavior := by decide\n\n"
        f"theorem {name}CandidateNormalized : normalizeSymbolicBehavior true {name}.targets candidateBehavior{index} = some {name}NormalizedBehavior := by decide\n\n"
    )

    component_specs = (
        (
            "Registers",
            f"registersRelatedValues {original_image_base} {candidate_image_base} {name}.targets {name}.values "
            f"{name}.outputs ({name}NormalizedBehavior.eval originalState).registers "
            f"({name}NormalizedBehavior.eval candidateState).registers = true",
            f"  simp only [NormalizedSymbolicBehavior.eval_registers, {name}NormalizedRegisters]\n"
            f"  simp [evalNormalizedRegisters, registersRelatedValues, {common_simplifiers},\n"
            + flag_lemma_line
            + f"    originalBehavior{index}, {name}]\n"
            "  all_goals first | rfl | bv_normalize\n",
        ),
        (
            "X87",
            f"({name}NormalizedBehavior.eval originalState).x87 = "
            f"({name}NormalizedBehavior.eval candidateState).x87",
            f"  simp only [NormalizedSymbolicBehavior.eval_x87, {name}NormalizedX87]\n"
            f"  simp [evalNormalizedX87, {common_simplifiers},\n"
            + flag_lemma_line
            + f"    originalBehavior{index}, {name}]\n"
            "  all_goals first | rfl | bv_normalize\n",
        ),
        (
            "Writes",
            f"writesRelated {original_image_base} {candidate_image_base} {name}.targets {name}.values "
            f"({name}NormalizedBehavior.eval originalState).writes "
            f"({name}NormalizedBehavior.eval candidateState).writes = true",
            f"  simp only [NormalizedSymbolicBehavior.eval_writes, {name}NormalizedWrites]\n"
            f"  simp [evalNormalizedWrites, writesRelated, {common_simplifiers},\n"
            + flag_lemma_line
            + f"    originalBehavior{index}, {name}]\n"
            "  all_goals first | rfl | bv_normalize\n",
        ),
        (
            "Outcome",
            f"outcomesRelated {original_image_base} {candidate_image_base} {name}.targets {name}.values "
            f"({name}NormalizedBehavior.eval originalState).outcome "
            f"({name}NormalizedBehavior.eval candidateState).outcome = true",
            f"  simp only [NormalizedSymbolicBehavior.eval_outcome, {name}NormalizedOutcome]\n"
            f"  simp [NormalizedOutcomeExpr.eval, outcomesRelated, {common_simplifiers},\n"
            + flag_lemma_line
            + f"    {name}]\n"
            "  all_goals first | rfl | bv_normalize\n",
        ),
    )
    component_theorems: list[str] = []
    for label, goal, proof in component_specs:
        component_theorems.append(
            f"theorem {name}{label}Component (originalState candidateState : MachineState)\n"
            f"    (related : {state_relation}) :\n    {goal} := by\n"
            + setup
            + proof
        )

    bit_metadata = {
        0: ("carry", "cf"),
        2: ("parity", "pf"),
        6: ("zero", "zf"),
        7: ("sign", "sf"),
        10: (None, "df"),
        11: ("overflow", "of"),
    }
    bit_facts: list[str] = []
    bit_components: list[str] = []
    for bit in region.get("flag_outputs", []):
        field, suffix = bit_metadata[bit]
        within_goal = (
            f"{name}.flagInputs.contains 10 = true"
            if field is None else
            f"flagValueWithin {name}.flagInputs {bit} {name}CommonFlags.{field} = true"
        )
        bit_facts.append(
            f"theorem {name}Flag{bit}Within : {within_goal} := by decide\n\n"
            f"theorem {name}CommonFlag{bit}Agreement (original candidate : MachineState)\n"
            f"    (agreement : MachineStateAgreement {name}.flagInputs original candidate) :\n"
            f"    ({name}CommonFlags.eval original).extractLsb' {bit} 1 =\n"
            f"      ({name}CommonFlags.eval candidate).extractLsb' {bit} 1 :=\n"
            f"  FlagsExpr.eval_{suffix}_eq_of_flagsWithin {name}.flagInputs original candidate\n"
            f"    {name}CommonFlags {name}Flag{bit}Within agreement\n\n"
            f"theorem {name}NormalizedFlag{bit}Agreement (original candidate : MachineState)\n"
            f"    (agreement : MachineStateAgreement {name}.flagInputs original candidate) :\n"
            f"    ({name}NormalizedBehavior.eval original).eflags.extractLsb' {bit} 1 =\n"
            f"      ({name}NormalizedBehavior.eval candidate).eflags.extractLsb' {bit} 1 :=\n"
            f"  NormalizedSymbolicBehavior.eval_flag_eq_of_some {name}NormalizedBehavior {name}CommonFlags\n"
            f"    original candidate {bit} {name}NormalizedFlags\n"
            f"    ({name}CommonFlag{bit}Agreement original candidate agreement)\n\n"
        )
        bit_setup, _ = _lean_normalized_component_setup(
            index,
            region,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
            preserve_flags=True,
            preserve_states=True,
        )
        bit_components.append(
            f"theorem {name}Flag{bit}Component (originalState candidateState : MachineState)\n"
            f"    (related : {state_relation}) :\n"
            f"    ({name}NormalizedBehavior.eval originalState).eflags.extractLsb' {bit} 1 =\n"
            f"      ({name}NormalizedBehavior.eval candidateState).eflags.extractLsb' {bit} 1 := by\n"
            + bit_setup
            + f"  have stateAgreement : MachineStateAgreement {name}.flagInputs originalInput candidateInput := by\n"
            "    constructor\n"
            "    · rfl\n    · rfl\n    · rfl\n    · rfl\n    · rfl\n"
            "    · intro bit contains\n"
            f"      exact flagsRelated_of_contains {name}.flagInputs originalFlags candidateFlags flagsRelatedAll contains\n"
            f"  exact {name}NormalizedFlag{bit}Agreement originalInput candidateInput stateAgreement\n\n"
        )

    bit_component_names = [
        f"{name}Flag{bit}Component originalState candidateState related"
        for bit in region.get("flag_outputs", [])
    ]
    output_bits = list(region.get("flag_outputs", []))
    original_flags = f"({name}NormalizedBehavior.eval originalState).eflags"
    candidate_flags = f"({name}NormalizedBehavior.eval candidateState).eflags"
    flags_proof = f"flagsRelated_nil {original_flags} {candidate_flags}"
    for bit_index in range(len(output_bits) - 1, -1, -1):
        bit = output_bits[bit_index]
        tail = ", ".join(str(value) for value in output_bits[bit_index + 1:])
        flags_proof = (
            f"flagsRelated_cons_of_eq {bit} [{tail}] {original_flags} {candidate_flags} "
            f"({bit_component_names[bit_index]}) ({flags_proof})"
        )
    flags_component = (
        f"theorem {name}FlagsComponent (originalState candidateState : MachineState)\n"
        f"    (related : {state_relation}) :\n"
        f"    StageA.Relational.flagsRelated {name}.flagOutputs\n"
        f"      ({name}NormalizedBehavior.eval originalState).eflags\n"
        f"      ({name}NormalizedBehavior.eval candidateState).eflags = true := by\n"
        f"  change StageA.Relational.flagsRelated [{', '.join(str(bit) for bit in output_bits)}] "
        f"{original_flags} {candidate_flags} = true\n"
        f"  exact {flags_proof}\n\n"
    )

    direct = (
        f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent {original_image_base} {candidate_image_base} "
        f"originalBehavior{index} candidateBehavior{index} {name} :=\n"
        f"  behaviorsEquivalent_of_normalized_components {original_image_base} {candidate_image_base} "
        f"originalBehavior{index} candidateBehavior{index} {name}NormalizedBehavior {name}\n"
        f"    {name}OriginalNormalized {name}CandidateNormalized {name}RegistersComponent\n"
        f"    {name}X87Component {name}WritesComponent {name}FlagsComponent {name}OutcomeComponent\n"
    )
    return (
        definitions
        + "".join(bit_facts)
        + "\n".join(component_theorems)
        + "\n"
        + "".join(bit_components)
        + flags_component
        + direct
    )


def _lean_region_theorem_source(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
    *,
    original_image_base: int,
    candidate_image_base: int,
    replay: bool,
    certificate: dict[str, Any] | None,
) -> str:
    name = f"region{index}"
    theorem_name = f"{name}Checked"
    if _normalized_behavior_structure_matches(region, behaviors):
        compositional = _lean_compositional_normalized_theorem_source(
            index,
            region,
            behaviors,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        )
        if compositional is not None:
            return compositional
    memory_lemmas = ", ".join(
        _lean_region_memory_lemma_names(index, region, behaviors)
    )
    memory_lemma_line = f"    {memory_lemmas},\n" if memory_lemmas else ""
    memory_normalizer_line = (
        "    normalizeDataAddress, valueTargetContainsCandidate,\n"
        if region.get("values") and not _lean_region_indexed_memory_lemma_specs(region) else ""
    )
    bound_setup = _lean_region_bound_setup(index, region, behaviors)
    flag_setup, flag_hypotheses = _lean_region_flag_setup(index, region)
    flag_lemma_line = f"    {flag_hypotheses},\n" if flag_hypotheses else ""
    normalized_flag_simplifiers = f", {flag_hypotheses}" if flag_hypotheses else ""
    relocation_memory_setup = _lean_region_relocation_memory_setup(
        index, region, behaviors
    )
    separation_setup, separation_hypotheses = _lean_region_separation_setup(index, region)
    separation_lemma_line = (
        f"    {separation_hypotheses},\n" if separation_hypotheses else ""
    )
    indexed_memory_facts = _lean_region_indexed_memory_fact_names(index, region)
    index_mask_facts = [
        f"region{index}IndexMaskFact{mask_index}"
        for mask_index in range(len(_lean_region_index_masks(region, behaviors)))
    ]
    indexed_memory_rewrite = (
        (
            f"  all_goals try simp only [{', '.join(index_mask_facts)}]\n"
            if index_mask_facts else ""
        )
        + f"  all_goals try simp only [{', '.join(indexed_memory_facts)}]\n"
        + "  all_goals try simp\n"
        if indexed_memory_facts else ""
    )
    has_relocation_word_facts = bool(
        _lean_region_static_relocation_word_specs(region, behaviors)
        or _lean_region_indexed_relocation_word_specs(region)
    )
    word_relation_simplifiers = (
        "wordRelated_self"
        if has_relocation_word_facts else
        "wordRelated, codePointerRelated, codeAddressMatches, mappedValueRelated"
    )
    memory_read_simplifiers = (
        "machineStateRead32_eq_memoryRead32, assembledMemoryRead32_eq, "
        "assembledMemoryRead32OfNat_eq"
        if has_relocation_word_facts else
        "StageA.Formal.MachineState.read32, Memory.read32"
    )
    flag_eval_simplifiers = (
        "StageA.Formal.FlagsExpr.eval_extract_cf, "
        "StageA.Formal.FlagsExpr.eval_extract_pf, "
        "StageA.Formal.FlagsExpr.eval_extract_zf, "
        "StageA.Formal.FlagsExpr.eval_extract_sf, "
        "StageA.Formal.FlagsExpr.eval_extract_df, "
        "StageA.Formal.FlagsExpr.eval_extract_of, StageA.Formal.evalFlagBit"
    )
    if replay:
        if certificate and certificate.get("kind") == "lrat":
            tactic = f"bv_check \"../../certificates/{certificate['path']}\""
        elif certificate and certificate.get("kind") == "lean_normalization":
            tactic = "bv_normalize"
        else:
            tactic = "fail_if_success trivial"
    else:
        tactic = "bv_decide? (config := { timeout := 120, trimProofs := false })"
    relocation_bridge_tactics = "".join(
        f" | (rw [← {name}RelocationOriginalRead32Static{relocation_index}, "
        f"← {name}RelocationCandidateRead32Static{relocation_index}] at "
        f"{name}RelocationWordRelatedStatic{relocation_index}; exact "
        f"{name}RelocationWordRelatedStatic{relocation_index})"
        for relocation_index, _ in enumerate(
            _lean_region_static_relocation_word_specs(region, behaviors)
        )
    )
    input_hypotheses = [f"inputRelated{pair_index}" for pair_index in range(len(region["inputs"]))]
    relation_destructure = (
        "  rcases related with ⟨" + ", ".join(input_hypotheses) + "⟩\n"
        if len(input_hypotheses) > 1 else ""
    )
    substitutions = "".join(f"  subst c{pair['candidate']}\n" for pair in region["inputs"])
    normalized_fast_path = _normalized_behavior_fast_path(region, behaviors)
    normalized_theorem = (
        f"theorem {name}NormalizedBehavior : "
        f"normalizeSymbolicBehavior false {name}.targets originalBehavior{index} = "
        f"normalizeSymbolicBehavior true {name}.targets candidateBehavior{index} := by decide\n\n"
        f"theorem {name}NormalizedBehaviorExists : "
        f"(normalizeSymbolicBehavior false {name}.targets originalBehavior{index}).isSome := by decide\n\n"
        if normalized_fast_path else ""
    )
    proof_steps = (
        "  unfold evalBehavior\n"
        f"  rw [← {name}NormalizedBehavior]\n"
        f"  cases normalized : normalizeSymbolicBehavior false {name}.targets originalBehavior{index} with\n"
        f"  | none => simpa [normalized] using {name}NormalizedBehaviorExists\n"
        "  | some behavior =>\n"
        "    simp [normalized, NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
        f"registersRelatedValues, writesRelated_self, outcomesRelated_self, "
        f"StageA.Relational.flagsRelated, "
        f"wordRelated{normalized_flag_simplifiers}, {name}]\n"
        if normalized_fast_path else (
            "  simp [evalBehavior, evalBehaviorRegisters, evalBehaviorX87, evalBehaviorWrites, "
            "evalBehaviorFlags, evalBehaviorOutcome, normalizeSymbolicBehavior, normalizeOutcomeExpr, "
            "NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
            "evalNormalizedRegisters, evalNormalizedX87, evalNormalizedWrites, evalNormalizedFlags, "
            "StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval, "
            f"{flag_eval_simplifiers},\n"
            f"    {memory_read_simplifiers}, StageA.Formal.MachineState.readX87Word,\n"
            "    StageA.Formal.read8AfterWriteValue, BitVec.add_assoc,\n"
            "    StageA.Formal.X87LoadFormat.byteWidth, registersRelated, registersRelatedValues,\n"
            "    StageA.Formal.Registers.get, StageA.Formal.Registers.set, normalizeCodeTarget, normalizeImport,\n"
            f"    writesRelated, wordsRelated, outcomesRelated, "
            f"StageA.Relational.flagsRelated, "
            f"{word_relation_simplifiers},\n"
            + memory_normalizer_line
            + memory_lemma_line
            + separation_lemma_line
            + flag_lemma_line
            + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
            + indexed_memory_rewrite
            + f"  all_goals first | rfl{relocation_bridge_tactics} | {tactic}\n"
        )
    )
    direct_state_setup = (
        "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
        "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
        "  unfold statesRelated at related\n"
        "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
    )
    direct_state_equalities = (
        "  change originalUndefined = candidateUndefined at undefinedRelated\n  subst candidateUndefined\n"
        "  change originalX87 = candidateX87 at x87Related\n  subst candidateX87\n"
        + flag_setup
        + "  change originalFsBase = candidateFsBase at fsBaseRelated\n  subst candidateFsBase\n"
        f"  simp [registersRelated, StageA.Formal.Registers.get, {name}] at related\n"
        + relation_destructure
        + substitutions
        + f"  simp [StageA.Relational.boundsRelated, StageA.Formal.Registers.get, {name}] at boundsSatisfied\n"
    )
    direct_setup_base_without_memory = direct_state_setup + direct_state_equalities
    direct_setup_base = (
        direct_state_setup
        + _lean_region_memory_setup(
            index, region, str(original_image_base), str(candidate_image_base),
        )
        + direct_state_equalities
    )
    direct_setup = (
        direct_setup_base
        + bound_setup
        + relocation_memory_setup
        + separation_setup
    )
    if not normalized_fast_path and not replay:
        components = (
            ("Registers", "behaviorRegistersEquivalent"),
            ("X87", "behaviorX87Equivalent"),
            ("Writes", "behaviorWritesEquivalent"),
            ("Flags", "behaviorFlagsEquivalent"),
            ("Outcome", "behaviorOutcomeEquivalent"),
        )
        x87_proof_steps = proof_steps
        for omitted in (memory_lemma_line, separation_lemma_line, indexed_memory_rewrite):
            if omitted:
                x87_proof_steps = x87_proof_steps.replace(omitted, "")
        x87_state_only = _lean_x87_state_only_pair(behaviors)
        memory_free_fields = {
            "Registers": ("registers", "x87"),
            "Writes": ("writes", "comparison"),
            "Flags": ("flags", "outcome"),
        }
        memory_free_component_proofs = {
            "Registers": (
                "  simp [evalNormalizedRegisters, StageA.Formal.Expr.eval, "
                "registersRelatedValues, StageA.Formal.Registers.get, "
                "wordRelated, codePointerRelated, codeAddressMatches, "
                "mappedValueRelated, normalizeDataAddress, valueTargetContainsCandidate,\n"
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                f"  all_goals first | rfl | {tactic}\n"
            ),
            "Writes": (
                "  simp [evalNormalizedWrites, StageA.Formal.Expr.eval, "
                "writesRelated, wordsRelated, StageA.Formal.Registers.get, "
                "wordRelated, codePointerRelated, codeAddressMatches, "
                "mappedValueRelated, normalizeDataAddress, valueTargetContainsCandidate,\n"
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                f"  all_goals first | rfl | {tactic}\n"
            ),
            "Flags": (
                "  simp [evalNormalizedFlags, StageA.Formal.Expr.eval, "
                "StageA.Formal.BoolExpr.eval, "
                f"{flag_eval_simplifiers}, StageA.Relational.flagsRelated, "
                "StageA.Formal.Registers.get,\n"
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                f"  all_goals first | rfl | {tactic}\n"
            ),
        }
        component_sources: list[str] = []
        for label, predicate in components:
            source = (
                f"theorem {name}{label}DirectComponent : {predicate} "
                f"{original_image_base} {candidate_image_base} "
                f"originalBehavior{index} candidateBehavior{index} {name} := by\n"
                f"  unfold {predicate}\n"
                "  intro originalState candidateState related\n"
            )
            if label == "X87" and x87_state_only:
                source += (
                    "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, "
                    "oebp, oesp⟩, originalMemory, "
                    "originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
                    "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, "
                    "cebp, cesp⟩, candidateMemory, "
                    "candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
                    "  unfold statesRelated at related\n"
                    "  rcases related with ⟨registersRelated, boundsRelated, "
                    "separationsRelated, memoryRelated, undefinedRelated, x87Related, "
                    "flagsRelated, fsBaseRelated⟩\n"
                    "  change originalX87 = candidateX87 at x87Related\n"
                    "  subst candidateX87\n"
                    f"  simp [originalBehavior{index}, candidateBehavior{index}, "
                    "evalNormalizedX87, StageA.Formal.X87Expr.eval, "
                    "StageA.Formal.Expr.eval]\n"
                )
            else:
                field_spec = memory_free_fields.get(label)
                memory_free = bool(
                    field_spec
                    and _lean_behavior_fields_memory_free(
                        behaviors, field_spec[0], field_spec[1]
                    )
                )
                component_setup = (
                    direct_setup_base_without_memory + bound_setup
                    if memory_free else
                    (direct_setup_base if label == "X87" else direct_setup)
                )
                component_proof = x87_proof_steps if label == "X87" else proof_steps
                if memory_free:
                    component_proof = memory_free_component_proofs[label]
                source += component_setup + component_proof
            component_sources.append(source + "\n")
        component_theorems = "".join(component_sources)
        return (
            component_theorems
            + f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent {original_image_base} {candidate_image_base} "
            f"originalBehavior{index} candidateBehavior{index} {name} :=\n"
            f"  behaviorsEquivalent_of_components {original_image_base} {candidate_image_base} "
            f"originalBehavior{index} candidateBehavior{index} {name}\n"
            f"    {name}RegistersDirectComponent {name}X87DirectComponent {name}WritesDirectComponent\n"
            f"    {name}FlagsDirectComponent {name}OutcomeDirectComponent\n"
        )
    return (
        normalized_theorem
        + f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent {original_image_base} {candidate_image_base} originalBehavior{index} candidateBehavior{index} {name} := by\n"
        "  unfold behaviorsEquivalent\n"
        "  intro originalState candidateState related\n"
        + direct_setup
        + proof_steps
    )


def _write_text_if_changed(path: Path, content: str) -> None:
    try:
        if path.read_text(encoding="utf-8") == content:
            return
    except OSError:
        pass
    path.write_text(content, encoding="utf-8")


def _run_sharded_relational(lean_dir: Path, shard_modules: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    formal = _compile_formal_kernel(lean_dir)
    if formal.get("status") != "checked":
        formal["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
        return formal
    relational_kernel = _compile_relational_kernel(lean_dir)
    prerequisites: dict[str, dict[str, Any]] = {
        "relational_kernel": relational_kernel,
    }
    if relational_kernel.get("status") != "checked":
        return {
            **relational_kernel,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    jobs = min(len(shard_modules), _relational_proof_jobs())
    definition_modules = sorted(
        path.stem
        for path in (lean_dir / "StageA").glob("RelationalDefinitionsShard*.lean")
    )
    definition_results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(jobs, len(definition_modules) or 1)) as executor:
        futures = {
            executor.submit(
                _run_lean_relational_cached,
                lean_dir,
                bundle=module,
            ): module
            for module in definition_modules
        }
        for future in as_completed(futures):
            result = future.result()
            result["module"] = futures[future]
            definition_results.append(result)
            if result.get("status") != "checked":
                return {
                    **result,
                    "phase": "region_definitions",
                    "definition_results": definition_results,
                    "prerequisites": prerequisites,
                    "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
                }
    prerequisites["region_definitions"] = {
        "status": "checked",
        "modules": len(definition_results),
    }
    heavy_threshold = max(
        1,
        int(os.environ.get("WINCR_STAGE_A_RELATIONAL_HEAVY_SHARD_BYTES", "500000")),
    )
    heavy_jobs = min(
        jobs,
        max(1, int(os.environ.get("WINCR_STAGE_A_RELATIONAL_HEAVY_JOBS", "1"))),
    )
    source_sizes = {
        module: (lean_dir / "StageA" / f"{module}.lean").stat().st_size
        for module in shard_modules
    }
    pending_modules = sorted(shard_modules, key=lambda module: source_sizes[module], reverse=True)
    failure_hint_path = _failed_shard_hint_path(lean_dir)
    prioritized_module: str | None = None
    if failure_hint_path is not None:
        try:
            hint = json.loads(failure_hint_path.read_text(encoding="utf-8"))
            hinted_module = hint.get("module")
        except (OSError, json.JSONDecodeError):
            hinted_module = None
        if hinted_module in pending_modules:
            pending_modules.remove(hinted_module)
            pending_modules.insert(0, hinted_module)
            prioritized_module = hinted_module
    cancellation = Event()
    results: list[dict[str, Any]] = []
    running_heavy = 0

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        future_modules: dict[Any, str] = {}

        def submit_available() -> None:
            nonlocal running_heavy
            while pending_modules and len(future_modules) < jobs:
                selected = next(
                    (
                        index for index, module in enumerate(pending_modules)
                        if source_sizes[module] <= heavy_threshold or running_heavy < heavy_jobs
                    ),
                    None,
                )
                if selected is None:
                    return
                module = pending_modules.pop(selected)
                if source_sizes[module] > heavy_threshold:
                    running_heavy += 1
                future = executor.submit(
                    _run_lean_relational_cached,
                    lean_dir,
                    bundle=module,
                    cancel_event=cancellation,
                )
                future_modules[future] = module

        submit_available()
        while future_modules:
            completed, _ = wait(future_modules, return_when=FIRST_COMPLETED)
            for future in completed:
                module = future_modules.pop(future)
                if source_sizes[module] > heavy_threshold:
                    running_heavy -= 1
                result = future.result()
                result["module"] = module
                result["source_bytes"] = source_sizes[module]
                results.append(result)
                if result.get("status") != "checked":
                    cancellation.set()
                    if failure_hint_path is not None:
                        failure_hint_path.parent.mkdir(parents=True, exist_ok=True)
                        write_json(
                            failure_hint_path,
                            {
                                "format": "stage-a-relational-failed-shard-hint-v1",
                                "module": module,
                            },
                        )
                    for pending in future_modules:
                        pending.cancel()
                    result["completed_shards"] = len(results)
                    result["total_shards"] = len(shard_modules)
                    result["shard_results"] = results[:-1]
                    result["scheduler"] = {
                        "jobs": jobs,
                        "heavy_jobs": heavy_jobs,
                        "heavy_threshold_bytes": heavy_threshold,
                        "max_shard_source_bytes": max(source_sizes.values(), default=0),
                        "prerequisites": prerequisites,
                        "prioritized_failure_hint": prioritized_module,
                    }
                    result["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
                    return result
            submit_available()
    pe_attestation_jobs = {
        "original": lambda: _run_lean_relational_cached(
            lean_dir, bundle="RelationalProofOriginal"
        ),
        "candidate": lambda: _run_lean_relational_cached(
            lean_dir, bundle="RelationalProofCandidate"
        ),
    }
    with ThreadPoolExecutor(max_workers=len(pe_attestation_jobs)) as executor:
        futures = {
            executor.submit(run): name for name, run in pe_attestation_jobs.items()
        }
        for future in as_completed(futures):
            prerequisites[futures[future]] = future.result()
    failed_attestation = next(
        (
            result for name, result in prerequisites.items()
            if name != "relational_kernel" and result.get("status") != "checked"
        ),
        None,
    )
    if failed_attestation is not None:
        return {
            **failed_attestation,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    base = _run_lean_relational_cached(lean_dir, bundle="RelationalProofBase")
    if base.get("status") != "checked":
        base["prerequisites"] = prerequisites
        base["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
        return base
    region_chunks = _run_lean_relational_cached(
        lean_dir, bundle="RelationalRegionChunks"
    )
    if region_chunks.get("status") != "checked":
        region_chunks["phase"] = "region_chunks"
        region_chunks["prerequisites"] = prerequisites
        region_chunks["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
        return region_chunks
    def generated_modules(pattern: str) -> list[str]:
        def sort_key(module: str) -> tuple[int, str]:
            match = re.search(r"Chunk(\d+)$", module)
            return (int(match.group(1)) if match else -1, module)

        return sorted(
            (path.stem for path in (lean_dir / "StageA").glob(pattern)),
            key=sort_key,
        )

    def run_generated_phase(
        modules: list[str],
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        phase_results: list[dict[str, Any]] = []
        phase_cancellation = Event()
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            phase_futures = {
                executor.submit(
                    _run_lean_relational_cached,
                    lean_dir,
                    bundle=module,
                    cancel_event=phase_cancellation,
                ): module
                for module in modules
            }
            for future in as_completed(phase_futures):
                module = phase_futures[future]
                result = future.result()
                result["module"] = module
                result["source_bytes"] = (
                    lean_dir / "StageA" / f"{module}.lean"
                ).stat().st_size
                phase_results.append(result)
                if result.get("status") != "checked":
                    phase_cancellation.set()
                    for pending in phase_futures:
                        pending.cancel()
                    return phase_results, result
        return phase_results, None

    phase_results: dict[str, list[dict[str, Any]]] = {}
    for phase, pattern in (
        ("exact_decode_chunks", "RelationalProof*DecodeChunk*.lean"),
        ("direct_composition_chunks", "RelationalProofDirectChunk*.lean"),
    ):
        modules = generated_modules(pattern)
        phase_results[phase], failed = run_generated_phase(modules)
        if failed is not None:
            return {
                **failed,
                "phase": phase,
                "completed_phase_modules": len(phase_results[phase]),
                "total_phase_modules": len(modules),
                "phase_results": phase_results,
                "shard_results": results,
                "prerequisites": prerequisites,
                "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
            }

    closure_data = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProofClosureData",
    )
    phase_results["structural_data"] = [closure_data]
    if closure_data.get("status") != "checked":
        return {
            **closure_data,
            "phase": "structural_data",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    structural_fact_modules = sorted(set(
        generated_modules("RelationalProofStructuralRegionChunk*.lean")
        + generated_modules("RelationalProofStructuralPadding*Chunk*.lean")
        + generated_modules("RelationalProofStructuralCoverage*.lean")
        + ["RelationalProofStructuralIndependent"]
    ))
    phase_results["structural_facts"], failed = run_generated_phase(
        structural_fact_modules
    )
    if failed is not None:
        return {
            **failed,
            "phase": "structural_facts",
            "completed_phase_modules": len(phase_results["structural_facts"]),
            "total_phase_modules": len(structural_fact_modules),
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    structural_aggregates = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProofStructuralAggregates",
    )
    phase_results["structural_aggregates"] = [structural_aggregates]
    if structural_aggregates.get("status") != "checked":
        return {
            **structural_aggregates,
            "phase": "structural_aggregates",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    closure = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProofClosureBase",
    )
    phase_results["structural_closure"] = [closure]
    if closure.get("status") != "checked":
        return {
            **closure,
            "phase": "structural_closure",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    final = _run_lean_relational(lean_dir, bundle="RelationalBundle")
    if final.get("status") == "checked" and failure_hint_path is not None:
        failure_hint_path.unlink(missing_ok=True)
    final["shards"] = len(shard_modules)
    final["shard_results"] = results
    final["phase_results"] = phase_results
    final["scheduler"] = {
        "jobs": jobs,
        "heavy_jobs": heavy_jobs,
        "heavy_threshold_bytes": heavy_threshold,
        "max_shard_source_bytes": max(source_sizes.values(), default=0),
        "total_shard_source_bytes": sum(source_sizes.values()),
        "prerequisites": prerequisites,
        "prioritized_failure_hint": prioritized_module,
    }
    final["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
    return final


def _failed_shard_hint_path(lean_dir: Path) -> Path | None:
    cache_root = _relational_cache_dir()
    if cache_root is None:
        return None
    sources = [
        lean_dir / "StageA" / "RelationalProofOriginal.lean",
        lean_dir / "StageA" / "RelationalProofCandidate.lean",
        lean_dir / "StageA" / "RelationalBundle.lean",
    ]
    if not all(source.is_file() for source in sources):
        return None
    key = sha256_bytes(json.dumps({
        "format": "stage-a-relational-failed-shard-key-v1",
        "sources": [sha256_file(source) for source in sources],
    }, sort_keys=True, separators=(",", ":")).encode())
    return cache_root / "failed-shards" / f"{key}.json"


def _relational_proof_jobs() -> int:
    configured = os.environ.get("WINCR_STAGE_A_RELATIONAL_PROOF_JOBS")
    if configured is not None:
        return max(1, int(configured))
    cpu_jobs = min(16, os.cpu_count() or 1)
    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="ascii")
        match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", meminfo, re.MULTILINE)
        memory_jobs = max(1, int(match.group(1)) // (3 * 1024 * 1024)) if match else cpu_jobs
    except OSError:
        memory_jobs = cpu_jobs
    return max(1, min(cpu_jobs, memory_jobs))


def _compile_relational_kernel(lean_dir: Path) -> dict[str, Any]:
    formal_result = _compile_formal_kernel(lean_dir)
    if formal_result.get("status") != "checked":
        return formal_result
    source = lean_dir / "StageA" / "Relational.lean"
    output = lean_dir / "StageA" / "Relational.olean"
    formal = lean_dir / "StageA" / "Formal.olean"
    if _lean_output_current(source, output) and _lean_output_current(formal, output):
        return {"status": "checked", "source": "current_olean"}
    lean = shutil.which("lean")
    if lean is None:
        return {"status": "unavailable", "returncode": None, "stdout": "", "stderr": ""}
    try:
        completed = subprocess.run(
            [lean, "-o", "StageA/Relational.olean", "StageA/Relational.lean"],
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout", "returncode": None,
            "stdout": exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or "",
            "stderr": exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or "",
        }
    return {
        "status": "checked" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _compile_formal_kernel(lean_dir: Path) -> dict[str, Any]:
    source = lean_dir / "StageA" / "Formal.lean"
    output = lean_dir / "StageA" / "Formal.olean"
    if _lean_output_current(source, output):
        return {"status": "checked", "source": "current_olean"}
    lean = shutil.which("lean")
    if lean is None:
        return {"status": "unavailable", "returncode": None, "stdout": "", "stderr": ""}
    try:
        completed = subprocess.run(
            [lean, "-o", "StageA/Formal.olean", "StageA/Formal.lean"],
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout", "returncode": None,
            "stdout": exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or "",
            "stderr": exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or "",
        }
    return {
        "status": "checked" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _run_lean_relational_cached(
    lean_dir: Path,
    *,
    bundle: str,
    cancel_event: Event | None = None,
) -> dict[str, Any]:
    if cancel_event is not None and cancel_event.is_set():
        return {"status": "cancelled", "returncode": None, "stdout": "", "stderr": ""}
    if bundle in {"RelationalProofOriginal", "RelationalProofCandidate"}:
        formal = _compile_formal_kernel(lean_dir)
        if formal.get("status") != "checked":
            return formal
    source = lean_dir / "StageA" / f"{bundle}.lean"
    output = lean_dir / "StageA" / f"{bundle}.olean"
    if bundle in {"RelationalProofOriginal", "RelationalProofCandidate"}:
        dependency_names = ["Formal"]
    elif bundle == "RelationalProofBase":
        dependency_names = ["RelationalProofOriginal", "RelationalProofCandidate"]
    elif (
        bundle.startswith("RelationalProof")
        or bundle.startswith("RelationalDefinitions")
        or bundle.startswith("RelationalRegion")
    ):
        dependency_names = re.findall(
            r"^import StageA\.([A-Za-z0-9_]+)$",
            source.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    elif bundle.startswith("RelationalProofShard"):
        dependency_names = ["Relational"]
    else:
        dependency_names = ["Relational", "RelationalProofBase"]
    dependencies = [lean_dir / "StageA" / f"{name}.olean" for name in dependency_names]
    cached_output = _persistent_olean_path(lean_dir, bundle, source, dependencies)
    if _lean_output_current(source, output) and all(
        _lean_output_current(dependency, output) for dependency in dependencies
    ):
        if cached_output is not None and not cached_output.exists():
            cached_output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(output, cached_output)
        return {
            "status": "checked",
            "source": "current_olean",
            "command": [],
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        }
    if cached_output is not None and cached_output.exists():
        shutil.copyfile(cached_output, output)
        return {
            "status": "checked",
            "source": "persistent_olean_cache",
            "command": [],
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        }
    result = _run_lean_relational(lean_dir, bundle=bundle, cancel_event=cancel_event)
    if result.get("status") == "checked" and cached_output is not None and output.exists():
        cached_output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output, cached_output)
    return result


def _persistent_olean_path(
    lean_dir: Path,
    bundle: str,
    source: Path,
    dependencies: list[Path],
) -> Path | None:
    cache_root = _relational_cache_dir()
    if cache_root is None:
        return None
    lean = shutil.which("lean") or "lean-unavailable"
    key = sha256_bytes(json.dumps({
        "format": "stage-a-relational-olean-cache-v2",
        "bundle": bundle,
        "source_sha256": sha256_file(source),
        "formal_sha256": sha256_file(lean_dir / "StageA" / "Formal.lean"),
        "dependencies": [
            {
                "module": dependency.stem,
                "source_sha256": sha256_file(dependency.with_suffix(".lean")),
            }
            for dependency in dependencies
        ],
        "lean": lean,
    }, sort_keys=True, separators=(",", ":")).encode())
    return cache_root / "lean-oleans" / f"{bundle}-{key}.olean"


def _lean_register_pair(pair: dict[str, str]) -> str:
    return f"{{ original := .{pair['original']}, candidate := .{pair['candidate']} }}"


def _required_input_pairs(regions: list[dict[str, Any]]) -> list[dict[str, str]]:
    return _required_input_pairs_from([], regions)


def _required_input_pairs_from(
    initial: list[dict[str, str]],
    regions: list[dict[str, Any]],
) -> list[dict[str, str]]:
    required = list(initial)
    seen = {(pair["original"], pair["candidate"]) for pair in required}
    for region in regions:
        for pair in region["inputs"]:
            key = (pair["original"], pair["candidate"])
            if key not in seen:
                seen.add(key)
                # Match Lean's insertRegisterPair, which prepends each first occurrence.
                required.insert(0, pair)
    return required


def _lean_span(span: dict[str, Any]) -> str:
    return f"{{ start := {span['rva_start']}, size := {span['size']} }}"


def _side_padding(contract: dict[str, Any], side: str) -> list[dict[str, Any]]:
    return [
        span for span in contract["padding"]
        if span["side"] in {side, "both"}
    ]


def _side_coverage_spans(contract: dict[str, Any], side: str) -> list[dict[str, Any]]:
    return [region[side] for region in contract["regions"]] + _side_padding(contract, side)


def _sorted_span_certificate(spans: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        enumerate(spans),
        key=lambda item: (item[1]["rva_start"], item[1]["size"], item[0]),
    )
    source_to_sorted = [0] * len(spans)
    for ordinal, (source_index, _) in enumerate(ordered):
        source_to_sorted[source_index] = ordinal
    return {
        "sorted": [span for _, span in ordered],
        "sorted_source_indices": [source_index for source_index, _ in ordered],
        "source_to_sorted": source_to_sorted,
        "source": spans,
    }


def _lean_sorted_span_certificate(spans: list[dict[str, Any]]) -> str:
    certificate = _sorted_span_certificate(spans)
    sorted_spans = ", ".join(_lean_span(span) for span in certificate["sorted"])
    sorted_indices = ", ".join(str(index) for index in certificate["sorted_source_indices"])
    return (
        f"{{ sorted := [{sorted_spans}], "
        f"sourceIndex := {_lean_index_tree([_lean_span(span) for span in certificate['source']])}, "
        f"sortedSourceIndices := [{sorted_indices}], "
        f"sourceToSorted := {_lean_index_tree([str(index) for index in certificate['source_to_sorted']])} }}"
    )


def _lean_padding_alias_certificate(spans: list[dict[str, Any]]) -> str:
    certificate = _sorted_span_certificate(spans)
    run_stops = [0] * len(spans)
    next_start: int | None = None
    next_run_stop: int | None = None
    for source_index, span in reversed(
        list(zip(certificate["sorted_source_indices"], certificate["sorted"], strict=True))
    ):
        stop = span["rva_start"] + span["size"]
        run_stop = next_run_stop if next_start == stop else stop
        run_stops[source_index] = run_stop
        next_start = span["rva_start"]
        next_run_stop = run_stop
    return (
        f"{{ sorted := {_lean_sorted_span_certificate(spans)}, "
        f"runStops := {_lean_index_tree([str(stop) for stop in run_stops])} }}"
    )


def _lean_index_tree(items: list[str]) -> str:
    if not items:
        return ".empty"
    if len(items) == 1:
        return f".leaf ({items[0]})"
    midpoint = len(items) // 2
    return (
        f".node {midpoint} ({_lean_index_tree(items[:midpoint])}) "
        f"({_lean_index_tree(items[midpoint:])})"
    )


def _lean_right_append(names: list[str]) -> str:
    if not names:
        return "[]"
    if len(names) == 1:
        return names[0]
    return f"{names[0]} ++ ({_lean_right_append(names[1:])})"


def _lean_all_append_proof(
    predicate: str,
    chunks: list[str],
    facts: list[str],
) -> str:
    if len(chunks) != len(facts) or not chunks:
        raise ValueError("chunk and fact lists must be non-empty and equal length")
    if len(chunks) == 1:
        return facts[0]
    return (
        f"listAllAppendTrue ({predicate}) {chunks[0]} "
        f"({_lean_right_append(chunks[1:])}) {facts[0]} "
        f"({_lean_all_append_proof(predicate, chunks[1:], facts[1:])})"
    )


def _lean_direct_append_proof(chunks: list[str], facts: list[str]) -> str:
    if len(chunks) != len(facts) or not chunks:
        raise ValueError("chunk and fact lists must be non-empty and equal length")
    if len(chunks) == 1:
        return facts[0]
    return (
        "allDirectRegionGoals_append originalPe candidatePe originalImports candidateImports "
        f"{chunks[0]} ({_lean_right_append(chunks[1:])}) {facts[0]} "
        f"({_lean_direct_append_proof(chunks[1:], facts[1:])})"
    )


def _lean_bool(value: bool) -> str:
    return "true" if value else "false"


def _lean_bytes(data: bytes) -> str:
    rows = [", ".join(str(byte) for byte in data[offset : offset + 32]) for offset in range(0, len(data), 32)]
    return "[\n  " + ",\n  ".join(rows) + "\n]"


def _lean_byte_tree_definitions(name: str, data: bytes, *, chunk_size: int = 1024) -> str:
    chunks = [data[offset : offset + chunk_size] for offset in range(0, len(data), chunk_size)]
    definitions = [
        f"def {name}Chunk{index} : Bytes := {_lean_bytes(chunk)}"
        for index, chunk in enumerate(chunks)
    ]
    trees = [
        (len(chunk), f"(.leaf {name}Chunk{index})")
        for index, chunk in enumerate(chunks)
    ]
    if not trees:
        definitions.append(f"def {name} : ByteTree := .empty")
        return "\n\n".join(definitions)
    while len(trees) > 1:
        merged: list[tuple[int, str]] = []
        for index in range(0, len(trees), 2):
            if index + 1 == len(trees):
                merged.append(trees[index])
                continue
            left_size, left = trees[index]
            right_size, right = trees[index + 1]
            merged.append((
                left_size + right_size,
                f"(.node {left_size + right_size} {left_size} {left} {right})",
            ))
        trees = merged
    definitions.append(f"def {name} : ByteTree := {trees[0][1]}")
    return "\n\n".join(definitions)


def _lean_import_certificate(binary: StageABinary) -> str:
    def bytes_literal(value: bytes) -> str:
        return "[" + ", ".join(str(byte) for byte in value) + "]"

    descriptors: list[str] = []
    import_directory_rva = int(binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress)
    for descriptor_index, entry in enumerate(getattr(binary.pe, "DIRECTORY_ENTRY_IMPORT", []) or []):
        dll = bytes(entry.dll) if isinstance(entry.dll, bytes) else str(entry.dll).encode()
        original_first_thunk = int(entry.struct.OriginalFirstThunk)
        first_thunk = int(entry.struct.FirstThunk)
        lookup_rva = original_first_thunk or first_thunk
        thunks: list[str] = []
        for thunk_index, imported in enumerate(entry.imports):
            if imported.name is not None:
                raw_name = bytes(imported.name) if isinstance(imported.name, bytes) else str(imported.name).encode()
                name = f"(.symbol {bytes_literal(raw_name)})"
                name_rva = int(imported.hint_name_table_rva)
            else:
                name = f"(.ordinal {int(imported.ordinal)})"
                name_rva = 0
            iat_rva = int(imported.address - binary.image_base)
            imported_literal = f"{{ dll := {bytes_literal(dll)}, name := {name}, iatRva := {iat_rva} }}"
            thunks.append(
                "{ lookupRva := " + str(lookup_rva + thunk_index * 4)
                + ", iatRva := " + str(iat_rva)
                + ", nameRva := " + str(name_rva)
                + ", imported := " + imported_literal + " }"
            )
        descriptors.append(
            "{ descriptorRva := " + str(import_directory_rva + descriptor_index * 20)
            + ", lookupRva := " + str(lookup_rva)
            + ", firstThunk := " + str(first_thunk)
            + ", nameRva := " + str(int(entry.struct.Name))
            + ", dll := " + bytes_literal(dll)
            + ", thunks := [" + ", ".join(thunks) + "] }"
        )
    return "{ descriptors := [" + ", ".join(descriptors) + "] }"


def _lean_relocations(binary: StageABinary) -> str:
    relocations = [
        f"{{ rva := {relocation['rva']}, kind := 3 }}"
        for relocation in _raw_base_relocations(binary)
        if relocation["type"] == 3
    ]
    return "[" + ", ".join(relocations) + "]"


def _lean_pe(binary: StageABinary, byte_tree_name: str) -> str:
    pe = binary.pe
    imports = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    relocations = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    sections = ", ".join(
        "{ virtualSize := " + str(int(section.Misc_VirtualSize))
        + ", virtualAddress := " + str(int(section.VirtualAddress))
        + ", rawSize := " + str(int(section.SizeOfRawData))
        + ", rawPointer := " + str(int(section.PointerToRawData))
        + ", characteristics := " + str(int(section.Characteristics)) + " }"
        for section in pe.sections
    )
    return (
        "{ bytes := " + byte_tree_name
        + ", peOffset := " + str(int(pe.DOS_HEADER.e_lfanew))
        + ", entrypointRva := " + str(binary.entrypoint_rva)
        + ", imageBase := " + str(binary.image_base)
        + ", sectionAlignment := " + str(int(pe.OPTIONAL_HEADER.SectionAlignment))
        + ", fileAlignment := " + str(int(pe.OPTIONAL_HEADER.FileAlignment))
        + ", sizeOfImage := " + str(binary.size_of_image)
        + ", importDirectoryRva := " + str(int(imports.VirtualAddress))
        + ", importDirectorySize := " + str(int(imports.Size))
        + ", relocationDirectoryRva := " + str(int(relocations.VirtualAddress))
        + ", relocationDirectorySize := " + str(int(relocations.Size))
        + ", sections := [" + sections + "] }"
    )


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _run_lean_relational(
    lean_dir: Path,
    *,
    bundle: str = "RelationalBundle",
    cancel_event: Event | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    command_elapsed: list[float] = []

    def finish(payload: dict[str, Any]) -> dict[str, Any]:
        payload["elapsed_seconds"] = round(time.monotonic() - started, 3)
        payload["command_elapsed_seconds"] = command_elapsed
        return payload

    lean = shutil.which("lean")
    if lean is None:
        return finish({"status": "unavailable", "returncode": None, "stdout": "", "stderr": ""})
    commands: list[list[str]] = []
    formal_source = lean_dir / "StageA" / "Formal.lean"
    formal_output = lean_dir / "StageA" / "Formal.olean"
    relational_source = lean_dir / "StageA" / "Relational.lean"
    relational_output = lean_dir / "StageA" / "Relational.olean"
    needs_relational = bundle not in {
        "RelationalProofOriginal",
        "RelationalProofCandidate",
        "RelationalProofBase",
    }
    if not _lean_output_current(formal_source, formal_output):
        commands.append([lean, "-o", "StageA/Formal.olean", "StageA/Formal.lean"])
    if needs_relational and (
        not _lean_output_current(relational_source, relational_output)
        or not _lean_output_current(formal_output, relational_output)
    ):
        commands.append([lean, "-o", "StageA/Relational.olean", "StageA/Relational.lean"])
    commands.append([lean, "-o", f"StageA/{bundle}.olean", f"StageA/{bundle}.lean"])
    stdout: list[str] = []
    stderr: list[str] = []
    for command in commands:
        if cancel_event is not None and cancel_event.is_set():
            return finish({
                "status": "cancelled",
                "command": commands,
                "failed_command": command,
                "returncode": None,
                "stdout": "".join(stdout),
                "stderr": "".join(stderr),
            })
        command_started = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        deadline = command_started + 300
        while True:
            if cancel_event is not None and cancel_event.is_set():
                _terminate_process_group(process)
                completed_stdout, completed_stderr = process.communicate()
                command_elapsed.append(round(time.monotonic() - command_started, 3))
                return finish({
                    "status": "cancelled",
                    "command": commands,
                    "failed_command": command,
                    "returncode": process.returncode,
                    "stdout": "".join(stdout) + completed_stdout,
                    "stderr": "".join(stderr) + completed_stderr,
                })
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                completed_stdout, completed_stderr = process.communicate()
                command_elapsed.append(round(time.monotonic() - command_started, 3))
                return finish({
                    "status": "timeout",
                    "command": commands,
                    "failed_command": command,
                    "returncode": None,
                    "stdout": "".join(stdout) + completed_stdout,
                    "stderr": "".join(stderr) + completed_stderr,
                })
            try:
                completed_stdout, completed_stderr = process.communicate(timeout=min(0.2, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        command_elapsed.append(round(time.monotonic() - command_started, 3))
        stdout.append(completed_stdout)
        stderr.append(completed_stderr)
        if process.returncode != 0:
            return finish({"status": "failed", "command": commands, "failed_command": command, "returncode": process.returncode, "stdout": "".join(stdout), "stderr": "".join(stderr)})
    checked_sources = [
        lean_dir / "StageA" / "Formal.lean",
        lean_dir / "StageA" / f"{bundle}.lean",
    ]
    if needs_relational:
        checked_sources.append(lean_dir / "StageA" / "Relational.lean")
    unchecked = [
        str(path)
        for path in checked_sources
        if re.search(r"\b(?:sorry|axiom|unsafe)\b", path.read_text(encoding="utf-8"))
    ]
    if unchecked:
        return finish({
            "status": "unchecked_marker",
            "command": commands,
            "returncode": 1,
            "stdout": "".join(stdout),
            "stderr": "unchecked Lean marker in: " + ", ".join(unchecked),
        })
    if bundle in {"RelationalBundle", "RelationalCounterexample"}:
        combined = "".join(stdout) + "\n" + "".join(stderr)
        match = re.search(r"depends on axioms: \[(.*?)\]", combined, re.DOTALL)
        if match is None:
            return finish({"status": "axioms_missing", "command": commands, "returncode": 1, "stdout": "".join(stdout), "stderr": "".join(stderr)})
        axioms = {item.strip() for item in match.group(1).replace("\n", " ").split(",") if item.strip()}
        if not axioms.issubset(RELATIONAL_APPROVED_AXIOMS):
            return finish({
                "status": "unapproved_axiom",
                "command": commands,
                "returncode": 1,
                "stdout": "".join(stdout),
                "stderr": "unapproved axioms: " + ", ".join(sorted(axioms - RELATIONAL_APPROVED_AXIOMS)),
            })
    return finish({"status": "checked", "command": commands, "returncode": 0, "stdout": "".join(stdout), "stderr": "".join(stderr)})


def _lean_output_current(source: Path, output: Path) -> bool:
    try:
        return output.stat().st_mtime_ns >= source.stat().st_mtime_ns
    except OSError:
        return False


def _collect_certificates(lean_dir: Path, destination: Path) -> list[dict[str, Any]]:
    files = sorted(lean_dir.glob("StageA-Relational*-region*CheckedDirectBehavior-*.lrat"))
    entries: list[dict[str, Any]] = []
    for path in files:
        match = re.search(r"region(\d+)CheckedDirect", path.name)
        if match is None:
            continue
        region_index = int(match.group(1))
        target = destination / f"region-{region_index}.lrat"
        shutil.copyfile(path, target)
        entries.append({"region_index": region_index, "kind": "lrat", "path": target.name, "sha256": sha256_file(target)})
    return entries


def _write_relational_verdict(out: Path, started_at: str, original: StageABinary, candidate: StageABinary, contract: dict[str, Any], proof_ir: dict[str, Any], trusted_base: dict[str, Any], verdict: str, lean: dict[str, Any], *, certificates: list[dict[str, Any]], blocker: str | None) -> dict[str, Any]:
    for entry in certificates:
        index = entry.get("region_index")
        if isinstance(index, int) and 0 <= index < len(contract["regions"]):
            entry["region_id"] = contract["regions"][index]["id"]
    certificate_index = {
        "format": "stage-a-relational-certificates-v1",
        "status": "satisfied" if len(certificates) == len(contract["regions"]) else "incomplete",
        "entries": certificates,
        "counts": {"certificates": len(certificates), "regions": len(contract["regions"])},
    }
    write_json(out / "certificates" / "index.json", certificate_index)
    obligation_status = "proved" if verdict == "pass" else "failed" if verdict == "fail" else "incomplete"
    assumption_obligations = [
        obligation for obligation in proof_ir["obligations"]
        if obligation["kind"] != "relational_region_equivalence"
    ]
    finalized_ir = dict(proof_ir)
    finalized_ir["status"] = (
        "violated" if verdict == "fail"
        else "incomplete" if verdict != "pass" or assumption_obligations
        else "satisfied"
    )
    finalized_ir["families"] = [
        {"family": "exact_pe_decode", "status": "satisfied" if lean.get("status") == "checked" else "incomplete"},
        {"family": "x86_semantics", "status": "satisfied" if verdict in {"pass", "fail"} else "incomplete"},
        {"family": "executable_coverage", "status": "satisfied"},
        {"family": "roots_and_targets", "status": "satisfied"},
        {"family": "relational_regions", "status": "satisfied" if verdict == "pass" else "violated" if verdict == "fail" else "incomplete"},
        {
            "family": "cfg_invariants",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "cfg_bound_invariant",
                    "cfg_address_separation_invariant",
                }
                for obligation in assumption_obligations
            ) else "not_applicable",
        },
        {
            "family": "memory_relation",
            "status": "incomplete" if any(
                obligation["kind"] == "relocation_aware_memory_relation"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {"family": "adversarial_environment", "status": "satisfied"},
    ]
    finalized_ir["obligations"] = [
        ({
            **obligation,
            "status": obligation_status,
            "evidence": next(
                (entry for entry in certificates if entry.get("region_id") == obligation["id"].removeprefix("relational:")),
                None,
            ),
        } if obligation["kind"] == "relational_region_equivalence" else obligation)
        for obligation in proof_ir["obligations"]
    ]
    write_json(out / "relational-proof-ir.json", finalized_ir)
    diagnostic = _lean_diagnostic(lean)
    write_json(
        out / "diagnostics.json",
        {
            "format": "stage-a-relational-diagnostics-v1",
            "status": "satisfied" if verdict == "pass" else "violated" if verdict == "fail" else "incomplete",
            "blocker": blocker,
            "diagnostic": diagnostic,
        },
    )
    result = {
        "format": "stage-a-relational-verdict-v1",
        "verdict": verdict,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "claim_scope": {
            "kind": "relational_region_certificate",
            "whole_program_observational_equivalence": False,
            "acceptance_eligible": False,
        },
        "started_at": started_at,
        "completed_at": utc_now(),
        "original": {"path": str(original.path), "sha256": original.sha256},
        "candidate": {"path": str(candidate.path), "sha256": candidate.sha256},
        "relation_contract_sha256": sha256_file(out / "relation-contract.json"),
        "proof_ir_sha256": sha256_file(out / "relational-proof-ir.json"),
        "trusted_base_sha256": sha256_file(out / "trusted-base.json"),
        "counts": {
            "regions": len(contract["regions"]),
            "certificates": len(certificates),
            "failed": 1 if verdict == "fail" else 0,
            "incomplete": (1 if verdict == "incomplete" else 0) + len(assumption_obligations),
            "incomplete_assumptions": len(assumption_obligations),
        },
        "proof": {
            "theorem": lean.get("theorem", "StageA.GeneratedRelational.candidateRelationalCertificate"),
            "lean": lean,
            "certificate_index": certificate_index,
        },
        "blocker": blocker,
        "diagnostic": diagnostic,
    }
    write_json(out / "verdict.json", result)
    return result


def _write_incomplete(out: Path, started_at: str, original: Path, candidate: Path, blocker: str, *, issues: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    issue_rows = issues or []
    result = {
        "format": "stage-a-relational-verdict-v1",
        "verdict": "incomplete",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "started_at": started_at,
        "completed_at": utc_now(),
        "original": {"path": str(original)},
        "candidate": {"path": str(candidate)},
        "counts": {"regions": 0, "certificates": 0, "incomplete": 1},
        "issues": issue_rows,
        "blocker": blocker,
    }
    write_json(out / "verdict.json", result)
    write_json(
        out / "coverage_gaps.json",
        {
            "format": "stage-a-relational-coverage-gaps-v1",
            "status": "incomplete",
            "gaps": issue_rows,
        },
    )
    return result


def _lean_diagnostic(lean: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(lean.get("counterexample"), dict):
        return {
            "category": "checked_relational_counterexample",
            "severity": "hard",
            "region_id": lean.get("region_id"),
            "counterexample": lean["counterexample"],
            "next_action": "repair the candidate semantics or strengthen only a justified entry invariant",
        }
    if lean.get("status") == "checked":
        return None
    if isinstance(lean.get("issues"), list) and lean["issues"]:
        return {
            "category": "semantic_preflight_incomplete",
            "severity": "hard",
            "count": len(lean["issues"]),
            "first_issue": lean["issues"][0],
            "next_action": lean["issues"][0].get("next_action"),
        }
    stderr = str(lean.get("stderr") or "") + "\n" + str(lean.get("stdout") or "")
    if not stderr:
        return None
    assignment = _counterexample_assignment(stderr)
    error = next((line.strip() for line in stderr.splitlines() if "error:" in line), None)
    return {
        "category": "relational_proof_not_closed",
        "severity": "hard",
        "summary": error or "Lean did not close a generated relational theorem",
        "counterexample": assignment or None,
        "next_action": "inspect the first incomplete region and repair its output relation or candidate semantics",
    }


def _counterexample_assignment(output: str) -> dict[str, int]:
    counterexample = re.search(r"(?:Consider|consider) the following assignment:\n(.*)", output, re.DOTALL)
    if counterexample is None:
        return {}
    assignment: dict[str, int] = {}
    for register, value in re.findall(r"^([a-z][a-z0-9]*) = (\d+)#32$", counterexample.group(1), re.MULTILINE):
        assignment[register] = int(value)
    return assignment


def _certificate_hashes_match(report: Path, index: dict[str, Any]) -> bool:
    entries = index.get("entries")
    if not isinstance(entries, list):
        return False
    return all(
        isinstance(entry, dict)
        and (
            entry.get("kind") == "lean_normalization"
            or (
                entry.get("kind") == "lrat"
                and isinstance(entry.get("path"), str)
                and (report / "certificates" / entry["path"]).is_file()
                and sha256_file(report / "certificates" / entry["path"]) == entry.get("sha256")
            )
        )
        for entry in entries
    )


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None
