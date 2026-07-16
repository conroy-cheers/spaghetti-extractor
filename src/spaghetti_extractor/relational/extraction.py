from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from ..stage_binary import StageABinary, StageAInputError
from ..util import sha256_bytes, sha256_file, write_json
from .analyses.external import _semantic_external_target_identity
from .contract import _import_identity, _raw_base_relocations
from .executor import _relational_cache_dir, _run_lean_relational
from .lean.definitions import _lean_extraction_source
from .model import PURE_SEMANTIC_EXPR_OPERATIONS
from .preflight import side_diagnostics
from .schema import STAGE_A_RELATIONAL_MODEL_ID


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parent.parent / "lean" / "StageA"


def _relational_semantic_preflight(original: Path, candidate: Path, contract: dict[str, Any]) -> dict[str, Any]:
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
    issues = side_diagnostics("original", original, mapping_contract)
    issues += side_diagnostics("candidate", candidate, mapping_contract)
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
        "size_of_headers": binary.size_of_headers,
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
) -> tuple[list[dict[str, Any]] | None, dict[str, Any]]:
    cache_dir = _relational_cache_dir() if use_cache else None
    values: dict[tuple[str, int], dict[str, Any]] = {}
    cache_keys: dict[tuple[str, int], str] = {}
    binaries = {"original": original_bin, "candidate": candidate_bin}
    lean_root = _LEAN_SOURCE_ROOT
    formal_sha256 = sha256_file(lean_root / "Formal.lean")
    decode_path = lean_root / "RelationalDecode.lean"
    extraction_semantics_sha256 = _relational_extraction_semantics_sha256(
        decode_path
    )
    for index, region in enumerate(contract["regions"]):
        for side in ("original", "candidate"):
            key = _behavior_cache_key(
                binaries[side], region[side],
                side=side,
                targets=region.get("code_targets", []),
                machine_import_call_contracts=contract.get(
                    "machine_import_call_contracts", []
                ),
                formal_sha256=formal_sha256,
                extraction_semantics_sha256=extraction_semantics_sha256,
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
        r"STAGE_A_BEHAVIOR_BEGIN (original|candidate) (\d+)\n"
        r"(.*?)\nSTAGE_A_BEHAVIOR_IR\n(.*?)\nSTAGE_A_BEHAVIOR_END",
        re.DOTALL,
    )
    batch_size = max(1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_BATCH", "128")))
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

    jobs = max(1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_EXTRACTION_JOBS", "8")))
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
            for side, index_text, value, semantic_text in pattern.findall(result.get("stdout", "")):
                location = (side, int(index_text))
                if location not in batch:
                    continue
                value = re.sub(r"\s+", " ", value).strip()
                if not value.startswith("some "):
                    for pending in futures:
                        pending.cancel()
                    return None, {**result, "status": "unsupported", "stderr": result.get("stderr", "") + f"\n{side} region {index_text} did not decode"}
                try:
                    semantic = json.loads(semantic_text)
                except json.JSONDecodeError as exc:
                    for pending in futures:
                        pending.cancel()
                    return None, {
                        **result,
                        "status": "malformed_output",
                        "stderr": result.get("stderr", "")
                        + f"\ninvalid semantic IR for {side} region {index_text}: {exc}",
                    }
                if not isinstance(semantic, dict) or semantic.get("format") != "stage-a-normalized-behavior-v1":
                    for pending in futures:
                        pending.cancel()
                    return None, {
                        **result,
                        "status": "malformed_output",
                        "stderr": result.get("stderr", "")
                        + f"\nunsupported semantic IR for {side} region {index_text}",
                    }
                values[location] = {
                    "behavior": value[len("some ") :],
                    "semantic_ir": semantic,
                }
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
                        {
                            "format": "stage-a-relational-behavior-cache-v2",
                            **values[location],
                        },
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

def _behavior_rows(
    values: dict[tuple[str, int], dict[str, Any]], count: int
) -> list[dict[str, Any]]:
    return [
        {
            "original": values.get(("original", index), {}).get("behavior", ""),
            "candidate": values.get(("candidate", index), {}).get("behavior", ""),
            "original_ir": values.get(("original", index), {}).get("semantic_ir"),
            "candidate_ir": values.get(("candidate", index), {}).get("semantic_ir"),
        }
        for index in range(count)
    ]

def _relational_semantic_ir(
    original: StageABinary,
    candidate: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
) -> dict[str, Any]:
    regions = []
    for index, (region, behavior) in enumerate(
        zip(contract["regions"], behaviors, strict=True)
    ):
        original_ir = behavior["original_ir"]
        candidate_ir = behavior["candidate_ir"]
        regions.append({
            "index": index,
            "id": region["id"],
            "numeric_id": region["numeric_id"],
            "root": region["root"],
            "original_span": region["original"],
            "candidate_span": region["candidate"],
            "original": original_ir,
            "candidate": candidate_ir,
            "original_sha256": sha256_bytes(
                json.dumps(original_ir, sort_keys=True, separators=(",", ":")).encode()
            ),
            "candidate_sha256": sha256_bytes(
                json.dumps(candidate_ir, sort_keys=True, separators=(",", ":")).encode()
            ),
        })
    return {
        "format": "stage-a-relational-semantic-ir-v1",
        "status": "extracted_untrusted_checked_by_generated_lean_proofs",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "original_sha256": original.sha256,
        "candidate_sha256": candidate.sha256,
        "relation_contract_sha256": sha256_bytes(
            json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
        ),
        "trust": {
            "role": "analysis_and_proof_proposal_only",
            "acceptance_rule": (
                "every decoded behavior, invariant, edge, and composition claim must be "
                "reconstructed from exact PE bytes and checked by Lean"
            ),
        },
        "regions": regions,
    }

def _semantic_memory_expression_pullback_supported(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    operation = value.get("op")
    if operation in {"input_reg", "input_fs_base", "constant", "undefined"}:
        return True
    if operation == "input_flag_value":
        return int(value.get("bit", -1)) in {0, 2, 6, 7, 10, 11}
    if operation in {"read8", "read32"}:
        return _semantic_memory_expression_pullback_supported(value.get("address"))
    if operation == "read8_after_write":
        return all(
            _semantic_memory_expression_pullback_supported(value.get(field))
            for field in ("address", "write_address", "write_value", "prior")
        )
    if operation not in PURE_SEMANTIC_EXPR_OPERATIONS:
        return False
    return all(
        _semantic_memory_expression_pullback_supported(child)
        for key, child in value.items()
        if key != "op" and isinstance(child, dict) and "op" in child
    )

def _semantic_exact_memory_inputs(
    value: Any, exact_registers: set[str]
) -> bool:
    if not isinstance(value, dict):
        return False
    operation = value.get("op")
    if operation == "input_reg":
        return str(value.get("reg")) in exact_registers
    if operation in {"input_fs_base", "constant", "undefined"}:
        return True
    if operation in {"input_flag_value", "input_x87_control", "input_x87_status"}:
        return False
    if operation in {"read8", "read32"}:
        return _semantic_exact_memory_inputs(value.get("address"), exact_registers)
    if operation == "read8_after_write":
        return all(
            _semantic_exact_memory_inputs(value.get(field), exact_registers)
            for field in ("address", "write_address", "write_value", "prior")
        )
    if operation not in PURE_SEMANTIC_EXPR_OPERATIONS:
        return False
    return all(
        _semantic_exact_memory_inputs(child, exact_registers)
        for key, child in value.items()
        if key != "op" and isinstance(child, dict) and "op" in child
    )

def _semantic_pullback_exact_memory_inputs(
    value: Any,
    source_behavior: dict[str, Any],
    exact_registers: set[str],
) -> bool:
    if not isinstance(value, dict):
        return False
    operation = value.get("op")
    if operation == "input_reg":
        expression = source_behavior.get("registers", {}).get(str(value.get("reg")))
        return _semantic_exact_memory_inputs(expression, exact_registers)
    if operation in {"input_fs_base", "constant", "undefined"}:
        return True
    if operation in {"input_flag_value", "input_x87_control", "input_x87_status"}:
        return False
    if operation in {"read8", "read32"}:
        return (
            _semantic_pullback_exact_memory_inputs(
                value.get("address"), source_behavior, exact_registers
            )
            and all(
                _semantic_exact_memory_inputs(expression, exact_registers)
                for write in source_behavior.get("writes", [])
                for expression in (write.get("address"), write.get("value"))
            )
        )
    if operation == "read8_after_write":
        return all(
            _semantic_pullback_exact_memory_inputs(
                value.get(field), source_behavior, exact_registers
            )
            for field in ("address", "write_address", "write_value", "prior")
        )
    if operation not in PURE_SEMANTIC_EXPR_OPERATIONS:
        return False
    return all(
        _semantic_pullback_exact_memory_inputs(child, source_behavior, exact_registers)
        for key, child in value.items()
        if key != "op" and isinstance(child, dict) and "op" in child
    )

def _semantic_memory_pullback_support(value: dict[str, Any]) -> tuple[str, str | None]:
    operation = value.get("op")
    if operation in {"read8", "read32", "read8_after_write"}:
        if _semantic_memory_expression_pullback_supported(value):
            return "lean_pullback_supported", None
    if operation in {"read8", "read32"}:
        return (
            "unsupported_stateful_address",
            "the read address contains a flag-dependent, x87-dependent, or unsupported "
            "machine-state expression",
        )
    if operation == "read8_after_write":
        return (
            "unsupported_nested_post_write_read",
            "the local write operands or prior byte observation contain a flag-dependent, "
            "x87-dependent, or unsupported machine-state expression",
        )
    return (
        "unsupported_x87_load",
        "x87 load observations require a byte-range pullback into X87Expr semantics",
    )

def _semantic_value_at_path(value: Any, path: list[str]) -> Any:
    for component in path:
        value = value[int(component)] if isinstance(value, list) else value[component]
    return value

def _semantic_x87_load_pullback_supported(
    observation: dict[str, Any], source_behavior: dict[str, Any]
) -> bool:
    address = observation.get("address")
    control = observation.get("control")
    if not _semantic_memory_expression_pullback_supported(address):
        return False
    if isinstance(control, dict) and control.get("op") == "input_x87_control":
        return isinstance(source_behavior.get("x87", {}).get("control"), dict)
    return _semantic_memory_expression_pullback_supported(control)

def _semantic_memory_reads(value: Any, path: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    reads: list[dict[str, Any]] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            reads.extend(_semantic_memory_reads(item, (*path, str(index))))
        return reads
    if not isinstance(value, dict):
        return reads

    operation = value.get("op")
    if operation in {"read8", "read32", "read8_after_write", "load"}:
        if operation == "read8":
            width = 1
            relation = "exact_byte"
        elif operation == "read32":
            width = 4
            relation = "word_related_or_exact_dword"
        elif operation == "read8_after_write":
            width = 1
            relation = "exact_byte_after_local_write_pullback"
        else:
            width = {
                "float32": 4,
                "float64": 8,
                "float80": 10,
                "int32": 4,
            }.get(value.get("format"))
            relation = "exact_x87_load_bytes"
        address = value.get("address")
        pullback_support, pullback_blocker = _semantic_memory_pullback_support(value)
        reads.append({
            "path": list(path),
            "operation": operation,
            "width": width,
            "required_relation": relation,
            "pullback_support": pullback_support,
            "pullback_blocker": pullback_blocker,
            "address_sha256": sha256_bytes(
                json.dumps(address, sort_keys=True, separators=(",", ":")).encode()
            ),
            "address": address,
            "constant_address": (
                int(address["value"]) & 0xFFFFFFFF
                if isinstance(address, dict) and address.get("op") == "constant"
                else None
            ),
        })

    for key in sorted(value):
        if key in {"op", "prior"} and operation == "read8_after_write":
            continue
        if key == "op":
            continue
        reads.extend(_semantic_memory_reads(value[key], (*path, key)))
    return reads

def _iat_read_classification(
    binary: StageABinary, observation: dict[str, Any],
) -> dict[str, Any]:
    address = observation.get("constant_address")
    width = observation.get("width")
    if not isinstance(address, int) or not isinstance(width, int):
        return {
            "status": "dynamic_address_requires_non_iat_proof",
            "proof_role": "untrusted_side_condition_proposal",
        }
    end = address + width
    overlaps = []
    for imported in binary.imports:
        if imported.thunk_rva is None:
            continue
        iat_address = binary.image_base + int(imported.thunk_rva)
        if address < iat_address + 4 and iat_address < end:
            overlaps.append((imported, iat_address))
    if not overlaps:
        return {
            "status": "statically_outside_iat",
            "proof_role": "untrusted_side_condition_proposal",
        }
    if len(overlaps) == 1 and width == 4 and address == overlaps[0][1]:
        imported, iat_address = overlaps[0]
        identity = _import_identity(imported)
        if identity is not None:
            return {
                "status": "exact_iat_cell",
                "proof_role": "requires_import_address_pair_witness",
                "iat_rva": iat_address - binary.image_base,
                "import": {
                    "dll": identity[0],
                    identity[1]: identity[2],
                },
            }
    return {
        "status": "partial_iat_overlap_unsupported",
        "proof_role": "hard_incomplete",
        "overlap_count": len(overlaps),
    }

def _assembled_iat_read_candidates(
    binary: StageABinary, semantic: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for register, expression in sorted((semantic.get("registers") or {}).items()):
        assembled = _assembled_u32_after_register_writes(expression)
        if assembled is None:
            continue
        address, writes = assembled
        imported = _unique_import_at_absolute_address(binary, address)
        identity = _import_identity(imported) if imported is not None else None
        if identity is None:
            continue
        candidates.append({
            "register": register,
            "absolute_address": address,
            "iat_rva": address - binary.image_base,
            "import": {"dll": identity[0], identity[1]: identity[2]},
            "intervening_register_writes": len(writes),
            "status": (
                "exact_iat_cell"
                if not writes else "requires_intervening_write_separation"
            ),
            "next_action": (
                "use ImportAddressPair.memoryHolds directly"
                if not writes else
                "prove every intervening write avoids the four-byte IAT cell, then "
                "reduce the assembled bytes to Memory.read32"
            ),
        })
    return candidates

def _semantic_successors(outcome: dict[str, Any]) -> dict[str, Any]:
    operation = outcome.get("op")
    if operation == "jump":
        direct = [outcome.get("target")]
    elif operation == "branch":
        direct = [outcome.get("taken"), outcome.get("fallthrough")]
    elif operation == "call":
        direct = [outcome.get("target")]
    elif operation in {
        "external_call", "bulk_copy", "checked_continue", "atomic_compare_exchange",
    }:
        direct = [outcome.get("continuation")]
    else:
        direct = []
    return {
        "outcome": operation,
        "direct": [target for target in direct if isinstance(target, int)],
        "continuation": (
            outcome.get("continuation")
            if isinstance(outcome.get("continuation"), int) else None
        ),
        "dynamic_target": operation in {"indirect_call", "indirect_jump", "returned"},
    }

def _relational_memory_contracts(
    original: StageABinary,
    candidate: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
) -> dict[str, Any]:
    region_rows: list[dict[str, Any]] = []
    reads_by_id: dict[int, dict[str, Any]] = {}
    for index, (region, behavior) in enumerate(
        zip(contract["regions"], behaviors, strict=True)
    ):
        side_reads: dict[str, list[dict[str, Any]]] = {}
        for side in ("original", "candidate"):
            semantic = behavior.get(f"{side}_ir") or {}
            side_reads[side] = _semantic_memory_reads(semantic)
            binary = original if side == "original" else candidate
            for observation in side_reads[side]:
                observation["iat_classification"] = _iat_read_classification(
                    binary, observation
                )
        paired = []
        reads_by_path = {
            side: {tuple(read["path"]): read for read in side_reads[side]}
            for side in ("original", "candidate")
        }
        read_paths = sorted(
            set(reads_by_path["original"]) | set(reads_by_path["candidate"])
        )
        for read_index, read_path in enumerate(read_paths):
            original_read = reads_by_path["original"].get(read_path)
            candidate_read = reads_by_path["candidate"].get(read_path)
            same_shape = bool(
                original_read is not None
                and candidate_read is not None
                and original_read["operation"] == candidate_read["operation"]
                and original_read["width"] == candidate_read["width"]
            )
            paired.append({
                "id": f"memory-read:{region['id']}:{read_index}",
                "status": "paired_shape" if same_shape else "unpaired_shape",
                "original": original_read,
                "candidate": candidate_read,
            })
        original_semantic = behavior.get("original_ir") or {}
        candidate_semantic = behavior.get("candidate_ir") or {}
        original_writes = original_semantic.get("writes") or []
        candidate_writes = candidate_semantic.get("writes") or []
        successor = _semantic_successors(original_semantic.get("outcome") or {})
        candidate_successor = _semantic_successors(
            candidate_semantic.get("outcome") or {}
        )

        def pullback_summary(side: str) -> dict[str, Any]:
            observations = [
                read[side] for read in paired if read.get(side) is not None
            ]
            ordinary = [
                read for read in observations if read["operation"] != "load"
            ]
            unsupported: dict[str, int] = {}
            for read in ordinary:
                status = read["pullback_support"]
                if status != "lean_pullback_supported":
                    unsupported[status] = unsupported.get(status, 0) + 1
            return {
                "ordinary_observations": len(ordinary),
                "lean_pullback_supported": sum(
                    read["pullback_support"] == "lean_pullback_supported"
                    for read in ordinary
                ),
                "all_ordinary_reads_supported": not unsupported,
                "unsupported": dict(sorted(unsupported.items())),
                "x87_load_observations": sum(
                    read["operation"] == "load" for read in observations
                ),
            }

        pullback = {
            side: pullback_summary(side) for side in ("original", "candidate")
        }
        pullback["paired_direct_successors"] = (
            successor["direct"] == candidate_successor["direct"]
        )
        row = {
            "index": index,
            "id": region["id"],
            "numeric_id": region["numeric_id"],
            "reads": paired,
            "writes": {
                "original_count": len(original_writes),
                "candidate_count": len(candidate_writes),
                "symbolically_identical": original_writes == candidate_writes,
            },
            "successors": successor,
            "candidate_successors": candidate_successor,
            "pullback": pullback,
            "assembled_iat_read_candidates": {
                "original": _assembled_iat_read_candidates(
                    original, original_semantic
                ),
                "candidate": _assembled_iat_read_candidates(
                    candidate, candidate_semantic
                ),
            },
        }
        region_rows.append(row)
        reads_by_id[region["numeric_id"]] = {
            "paired": sum(read["status"] == "paired_shape" for read in paired),
            "unpaired": sum(read["status"] != "paired_shape" for read in paired),
            "pullback": pullback,
        }

    index_by_numeric_id = {
        row["numeric_id"]: row["index"] for row in region_rows
    }
    for row in region_rows:
        requirements = []
        for target in row["successors"]["direct"]:
            if target not in reads_by_id:
                continue
            target_index = index_by_numeric_id[target]
            target_row = region_rows[target_index]
            x87_loads = [
                read for read in target_row["reads"]
                if (read.get("original") or {}).get("operation") == "load"
            ]
            x87_side_supported = {}
            for side in ("original", "candidate"):
                source_behavior = behaviors[row["index"]].get(f"{side}_ir") or {}
                target_behavior = behaviors[target_index].get(f"{side}_ir") or {}
                observations = [
                    _semantic_value_at_path(target_behavior, read[side]["path"])
                    for read in x87_loads
                    if read.get(side) is not None
                ]
                x87_side_supported[side] = all(
                    _semantic_x87_load_pullback_supported(
                        observation, source_behavior
                    )
                    for observation in observations
                )
            source_index = row["index"]
            original_source = behaviors[source_index].get("original_ir") or {}
            candidate_source = behaviors[source_index].get("candidate_ir") or {}
            exact_registers = {
                relation["original"]
                for relation in register_relations["regions"][source_index]["inputs"]
                if relation["relation"] == "exact"
                and relation["original"] == relation["candidate"]
            }
            exact_pullback_pair_claims = []
            if (
                not contract.get("value_targets")
                and original_source.get("registers") == candidate_source.get("registers")
                and original_source.get("writes") == candidate_source.get("writes")
            ):
                original_target = behaviors[target_index].get("original_ir") or {}
                candidate_target = behaviors[target_index].get("candidate_ir") or {}
                for read in target_row["reads"]:
                    if (
                        read["status"] != "paired_shape"
                        or (read.get("original") or {}).get("operation") == "load"
                    ):
                        continue
                    original_expression = _semantic_value_at_path(
                        original_target, read["original"]["path"]
                    )
                    candidate_expression = _semantic_value_at_path(
                        candidate_target, read["candidate"]["path"]
                    )
                    if (
                        original_expression == candidate_expression
                        and _semantic_pullback_exact_memory_inputs(
                            original_expression, original_source, exact_registers
                        )
                    ):
                        exact_pullback_pair_claims.append({
                            "read_id": read["id"],
                            "path": read["original"]["path"],
                            "expression": original_expression,
                        })
            requirements.append({
                "numeric_id": target,
                **reads_by_id[target],
                "ordinary_pullback_pair_supported": (
                    row["pullback"]["paired_direct_successors"]
                    and all(
                        reads_by_id[target]["pullback"][side][
                            "all_ordinary_reads_supported"
                        ]
                        for side in ("original", "candidate")
                    )
                ),
                "x87_load_observations": len(x87_loads),
                "x87_load_pullback": x87_side_supported,
                "x87_load_pullback_pair_supported": (
                    row["pullback"]["paired_direct_successors"]
                    and all(x87_side_supported.values())
                ),
                "exact_pullback_pair_claims": exact_pullback_pair_claims,
                "exact_memory_transition_proposed": (
                    len(exact_pullback_pair_claims)
                    == reads_by_id[target]["pullback"]["original"][
                        "ordinary_observations"
                    ]
                    and reads_by_id[target]["unpaired"] == 0
                    and not x87_loads
                ),
            })
        row["successor_read_requirements"] = requirements

    all_reads = [read for row in region_rows for read in row["reads"]]
    operation_counts = {
        operation: sum(
            read.get("original", {}).get("operation") == operation
            for read in all_reads
            if read.get("original") is not None
        )
        for operation in sorted({
            read["original"]["operation"]
            for read in all_reads
            if read.get("original") is not None
        })
    }
    pullback_counts = {
        side: {
            "ordinary_observations": sum(
                row["pullback"][side]["ordinary_observations"] for row in region_rows
            ),
            "lean_pullback_supported": sum(
                row["pullback"][side]["lean_pullback_supported"] for row in region_rows
            ),
            "regions_all_ordinary_reads_supported": sum(
                row["pullback"][side]["all_ordinary_reads_supported"]
                for row in region_rows
            ),
        }
        for side in ("original", "candidate")
    }
    direct_requirements = [
        requirement
        for row in region_rows
        for requirement in row["successor_read_requirements"]
    ]
    iat_read_counts = {
        side: dict(sorted(Counter(
            read[side]["iat_classification"]["status"]
            for read in all_reads if read.get(side) is not None
        ).items()))
        for side in ("original", "candidate")
    }
    assembled_iat_counts = {
        side: dict(sorted(Counter(
            candidate["status"]
            for row in region_rows
            for candidate in row["assembled_iat_read_candidates"][side]
        ).items()))
        for side in ("original", "candidate")
    }
    return {
        "format": "stage-a-relational-memory-contracts-v1",
        "status": "analysis_requires_lean_pullback_replay",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "original_sha256": original.sha256,
        "candidate_sha256": candidate.sha256,
        "relation_contract_sha256": sha256_bytes(
            json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
        ),
        "trust": {
            "role": "proof_obligation_generation_only",
            "acceptance_rule": (
                "read inventories, successor edges, and write pullbacks must be reconstructed "
                "from exact decoded behaviors and checked by Lean"
            ),
        },
        "counts": {
            "regions": len(region_rows),
            "read_observations": len(all_reads),
            "paired_read_shapes": sum(
                read["status"] == "paired_shape" for read in all_reads
            ),
            "unpaired_read_shapes": sum(
                read["status"] != "paired_shape" for read in all_reads
            ),
            "read_operations": operation_counts,
            "iat_read_classification": iat_read_counts,
            "assembled_iat_reads": assembled_iat_counts,
            "pullback": pullback_counts,
            "direct_successor_requirements": len(direct_requirements),
            "ordinary_pullback_pair_supported_edges": sum(
                requirement["ordinary_pullback_pair_supported"]
                for requirement in direct_requirements
            ),
            "x87_load_successor_edges": sum(
                requirement["x87_load_observations"] > 0
                for requirement in direct_requirements
            ),
            "x87_load_pullback_pair_supported_edges": sum(
                requirement["x87_load_observations"] > 0
                and requirement["x87_load_pullback_pair_supported"]
                for requirement in direct_requirements
            ),
            "exact_pullback_pair_claims": sum(
                len(requirement["exact_pullback_pair_claims"])
                for requirement in direct_requirements
            ),
            "edges_with_exact_pullback_pair_claims": sum(
                bool(requirement["exact_pullback_pair_claims"])
                for requirement in direct_requirements
            ),
            "exact_memory_transition_edges": sum(
                requirement["exact_memory_transition_proposed"]
                for requirement in direct_requirements
            ),
        },
        "regions": region_rows,
    }

def _behavior_cache_key(
    binary: StageABinary,
    span: dict[str, Any],
    *,
    side: str,
    targets: list[dict[str, Any]],
    machine_import_call_contracts: list[dict[str, Any]] | None = None,
    formal_sha256: str | None = None,
    extraction_semantics_sha256: str | None = None,
) -> str:
    lean_root = _LEAN_SOURCE_ROOT
    payload = {
        "format": "stage-a-relational-behavior-cache-key-v6",
        "binary_sha256": binary.sha256,
        "span": {"rva_start": span["rva_start"], "size": span["size"]},
        "side": side,
        "targets": targets,
        "machine_import_call_contracts": machine_import_call_contracts or [],
        "formal_sha256": formal_sha256 or sha256_file(lean_root / "Formal.lean"),
        "decode_module_sha256": extraction_semantics_sha256
        or _relational_extraction_semantics_sha256(
            lean_root / "RelationalDecode.lean"
        ),
    }
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())

def _relational_extraction_semantics_sha256(path: Path) -> str:
    if path.name != "RelationalDecode.lean":
        raise StageAInputError(
            "relational extraction semantics must come from RelationalDecode.lean"
        )
    return sha256_file(path)

def _read_behavior_cache(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("format") != "stage-a-relational-behavior-cache-v2":
        return None
    behavior = payload.get("behavior")
    semantic_ir = payload.get("semantic_ir")
    if (
        not isinstance(behavior, str)
        or not behavior
        or not isinstance(semantic_ir, dict)
        or semantic_ir.get("format") != "stage-a-normalized-behavior-v1"
    ):
        return None
    return {"behavior": behavior, "semantic_ir": semantic_ir}

def _cached_behavior_affected_by_machine_contracts(
    cached: dict[str, Any], contracts: list[dict[str, Any]]
) -> bool:
    outcome = cached.get("semantic_ir", {}).get("outcome")
    if not isinstance(outcome, dict) or outcome.get("op") not in {
        "external_call", "external_jump",
    }:
        return False
    target = _semantic_external_target_identity(outcome.get("import"))
    if target is None:
        return bool(contracts)
    for contract in contracts:
        imported = contract.get("import", {})
        identity = (
            str(imported.get("dll", "")).lower(),
            "symbol" if "symbol" in imported else "ordinal",
            imported.get("symbol", imported.get("ordinal")),
        )
        if identity == target:
            return True
    return False

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

def _assembled_u32_after_register_writes(
    expression: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]] | None:
    if expression.get("op") == "read32":
        address = expression.get("address") or {}
        if address.get("op") == "constant":
            return int(address["value"]), []
    shifted_bytes: dict[int, dict[str, Any]] = {}

    def collect(node: dict[str, Any], shift: int = 0) -> bool:
        operation = node.get("op")
        if operation == "bit_or":
            return collect(node.get("left") or {}, shift) and collect(
                node.get("right") or {}, shift
            )
        if operation == "shift_left":
            return collect(node.get("value") or {}, shift + int(node.get("amount", -1)))
        if shift not in {0, 8, 16, 24} or shift in shifted_bytes:
            return False
        shifted_bytes[shift] = node
        return True

    if not collect(expression) or set(shifted_bytes) != {0, 8, 16, 24}:
        return None
    decoded = [
        _read8_after_register_writes(shifted_bytes[shift])
        for shift in (0, 8, 16, 24)
    ]
    if any(item is None for item in decoded):
        return None
    byte_rows = [item for item in decoded if item is not None]
    base = byte_rows[0][0]
    writes = byte_rows[0][1]
    if any(address != base + index or row_writes != writes
           for index, (address, row_writes) in enumerate(byte_rows)):
        return None
    return base, writes

def _read8_after_register_writes(
    expression: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]] | None:
    writes_reversed: list[dict[str, Any]] = []
    cursor = expression
    while cursor.get("op") == "read8_after_write":
        write = _register_offset_write(
            cursor.get("write_address") or {}, cursor.get("write_value") or {}
        )
        if write is None:
            return None
        writes_reversed.append(write)
        cursor = cursor.get("prior") or {}
    address = cursor.get("address") or {}
    if cursor.get("op") != "read8" or address.get("op") != "constant":
        return None
    return int(address["value"]), list(reversed(writes_reversed))

def _register_offset_write(
    address: dict[str, Any], value: dict[str, Any]
) -> dict[str, Any] | None:
    if address.get("op") == "input_reg":
        return {
            "register": str(address["reg"]),
            "offset": 0,
            "value": value,
        }
    if address.get("op") != "add":
        return None
    left = address.get("left") or {}
    right = address.get("right") or {}
    if left.get("op") == "constant":
        left, right = right, left
    if left.get("op") != "input_reg" or right.get("op") != "constant":
        return None
    offset = int(right["value"])
    if not 0 <= offset < 2**32:
        return None
    return {
        "register": str(left["reg"]),
        "offset": offset,
        "value": value,
    }

def _unique_import_at_absolute_address(
    binary: StageABinary, absolute_address: int,
) -> Any | None:
    iat_rva = absolute_address - binary.image_base
    matches = [
        imported for imported in binary.imports
        if imported.thunk_rva is not None and int(imported.thunk_rva) == iat_rva
    ]
    return matches[0] if len(matches) == 1 else None
