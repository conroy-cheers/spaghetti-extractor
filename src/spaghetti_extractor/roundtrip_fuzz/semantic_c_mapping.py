"""Untrusted Stage A mapping proposals for compiled semantic-C transfers."""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

import capstone

from ..errors import StageAInputError
from ..stage_binary import (
    StageABinary,
    _linker_function_match_key,
    _parse_linker_map_functions,
    _parse_linker_map_symbol_line,
    _parse_stage_a_pe,
)
from ..util import sha256_file, write_json


SEMANTIC_C_MAPPING_PROPOSAL_FORMAT = "stage-a-semantic-c-mapping-proposal-v1"
STAGE_A_BLOCK_MAP_FORMAT = "stage-a-block-map-v1"
_SOURCE_MAP_FORMAT = "stage-b-semantic-c-source-map-v1"
_IMPLEMENTATION_FORMAT = "stage-b-semantic-c-implementation-v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def build_semantic_c_mapping_proposal(
    *,
    original: Path,
    candidate: Path,
    source_map: Path,
    candidate_linker_map: Path,
    implementation: Path | None = None,
    implementation_manifest: Path | None = None,
    runtime_binding: Path | None = None,
) -> dict[str, Any]:
    """Build a deterministic mapping hint without making a proof claim.

    The semantic-C manifests and linker map are all untrusted inputs.  A block
    is included only when their bindings select one exactly decoded executable
    range on each side.  The returned block map must still go through the
    ordinary Stage A relation construction and Lean checker.
    """

    implementation_path = _select_implementation_path(
        implementation=implementation,
        implementation_manifest=implementation_manifest,
    )
    original_path = Path(original)
    candidate_path = Path(candidate)
    source_map_path = Path(source_map)
    candidate_map_path = Path(candidate_linker_map)
    original_binary = _parse_stage_a_pe(original_path)
    candidate_binary = _parse_stage_a_pe(candidate_path)
    source_payload = _read_json_object(source_map_path, "semantic-C source map")
    implementation_payload = _read_json_object(
        implementation_path, "semantic-C implementation manifest"
    )
    runtime_binding_path = Path(runtime_binding) if runtime_binding is not None else None
    runtime_binding_payload = (
        _read_json_object(runtime_binding_path, "native runtime binding")
        if runtime_binding_path is not None
        else None
    )

    issues: list[dict[str, Any]] = []
    globally_blocked = False
    if source_payload.get("format") != _SOURCE_MAP_FORMAT:
        issues.append(_issue(
            "invalid_source_map_format",
            "the semantic-C source map format is missing or unsupported",
            f"regenerate {_SOURCE_MAP_FORMAT} with the Stage B semantic-C backend",
            details={"actual": source_payload.get("format"), "expected": _SOURCE_MAP_FORMAT},
        ))
        globally_blocked = True
    if implementation_payload.get("format") != _IMPLEMENTATION_FORMAT:
        issues.append(_issue(
            "invalid_implementation_format",
            "the semantic-C implementation manifest format is missing or unsupported",
            f"regenerate {_IMPLEMENTATION_FORMAT} with the Stage B semantic-C backend",
            details={
                "actual": implementation_payload.get("format"),
                "expected": _IMPLEMENTATION_FORMAT,
            },
        ))
        globally_blocked = True

    source_map_sha256 = _hash_input(source_map_path, "semantic-C source map")
    implementation_sha256 = _hash_input(
        implementation_path, "semantic-C implementation manifest"
    )
    candidate_map_sha256 = _hash_input(candidate_map_path, "candidate linker map")
    source_binding = _source_map_binding(implementation_payload)
    if source_binding is None:
        issues.append(_issue(
            "missing_source_map_hash_binding",
            "the implementation manifest does not bind its source map by SHA-256",
            "regenerate the implementation manifest together with state-machine-source-map.json",
        ))
        globally_blocked = True
    elif source_binding != source_map_sha256:
        issues.append(_issue(
            "source_map_hash_mismatch",
            "the supplied source map does not match the implementation manifest binding",
            "use state-machine-source-map.json from the same semantic-C generation directory",
            details={"actual": source_map_sha256, "expected": source_binding},
        ))
        globally_blocked = True

    if (
        original_binary.machine != candidate_binary.machine
        or original_binary.bitness != candidate_binary.bitness
    ):
        issues.append(_issue(
            "binary_model_mismatch",
            "the original and candidate PEs use different machine models",
            "compile the semantic-C candidate for the original PE architecture",
            details={
                "candidate": {
                    "bitness": candidate_binary.bitness,
                    "machine": candidate_binary.machine,
                },
                "original": {
                    "bitness": original_binary.bitness,
                    "machine": original_binary.machine,
                },
            },
        ))
        globally_blocked = True

    source_rows = source_payload.get("transfers")
    if not isinstance(source_rows, list) or not source_rows:
        issues.append(_issue(
            "missing_source_transfer_inventory",
            "the source map has no nonempty transfer inventory",
            "regenerate semantic C from a nonempty Stage A semantic transfer inventory",
        ))
        source_rows = []
        globally_blocked = True
    implementation_rows = implementation_payload.get("transfer_inventory")
    if not isinstance(implementation_rows, list):
        issues.append(_issue(
            "missing_implementation_transfer_inventory",
            "the implementation manifest has no transfer_inventory list",
            "regenerate the semantic-C implementation manifest",
        ))
        implementation_rows = []
        globally_blocked = True

    parsed_sources, invalid_ids = _parse_source_rows(source_rows, issues)
    parsed_implementations, duplicate_implementation_ids = _index_implementation_rows(
        implementation_rows, issues
    )
    invalid_ids.update(duplicate_implementation_ids)
    _mark_duplicate_source_fields(parsed_sources, invalid_ids, issues)

    source_ids = {row["id"] for row in parsed_sources}
    for transfer_id in sorted(set(parsed_implementations) - source_ids):
        issues.append(_issue(
            "implementation_transfer_not_in_source_map",
            "the implementation inventory contains a transfer absent from the source map",
            "regenerate both semantic-C manifests from the same transfer inventory",
            transfer_id=transfer_id,
        ))

    strict_candidate = implementation_payload.get("strict_candidate")
    runtime_binding_ready = _runtime_binding_closes_strict_candidate(
        implementation_payload, strict_candidate, runtime_binding_payload
    )
    if (
        not isinstance(strict_candidate, Mapping)
        or (
            strict_candidate.get("status") != "ready"
            and not runtime_binding_ready
        )
    ):
        blockers = (
            sorted(str(value) for value in strict_candidate.get("blockers", []))
            if isinstance(strict_candidate, Mapping)
            and isinstance(strict_candidate.get("blockers"), list)
            else []
        )
        issues.append(_issue(
            "semantic_c_candidate_not_ready",
            "the implementation manifest does not classify the semantic-C candidate as ready",
            "resolve every implementation blocker and regenerate the semantic-C artifacts",
            details={"blockers": blockers},
        ))

    functions = _parse_linker_map_functions(candidate_map_path, candidate_binary)
    functions_by_symbol = _functions_by_symbol(functions)
    raw_symbol_rvas = _raw_symbol_rvas(candidate_map_path, candidate_binary)
    known_original_starts = sorted({row["rva_start"] for row in parsed_sources})

    blocks: list[dict[str, Any]] = []
    candidate_rvas: dict[int, list[str]] = defaultdict(list)
    resolved: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for source_row in sorted(parsed_sources, key=lambda row: (row["rva_start"], row["id"])):
        transfer_id = source_row["id"]
        if transfer_id in invalid_ids or globally_blocked:
            continue
        implementation_matches = parsed_implementations.get(transfer_id, [])
        if len(implementation_matches) != 1:
            if not implementation_matches:
                issues.append(_issue(
                    "missing_implementation_transfer",
                    "the source-map transfer has no implementation inventory row",
                    "regenerate both semantic-C manifests from the same transfer inventory",
                    transfer_id=transfer_id,
                ))
            continue
        implementation_row = implementation_matches[0]
        if not _validate_transfer_binding(source_row, implementation_row, issues):
            continue

        original_span = _resolve_original_span(
            source_row,
            implementation_row,
            binary=original_binary,
            known_starts=known_original_starts,
            issues=issues,
        )
        if original_span is None or not _validate_decoded_range(
            original_binary,
            original_span[0],
            original_span[1],
            side="original",
            transfer_id=transfer_id,
            issues=issues,
        ):
            continue

        symbol = source_row["symbol"]
        symbol_key = _symbol_key(symbol)
        matches = functions_by_symbol.get(symbol_key, [])
        raw_rvas = sorted(raw_symbol_rvas.get(symbol_key, set()))
        if len(matches) != 1 or len(raw_rvas) > 1:
            if not matches and raw_rvas and all(
                _executable_range(candidate_binary, rva, rva + 1) is None
                for rva in raw_rvas
            ):
                category = "candidate_symbol_out_of_bounds"
                blocker = "the candidate linker-map symbol is outside executable PE bounds"
                next_action = "fix the candidate link layout so the transfer symbol is in executable code"
            elif not matches:
                category = "candidate_symbol_missing"
                blocker = "the candidate linker map does not resolve the transfer symbol"
                next_action = "retain the generated transfer symbol in the GNU linker map"
            else:
                category = "candidate_symbol_ambiguous"
                blocker = "the candidate linker map resolves the transfer symbol to multiple ranges"
                next_action = "make transfer symbols unique and disable linker aliases that select different ranges"
            issues.append(_issue(
                category,
                blocker,
                next_action,
                transfer_id=transfer_id,
                details={
                    "candidate_rvas": sorted(int(item["rva_start"]) for item in matches),
                    "raw_symbol_rvas": raw_rvas,
                    "symbol": symbol,
                },
            ))
            continue
        function = matches[0]
        candidate_span = (int(function["rva_start"]), int(function["rva_end"]))
        if not _validate_decoded_range(
            candidate_binary,
            candidate_span[0],
            candidate_span[1],
            side="candidate",
            transfer_id=transfer_id,
            issues=issues,
        ):
            continue
        candidate_rvas[candidate_span[0]].append(transfer_id)
        resolved.append((source_row, {
            "original_span": original_span,
            "candidate_span": candidate_span,
            "function": function,
        }))

    duplicate_candidate_ids: set[str] = set()
    for rva, transfer_ids in sorted(candidate_rvas.items()):
        if len(transfer_ids) <= 1:
            continue
        identities = sorted(transfer_ids)
        duplicate_candidate_ids.update(identities)
        issues.append(_issue(
            "duplicate_candidate_rva",
            "multiple transfers resolve to the same candidate RVA",
            "give each generated transfer a distinct linker-visible function symbol",
            details={"rva": rva, "transfer_ids": identities},
        ))

    for source_row, resolution in resolved:
        if source_row["id"] in duplicate_candidate_ids:
            continue
        original_start, original_end = resolution["original_span"]
        candidate_start, candidate_end = resolution["candidate_span"]
        function = resolution["function"]
        blocks.append({
            "id": source_row["id"],
            "kind": "code",
            "reachable": original_start == original_binary.entrypoint_rva,
            "original": {"rva": original_start, "size": original_end - original_start},
            "candidate": {"rva": candidate_start, "size": candidate_end - candidate_start},
            "invariant": {
                "checked": False,
                "kind": "untrusted_semantic_c_mapping_proposal",
            },
            "source": {
                "kind": SEMANTIC_C_MAPPING_PROPOSAL_FORMAT,
                "transfer_id": source_row["id"],
                "contract_sha256": source_row["contract_sha256"],
                "candidate_symbol": source_row["symbol"],
                "candidate_symbol_aliases": sorted(str(value) for value in function["aliases"]),
                "source_map_sha256": source_map_sha256,
                "implementation_sha256": implementation_sha256,
                "candidate_linker_map_sha256": candidate_map_sha256,
                "proof_authority": False,
            },
        })

    overlap_ids = _overlapping_range_ids(blocks, issues)
    if overlap_ids:
        blocks = [block for block in blocks if block["id"] not in overlap_ids]
    blocks.sort(key=lambda block: (
        int(block["original"]["rva"]),
        str(block["id"]),
        int(block["candidate"]["rva"]),
    ))
    issues = _canonical_issues(issues)
    issue_counts = Counter(str(issue["category"]) for issue in issues)
    ready = len(blocks) == len(parsed_sources) and not issues
    runtime_binding_sha256 = (
        _hash_input(runtime_binding_path, "native runtime binding")
        if runtime_binding_path is not None
        else None
    )
    return {
        "format": STAGE_A_BLOCK_MAP_FORMAT,
        "proposal_format": SEMANTIC_C_MAPPING_PROPOSAL_FORMAT,
        "generator": "build-semantic-c-mapping-proposal",
        "status": "ready" if ready else "incomplete",
        "acceptance_authority": False,
        "trust": {
            "acceptance_authority": False,
            "equivalence_claimed": False,
            "linker_map_trusted": False,
            "requires_ordinary_lean_checker": True,
            "source_map_trusted": False,
        },
        "inputs": {
            "original": {"sha256": original_binary.sha256},
            "candidate": {"sha256": candidate_binary.sha256},
            "source_map": {"sha256": source_map_sha256},
            "implementation": {"sha256": implementation_sha256},
            "runtime_binding": (
                {"sha256": runtime_binding_sha256}
                if runtime_binding_sha256 is not None
                else None
            ),
            "candidate_linker_map": {"sha256": candidate_map_sha256},
        },
        "blocks": blocks,
        "waivers": [],
        "issues": issues,
        "counts": {
            "source_transfers": len(source_rows),
            "valid_source_transfers": len(parsed_sources),
            "mapped_transfers": len(blocks),
            "issues": len(issues),
            "issues_by_category": dict(sorted(issue_counts.items())),
        },
        "acceptance": (
            "untrusted mapping hint only; construct the ordinary relation contract "
            "and replay the ordinary Lean checker before any equivalence verdict"
        ),
    }


def write_semantic_c_mapping_proposal(
    *,
    original: Path,
    candidate: Path,
    source_map: Path,
    candidate_linker_map: Path,
    out: Path,
    implementation: Path | None = None,
    implementation_manifest: Path | None = None,
    runtime_binding: Path | None = None,
) -> dict[str, Any]:
    proposal = build_semantic_c_mapping_proposal(
        original=original,
        candidate=candidate,
        source_map=source_map,
        implementation=implementation,
        implementation_manifest=implementation_manifest,
        runtime_binding=runtime_binding,
        candidate_linker_map=candidate_linker_map,
    )
    write_json(Path(out), proposal)
    return proposal


def _runtime_binding_closes_strict_candidate(
    implementation: Mapping[str, Any],
    strict_candidate: object,
    runtime_binding: Mapping[str, Any] | None,
) -> bool:
    """Recognize the later native-binding phase without granting proof authority.

    Semantic C is intentionally emitted before a native call owner exists.  A
    ready, content-bound native binding may close exactly that one generation
    blocker.  All other implementation blockers remain visible.
    """

    if not isinstance(strict_candidate, Mapping):
        return False
    blockers = strict_candidate.get("blockers")
    if blockers != ["runtime_call_adapters_unbound"]:
        return False
    if not isinstance(runtime_binding, Mapping):
        return False
    if (
        runtime_binding.get("format") != "stage-b-native-runtime-binding-v1"
        or runtime_binding.get("status") != "ready"
        or runtime_binding.get("acceptance_authority") is not False
        or runtime_binding.get("blockers") != []
    ):
        return False

    counts = runtime_binding.get("counts")
    sources = runtime_binding.get("sources")
    state_machine = implementation.get("state_machine")
    artifacts = implementation.get("artifacts")
    if not all(isinstance(value, Mapping) for value in (
        counts, sources, state_machine, artifacts
    )):
        return False
    native_obligations = counts.get("native_obligations")
    native_sites = counts.get("native_sites")
    return (
        isinstance(native_obligations, int)
        and not isinstance(native_obligations, bool)
        and native_obligations >= 0
        and counts.get("bound_native_sites") == native_obligations
        and counts.get("unbound_native_obligations") == 0
        and native_sites == native_obligations
        and counts.get("blockers") == 0
        and isinstance(sources.get("state_machine"), Mapping)
        and sources["state_machine"].get("sha256")
        == state_machine.get("sha256")
        and isinstance(sources.get("runtime_call_obligations"), Mapping)
        and isinstance(artifacts.get("runtime_obligations"), Mapping)
        and sources["runtime_call_obligations"].get("sha256")
        == artifacts["runtime_obligations"].get("sha256")
    )


def _select_implementation_path(
    *, implementation: Path | None, implementation_manifest: Path | None
) -> Path:
    if implementation is None and implementation_manifest is None:
        raise StageAInputError("semantic-C implementation manifest is required")
    if implementation is not None and implementation_manifest is not None:
        if Path(implementation).resolve() != Path(implementation_manifest).resolve():
            raise StageAInputError(
                "implementation and implementation_manifest name different files"
            )
    return Path(
        implementation if implementation is not None else implementation_manifest
    )


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError(f"{label} must contain a JSON object")
    return payload


def _hash_input(path: Path, label: str) -> str:
    try:
        return sha256_file(Path(path))
    except OSError as exc:
        raise StageAInputError(f"cannot read {label} {path}: {exc}") from exc


def _source_map_binding(payload: Mapping[str, Any]) -> str | None:
    artifacts = payload.get("artifacts")
    source = artifacts.get("source_map") if isinstance(artifacts, Mapping) else None
    digest = source.get("sha256") if isinstance(source, Mapping) else None
    return str(digest) if isinstance(digest, str) and _SHA256_RE.fullmatch(digest) else None


def _parse_source_rows(
    rows: list[Any], issues: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], set[str]]:
    parsed: list[dict[str, Any]] = []
    invalid_ids: set[str] = set()
    by_id: dict[str, list[int]] = defaultdict(list)
    for index, raw in enumerate(rows):
        context_id = f"source-row-{index}"
        if not isinstance(raw, Mapping):
            issues.append(_issue(
                "malformed_source_transfer",
                "a source-map transfer row is not an object",
                "regenerate the semantic-C source map",
                transfer_id=context_id,
            ))
            continue
        transfer_id = raw.get("id")
        if not isinstance(transfer_id, str) or not transfer_id:
            issues.append(_issue(
                "malformed_source_transfer",
                "a source-map transfer has no nonempty string id",
                "regenerate the source map with stable transfer identities",
                transfer_id=context_id,
            ))
            continue
        by_id[transfer_id].append(index)
        digest = raw.get("contract_sha256")
        symbol = raw.get("symbol")
        rva = raw.get("rva_start")
        valid = True
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            issues.append(_issue(
                "invalid_contract_hash",
                "the source-map transfer contract_sha256 is not a canonical SHA-256",
                "regenerate the source map from the canonical transfer contract",
                transfer_id=transfer_id,
            ))
            valid = False
        if not isinstance(symbol, str) or not symbol:
            issues.append(_issue(
                "missing_candidate_symbol",
                "the source-map transfer has no candidate implementation symbol",
                "regenerate the semantic-C source map with linker-visible symbols",
                transfer_id=transfer_id,
            ))
            valid = False
        if not _is_integer(rva) or int(rva) < 0:
            issues.append(_issue(
                "invalid_original_rva",
                "the source-map transfer rva_start is not a nonnegative integer",
                "regenerate the source map from a bounded original transfer",
                transfer_id=transfer_id,
            ))
            valid = False
        blockers = raw.get("blockers")
        if isinstance(blockers, list) and blockers:
            issues.append(_issue(
                "source_transfer_incomplete",
                "the source-map transfer still names semantic-C implementation blockers",
                "resolve the transfer blockers before proposing a candidate mapping",
                transfer_id=transfer_id,
                details={"blockers": sorted(str(value) for value in blockers)},
            ))
            valid = False
        if not valid:
            invalid_ids.add(transfer_id)
            continue
        parsed.append({
            "id": transfer_id,
            "contract_sha256": digest,
            "symbol": symbol,
            "rva_start": int(rva),
            "implementation": raw.get("implementation"),
            "raw": raw,
        })
    for transfer_id, indexes in sorted(by_id.items()):
        if len(indexes) > 1:
            invalid_ids.add(transfer_id)
            issues.append(_issue(
                "duplicate_transfer_id",
                "the source map contains a duplicate transfer id",
                "emit each semantic transfer exactly once",
                transfer_id=transfer_id,
                details={"row_indexes": indexes},
            ))
    return parsed, invalid_ids


def _index_implementation_rows(
    rows: list[Any], issues: list[dict[str, Any]]
) -> tuple[dict[str, list[Mapping[str, Any]]], set[str]]:
    indexed: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            issues.append(_issue(
                "malformed_implementation_transfer",
                "an implementation transfer row is not an object",
                "regenerate the semantic-C implementation manifest",
                transfer_id=f"implementation-row-{index}",
            ))
            continue
        transfer_id = raw.get("id")
        if not isinstance(transfer_id, str) or not transfer_id:
            issues.append(_issue(
                "malformed_implementation_transfer",
                "an implementation transfer row has no nonempty string id",
                "regenerate the implementation manifest with stable transfer identities",
                transfer_id=f"implementation-row-{index}",
            ))
            continue
        indexed[transfer_id].append(raw)
    duplicates: set[str] = set()
    for transfer_id, matches in sorted(indexed.items()):
        if len(matches) > 1:
            duplicates.add(transfer_id)
            issues.append(_issue(
                "duplicate_implementation_transfer",
                "the implementation manifest contains a duplicate transfer id",
                "emit each semantic-C implementation exactly once",
                transfer_id=transfer_id,
                details={"count": len(matches)},
            ))
    return dict(indexed), duplicates


def _mark_duplicate_source_fields(
    rows: list[dict[str, Any]],
    invalid_ids: set[str],
    issues: list[dict[str, Any]],
) -> None:
    for field, category, blocker, next_action in (
        (
            "rva_start",
            "duplicate_original_rva",
            "multiple source-map transfers use the same original RVA",
            "deduplicate the Stage A transfer inventory before semantic-C generation",
        ),
        (
            "symbol",
            "duplicate_candidate_symbol_binding",
            "multiple source-map transfers name the same candidate symbol",
            "generate a unique semantic-C function symbol for each transfer",
        ),
    ):
        grouped: dict[Any, list[str]] = defaultdict(list)
        for row in rows:
            grouped[row[field]].append(row["id"])
        for value, transfer_ids in sorted(grouped.items(), key=lambda item: str(item[0])):
            if len(transfer_ids) <= 1:
                continue
            identities = sorted(transfer_ids)
            invalid_ids.update(identities)
            issues.append(_issue(
                category,
                blocker,
                next_action,
                details={field: value, "transfer_ids": identities},
            ))


def _validate_transfer_binding(
    source: Mapping[str, Any],
    implementation: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> bool:
    transfer_id = str(source["id"])
    valid = True
    implementation_hash = implementation.get("contract_sha256")
    if not isinstance(implementation_hash, str) or not _SHA256_RE.fullmatch(implementation_hash):
        issues.append(_issue(
            "invalid_contract_hash",
            "the implementation transfer contract_sha256 is not a canonical SHA-256",
            "regenerate the implementation manifest from the canonical transfer contract",
            transfer_id=transfer_id,
        ))
        valid = False
    elif implementation_hash != source["contract_sha256"]:
        issues.append(_issue(
            "contract_hash_mismatch",
            "the source-map and implementation transfer hashes differ",
            "use source-map and implementation files generated from the same transfer contracts",
            transfer_id=transfer_id,
            details={
                "implementation": implementation_hash,
                "source_map": source["contract_sha256"],
            },
        ))
        valid = False
    for field, category in (
        ("rva_start", "original_rva_mismatch"),
        ("symbol", "candidate_symbol_binding_mismatch"),
        ("implementation", "implementation_kind_mismatch"),
    ):
        if implementation.get(field) != source.get(field):
            issues.append(_issue(
                category,
                f"the source-map and implementation transfer {field} values differ",
                "regenerate both semantic-C manifests from the same backend invocation",
                transfer_id=transfer_id,
                details={
                    "implementation": implementation.get(field),
                    "source_map": source.get(field),
                },
            ))
            valid = False
    return valid


def _resolve_original_span(
    source: Mapping[str, Any],
    implementation: Mapping[str, Any],
    *,
    binary: StageABinary,
    known_starts: list[int],
    issues: list[dict[str, Any]],
) -> tuple[int, int] | None:
    transfer_id = str(source["id"])
    start = int(source["rva_start"])
    declared: list[tuple[int, int]] = []
    for raw in (source.get("raw"), implementation):
        span = _declared_span(raw, fallback_start=start)
        if span is not None:
            declared.append(span)
    if declared:
        if len(set(declared)) != 1 or declared[0][0] != start:
            issues.append(_issue(
                "original_span_mismatch",
                "the semantic-C manifests disagree about the original transfer span",
                "regenerate both manifests from the same bounded transfer contract",
                transfer_id=transfer_id,
                details={"declared_spans": [list(value) for value in sorted(set(declared))]},
            ))
            return None
        return declared[0]

    section = _section_containing(binary, start)
    if section is None or not section.executable:
        issues.append(_issue(
            "original_range_not_executable",
            "the transfer start does not lie in an executable original PE section",
            "fix the source-map RVA or regenerate it from the exact original PE",
            transfer_id=transfer_id,
            details={"rva_start": start},
        ))
        return None
    next_index = bisect_right(known_starts, start)
    next_start = (
        known_starts[next_index]
        if next_index < len(known_starts)
        and known_starts[next_index] <= section.rva_end
        else None
    )
    limit = next_start if next_start is not None else section.rva_end
    end = _infer_basic_block_end(binary, start, limit)
    if end is None:
        issues.append(_issue(
            "original_span_unresolved",
            "the source map omits the transfer end and no exact basic-block end can be decoded",
            "include rva_end or size for this transfer in state-machine-source-map.json",
            transfer_id=transfer_id,
            details={"decode_limit": limit, "rva_start": start},
        ))
        return None
    return start, end


def _declared_span(
    raw: Any, *, fallback_start: int
) -> tuple[int, int] | None:
    if not isinstance(raw, Mapping):
        return None
    nested = raw.get("original")
    candidates = [nested, raw] if isinstance(nested, Mapping) else [raw]
    for candidate in candidates:
        start_value = candidate.get("rva_start", candidate.get("rva", fallback_start))
        if not _is_integer(start_value):
            continue
        start = int(start_value)
        end_value = candidate.get("rva_end")
        if _is_integer(end_value):
            return start, int(end_value)
        size_value = candidate.get("size")
        if _is_integer(size_value):
            return start, start + int(size_value)
    return None


def _infer_basic_block_end(
    binary: StageABinary, start: int, limit: int
) -> int | None:
    if limit <= start:
        return None
    disassembler = capstone.Cs(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64 if binary.bitness == 64 else capstone.CS_MODE_32,
    )
    disassembler.detail = True
    cursor = start
    while cursor < limit:
        data = binary.pe.get_data(cursor, min(15, limit - cursor))
        decoded = list(disassembler.disasm(data, binary.image_base + cursor, count=1))
        if not decoded:
            return None
        instruction = decoded[0]
        instruction_start = int(instruction.address) - binary.image_base
        instruction_end = instruction_start + int(instruction.size)
        if instruction_start != cursor or instruction_end > limit:
            return None
        cursor = instruction_end
        if _ends_basic_block(instruction):
            return cursor
    return limit if cursor == limit and limit < _section_end(binary, start) else None


def _ends_basic_block(instruction: Any) -> bool:
    groups = {
        capstone.CS_GRP_CALL,
        capstone.CS_GRP_JUMP,
        capstone.CS_GRP_RET,
    }
    iret = getattr(capstone, "CS_GRP_IRET", None)
    if iret is not None:
        groups.add(iret)
    return any(instruction.group(group) for group in groups)


def _functions_by_symbol(
    functions: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for function in functions:
        names = [function.get("name"), *function.get("aliases", [])]
        for key in sorted({_symbol_key(str(name)) for name in names if name}):
            if function not in indexed[key]:
                indexed[key].append(function)
    for matches in indexed.values():
        matches.sort(key=lambda value: (
            int(value["rva_start"]), int(value["rva_end"]), str(value["name"])
        ))
    return dict(indexed)


def _raw_symbol_rvas(path: Path, binary: StageABinary) -> dict[str, set[int]]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise StageAInputError(f"cannot read linker map {path}: {exc}") from exc
    result: dict[str, set[int]] = defaultdict(set)
    for line in text.splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is not None:
            rva, name = parsed
            result[_symbol_key(name)].add(int(rva))
    return dict(result)


def _symbol_key(name: str) -> str:
    return _linker_function_match_key(name)


def _validate_decoded_range(
    binary: StageABinary,
    start: int,
    end: int,
    *,
    side: str,
    transfer_id: str,
    issues: list[dict[str, Any]],
) -> bool:
    if start < 0 or end <= start or end > binary.size_of_image:
        issues.append(_issue(
            f"{side}_range_out_of_bounds",
            f"the {side} transfer range is empty, inverted, or outside the PE image",
            f"fix the {side} range so it is wholly contained in the exact PE image",
            transfer_id=transfer_id,
            details={"rva_end": end, "rva_start": start, "size_of_image": binary.size_of_image},
        ))
        return False
    section = _executable_range(binary, start, end)
    if section is None:
        issues.append(_issue(
            f"{side}_range_not_executable",
            f"the {side} transfer range is not wholly contained in one executable section",
            f"fix the {side} mapping range or candidate linker-map boundaries",
            transfer_id=transfer_id,
            details={"rva_end": end, "rva_start": start},
        ))
        return False
    data = binary.pe.get_data(start, end - start)
    if len(data) != end - start:
        issues.append(_issue(
            f"{side}_range_not_mapped",
            f"the {side} executable range is not fully mapped by the PE image",
            f"restrict the {side} range to raw-backed mapped bytes",
            transfer_id=transfer_id,
            details={"mapped_bytes": len(data), "range_size": end - start},
        ))
        return False
    disassembler = capstone.Cs(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64 if binary.bitness == 64 else capstone.CS_MODE_32,
    )
    decoded = list(disassembler.disasm(data, binary.image_base + start))
    decoded_bytes = sum(int(instruction.size) for instruction in decoded)
    if not decoded or decoded_bytes != len(data):
        issues.append(_issue(
            f"{side}_range_decode_incomplete",
            f"the {side} executable range does not decode exactly",
            f"tighten the {side} range to complete instruction boundaries",
            transfer_id=transfer_id,
            details={"decoded_bytes": decoded_bytes, "range_size": len(data)},
        ))
        return False
    return True


def _section_containing(binary: StageABinary, rva: int) -> Any | None:
    return next(
        (section for section in binary.sections if section.rva_start <= rva < section.rva_end),
        None,
    )


def _section_end(binary: StageABinary, rva: int) -> int:
    section = _section_containing(binary, rva)
    return int(section.rva_end) if section is not None else rva


def _executable_range(binary: StageABinary, start: int, end: int) -> Any | None:
    return next(
        (
            section
            for section in binary.sections
            if section.executable and section.rva_start <= start and end <= section.rva_end
        ),
        None,
    )


def _overlapping_range_ids(
    blocks: list[dict[str, Any]], issues: list[dict[str, Any]]
) -> set[str]:
    invalid: set[str] = set()
    for side in ("original", "candidate"):
        ordered = sorted(
            blocks,
            key=lambda block: (
                int(block[side]["rva"]),
                int(block[side]["size"]),
                str(block["id"]),
            ),
        )
        for left_index, left in enumerate(ordered):
            left_end = int(left[side]["rva"]) + int(left[side]["size"])
            for right in ordered[left_index + 1:]:
                if left_end <= int(right[side]["rva"]):
                    break
                identities = sorted((str(left["id"]), str(right["id"])))
                invalid.update(identities)
                issues.append(_issue(
                    f"overlapping_{side}_ranges",
                    f"resolved {side} transfer ranges overlap",
                    f"provide disjoint exact {side} transfer boundaries",
                    details={"transfer_ids": identities},
                ))
    return invalid


def _issue(
    category: str,
    blocker: str,
    next_action: str,
    *,
    transfer_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    identity = transfer_id or "inventory"
    issue = {
        "category": category,
        "obligation_id": f"semantic-c-mapping:{_safe_id(identity)}:{category}",
        "status": "incomplete",
        "blocker": blocker,
        "next_action": next_action,
    }
    if transfer_id is not None:
        issue["transfer_id"] = transfer_id
    if details:
        issue["details"] = dict(details)
    return issue


def _canonical_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for issue in issues:
        key = json.dumps(issue, sort_keys=True, separators=(",", ":"))
        unique[key] = issue
    return sorted(
        unique.values(),
        key=lambda issue: (
            str(issue["obligation_id"]),
            str(issue["category"]),
            json.dumps(issue.get("details", {}), sort_keys=True, separators=(",", ":")),
        ),
    )


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "inventory"


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


__all__ = [
    "SEMANTIC_C_MAPPING_PROPOSAL_FORMAT",
    "STAGE_A_BLOCK_MAP_FORMAT",
    "build_semantic_c_mapping_proposal",
    "write_semantic_c_mapping_proposal",
]
