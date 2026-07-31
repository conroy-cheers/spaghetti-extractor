from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..contract_tools import (
    BlockSide,
    _linker_function_import_thunk_evidence,
    _linker_function_issues,
    _parse_linker_map_functions,
    _recover_basic_blocks,
    _section_gap_code_blocks,
    _section_gaps,
)
from ..stage_binary import StageAInputError, _parse_stage_a_pe
from ..util import sha256_bytes, sha256_file, write_json
from .contract import (
    _raw_base_relocations,
)
from .semantic_cutpoints import (
    decode_semantic_cutpoint_span,
    semantic_cutpoint_spans_for_side,
)
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID
from .side_extraction_artifact import parse_request


BINARY_CUTPOINT_INVENTORY_FORMAT = "stage-a-binary-cutpoint-inventory-v1"
_SIDES = {"original", "candidate"}
_NO_LINKER_MAP_SHA256 = sha256_bytes(b"")


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    )


def _issue(category: str, blocker: str, **details: Any) -> dict[str, Any]:
    identity = {"category": category, "blocker": blocker, "details": details}
    return {
        "id": "binary-inventory-" + _canonical_sha256(identity)[:20],
        "category": category,
        "severity": "hard",
        "status": "incomplete",
        "blocker": blocker,
        "details": details,
    }


def _span_key(row: Mapping[str, Any]) -> tuple[int, int]:
    span = row["span"]
    return int(span["rva_start"]), int(span["rva_start"]) + int(span["size"])


def _immutable_relocation_instruction_starts(parsed: Any) -> set[int]:
    relocation_counts = Counter(
        int(relocation["rva"])
        for relocation in _raw_base_relocations(parsed)
        if int(relocation["type"]) == 3
    )
    starts: set[int] = set()
    for relocation_rva, count in relocation_counts.items():
        if count != 1 or not any(
            not section.writable
            and section.rva_start <= relocation_rva
            and relocation_rva + 4 <= section.rva_end
            for section in parsed.sections
        ):
            continue
        if any(
            imported.thunk_rva is not None
            and relocation_rva < int(imported.thunk_rva) + 4
            and int(imported.thunk_rva) < relocation_rva + 4
            for imported in parsed.imports
        ):
            continue
        data = parsed.pe.get_data(relocation_rva, 4)
        if len(data) != 4:
            continue
        target_rva = int.from_bytes(data, "little") - parsed.image_base
        if any(
            section.executable
            and section.rva_start <= target_rva < section.rva_end
            for section in parsed.sections
        ):
            starts.add(target_rva)
    return starts


def _relocation_split_spans(
    parsed: Any,
    span: dict[str, int],
    relocation_starts: set[int],
    block_id: str,
) -> list[dict[str, int]]:
    decoded = decode_semantic_cutpoint_span(parsed, span, block_id)
    instruction_starts = {
        int(instruction.address) - parsed.image_base for instruction in decoded
    }
    boundaries = [
        int(span["rva_start"]),
        *sorted(
            relocation_starts.intersection(instruction_starts)
            - {int(span["rva_start"])}
        ),
        int(span["rva_start"]) + int(span["size"]),
    ]
    return [
        {
            "rva_start": boundaries[index],
            "size": boundaries[index + 1] - boundaries[index],
        }
        for index in range(len(boundaries) - 1)
    ]


def _validate_coverage(payload: Mapping[str, Any]) -> None:
    regions = payload.get("regions")
    waivers = payload.get("padding_waivers")
    sections = payload.get("executable_sections")
    if not isinstance(regions, list) or not isinstance(waivers, list):
        raise StageAInputError("binary cutpoint coverage inventory is malformed")
    if not isinstance(sections, list):
        raise StageAInputError("binary cutpoint executable sections are malformed")
    if not sections and payload.get("status") == "pass":
        raise StageAInputError(
            "passing binary cutpoint inventory has no executable sections"
        )
    previous_section_end: int | None = None
    for index, section in enumerate(sections):
        if not isinstance(section, Mapping) or set(section) != {
            "name",
            "rva_start",
            "rva_end",
        }:
            raise StageAInputError(
                f"binary executable section {index} is malformed"
            )
        name = section.get("name")
        start = section.get("rva_start")
        stop = section.get("rva_end")
        if (
            not isinstance(name, str)
            or not name
            or isinstance(start, bool)
            or not isinstance(start, int)
            or start < 0
            or isinstance(stop, bool)
            or not isinstance(stop, int)
            or stop <= start
            or stop > 2**32
        ):
            raise StageAInputError(
                f"binary executable section {index} is invalid"
            )
        if previous_section_end is not None and start < previous_section_end:
            raise StageAInputError("binary executable sections overlap or are unordered")
        previous_section_end = stop
    coverage: list[tuple[int, int, str]] = []
    for index, region in enumerate(regions):
        if not isinstance(region, Mapping):
            raise StageAInputError(f"binary cutpoint region {index} is malformed")
        start, stop = _span_key(region)
        coverage.append((start, stop, f"region:{index}"))
    waiver_ids: set[str] = set()
    for index, waiver in enumerate(waivers):
        if not isinstance(waiver, Mapping) or set(waiver) != {
            "binary",
            "id",
            "reason",
            "rva",
            "size",
        }:
            raise StageAInputError(f"binary padding waiver {index} is malformed")
        waiver_side = waiver.get("binary")
        identity = waiver.get("id")
        reason = waiver.get("reason")
        start = waiver.get("rva")
        size = waiver.get("size")
        if (
            waiver_side != payload.get("side")
            or not isinstance(identity, str)
            or not identity
            or identity in waiver_ids
            or not isinstance(reason, str)
            or not reason
            or isinstance(start, bool)
            or not isinstance(start, int)
            or start < 0
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or start + size > 2**32
        ):
            raise StageAInputError(f"binary padding waiver {index} is invalid")
        waiver_ids.add(identity)
        coverage.append((start, start + size, f"padding:{index}"))
    coverage.sort()
    for section in sections:
        if not isinstance(section, Mapping):
            raise StageAInputError("binary executable section row is malformed")
        start = int(section.get("rva_start", -1))
        stop = int(section.get("rva_end", -1))
        rows = [row for row in coverage if start <= row[0] and row[1] <= stop]
        cursor = start
        for row_start, row_stop, identity in rows:
            if row_start != cursor or row_stop <= row_start:
                raise StageAInputError(
                    f"binary executable coverage is not exact at {identity}"
                )
            cursor = row_stop
        if cursor != stop:
            raise StageAInputError(
                f"binary executable coverage stops at {cursor:#x}, expected {stop:#x}"
            )
    for start, stop, identity in coverage:
        if not any(
            int(section["rva_start"]) <= start < stop <= int(section["rva_end"])
            for section in sections
        ):
            raise StageAInputError(
                f"binary executable coverage escapes its sections at {identity}"
            )


def parse_binary_cutpoint_inventory(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise StageAInputError("binary cutpoint inventory must be an object")
    required = {
        "format",
        "profile",
        "model",
        "status",
        "side",
        "binary_sha256",
        "linker_map_sha256",
        "executable_sections",
        "regions",
        "extraction_regions",
        "padding_waivers",
        "issues",
        "counts",
    }
    if set(payload) != required:
        raise StageAInputError("binary cutpoint inventory fields are malformed")
    if payload.get("format") != BINARY_CUTPOINT_INVENTORY_FORMAT:
        raise StageAInputError("unsupported binary cutpoint inventory format")
    if payload.get("profile") != STAGE_A_RELATIONAL_PROFILE_ID:
        raise StageAInputError("binary cutpoint inventory profile mismatch")
    if payload.get("model") != STAGE_A_RELATIONAL_MODEL_ID:
        raise StageAInputError("binary cutpoint inventory model mismatch")
    side = payload.get("side")
    if side not in _SIDES:
        raise StageAInputError("binary cutpoint inventory side is invalid")
    for field in ("binary_sha256", "linker_map_sha256"):
        value = payload.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise StageAInputError(f"binary cutpoint inventory {field} is invalid")
    issues = payload.get("issues")
    if not isinstance(issues, list) or any(
        not isinstance(issue, Mapping) for issue in issues
    ):
        raise StageAInputError("binary cutpoint inventory issues are malformed")
    expected_status = "pass" if not issues else "incomplete"
    if payload.get("status") != expected_status:
        raise StageAInputError("binary cutpoint inventory status is inconsistent")
    def validate_regions(field: str, *, allow_overlap: bool) -> list[Any]:
        regions = payload.get(field)
        if not isinstance(regions, list):
            raise StageAInputError(
                f"binary cutpoint inventory {field} must be a list"
            )
        seen_ids: set[str] = set()
        seen_spans: set[tuple[int, int]] = set()
        previous_start: int | None = None
        previous_stop: int | None = None
        for index, region in enumerate(regions):
            if not isinstance(region, Mapping) or set(region) != {
                "index",
                "id",
                "numeric_id",
                "span",
                "source",
            }:
                raise StageAInputError(
                    f"binary cutpoint {field} region {index} is malformed"
                )
            if region.get("index") != index or region.get("numeric_id") != index:
                raise StageAInputError(
                    f"binary cutpoint {field} region indices are not canonical"
                )
            identity = region.get("id")
            if not isinstance(identity, str) or not identity or identity in seen_ids:
                raise StageAInputError(
                    f"binary cutpoint {field} region ids are invalid"
                )
            seen_ids.add(identity)
            span = region.get("span")
            if not isinstance(span, Mapping) or set(span) != {"rva_start", "size"}:
                raise StageAInputError(
                    f"binary cutpoint {field} region {index} span is malformed"
                )
            start = span.get("rva_start")
            size = span.get("size")
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or start < 0
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size <= 0
            ):
                raise StageAInputError(
                    f"binary cutpoint {field} region {index} span is invalid"
                )
            stop = start + size
            if stop > 2**32:
                raise StageAInputError(
                    f"binary cutpoint {field} region {index} span is invalid"
                )
            span_key = (start, size)
            if span_key in seen_spans:
                raise StageAInputError(
                    f"binary cutpoint {field} contains duplicate spans"
                )
            seen_spans.add(span_key)
            if previous_start is not None and start < previous_start:
                raise StageAInputError(
                    f"binary cutpoint {field} regions are not ordered"
                )
            if not allow_overlap and previous_stop is not None and start < previous_stop:
                raise StageAInputError(f"binary cutpoint {field} regions overlap")
            previous_start = start
            previous_stop = stop
            if not isinstance(region.get("source"), Mapping):
                raise StageAInputError(
                    f"binary cutpoint {field} region {index} source is malformed"
                )
        return regions

    regions = validate_regions("regions", allow_overlap=False)
    extraction_regions = validate_regions(
        "extraction_regions", allow_overlap=True
    )
    _validate_coverage(payload)
    executable_sections = payload["executable_sections"]
    for extraction in extraction_regions:
        start, stop = _span_key(extraction)
        if not any(
            int(section["rva_start"]) <= start < stop <= int(section["rva_end"])
            for section in executable_sections
        ):
            raise StageAInputError(
                "binary extraction region escapes its executable sections"
            )
    for region in regions:
        if not any(
            extraction["span"] == region["span"]
            for extraction in extraction_regions
        ):
            raise StageAInputError(
                "binary extraction regions omit a coverage cutpoint"
            )
    counts = payload.get("counts")
    expected_counts = {
        "regions": len(regions),
        "extraction_regions": len(extraction_regions),
        "padding_waivers": len(payload["padding_waivers"]),
        "issues": len(issues),
    }
    if not isinstance(counts, Mapping) or set(counts) != set(expected_counts) or any(
        counts.get(field) != value for field, value in expected_counts.items()
    ):
        raise StageAInputError("binary cutpoint inventory counts are inconsistent")
    return dict(payload)


def _deduplicate_code_spans(
    rows: list[dict[str, Any]], issues: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    unique: dict[tuple[int, int], dict[str, Any]] = {}
    for row in rows:
        key = _span_key(row)
        unique.setdefault(key, row)
    ordered = sorted(unique.values(), key=_span_key)
    accepted: list[dict[str, Any]] = []
    for row in ordered:
        start, stop = _span_key(row)
        if accepted and start < _span_key(accepted[-1])[1]:
            issues.append(
                _issue(
                    "overlapping_executable_ranges",
                    "side-local recovered executable spans overlap",
                    previous=_span_key(accepted[-1]),
                    observed=(start, stop),
                )
            )
            continue
        accepted.append(row)
    return accepted


def stage_a_inventory_binary(
    *,
    binary: Path,
    linker_map: Path | None = None,
    side: str,
    out: Path,
) -> dict[str, Any]:
    if side not in _SIDES:
        raise StageAInputError("binary cutpoint inventory side is invalid")
    binary = Path(binary)
    parsed = _parse_stage_a_pe(binary)
    linker_map = Path(linker_map) if linker_map is not None else None
    functions = (
        _parse_linker_map_functions(linker_map, parsed)
        if linker_map is not None
        else []
    )
    issues = (
        list(_linker_function_issues(side, functions))
        if linker_map is not None
        else []
    )
    raw_rows: list[dict[str, Any]] = []
    for function in sorted(
        functions, key=lambda row: (int(row["rva_start"]), str(row["name"]))
    ):
        name = str(function["name"])
        thunk = _linker_function_import_thunk_evidence(parsed, function)
        if thunk is not None:
            thunk_block: BlockSide = thunk["block"]
            raw_rows.append({
                "span": {
                    "rva_start": thunk_block.rva_start,
                    "size": thunk_block.size,
                },
                "source": {"kind": "import_thunk", "function": name},
            })
            continue
        recovered = _recover_basic_blocks(
            parsed, int(function["rva_start"]), int(function["rva_end"])
        )
        if not recovered:
            issues.append(
                _issue(
                    "unrecovered_linker_function",
                    "linker-map function produced no basic blocks",
                    function=name,
                )
            )
        for block_index, block in enumerate(recovered):
            raw_rows.append({
                "span": {
                    "rva_start": int(block["rva_start"]),
                    "size": int(block["rva_end"]) - int(block["rva_start"]),
                },
                "source": {
                    "kind": "linker_map_basic_block",
                    "function": name,
                    "block_index": block_index,
                },
            })
    raw_rows = _deduplicate_code_spans(raw_rows, issues)
    ranges = [BlockSide(*_span_key(row)) for row in raw_rows]
    padding_waivers: list[dict[str, Any]] = []
    for section, gaps in sorted(_section_gaps(parsed, ranges).items()):
        gap_blocks, waivers = _section_gap_code_blocks(side, parsed, gaps)
        padding_waivers.extend(waivers)
        for row in gap_blocks:
            block = row["block"]
            raw_rows.append({
                "span": {"rva_start": block.rva_start, "size": block.size},
                "source": {
                    "kind": (
                        "executable_section_gap_block"
                        if linker_map is not None
                        else "static_executable_section_block"
                    ),
                    "section": section,
                    "gap_index": row["gap_index"],
                    "gap_block_index": row["gap_block_index"],
                },
            })
    raw_rows = _deduplicate_code_spans(raw_rows, issues)

    relocation_starts = _immutable_relocation_instruction_starts(parsed)
    cutpoints: list[dict[str, Any]] = []
    extraction_cutpoints: dict[tuple[int, int], dict[str, Any]] = {}
    for row in raw_rows:
        start, stop = _span_key(row)
        try:
            periodic_spans = semantic_cutpoint_spans_for_side(
                parsed,
                {"rva_start": start, "rva_end": stop, "size": stop - start},
                f"{side}-{start:x}-{stop:x}",
                periodic=True,
            )
            semantic_spans = semantic_cutpoint_spans_for_side(
                parsed,
                {"rva_start": start, "rva_end": stop, "size": stop - start},
                f"{side}-{start:x}-{stop:x}",
                periodic=False,
            )
        except StageAInputError as exc:
            issues.append(
                _issue(
                    "semantic_cutpoint_decode_failed",
                    str(exc),
                    rva_start=start,
                    rva_end=stop,
                )
            )
            continue
        for policy, spans in (
            ("periodic_and_semantic", periodic_spans),
            ("semantic_only", semantic_spans),
        ):
            for cutpoint_index, span in enumerate(spans):
                cutpoint = {
                    "span": {
                        "rva_start": span["rva_start"],
                        "size": span["size"],
                    },
                    "source": {
                        **row["source"],
                        "cutpoint_index": cutpoint_index,
                        "cutpoint_policy": policy,
                    },
                }
                extraction_cutpoints.setdefault(_span_key(cutpoint), cutpoint)
                if policy == "periodic_and_semantic":
                    cutpoints.append(cutpoint)
                relocation_spans = _relocation_split_spans(
                    parsed,
                    span,
                    relocation_starts,
                    f"{side}-{span['rva_start']:x}-relocation-split",
                )
                if len(relocation_spans) <= 1:
                    continue
                for relocation_index, relocation_span in enumerate(
                    relocation_spans
                ):
                    relocation_cutpoint = {
                        "span": relocation_span,
                        "source": {
                            **row["source"],
                            "cutpoint_index": relocation_index,
                            "cutpoint_policy": (
                                f"{policy}_immutable_relocation_internal"
                            ),
                        },
                    }
                    extraction_cutpoints.setdefault(
                        _span_key(relocation_cutpoint), relocation_cutpoint
                    )
    cutpoints.sort(key=_span_key)
    extraction_rows = sorted(extraction_cutpoints.values(), key=_span_key)

    def inventory_regions(
        rows: list[dict[str, Any]], identity: str
    ) -> list[dict[str, Any]]:
        result = []
        for index, row in enumerate(rows):
            start, stop = _span_key(row)
            result.append({
                "index": index,
                "id": f"{side}-{identity}-{start:08x}-{stop:08x}",
                "numeric_id": index,
                "span": {"rva_start": start, "size": stop - start},
                "source": row["source"],
            })
        return result

    regions = inventory_regions(cutpoints, "cutpoint")
    extraction_regions = inventory_regions(extraction_rows, "extraction")
    padding_waivers.sort(key=lambda row: (int(row["rva"]), int(row["size"])))
    executable_sections = [
        {
            "name": section.name,
            "rva_start": section.rva_start,
            "rva_end": section.rva_end,
        }
        for section in parsed.sections
        if section.executable
    ]
    payload = {
        "format": BINARY_CUTPOINT_INVENTORY_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "pass" if not issues else "incomplete",
        "side": side,
        "binary_sha256": parsed.sha256,
        "linker_map_sha256": (
            sha256_file(linker_map)
            if linker_map is not None
            else _NO_LINKER_MAP_SHA256
        ),
        "executable_sections": executable_sections,
        "regions": regions,
        "extraction_regions": extraction_regions,
        "padding_waivers": padding_waivers,
        "issues": issues,
        "counts": {
            "regions": len(regions),
            "extraction_regions": len(extraction_regions),
            "padding_waivers": len(padding_waivers),
            "issues": len(issues),
        },
    }
    if not issues:
        try:
            parse_binary_cutpoint_inventory(payload)
        except StageAInputError as exc:
            payload["issues"].append(
                _issue("executable_coverage_incomplete", str(exc))
            )
            payload["status"] = "incomplete"
            payload["counts"]["issues"] = len(payload["issues"])
    write_json(Path(out), payload)
    return payload


def side_extraction_request_from_inventory(
    payload: Any, *, scope: str = "base"
) -> dict[str, Any]:
    inventory = parse_binary_cutpoint_inventory(payload)
    if inventory["status"] != "pass":
        raise StageAInputError("incomplete binary inventory cannot authorize extraction")
    if scope not in {"base", "superset"}:
        raise StageAInputError("binary inventory extraction scope is invalid")
    selected_regions = (
        inventory["regions"]
        if scope == "base"
        else inventory["extraction_regions"]
    )
    request = {
        "format": "stage-a-relational-side-extraction-request-v1",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "side": inventory["side"],
        "binary_sha256": inventory["binary_sha256"],
        "regions": [
            {
                "index": region["index"],
                "id": region["id"],
                "numeric_id": region["numeric_id"],
                "span": region["span"],
            }
            for region in selected_regions
        ],
    }
    return parse_request(request).to_payload()
