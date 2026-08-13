"""Exact single-binary ISA requirements for static hybrid authority.

Machine IR and Capstone metadata are useful proposal inputs, but neither may
select the semantic form used by the ISA authority gate.  This module consumes
the rows emitted by the Lean decoder for exact PE spans and binds every
conservatively reachable instruction location to that Lean-owned form.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .isa_kernel_qualification import BinaryFormRequirement, SourceLocation
from .isa_kernel_selection import ISAKernelSelectionAuthority
from .isa_semantic_forms import lean_semantic_form_id


MACHINE_IR_ISA_REQUIREMENTS_V2_FORMAT = (
    "spaghetti-extractor-machine-ir-isa-requirements-v2"
)
MACHINE_IR_ISA_SEMANTIC_REQUIREMENTS_V2_FORMAT = (
    "spaghetti-extractor-machine-ir-isa-semantic-requirements-v2"
)
MACHINE_IR_FALLBACK_CAPABILITY_V2 = "machine-ir-fallback-v2"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class MachineIRISARequirementsV2Error(ValueError):
    """The exact machine-IR ISA inventory is malformed or contradictory."""


@dataclass(frozen=True)
class MachineIRISARequirementsV2:
    status: str
    binary_sha256: str
    machine_ir_sha256: str
    request_sha256: str
    classifier_sha256: str | None
    forms: tuple[BinaryFormRequirement, ...]
    fallback_capability_ids: tuple[tuple[str, str], ...]
    issues: tuple[Mapping[str, Any], ...]
    payload: Mapping[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self.payload))


def build_machine_ir_isa_extraction_request_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    binary_sha256: str,
    include_structural_universe: bool = False,
) -> dict[str, Any]:
    """Return one canonical exact span per conservatively reachable instruction."""

    binary_sha256 = _digest(binary_sha256, "binary SHA-256")
    regions: list[dict[str, Any]] = []
    locations: dict[tuple[int, int], dict[str, Any]] = {}
    selected = sorted(
        (
            row
            for row in units
            if include_structural_universe or row.get("reachable") is True
        ),
        key=lambda row: (
            int(row.get("source", {}).get("original", {}).get("rva_start", -1)),
            str(row.get("id", "")),
        ),
    )
    for row in selected:
        unit_id = _string(row.get("id"), "machine-IR unit ID")
        source = _object(row.get("source"), f"{unit_id} source")
        span = _object(source.get("original"), f"{unit_id} original span")
        start = _nonnegative_int(span.get("rva_start"), f"{unit_id} RVA start")
        stop = _positive_int(span.get("rva_end"), f"{unit_id} RVA end")
        if stop <= start:
            raise MachineIRISARequirementsV2Error(
                f"{unit_id} original span is empty or reversed"
            )
        instructions = row.get("instructions")
        if not isinstance(instructions, list) or not instructions:
            raise MachineIRISARequirementsV2Error(
                f"{unit_id} has no exact instruction inventory"
            )
        cursor = start
        for index, instruction in enumerate(instructions):
            item = _object(instruction, f"{unit_id} instruction {index}")
            instruction_start = _nonnegative_int(
                item.get("rva_start"), f"{unit_id} instruction {index} start"
            )
            instruction_stop = _positive_int(
                item.get("rva_end"), f"{unit_id} instruction {index} end"
            )
            if instruction_start != cursor or instruction_stop <= instruction_start:
                raise MachineIRISARequirementsV2Error(
                    f"{unit_id} instruction inventory is not exact and contiguous"
                )
            location = (instruction_start, instruction_stop - instruction_start)
            owner = {
                "unit_id": unit_id,
                "instruction_index": index,
                "diagnostic_proposal": {
                    "mnemonic": item.get("mnemonic"),
                    "operands": copy.deepcopy(item.get("operands")),
                },
            }
            existing = locations.get(location)
            if existing is not None:
                existing["owners"].append(owner)
                cursor = instruction_stop
                continue
            if any(
                instruction_start < prior_start + prior_size
                and prior_start < instruction_stop
                for prior_start, prior_size in locations
            ):
                raise MachineIRISARequirementsV2Error(
                    "reachable machine-IR instruction boundaries overlap"
                )
            region = {
                "index": len(regions),
                "unit_id": unit_id,
                "instruction_index": index,
                "span": {"rva_start": location[0], "size": location[1]},
                "diagnostic_proposal": {
                    "mnemonic": item.get("mnemonic"),
                    "operands": copy.deepcopy(item.get("operands")),
                },
                "instruction_locations": [{
                    "rva": location[0],
                    "size": location[1],
                }],
                "owners": [owner],
            }
            locations[location] = region
            regions.append(region)
            cursor = instruction_stop
        if cursor != stop:
            raise MachineIRISARequirementsV2Error(
                f"{unit_id} instruction inventory does not cover its exact span"
            )
    if not regions:
        raise MachineIRISARequirementsV2Error(
            "machine IR has no conservatively reachable instruction spans"
        )
    body = {
        "format": "spaghetti-extractor-machine-ir-isa-extraction-request-v2",
        "side": "original",
        "binary_sha256": binary_sha256,
        "regions": regions,
    }
    return {**body, "request_sha256": _canonical_sha256(body)}


def build_machine_ir_isa_requirements_v2(
    *,
    request: Mapping[str, Any],
    machine_ir_sha256: str,
    lean_rows: Mapping[tuple[str, int], Sequence[Mapping[str, Any]]],
    lean_evidence: Mapping[str, Any],
    lean_gaps: Sequence[Mapping[str, Any]] = (),
    fallback_capability_id: str = MACHINE_IR_FALLBACK_CAPABILITY_V2,
) -> dict[str, Any]:
    """Bind exact Lean-decoded forms to all requested instruction locations."""

    machine_ir_sha256 = _digest(machine_ir_sha256, "machine-IR SHA-256")
    fallback_capability_id = _string(
        fallback_capability_id, "fallback capability ID"
    )
    binary_sha256 = _digest(request.get("binary_sha256"), "binary SHA-256")
    request_sha256 = _digest(request.get("request_sha256"), "request SHA-256")
    request_body = dict(request)
    request_body.pop("request_sha256", None)
    if request_sha256 != _canonical_sha256(request_body):
        raise MachineIRISARequirementsV2Error("ISA request self-hash is stale")
    if request.get("side") != "original":
        raise MachineIRISARequirementsV2Error("ISA request side must be original")
    classifier_sha256 = _digest(
        lean_evidence.get("classifier_sha256"), "Lean classifier SHA-256"
    )
    extractor_sha256 = _digest(
        lean_evidence.get("extractor_sha256"), "Lean extractor SHA-256"
    )
    source_sha256 = _digest(
        lean_evidence.get("source_sha256"), "Lean source SHA-256"
    )
    regions = request.get("regions")
    if not isinstance(regions, list) or not regions:
        raise MachineIRISARequirementsV2Error("ISA request has no regions")
    gap_by_index = {
        int(row["node_id"]): row
        for row in lean_gaps
        if isinstance(row, Mapping)
        and isinstance(row.get("node_id"), int)
        and not isinstance(row.get("node_id"), bool)
    }
    expected_keys = {("original", index) for index in range(len(regions))}
    supplied_keys = set(lean_rows) | {
        ("original", index) for index in gap_by_index
    }
    if supplied_keys != expected_keys or len(gap_by_index) != len(lean_gaps):
        raise MachineIRISARequirementsV2Error(
            "Lean decode rows do not exactly cover the ISA request"
        )

    forms: dict[str, dict[str, Any]] = {}
    occurrences: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    observed_locations: set[tuple[int, int]] = set()
    for index, region in enumerate(regions):
        region = _object(region, f"ISA request region {index}")
        unit_id = _string(region.get("unit_id"), f"ISA request region {index} unit")
        instruction_index = _nonnegative_int(
            region.get("instruction_index"),
            f"ISA request region {index} instruction index",
        )
        expected = region.get("instruction_locations")
        if not isinstance(expected, list) or not expected:
            raise MachineIRISARequirementsV2Error(
                f"ISA request region {index} has no instruction locations"
            )
        if index in gap_by_index:
            gap = gap_by_index[index]
            span = _object(region.get("span"), f"ISA request region {index} span")
            issues.append({
                "status": "incomplete",
                "code": "lean_semantic_form_unsupported",
                "unit_id": unit_id,
                "instruction_index": instruction_index,
                "rva": _nonnegative_int(span.get("rva_start"), "gap RVA"),
                "byte_length": _positive_int(span.get("size"), "gap size"),
                "decoder_code": gap.get("code"),
                "diagnostic_proposal": copy.deepcopy(
                    region.get("diagnostic_proposal")
                ),
            })
            continue
        rows = list(lean_rows[("original", index)])
        observed = [
            {"rva": row.get("rva"), "size": row.get("size")}
            for row in rows
        ]
        if observed != expected:
            raise MachineIRISARequirementsV2Error(
                f"Lean decode locations contradict exact machine IR for {unit_id}"
            )
        if len(rows) != 1:
            raise MachineIRISARequirementsV2Error(
                "one-instruction ISA request produced multiple occurrences"
            )
        row = rows[0]
        rva = _nonnegative_int(row.get("rva"), "Lean occurrence RVA")
        size = _positive_int(row.get("size"), "Lean occurrence size")
        encoded = row.get("bytes")
        semantic_form = _string(row.get("form"), "Lean semantic form")
        if (
            not isinstance(encoded, str)
            or len(encoded) != size * 2
            or any(character not in "0123456789abcdef" for character in encoded)
        ):
            raise MachineIRISARequirementsV2Error(
                "Lean occurrence bytes are not canonical hexadecimal"
            )
        location = (rva, size)
        if location in observed_locations:
            raise MachineIRISARequirementsV2Error(
                "Lean decode emitted a duplicate instruction location"
            )
        observed_locations.add(location)
        form_id = lean_semantic_form_id(
            semantic_form, classifier_sha256=classifier_sha256
        )
        form = forms.setdefault(form_id, {
            "id": form_id,
            "semantic_form": semantic_form,
            "source_locations": [],
            "fallback_capability_id": fallback_capability_id,
        })
        if form["semantic_form"] != semantic_form:
            raise MachineIRISARequirementsV2Error(
                "Lean semantic-form identity collision"
            )
        location_row = {
            "image_id": "original",
            "image_sha256": binary_sha256,
            "rva": rva,
            "byte_length": size,
        }
        form["source_locations"].append(location_row)
        occurrences.append({
            "unit_id": unit_id,
            "instruction_index": instruction_index,
            "rva": rva,
            "byte_length": size,
            "bytes": encoded,
            "form_id": form_id,
        })
    form_rows = sorted(forms.values(), key=lambda row: row["id"])
    for row in form_rows:
        row["source_locations"].sort(
            key=lambda location: (location["rva"], location["byte_length"])
        )
    occurrences.sort(key=lambda row: (row["rva"], row["byte_length"]))
    body = {
        "format": MACHINE_IR_ISA_REQUIREMENTS_V2_FORMAT,
        "status": "incomplete" if issues else "complete",
        "binding": {
            "binary_sha256": binary_sha256,
            "machine_ir_sha256": machine_ir_sha256,
            "request_sha256": request_sha256,
            "classifier_sha256": classifier_sha256,
            "extractor_sha256": extractor_sha256,
            "lean_source_sha256": source_sha256,
        },
        "forms": form_rows,
        "occurrences": occurrences,
        "fallback_capability_ids": [
            {
                "form_id": row["id"],
                "capability_id": row["fallback_capability_id"],
            }
            for row in form_rows
        ],
        "counts": {
            "regions": len(regions),
            "forms": len(form_rows),
            "occurrences": len(occurrences),
        },
        "lean_evidence": {
            "status": lean_evidence.get("status"),
            "classifier_sha256": classifier_sha256,
            "extractor_sha256": extractor_sha256,
            "source_sha256": source_sha256,
        },
        "issues": sorted(
            issues,
            key=lambda row: (int(row["rva"]), int(row["byte_length"])),
        ),
        "trust": {
            "machine_ir_selects_semantic_forms": False,
            "lean_decoder_selects_semantic_forms": True,
            "selection_authority_required": True,
        },
    }
    return {**body, "requirements_sha256": _canonical_sha256(body)}


def incomplete_machine_ir_isa_requirements_v2(
    *,
    request: Mapping[str, Any],
    machine_ir_sha256: str,
    code: str,
    reason: str,
) -> dict[str, Any]:
    """Return a fail-closed artifact when exact Lean extraction cannot finish."""

    return failed_machine_ir_isa_requirements_v2(
        request=request,
        machine_ir_sha256=machine_ir_sha256,
        status="incomplete",
        code=code,
        reason=reason,
    )


def failed_machine_ir_isa_requirements_v2(
    *,
    request: Mapping[str, Any],
    machine_ir_sha256: str,
    status: str,
    code: str,
    reason: str,
) -> dict[str, Any]:
    """Return a deterministic incomplete or violated requirements artifact."""

    if status not in {"incomplete", "violated"}:
        raise MachineIRISARequirementsV2Error("failed ISA status is invalid")

    body = {
        "format": MACHINE_IR_ISA_REQUIREMENTS_V2_FORMAT,
        "status": status,
        "binding": {
            "binary_sha256": request.get("binary_sha256"),
            "machine_ir_sha256": machine_ir_sha256,
            "request_sha256": request.get("request_sha256"),
            "classifier_sha256": None,
            "extractor_sha256": None,
            "lean_source_sha256": None,
        },
        "forms": [],
        "occurrences": [],
        "fallback_capability_ids": [],
        "counts": {
            "regions": len(request.get("regions", [])),
            "forms": 0,
            "occurrences": 0,
        },
        "lean_evidence": None,
        "issues": [{"status": status, "code": code, "reason": reason}],
        "trust": {
            "machine_ir_selects_semantic_forms": False,
            "lean_decoder_selects_semantic_forms": True,
            "selection_authority_required": True,
        },
    }
    return {**body, "requirements_sha256": _canonical_sha256(body)}


def parse_machine_ir_isa_requirements_v2(
    value: Mapping[str, Any],
) -> MachineIRISARequirementsV2:
    payload = _json_clone(value)
    expected = {
        "format", "status", "binding", "forms", "occurrences",
        "fallback_capability_ids", "counts", "lean_evidence", "issues",
        "trust", "requirements_sha256",
    }
    if set(payload) != expected or payload.get("format") != MACHINE_IR_ISA_REQUIREMENTS_V2_FORMAT:
        raise MachineIRISARequirementsV2Error("ISA requirements field inventory is invalid")
    body = dict(payload)
    observed_sha = body.pop("requirements_sha256", None)
    if observed_sha != _canonical_sha256(body):
        raise MachineIRISARequirementsV2Error("ISA requirements self-hash is stale")
    status = payload.get("status")
    if status not in {"complete", "incomplete", "violated"}:
        raise MachineIRISARequirementsV2Error("ISA requirements status is invalid")
    binding = _object(payload.get("binding"), "ISA requirements binding")
    if set(binding) != {
        "binary_sha256", "machine_ir_sha256", "request_sha256",
        "classifier_sha256", "extractor_sha256", "lean_source_sha256",
    }:
        raise MachineIRISARequirementsV2Error(
            "ISA requirements binding field inventory is invalid"
        )
    binary_sha256 = _digest(binding.get("binary_sha256"), "binary SHA-256")
    machine_ir_sha256 = _digest(
        binding.get("machine_ir_sha256"), "machine-IR SHA-256"
    )
    request_sha256 = _digest(binding.get("request_sha256"), "request SHA-256")
    classifier = binding.get("classifier_sha256")
    extractor = binding.get("extractor_sha256")
    lean_source = binding.get("lean_source_sha256")
    classifier_sha256 = (
        None
        if classifier is None
        else _digest(classifier, "classifier SHA-256")
    )
    if (extractor is None) != (classifier_sha256 is None) or (
        lean_source is None
    ) != (classifier_sha256 is None):
        raise MachineIRISARequirementsV2Error(
            "ISA requirements Lean binding is only partially present"
        )
    if extractor is not None:
        _digest(extractor, "extractor SHA-256")
        _digest(lean_source, "Lean source SHA-256")

    raw_forms = payload.get("forms")
    raw_occurrences = payload.get("occurrences")
    raw_fallbacks = payload.get("fallback_capability_ids")
    raw_issues = payload.get("issues")
    if (
        not isinstance(raw_forms, list)
        or not isinstance(raw_occurrences, list)
        or not isinstance(raw_fallbacks, list)
        or not isinstance(raw_issues, list)
    ):
        raise MachineIRISARequirementsV2Error("ISA requirements arrays are malformed")
    forms: list[BinaryFormRequirement] = []
    form_locations: dict[str, set[tuple[int, int]]] = {}
    for index, row in enumerate(raw_forms):
        row = _object(row, f"ISA form {index}")
        if set(row) != {
            "id", "semantic_form", "source_locations", "fallback_capability_id",
        }:
            raise MachineIRISARequirementsV2Error(
                f"ISA form {index} field inventory is invalid"
            )
        locations = row.get("source_locations")
        if (
            not isinstance(locations, list)
            or not locations
            or any(not isinstance(location, Mapping) for location in locations)
        ):
            raise MachineIRISARequirementsV2Error(f"ISA form {index} has no locations")
        form_id = _string(row.get("id"), f"ISA form {index} ID")
        semantic_form = _string(
            row.get("semantic_form"), f"ISA form {index} semantic form"
        )
        if classifier_sha256 is None:
            raise MachineIRISARequirementsV2Error(
                "ISA forms require a Lean classifier binding"
            )
        if form_id != lean_semantic_form_id(
            semantic_form, classifier_sha256=classifier_sha256
        ):
            raise MachineIRISARequirementsV2Error(
                f"ISA form {index} identity is stale"
            )
        if row.get("fallback_capability_id") != MACHINE_IR_FALLBACK_CAPABILITY_V2:
            raise MachineIRISARequirementsV2Error(
                f"ISA form {index} fallback capability is invalid"
            )
        parsed_locations: list[SourceLocation] = []
        local_locations: set[tuple[int, int]] = set()
        for location in locations:
            if set(location) != {
                "image_id", "image_sha256", "rva", "byte_length",
            }:
                raise MachineIRISARequirementsV2Error(
                    f"ISA form {index} location field inventory is invalid"
                )
            parsed = SourceLocation(
                image_id=_string(location.get("image_id"), "ISA location image ID"),
                image_sha256=_digest(location.get("image_sha256"), "ISA location image SHA-256"),
                rva=_nonnegative_int(location.get("rva"), "ISA location RVA"),
                byte_length=_positive_int(location.get("byte_length"), "ISA location length"),
            )
            if parsed.image_id != "original" or parsed.image_sha256 != binary_sha256:
                raise MachineIRISARequirementsV2Error(
                    f"ISA form {index} location is not bound to the exact original image"
                )
            location_key = (parsed.rva, parsed.byte_length)
            if location_key in local_locations:
                raise MachineIRISARequirementsV2Error(
                    f"ISA form {index} repeats a source location"
                )
            local_locations.add(location_key)
            parsed_locations.append(parsed)
        if form_id in form_locations:
            raise MachineIRISARequirementsV2Error("ISA form IDs are duplicated")
        form_locations[form_id] = local_locations
        forms.append(BinaryFormRequirement(
            form_id=form_id,
            semantic_form=semantic_form,
            source_locations=tuple(parsed_locations),
        ))

    occurrence_locations: dict[str, set[tuple[int, int]]] = {
        form_id: set() for form_id in form_locations
    }
    all_locations: set[tuple[int, int]] = set()
    for index, row in enumerate(raw_occurrences):
        row = _object(row, f"ISA occurrence {index}")
        if set(row) != {
            "unit_id", "instruction_index", "rva", "byte_length", "bytes", "form_id",
        }:
            raise MachineIRISARequirementsV2Error(
                f"ISA occurrence {index} field inventory is invalid"
            )
        _string(row.get("unit_id"), f"ISA occurrence {index} unit ID")
        _nonnegative_int(
            row.get("instruction_index"),
            f"ISA occurrence {index} instruction index",
        )
        rva = _nonnegative_int(row.get("rva"), f"ISA occurrence {index} RVA")
        length = _positive_int(
            row.get("byte_length"), f"ISA occurrence {index} byte length"
        )
        encoded = row.get("bytes")
        if (
            not isinstance(encoded, str)
            or len(encoded) != length * 2
            or any(character not in "0123456789abcdef" for character in encoded)
        ):
            raise MachineIRISARequirementsV2Error(
                f"ISA occurrence {index} bytes are invalid"
            )
        form_id = _string(row.get("form_id"), f"ISA occurrence {index} form ID")
        if form_id not in occurrence_locations:
            raise MachineIRISARequirementsV2Error(
                f"ISA occurrence {index} references an unknown form"
            )
        location = (rva, length)
        if location in all_locations:
            raise MachineIRISARequirementsV2Error(
                "ISA occurrence locations are duplicated"
            )
        all_locations.add(location)
        occurrence_locations[form_id].add(location)
    if occurrence_locations != form_locations:
        raise MachineIRISARequirementsV2Error(
            "ISA form source locations do not replay from exact occurrences"
        )
    if any(
        not isinstance(row, Mapping) or set(row) != {"form_id", "capability_id"}
        for row in raw_fallbacks
    ):
        raise MachineIRISARequirementsV2Error(
            "fallback capability rows must be objects"
        )
    fallback_rows = tuple(sorted(
        (
            _string(row.get("form_id"), "fallback form ID"),
            _string(row.get("capability_id"), "fallback capability ID"),
        )
        for row in raw_fallbacks
    ))
    expected_fallbacks = tuple(sorted(
        (row.form_id, MACHINE_IR_FALLBACK_CAPABILITY_V2) for row in forms
    ))
    if fallback_rows != expected_fallbacks:
        raise MachineIRISARequirementsV2Error(
            "ISA fallback capability inventory does not match the exact forms"
        )

    issue_locations: set[tuple[int, int]] = set()
    issue_statuses: list[str] = []
    for index, row in enumerate(raw_issues):
        row = _object(row, f"ISA requirements issue {index}")
        issue_status = row.get("status")
        if issue_status not in {"incomplete", "violated"}:
            raise MachineIRISARequirementsV2Error(
                f"ISA requirements issue {index} status is invalid"
            )
        _string(row.get("code"), f"ISA requirements issue {index} code")
        issue_statuses.append(str(issue_status))
        has_location = "rva" in row or "byte_length" in row
        if has_location:
            if not {"rva", "byte_length"} <= set(row):
                raise MachineIRISARequirementsV2Error(
                    f"ISA requirements issue {index} location is partial"
                )
            location = (
                _nonnegative_int(row.get("rva"), "ISA issue RVA"),
                _positive_int(row.get("byte_length"), "ISA issue byte length"),
            )
            if location in issue_locations or location in all_locations:
                raise MachineIRISARequirementsV2Error(
                    "ISA requirement issue locations overlap checked evidence"
                )
            issue_locations.add(location)
    derived_status = (
        "violated" if "violated" in issue_statuses
        else "incomplete" if issue_statuses
        else "complete"
    )
    if status != derived_status:
        raise MachineIRISARequirementsV2Error(
            "ISA requirements status contradicts its issue inventory"
        )

    counts = _object(payload.get("counts"), "ISA requirements counts")
    if set(counts) != {"regions", "forms", "occurrences"}:
        raise MachineIRISARequirementsV2Error(
            "ISA requirements count field inventory is invalid"
        )
    region_count = _positive_int(counts.get("regions"), "ISA region count")
    if counts.get("forms") != len(forms) or counts.get("occurrences") != len(raw_occurrences):
        raise MachineIRISARequirementsV2Error(
            "ISA requirements counts are stale"
        )

    lean_evidence = payload.get("lean_evidence")
    if lean_evidence is None:
        if forms or raw_occurrences or classifier_sha256 is not None:
            raise MachineIRISARequirementsV2Error(
                "failed ISA requirements retain partial Lean evidence"
            )
    else:
        lean_evidence = _object(lean_evidence, "ISA requirements Lean evidence")
        if set(lean_evidence) != {
            "status", "classifier_sha256", "extractor_sha256", "source_sha256",
        }:
            raise MachineIRISARequirementsV2Error(
                "ISA requirements Lean evidence field inventory is invalid"
            )
        if lean_evidence.get("status") != "lean_extracted_untrusted":
            raise MachineIRISARequirementsV2Error(
                "ISA requirements Lean evidence status is invalid"
            )
        if (
            lean_evidence.get("classifier_sha256") != classifier_sha256
            or lean_evidence.get("extractor_sha256") != extractor
            or lean_evidence.get("source_sha256") != lean_source
        ):
            raise MachineIRISARequirementsV2Error(
                "ISA requirements Lean evidence contradicts its binding"
            )
        if region_count != len(raw_occurrences) + len(issue_locations):
            raise MachineIRISARequirementsV2Error(
                "ISA exact instruction inventory is not closed"
            )

    if payload.get("trust") != {
        "machine_ir_selects_semantic_forms": False,
        "lean_decoder_selects_semantic_forms": True,
        "selection_authority_required": True,
    }:
        raise MachineIRISARequirementsV2Error(
            "ISA requirements trust policy is invalid"
        )
    if status == "complete" and (not forms or raw_issues):
        raise MachineIRISARequirementsV2Error(
            "complete ISA requirements do not close their exact inventory"
        )
    return MachineIRISARequirementsV2(
        status=str(status),
        binary_sha256=binary_sha256,
        machine_ir_sha256=machine_ir_sha256,
        request_sha256=request_sha256,
        classifier_sha256=classifier_sha256,
        forms=tuple(forms),
        fallback_capability_ids=fallback_rows,
        issues=tuple(_object(row, "ISA requirements issue") for row in raw_issues),
        payload=payload,
    )


def build_machine_ir_isa_semantic_requirements_v2(
    value: Mapping[str, Any] | MachineIRISARequirementsV2,
) -> dict[str, Any]:
    """Project authority-bound requirements onto reusable ISA semantics."""

    requirements = (
        value
        if isinstance(value, MachineIRISARequirementsV2)
        else parse_machine_ir_isa_requirements_v2(value)
    )
    if requirements.status != "complete":
        raise MachineIRISARequirementsV2Error(
            "only complete exact ISA requirements have a semantic projection"
        )
    payload = requirements.to_payload()
    binding = _object(payload.get("binding"), "ISA requirements binding")
    checker = {
        "classifier_sha256": _digest(
            binding.get("classifier_sha256"), "classifier SHA-256"
        ),
        "extractor_sha256": _digest(
            binding.get("extractor_sha256"), "extractor SHA-256"
        ),
        "lean_source_sha256": _digest(
            binding.get("lean_source_sha256"), "Lean source SHA-256"
        ),
    }
    forms_by_id = {
        _string(row.get("id"), f"ISA form {index} ID"): {
            "semantic_form": _string(
                row.get("semantic_form"), f"ISA form {index} semantic form"
            ),
            "instruction_hexes": set(),
        }
        for index, raw in enumerate(payload["forms"])
        for row in (_object(raw, f"ISA form {index}"),)
    }
    for index, raw in enumerate(payload["occurrences"]):
        row = _object(raw, f"ISA occurrence {index}")
        form_id = _string(row.get("form_id"), f"ISA occurrence {index} form ID")
        encoded = row.get("bytes")
        if form_id not in forms_by_id or not isinstance(encoded, str):
            raise MachineIRISARequirementsV2Error(
                "ISA semantic projection does not replay from exact requirements"
            )
        forms_by_id[form_id]["instruction_hexes"].add(encoded)
    forms = [
        {
            "form_id": form_id,
            "semantic_form": str(forms_by_id[form_id]["semantic_form"]),
            "instruction_hexes": sorted(forms_by_id[form_id]["instruction_hexes"]),
        }
        for form_id in sorted(forms_by_id)
    ]
    if any(not row["instruction_hexes"] for row in forms):
        raise MachineIRISARequirementsV2Error(
            "ISA semantic projection contains a form without an exact encoding"
        )
    semantic_body = {
        "format": MACHINE_IR_ISA_SEMANTIC_REQUIREMENTS_V2_FORMAT,
        "checker": checker,
        "forms": forms,
    }
    body = {
        **semantic_body,
        "status": "complete",
        "binary_sha256": requirements.binary_sha256,
        "counts": {
            "forms": len(forms),
            "encodings": sum(len(row["instruction_hexes"]) for row in forms),
        },
        "trust": {
            "authority_binding_retained_upstream": True,
            "machine_ir_metadata_is_semantic": False,
            "exact_instruction_bytes_and_forms_are_semantic": True,
        },
        "semantic_requirements_sha256": _canonical_sha256(semantic_body),
    }
    return {**body, "projection_sha256": _canonical_sha256(body)}


def parse_machine_ir_isa_semantic_requirements_v2(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a semantic projection and reject stale or broadened identities."""

    payload = _json_clone(value)
    expected = {
        "format",
        "status",
        "binary_sha256",
        "checker",
        "forms",
        "counts",
        "trust",
        "semantic_requirements_sha256",
        "projection_sha256",
    }
    if set(payload) != expected:
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements field inventory is invalid"
        )
    if payload.get("format") != MACHINE_IR_ISA_SEMANTIC_REQUIREMENTS_V2_FORMAT:
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements format is invalid"
        )
    body = dict(payload)
    projection_sha256 = body.pop("projection_sha256", None)
    if projection_sha256 != _canonical_sha256(body):
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements projection hash is stale"
        )
    if payload.get("status") != "complete":
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements status is invalid"
        )
    _digest(payload.get("binary_sha256"), "binary SHA-256")
    checker = _object(payload.get("checker"), "ISA semantic requirements checker")
    if set(checker) != {
        "classifier_sha256",
        "extractor_sha256",
        "lean_source_sha256",
    }:
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements checker inventory is invalid"
        )
    classifier_sha256 = _digest(
        checker.get("classifier_sha256"), "classifier SHA-256"
    )
    _digest(checker.get("extractor_sha256"), "extractor SHA-256")
    _digest(checker.get("lean_source_sha256"), "Lean source SHA-256")
    raw_forms = payload.get("forms")
    if not isinstance(raw_forms, list) or not raw_forms:
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements have no forms"
        )
    forms: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_forms):
        row = _object(raw, f"ISA semantic form {index}")
        if set(row) != {"form_id", "semantic_form", "instruction_hexes"}:
            raise MachineIRISARequirementsV2Error(
                f"ISA semantic form {index} field inventory is invalid"
            )
        form_id = _string(row.get("form_id"), f"ISA semantic form {index} ID")
        semantic_form = _string(
            row.get("semantic_form"), f"ISA semantic form {index} semantic form"
        )
        if form_id != lean_semantic_form_id(
            semantic_form, classifier_sha256=classifier_sha256
        ):
            raise MachineIRISARequirementsV2Error(
                f"ISA semantic form {index} identity is stale"
            )
        raw_encodings = row.get("instruction_hexes")
        if not isinstance(raw_encodings, list) or not raw_encodings:
            raise MachineIRISARequirementsV2Error(
                f"ISA semantic form {index} has no encodings"
            )
        encodings = [
            _instruction_hex(encoded, f"ISA semantic form {index} encoding")
            for encoded in raw_encodings
        ]
        if encodings != sorted(set(encodings)):
            raise MachineIRISARequirementsV2Error(
                f"ISA semantic form {index} encodings are not canonical"
            )
        forms.append({
            "form_id": form_id,
            "semantic_form": semantic_form,
            "instruction_hexes": encodings,
        })
    if [row["form_id"] for row in forms] != sorted(
        {row["form_id"] for row in forms}
    ):
        raise MachineIRISARequirementsV2Error(
            "ISA semantic form inventory is not canonical"
        )
    counts = _object(payload.get("counts"), "ISA semantic requirements counts")
    expected_counts = {
        "forms": len(forms),
        "encodings": sum(len(row["instruction_hexes"]) for row in forms),
    }
    if dict(counts) != expected_counts:
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements counts are stale"
        )
    if payload.get("trust") != {
        "authority_binding_retained_upstream": True,
        "machine_ir_metadata_is_semantic": False,
        "exact_instruction_bytes_and_forms_are_semantic": True,
    }:
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements trust policy is invalid"
        )
    semantic_body = {
        "format": MACHINE_IR_ISA_SEMANTIC_REQUIREMENTS_V2_FORMAT,
        "checker": dict(checker),
        "forms": forms,
    }
    if payload.get("semantic_requirements_sha256") != _canonical_sha256(
        semantic_body
    ):
        raise MachineIRISARequirementsV2Error(
            "ISA semantic requirements identity is stale"
        )
    return payload


def compare_selection_to_machine_ir_requirements_v2(
    requirements: MachineIRISARequirementsV2,
    authority: ISAKernelSelectionAuthority,
) -> list[dict[str, Any]]:
    """Return fail-closed issues for any stale form, location, or fallback."""

    issues: list[dict[str, Any]] = []
    if requirements.status != "complete":
        issues.append({
            "status": "incomplete",
            "code": "isa_exact_requirements_incomplete",
            "requirement_issues": copy.deepcopy(list(requirements.issues)),
        })
        return issues
    if authority.requirements.binary_sha256 != requirements.binary_sha256:
        issues.append({
            "status": "violated",
            "code": "isa_selection_binary_mismatch",
        })
    expected_forms = tuple(sorted(
        requirements.forms,
        key=lambda row: row.form_id,
    ))
    observed_forms = tuple(sorted(
        authority.requirements.forms,
        key=lambda row: row.form_id,
    ))
    if observed_forms != expected_forms:
        issues.append({
            "status": "violated",
            "code": "isa_selection_exact_form_inventory_mismatch",
            "expected_form_ids": [row.form_id for row in expected_forms],
            "observed_form_ids": [row.form_id for row in observed_forms],
        })
    observed_fallbacks = tuple(sorted(
        (row.form_id, row.capability_id)
        for row in authority.fallback_capability_ids
    ))
    if observed_fallbacks != requirements.fallback_capability_ids:
        issues.append({
            "status": "violated",
            "code": "isa_selection_fallback_inventory_mismatch",
        })
    return issues


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineIRISARequirementsV2Error(f"{context} must be an object")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise MachineIRISARequirementsV2Error(f"{context} must be a canonical string")
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise MachineIRISARequirementsV2Error(f"{context} is invalid")
    return value


def _instruction_hex(value: Any, context: str) -> str:
    encoded = _string(value, context)
    if (
        len(encoded) % 2
        or not 1 <= len(encoded) // 2 <= 15
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        raise MachineIRISARequirementsV2Error(
            f"{context} is not a canonical x86 instruction"
        )
    return encoded


def _nonnegative_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MachineIRISARequirementsV2Error(f"{context} must be non-negative")
    return value


def _positive_int(value: Any, context: str) -> int:
    value = _nonnegative_int(value, context)
    if value == 0:
        raise MachineIRISARequirementsV2Error(f"{context} must be positive")
    return value


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    ).hexdigest()


def _json_clone(value: Any) -> dict[str, Any]:
    try:
        result = json.loads(json.dumps(value, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise MachineIRISARequirementsV2Error("ISA requirements are not canonical JSON") from exc
    if not isinstance(result, dict):
        raise MachineIRISARequirementsV2Error("ISA requirements must be an object")
    return result


__all__ = [
    "MACHINE_IR_FALLBACK_CAPABILITY_V2",
    "MACHINE_IR_ISA_REQUIREMENTS_V2_FORMAT",
    "MACHINE_IR_ISA_SEMANTIC_REQUIREMENTS_V2_FORMAT",
    "MachineIRISARequirementsV2",
    "MachineIRISARequirementsV2Error",
    "build_machine_ir_isa_extraction_request_v2",
    "build_machine_ir_isa_requirements_v2",
    "build_machine_ir_isa_semantic_requirements_v2",
    "compare_selection_to_machine_ir_requirements_v2",
    "failed_machine_ir_isa_requirements_v2",
    "incomplete_machine_ir_isa_requirements_v2",
    "parse_machine_ir_isa_requirements_v2",
    "parse_machine_ir_isa_semantic_requirements_v2",
]
