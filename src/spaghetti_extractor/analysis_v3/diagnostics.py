"""Deterministic operator diagnostics over checked v3 authority artifacts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..artifact_set_v3 import open_artifact_reader_v3


AUTHORITY_DIAGNOSTICS_V3_FORMAT = (
    "spaghetti-extractor-authority-diagnostics-v3"
)


_NEXT_ACTIONS = {
    "implementation_capability_missing": (
        "qualify the exact ISA form, then regenerate the fallback capability "
        "evidence for this unit"
    ),
    "isa_qualification_evidence_missing": (
        "inspect the ISA projection form_frontiers entry for this RVA and "
        "resolve its missing, vetoed, or disputed semantic-form evidence"
    ),
    "structural_target_proposal_incomplete": (
        "supply a finite target certificate for the exact target expression "
        "or improve generic provenance until one is derived"
    ),
    "canonical_external_sites_not_complete": (
        "complete the checked external-site identity, ABI, effects, and "
        "continuation contract named by this record"
    ),
    "external_argument_words_missing": (
        "recover and bind every machine-level argument word at this external "
        "call site"
    ),
    "external_callback_requirements_missing": (
        "bind callback registration, entry ABI, continuation, and nested "
        "entry-state requirements for this external site"
    ),
    "target_evaluation_evidence_missing": (
        "prove that the normalized target expression evaluates into its "
        "declared finite target set"
    ),
    "direct_target_unresolved": (
        "decode and bind the exact direct destination, or classify the "
        "transfer as an explicit unsupported frontier"
    ),
}


def _next_action(code: str) -> str:
    return _NEXT_ACTIONS.get(
        code,
        "inspect the terminal authority record and satisfy or correct its "
        "checked dependency without changing the acceptance policy",
    )


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _phase_inputs(
    graph_manifest: Mapping[str, Any] | None,
) -> dict[str, dict[str, tuple[str, str]]]:
    """Return phase-local input names mapped to their declared producers."""

    if graph_manifest is None:
        return {}
    result: dict[str, dict[str, tuple[str, str]]] = {}
    phases = graph_manifest.get("phases")
    if not isinstance(phases, list):
        return result
    for raw_phase in phases:
        phase = _mapping(raw_phase)
        if phase is None or not isinstance(phase.get("phase_id"), str):
            continue
        inputs = _mapping(phase.get("inputs"))
        if inputs is None:
            continue
        aliases: dict[str, tuple[str, str]] = {}
        for input_name, raw_source in inputs.items():
            source = _mapping(raw_source)
            if (
                isinstance(input_name, str)
                and source is not None
                and source.get("source") in {"phase", "external"}
                and isinstance(source.get("id"), str)
            ):
                aliases[input_name] = (source["source"], source["id"])
        result[phase["phase_id"]] = aliases
    return result


def _blocker(value: Mapping[str, Any]) -> Mapping[str, Any] | None:
    return _mapping(value.get("primary_blocker"))


def _status(value: Mapping[str, Any]) -> str | None:
    status = value.get("status")
    return status if isinstance(status, str) else None


def _blocker_code(
    blocker: Mapping[str, Any] | None, fallback: str = "incomplete_dependency"
) -> str:
    if blocker is not None and isinstance(blocker.get("code"), str):
        return blocker["code"]
    return fallback


def summarize_authority_artifacts_v3(
    artifacts: Mapping[str, Path],
    *,
    graph_manifest: Mapping[str, Any] | None = None,
    example_limit: int = 8,
) -> dict[str, Any]:
    """Summarize checked authority failures as root causes and consequences.

    Authority records intentionally repeat blockers at every dependent phase so
    that each record fails closed in isolation.  Presenting those repetitions
    as separate operator tasks is misleading.  This pass follows only the
    graph-declared input aliases and keeps the terminal checked dependency as
    the repair frontier.  It never changes or grants authority.
    """

    if example_limit < 1:
        raise ValueError("authority diagnostics example_limit must be positive")

    readers = {
        name: open_artifact_reader_v3(path)
        for name, path in sorted(artifacts.items())
    }
    binary_bindings = sorted(
        {
            (
                binding.name,
                binding.kind,
                binding.identity,
                binding.sha256,
            )
            for reader in readers.values()
            for binding in reader.manifest.bindings
            if binding.name == "binary" and binding.kind == "pe32"
        }
    )
    source_locations: dict[str, dict[str, Any]] = {}
    semantic_reader = readers.get("semantic-index-v3")
    if semantic_reader is not None:
        for record in semantic_reader.iter_records():
            value = _mapping(record.value.to_value())
            if value is None:
                continue
            source_locations[record.record_id] = {
                key: value[key]
                for key in ("rva_start", "rva_end", "unit_sha256")
                if key in value
            }

    phase_inputs = _phase_inputs(graph_manifest)
    records_by_phase: dict[str, dict[str, Mapping[str, Any]]] = {}
    for name, reader in readers.items():
        rows: dict[str, Mapping[str, Any]] = {}
        for record in reader.iter_records():
            value = _mapping(record.value.to_value())
            if value is not None:
                rows[record.record_id] = value
        records_by_phase[name] = rows

    def resolve_root(
        phase: str,
        record_id: str,
        value: Mapping[str, Any],
    ) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
        chain: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        current_phase = phase
        current_record_id = record_id
        current_value = value
        inherited_code = _blocker_code(_blocker(value))
        while True:
            key = (current_phase, current_record_id)
            if key in seen:
                return (
                    {
                        "family": current_phase,
                        "record_id": current_record_id,
                        "status": _status(current_value) or "incomplete",
                        "code": "diagnostic_dependency_cycle",
                        "source_location": source_locations.get(current_record_id),
                    },
                    tuple(chain),
                )
            seen.add(key)
            blocker = _blocker(current_value)
            dependency_input = None if blocker is None else blocker.get("input")
            dependency_record = (
                None if blocker is None else blocker.get("record_id")
            )
            if not (
                isinstance(dependency_input, str)
                and isinstance(dependency_record, str)
            ):
                return (
                    {
                        "family": current_phase,
                        "record_id": current_record_id,
                        "status": (
                            _status(current_value)
                            or (blocker or {}).get("status")
                            or "incomplete"
                        ),
                        "code": _blocker_code(blocker, inherited_code),
                        "source_location": source_locations.get(current_record_id),
                    },
                    tuple(chain),
                )
            source = phase_inputs.get(current_phase, {}).get(dependency_input)
            chain.append(
                {
                    "family": current_phase,
                    "record_id": current_record_id,
                    "code": _blocker_code(blocker, inherited_code),
                    "blocked_by": {
                        "input": dependency_input,
                        "record_id": dependency_record,
                    },
                }
            )
            if source is None or source[0] == "external":
                external_id = dependency_input if source is None else source[1]
                return (
                    {
                        "family": f"external:{external_id}",
                        "record_id": dependency_record,
                        "status": (blocker or {}).get("status") or "incomplete",
                        "code": _blocker_code(blocker, inherited_code),
                        "source_location": source_locations.get(current_record_id),
                    },
                    tuple(chain),
                )
            producer = source[1]
            dependency_value = records_by_phase.get(producer, {}).get(
                dependency_record
            )
            if dependency_value is None:
                return (
                    {
                        "family": producer,
                        "record_id": dependency_record,
                        "status": "incomplete",
                        "code": "diagnostic_dependency_record_missing",
                        "source_location": source_locations.get(dependency_record),
                    },
                    tuple(chain),
                )
            current_phase = producer
            current_record_id = dependency_record
            current_value = dependency_value

    families: list[dict[str, Any]] = []
    raw_frontiers: list[dict[str, Any]] = []
    consequence_counts: Counter[tuple[str, str, str, str]] = Counter()
    final: dict[str, Any] | None = None
    for name, reader in readers.items():
        status_counts: Counter[str] = Counter()
        authorizing_counts: Counter[str] = Counter()
        blocker_counts: Counter[str] = Counter()
        records = tuple(reader.iter_records())
        for record in records:
            value = _mapping(record.value.to_value())
            if value is None:
                status_counts["malformed"] += 1
                continue
            status = value.get("status")
            if isinstance(status, str):
                status_counts[status] += 1
            authorizing = value.get("authorizing")
            if isinstance(authorizing, bool):
                authorizing_counts[str(authorizing).lower()] += 1
            blocker = _mapping(value.get("primary_blocker"))
            if blocker is not None:
                code = blocker.get("code")
                code_text = code if isinstance(code, str) else "malformed_blocker"
                blocker_counts[code_text] += 1
                root, chain = resolve_root(name, record.record_id, value)
                root["observed_at"] = {
                    "family": name,
                    "record_id": record.record_id,
                }
                root["dependency_depth"] = len(chain)
                raw_frontiers.append(root)
                for consequence in chain:
                    blocked_by = consequence["blocked_by"]
                    consequence_counts[
                        (
                            consequence["family"],
                            consequence["code"],
                            blocked_by["input"],
                            root["code"],
                        )
                    ] += 1
            if name == "final-authority-v3":
                final = {
                    "record_id": record.record_id,
                    "status": status,
                    "authorizing": authorizing,
                    "primary_blocker": blocker,
                    "exact_unit_count": value.get("exact_unit_count"),
                }
        families.append(
            {
                "phase": name,
                "artifact_kind": reader.manifest.artifact_kind,
                "artifact_id": reader.manifest.artifact_id,
                "manifest_status": reader.manifest.status,
                "record_count": len(records),
                "status_counts": dict(sorted(status_counts.items())),
                "authorizing_counts": dict(sorted(authorizing_counts.items())),
                "primary_blocker_counts": dict(sorted(blocker_counts.items())),
            }
        )

    raw_frontiers.sort(
        key=lambda row: (
            0 if row["status"] == "violated" else 1,
            row["family"],
            row["code"],
            row["record_id"],
        )
    )
    unique_frontiers: dict[tuple[str, str, str], dict[str, Any]] = {}
    occurrence_counts: Counter[tuple[str, str, str]] = Counter()
    observed_examples: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in raw_frontiers:
        key = (row["family"], row["code"], row["record_id"])
        occurrence_counts[key] += 1
        unique_frontiers.setdefault(
            key,
            {
                name: value
                for name, value in row.items()
                if name not in {"observed_at", "dependency_depth"}
            },
        )
        examples = observed_examples.setdefault(key, [])
        if row["observed_at"] not in examples and len(examples) < example_limit:
            examples.append(row["observed_at"])
    frontiers: list[dict[str, Any]] = []
    for key, row in unique_frontiers.items():
        row["dependent_occurrences"] = occurrence_counts[key]
        row["observed_at_examples"] = observed_examples[key]
        row["next_action"] = _next_action(row["code"])
        frontiers.append(row)
    frontiers.sort(
        key=lambda row: (
            0 if row["status"] == "violated" else 1,
            row["family"],
            row["code"],
            row["record_id"],
        )
    )
    dependency_groups = [
        {
            "family": family,
            "code": code,
            "blocked_input": blocked_input,
            "root_code": root_code,
            "occurrences": count,
        }
        for (family, code, blocked_input, root_code), count in sorted(
            consequence_counts.items()
        )
    ]
    return {
        "format": AUTHORITY_DIAGNOSTICS_V3_FORMAT,
        "status": None if final is None else final["status"],
        "authorizing": False if final is None else final["authorizing"] is True,
        "final_authority": final,
        "binary_bindings": [
            {
                "name": name,
                "kind": kind,
                "identity": identity,
                "sha256": sha256,
            }
            for name, kind, identity, sha256 in binary_bindings
        ],
        "families": families,
        "counts": {
            "families": len(families),
            "primary_frontiers": len(frontiers),
            "dependent_occurrences": sum(consequence_counts.values()),
            "violated_frontiers": sum(
                row["status"] == "violated" for row in frontiers
            ),
            "incomplete_frontiers": sum(
                row["status"] == "incomplete" for row in frontiers
            ),
        },
        "primary_frontiers": frontiers,
        "dependency_consequences": dependency_groups,
        "trust": {
            "authorizes_candidate_generation": False,
            "authority_is_owned_by_final_record": True,
            "original_binary_executed": False,
        },
    }


__all__ = [
    "AUTHORITY_DIAGNOSTICS_V3_FORMAT",
    "summarize_authority_artifacts_v3",
]
