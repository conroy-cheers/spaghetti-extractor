"""Explicit total provider selection for linked-semantic-module-v2.

Qualifications are reusable because they bind semantic slices rather than a
whole module.  Selection is the single admission point: it reconstructs each
selected slice from the current module, requires an exact content match, and
then selects one provider for every definition and residual obligation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..util import write_json
from .formats import IMPLEMENTATION_SELECTION_V2_FORMAT
from .qualification_v2 import (
    SEMANTIC_PROVIDER_KINDS_V2,
    SemanticProviderQualificationV2,
)
from .slices_v2 import SemanticSliceV2Error, build_semantic_slice_v2


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODES = frozenset({"faithful", "hybrid", "portable"})
_FIELDS = {
    "format", "status", "ready_for_realization", "mode", "bindings",
    "qualification_sha256s", "definition_selections",
    "obligation_selections", "blockers", "selection_sha256",
}


class ImplementationSelectionV2Error(ValueError):
    """A V2 selection is malformed, stale, ambiguous, or incomplete."""


def _fail(message: str) -> None:
    raise ImplementationSelectionV2Error(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(row, Mapping) for row in value
    ):
        _fail(f"{context} must be an array of objects")
    return list(value)


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{context} must be a lowercase SHA-256")
    return value


def _canonical_rows(
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        {canonical_sha256_v3(dict(row)): dict(row) for row in rows}.values(),
        key=canonical_sha256_v3,
    )


@dataclass(frozen=True)
class ImplementationSelectionV2:
    payload: Mapping[str, Any]

    @property
    def identity(self) -> str:
        return str(self.payload["selection_sha256"])

    @classmethod
    def parse(cls, value: object) -> "ImplementationSelectionV2":
        payload = dict(_mapping(value, "implementation selection V2"))
        if set(payload) != _FIELDS:
            _fail("implementation-selection V2 fields are incomplete")
        if payload.get("format") != IMPLEMENTATION_SELECTION_V2_FORMAT:
            _fail("implementation-selection V2 format is unsupported")
        identity = _digest(payload.get("selection_sha256"), "selection identity")
        if identity != canonical_sha256_v3({
            key: item for key, item in payload.items()
            if key != "selection_sha256"
        }):
            _fail("implementation-selection V2 self hash is stale")
        mode = payload.get("mode")
        if mode not in _MODES:
            _fail("implementation-selection V2 mode is unsupported")
        bindings = _mapping(payload.get("bindings"), "selection V2 bindings")
        if set(bindings) != {"linked_semantic_module_sha256"}:
            _fail("implementation-selection V2 bindings are incomplete")
        _digest(
            bindings.get("linked_semantic_module_sha256"),
            "linked semantic module V2 binding",
        )
        qualification_sha256s = payload.get("qualification_sha256s")
        if (
            not isinstance(qualification_sha256s, list)
            or qualification_sha256s != sorted(set(qualification_sha256s))
        ):
            _fail("selection V2 qualification inventory is noncanonical")
        for digest in qualification_sha256s:
            _digest(digest, "selection V2 qualification identity")

        definition_rows = _rows(
            payload.get("definition_selections"), "definition selections V2"
        )
        definition_ids: list[str] = []
        for row in definition_rows:
            if set(row) != {
                "definition_id", "symbol_id", "provider_id", "provider_kind",
                "qualification_sha256", "native_symbol",
            }:
                _fail("definition-selection V2 fields are incomplete")
            if any(
                not isinstance(row.get(field), str) or not row[field]
                for field in (
                    "definition_id", "symbol_id", "provider_id",
                    "native_symbol",
                )
            ) or row.get("provider_kind") not in SEMANTIC_PROVIDER_KINDS_V2:
                _fail("definition-selection V2 identity is malformed")
            qualification = _digest(
                row.get("qualification_sha256"),
                "definition qualification identity",
            )
            if qualification not in qualification_sha256s:
                _fail("definition qualification is absent from inventory")
            definition_ids.append(str(row["definition_id"]))
        if definition_ids != sorted(set(definition_ids)):
            _fail("definition selections V2 are noncanonical or ambiguous")

        obligation_rows = _rows(
            payload.get("obligation_selections"), "obligation selections V2"
        )
        obligation_ids: list[str] = []
        for row in obligation_rows:
            if set(row) != {
                "obligation_id", "provider_id", "provider_kind",
                "qualification_sha256", "native_symbol", "receipt_sha256",
            }:
                _fail("obligation-selection V2 fields are incomplete")
            if any(
                not isinstance(row.get(field), str) or not row[field]
                for field in ("obligation_id", "provider_id", "native_symbol")
            ) or row.get("provider_kind") not in SEMANTIC_PROVIDER_KINDS_V2:
                _fail("obligation-selection V2 identity is malformed")
            qualification = _digest(
                row.get("qualification_sha256"),
                "obligation qualification identity",
            )
            _digest(row.get("receipt_sha256"), "obligation receipt identity")
            if qualification not in qualification_sha256s:
                _fail("obligation qualification is absent from inventory")
            obligation_ids.append(str(row["obligation_id"]))
        if obligation_ids != sorted(set(obligation_ids)):
            _fail("obligation selections V2 are noncanonical or ambiguous")

        blockers = _rows(payload.get("blockers"), "selection V2 blockers")
        if blockers != _canonical_rows(blockers) or any(
            not isinstance(row.get("code"), str) or not row["code"]
            for row in blockers
        ):
            _fail("implementation-selection V2 blockers are malformed")
        status = payload.get("status")
        ready = payload.get("ready_for_realization")
        if (
            status not in {"complete", "incomplete"}
            or not isinstance(ready, bool)
            or (status == "complete") != (not blockers)
            or ready != (status == "complete")
        ):
            _fail("implementation-selection V2 readiness contradicts blockers")
        if mode == "portable" and any(
            row["provider_kind"] == "generated_behavioral_c"
            for row in definition_rows
        ):
            _fail("portable V2 selection contains generated Behavioral C")
        return cls(payload)

    @classmethod
    def load(cls, path: Path) -> "ImplementationSelectionV2":
        return cls.parse(json.loads(Path(path).read_text(encoding="utf-8")))


def _choices(value: Mapping[str, str] | None, context: str) -> dict[str, str]:
    result = dict(value or {})
    if any(
        not isinstance(subject_id, str) or not subject_id
        or not isinstance(provider_id, str) or not provider_id
        for subject_id, provider_id in result.items()
    ):
        _fail(f"{context} choices are malformed")
    return result


def build_implementation_selection_v2(
    *, linked_semantic_module: LinkedSemanticModuleV2,
    qualifications: Sequence[SemanticProviderQualificationV2],
    definition_choices: Mapping[str, str] | None = None,
    obligation_choices: Mapping[str, str] | None = None,
    mode: str = "faithful",
) -> dict[str, Any]:
    if mode not in _MODES:
        _fail("implementation-selection V2 mode is unsupported")
    explicit_definitions = _choices(
        definition_choices, "definition selection V2"
    )
    explicit_obligations = _choices(
        obligation_choices, "obligation selection V2"
    )
    definitions = {
        str(row["definition_id"]): row
        for row in linked_semantic_module.payload["definitions"]
    }
    requirements = {
        str(row["definition_id"]): row
        for row in linked_semantic_module.payload["definition_requirements"]
        if row.get("definition_id") is not None
    }
    obligations = {
        str(row["obligation_id"]): row
        for row in linked_semantic_module.payload["residual_obligations"]
    }
    qualifications_by_id: dict[
        str, list[SemanticProviderQualificationV2]
    ] = {}
    for qualification in qualifications:
        qualifications_by_id.setdefault(
            qualification.provider_id, []
        ).append(qualification)
    definition_materializations = {
        qualification.identity: {
            str(row["definition_id"]): row
            for row in qualification.payload["definition_materializations"]
        }
        for qualification in qualifications
    }
    obligation_implementations = {
        qualification.identity: {
            str(row["obligation_id"]): row
            for row in qualification.payload["obligation_implementations"]
        }
        for qualification in qualifications
    }

    blockers: list[dict[str, Any]] = []
    selected_qualification_sha256s: set[str] = set()
    admission: dict[str, bool] = {}

    def resolve(
        *, provider_id: str, subject_kind: str, subject_id: str,
    ) -> SemanticProviderQualificationV2 | None:
        matches = qualifications_by_id.get(provider_id, [])
        selected_qualification_sha256s.update(item.identity for item in matches)
        if not matches:
            blockers.append({
                "code": "selected_provider_qualification_missing",
                "provider_id": provider_id,
                f"{subject_kind}_id": subject_id,
            })
            return None
        if len(matches) != 1:
            blockers.append({
                "code": "selected_provider_qualification_ambiguous",
                "provider_id": provider_id,
                f"{subject_kind}_id": subject_id,
            })
            return None
        qualification = matches[0]
        if qualification.identity not in admission:
            semantic_slice = qualification.semantic_slice
            try:
                current_slice = build_semantic_slice_v2(
                    linked_semantic_module=linked_semantic_module,
                    definition_ids=[
                        str(row["definition_id"])
                        for row in semantic_slice.payload["definitions"]
                    ],
                    obligation_ids=[
                        str(row["obligation_id"])
                        for row in semantic_slice.payload["obligations"]
                    ],
                )
                admission[qualification.identity] = (
                    current_slice["semantic_slice_sha256"]
                    == semantic_slice.identity
                )
            except SemanticSliceV2Error:
                admission[qualification.identity] = False
        if not admission[qualification.identity]:
            blockers.append({
                "code": "provider_qualification_slice_stale",
                "provider_id": provider_id,
                "qualification_sha256": qualification.identity,
            })
            return None
        if qualification.payload["status"] != "complete":
            blockers.append({
                "code": "provider_qualification_incomplete",
                "provider_id": provider_id,
                "qualification_sha256": qualification.identity,
            })
        return qualification

    definition_selections: list[dict[str, Any]] = []
    for definition_id, requirement in sorted(requirements.items()):
        provider_id = explicit_definitions.get(definition_id)
        if provider_id is None:
            blockers.append({
                "code": "definition_selection_missing",
                "definition_id": definition_id,
                "symbol_id": requirement["symbol_id"],
            })
            continue
        qualification = resolve(
            provider_id=provider_id, subject_kind="definition",
            subject_id=definition_id,
        )
        if qualification is None:
            continue
        materialization = definition_materializations[
            qualification.identity
        ].get(definition_id)
        if materialization is None:
            blockers.append({
                "code": "selected_provider_definition_missing",
                "definition_id": definition_id,
                "provider_id": provider_id,
            })
            continue
        provider_kind = qualification.provider_kind
        if provider_kind not in requirement["allowed_provider_kinds"]:
            blockers.append({
                "code": "selected_provider_kind_not_allowed",
                "definition_id": definition_id,
                "provider_id": provider_id,
                "provider_kind": provider_kind,
            })
            continue
        definition = definitions[definition_id]
        if (
            mode == "faithful"
            and definition["definition_kind"] == "transfer_v2"
            and provider_kind != "generated_behavioral_c"
        ):
            blockers.append({
                "code": "faithful_mode_original_definition_not_generated",
                "definition_id": definition_id,
                "provider_id": provider_id,
            })
            continue
        if mode == "portable" and provider_kind == "generated_behavioral_c":
            blockers.append({
                "code": "portable_mode_generated_behavioral_c",
                "definition_id": definition_id,
                "provider_id": provider_id,
            })
            continue
        definition_selections.append({
            "definition_id": definition_id,
            "symbol_id": requirement["symbol_id"],
            "provider_id": provider_id,
            "provider_kind": provider_kind,
            "qualification_sha256": qualification.identity,
            "native_symbol": materialization["native_symbol"],
        })

    obligation_selections: list[dict[str, Any]] = []
    for obligation_id, obligation in sorted(obligations.items()):
        provider_id = explicit_obligations.get(obligation_id)
        if provider_id is None:
            blockers.append({
                "code": "obligation_selection_missing",
                "obligation_id": obligation_id,
            })
            continue
        qualification = resolve(
            provider_id=provider_id, subject_kind="obligation",
            subject_id=obligation_id,
        )
        if qualification is None:
            continue
        implementation = obligation_implementations[
            qualification.identity
        ].get(obligation_id)
        if implementation is None:
            blockers.append({
                "code": "selected_provider_obligation_missing",
                "obligation_id": obligation_id,
                "provider_id": provider_id,
            })
            continue
        provider_kind = qualification.provider_kind
        if provider_kind not in obligation["allowed_provider_kinds"]:
            blockers.append({
                "code": "selected_provider_kind_not_allowed",
                "obligation_id": obligation_id,
                "provider_id": provider_id,
                "provider_kind": provider_kind,
            })
            continue
        obligation_selections.append({
            "obligation_id": obligation_id,
            "provider_id": provider_id,
            "provider_kind": provider_kind,
            "qualification_sha256": qualification.identity,
            "native_symbol": implementation["native_symbol"],
            "receipt_sha256": implementation["receipt_sha256"],
        })

    for definition_id in sorted(set(explicit_definitions) - set(requirements)):
        blockers.append({
            "code": "definition_selection_extra",
            "definition_id": definition_id,
        })
    for obligation_id in sorted(set(explicit_obligations) - set(obligations)):
        blockers.append({
            "code": "obligation_selection_extra",
            "obligation_id": obligation_id,
        })
    unavailable = [
        row for row in linked_semantic_module.payload["definition_requirements"]
        if row.get("definition_id") is None
    ]
    blockers.extend({
        "code": "definition_unavailable", "symbol_id": row["symbol_id"],
    } for row in unavailable)
    if (
        linked_semantic_module.payload.get("status") != "complete"
        or linked_semantic_module.payload.get("semantic_holes")
    ):
        blockers.append({"code": "linked_semantic_module_incomplete"})

    blockers = _canonical_rows(blockers)
    core = {
        "format": IMPLEMENTATION_SELECTION_V2_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "ready_for_realization": not blockers,
        "mode": mode,
        "bindings": {
            "linked_semantic_module_sha256": linked_semantic_module.identity,
        },
        "qualification_sha256s": sorted(selected_qualification_sha256s),
        "definition_selections": sorted(
            definition_selections, key=lambda row: row["definition_id"]
        ),
        "obligation_selections": sorted(
            obligation_selections, key=lambda row: row["obligation_id"]
        ),
        "blockers": blockers,
    }
    payload = {**core, "selection_sha256": canonical_sha256_v3(core)}
    return dict(ImplementationSelectionV2.parse(payload).payload)


def write_implementation_selection_v2(
    *, out: Path, **arguments: Any,
) -> None:
    write_json(Path(out), build_implementation_selection_v2(**arguments))


__all__ = [
    "ImplementationSelectionV2",
    "ImplementationSelectionV2Error",
    "build_implementation_selection_v2",
    "write_implementation_selection_v2",
]
