"""Content-addressed semantic slices over linked-semantic-module-v2."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..util import write_json
from .formats import SEMANTIC_SLICE_V2_FORMAT


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = {
    "format", "definitions", "obligations", "dependency_contract_sha256s",
    "semantic_slice_sha256",
}


class SemanticSliceV2Error(ValueError):
    """A semantic slice is malformed, stale, or names unknown semantics."""


def _fail(message: str) -> None:
    raise SemanticSliceV2Error(message)


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


def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{context} must be lowercase SHA-256")
    return value


def _dependency_hashes(values: object) -> list[str]:
    if not isinstance(values, list):
        _fail("semantic dependency inventory must be an array")
    result = []
    for value in values:
        if not isinstance(value, str) or not value:
            _fail("semantic dependency identity must be nonempty text")
        candidate = value.rsplit(":", 1)[-1]
        if _SHA256.fullmatch(candidate) is None:
            _fail("semantic dependency identity has no content hash")
        result.append(candidate)
    return sorted(set(result))


@dataclass(frozen=True)
class SemanticSliceV2:
    payload: Mapping[str, Any]

    @property
    def identity(self) -> str:
        return str(self.payload["semantic_slice_sha256"])

    @classmethod
    def parse(cls, value: object) -> "SemanticSliceV2":
        payload = dict(_mapping(value, "semantic slice V2"))
        if set(payload) != _FIELDS:
            _fail("semantic-slice V2 fields are incomplete")
        if payload.get("format") != SEMANTIC_SLICE_V2_FORMAT:
            _fail("semantic-slice V2 format is unsupported")
        identity = _sha256(
            payload.get("semantic_slice_sha256"), "semantic-slice identity"
        )
        if identity != canonical_sha256_v3({
            key: item for key, item in payload.items()
            if key != "semantic_slice_sha256"
        }):
            _fail("semantic-slice V2 self hash is stale")
        definitions = _rows(payload.get("definitions"), "slice definitions")
        definition_ids = []
        dependencies: set[str] = set()
        for row in definitions:
            if set(row) != {
                "definition_id", "symbol_id", "definition_kind",
                "definition_sha256", "dependency_contract_sha256s",
                "allowed_provider_kinds",
            }:
                _fail("slice-definition fields are incomplete")
            definition_id = row.get("definition_id")
            if not isinstance(definition_id, str) or not definition_id:
                _fail("slice-definition identity is malformed")
            _sha256(row.get("definition_sha256"), "slice definition hash")
            row_dependencies = row.get("dependency_contract_sha256s")
            if (
                not isinstance(row_dependencies, list)
                or row_dependencies != sorted(set(row_dependencies))
                or any(
                    _sha256(item, "definition dependency") != item
                    for item in row_dependencies
                )
            ):
                _fail("slice-definition dependencies are malformed")
            definition_ids.append(definition_id)
            providers = row.get("allowed_provider_kinds")
            if (
                not isinstance(providers, list) or not providers
                or providers != sorted(set(providers))
                or any(not isinstance(item, str) or not item for item in providers)
            ):
                _fail("slice-definition provider kinds are malformed")
            dependencies.update(row_dependencies)
        if definition_ids != sorted(set(definition_ids)):
            _fail("slice definitions are noncanonical or duplicated")

        obligations = _rows(payload.get("obligations"), "slice obligations")
        obligation_ids = []
        for row in obligations:
            if set(row) != {
                "obligation_id", "class", "semantic_contract_sha256",
                "admitted_domain_sha256", "dependency_contract_sha256s",
                "allowed_provider_kinds",
            }:
                _fail("slice-obligation fields are incomplete")
            obligation_id = row.get("obligation_id")
            if not isinstance(obligation_id, str) or not obligation_id:
                _fail("slice-obligation identity is malformed")
            _sha256(
                row.get("semantic_contract_sha256"),
                "slice obligation contract",
            )
            _sha256(
                row.get("admitted_domain_sha256"),
                "slice obligation admitted domain",
            )
            row_dependencies = row.get("dependency_contract_sha256s")
            if (
                not isinstance(row_dependencies, list)
                or row_dependencies != sorted(set(row_dependencies))
                or any(
                    _sha256(item, "obligation dependency") != item
                    for item in row_dependencies
                )
            ):
                _fail("slice-obligation dependencies are malformed")
            obligation_ids.append(obligation_id)
            providers = row.get("allowed_provider_kinds")
            if (
                not isinstance(providers, list) or not providers
                or providers != sorted(set(providers))
                or any(not isinstance(item, str) or not item for item in providers)
            ):
                _fail("slice-obligation provider kinds are malformed")
            dependencies.update(row_dependencies)
        if obligation_ids != sorted(set(obligation_ids)):
            _fail("slice obligations are noncanonical or duplicated")
        if not definitions and not obligations:
            _fail("semantic slice cannot be empty")
        declared_dependencies = payload.get("dependency_contract_sha256s")
        if declared_dependencies != sorted(dependencies):
            _fail("semantic-slice dependency catalog is stale")
        return cls(payload)

    @classmethod
    def load(cls, path: Path) -> "SemanticSliceV2":
        return cls.parse(json.loads(Path(path).read_text(encoding="utf-8")))


def build_semantic_slice_v2(
    *, linked_semantic_module: LinkedSemanticModuleV2,
    definition_ids: Sequence[str] = (), obligation_ids: Sequence[str] = (),
) -> dict[str, Any]:
    definitions = {
        str(row["definition_id"]): row
        for row in linked_semantic_module.payload["definitions"]
    }
    obligations = {
        str(row["obligation_id"]): row
        for row in linked_semantic_module.payload["residual_obligations"]
    }
    requirements = {
        str(row["definition_id"]): row
        for row in linked_semantic_module.payload["definition_requirements"]
        if row.get("definition_id") is not None
    }
    requested_definitions = sorted(set(definition_ids))
    requested_obligations = sorted(set(obligation_ids))
    unknown_definitions = sorted(set(requested_definitions) - set(definitions))
    unknown_obligations = sorted(set(requested_obligations) - set(obligations))
    if unknown_definitions or unknown_obligations:
        _fail(
            "semantic slice names unknown definitions or obligations: "
            f"definitions={unknown_definitions!r} obligations={unknown_obligations!r}"
        )
    inactive_definitions = sorted(
        set(requested_definitions) - set(requirements)
    )
    if inactive_definitions:
        _fail(
            "semantic slice names definitions outside active implementation "
            f"requirements: {inactive_definitions!r}"
        )
    definition_rows = [{
        **dict(definitions[item]),
        "allowed_provider_kinds": list(
            requirements[item]["allowed_provider_kinds"]
        ),
    } for item in requested_definitions]
    obligation_rows = []
    for obligation_id in requested_obligations:
        row = obligations[obligation_id]
        admitted_domain = _mapping(
            row.get("admitted_domain"), "obligation admitted domain"
        )
        obligation_rows.append({
            "obligation_id": obligation_id,
            "class": row["class"],
            "semantic_contract_sha256": row["semantic_contract_sha256"],
            "admitted_domain_sha256": canonical_sha256_v3(dict(admitted_domain)),
            "dependency_contract_sha256s": _dependency_hashes(
                row["evidence_dependencies"]
            ),
            "allowed_provider_kinds": list(row["allowed_provider_kinds"]),
        })
    dependencies = sorted({
        item
        for row in [*definition_rows, *obligation_rows]
        for item in row["dependency_contract_sha256s"]
    })
    core = {
        "format": SEMANTIC_SLICE_V2_FORMAT,
        "definitions": definition_rows,
        "obligations": obligation_rows,
        "dependency_contract_sha256s": dependencies,
    }
    payload = {**core, "semantic_slice_sha256": canonical_sha256_v3(core)}
    return dict(SemanticSliceV2.parse(payload).payload)


def write_semantic_slice_v2(*, out: Path, **arguments: Any) -> None:
    write_json(Path(out), build_semantic_slice_v2(**arguments))


__all__ = [
    "SemanticSliceV2", "SemanticSliceV2Error", "build_semantic_slice_v2",
    "write_semantic_slice_v2",
]
