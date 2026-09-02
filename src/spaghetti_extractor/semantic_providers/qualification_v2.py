"""Closed qualification for one reusable linked-semantic-module V2 slice.

The qualification is deliberately module-independent.  It binds the semantic
contracts in a content-addressed slice, while implementation selection later
re-admits that slice against the current linked module.  Analysis-only module
changes therefore do not invalidate a proof, but changed definitions,
obligations, dependencies, admitted domains, or provider policy do.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import write_json
from .formats import SEMANTIC_PROVIDER_QUALIFICATION_V2_FORMAT
from .slices_v2 import SemanticSliceV2


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
SEMANTIC_PROVIDER_KINDS_V2 = frozenset({
    "external_environment",
    "generated_behavioral_c",
    "pinned_binary",
    "qualified_portable_c",
    "qualified_runtime",
})
_REQUIRED_FACETS = {
    "external_environment": frozenset({"external_contract"}),
    "generated_behavioral_c": frozenset({
        "compile", "native_objects", "ownership", "semantic_lowering",
        "source",
    }),
    "pinned_binary": frozenset({"native_objects", "pinned_layout"}),
    "qualified_portable_c": frozenset({
        "compile", "contextual_refinement", "induction", "lifecycle",
        "native_objects", "object_binding", "ownership", "relations",
        "services", "source",
    }),
    "qualified_runtime": frozenset({
        "reviewed_native_primitive", "runtime_qualification",
    }),
}
_SOURCE_KINDS = frozenset({
    "generated_behavioral_c", "qualified_portable_c", "qualified_runtime",
})
_OBJECT_KINDS = frozenset({
    "generated_behavioral_c", "pinned_binary", "qualified_portable_c",
    "qualified_runtime",
})
_TOOL_KINDS = _OBJECT_KINDS
_FIELDS = {
    "format", "status", "provider_id", "provider_kind", "bindings",
    "semantic_slice", "facets", "definition_materializations",
    "obligation_implementations", "tool_sha256s", "dependencies",
    "blockers", "qualification_sha256",
}


class SemanticProviderQualificationV2Error(ValueError):
    """A V2 provider qualification is malformed, stale, or incomplete."""


def _fail(message: str) -> None:
    raise SemanticProviderQualificationV2Error(message)


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


def _digests(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or value != sorted(set(value)):
        _fail(f"{context} must be a canonical digest inventory")
    for item in value:
        _digest(item, f"{context} entry")
    return list(value)


def _canonical_rows(
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        {canonical_sha256_v3(dict(row)): dict(row) for row in rows}.values(),
        key=canonical_sha256_v3,
    )


def _expected_blockers(
    *, provider_kind: str, semantic_slice: SemanticSliceV2,
    facets: Sequence[Mapping[str, Any]],
    definitions: Sequence[Mapping[str, Any]],
    obligations: Sequence[Mapping[str, Any]], tool_sha256s: Sequence[str],
) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    facet_status = {
        str(row.get("name")): row.get("status") for row in facets
    }
    for name in sorted(_REQUIRED_FACETS.get(provider_kind, ())):
        if name not in facet_status:
            expected.append({"code": "provider_facet_missing", "facet": name})
        elif facet_status[name] != "checked":
            expected.append({
                "code": "provider_facet_incomplete", "facet": name,
            })

    slice_definitions = {
        str(row["definition_id"]): row
        for row in semantic_slice.payload["definitions"]
    }
    materializations = {
        str(row["definition_id"]): row for row in definitions
    }
    for definition_id in sorted(set(slice_definitions) - set(materializations)):
        expected.append({
            "code": "provider_definition_missing",
            "definition_id": definition_id,
        })
    for definition_id in sorted(set(materializations) - set(slice_definitions)):
        expected.append({
            "code": "provider_definition_extra",
            "definition_id": definition_id,
        })
    for definition_id in sorted(set(slice_definitions) & set(materializations)):
        row = materializations[definition_id]
        contract = slice_definitions[definition_id]
        if provider_kind not in contract["allowed_provider_kinds"]:
            expected.append({
                "code": "provider_kind_not_allowed",
                "definition_id": definition_id,
                "provider_kind": provider_kind,
            })
        if provider_kind in _SOURCE_KINDS and not row["source_sha256s"]:
            expected.append({
                "code": "provider_definition_source_missing",
                "definition_id": definition_id,
            })
        if provider_kind in _OBJECT_KINDS and not row["object_sha256s"]:
            expected.append({
                "code": "provider_definition_object_missing",
                "definition_id": definition_id,
            })

    slice_obligations = {
        str(row["obligation_id"]): row
        for row in semantic_slice.payload["obligations"]
    }
    implementations = {
        str(row["obligation_id"]): row for row in obligations
    }
    for obligation_id in sorted(set(slice_obligations) - set(implementations)):
        expected.append({
            "code": "provider_obligation_missing",
            "obligation_id": obligation_id,
        })
    for obligation_id in sorted(set(implementations) - set(slice_obligations)):
        expected.append({
            "code": "provider_obligation_extra",
            "obligation_id": obligation_id,
        })
    for obligation_id in sorted(set(slice_obligations) & set(implementations)):
        row = implementations[obligation_id]
        contract = slice_obligations[obligation_id]
        if provider_kind not in contract["allowed_provider_kinds"]:
            expected.append({
                "code": "provider_kind_not_allowed",
                "obligation_id": obligation_id,
                "provider_kind": provider_kind,
            })
        if provider_kind in _SOURCE_KINDS and not row["source_sha256s"]:
            expected.append({
                "code": "provider_obligation_source_missing",
                "obligation_id": obligation_id,
            })
        if provider_kind in _OBJECT_KINDS and not row["object_sha256s"]:
            expected.append({
                "code": "provider_obligation_object_missing",
                "obligation_id": obligation_id,
            })
    if provider_kind in _TOOL_KINDS and not tool_sha256s:
        expected.append({"code": "provider_tool_identity_missing"})
    return _canonical_rows(expected)


@dataclass(frozen=True)
class SemanticProviderQualificationV2:
    payload: Mapping[str, Any]

    @property
    def identity(self) -> str:
        return str(self.payload["qualification_sha256"])

    @property
    def provider_id(self) -> str:
        return str(self.payload["provider_id"])

    @property
    def provider_kind(self) -> str:
        return str(self.payload["provider_kind"])

    @property
    def semantic_slice(self) -> SemanticSliceV2:
        return SemanticSliceV2.parse(self.payload["semantic_slice"])

    @classmethod
    def parse(cls, value: object) -> "SemanticProviderQualificationV2":
        payload = dict(_mapping(value, "semantic-provider qualification V2"))
        if set(payload) != _FIELDS:
            _fail("semantic-provider qualification V2 fields are incomplete")
        if payload.get("format") != SEMANTIC_PROVIDER_QUALIFICATION_V2_FORMAT:
            _fail("semantic-provider qualification V2 format is unsupported")
        identity = _digest(
            payload.get("qualification_sha256"), "qualification identity"
        )
        if identity != canonical_sha256_v3({
            key: item for key, item in payload.items()
            if key != "qualification_sha256"
        }):
            _fail("semantic-provider qualification V2 self hash is stale")
        provider_id = payload.get("provider_id")
        provider_kind = payload.get("provider_kind")
        if (
            not isinstance(provider_id, str)
            or _STABLE_ID.fullmatch(provider_id) is None
            or provider_kind not in SEMANTIC_PROVIDER_KINDS_V2
        ):
            _fail("semantic-provider V2 identity or kind is malformed")
        semantic_slice = SemanticSliceV2.parse(payload.get("semantic_slice"))
        bindings = _mapping(payload.get("bindings"), "provider V2 bindings")
        if set(bindings) != {
            "semantic_slice_sha256", "provider_artifact_sha256",
        }:
            _fail("semantic-provider V2 bindings are incomplete")
        if bindings.get("semantic_slice_sha256") != semantic_slice.identity:
            _fail("semantic-provider V2 slice binding is stale")
        _digest(
            bindings.get("provider_artifact_sha256"),
            "provider artifact binding",
        )

        facets = _rows(payload.get("facets"), "provider V2 facets")
        facet_names: list[str] = []
        for row in facets:
            if set(row) != {"name", "status", "receipt_sha256"}:
                _fail("semantic-provider V2 facet fields are incomplete")
            name = row.get("name")
            if (
                not isinstance(name, str) or not name
                or row.get("status") not in {
                    "checked", "incomplete", "not_applicable",
                }
            ):
                _fail("semantic-provider V2 facet is malformed")
            _digest(row.get("receipt_sha256"), "provider facet receipt")
            facet_names.append(name)
        if facet_names != sorted(set(facet_names)):
            _fail("semantic-provider V2 facets are noncanonical or duplicated")

        definitions = _rows(
            payload.get("definition_materializations"),
            "provider V2 definition materializations",
        )
        definition_ids: list[str] = []
        native_materializations: dict[
            str, tuple[tuple[str, ...], tuple[str, ...]]
        ] = {}
        for row in definitions:
            if set(row) != {
                "definition_id", "native_symbol", "source_sha256s",
                "object_sha256s",
            }:
                _fail("provider V2 definition materialization is incomplete")
            definition_id = row.get("definition_id")
            native_symbol = row.get("native_symbol")
            if (
                not isinstance(definition_id, str) or not definition_id
                or not isinstance(native_symbol, str) or not native_symbol
            ):
                _fail("provider V2 definition identity is malformed")
            sources = _digests(
                row.get("source_sha256s"), "provider definition sources"
            )
            objects = _digests(
                row.get("object_sha256s"), "provider definition objects"
            )
            definition_ids.append(definition_id)
            materialization = (tuple(sources), tuple(objects))
            previous = native_materializations.setdefault(
                native_symbol, materialization
            )
            if previous != materialization:
                _fail("shared native symbol has conflicting materialization")
        if definition_ids != sorted(set(definition_ids)):
            _fail("provider V2 definitions are noncanonical or duplicated")

        obligations = _rows(
            payload.get("obligation_implementations"),
            "provider V2 obligation implementations",
        )
        obligation_ids: list[str] = []
        for row in obligations:
            if set(row) != {
                "obligation_id", "native_symbol", "receipt_sha256",
                "source_sha256s", "object_sha256s",
            }:
                _fail("provider V2 obligation implementation is incomplete")
            obligation_id = row.get("obligation_id")
            native_symbol = row.get("native_symbol")
            if (
                not isinstance(obligation_id, str) or not obligation_id
                or not isinstance(native_symbol, str) or not native_symbol
            ):
                _fail("provider V2 obligation identity is malformed")
            _digest(row.get("receipt_sha256"), "obligation receipt")
            sources = _digests(
                row.get("source_sha256s"), "provider obligation sources"
            )
            objects = _digests(
                row.get("object_sha256s"), "provider obligation objects"
            )
            obligation_ids.append(obligation_id)
            materialization = (tuple(sources), tuple(objects))
            previous = native_materializations.setdefault(
                native_symbol, materialization
            )
            if previous != materialization:
                _fail("shared native symbol has conflicting materialization")
        if obligation_ids != sorted(set(obligation_ids)):
            _fail("provider V2 obligations are noncanonical or duplicated")

        tool_sha256s = _digests(
            payload.get("tool_sha256s"), "provider tool identities"
        )
        dependencies = payload.get("dependencies")
        if (
            not isinstance(dependencies, list)
            or dependencies != sorted(set(dependencies))
            or any(not isinstance(item, str) or not item for item in dependencies)
        ):
            _fail("semantic-provider V2 dependencies are noncanonical")
        blockers = _rows(payload.get("blockers"), "provider V2 blockers")
        if blockers != _canonical_rows(blockers) or any(
            not isinstance(row.get("code"), str) or not row["code"]
            for row in blockers
        ):
            _fail("semantic-provider V2 blockers are malformed")
        required_blockers = _expected_blockers(
            provider_kind=str(provider_kind), semantic_slice=semantic_slice,
            facets=facets, definitions=definitions, obligations=obligations,
            tool_sha256s=tool_sha256s,
        )
        blocker_hashes = {canonical_sha256_v3(dict(row)) for row in blockers}
        if any(
            canonical_sha256_v3(row) not in blocker_hashes
            for row in required_blockers
        ):
            _fail("semantic-provider V2 blockers omit an incomplete proof")
        status = payload.get("status")
        if status not in {"complete", "incomplete"} or (
            status == "complete"
        ) != (not blockers):
            _fail("semantic-provider V2 status contradicts its blockers")
        return cls(payload)

    @classmethod
    def load(cls, path: Path) -> "SemanticProviderQualificationV2":
        return cls.parse(json.loads(Path(path).read_text(encoding="utf-8")))


def build_semantic_provider_qualification_v2(
    *, semantic_slice: SemanticSliceV2, provider_id: str, provider_kind: str,
    provider_artifact_sha256: str, facets: Sequence[Mapping[str, Any]],
    definition_materializations: Sequence[Mapping[str, Any]] = (),
    obligation_implementations: Sequence[Mapping[str, Any]] = (),
    tool_sha256s: Sequence[str] = (), dependencies: Sequence[str] = (),
    blockers: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    normalized_facets = sorted(
        (dict(row) for row in facets), key=lambda row: str(row.get("name"))
    )
    definitions = sorted(
        (dict(row) for row in definition_materializations),
        key=lambda row: str(row.get("definition_id")),
    )
    obligations = sorted(
        (dict(row) for row in obligation_implementations),
        key=lambda row: str(row.get("obligation_id")),
    )
    normalized_tools = sorted(set(tool_sha256s))
    derived_blockers = [dict(row) for row in blockers]
    derived_blockers.extend(_expected_blockers(
        provider_kind=provider_kind, semantic_slice=semantic_slice,
        facets=normalized_facets, definitions=definitions,
        obligations=obligations, tool_sha256s=normalized_tools,
    ))
    derived_blockers = _canonical_rows(derived_blockers)
    core = {
        "format": SEMANTIC_PROVIDER_QUALIFICATION_V2_FORMAT,
        "status": "complete" if not derived_blockers else "incomplete",
        "provider_id": provider_id,
        "provider_kind": provider_kind,
        "bindings": {
            "semantic_slice_sha256": semantic_slice.identity,
            "provider_artifact_sha256": provider_artifact_sha256,
        },
        "semantic_slice": dict(semantic_slice.payload),
        "facets": normalized_facets,
        "definition_materializations": definitions,
        "obligation_implementations": obligations,
        "tool_sha256s": normalized_tools,
        "dependencies": sorted(set(dependencies)),
        "blockers": derived_blockers,
    }
    payload = {**core, "qualification_sha256": canonical_sha256_v3(core)}
    return dict(SemanticProviderQualificationV2.parse(payload).payload)


def write_semantic_provider_qualification_v2(
    *, out: Path, **arguments: Any,
) -> None:
    write_json(Path(out), build_semantic_provider_qualification_v2(**arguments))


__all__ = [
    "SEMANTIC_PROVIDER_KINDS_V2",
    "SemanticProviderQualificationV2",
    "SemanticProviderQualificationV2Error",
    "build_semantic_provider_qualification_v2",
    "write_semantic_provider_qualification_v2",
]
