"""Shared closed primitives for linked-semantic-module-v2."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.semantic_object import SemanticObjectV1
from .errors import LinkedSemanticModuleError

MAX_LINKED_SEMANTIC_MODULE_V2_BYTES = 256 * 1024 * 1024
MAX_LINKED_SEMANTIC_MODULE_V2_ROWS = 2_000_000
_FIELDS = {
    "format", "status", "authority", "bindings", "definitions", "roots",
    "active_symbols", "may_reach", "active_relocations", "active_objects",
    "effects", "definition_requirements", "residual_obligations",
    "admitted_domains", "semantic_holes", "analysis_frontiers",
    "link_provenance", "counts", "linked_semantic_module_sha256",
}
_PROVIDER_KINDS = frozenset({
    "generated_behavioral_c", "qualified_portable_c", "qualified_runtime",
    "external_environment", "pinned_binary",
})
_OBLIGATION_CLASSES = frozenset({
    "object_reference_resolution", "mapped_memory_access",
    "external_write_validation", "internal_code_dispatch",
    "indirect_external_callthrough", "callback_capability_publication",
    "loader_service_resolution", "guest_atomics", "lifecycle_cleanup",
    "checked_exceptions_outcomes", "tls", "private_stack_support",
    "checked_external_nonlocal_service",
    "checked_external_exception_object_service",
})
_LINK_FACT_FIELDS = frozenset({
    "bindings", "blockers", "link_provenance", "objects", "relocations",
    "roots", "symbols",
})


def _fail(message: str) -> None:
    raise LinkedSemanticModuleError(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _callable_external_contracts(
    environment: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    """Return the one checked catalog of statically and dynamically callable code.

    ``machine_import_contracts`` also preserves unresolved import identities so
    the environment can report stable, honest blockers.  Those rows have no
    physical frame and are not callable authority; their blockers become V2
    semantic holes through the ordinary linked-blocker path.  They must never
    enter the runtime's finite loader-capability domain.
    """

    result = []
    for raw in _rows(
        environment.get("machine_import_contracts"),
        "machine-import contracts",
    ):
        row = _mapping(raw, "machine-import contract")
        boundary = row.get("boundary")
        frame = (
            boundary.get("physical_call_frame_v3")
            if isinstance(boundary, Mapping) else None
        )
        if isinstance(frame, Mapping):
            result.append(row)
    for raw_service in _rows(
        environment.get("loader_service_contracts"), "loader-service contracts"
    ):
        service = _mapping(raw_service, "loader-service contract")
        catalog = service.get("resolution_catalog", [])
        if not isinstance(catalog, list):
            _fail("loader-service resolution catalog is malformed")
        for raw_target in catalog:
            target = _mapping(raw_target, "dynamic-export contract")
            boundary = target.get("boundary")
            frame = (
                boundary.get("physical_call_frame_v3")
                if isinstance(boundary, Mapping) else None
            )
            if (
                target.get("dynamic_export_kind") == "code"
                and isinstance(frame, Mapping)
            ):
                result.append(target)
    by_identity: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in result:
        identity = _mapping(row.get("identity"), "callable external identity")
        key = _import_identity_key(identity)
        if key is None:
            _fail("callable external contract has an invalid identity")
        prior = by_identity.get(key)
        if prior is not None and prior != row:
            _fail("callable external contracts duplicate an identity")
        by_identity[key] = row
    return [by_identity[key] for key in sorted(by_identity)]


def _rows(value: object, context: str) -> list[Any]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_LINKED_SEMANTIC_MODULE_V2_ROWS
    ):
        _fail(f"{context} must be a bounded array")
    return value


def _sha256(value: object, context: str) -> str:
    if (
        not isinstance(value, str) or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{context} must be lowercase SHA-256")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{context} must be nonempty text")
    return value


@dataclass(frozen=True)
class SemanticLinkFactsV2:
    """Checked conservative-link facts consumed by the V2 renderer.

    This is an internal carrier, not a serialized format or a second semantic
    language.  Keeping the field set closed makes it impossible for the V2
    renderer to inherit a partial V1 effect inventory accidentally.
    """

    payload: Mapping[str, Any]

    @classmethod
    def from_checked_link(
        cls, payload: Mapping[str, Any],
    ) -> "SemanticLinkFactsV2":
        missing = sorted(_LINK_FACT_FIELDS - payload.keys())
        if missing:
            _fail(f"semantic link facts are missing {missing!r}")
        facts = {key: payload[key] for key in sorted(_LINK_FACT_FIELDS)}
        return cls(payload=facts)


def _import_identity_key(value: Mapping[str, Any]) -> tuple[str, str] | None:
    dll = value.get("dll")
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    if not isinstance(dll, str) or not dll:
        return None
    if isinstance(symbol, str) and symbol:
        return dll.lower(), symbol
    if isinstance(ordinal, int) and not isinstance(ordinal, bool) and ordinal >= 0:
        return dll.lower(), f"ordinal:{ordinal}"
    return None


def _load_json(path: Path, context: str) -> dict[str, Any]:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_LINKED_SEMANTIC_MODULE_V2_BYTES:
            _fail(f"{context} exceeds the byte bound")
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    return dict(_mapping(value, context))


def _identity_rows(
    value: object, *, context: str, identity_field: str,
) -> list[Mapping[str, Any]]:
    rows = [
        _mapping(raw, context)
        for raw in _rows(value, f"{context} inventory")
    ]
    identities = [
        _text(row.get(identity_field), f"{context} identity") for row in rows
    ]
    if identities != sorted(set(identities)):
        _fail(f"{context} inventory is noncanonical or duplicated")
    return rows


def _definition_catalog(
    semantic: SemanticObjectV1,
) -> list[dict[str, Any]]:
    result = []
    defined_symbols: set[str] = set()
    evidence_rows = [
        dict(_mapping(raw, "semantic evidence"))
        for raw in semantic.payload["evidence"]
    ]
    evidence_sha256s = [canonical_sha256_v3(row) for row in evidence_rows]
    for raw in semantic.payload["definitions"]:
        definition = _mapping(raw, "semantic definition")
        symbol_id = _text(
            definition.get("symbol_id"), "semantic definition symbol"
        )
        definition_kind = _text(
            definition.get("definition_kind"), "semantic definition kind"
        )
        definition_sha256 = canonical_sha256_v3(dict(definition))
        dependency_contract_sha256s = sorted({
            evidence_sha256s[index]
            for index in definition.get("evidence_dependencies", [])
        })
        core = {
            "symbol_id": symbol_id,
            "definition_kind": definition_kind,
            "definition_sha256": definition_sha256,
            "dependency_contract_sha256s": dependency_contract_sha256s,
        }
        result.append({
            "definition_id": (
                f"semantic-definition-v2:{canonical_sha256_v3(core)}"
            ),
            **core,
        })
        defined_symbols.add(symbol_id)
    evidence_by_kind = {
        str(row["kind"]): index
        for index, row in enumerate(evidence_rows)
    }
    qualified_runtime_providers = {
        str(row.get("provider"))
        for row in (
            semantic.qualified_platform.get("runtime_provider_catalog", [])
            if semantic.qualified_platform is not None else []
        )
        if isinstance(row, Mapping) and row.get("layer") == "transfer_plan"
    }
    for raw in semantic.payload["symbols"]:
        symbol = _mapping(raw, "semantic symbol")
        symbol_id = str(symbol["symbol_id"])
        if symbol_id in defined_symbols:
            continue
        declaration = symbol.get("declaration")
        definition_kind: str | None = None
        dependencies: list[str] = []
        if (
            isinstance(declaration, Mapping)
            and isinstance(declaration.get("environment_contract_sha256"), str)
        ):
            definition_kind = "checked_external_contract"
            dependencies = [
                evidence_sha256s[evidence_by_kind["resolved_external_environment"]]
            ]
        elif (
            symbol.get("kind") == "runtime_primitive"
            and isinstance(declaration, Mapping)
            and declaration.get("provider_id") in qualified_runtime_providers
        ):
            definition_kind = "qualified_platform_primitive"
            dependencies = [evidence_sha256s[evidence_by_kind["qualified_platform"]]]
        if definition_kind is None:
            continue
        contract = {
            "symbol": dict(symbol),
            "definition_kind": definition_kind,
            "dependency_contract_sha256s": dependencies,
        }
        definition_sha256 = canonical_sha256_v3(contract)
        core = {
            "symbol_id": symbol_id,
            "definition_kind": definition_kind,
            "definition_sha256": definition_sha256,
            "dependency_contract_sha256s": dependencies,
        }
        result.append({
            "definition_id": (
                f"semantic-definition-v2:{canonical_sha256_v3(core)}"
            ),
            **core,
        })
    result.sort(key=lambda row: row["symbol_id"])
    return result

def _check_content_identity(
    row: Mapping[str, Any], *, identity_field: str, prefix: str,
) -> None:
    identity = _text(row.get(identity_field), identity_field)
    core = {key: value for key, value in row.items() if key != identity_field}
    if identity != f"{prefix}{canonical_sha256_v3(core)}":
        _fail(f"{identity_field} is stale")
