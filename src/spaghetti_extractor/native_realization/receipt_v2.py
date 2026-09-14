"""Exact native realization receipt for linked-semantic-module-v2.

The receipt is the sole selected-implementation/link/composition claim.  It
does not alter semantic definitions: it proves that every V2 selection and
residual-obligation provider is represented by the exact objects and native
symbols that entered one PE32 link.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.qualification_v2 import (
    SEMANTIC_PROVIDER_KINDS_V2,
    SemanticProviderQualificationV2,
)
from ..semantic_providers.selection_v2 import ImplementationSelectionV2
from ..semantic_providers.exact_context import exact_context_blockers
from ..semantic_providers.slices_v2 import SemanticSliceV2, SemanticSliceV2Error
from .context_link import ExactContextLinkError, validate_context_receipt, validate_realized_contexts
from ..util import sha256_file, write_json
from .formats import (
    NATIVE_REALIZATION_V2_FORMAT,
    PORTABLE_DISPATCH_LINK_RECEIPT_V1_FORMAT,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = {
    "format", "status", "ready_for_observation", "bindings", "providers",
    "definitions", "obligations", "native_objects", "bridges", "runtime",
    "link", "portable_dispatch_link_receipt", "loader_surface", "candidate",
    "pinned_code_layout_requirements", "blockers",
    "native_realization_sha256",
}
_OBJECT_ROLES = frozenset({
    "generated_behavioral_c", "portable_c", "original_storage", "runtime",
    "ingress", "loader_support",
})
_ADDRESS_KINDS = frozenset({
    "linked_rva", "loader_import", "loader_resolved_export", "object_anchor",
})
_PORTABLE_DISPATCH_POLICY = {
    "strong_module_registry_required_when_portable": True,
    "one_strong_implementation_symbol_per_entry": True,
    "exact_selected_object_membership_required": True,
    "contextual_bisimulation_authority_required": True,
    "weak_or_duplicate_fallback_forbidden": True,
    "source_only_authority": False,
}
_PORTABLE_REGISTRY_SYMBOLS = {
    "spx_region_override_count",
    "spx_region_override_lookup",
    "spx_region_overrides",
}


class NativeRealizationV2Error(ValueError):
    """A V2 realization is malformed, stale, incomplete, or overclaims."""


def _fail(message: str) -> None:
    raise NativeRealizationV2Error(message)


def _mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return dict(value)


def _rows(value: object, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(row, Mapping) for row in value
    ):
        _fail(f"{context} must be an array of objects")
    return [dict(row) for row in value]


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{context} must be nonempty text")
    return value


def _digest(value: object, context: str) -> str:
    text = _text(value, context)
    if _SHA256.fullmatch(text) is None:
        _fail(f"{context} must be a lowercase SHA-256")
    return text


def _uint(value: object, context: str, *, positive: bool = False) -> int:
    if (
        not isinstance(value, int) or isinstance(value, bool)
        or value < (1 if positive else 0)
    ):
        _fail(f"{context} must be an unsigned integer")
    return value


def _texts(value: object, context: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        _fail(f"{context} must be canonical text identities")
    return list(value)


def _digests(value: object, context: str) -> list[str]:
    result = _texts(value, context)
    for item in result:
        _digest(item, f"{context} entry")
    return result


def _canonical_rows(
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        {canonical_sha256_v3(dict(row)): dict(row) for row in rows}.values(),
        key=canonical_sha256_v3,
    )


def _address(value: object) -> dict[str, Any]:
    address = _mapping(value, "definition realization address")
    kind = address.get("kind")
    if kind not in _ADDRESS_KINDS:
        _fail("definition realization address kind is unsupported")
    if kind == "linked_rva":
        if set(address) != {"kind", "rva"}:
            _fail("linked-RVA address fields are incomplete")
        _uint(address.get("rva"), "linked RVA")
    elif kind == "loader_import":
        if set(address) != {"kind", "iat_rva"}:
            _fail("loader-import address fields are incomplete")
        _uint(address.get("iat_rva"), "loader import IAT RVA")
    elif kind == "loader_resolved_export":
        if set(address) != {
            "kind", "dll", "symbol", "ordinal",
            "loader_service_contract_sha256",
        }:
            _fail("loader-resolved-export address fields are incomplete")
        _text(address.get("dll"), "loader-resolved-export DLL")
        symbol = address.get("symbol")
        ordinal = address.get("ordinal")
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = (
            isinstance(ordinal, int)
            and not isinstance(ordinal, bool)
            and ordinal >= 0
        )
        if has_symbol == has_ordinal:
            _fail(
                "loader-resolved export must name exactly one symbol or ordinal"
            )
        _digest(
            address.get("loader_service_contract_sha256"),
            "loader-resolved-export service contract",
        )
    else:
        if set(address) != {"kind", "object_id", "offset"}:
            _fail("object-anchor address fields are incomplete")
        _text(address.get("object_id"), "object anchor identity")
        _uint(address.get("offset"), "object anchor offset")
    return address


def _shared_surface(payload: Mapping[str, Any]) -> None:
    bridges = _rows(payload.get("bridges"), "V2 bridge classes")
    bridge_ids: list[str] = []
    bridge_rvas: list[int] = []
    for row in bridges:
        if set(row) != {
            "bridge_class_id", "native_symbol", "rva",
            "physical_frame_sha256", "capability_ids", "ingress_kinds",
        }:
            _fail("V2 bridge fields are incomplete")
        bridge_ids.append(_text(row.get("bridge_class_id"), "bridge identity"))
        _text(row.get("native_symbol"), "bridge native symbol")
        bridge_rvas.append(_uint(row.get("rva"), "bridge RVA"))
        _digest(row.get("physical_frame_sha256"), "bridge physical frame")
        _texts(row.get("capability_ids"), "bridge capabilities")
        _texts(row.get("ingress_kinds"), "bridge ingress kinds")
    if (
        bridge_ids != sorted(set(bridge_ids))
        or len(bridge_rvas) != len(set(bridge_rvas))
    ):
        _fail("V2 bridge inventory is noncanonical or ambiguous")

    link = _mapping(payload.get("link"), "V2 native link")
    if set(link) != {
        "payload_sha256", "linker_map_sha256", "relocation_inventory_sha256",
        "section_table_sha256", "entry_symbols",
    }:
        _fail("V2 native-link fields are incomplete")
    for field in (
        "payload_sha256", "linker_map_sha256", "relocation_inventory_sha256",
        "section_table_sha256",
    ):
        _digest(link.get(field), f"V2 native link {field}")
    _texts(link.get("entry_symbols"), "V2 native link entry symbols")

    loader = _mapping(payload.get("loader_surface"), "V2 loader surface")
    if set(loader) != {
        "entry_rva", "exports_sha256", "imports_sha256", "tls_sha256",
        "base_relocations_sha256", "resources_sha256", "load_config_sha256",
    }:
        _fail("V2 loader-surface fields are incomplete")
    if loader["entry_rva"] is not None:
        _uint(loader["entry_rva"], "V2 loader entry RVA")
    for field in (
        "exports_sha256", "imports_sha256", "tls_sha256",
        "base_relocations_sha256",
    ):
        _digest(loader.get(field), f"V2 loader surface {field}")
    for field in ("resources_sha256", "load_config_sha256"):
        if loader[field] is not None:
            _digest(loader[field], f"V2 loader surface {field}")

    candidate = _mapping(payload.get("candidate"), "V2 candidate")
    if set(candidate) != {
        "filename", "sha256", "size", "module_interface_sha256",
    }:
        _fail("V2 candidate fields are incomplete")
    _text(candidate.get("filename"), "V2 candidate filename")
    _digest(candidate.get("sha256"), "V2 candidate hash")
    _uint(candidate.get("size"), "V2 candidate size", positive=True)
    _digest(candidate.get("module_interface_sha256"), "V2 candidate interface")

    pinned = _rows(
        payload.get("pinned_code_layout_requirements"),
        "V2 pinned code-layout requirements",
    )
    if pinned != _canonical_rows(pinned):
        _fail("V2 pinned code-layout requirements are noncanonical")


def _portable_dispatch_link_receipt(value: object) -> dict[str, Any]:
    receipt = _mapping(value, "portable dispatch link receipt")
    if set(receipt) != {
        "format", "status", "activation_authorized", "bindings", "registry",
        "entries", "policy", "blockers", "receipt_sha256",
    } or receipt.get("format") != PORTABLE_DISPATCH_LINK_RECEIPT_V1_FORMAT:
        _fail("portable dispatch link receipt fields are incomplete")
    identity = _digest(
        receipt.get("receipt_sha256"), "portable dispatch link receipt identity"
    )
    if identity != canonical_sha256_v3({
        key: item for key, item in receipt.items() if key != "receipt_sha256"
    }):
        _fail("portable dispatch link receipt self hash is stale")
    bindings = _mapping(
        receipt.get("bindings"), "portable dispatch link bindings"
    )
    if set(bindings) != {
        "implementation_selection_sha256", "payload_sha256",
        "linker_map_sha256",
    }:
        _fail("portable dispatch link bindings are incomplete")
    for field, digest in bindings.items():
        _digest(digest, f"portable dispatch link {field}")
    if receipt.get("policy") != _PORTABLE_DISPATCH_POLICY:
        _fail("portable dispatch link policy is unsupported")

    entries = _rows(receipt.get("entries"), "portable dispatch link entries")
    expected_entry_fields = {
        "component_id", "operation_id", "entry_unit_id", "owned_unit_ids",
        "entry_rva", "native_symbol", "provider_id", "qualification_sha256",
        "contextual_refinement_sha256", "contextual_proof_sha256",
        "provider_object_manifest_sha256", "implementation_source_sha256",
        "implementation_object_sha256", "linked_rva",
    }
    entry_keys: list[tuple[int, str, str, str]] = []
    owned: set[str] = set()
    for row in entries:
        if set(row) - {"exact_context"} != expected_entry_fields:
            _fail("portable dispatch link entry fields are incomplete")
        if "exact_context" in row:
            try:
                validate_context_receipt(row["exact_context"])
            except ExactContextLinkError as exc:
                _fail(str(exc))
        for field in (
            "component_id", "operation_id", "entry_unit_id", "native_symbol",
            "provider_id",
        ):
            _text(row.get(field), f"portable dispatch entry {field}")
        unit_ids = _texts(
            row.get("owned_unit_ids"), "portable dispatch owned units"
        )
        if row["entry_unit_id"] not in unit_ids or owned & set(unit_ids):
            _fail("portable dispatch owned-unit partition is ambiguous")
        owned.update(unit_ids)
        entry_rva = _uint(row.get("entry_rva"), "portable dispatch entry RVA")
        _uint(row.get("linked_rva"), "portable dispatch linked RVA", positive=True)
        for field in (
            "qualification_sha256", "contextual_refinement_sha256",
            "contextual_proof_sha256", "provider_object_manifest_sha256",
            "implementation_source_sha256", "implementation_object_sha256",
        ):
            _digest(row.get(field), f"portable dispatch entry {field}")
        entry_keys.append((
            entry_rva, str(row["provider_id"]), str(row["component_id"]),
            str(row["operation_id"]),
        ))
    if entry_keys != sorted(set(entry_keys)):
        _fail("portable dispatch link entries are noncanonical or duplicated")

    registry = receipt.get("registry")
    if entries:
        registry_row = _mapping(registry, "portable dispatch registry")
        if set(registry_row) != {
            "source_sha256", "object_sha256", "symbol_rvas",
        }:
            _fail("portable dispatch registry fields are incomplete")
        _digest(registry_row.get("source_sha256"), "dispatch registry source")
        _digest(registry_row.get("object_sha256"), "dispatch registry object")
        symbol_rvas = _mapping(
            registry_row.get("symbol_rvas"), "dispatch registry symbols"
        )
        if set(symbol_rvas) != _PORTABLE_REGISTRY_SYMBOLS:
            _fail("portable dispatch registry symbol inventory is incomplete")
        for symbol, rva in symbol_rvas.items():
            _uint(rva, f"portable dispatch registry symbol {symbol}", positive=True)
    elif registry is not None:
        _fail("empty portable dispatch receipt carries a registry")

    blockers = _rows(receipt.get("blockers"), "portable dispatch blockers")
    if blockers != _canonical_rows(blockers) or any(
        not isinstance(row.get("code"), str) or not row["code"]
        for row in blockers
    ):
        _fail("portable dispatch blockers are malformed")
    status = receipt.get("status")
    authorized = receipt.get("activation_authorized")
    if (
        status not in {"complete", "incomplete"}
        or not isinstance(authorized, bool)
        or (status == "complete") != (not blockers)
        or authorized != (status == "complete")
    ):
        _fail("portable dispatch link authority contradicts its blockers")
    return receipt


@dataclass(frozen=True)
class NativeRealizationV2:
    payload: Mapping[str, Any]

    @property
    def identity(self) -> str:
        return str(self.payload["native_realization_sha256"])

    @classmethod
    def parse(cls, value: object) -> "NativeRealizationV2":
        payload = _mapping(value, "native realization V2")
        if set(payload) != _FIELDS:
            _fail("native-realization V2 fields are incomplete")
        if payload.get("format") != NATIVE_REALIZATION_V2_FORMAT:
            _fail("native-realization V2 format is unsupported")
        identity = _digest(
            payload.get("native_realization_sha256"), "V2 realization identity"
        )
        if identity != canonical_sha256_v3({
            key: item for key, item in payload.items()
            if key != "native_realization_sha256"
        }):
            _fail("native-realization V2 self hash is stale")

        bindings = _mapping(payload.get("bindings"), "V2 realization bindings")
        if set(bindings) != {
            "linked_semantic_module_sha256",
            "implementation_selection_sha256", "qualified_platform_sha256",
            "original_module_interface_sha256",
        }:
            _fail("native-realization V2 bindings are incomplete")
        for field, digest in bindings.items():
            if field == "qualified_platform_sha256" and digest is None:
                continue
            _digest(digest, f"V2 realization {field}")

        providers = _rows(payload.get("providers"), "V2 realization providers")
        provider_ids: list[str] = []
        for row in providers:
            if set(row) - {"exact_context"} != {
                "provider_id", "provider_kind", "qualification_sha256",
                "artifact_sha256", "semantic_slice_sha256", "tool_sha256s",
                "definition_ids", "obligation_ids",
            }:
                _fail("V2 realization provider fields are incomplete")
            if "exact_context" in row:
                try:
                    context = SemanticSliceV2.parse(row["exact_context"])
                except SemanticSliceV2Error as exc:
                    _fail(str(exc))
                if row["provider_kind"] != "qualified_portable_c" or context.payload["obligations"]:
                    _fail("V2 exact continuation provider context is invalid")
            provider_ids.append(_text(row.get("provider_id"), "V2 provider"))
            if row.get("provider_kind") not in SEMANTIC_PROVIDER_KINDS_V2:
                _fail("V2 realization provider kind is unsupported")
            for field in (
                "qualification_sha256", "artifact_sha256",
                "semantic_slice_sha256",
            ):
                _digest(row.get(field), f"V2 provider {field}")
            _digests(row.get("tool_sha256s"), "V2 provider tools")
            _texts(row.get("definition_ids"), "V2 provider definitions")
            _texts(row.get("obligation_ids"), "V2 provider obligations")
        if provider_ids != sorted(set(provider_ids)) or not providers:
            _fail("V2 realization providers are noncanonical or empty")

        definitions = _rows(
            payload.get("definitions"), "V2 realized definitions"
        )
        definition_ids: list[str] = []
        for row in definitions:
            if set(row) != {
                "definition_id", "symbol_id", "provider_id", "provider_kind",
                "qualification_sha256", "native_symbol", "address",
                "implementation_rva", "bridge_class_id",
            }:
                _fail("V2 realized-definition fields are incomplete")
            definition_ids.append(_text(row.get("definition_id"), "definition"))
            for field in ("symbol_id", "provider_id", "native_symbol"):
                _text(row.get(field), f"V2 definition {field}")
            if row.get("provider_kind") not in SEMANTIC_PROVIDER_KINDS_V2:
                _fail("V2 definition provider kind is unsupported")
            _digest(row.get("qualification_sha256"), "V2 definition qualification")
            address = _address(row.get("address"))
            if row["implementation_rva"] is not None:
                _uint(row["implementation_rva"], "V2 implementation RVA")
            if row["bridge_class_id"] is not None:
                _text(row["bridge_class_id"], "V2 definition bridge class")
            if address["kind"] == "loader_resolved_export" and (
                row.get("provider_kind") != "external_environment"
                or row["implementation_rva"] is not None
                or row["bridge_class_id"] is not None
            ):
                _fail(
                    "loader-resolved export must be an unbridged external "
                    "environment definition"
                )
        if definition_ids != sorted(set(definition_ids)) or not definitions:
            _fail("V2 realized definitions are noncanonical or empty")

        obligations = _rows(
            payload.get("obligations"), "V2 realized obligations"
        )
        obligation_ids: list[str] = []
        for row in obligations:
            if set(row) != {
                "obligation_id", "provider_id", "provider_kind",
                "qualification_sha256", "native_symbol", "receipt_sha256",
                "implementation_rva",
            }:
                _fail("V2 realized-obligation fields are incomplete")
            obligation_ids.append(_text(row.get("obligation_id"), "obligation"))
            for field in ("provider_id", "native_symbol"):
                _text(row.get(field), f"V2 obligation {field}")
            if row.get("provider_kind") not in SEMANTIC_PROVIDER_KINDS_V2:
                _fail("V2 obligation provider kind is unsupported")
            _digest(row.get("qualification_sha256"), "V2 obligation qualification")
            _digest(row.get("receipt_sha256"), "V2 obligation receipt")
            _uint(row.get("implementation_rva"), "V2 obligation implementation RVA")
        if obligation_ids != sorted(set(obligation_ids)):
            _fail("V2 realized obligations are noncanonical")

        objects = _rows(payload.get("native_objects"), "V2 native objects")
        object_hashes: list[str] = []
        for row in objects:
            if set(row) != {
                "object_sha256", "role", "provider_ids", "definition_ids",
                "obligation_ids", "section_ids",
            }:
                _fail("V2 native-object fields are incomplete")
            object_hashes.append(_digest(row.get("object_sha256"), "native object"))
            if row.get("role") not in _OBJECT_ROLES:
                _fail("V2 native-object role is unsupported")
            for field in (
                "provider_ids", "definition_ids", "obligation_ids", "section_ids",
            ):
                _texts(row.get(field), f"V2 native object {field}")
        if object_hashes != sorted(set(object_hashes)):
            _fail("V2 native-object inventory is noncanonical or ambiguous")

        portable_receipt = _portable_dispatch_link_receipt(
            payload.get("portable_dispatch_link_receipt")
        )
        portable_bindings = portable_receipt["bindings"]
        link = _mapping(payload.get("link"), "V2 native link")
        if (
            portable_bindings["implementation_selection_sha256"]
            != bindings["implementation_selection_sha256"]
            or portable_bindings["payload_sha256"] != link.get("payload_sha256")
            or portable_bindings["linker_map_sha256"]
            != link.get("linker_map_sha256")
        ):
            _fail("portable dispatch link receipt is stale for this realization")
        portable_definitions = [
            row for row in definitions
            if row["provider_kind"] == "qualified_portable_c"
        ]
        portable_entries = portable_receipt["entries"]
        try:
            validate_realized_contexts(entries=portable_entries, providers=providers, definitions=definitions, objects=objects,
                                      selection_sha256=bindings["implementation_selection_sha256"])
        except (ExactContextLinkError, SemanticSliceV2Error) as exc:
            _fail(str(exc))
        if bool(portable_definitions) != bool(portable_entries):
            _fail("portable dispatch link receipt coverage is incomplete")
        object_by_hash = {
            str(row["object_sha256"]): row for row in objects
        }
        registry = portable_receipt["registry"]
        if registry is not None and registry["object_sha256"] not in object_by_hash:
            _fail("portable dispatch registry object is absent from the link")
        for definition in portable_definitions:
            symbol_id = str(definition["symbol_id"])
            prefix = "original:function:"
            if not symbol_id.startswith(prefix):
                _fail("portable realization contains a non-transfer definition")
            unit_id = symbol_id[len(prefix) :]
            matches = [
                row for row in portable_entries
                if unit_id in row["owned_unit_ids"]
            ]
            if len(matches) != 1:
                _fail("portable definition has no unique linked dispatch entry")
            entry = matches[0]
            if any(
                definition.get(field) != entry.get(field)
                for field in (
                    "provider_id", "qualification_sha256", "native_symbol",
                )
            ) or definition.get("implementation_rva") != entry.get("linked_rva"):
                _fail("portable linked dispatch disagrees with its definition")
            implementation_object = object_by_hash.get(
                str(entry["implementation_object_sha256"])
            )
            if (
                implementation_object is None
                or entry["provider_id"]
                not in implementation_object["provider_ids"]
                or definition["definition_id"]
                not in implementation_object["definition_ids"]
            ):
                _fail("portable implementation object membership is incomplete")
        if portable_receipt["activation_authorized"] is not True:
            _fail("native realization carries unauthorized portable dispatch")

        runtime = _mapping(payload.get("runtime"), "V2 realization runtime")
        if set(runtime) != {
            "qualification_sha256", "tls_layout_sha256", "private_stack_size",
            "support_import_ids", "required_symbols",
            "obligation_receipt_sha256s",
        }:
            _fail("V2 realization runtime fields are incomplete")
        _digest(runtime.get("qualification_sha256"), "V2 runtime qualification")
        _digest(runtime.get("tls_layout_sha256"), "V2 runtime TLS layout")
        _uint(runtime.get("private_stack_size"), "V2 private stack", positive=True)
        _texts(runtime.get("support_import_ids"), "V2 runtime support imports")
        _digests(
            runtime.get("obligation_receipt_sha256s"),
            "V2 runtime obligation receipts",
        )
        required_symbols = _rows(
            runtime.get("required_symbols"), "V2 required runtime symbols"
        )
        symbol_names: list[str] = []
        for row in required_symbols:
            if set(row) != {"symbol", "rva", "role"}:
                _fail("V2 required runtime-symbol fields are incomplete")
            symbol_names.append(_text(row.get("symbol"), "runtime symbol"))
            _uint(row.get("rva"), "runtime symbol RVA")
            _text(row.get("role"), "runtime symbol role")
        if symbol_names != sorted(set(symbol_names)):
            _fail("V2 required runtime symbols are noncanonical")

        _shared_surface(payload)
        blockers = _rows(payload.get("blockers"), "V2 realization blockers")
        if blockers != _canonical_rows(blockers) or any(
            not isinstance(row.get("code"), str) or not row["code"]
            for row in blockers
        ):
            _fail("V2 realization blockers are malformed or noncanonical")
        status = payload.get("status")
        ready = payload.get("ready_for_observation")
        if (
            status not in {"complete", "incomplete"}
            or not isinstance(ready, bool)
            or (status == "complete") != (not blockers)
            or ready != (status == "complete")
        ):
            _fail("V2 realization readiness contradicts blockers")
        return cls(payload)

    @classmethod
    def load(cls, path: Path) -> "NativeRealizationV2":
        return cls.parse(json.loads(Path(path).read_text(encoding="utf-8")))


def build_native_realization_v2(
    *, linked_semantic_module: LinkedSemanticModuleV2,
    implementation_selection: ImplementationSelectionV2,
    qualified_platform_sha256: str | None,
    original_module_interface_sha256: str,
    providers: Sequence[Mapping[str, Any]],
    definitions: Sequence[Mapping[str, Any]],
    obligations: Sequence[Mapping[str, Any]],
    native_objects: Sequence[Mapping[str, Any]],
    bridges: Sequence[Mapping[str, Any]],
    runtime: Mapping[str, Any], link: Mapping[str, Any],
    portable_dispatch_link_receipt: Mapping[str, Any],
    loader_surface: Mapping[str, Any], candidate: Mapping[str, Any],
    pinned_code_layout_requirements: Sequence[Mapping[str, Any]] = (),
    blockers: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Build V2 and derive all selection/object/obligation completeness gates."""

    normalized_providers = sorted(
        (dict(row) for row in providers), key=lambda row: str(row["provider_id"])
    )
    normalized_definitions = sorted(
        (dict(row) for row in definitions),
        key=lambda row: str(row["definition_id"]),
    )
    normalized_obligations = sorted(
        (dict(row) for row in obligations),
        key=lambda row: str(row["obligation_id"]),
    )
    normalized_objects = sorted(
        (dict(row) for row in native_objects),
        key=lambda row: str(row["object_sha256"]),
    )
    normalized_bridges = sorted(
        (dict(row) for row in bridges),
        key=lambda row: str(row["bridge_class_id"]),
    )
    normalized_portable_dispatch = _portable_dispatch_link_receipt(
        portable_dispatch_link_receipt
    )
    derived = [dict(row) for row in blockers]
    if linked_semantic_module.payload.get("status") != "complete":
        derived.append({"code": "linked_semantic_module_incomplete"})
    if implementation_selection.payload.get("status") != "complete":
        derived.append({"code": "implementation_selection_incomplete"})
    if implementation_selection.payload["bindings"].get(
        "linked_semantic_module_sha256"
    ) != linked_semantic_module.identity:
        derived.append({"code": "implementation_selection_link_stale"})
    linked_bindings = linked_semantic_module.payload["bindings"]
    if linked_bindings.get("module_interface_sha256") != (
        original_module_interface_sha256
    ):
        derived.append({"code": "original_module_interface_binding_stale"})
    if qualified_platform_sha256 is None:
        derived.append({"code": "qualified_platform_binding_missing"})
    elif linked_bindings.get("qualified_platform_sha256") != (
        qualified_platform_sha256
    ):
        derived.append({"code": "qualified_platform_binding_stale"})

    provider_by_id = {
        str(row["provider_id"]): row for row in normalized_providers
    }
    selected_qualification_ids = set(
        implementation_selection.payload["qualification_sha256s"]
    )
    observed_qualification_ids = {
        str(row["qualification_sha256"]) for row in normalized_providers
    }
    if observed_qualification_ids != selected_qualification_ids:
        derived.append({"code": "selected_qualification_inventory_mismatch"})

    selected_definitions = {
        str(row["definition_id"]): row
        for row in implementation_selection.payload["definition_selections"]
    }
    realized_definitions = {
        str(row.get("definition_id")): row for row in normalized_definitions
    }
    for definition_id in sorted(set(selected_definitions) - set(realized_definitions)):
        derived.append({
            "code": "selected_definition_not_realized",
            "definition_id": definition_id,
        })
    for definition_id in sorted(set(realized_definitions) - set(selected_definitions)):
        derived.append({
            "code": "unselected_definition_realized",
            "definition_id": definition_id,
        })
    for definition_id in sorted(set(selected_definitions) & set(realized_definitions)):
        choice = selected_definitions[definition_id]
        realized = realized_definitions[definition_id]
        if any(realized.get(field) != choice.get(field) for field in (
            "definition_id", "symbol_id", "provider_id", "provider_kind",
            "qualification_sha256", "native_symbol",
        )):
            derived.append({
                "code": "realized_definition_selection_mismatch",
                "definition_id": definition_id,
            })
        provider = provider_by_id.get(str(choice["provider_id"]))
        if (
            provider is None
            or definition_id not in provider["definition_ids"]
            or provider["provider_kind"] != choice["provider_kind"]
            or provider["qualification_sha256"] != choice["qualification_sha256"]
        ):
            derived.append({
                "code": "realized_definition_provider_evidence_missing",
                "definition_id": definition_id,
            })

    selected_obligations = {
        str(row["obligation_id"]): row
        for row in implementation_selection.payload["obligation_selections"]
    }
    realized_obligations = {
        str(row.get("obligation_id")): row for row in normalized_obligations
    }
    for obligation_id in sorted(set(selected_obligations) - set(realized_obligations)):
        derived.append({
            "code": "selected_obligation_not_realized",
            "obligation_id": obligation_id,
        })
    for obligation_id in sorted(set(realized_obligations) - set(selected_obligations)):
        derived.append({
            "code": "unselected_obligation_realized",
            "obligation_id": obligation_id,
        })
    for obligation_id in sorted(set(selected_obligations) & set(realized_obligations)):
        choice = selected_obligations[obligation_id]
        realized = realized_obligations[obligation_id]
        if any(realized.get(field) != choice.get(field) for field in (
            "obligation_id", "provider_id", "provider_kind",
            "qualification_sha256", "native_symbol", "receipt_sha256",
        )):
            derived.append({
                "code": "realized_obligation_selection_mismatch",
                "obligation_id": obligation_id,
            })
        provider = provider_by_id.get(str(choice["provider_id"]))
        if (
            provider is None
            or obligation_id not in provider["obligation_ids"]
            or provider["provider_kind"] != choice["provider_kind"]
            or provider["qualification_sha256"] != choice["qualification_sha256"]
        ):
            derived.append({
                "code": "realized_obligation_provider_evidence_missing",
                "obligation_id": obligation_id,
            })

    object_by_hash = {
        str(row["object_sha256"]): row for row in normalized_objects
    }
    for provider in normalized_providers:
        for definition_id in provider["definition_ids"]:
            if definition_id not in selected_definitions:
                derived.append({
                    "code": "unselected_provider_definition_materialized",
                    "definition_id": definition_id,
                    "provider_id": provider["provider_id"],
                })
        for obligation_id in provider["obligation_ids"]:
            if obligation_id not in selected_obligations:
                derived.append({
                    "code": "unselected_provider_obligation_materialized",
                    "obligation_id": obligation_id,
                    "provider_id": provider["provider_id"],
                })
    for row in normalized_objects:
        for definition_id in row["definition_ids"]:
            if definition_id not in selected_definitions:
                derived.append({
                    "code": "native_object_definition_unselected",
                    "definition_id": definition_id,
                    "object_sha256": row["object_sha256"],
                })
        for obligation_id in row["obligation_ids"]:
            if obligation_id not in selected_obligations:
                derived.append({
                    "code": "native_object_obligation_unselected",
                    "obligation_id": obligation_id,
                    "object_sha256": row["object_sha256"],
                })

    # Each non-environment selected provider must own at least one linked
    # object, and every selected subject with object materialization must occur
    # on the exact object row.  The writer supplies the precise expected map.
    expected_objects = {
        str(row.get("object_sha256")): row
        for row in normalized_objects
        if row.get("provider_ids")
    }
    for provider in normalized_providers:
        if provider["provider_kind"] == "external_environment":
            continue
        if not any(provider["provider_id"] in row["provider_ids"] for row in expected_objects.values()):
            derived.append({
                "code": "selected_provider_object_not_linked",
                "provider_id": provider["provider_id"],
            })

    core = {
        "format": NATIVE_REALIZATION_V2_FORMAT,
        "status": "complete" if not derived else "incomplete",
        "ready_for_observation": not derived,
        "bindings": {
            "linked_semantic_module_sha256": linked_semantic_module.identity,
            "implementation_selection_sha256": implementation_selection.identity,
            "qualified_platform_sha256": qualified_platform_sha256,
            "original_module_interface_sha256": original_module_interface_sha256,
        },
        "providers": normalized_providers,
        "definitions": normalized_definitions,
        "obligations": normalized_obligations,
        "native_objects": normalized_objects,
        "bridges": normalized_bridges,
        "runtime": dict(runtime),
        "link": dict(link),
        "portable_dispatch_link_receipt": normalized_portable_dispatch,
        "loader_surface": dict(loader_surface),
        "candidate": dict(candidate),
        "pinned_code_layout_requirements": _canonical_rows(
            pinned_code_layout_requirements
        ),
        "blockers": _canonical_rows(derived),
    }
    payload = {
        **core, "native_realization_sha256": canonical_sha256_v3(core),
    }
    return dict(NativeRealizationV2.parse(payload).payload)


def write_native_realization_v2(
    *, linked_semantic_module: Path, implementation_selection: Path,
    provider_qualifications: Sequence[Path], candidate_module: Path,
    out: Path, **facts: Any,
) -> NativeRealizationV2:
    """Write V2 while checking selected package objects and candidate bytes."""

    linked = LinkedSemanticModuleV2.load(
        linked_semantic_module, require_complete=True
    )
    selection = ImplementationSelectionV2.load(implementation_selection)
    records = [
        (Path(path), SemanticProviderQualificationV2.load(Path(path)))
        for path in provider_qualifications
    ]
    qualifications = [item for _path, item in records]
    context_blockers = exact_context_blockers(
        qualifications=qualifications,
        definition_selections=selection.payload["definition_selections"], linked=linked,
        obligation_selections=selection.payload["obligation_selections"],
    )
    if context_blockers:
        _fail(f"V2 selected provider exact context is unsatisfied: {context_blockers}")
    if len({item.provider_id for item in qualifications}) != len(qualifications):
        _fail("V2 provider qualification identities are ambiguous")
    by_id = {item.provider_id: (path, item) for path, item in records}
    if {item.identity for item in qualifications} != set(
        selection.payload["qualification_sha256s"]
    ):
        _fail("V2 selected qualification inventory is not exact")

    available_objects_by_root = {
        path.parent: {
            sha256_file(candidate)
            for candidate in path.parent.rglob("*.o")
            if candidate.is_file()
        }
        for path, _qualification in records
    }
    materialization_indexes = {
        qualification.provider_id: {
            "definition_materializations": {
                str(row["definition_id"]): row
                for row in qualification.payload["definition_materializations"]
            },
            "obligation_implementations": {
                str(row["obligation_id"]): row
                for row in qualification.payload["obligation_implementations"]
            },
        }
        for _path, qualification in records
    }
    expected_objects: dict[str, dict[str, set[str]]] = {}
    for subject_kind, choices, materialization_field, identity_field in (
        (
            "definition", selection.payload["definition_selections"],
            "definition_materializations", "definition_id",
        ),
        (
            "obligation", selection.payload["obligation_selections"],
            "obligation_implementations", "obligation_id",
        ),
    ):
        for choice in choices:
            provider_id = str(choice["provider_id"])
            pair = by_id.get(provider_id)
            if pair is None:
                _fail(f"selected V2 provider qualification is absent: {provider_id}")
            path, qualification = pair
            subject_id = str(choice[identity_field])
            materialization = materialization_indexes[provider_id][
                materialization_field
            ].get(subject_id)
            if materialization is None:
                _fail(f"selected V2 {subject_kind} materialization is absent")
            available = available_objects_by_root[path.parent]
            for digest in materialization["object_sha256s"]:
                if digest not in available:
                    _fail(
                        "selected V2 provider object is absent from its package: "
                        f"{provider_id}:{subject_id}:{digest}"
                    )
                expected = expected_objects.setdefault(digest, {
                    "provider_ids": set(), "definition_ids": set(),
                    "obligation_ids": set(),
                })
                expected["provider_ids"].add(provider_id)
                expected[f"{subject_kind}_ids"].add(subject_id)

    native_objects = [dict(row) for row in facts.pop("native_objects")]
    linked_objects = {
        str(row["object_sha256"]): row for row in native_objects
    }
    for digest, expected in expected_objects.items():
        linked_row = linked_objects.get(digest)
        if linked_row is None:
            _fail(f"selected V2 provider object is absent from link: {digest}")
        for field in ("provider_ids", "definition_ids", "obligation_ids"):
            if not expected[field] <= set(linked_row[field]):
                _fail(
                    f"selected V2 provider object {field} binding is incomplete: "
                    f"{digest}"
                )

    providers = [{
        "provider_id": qualification.provider_id,
        "provider_kind": qualification.provider_kind,
        "qualification_sha256": qualification.identity,
        "artifact_sha256": qualification.payload["bindings"][
            "provider_artifact_sha256"
        ],
        "semantic_slice_sha256": qualification.semantic_slice.identity,
        "tool_sha256s": list(qualification.payload["tool_sha256s"]),
        "definition_ids": [
            str(row["definition_id"])
            for row in qualification.payload["definition_materializations"]
        ],
        "obligation_ids": [
            str(row["obligation_id"])
            for row in qualification.payload["obligation_implementations"]
        ],
        **({"exact_context": qualification.payload["exact_context"]} if "exact_context" in qualification.payload else {}),
    } for qualification in sorted(
        qualifications, key=lambda item: item.provider_id
    )]
    candidate = _mapping(facts.pop("candidate"), "V2 native candidate")
    module = Path(candidate_module)
    if (
        candidate.get("size") != module.stat().st_size
        or candidate.get("sha256") != sha256_file(module)
    ):
        _fail("V2 candidate facts do not match the exact module")
    payload = build_native_realization_v2(
        linked_semantic_module=linked,
        implementation_selection=selection,
        providers=providers,
        candidate=candidate,
        native_objects=native_objects,
        **facts,
    )
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "native-realization.json", payload)
    return NativeRealizationV2.parse(payload)


__all__ = [
    "NativeRealizationV2", "NativeRealizationV2Error",
    "build_native_realization_v2", "write_native_realization_v2",
]
