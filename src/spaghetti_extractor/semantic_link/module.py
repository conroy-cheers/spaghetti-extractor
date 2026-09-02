"""Checked joins for the construction-local semantic-link worklist.

This module contains no public artifact codec.  It joins the one transfer-v2
fixed point to semantic-object symbols, relocations, objects, effects, and
blockers, then returns only the closed facts consumed by
``linked-semantic-module-v2``.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..external.resolved import ResolvedExternalEnvironmentV1
from ..semantic_objects.semantic_object import SemanticObjectV1
from ..transfer.closure import (
    validate_module_execution_closure_v1,
)
from ..util import json_dumps, sha256_bytes, sha256_file
from .capabilities import (
    semantic_code_capabilities_v1 as _semantic_code_capabilities,
    semantic_export_capabilities_v1 as _semantic_export_capabilities,
)
from .errors import LinkedSemanticModuleError
from .import_uses import (
    bind_semantic_import_use_roots_v1 as _bind_semantic_import_use_roots_v1,
    semantic_import_uses_v1 as _semantic_import_uses_v1,
)
from .reference_facts import (
    empty_reference_facts_v1 as _empty_reference_facts_v1,
    check_native_link_facts_v1 as _check_native_link_facts_v1,
)


MAX_LINKED_SEMANTIC_ROWS = 2_000_000


def _fail(message: str) -> None:
    raise LinkedSemanticModuleError(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Any]:
    if not isinstance(value, list) or len(value) > MAX_LINKED_SEMANTIC_ROWS:
        _fail(f"{context} must be a bounded array")
    return value


def _payload_sha256(payload: Mapping[str, Any]) -> str:
    return sha256_bytes((json_dumps(dict(payload)) + "\n").encode("utf-8"))


def _identity_key(declaration: Mapping[str, Any]) -> tuple[str, str] | None:
    dll = declaration.get("dll")
    symbol = declaration.get("symbol")
    ordinal = declaration.get("ordinal")
    if not isinstance(dll, str) or not dll:
        return None
    if isinstance(symbol, str) and symbol:
        return dll.lower(), symbol
    if isinstance(ordinal, int) and not isinstance(ordinal, bool) and ordinal >= 0:
        return dll.lower(), f"ordinal:{ordinal}"
    return None


def _transfer_symbol_indexes(
    semantic: SemanticObjectV1,
) -> tuple[
    dict[str, tuple[str, int]], dict[str, str], dict[int, str],
]:
    """Read the exact transfer/symbol join from checked semantic definitions."""

    symbols = {
        str(_mapping(row, "semantic symbol")["symbol_id"]): _mapping(
            row, "semantic symbol"
        )
        for row in semantic.payload["symbols"]
    }
    by_symbol: dict[str, tuple[str, int]] = {}
    by_unit: dict[str, str] = {}
    by_rva: dict[int, str] = {}
    for raw in semantic.payload["definitions"]:
        definition = _mapping(raw, "semantic definition")
        if definition.get("definition_kind") != "transfer_v2":
            continue
        symbol_id = definition.get("symbol_id")
        body = _mapping(definition.get("body"), "transfer-v2 definition body")
        unit_id = body.get("transfer_id")
        symbol = symbols.get(str(symbol_id))
        rva = None if symbol is None else symbol.get("original_rva")
        if (
            not isinstance(symbol_id, str) or not symbol_id
            or not isinstance(unit_id, str) or not unit_id
            or symbol is None or symbol.get("kind") != "function"
            or not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
            or symbol_id in by_symbol or unit_id in by_unit or rva in by_rva
        ):
            _fail("semantic transfer definitions are malformed or duplicated")
        by_symbol[symbol_id] = (unit_id, rva)
        by_unit[unit_id] = symbol_id
        by_rva[rva] = symbol_id
    if len(by_symbol) != len(semantic.transfers):
        _fail("semantic definitions do not cover the exact transfer universe")
    return by_symbol, by_unit, by_rva


def _runtime_primitive_dependencies(
    semantic: SemanticObjectV1,
) -> list[Mapping[str, Any]]:
    effect_index = _mapping(
        semantic.payload.get("effect_index"), "semantic effect index"
    )
    rows = _rows(
        effect_index.get("runtime_primitive_dependencies"),
        "runtime-primitive dependencies",
    )
    transfer_by_symbol, _by_unit, _by_rva = _transfer_symbol_indexes(semantic)
    symbols = {
        str(_mapping(row, "semantic symbol")["symbol_id"]): _mapping(
            row, "semantic symbol"
        )
        for row in semantic.payload["symbols"]
    }
    previous: str | None = None
    result: list[Mapping[str, Any]] = []
    for raw in rows:
        row = _mapping(raw, "runtime-primitive dependency")
        provider = row.get("provider_id")
        target = row.get("target_symbol")
        sources = row.get("source_symbols")
        target_row = symbols.get(str(target))
        declaration = (
            target_row.get("declaration") if target_row is not None else None
        )
        if (
            set(row) != {"provider_id", "target_symbol", "source_symbols"}
            or not isinstance(provider, str) or not provider
            or previous is not None and provider <= previous
            or not isinstance(target, str) or not target
            or target_row is None or target_row.get("kind") != "runtime_primitive"
            or not isinstance(declaration, Mapping)
            or declaration.get("provider_id") != provider
            or not isinstance(sources, list) or not sources
            or sources != sorted(set(sources))
            or any(source not in transfer_by_symbol for source in sources)
        ):
            _fail("runtime-primitive dependencies are malformed or noncanonical")
        previous = provider
        result.append(row)
    return result


def _object_symbol_bindings(
    semantic: SemanticObjectV1,
) -> list[Mapping[str, Any]]:
    """Read the canonical object-rule to semantic-symbol relation."""

    effect_index = _mapping(
        semantic.payload.get("effect_index"), "semantic effect index"
    )
    rows = _rows(
        effect_index.get("object_symbol_bindings"), "object-symbol bindings"
    )
    symbols = {
        str(_mapping(row, "semantic symbol")["symbol_id"]): _mapping(
            row, "semantic symbol"
        )
        for row in semantic.payload["symbols"]
    }
    expected = []
    for rule in semantic.machine_object_authority.rules:
        candidate = f"original:object:{rule.identity}"
        expected.append({
            "object_id": rule.identity,
            "target_symbol": candidate if candidate in symbols else None,
        })
    result: list[Mapping[str, Any]] = []
    for raw in rows:
        row = _mapping(raw, "object-symbol binding")
        target = row.get("target_symbol")
        if (
            set(row) != {"object_id", "target_symbol"}
            or not isinstance(row.get("object_id"), str)
            or not row["object_id"]
            or target is not None and (
                not isinstance(target, str)
                or target not in symbols
                or symbols[target].get("kind") != "data"
            )
        ):
            _fail("object-symbol bindings are malformed")
        result.append(row)
    if [dict(row) for row in result] != expected:
        _fail("object-symbol bindings contradict object authority")
    return result


def _closure_contracts(
    closure: Mapping[str, Any],
) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for raw in closure["external_contracts"]:
        row = _mapping(raw, "reachable external contract")
        key = (str(row["dll"]).lower(), str(row["identity"]))
        if key in result:
            _fail("execution closure repeats an external contract")
        result.add(key)
    return result


def _root_provenance(
    semantic: SemanticObjectV1,
    closure: Mapping[str, Any],
) -> tuple[
    dict[str, set[str]], dict[int, tuple[str, ...]], dict[str, str],
    list[dict[str, Any]],
]:
    root_ids_by_rva_mutable: dict[int, set[str]] = {}
    root_symbol_by_id: dict[str, str] = {}
    root_symbol_by_rva: dict[int, str] = {}
    for raw in semantic.payload["roots"]:
        root = _mapping(raw, "semantic root")
        if root.get("kind") in {"data_export", "forwarder"}:
            # Loader-visible data/forwarder declarations are resolved by the
            # object-anchor and external-provider tables.  They do not seed
            # executable transfer reachability.
            continue
        rva = root.get("original_rva")
        root_id = root.get("root_id")
        target = root.get("target_symbol")
        if (
            not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
            or not isinstance(root_id, str) or not root_id
            or not isinstance(target, str) or not target
            or root_id in root_symbol_by_id
            or (
                rva in root_symbol_by_rva
                and root_symbol_by_rva[rva] != target
            )
        ):
            _fail("semantic-object roots are malformed or duplicated")
        root_ids_by_rva_mutable.setdefault(rva, set()).add(root_id)
        root_symbol_by_id[root_id] = target
        root_symbol_by_rva[rva] = target
    if set(closure["roots"]) != set(root_ids_by_rva_mutable):
        _fail("execution closure and semantic object disagree on roots")

    symbol_by_rva = {
        transfer.rva_start: f"original:function:{transfer.identity}"
        for transfer in semantic.transfers
    }
    callback_rvas = {
        int(rva)
        for row in closure["callback_escapes"]
        for rva in (_mapping(row, "callback escape").get("targets") or [])
    }
    witness_root_rvas = {
        int(_mapping(row, "execution witness")["root_rva"])
        for row in closure["witnesses"]
    }
    for rva in sorted(witness_root_rvas - set(root_ids_by_rva_mutable)):
        symbol_id = symbol_by_rva.get(rva)
        if symbol_id is None:
            _fail("discovered execution root has no semantic function symbol")
        kind = "callback" if rva in callback_rvas else "continuation"
        root_id = f"discovered:{kind}:{symbol_id}"
        root_ids_by_rva_mutable[rva] = {root_id}
        root_symbol_by_id[root_id] = symbol_id
        root_symbol_by_rva[rva] = symbol_id

    root_ids_by_rva = {
        rva: tuple(sorted(root_ids))
        for rva, root_ids in root_ids_by_rva_mutable.items()
    }

    roots_by_unit: dict[str, set[str]] = {}
    for raw in closure["witnesses"]:
        row = _mapping(raw, "execution witness")
        root_ids = root_ids_by_rva.get(row.get("root_rva"))
        unit_id = row.get("unit_id")
        if root_ids is None or not isinstance(unit_id, str):
            _fail("execution witness names an unknown semantic root or unit")
        roots_by_unit.setdefault(unit_id, set()).update(root_ids)
    for raw in closure["reachable_units"]:
        row = _mapping(raw, "reachable unit")
        unit_id = str(row["unit_id"])
        if unit_id not in roots_by_unit:
            _fail("reachable unit has no root-provenance witness")
    root_rows: list[dict[str, Any]] = []
    initial_by_id = {
        str(_mapping(row, "semantic root")["root_id"]): dict(row)
        for row in semantic.payload["roots"]
        if _mapping(row, "semantic root").get("kind")
        not in {"data_export", "forwarder"}
    }
    for rva, root_ids in root_ids_by_rva.items():
        for root_id in root_ids:
            if root_id in initial_by_id:
                root_rows.append({
                    **initial_by_id[root_id],
                    "origin": "module_interface",
                    "reachable": True,
                })
            else:
                root_rows.append({
                    "root_id": root_id,
                    "kind": (
                        "callback" if rva in callback_rvas else "continuation"
                    ),
                    "original_rva": rva,
                    "target_symbol": root_symbol_by_id[root_id],
                    "origin": "total_semantic_fixed_point",
                    "reachable": True,
                })
    root_rows.sort(key=lambda row: row["root_id"])
    return roots_by_unit, root_ids_by_rva, root_symbol_by_id, root_rows


def _effect_provenance(
    semantic: SemanticObjectV1,
    closure: Mapping[str, Any],
    roots_by_unit: Mapping[str, set[str]],
    root_ids_by_rva: Mapping[int, Sequence[str]],
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[tuple[str, str], set[str]],
    dict[str, set[str]],
    list[dict[str, Any]],
]:
    """Attach exact semantic-root provenance to every reachable effect.

    The transfer fixed point decides reachability.  This projection does not
    infer a second call graph: it joins the fixed point's reachable effect
    rows back to the transfer units and witnesses that produced them.
    """

    transfer_by_symbol, _symbol_by_unit, _symbol_by_rva = (
        _transfer_symbol_indexes(semantic)
    )
    roots_by_source_rva: dict[int, set[str]] = {
        rva: set(roots_by_unit.get(unit_id, ()))
        for unit_id, rva in transfer_by_symbol.values()
    }

    semantic_symbols = {
        str(_mapping(row, "semantic symbol")["symbol_id"]): _mapping(
            row, "semantic symbol"
        )
        for row in semantic.payload["symbols"]
    }
    for raw in semantic.payload["relocations"]:
        relocation = _mapping(raw, "semantic relocation")
        source = transfer_by_symbol.get(str(relocation.get("source_symbol")))
        site = relocation.get("site")
        instruction_rva = (
            site.get("instruction_rva") if isinstance(site, Mapping) else None
        )
        if source is not None and isinstance(instruction_rva, int):
            roots_by_source_rva.setdefault(instruction_rva, set()).update(
                roots_by_unit.get(source[0], ())
            )

    provider_roots: dict[str, set[str]] = {}
    external_roots: dict[tuple[str, str], set[str]] = {}
    for dependency in _runtime_primitive_dependencies(semantic):
        provider = str(dependency["provider_id"])
        for source_symbol in dependency["source_symbols"]:
            unit_id, _rva = transfer_by_symbol[str(source_symbol)]
            roots = roots_by_unit.get(unit_id, ())
            if roots:
                provider_roots.setdefault(provider, set()).update(roots)
    for raw in semantic.payload["relocations"]:
        relocation = _mapping(raw, "semantic relocation")
        source = transfer_by_symbol.get(str(relocation.get("source_symbol")))
        if source is None:
            continue
        roots = set(roots_by_unit.get(source[0], ()))
        if not roots:
            continue
        target_symbol = semantic_symbols.get(str(relocation.get("target_symbol")))
        declaration = (
            _mapping(target_symbol.get("declaration"), "semantic declaration")
            if target_symbol is not None
            and isinstance(target_symbol.get("declaration"), Mapping)
            else None
        )
        if relocation.get("kind") == "external_call":
            key = None if declaration is None else _identity_key(declaration)
            if key is None:
                _fail("external-call relocation has no external declaration")
            external_roots.setdefault(key, set()).update(roots)

    for raw in closure["indirect_targets"]:
        row = _mapping(raw, "indirect target set")
        roots = roots_by_source_rva.get(int(row["source_rva"]), set())
        for raw_external in row.get("external_targets") or []:
            external = _mapping(raw_external, "indirect external target")
            key = (
                str(external.get("dll", "")).lower(),
                str(external.get("identity", "")),
            )
            if all(key):
                external_roots.setdefault(key, set()).update(roots)

    blockers: list[dict[str, Any]] = []

    def root_ids_for(row: Mapping[str, Any]) -> list[str]:
        roots: set[str] = set()
        unit_id = row.get("unit_id")
        if isinstance(unit_id, str):
            roots.update(roots_by_unit.get(unit_id, ()))
        for field in ("source_rva", "instruction_rva"):
            rva = row.get(field)
            if isinstance(rva, int) and not isinstance(rva, bool):
                roots.update(roots_by_source_rva.get(rva, ()))
        for rva in row.get("root_rvas") or []:
            if isinstance(rva, int) and rva in root_ids_by_rva:
                roots.update(root_ids_by_rva[rva])
        return sorted(roots)

    def rows_with_roots(
        kind: str, rows: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for raw in rows:
            row = dict(_mapping(raw, f"{kind} effect"))
            root_ids = root_ids_for(row)
            result.append({**row, "root_ids": root_ids})
            if not root_ids:
                blockers.append({
                    "code": "reachable_effect_root_provenance_missing",
                    "effect_kind": kind,
                    "effect_sha256": canonical_sha256_v3(row),
                })
        return result

    declared_providers = set(closure["runtime_providers"])
    if not set(provider_roots) <= declared_providers:
        _fail("reachable transfer requires an undeclared runtime provider")
    runtime_rows = [
        {
            "provider_id": provider,
            "root_ids": sorted(provider_roots[provider]),
        }
        for provider in sorted(provider_roots)
    ]

    external_rows: list[dict[str, Any]] = []
    for raw in closure["external_contracts"]:
        row = dict(_mapping(raw, "external-contract effect"))
        key = (str(row["dll"]).lower(), str(row["identity"]))
        roots = sorted(external_roots.get(key, ()))
        external_rows.append({**row, "root_ids": roots})
        if not roots:
            blockers.append({
                "code": "reachable_effect_root_provenance_missing",
                "effect_kind": "external_contract",
                "dll": key[0],
                "identity": key[1],
            })

    effects = {
        "runtime_providers": runtime_rows,
        "external_contracts": external_rows,
        "indirect_targets": rows_with_roots(
            "indirect_target", closure["indirect_targets"]
        ),
        "callbacks": rows_with_roots(
            "callback", closure["callback_escapes"]
        ),
        "exceptions": rows_with_roots(
            "exception", closure["exception_continuations"]
        ),
        "nonlocal_transitions": rows_with_roots(
            "nonlocal_transition", closure["nonlocal_transitions"]
        ),
        "lifecycle": rows_with_roots(
            "lifecycle", closure["lifecycle_effects"]
        ),
    }
    return effects, external_roots, provider_roots, blockers
def _linked_edges(
    semantic: SemanticObjectV1,
    closure: Mapping[str, Any],
    edge_root_provenance: Sequence[Mapping[str, Any]],
    root_ids_by_rva: Mapping[int, Sequence[str]],
) -> list[dict[str, Any]]:
    symbol_by_rva = {
        transfer.rva_start: f"original:function:{transfer.identity}"
        for transfer in semantic.transfers
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    previous: tuple[int, int, str] | None = None
    for raw in edge_root_provenance:
        row = _mapping(raw, "semantic edge provenance")
        source_rva = row.get("source_rva")
        target_rva = row.get("target_rva")
        kind = row.get("kind")
        root_rvas = row.get("root_rvas")
        if (
            not isinstance(source_rva, int) or isinstance(source_rva, bool)
            or not isinstance(target_rva, int) or isinstance(target_rva, bool)
            or source_rva < 0 or target_rva < 0
            or source_rva not in symbol_by_rva
            or target_rva not in symbol_by_rva
            or not isinstance(kind, str) or not kind
            or not isinstance(root_rvas, list)
            or any(
                not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
                for rva in root_rvas
            )
            or root_rvas != sorted(set(root_rvas))
            or not root_rvas
            or any(rva not in root_ids_by_rva for rva in root_rvas)
        ):
            _fail("semantic edge provenance is malformed")
        identity = (source_rva, target_rva, kind)
        if previous is not None and identity <= previous:
            _fail("semantic edge provenance is noncanonical or duplicated")
        previous = identity
        core = {
            "kind": kind,
            "source_symbol": symbol_by_rva[source_rva],
            "target_symbol": symbol_by_rva[target_rva],
            "source_rva": source_rva,
            "target_rva": target_rva,
            "root_ids": sorted({
                root_id
                for rva in root_rvas
                for root_id in root_ids_by_rva[rva]
            }),
        }
        edge_id = f"semantic-edge:{canonical_sha256_v3(core)}"
        if edge_id in seen:
            _fail("semantic edge provenance is duplicated")
        seen.add(edge_id)
        result.append({"edge_id": edge_id, **core})
    if [
        {
            "source_rva": row["source_rva"],
            "target_rva": row["target_rva"],
            "kind": row["kind"],
        }
        for row in result
    ] != closure["reachable_edges"]:
        _fail("semantic edge provenance contradicts the transfer closure")
    return result


def _semantic_link_kernel_input_v1(
    semantic: SemanticObjectV1,
) -> dict[str, Any]:
    """Build the bounded private input for the existing native link pass.

    This projection contains no behavioral language and is not persisted as an
    artifact.  It transports already validated relocatable declarations into
    the same invocation that computes the transfer-v2 fixed point.
    """

    if semantic.resolved_external_environment is None:
        _fail("semantic link requires a resolved-environment semantic member")
    definitions = {
        str(_mapping(row, "semantic definition")["symbol_id"]): _mapping(
            row, "semantic definition"
        )
        for row in semantic.payload["definitions"]
    }
    transfer_by_symbol, _symbol_by_unit, _symbol_by_rva = (
        _transfer_symbol_indexes(semantic)
    )
    qualified_runtime_providers = {
        str(row.get("provider"))
        for row in (
            semantic.qualified_platform.get("runtime_provider_catalog", [])
            if semantic.qualified_platform is not None else []
        )
        if isinstance(row, Mapping) and row.get("layer") == "transfer_plan"
    }
    symbols: list[dict[str, Any]] = []
    for raw in semantic.payload["symbols"]:
        symbol = _mapping(raw, "semantic symbol")
        symbol_id = str(symbol["symbol_id"])
        declaration_value = symbol.get("declaration")
        declaration = (
            _mapping(declaration_value, "semantic symbol declaration")
            if isinstance(declaration_value, Mapping) else {}
        )
        transfer = transfer_by_symbol.get(symbol_id)
        external_key = (
            _identity_key(declaration)
            if symbol.get("linkage") == "external" else None
        )
        provider = (
            declaration.get("provider_id")
            if symbol.get("kind") == "runtime_primitive" else None
        )
        definition = definitions.get(symbol_id)
        contract_sha256 = declaration.get("environment_contract_sha256")
        symbols.append({
            "symbol_id": symbol_id,
            "kind": symbol.get("kind"),
            "linkage": symbol.get("linkage"),
            "original_rva": symbol.get("original_rva"),
            "unit_id": transfer[0] if transfer is not None else None,
            "definition_kind": (
                definition.get("definition_kind")
                if definition is not None else None
            ),
            "runtime_provider_id": provider,
            "external_dll": external_key[0] if external_key is not None else None,
            "external_identity": (
                external_key[1] if external_key is not None else None
            ),
            "checked_contract_sha256": (
                contract_sha256 if isinstance(contract_sha256, str) else None
            ),
            "loader_service_contract_sha256": (
                declaration.get("loader_service_contract_sha256")
                if isinstance(
                    declaration.get("loader_service_contract_sha256"), str
                ) else None
            ),
            "provider_qualified": (
                provider in qualified_runtime_providers
                if isinstance(provider, str) else None
            ),
        })

    relocations: list[dict[str, Any]] = []
    for raw in semantic.payload["relocations"]:
        relocation = _mapping(raw, "semantic relocation")
        site = relocation.get("site")
        relocations.append({
            "relocation_id": relocation.get("relocation_id"),
            "kind": relocation.get("kind"),
            "source_symbol": relocation.get("source_symbol"),
            "source_rva": relocation.get("source_rva"),
            "target_symbol": relocation.get("target_symbol"),
            "target_rva": relocation.get("target_rva"),
            "input_status": relocation.get("status"),
            "instruction_rva": (
                site.get("instruction_rva") if isinstance(site, Mapping) else None
            ),
        })
    objects = [
        {
            "object_id": row["object_id"],
            "semantic_symbol_id": row["target_symbol"],
        }
        for row in _object_symbol_bindings(semantic)
    ]
    return {
        "version": 2,
        "symbols": sorted(symbols, key=lambda row: row["symbol_id"]),
        "relocations": sorted(
            relocations, key=lambda row: row["relocation_id"]
        ),
        "objects": objects,
        "runtime_primitive_dependencies": [
            dict(row) for row in _runtime_primitive_dependencies(semantic)
        ],
    }


def _symbol_tables(
    semantic: SemanticObjectV1,
    closure: Mapping[str, Any],
    roots_by_unit: Mapping[str, set[str]],
    external_roots: Mapping[tuple[str, str], set[str]],
    provider_roots: Mapping[str, set[str]],
) -> tuple[
    list[dict[str, Any]], dict[int, str], set[str], list[dict[str, Any]],
]:
    definitions: dict[str, Mapping[str, Any]] = {}
    for raw in semantic.payload["definitions"]:
        row = _mapping(raw, "semantic definition")
        symbol_id = row.get("symbol_id")
        if not isinstance(symbol_id, str) or symbol_id in definitions:
            _fail("semantic object has malformed or duplicate definitions")
        definitions[symbol_id] = row

    unit_symbol_by_rva: dict[int, str] = {}
    unit_id_by_symbol: dict[str, str] = {}
    for transfer in semantic.transfers:
        symbol_id = f"original:function:{transfer.identity}"
        if transfer.rva_start in unit_symbol_by_rva:
            _fail("semantic object repeats a transfer RVA")
        unit_symbol_by_rva[transfer.rva_start] = symbol_id
        unit_id_by_symbol[symbol_id] = transfer.identity

    reachable_unit_ids = {
        str(_mapping(row, "reachable unit")["unit_id"])
        for row in closure["reachable_units"]
    }
    reachable_contracts = _closure_contracts(closure)
    qualified_runtime_providers = {
        str(row.get("provider"))
        for row in (
            semantic.qualified_platform.get("runtime_provider_catalog", [])
            if semantic.qualified_platform is not None else []
        )
        if isinstance(row, Mapping) and row.get("layer") == "transfer_plan"
    }
    linked_symbols: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    seen: set[str] = set()

    for raw in semantic.payload["symbols"]:
        symbol = _mapping(raw, "semantic symbol")
        symbol_id = symbol.get("symbol_id")
        if not isinstance(symbol_id, str) or not symbol_id or symbol_id in seen:
            _fail("semantic object has malformed or duplicate symbols")
        seen.add(symbol_id)
        unit_id = unit_id_by_symbol.get(symbol_id)
        reachable = unit_id in reachable_unit_ids if unit_id is not None else False
        root_ids = set(roots_by_unit.get(unit_id, ()))
        resolution: dict[str, Any]
        definition = definitions.get(symbol_id)
        if definition is not None:
            resolution = {
                "kind": "semantic_definition",
                "definition_kind": definition.get("definition_kind"),
            }
        elif symbol.get("kind") == "runtime_primitive":
            declaration = _mapping(symbol.get("declaration"), "runtime declaration")
            provider = declaration.get("provider_id")
            required = isinstance(provider, str) and provider in provider_roots
            reachable = required
            if isinstance(provider, str):
                root_ids.update(provider_roots.get(provider, ()))
            resolution = {
                "kind": "qualified_platform_primitive" if required else "unselected",
                "provider_id": provider,
            }
            if required and provider not in qualified_runtime_providers:
                blockers.append({
                    "code": "qualified_runtime_primitive_missing",
                    "symbol_id": symbol_id,
                    "provider_id": provider,
                })
        elif symbol.get("linkage") == "external":
            declaration = _mapping(symbol.get("declaration"), "external declaration")
            key = _identity_key(declaration)
            contract_sha256 = declaration.get("environment_contract_sha256")
            is_reachable = key in reachable_contracts if key is not None else False
            reachable = reachable or is_reachable
            if key is not None:
                root_ids.update(external_roots.get(key, ()))
            resolution = {
                "kind": (
                    "checked_external_contract"
                    if isinstance(contract_sha256, str)
                    else "unresolved_external"
                ),
                "contract_sha256": (
                    contract_sha256
                    if isinstance(contract_sha256, str) else None
                ),
            }
            if is_reachable and not isinstance(contract_sha256, str):
                blockers.append({
                    "code": "reachable_external_symbol_unresolved",
                    "symbol_id": symbol_id,
                    "dll": key[0] if key is not None else None,
                    "identity": key[1] if key is not None else None,
                })
        else:
            resolution = {"kind": "unresolved"}
            if reachable:
                blockers.append({
                    "code": "reachable_symbol_unresolved",
                    "symbol_id": symbol_id,
                })
        linked_symbols.append({
            "symbol_id": symbol_id,
            "kind": symbol.get("kind"),
            "linkage": symbol.get("linkage"),
            "visibility": symbol.get("visibility"),
            "storage_class": symbol.get("storage_class"),
            "logical_type": symbol.get("logical_type"),
            "physical_frame": symbol.get("physical_frame"),
            "lifetime": symbol.get("lifetime"),
            "permissions": symbol.get("permissions"),
            "original_rva": symbol.get("original_rva"),
            "declaration": symbol.get("declaration"),
            "resolution": resolution,
            "reachable": reachable,
            "root_ids": sorted(root_ids),
        })
    if set(definitions) - seen:
        _fail("semantic definitions name undeclared symbols")
    linked_symbols.sort(key=lambda row: row["symbol_id"])
    return (
        linked_symbols, unit_symbol_by_rva, reachable_unit_ids, blockers,
    )


def _linked_relocations(
    semantic: SemanticObjectV1,
    closure: Mapping[str, Any],
    symbols: Sequence[Mapping[str, Any]],
    unit_symbol_by_rva: Mapping[int, str],
) -> list[dict[str, Any]]:
    known = {str(row["symbol_id"]) for row in symbols}
    external_symbol_by_identity: dict[tuple[str, str], str] = {}
    for symbol in symbols:
        resolution = symbol.get("resolution")
        if (
            not isinstance(resolution, Mapping)
            or resolution.get("kind") != "checked_external_contract"
        ):
            continue
        declaration = symbol.get("declaration")
        key = _identity_key(declaration) if isinstance(declaration, Mapping) else None
        if key is not None:
            external_symbol_by_identity.setdefault(key, str(symbol["symbol_id"]))
    reachable = {
        str(row["symbol_id"]) for row in symbols if row.get("reachable") is True
    }
    indirect_by_source: dict[int, list[Mapping[str, Any]]] = {}
    for raw in closure["indirect_targets"]:
        row = _mapping(raw, "indirect target set")
        indirect_by_source.setdefault(int(row["source_rva"]), []).append(row)
    reachable_direct_edges = {
        (int(row["source_rva"]), int(row["target_rva"]))
        for raw in closure["reachable_edges"]
        for row in (_mapping(raw, "reachable closure edge"),)
        if row.get("kind") == "direct_control"
    }
    linked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in semantic.payload["relocations"]:
        relocation = _mapping(raw, "semantic relocation")
        relocation_id = relocation.get("relocation_id")
        source = relocation.get("source_symbol")
        if (
            not isinstance(relocation_id, str) or not relocation_id
            or relocation_id in seen or not isinstance(source, str)
            or source not in known
        ):
            _fail("semantic relocation identity or source is malformed")
        seen.add(relocation_id)
        targets: list[str] = []
        target = relocation.get("target_symbol")
        if isinstance(target, str):
            targets.append(target)
        elif relocation.get("target_rva") in unit_symbol_by_rva:
            targets.append(unit_symbol_by_rva[int(relocation["target_rva"])])
        elif relocation.get("status") == "unresolved_indirect":
            candidates = indirect_by_source.get(int(relocation["source_rva"]), [])
            site = relocation.get("site")
            instruction_rva = (
                site.get("instruction_rva") if isinstance(site, Mapping) else None
            )
            if isinstance(instruction_rva, int):
                exact = [
                    row for row in candidates
                    if str(row.get("site", "")).startswith(
                        f"call:{instruction_rva:08x}:"
                    )
                ]
                if exact:
                    candidates = exact
            for target_set in candidates:
                targets.extend(
                    unit_symbol_by_rva[rva]
                    for rva in target_set.get("targets") or []
                    if rva in unit_symbol_by_rva
                )
                for raw_external in target_set.get("external_targets") or []:
                    external = _mapping(
                        raw_external, "indirect external target"
                    )
                    key = (
                        str(external.get("dll", "")).lower(),
                        str(external.get("identity", "")),
                    )
                    symbol_id = external_symbol_by_identity.get(key)
                    if symbol_id is not None:
                        targets.append(symbol_id)
        targets = sorted(set(targets))
        unknown_targets = sorted(set(targets) - known)
        if unknown_targets:
            _fail("semantic relocation resolves to undeclared symbols")
        # A reachable source unit does not imply that every syntactic control
        # successor is reachable.  In particular, checked no-return imports
        # leave a machine fallthrough edge in transfer-v2 while the execution
        # closure correctly proves that edge infeasible.  Use the exact
        # same-pass edge fixed point for control relocations; other relocation
        # kinds are activated by their source symbol.
        is_reachable = (
            (
                int(relocation["source_rva"]),
                int(relocation["target_rva"]),
            ) in reachable_direct_edges
            if relocation.get("kind") == "direct_control"
            else source in reachable
        )
        if targets:
            status = "resolved"
        elif relocation.get("status") == "unresolved_external":
            status = "external_declaration"
        elif not is_reachable:
            status = "unresolved_unreachable"
        else:
            status = "unresolved_reachable"
        linked.append({
            "relocation_id": relocation_id,
            "kind": relocation.get("kind"),
            "source_symbol": source,
            "site": relocation.get("site"),
            "addend": relocation.get("addend"),
            "offset": relocation.get("offset"),
            "required_view": relocation.get("required_view"),
            "selector_value": relocation.get("selector_value"),
            "status": status,
            "target_symbols": targets,
            "reachable": is_reachable,
        })
    linked.sort(key=lambda row: row["relocation_id"])
    return linked


def _propagate_link_reachability(
    symbols: list[dict[str, Any]], relocations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Close typed symbol reachability over already resolved relocations."""

    by_id = {str(row["symbol_id"]): row for row in symbols}
    initially_reachable = {
        symbol_id for symbol_id, row in by_id.items()
        if row.get("reachable") is True
    }
    changed = True
    while changed:
        changed = False
        for relocation in relocations:
            source = by_id[str(relocation["source_symbol"])]
            source_reachable = source["reachable"] is True
            if (
                relocation["kind"] != "direct_control"
                and relocation["reachable"] != source_reachable
            ):
                relocation["reachable"] = source_reachable
                changed = True
            if not relocation["reachable"]:
                continue
            source_roots = set(source["root_ids"])
            for target_id in relocation["target_symbols"]:
                target = by_id[str(target_id)]
                # Executable reachability is the transfer-v2 fixed point's
                # result, including feasibility and context.  A relocatable
                # code address alone never grants execution reachability.
                if target.get("kind") == "function":
                    continue
                target_roots = set(target["root_ids"])
                if target["reachable"] is not True or not source_roots <= target_roots:
                    target["reachable"] = True
                    target["root_ids"] = sorted(target_roots | source_roots)
                    changed = True
    blockers: list[dict[str, Any]] = []
    for relocation in relocations:
        if relocation["reachable"] is not True:
            if relocation["status"] == "unresolved_reachable":
                relocation["status"] = "unresolved_unreachable"
            continue
        if relocation["status"] == "unresolved_unreachable":
            relocation["status"] = "unresolved_reachable"
        if (
            relocation["status"] == "unresolved_reachable"
            and relocation["kind"] != "indirect_call"
        ):
            blockers.append({
                "code": "reachable_relocation_unresolved",
                "relocation_id": relocation["relocation_id"],
                "source_symbol": relocation["source_symbol"],
                "kind": relocation["kind"],
            })
    blockers.extend({
        "code": "reachable_symbol_unresolved",
        "symbol_id": row["symbol_id"],
    } for row in symbols if (
        row.get("reachable") is True
        and row.get("symbol_id") not in initially_reachable
        and _mapping(row.get("resolution"), "symbol resolution").get("kind")
        == "unresolved"
    ))
    return blockers


def _symbol_root_provenance_blockers(
    symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "code": "reachable_symbol_root_provenance_missing",
            "symbol_id": row["symbol_id"],
        }
        for row in symbols
        if row.get("reachable") is True and not row.get("root_ids")
    ]


def _linked_holes(
    semantic: SemanticObjectV1,
    reachable_unit_ids: set[str],
    relocations: Sequence[Mapping[str, Any]],
    symbols: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Discharge link-owned holes and classify remaining holes by reachability."""

    discharged = {
        "boundary_types_unlinked", "effect_closure_unlinked",
        "evidence_inventory_unlinked", "loader_relocations_unlinked",
        "object_views_unlinked", "physical_frames_unlinked",
    }
    relocation_by_id = {
        str(row["relocation_id"]): row for row in relocations
    }
    symbol_by_id = {str(row["symbol_id"]): row for row in symbols}
    unavailable_forms = {
        str(row.get("form_id"))
        for row in (
            semantic.platform_selection.get("issues", [])
            if semantic.platform_selection is not None else []
        )
        if isinstance(row, Mapping)
    }
    reachable_unavailable_forms = {
        str(row.get("form_id"))
        for row in (
            semantic.platform_selection.get("occurrences", [])
            if semantic.platform_selection is not None else []
        )
        if (
            isinstance(row, Mapping)
            and row.get("form_id") in unavailable_forms
            and row.get("unit_id") in reachable_unit_ids
        )
    }
    holes: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for raw in semantic.payload["holes"]:
        hole = dict(_mapping(raw, "semantic-object hole"))
        kind = hole.get("kind")
        if kind in discharged:
            continue
        subject = hole.get("subject")
        reachable = True
        resolved = False
        if isinstance(subject, str) and subject in relocation_by_id:
            relocation = relocation_by_id[subject]
            reachable = relocation.get("reachable") is True
            resolved = relocation.get("status") in {
                "resolved", "external_declaration"
            }
        elif isinstance(subject, str) and subject in symbol_by_id:
            reachable = symbol_by_id[subject].get("reachable") is True
        elif kind == "qualified_platform_selection_incomplete":
            reachable = subject in reachable_unavailable_forms
        if resolved:
            continue
        linked_hole = {**hole, "reachable": reachable}
        holes.append(linked_hole)
        if reachable and not (
            isinstance(subject, str)
            and subject in relocation_by_id
            and relocation_by_id[subject].get("status") == "unresolved_reachable"
        ):
            blockers.append({
                "code": "reachable_semantic_hole",
                "kind": kind,
                "subject": subject,
            })
    holes.sort(key=canonical_sha256_v3)
    return holes, blockers


def _objects(
    authority: MachineObjectAuthorityV2,
    symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    anchors_by_rule: dict[str, list[dict[str, Any]]] = {}
    for anchor in authority.data_export_anchors:
        anchors_by_rule.setdefault(anchor.rule_id, []).append(anchor.to_payload())
    symbols_by_id = {str(row["symbol_id"]): row for row in symbols}
    result: list[dict[str, Any]] = []
    for rule in authority.rules:
        symbol_id = f"original:object:{rule.identity}"
        symbol = symbols_by_id.get(symbol_id)
        anchors = anchors_by_rule.get(rule.identity, [])
        typed_views = sorted(({
            "anchor_id": str(anchor["id"]),
            "byte_offset": int(anchor["byte_offset"]),
            **dict(_mapping(anchor["typed_view"], "data-anchor typed view")),
        } for anchor in anchors if anchor["typed_view"] is not None), key=lambda row: (
            str(row["anchor_id"]), int(row["byte_offset"]),
            str(row["boundary_type_id"]), str(row["target_layout_sha256"]),
        ))
        result.append({
            **rule.to_payload(),
            "generation_policy": rule.generation_policy,
            "typed_views": typed_views,
            "semantic_symbol_id": symbol_id if symbol is not None else None,
            "reachable": symbol is not None and symbol.get("reachable") is True,
            "root_ids": (
                list(symbol.get("root_ids", ())) if symbol is not None else []
            ),
            "data_export_anchors": anchors,
        })
    return result


def _implementation_requirements(
    semantic: SemanticObjectV1,
    symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    definitions = {
        str(row["symbol_id"]): _mapping(row, "semantic definition")
        for row in semantic.payload["definitions"]
    }
    evidence = _rows(semantic.payload["evidence"], "semantic evidence")
    evidence_by_kind = {
        str(_mapping(row, "semantic evidence row")["kind"]): index
        for index, row in enumerate(evidence)
    }
    requirements: list[dict[str, Any]] = []
    for symbol in symbols:
        if symbol.get("reachable") is not True:
            continue
        resolution = _mapping(symbol.get("resolution"), "symbol resolution")
        kind = resolution.get("kind")
        if kind == "semantic_definition":
            definition = definitions.get(str(symbol["symbol_id"]))
            if definition is None:
                _fail("reachable semantic definition has no definition record")
            definition_kind = resolution.get("definition_kind")
            if definition_kind == "transfer_v2":
                providers = ["generated_behavioral_c", "qualified_portable_c"]
            elif definition_kind in {
                "image_object", "object_anchor", "resource_data",
                "resource_directory", "resource_entry",
                "checked_exception_transition", "load_config_table",
                "loader_section_storage",
            }:
                providers = ["native_realizer"]
            else:
                providers = ["qualified_semantic_provider"]
            dependencies = _rows(
                definition.get("evidence_dependencies"),
                "definition evidence dependencies",
            )
        elif kind == "checked_external_contract":
            providers = ["external_environment"]
            dependencies = [evidence_by_kind["resolved_external_environment"]]
        elif kind == "qualified_platform_primitive":
            providers = ["qualified_platform"]
            platform_evidence = evidence_by_kind.get("qualified_platform")
            dependencies = (
                [] if platform_evidence is None else [platform_evidence]
            )
        else:
            providers = []
            dependencies = []
        requirements.append({
            "symbol_id": symbol["symbol_id"],
            "allowed_provider_kinds": providers,
            "evidence_dependencies": dependencies,
        })
    return requirements


def _canonical_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        {canonical_sha256_v3(dict(row)): dict(row) for row in rows}.values(),
        key=canonical_sha256_v3,
    )


def build_semantic_link_worklist_facts(
    *, semantic: SemanticObjectV1, closure: Mapping[str, Any],
    native_link_facts: Mapping[str, Any] | None = None,
    provisional_import_uses: tuple[
        Sequence[Mapping[str, Any]], Sequence[Mapping[str, Any]]
    ] | None = None,
) -> dict[str, Any]:
    """Return the closed internal facts consumed by semantic module V2.

    The fixed point and all blocker-producing joins are checked here, but the
    producer returns no serialized compatibility artifact, effect projection,
    or authority claim.
    """

    if semantic.resolved_external_environment is None:
        _fail("semantic link requires a resolved-environment semantic member")
    object_authority = semantic.machine_object_authority
    validate_module_execution_closure_v1(closure)
    resolved_environment = dict(ResolvedExternalEnvironmentV1.parse(
        semantic.resolved_external_environment.payload,
        module_interface=semantic.module_interface,
    ).payload)
    environment_blockers = [
        dict(_mapping(row, "resolved-environment blocker"))
        for row in _rows(
            resolved_environment.get("blockers"),
            "resolved-environment blockers",
        )
    ]
    bindings = _mapping(closure["bindings"], "execution-closure bindings")
    members = _mapping(semantic.payload["members"], "semantic-object members")
    if bindings.get("executable_transfer_plan_sha256") != members["transfer_plan"]["content_sha256"]:
        _fail("execution closure is stale for the semantic-object transfer member")
    if bindings.get("module_interface_sha256") != members["module_interface"]["content_sha256"]:
        _fail("execution closure is stale for the semantic-object module member")
    environment_bindings = _mapping(
        resolved_environment.get("bindings"), "resolved-environment bindings"
    )
    if environment_bindings.get("module_interface_sha256") != (
        members["module_interface"]["identity"]
    ):
        _fail("resolved environment is stale for the semantic-object module")
    if object_authority.bindings.get("module_interface_sha256") != (
        members["module_interface"]["content_sha256"]
    ):
        _fail("object authority is stale for the semantic-object module")
    environment_identity = resolved_environment.get("resolved_environment_sha256")
    environment_content_sha256 = _payload_sha256(resolved_environment)
    if bindings.get("resolved_external_environment_sha256") != environment_content_sha256:
        _fail("execution closure is stale for the resolved environment")
    object_authority_payload = object_authority.to_payload()
    object_authority_content_sha256 = _payload_sha256(object_authority_payload)
    if bindings.get("machine_object_authority_sha256") != object_authority_content_sha256:
        _fail("execution closure is stale for the object authority")

    roots_by_unit, root_ids_by_rva, _root_symbol_by_id, roots = (
        _root_provenance(semantic, closure)
    )
    effects, external_roots, provider_roots, effect_blockers = (
        _effect_provenance(
            semantic, closure, roots_by_unit, root_ids_by_rva
        )
    )
    symbols, unit_symbol_by_rva, reachable_units, symbol_blockers = (
        _symbol_tables(
            semantic,
            closure,
            roots_by_unit,
            external_roots,
            provider_roots,
        )
    )
    relocations = _linked_relocations(
        semantic, closure, symbols, unit_symbol_by_rva
    )
    relocation_blockers = _propagate_link_reachability(symbols, relocations)
    provenance_blockers = _symbol_root_provenance_blockers(symbols)
    objects = _objects(object_authority, symbols)
    native_kernel_blockers: list[dict[str, Any]] | None = None
    references = _empty_reference_facts_v1()
    reference_blockers: list[dict[str, Any]] = []
    if native_link_facts is not None:
        native_kernel_blockers, references = _check_native_link_facts_v1(
            native_link_facts,
            semantic=semantic,
            symbols=symbols,
            relocations=relocations,
            objects=objects,
            effects=effects,
            root_ids_by_rva=root_ids_by_rva,
            expected_blockers=[
                *symbol_blockers,
                *relocation_blockers,
                *provenance_blockers,
                *effect_blockers,
            ],
        )
    else:
        reference_blockers.append({
            "code": "semantic_reference_facts_unavailable",
            "detail": (
                "compact reference facts require the same-pass native "
                "semantic-link worklist"
            ),
        })
    # Native/Python parity above covers the fixed-point effect inventory.  The
    # semantic capability registry is a deterministic link view over those
    # checked callbacks and symbols; it intentionally has no bridge symbols or
    # candidate addresses.
    effects["code_capabilities"] = _semantic_code_capabilities(
        module_interface=semantic.module_interface,
        effects=effects,
        symbols=symbols,
    )
    (
        effects["export_capabilities"],
        export_capability_blockers,
    ) = _semantic_export_capabilities(
        module_interface=semantic.module_interface,
        resolved_environment=resolved_environment,
        symbols=symbols,
    )
    if provisional_import_uses is None:
        (
            effects["import_uses"],
            import_use_blockers,
        ) = _semantic_import_uses_v1(
            semantic=semantic,
            resolved_environment=resolved_environment,
            roots_by_unit=roots_by_unit,
        )
    else:
        (
            effects["import_uses"],
            import_use_blockers,
        ) = _bind_semantic_import_use_roots_v1(
            *provisional_import_uses,
            roots_by_unit=roots_by_unit,
        )
    holes, hole_blockers = _linked_holes(
        semantic, reachable_units, relocations, symbols
    )
    blockers = _canonical_rows([
        *(
            native_kernel_blockers
            if native_kernel_blockers is not None else [
                *symbol_blockers,
                *relocation_blockers,
                *provenance_blockers,
                *effect_blockers,
            ]
        ),
        *reference_blockers,
        *export_capability_blockers,
        *import_use_blockers,
        *hole_blockers,
        *(
            {
                "code": "resolved_external_environment_incomplete",
                "environment_blocker": row,
            }
            for row in environment_blockers
        ),
        *(dict(row) for row in closure["blockers"]),
    ])
    link_bindings = {
        "semantic_object_sha256": semantic.identity,
        "semantic_object_content_sha256": sha256_file(
            semantic.package_root / "semantic-object.json"
        ) if semantic.package_root is not None else semantic.identity,
        "executable_transfer_plan_sha256": members["transfer_plan"]["identity"],
        "module_interface_sha256": members["module_interface"]["identity"],
        "resolved_external_environment_sha256": environment_identity,
        "resolved_external_environment_content_sha256": (
            environment_content_sha256
        ),
        "machine_object_authority_sha256": object_authority.authority_sha256,
        "machine_object_authority_content_sha256": (
            object_authority_content_sha256
        ),
        "module_execution_closure_sha256": closure["closure_sha256"],
        **({
            "qualified_platform_sha256": semantic.payload["bindings"][
                "qualified_platform_sha256"
            ],
        } if isinstance(
            semantic.payload["bindings"].get("qualified_platform_sha256"),
            str,
        ) else {}),
    }
    fixed_point = {
        "status": closure["status"],
        "closure_sha256": closure["closure_sha256"],
        "blockers": [dict(row) for row in closure["blockers"]],
    }
    worklist_facts = {
        "analysis_policy": dict(closure["analysis_policy"]),
        "bindings": link_bindings,
        "blockers": blockers,
        "fixed_point": fixed_point,
        "objects": objects,
        "relocations": relocations,
        "roots": roots,
        "symbols": symbols,
    }
    return worklist_facts
__all__ = [
    "LinkedSemanticModuleError", "build_semantic_link_worklist_facts",
]
