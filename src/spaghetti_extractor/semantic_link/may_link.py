"""Deterministic conservative linker for ``linked-semantic-module-v2``.

The linker consumes the checked relocatable declarations in one
``semantic-object-v1`` package. It does not interpret transfer operations,
solve values, or run the optional must-provenance fixed point. Its only graph
operation is monotone may reachability over already-declared roots,
relocations, and runtime-provider dependencies.
"""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.semantic_object import SemanticObjectV1
from ..util import sha256_file
from .module_v2_core import SemanticLinkFactsV2, _fail, _mapping


MAY_LINK_ALGORITHM_V1 = "semantic-object-conservative-may-link-v1"


def _definitions(semantic: SemanticObjectV1) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for raw in semantic.payload["definitions"]:
        row = _mapping(raw, "semantic definition")
        symbol_id = row.get("symbol_id")
        if not isinstance(symbol_id, str) or not symbol_id or symbol_id in result:
            _fail("semantic definitions are malformed or duplicated")
        result[symbol_id] = row
    return result


def _qualified_runtime_providers(semantic: SemanticObjectV1) -> set[str]:
    return {
        str(row.get("provider"))
        for raw in (
            semantic.qualified_platform.get("runtime_provider_catalog", [])
            if semantic.qualified_platform is not None else []
        )
        for row in (_mapping(raw, "qualified runtime-provider rule"),)
        if row.get("layer") == "transfer_plan"
        and isinstance(row.get("provider"), str)
        and row.get("provider")
    }


def _symbol_rows(
    semantic: SemanticObjectV1,
) -> tuple[dict[str, dict[str, Any]], dict[int, str]]:
    definitions = _definitions(semantic)
    qualified_runtime = _qualified_runtime_providers(semantic)
    result: dict[str, dict[str, Any]] = {}
    transfer_by_rva: dict[int, str] = {}
    for raw in semantic.payload["symbols"]:
        source = _mapping(raw, "semantic symbol")
        symbol_id = source.get("symbol_id")
        if not isinstance(symbol_id, str) or not symbol_id or symbol_id in result:
            _fail("semantic symbols are malformed or duplicated")
        definition = definitions.get(symbol_id)
        declaration = source.get("declaration")
        resolution: dict[str, Any]
        if definition is not None:
            resolution = {
                "kind": "semantic_definition",
                "definition_kind": definition.get("definition_kind"),
            }
        elif source.get("kind") == "runtime_primitive":
            provider = (
                declaration.get("provider_id")
                if isinstance(declaration, Mapping) else None
            )
            resolution = {
                "kind": (
                    "qualified_platform_primitive"
                    if provider in qualified_runtime else "unselected"
                ),
                "provider_id": provider,
            }
        elif source.get("linkage") == "external":
            contract_sha256 = (
                declaration.get("environment_contract_sha256")
                if isinstance(declaration, Mapping) else None
            )
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
        else:
            resolution = {"kind": "unresolved"}
        result[symbol_id] = {
            **dict(source),
            "resolution": resolution,
            "reachable": False,
            "root_ids": [],
        }
        if (
            definition is not None
            and definition.get("definition_kind") == "transfer_v2"
        ):
            rva = source.get("original_rva")
            if (
                not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
                or rva in transfer_by_rva
            ):
                _fail("transfer definitions do not have unique entry RVAs")
            transfer_by_rva[rva] = symbol_id
    if set(definitions) - set(result):
        _fail("semantic definitions name undeclared symbols")
    return result, transfer_by_rva


def _roots(
    semantic: SemanticObjectV1,
    symbols: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    roots: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for raw in semantic.payload["roots"]:
        source = _mapping(raw, "semantic root")
        if source.get("kind") in {"data_export", "forwarder"}:
            continue
        root_id = source.get("root_id")
        target = source.get("target_symbol")
        rva = source.get("original_rva")
        if (
            not isinstance(root_id, str) or not root_id
            or not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
        ):
            _fail("semantic executable root is malformed")
        if not isinstance(target, str) or target not in symbols:
            blockers.append({
                "code": "semantic_root_unresolved",
                "root_id": root_id,
                "original_rva": rva,
                "evidence_sha256": canonical_sha256_v3(dict(source)),
            })
            continue
        roots.append({
            "root_id": root_id,
            "kind": str(source["kind"]),
            "origin": "module_interface",
            "original_rva": rva,
            "target_symbol": target,
            "reachable": True,
        })
    roots.sort(key=lambda row: row["root_id"])
    if len({row["root_id"] for row in roots}) != len(roots):
        _fail("semantic executable roots are duplicated")
    return roots, blockers


def _relocations(
    semantic: SemanticObjectV1,
    symbols: Mapping[str, Mapping[str, Any]],
    transfer_by_rva: Mapping[int, str],
) -> list[dict[str, Any]]:
    result = []
    seen: set[str] = set()
    for raw in semantic.payload["relocations"]:
        source = _mapping(raw, "semantic relocation")
        relocation_id = source.get("relocation_id")
        if (
            not isinstance(relocation_id, str) or not relocation_id
            or relocation_id in seen
        ):
            _fail("semantic relocation identities are malformed or duplicated")
        seen.add(relocation_id)
        target_symbol = source.get("target_symbol")
        if not isinstance(target_symbol, str):
            target_rva = source.get("target_rva")
            target_symbol = (
                transfer_by_rva.get(target_rva)
                if isinstance(target_rva, int) and not isinstance(target_rva, bool)
                else None
            )
        targets = (
            [target_symbol]
            if isinstance(target_symbol, str) and target_symbol in symbols else []
        )
        input_status = source.get("status")
        if targets:
            status = "resolved"
        elif input_status == "unresolved_external":
            status = "external_declaration"
        else:
            status = "unresolved_unreachable"
        result.append({
            "relocation_id": relocation_id,
            "kind": source.get("kind"),
            "source_symbol": source.get("source_symbol"),
            "site": source.get("site"),
            "addend": source.get("addend"),
            "offset": source.get("offset"),
            "required_view": source.get("required_view"),
            "selector_value": source.get("selector_value"),
            "status": status,
            "target_symbols": targets,
            "reachable": False,
        })
    result.sort(key=lambda row: row["relocation_id"])
    return result


def _rooted_static_closure(
    *, semantic: SemanticObjectV1, roots: list[dict[str, Any]],
    symbols: dict[str, dict[str, Any]], relocations: list[dict[str, Any]],
) -> None:
    outgoing: dict[str, set[str]] = defaultdict(set)
    for row in relocations:
        source = row.get("source_symbol")
        if not isinstance(source, str) or source not in symbols:
            continue
        outgoing[source].update(str(target) for target in row["target_symbols"])
    effect_index = _mapping(
        semantic.payload.get("effect_index"), "semantic effect index"
    )
    for raw in effect_index.get("runtime_primitive_dependencies", []):
        dependency = _mapping(raw, "runtime-primitive dependency")
        target = dependency.get("target_symbol")
        sources = dependency.get("source_symbols")
        if not isinstance(target, str) or target not in symbols:
            _fail("runtime-primitive dependency target is undeclared")
        if not isinstance(sources, list):
            _fail("runtime-primitive dependency sources are malformed")
        for source in sources:
            if not isinstance(source, str) or source not in symbols:
                _fail("runtime-primitive dependency source is undeclared")
            outgoing[source].add(target)

    roots_by_symbol: dict[str, set[str]] = defaultdict(set)
    pending: deque[str] = deque()
    queued: set[str] = set()
    for root in roots:
        target = str(root["target_symbol"])
        roots_by_symbol[target].add(str(root["root_id"]))
        if target not in queued:
            pending.append(target)
            queued.add(target)
    while pending:
        source = pending.popleft()
        queued.remove(source)
        for target in sorted(outgoing.get(source, ())):
            before = len(roots_by_symbol[target])
            roots_by_symbol[target].update(roots_by_symbol[source])
            if len(roots_by_symbol[target]) != before and target not in queued:
                pending.append(target)
                queued.add(target)
    for symbol_id, root_ids in roots_by_symbol.items():
        symbols[symbol_id]["reachable"] = True
        symbols[symbol_id]["root_ids"] = sorted(root_ids)
    for relocation in relocations:
        source = relocation.get("source_symbol")
        reachable = isinstance(source, str) and source in roots_by_symbol
        relocation["reachable"] = reachable
        if reachable and not relocation["target_symbols"]:
            relocation["status"] = "unresolved_reachable"


def _objects(
    semantic: SemanticObjectV1,
    symbols: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    anchors_by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for anchor in semantic.machine_object_authority.data_export_anchors:
        anchors_by_rule[anchor.rule_id].append(anchor.to_payload())
    result = []
    for rule in semantic.machine_object_authority.rules:
        symbol_id = f"original:object:{rule.identity}"
        symbol = symbols.get(symbol_id)
        anchors = anchors_by_rule.get(rule.identity, [])
        typed_views = sorted(({
            "anchor_id": str(anchor["id"]),
            "byte_offset": int(anchor["byte_offset"]),
            **dict(_mapping(anchor["typed_view"], "data-anchor typed view")),
        } for anchor in anchors if anchor["typed_view"] is not None), key=lambda row: (
            row["anchor_id"], row["byte_offset"],
            str(row["boundary_type_id"]), str(row["target_layout_sha256"]),
        ))
        result.append({
            **rule.to_payload(),
            "generation_policy": rule.generation_policy,
            "typed_views": typed_views,
            "semantic_symbol_id": symbol_id if symbol is not None else None,
            "reachable": symbol is not None and symbol.get("reachable") is True,
            "root_ids": list(symbol.get("root_ids", ())) if symbol else [],
            "data_export_anchors": anchors,
        })
    return result


def compile_semantic_may_link_facts_v2(
    *, semantic_object: Path,
) -> tuple[SemanticObjectV1, SemanticLinkFactsV2]:
    """Compile the target-independent conservative link from one package."""

    semantic = SemanticObjectV1.load_link_view(semantic_object)
    if semantic.package_root is None:
        _fail("semantic link requires a packaged semantic object")
    if semantic.resolved_external_environment is None:
        _fail("semantic link requires a resolved-environment semantic member")
    symbols, transfer_by_rva = _symbol_rows(semantic)
    roots, blockers = _roots(semantic, symbols)
    relocations = _relocations(semantic, symbols, transfer_by_rva)
    _rooted_static_closure(
        semantic=semantic, roots=roots, symbols=symbols,
        relocations=relocations,
    )
    environment = semantic.resolved_external_environment
    for raw in environment.payload["blockers"]:
        blockers.append({
            "code": "resolved_external_environment_incomplete",
            "environment_blocker": dict(_mapping(
                raw, "resolved-environment blocker"
            )),
        })
    members = _mapping(semantic.payload["members"], "semantic-object members")
    bindings = {
        "semantic_object_sha256": semantic.identity,
        "semantic_object_content_sha256": sha256_file(
            semantic.package_root / "semantic-object.json"
        ),
        "executable_transfer_plan_sha256": members["transfer_plan"]["identity"],
        "module_interface_sha256": members["module_interface"]["identity"],
        "resolved_external_environment_sha256": environment.identity,
        "resolved_external_environment_content_sha256": members[
            "resolved_external_environment"
        ]["content_sha256"],
        "machine_object_authority_sha256": (
            semantic.machine_object_authority.authority_sha256
        ),
        "machine_object_authority_content_sha256": members[
            "machine_object_authority"
        ]["content_sha256"],
    }
    qualified = semantic.payload["bindings"].get("qualified_platform_sha256")
    if isinstance(qualified, str):
        bindings["qualified_platform_sha256"] = qualified
    roots_projection = [{
        key: value for key, value in row.items() if key != "reachable"
    } for row in roots]
    link_provenance = {
        "algorithm": MAY_LINK_ALGORITHM_V1,
        "root_inventory_sha256": canonical_sha256_v3(roots_projection),
        "relocation_inventory_sha256": canonical_sha256_v3([{
            key: value for key, value in row.items() if key != "reachable"
        } for row in relocations]),
        "runtime_dependency_inventory_sha256": canonical_sha256_v3(
            _mapping(
                semantic.payload["effect_index"], "semantic effect index"
            )["runtime_primitive_dependencies"]
        ),
    }
    facts = SemanticLinkFactsV2.from_checked_link({
        "bindings": bindings,
        "blockers": sorted(blockers, key=canonical_sha256_v3),
        "link_provenance": link_provenance,
        "objects": _objects(semantic, symbols),
        "relocations": relocations,
        "roots": roots,
        "symbols": sorted(symbols.values(), key=lambda row: row["symbol_id"]),
    })
    return semantic, facts


__all__ = [
    "MAY_LINK_ALGORITHM_V1", "compile_semantic_may_link_facts_v2",
]
