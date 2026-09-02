"""Compact closed codec for ``linked-semantic-module-v2``.

V2 is a link manifest over ``semantic-object-v1`` rather than a second copy of
the executable transfer language.  Definitions remain in the content-bound
semantic-object package; this manifest records their stable hashes plus the
link-time reachability, resolution, effect, obligation, and provenance delta.

The conservative semantic linker emits the deliberately narrow
``SemanticLinkFactsV2`` carrier directly.  That construction-local carrier
has no effect projection, serialized form, or authority role.
"""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.semantic_object import SemanticObjectV1
from ..util import sha256_file, write_json
from .formats import LINKED_SEMANTIC_MODULE_V2_FORMAT
from .frontiers_v2 import classify_semantic_frontiers_v2
from .frontiers_v2 import derive_callback_capability_obligations_v2
from .frontiers_v2 import derive_internal_dispatch_obligations_v2
from .import_uses import semantic_import_uses_v1
from .package import publish_semantic_package_v1
from .may_link import compile_semantic_may_link_facts_v2


from .module_v2_core import (
    SemanticLinkFactsV2,
    _callable_external_contracts,
    _definition_catalog,
    _fail,
    _mapping,
    _text,
)
from .module_v2_effects import (
    _active_objects,
    _checked_no_return_sources,
    _exception_effects_v2,
    _export_capability_effects_v2,
    _external_contract_effects_v2,
    _import_code_use_subject as _effect_import_code_use_subject,
    _import_use_effects_v2,
    _lifecycle_effects_v2,
    _nonlocal_effects_and_holes_v2,
    _runtime_provider_effects_v2,
    external_service_obligations_v2,
)
from .module_v2_codec import LinkedSemanticModuleV2

_import_code_use_subject = _effect_import_code_use_subject


def _transfer_plan_holes_v2(
    transfer_plan: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Keep canonical transfer failures visible at the semantic link.

    Incomplete machine semantics are omitted from the executable transfer
    inventory, so a reachability-only link cannot rediscover every missing
    definition.  The canonical plan already owns those facts; V2 binds each
    one as a completion hole without copying its diagnostic payload.
    """

    result = []
    for raw in transfer_plan["semantic_blockers"]:
        blocker = dict(_mapping(raw, "transfer-plan semantic blocker"))
        subject = str(
            blocker.get("transfer_id")
            or blocker.get("unit_id")
            or (
                f"original-rva:{int(blocker['rva_start']):08x}"
                if isinstance(blocker.get("rva_start"), int)
                else "module"
            )
        )
        core = {
            "code": "upstream_transfer_plan_incomplete",
            "subject": subject,
            "evidence_sha256": canonical_sha256_v3(blocker),
        }
        result.append({
            "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(core)}",
            **core,
        })
    return sorted(
        {str(row["hole_id"]): row for row in result}.values(),
        key=lambda row: row["hole_id"],
    )


def _semantic_object_holes_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
    active_relocations: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Retain unresolved checked-relocatable facts without link diagnostics.

    The semantic object deliberately records several construction placeholders
    that this linker discharges structurally.  All other rows remain genuine
    completion holes unless their exact relocation is now resolved or their
    unavailable ISA form occurs only in an inactive transfer.
    """

    discharged = {
        "boundary_types_unlinked", "effect_closure_unlinked",
        "evidence_inventory_unlinked", "loader_relocations_unlinked",
        "object_views_unlinked", "physical_frames_unlinked",
        "indirect_code_relocation_unlinked", "upstream_transfer_blocker",
    }
    active_symbol_ids = {str(row["symbol_id"]) for row in active_symbols}
    active_transfer_ids = {
        symbol_id.removeprefix("original:function:")
        for symbol_id in active_symbol_ids
        if symbol_id.startswith("original:function:")
    }
    active_relocation_by_id = {
        str(row["relocation_id"]): row for row in active_relocations
    }
    active_unavailable_forms: set[str] = set()
    if semantic.platform_selection is not None:
        issue_forms = {
            str(row.get("form_id"))
            for row in semantic.platform_selection.get("issues", [])
            if isinstance(row, Mapping) and isinstance(row.get("form_id"), str)
        }
        active_unavailable_forms = {
            str(row["form_id"])
            for row in semantic.platform_selection.get("occurrences", [])
            if isinstance(row, Mapping)
            and row.get("unit_id") in active_transfer_ids
            and row.get("form_id") in issue_forms
        }
    result = []
    for raw in semantic.payload["holes"]:
        hole = dict(_mapping(raw, "semantic-object hole"))
        kind = str(hole.get("kind", "unknown_semantic_object_hole"))
        subject = str(hole.get("subject", "module"))
        if kind in discharged:
            continue
        relocation = active_relocation_by_id.get(subject)
        if relocation is not None and relocation.get("status") in {
            "resolved", "external_declaration", "runtime_obligation",
            "checked_infeasible",
        }:
            continue
        if (
            kind == "qualified_platform_selection_incomplete"
            and subject not in active_unavailable_forms
        ):
            continue
        evidence_sha256 = canonical_sha256_v3(hole)
        core = {
            "code": kind,
            "subject": f"semantic-object:{subject}",
            "evidence_sha256": evidence_sha256,
        }
        result.append({
            "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(core)}",
            **core,
        })
    return sorted(
        {str(row["hole_id"]): row for row in result}.values(),
        key=lambda row: row["hole_id"],
    )


def _definition_requirements(
    definitions: Sequence[Mapping[str, Any]],
    may_symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    definition_by_symbol = {
        str(row["symbol_id"]): row
        for row in definitions
    }
    result = []
    native_kinds = {
        "image_object", "object_anchor", "resource_data",
        "resource_directory", "resource_entry",
        "checked_exception_transition", "load_config_table",
        "loader_section_storage", "qualified_platform_primitive",
    }
    for symbol in may_symbols:
        symbol_id = _text(symbol.get("symbol_id"), "required symbol")
        definition = definition_by_symbol.get(symbol_id)
        definition_kind = (
            None if definition is None else definition["definition_kind"]
        )
        if definition_kind == "transfer_v2":
            providers = ["generated_behavioral_c", "qualified_portable_c"]
        elif definition_kind == "checked_external_contract":
            providers = ["external_environment"]
        elif definition_kind in native_kinds:
            providers = ["qualified_runtime"]
        elif definition_kind is None:
            providers = []
        else:
            providers = ["pinned_binary", "qualified_runtime"]
        result.append({
            "symbol_id": symbol_id,
            "definition_id": (
                None if definition is None else definition["definition_id"]
            ),
            "allowed_provider_kinds": providers,
            "dependency_contract_sha256s": (
                [] if definition is None
                else list(definition["dependency_contract_sha256s"])
            ),
        })
    result.sort(key=lambda row: row["symbol_id"])
    return result


def _normalized_roots_and_may_symbols(
    linked_payload: Mapping[str, Any],
    definitions: Sequence[Mapping[str, Any]],
    admitted_domains: Sequence[Mapping[str, Any]],
    semantic: SemanticObjectV1,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build conservative symbol reachability with explicit provenance."""

    symbols = {
        str(row["symbol_id"]): _mapping(row, "semantic-link worklist symbol")
        for raw in linked_payload["symbols"]
        for row in (_mapping(raw, "semantic-link worklist symbol"),)
    }
    roots = [{
        "root_id": str(row["root_id"]),
        "kind": str(row["kind"]),
        "origin": str(row["origin"]),
        "original_rva": row.get("original_rva"),
        "target_symbol": str(row["target_symbol"]),
    } for raw in linked_payload["roots"] for row in (
        _mapping(raw, "semantic-link worklist root"),
    )]
    root_sets: dict[str, set[str]] = {
        symbol_id: set(row.get("root_ids", ()))
        for symbol_id, row in symbols.items()
        if row.get("reachable") is True
        and row.get("root_ids")
    }
    domain_sets: dict[str, set[str]] = {
        symbol_id: set() for symbol_id in root_sets
    }
    definition_by_symbol = {
        str(row["symbol_id"]): row for row in definitions
    }
    transfer_symbol_by_rva: dict[int, str] = {}
    external_symbol_by_contract: dict[str, str] = {}
    import_slot_symbol_by_id: dict[str, str] = {}
    import_slot_symbols_by_contract: dict[str, list[str]] = {}
    for symbol_id, symbol in symbols.items():
        declaration = symbol.get("declaration")
        slot_id = (
            declaration.get("slot_id")
            if isinstance(declaration, Mapping) else None
        )
        if isinstance(slot_id, str) and slot_id:
            if slot_id in import_slot_symbol_by_id:
                _fail("loader import-slot declarations are duplicated")
            import_slot_symbol_by_id[slot_id] = symbol_id
            contract_sha256 = declaration.get(
                "environment_contract_sha256"
            )
            if isinstance(contract_sha256, str):
                import_slot_symbols_by_contract.setdefault(
                    contract_sha256, []
                ).append(symbol_id)
        definition = definition_by_symbol.get(symbol_id)
        if definition is None:
            continue
        if definition["definition_kind"] == "transfer_v2":
            rva = symbol.get("original_rva")
            if (
                not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
                or rva in transfer_symbol_by_rva
            ):
                _fail("transfer definitions do not have unique entry RVAs")
            transfer_symbol_by_rva[rva] = symbol_id
        elif definition["definition_kind"] == "checked_external_contract":
            contract_sha256 = (
                declaration.get("environment_contract_sha256")
                if isinstance(declaration, Mapping) else None
            )
            if symbol.get("kind") != "external_function":
                continue
            if (
                not isinstance(contract_sha256, str)
                or contract_sha256 in external_symbol_by_contract
            ):
                _fail("external definitions do not have unique contracts")
            external_symbol_by_contract[contract_sha256] = symbol_id

    # Activate exactly the members of every runtime-admitted domain.  Domain
    # membership is executable may-semantics, not optional target-precision
    # evidence, so a missing declaration or definition is a construction
    # failure rather than a runtime trap or a diagnostic frontier.
    for raw_domain in admitted_domains:
        domain = _mapping(raw_domain, "V2 admitted domain")
        domain_id = _text(domain.get("domain_sha256"), "domain identity")
        kind = domain.get("kind")
        if kind in {
            "frame_compatible_transfer_entry_rvas",
            "checked_callback_transfer_entry_rvas",
        }:
            guest_rvas = domain.get("targets")
        elif kind == "checked_indirect_callable_targets_v3":
            guest_rvas = domain.get("guest_transfer_entry_rvas")
        else:
            continue
        if not isinstance(guest_rvas, list):
            _fail("runtime admitted domain has no guest target inventory")
        for raw_rva in guest_rvas:
            symbol_id = transfer_symbol_by_rva.get(raw_rva)
            if symbol_id is None:
                _fail("runtime admitted guest target has no unique definition")
            root_sets.setdefault(symbol_id, set())
            domain_sets.setdefault(symbol_id, set()).add(domain_id)
        if kind != "checked_indirect_callable_targets_v3":
            continue
        external_targets = domain.get("external_loader_targets")
        if not isinstance(external_targets, list):
            _fail("callable admitted domain has no external target inventory")
        for raw_target in external_targets:
            target = _mapping(raw_target, "callable-domain external target")
            contract_sha256 = target.get("contract_sha256")
            symbol_id = external_symbol_by_contract.get(str(contract_sha256))
            if symbol_id is None:
                _fail(
                    "runtime admitted external target has no unique definition"
                )
            root_sets.setdefault(symbol_id, set())
            domain_sets.setdefault(symbol_id, set()).add(domain_id)
            for slot_symbol_id in import_slot_symbols_by_contract.get(
                str(contract_sha256), []
            ):
                root_sets.setdefault(slot_symbol_id, set())
                domain_sets.setdefault(slot_symbol_id, set()).add(domain_id)

    # Loader-visible storage is part of module realization even when no guest
    # instruction reads it.  Give it explicit roots instead of smuggling it
    # into execution reachability.
    for symbol_id, symbol in symbols.items():
        storage = symbol.get("storage_class")
        # An IAT cell is loader-owned storage, but the semantic-object symbol
        # names the value that the loader writes into that cell.  Rooting that
        # symbol would incorrectly make every unused import a may-call target.
        # The PE interface and composer preserve every IAT slot independently;
        # actual code/data uses activate the imported value through checked
        # transfer effects.
        if storage == "iat_slot":
            continue
        loader_visible = (
            symbol.get("visibility") == "loader"
            or storage == "image_section"
            or isinstance(storage, str) and storage.startswith("tls_")
        )
        if not loader_visible:
            continue
        root_core = {
            "kind": "loader_storage",
            "origin": "module_interface_and_object_authority",
            "original_rva": symbol.get("original_rva"),
            "target_symbol": symbol_id,
        }
        root_id = f"module:loader-storage:{canonical_sha256_v3(root_core)}"
        roots.append({"root_id": root_id, **root_core})
        root_sets.setdefault(symbol_id, set()).add(root_id)
        domain_sets.setdefault(symbol_id, set())

    # Resolved relocations propagate both execution-root and admitted-domain
    # provenance.  An unresolved dynamic edge is represented by its domain
    # obligation and therefore needs no quadratic target expansion here.
    loader_root_ids = {
        str(row["root_id"]) for row in roots
        if row.get("kind") == "loader_storage"
    }
    relocation_targets: dict[str, set[str]] = defaultdict(set)
    for raw in linked_payload["relocations"]:
        relocation = _mapping(raw, "semantic-link worklist relocation")
        relocation_targets[str(relocation["source_symbol"])].update(
            str(target) for target in relocation.get("target_symbols", [])
        )
    # Runtime primitives are definition dependencies rather than machine
    # relocations. They nevertheless belong to may closure: a transfer admitted
    # only through a dynamic domain must activate every primitive used by that
    # transfer, not merely those used by the narrower static root closure.
    effect_index = _mapping(
        semantic.payload.get("effect_index"), "semantic effect index"
    )
    for raw_dependency in effect_index.get(
        "runtime_primitive_dependencies", []
    ):
        dependency = _mapping(
            raw_dependency, "runtime-primitive dependency"
        )
        target = dependency.get("target_symbol")
        sources = dependency.get("source_symbols")
        if (
            not isinstance(target, str) or target not in symbols
            or not isinstance(sources, list)
            or any(
                not isinstance(source, str) or source not in symbols
                for source in sources
            )
        ):
            _fail("runtime-primitive dependency is disconnected")
        for source in sources:
            relocation_targets[source].add(target)
    pending = deque(sorted(
        symbol_id for symbol_id in root_sets
        if root_sets[symbol_id] - loader_root_ids
        or domain_sets.get(symbol_id)
    ))
    queued = set(pending)
    while pending:
        source = pending.popleft()
        queued.remove(source)
        semantic_roots = root_sets[source] - loader_root_ids
        semantic_domains = domain_sets.get(source, set())
        for target in sorted(relocation_targets.get(source, ())):
            target_roots = root_sets.setdefault(target, set())
            target_domains = domain_sets.setdefault(target, set())
            before = (len(target_roots), len(target_domains))
            target_roots.update(semantic_roots)
            target_domains.update(semantic_domains)
            if (
                (len(target_roots), len(target_domains)) != before
                and target not in queued
            ):
                pending.append(target)
                queued.add(target)

    # A runtime-admitted transfer can introduce an IAT use that was absent
    # from the narrower static fixed point.  Close the may universe over the exact
    # transfer-v2 import-use projection: activate only the loader slot and, for
    # a checked code use, its callable contract.  Never root every IAT slot.
    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("may-reach import-use closure requires a resolved environment")
    roots_by_unit = {
        symbol_id.removeprefix("original:function:"): {
            *root_sets.get(symbol_id, ()),
            *(f"domain:{item}" for item in domain_sets.get(symbol_id, ())),
        }
        for symbol_id in root_sets
        if symbol_id.startswith("original:function:")
    }
    import_uses, _ = semantic_import_uses_v1(
        semantic=semantic,
        resolved_environment=environment.payload,
        roots_by_unit=roots_by_unit,
    )
    for raw_use in import_uses:
        use = _mapping(raw_use, "may-reach import use")
        slot_symbol_id = import_slot_symbol_by_id.get(str(use.get("slot_id")))
        if slot_symbol_id is None:
            _fail("may-reach import use names no declared loader slot")
        source_roots: set[str] = set()
        source_domains: set[str] = set()
        for raw_site in use.get("sites", []):
            site = _mapping(raw_site, "may-reach import-use site")
            source_symbol_id = (
                f"original:function:{site.get('transfer_id')}"
            )
            if source_symbol_id not in root_sets:
                _fail("may-reach import-use source is not active")
            source_roots.update(root_sets[source_symbol_id])
            source_domains.update(domain_sets.get(source_symbol_id, ()))
        if not source_roots and not source_domains:
            _fail("may-reach import use has no executable provenance")
        root_sets.setdefault(slot_symbol_id, set()).update(source_roots)
        domain_sets.setdefault(slot_symbol_id, set()).update(source_domains)
        slot_definition = definition_by_symbol.get(slot_symbol_id)
        if (
            use.get("use_kind") != "code"
            or slot_definition is None
            or slot_definition.get("definition_kind")
            != "checked_external_contract"
        ):
            continue
        declaration = _mapping(
            symbols[slot_symbol_id].get("declaration"),
            "checked import-slot declaration",
        )
        callable_symbol_id = external_symbol_by_contract.get(str(
            declaration.get("environment_contract_sha256")
        ))
        if callable_symbol_id is None:
            _fail("checked import use has no callable contract definition")
        root_sets.setdefault(callable_symbol_id, set()).update(source_roots)
        domain_sets.setdefault(callable_symbol_id, set()).update(source_domains)

    result = []
    for symbol_id in sorted(root_sets):
        symbol = symbols.get(symbol_id)
        if symbol is None:
            _fail("may-reach propagation produced an undeclared symbol")
        definition = definition_by_symbol.get(symbol_id)
        resolution = dict(_mapping(
            symbol.get("resolution"), "semantic-link symbol resolution"
        ))
        if definition is not None:
            if definition["definition_kind"] == "qualified_platform_primitive":
                resolution = {
                    "kind": "qualified_platform_primitive",
                    "provider_id": _mapping(
                        symbol.get("declaration"), "runtime declaration"
                    ).get("provider_id"),
                }
            elif definition["definition_kind"] == "checked_external_contract":
                resolution = {
                    "kind": "checked_external_contract",
                    "contract_sha256": _mapping(
                        symbol.get("declaration"), "external declaration"
                    ).get("environment_contract_sha256"),
                }
        result.append({
            "symbol_id": symbol_id,
            "kind": symbol["kind"],
            "original_rva": symbol["original_rva"],
            "resolution": resolution,
            "definition_id": (
                definition.get("definition_id") if definition is not None else None
            ),
            "root_ids": sorted(root_sets[symbol_id]),
            "domain_ids": sorted(domain_sets.get(symbol_id, ())),
        })
    roots.sort(key=lambda row: row["root_id"])
    return roots, result


def _active_relocations(
    linked_payload: Mapping[str, Any], may_symbols: Sequence[Mapping[str, Any]],
    checked_no_return_sources: set[str],
) -> list[dict[str, Any]]:
    provenance = {
        str(row["symbol_id"]): row for row in may_symbols
    }
    may_symbol_ids = set(provenance)
    result = []
    for raw in linked_payload["relocations"]:
        row = _mapping(raw, "semantic-link worklist relocation")
        source_symbol = str(row.get("source_symbol"))
        source = provenance.get(source_symbol)
        if source is None:
            continue
        source_roots = source.get("root_ids")
        source_domains = source.get("domain_ids")
        if (
            not isinstance(source_roots, list)
            or not isinstance(source_domains, list)
            or not source_domains
            and not any(
                not str(root_id).startswith("module:loader-storage:")
                for root_id in source_roots
            )
        ):
            continue
        targets = row.get("target_symbols", [])
        if not isinstance(targets, list) or not set(targets) <= may_symbol_ids:
            continue
        projected = {
            key: value for key, value in row.items() if key != "reachable"
        }
        if not projected.get("target_symbols"):
            if projected.get("kind") == "indirect_call":
                projected["status"] = "runtime_obligation"
            elif (
                projected.get("kind") == "direct_control"
                and projected.get("source_symbol") in checked_no_return_sources
            ):
                projected["status"] = "checked_infeasible"
            else:
                projected["status"] = "unresolved_reachable"
        result.append(projected)
    result.sort(key=lambda row: row["relocation_id"])
    return result




def build_linked_semantic_module_v2(
    *, semantic: SemanticObjectV1, link_facts: SemanticLinkFactsV2,
) -> dict[str, Any]:
    """Project checked conservative-link facts into the compact V2 manifest."""

    linked = link_facts.payload
    bindings = _mapping(linked.get("bindings"), "semantic link bindings")
    if bindings.get("semantic_object_sha256") != semantic.identity:
        _fail("semantic link facts are stale for the semantic object")
    transfer_plan = semantic.transfer_plan
    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("linked-semantic-module V2 requires a resolved environment")
    callable_external_contracts = _callable_external_contracts(
        environment.payload
    )
    frontiers = classify_semantic_frontiers_v2(
        fixed_point_blockers=[],
        linked_blockers=linked["blockers"],
        transfers=transfer_plan["transfers"],
        entry_targets=transfer_plan["entry_targets"],
        external_contracts=callable_external_contracts,
        interface_method_catalogs=environment.payload[
            "interface_method_catalogs"
        ],
        transfer_plan_sha256=str(transfer_plan["plan_sha256"]),
        resolved_environment_sha256=environment.identity,
    )
    frontier_dispatch_widened = any(
        row.get("class") in {
            "internal_code_dispatch", "indirect_external_callthrough",
        }
        for row in frontiers["residual_obligations"]
    )
    statically_reachable_transfer_ids = {
        str(row["symbol_id"])[len("original:function:"):]
        for raw in linked["symbols"]
        for row in (_mapping(raw, "semantic link symbol"),)
        if row.get("reachable") is True
        and str(row.get("symbol_id", "")).startswith("original:function:")
        and _mapping(
            row.get("resolution"), "semantic-link symbol resolution"
        ).get(
            "definition_kind"
        ) == "transfer_v2"
    }
    preliminary_active_transfer_ids = (
        [str(row["identity"]) for row in transfer_plan["transfers"]]
        if frontier_dispatch_widened
        else sorted(statically_reachable_transfer_ids)
    )
    preliminary_callbacks = derive_callback_capability_obligations_v2(
        transfers=transfer_plan["transfers"],
        entry_targets=transfer_plan["entry_targets"],
        active_transfer_ids=preliminary_active_transfer_ids,
        machine_import_contracts=callable_external_contracts,
        transfer_plan_sha256=str(transfer_plan["plan_sha256"]),
        resolved_environment_sha256=environment.identity,
    )
    preliminary_dispatch = derive_internal_dispatch_obligations_v2(
        transfers=transfer_plan["transfers"],
        entry_targets=transfer_plan["entry_targets"],
        active_transfer_ids=preliminary_active_transfer_ids,
        transfer_plan_sha256=str(transfer_plan["plan_sha256"]),
        machine_import_contracts=callable_external_contracts,
        interface_method_catalogs=environment.payload[
            "interface_method_catalogs"
        ],
        resolved_environment_sha256=environment.identity,
    )
    dynamic_widened = (
        frontier_dispatch_widened
        or bool(preliminary_dispatch["admitted_domains"])
        or bool(preliminary_callbacks["admitted_domains"])
    )
    active_transfer_ids = (
        [str(row["identity"]) for row in transfer_plan["transfers"]]
        if dynamic_widened else preliminary_active_transfer_ids
    )
    dispatch = derive_internal_dispatch_obligations_v2(
        transfers=transfer_plan["transfers"],
        entry_targets=transfer_plan["entry_targets"],
        active_transfer_ids=active_transfer_ids,
        transfer_plan_sha256=str(transfer_plan["plan_sha256"]),
        machine_import_contracts=callable_external_contracts,
        interface_method_catalogs=environment.payload[
            "interface_method_catalogs"
        ],
        resolved_environment_sha256=environment.identity,
    )
    callbacks = derive_callback_capability_obligations_v2(
        transfers=transfer_plan["transfers"],
        entry_targets=transfer_plan["entry_targets"],
        active_transfer_ids=active_transfer_ids,
        machine_import_contracts=callable_external_contracts,
        transfer_plan_sha256=str(transfer_plan["plan_sha256"]),
        resolved_environment_sha256=environment.identity,
    )
    obligation_by_id = {
        str(row["obligation_id"]): row
        for row in [
            *frontiers["residual_obligations"],
            *dispatch["residual_obligations"],
            *callbacks["residual_obligations"],
        ]
    }
    domain_by_id = {
        str(row["domain_sha256"]): row
        for row in [
            *frontiers["admitted_domains"], *dispatch["admitted_domains"],
            *callbacks["admitted_domains"],
        ]
    }
    residual_obligations = sorted(
        obligation_by_id.values(), key=lambda row: row["obligation_id"]
    )
    admitted_domains = sorted(
        domain_by_id.values(), key=lambda row: row["domain_sha256"]
    )
    definitions = _definition_catalog(semantic)
    roots, active_symbols = _normalized_roots_and_may_symbols(
        linked, definitions, admitted_domains, semantic
    )
    may_symbol_ids = {str(row["symbol_id"]) for row in active_symbols}
    active_relocations = _active_relocations(
        linked, active_symbols, _checked_no_return_sources(semantic)
    )
    active_objects = _active_objects(linked, active_symbols)
    runtime_provider_effects = _runtime_provider_effects_v2(
        semantic=semantic, active_symbols=active_symbols,
        definitions=definitions,
    )
    exception_effects = _exception_effects_v2(
        semantic=semantic, active_symbols=active_symbols,
        definitions=definitions,
    )
    external_contract_effects = _external_contract_effects_v2(
        semantic=semantic, active_symbols=active_symbols
    )
    lifecycle_effects = _lifecycle_effects_v2(
        semantic=semantic, active_symbols=active_symbols
    )
    (
        nonlocal_effects,
        nonlocal_obligations,
        nonlocal_holes,
    ) = _nonlocal_effects_and_holes_v2(
        semantic=semantic, active_symbols=active_symbols
    )
    for row in nonlocal_obligations:
        obligation_by_id[str(row["obligation_id"])] = row
    residual_obligations = sorted(
        obligation_by_id.values(), key=lambda row: row["obligation_id"]
    )
    export_effects, export_holes = _export_capability_effects_v2(
        semantic=semantic, active_symbols=active_symbols
    )
    import_use_effects, import_use_holes = _import_use_effects_v2(
        semantic=semantic, active_symbols=active_symbols
    )
    for row in external_service_obligations_v2(
        semantic=semantic,
        external_contract_effects=external_contract_effects,
        import_use_effects=import_use_effects,
    ):
        obligation_by_id[str(row["obligation_id"])] = row
    residual_obligations = sorted(
        obligation_by_id.values(), key=lambda row: row["obligation_id"]
    )
    definition_requirements = _definition_requirements(
        definitions, active_symbols
    )
    provider_holes = [{
        "code": "may_reachable_symbol_has_no_provider",
        "subject": f"active-symbol:{row['symbol_id']}",
        "evidence_sha256": canonical_sha256_v3(row),
    } for row in definition_requirements if not row["allowed_provider_kinds"]]
    provider_holes = [{
        "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(row)}", **row,
    } for row in provider_holes]
    relocation_holes = [{
        "code": "may_reachable_relocation_unresolved",
        "subject": f"relocation:{row['relocation_id']}",
        "evidence_sha256": canonical_sha256_v3(row),
    } for row in active_relocations if row["status"] == "unresolved_reachable"]
    relocation_holes = [{
        "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(row)}", **row,
    } for row in relocation_holes]
    semantic_holes = sorted(
        [
            *_transfer_plan_holes_v2(transfer_plan),
            *_semantic_object_holes_v2(
                semantic=semantic, active_symbols=active_symbols,
                active_relocations=active_relocations,
            ),
            *frontiers["semantic_holes"], *callbacks["semantic_holes"],
            *import_use_holes, *nonlocal_holes, *export_holes,
            *provider_holes,
            *relocation_holes,
        ],
        key=lambda row: row["hole_id"],
    )
    link_provenance = dict(_mapping(
        linked.get("link_provenance"), "semantic link provenance"
    ))
    core: dict[str, Any] = {
        "format": LINKED_SEMANTIC_MODULE_V2_FORMAT,
        "status": (
            "complete" if not semantic_holes else "incomplete"
        ),
        "authority": False,
        "bindings": {
            key: value for key, value in bindings.items()
            if key != "module_execution_closure_sha256"
        },
        "definitions": definitions,
        "roots": roots,
        "active_symbols": active_symbols,
        "may_reach": {
            "widened_by_dynamic_dispatch": dynamic_widened,
            "direct_control_edges_sha256": canonical_sha256_v3(
                transfer_plan["direct_control_edges"]
            ),
            "may_symbol_ids_sha256": canonical_sha256_v3(
                sorted(may_symbol_ids)
            ),
            "admitted_domain_sha256s": sorted(domain_by_id),
        },
        "active_relocations": active_relocations,
        "active_objects": active_objects,
        "effects": {
            "runtime_providers": runtime_provider_effects,
            "exceptions": exception_effects,
            "external_contracts": external_contract_effects,
            "lifecycle": lifecycle_effects,
            "nonlocal_transitions": nonlocal_effects,
            "export_capabilities": export_effects,
            "import_uses": import_use_effects,
            # Every indirect site is inventoried from the V2 may universe.
            # Worklist target rows are optional target-precision evidence,
            # not a total runtime dispatch plan.
            "indirect_targets": dispatch["effects"],
            # Callback capability publication is runtime-authorizing and must
            # be total over V2 may reach.  Never inherit the static
            # must-analysis subset here.
            "callbacks": callbacks["effects"],
            # Static capability rows carry only worklist target precision.
            # V2 publishes checked capabilities transactionally through the
            # per-site obligations above instead of treating those rows as a
            # complete registry.
            "code_capabilities": [],
        },
        "definition_requirements": definition_requirements,
        "residual_obligations": residual_obligations,
        "admitted_domains": admitted_domains,
        "semantic_holes": semantic_holes,
        "analysis_frontiers": sorted(
            frontiers["analysis_frontiers"],
            key=lambda row: row["frontier_id"],
        ),
        "link_provenance": link_provenance,
        "counts": {
            "definitions": len(definitions),
            "roots": len(roots),
            "active_symbols": len(active_symbols),
            "direct_control_edges": len(transfer_plan["direct_control_edges"]),
            "active_relocations": len(active_relocations),
            "active_objects": len(active_objects),
            "definition_requirements": len(definition_requirements),
            "residual_obligations": len(residual_obligations),
            "admitted_domains": len(admitted_domains),
            "semantic_holes": len(semantic_holes),
            "analysis_frontiers": len(frontiers["analysis_frontiers"]),
        },
    }
    core["linked_semantic_module_sha256"] = canonical_sha256_v3(core)
    LinkedSemanticModuleV2.parse(core)
    return core






def linked_execution_view_v2(
    linked: LinkedSemanticModuleV2,
) -> dict[str, Any]:
    """Project exact V2 runtime facts into a construction-local runtime view.

    This is not a serialized compatibility artifact and performs no analysis.
    Native ingress consumes it while its internal APIs are migrated to V2
    names.  Semantic holes remain blockers; optional analysis frontiers are
    deliberately absent.
    """

    payload = linked.payload
    semantic = linked.semantic_object
    if semantic is None:
        _fail("V2 execution view requires the packaged semantic object")
    symbols = {
        str(row["symbol_id"]): _mapping(row, "V2 active symbol")
        for row in payload["active_symbols"]
    }
    reachable_units = []
    for symbol_id, symbol in symbols.items():
        prefix = "original:function:"
        rva = symbol.get("original_rva")
        if symbol.get("kind") != "function":
            continue
        if (
            not symbol_id.startswith(prefix) or len(symbol_id) == len(prefix)
            or not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
        ):
            _fail("active V2 function has no canonical transfer identity")
        reachable_units.append({
            "unit_id": symbol_id[len(prefix):], "rva": rva,
        })
    reachable_units.sort(key=lambda row: (row["rva"], row["unit_id"]))

    roots_by_id = {
        str(row["root_id"]): _mapping(row, "V2 root")
        for row in payload["roots"]
    }
    executable_root_ids = {
        root_id for root_id, root in roots_by_id.items()
        if root.get("kind") != "loader_storage"
        and symbols.get(str(root.get("target_symbol")), {}).get("kind")
        == "function"
    }
    roots = sorted({
        int(roots_by_id[root_id]["original_rva"])
        for root_id in executable_root_ids
    })

    reachable_edges: list[dict[str, Any]] = []
    for raw in payload["active_relocations"]:
        relocation = _mapping(raw, "V2 active relocation")
        if relocation.get("kind") not in {"direct_control", "internal_call"}:
            continue
        source = symbols.get(str(relocation.get("source_symbol")))
        targets = relocation.get("target_symbols")
        target = (
            symbols.get(str(targets[0]))
            if isinstance(targets, list) and len(targets) == 1 else None
        )
        if (
            source is None or target is None
            or source.get("kind") != "function"
            or target.get("kind") != "function"
        ):
            continue
        reachable_edges.append({
            "source_rva": int(source["original_rva"]),
            "target_rva": int(target["original_rva"]),
            "kind": str(relocation["kind"]),
        })
    reachable_edges.sort(key=lambda row: (
        row["source_rva"], row["target_rva"], row["kind"],
    ))

    domain_by_id = {
        str(row["domain_sha256"]): _mapping(row, "V2 admitted domain")
        for row in payload["admitted_domains"]
    }
    effects = _mapping(payload.get("effects"), "V2 effects")
    callback_escapes = []
    for raw in effects["callbacks"]:
        effect = _mapping(raw, "V2 callback effect")
        reference = _mapping(
            effect.get("admitted_domain"), "V2 callback domain reference"
        )
        domain = domain_by_id.get(str(reference.get("domain_sha256")))
        identity = _mapping(
            effect.get("external_identity"), "V2 callback external identity"
        )
        targets = None if domain is None else domain.get("targets")
        name = identity.get("symbol")
        if name is None:
            name = identity.get("ordinal")
        if (
            domain is None or domain.get("kind")
            != "checked_callback_transfer_entry_rvas"
            or not isinstance(targets, list) or not targets
            or not isinstance(name, (str, int)) or isinstance(name, bool)
        ):
            _fail("V2 callback effect has no executable admitted domain")
        callback_escapes.append({
            "instruction_rva": effect["instruction_rva"],
            "dll": str(identity["dll"]),
            "identity": name,
            "protocol_id": effect["callback_protocol_id"],
            "targets": list(targets),
            "action": effect["action"],
            "lifetime": effect["lifetime"],
            "delivery": dict(_mapping(
                effect.get("delivery"), "V2 callback delivery"
            )),
        })
    callback_escapes.sort(key=canonical_sha256_v3)

    exception_continuations = []
    for raw in effects["exceptions"]:
        effect = _mapping(raw, "V2 exception effect")
        occurrence = _mapping(
            effect.get("occurrence"), "V2 exception occurrence"
        )
        transition = _mapping(
            effect.get("transition"), "V2 exception transition"
        )
        root_rvas = sorted({
            int(roots_by_id[root_id]["original_rva"])
            for root_id in effect.get("root_ids", [])
            if root_id in executable_root_ids
        })
        exception_continuations.append({
            **dict(occurrence),
            "disposition": transition.get("disposition"),
            "guard": transition.get("guard"),
            "handler_rva": transition.get("handler_rva"),
            "handler_unit_id": transition.get("handler_unit_id"),
            "resumption_rva": transition.get("resumption_rva"),
            "resumption_unit_id": transition.get("resumption_unit_id"),
            "state_projection": transition.get("state_projection"),
            "transition_id": transition.get("transition_id"),
            "transition_sha256": transition.get("transition_sha256"),
            "unwind_unit_ids": list(transition.get("unwind_unit_ids", [])),
            "root_rvas": root_rvas,
        })
    exception_continuations.sort(key=canonical_sha256_v3)

    bindings = _mapping(payload.get("bindings"), "V2 bindings")
    return {
        "status": payload["status"],
        "linked_semantic_module_sha256": linked.identity,
        # Retained only in memory so direct V2 consumers lower the validated
        # shared domains/effects without reopening or reconstructing them.
        "_linked_semantic_module_v2": payload,
        "bindings": {
            "executable_transfer_plan_sha256": sha256_file(
                semantic.transfer_plan_path
            ),
            "resolved_external_environment_sha256": bindings[
                "resolved_external_environment_content_sha256"
            ],
        },
        "roots": roots,
        "reachable_units": reachable_units,
        "reachable_edges": reachable_edges,
        "indirect_targets": [
            dict(_mapping(row, "V2 indirect effect"))
            for row in effects["indirect_targets"]
        ],
        "callback_escapes": callback_escapes,
        "exception_continuations": exception_continuations,
        "nonlocal_transitions": [
            {
                "id": str(row["effect_id"]),
                "source_rva": int(row["source_rva"]),
                "target_rva": int(row["target_rva"]),
                "target_function_entry_rva": int(
                    row["target_function_entry_rva"]
                ),
            }
            for row in effects["nonlocal_transitions"]
        ],
        "blockers": [
            dict(_mapping(row, "V2 semantic hole"))
            for row in payload["semantic_holes"]
        ],
    }


def write_linked_semantic_module_from_inputs_v2(
    *, semantic_object: Path, out: Path,
) -> dict[str, Any]:
    """Run the conservative semantic link once and publish V2 directly."""

    output = Path(out)
    semantic, link_facts = compile_semantic_may_link_facts_v2(
        semantic_object=semantic_object,
    )
    payload = build_linked_semantic_module_v2(
        semantic=semantic,
        link_facts=link_facts,
    )
    publish_semantic_package_v1(
        semantic=semantic, semantic_object=Path(semantic_object), out=output
    )
    write_json(output / "linked-semantic-module.json", payload)
    return payload


__all__ = [
    "LinkedSemanticModuleV2", "SemanticLinkFactsV2",
    "build_linked_semantic_module_v2",
    "write_linked_semantic_module_from_inputs_v2",
]
