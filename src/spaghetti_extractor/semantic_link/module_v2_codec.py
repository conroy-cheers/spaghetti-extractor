"""Closed codec for linked-semantic-module-v2 packages."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.formats import CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT
from ..semantic_objects.semantic_object import SemanticObjectV1
from ..util import sha256_file
from .formats import LINKED_SEMANTIC_MODULE_V2_FORMAT
from .may_link import MAY_LINK_ALGORITHM_V1
from .module_v2_effects import _import_code_use_subject
from .module_v2_core import (
    _FIELDS,
    _OBLIGATION_CLASSES,
    _PROVIDER_KINDS,
    _check_content_identity,
    _definition_catalog,
    _fail,
    _identity_rows,
    _import_identity_key,
    _load_json,
    _mapping,
    _sha256,
)

@dataclass(frozen=True)
class LinkedSemanticModuleV2:
    payload: Mapping[str, Any]
    package_root: Path | None = None
    package_members: Mapping[str, Path] | None = None
    semantic_object: SemanticObjectV1 | None = None

    @property
    def identity(self) -> str:
        return str(self.payload["linked_semantic_module_sha256"])

    @property
    def semantic_complete(self) -> bool:
        return self.payload["status"] == "complete"

    @classmethod
    def parse(
        cls, value: object, *, require_complete: bool = False,
    ) -> "LinkedSemanticModuleV2":
        payload = dict(_mapping(value, "linked semantic module V2"))
        if set(payload) != _FIELDS:
            _fail("linked-semantic-module V2 fields are incomplete")
        if payload.get("format") != LINKED_SEMANTIC_MODULE_V2_FORMAT:
            _fail("linked-semantic-module V2 format is unsupported")
        declared = _sha256(
            payload.get("linked_semantic_module_sha256"),
            "linked-semantic-module V2 identity",
        )
        core = {
            key: item for key, item in payload.items()
            if key != "linked_semantic_module_sha256"
        }
        if canonical_sha256_v3(core) != declared:
            _fail("linked-semantic-module V2 self hash is stale")
        if payload.get("authority") is not False:
            _fail("linked-semantic-module V2 cannot authorize execution")
        bindings = _mapping(payload.get("bindings"), "V2 bindings")
        required_bindings = {
            "semantic_object_sha256", "semantic_object_content_sha256",
            "executable_transfer_plan_sha256", "module_interface_sha256",
            "resolved_external_environment_sha256",
            "resolved_external_environment_content_sha256",
            "machine_object_authority_sha256",
            "machine_object_authority_content_sha256",
        }
        extra_bindings = set(bindings) - required_bindings
        if (
            not required_bindings <= set(bindings)
            or extra_bindings not in (set(), {"qualified_platform_sha256"})
            or any(
            _sha256(value, f"V2 binding {key}") != value
            for key, value in bindings.items()
            )
        ):
            _fail("linked-semantic-module V2 bindings are malformed")

        definitions = _identity_rows(
            payload.get("definitions"), context="V2 definition",
            identity_field="symbol_id",
        )
        definition_ids: set[str] = set()
        definition_by_symbol: dict[str, str] = {}
        definition_kind_by_symbol: dict[str, str] = {}
        for row in definitions:
            if set(row) != {
                "definition_id", "symbol_id", "definition_kind",
                "definition_sha256", "dependency_contract_sha256s",
            }:
                _fail("V2 definition fields are incomplete")
            _sha256(row.get("definition_sha256"), "definition hash")
            dependencies = row.get("dependency_contract_sha256s")
            if (
                not isinstance(dependencies, list)
                or dependencies != sorted(set(dependencies))
                or any(
                    _sha256(item, "definition dependency contract") != item
                    for item in dependencies
                )
            ):
                _fail("V2 definition evidence dependencies are malformed")
            _check_content_identity(
                row, identity_field="definition_id",
                prefix="semantic-definition-v2:",
            )
            definition_id = str(row["definition_id"])
            if definition_id in definition_ids:
                _fail("V2 definition identities are duplicated")
            definition_ids.add(definition_id)
            definition_by_symbol[str(row["symbol_id"])] = definition_id
            definition_kind_by_symbol[str(row["symbol_id"])] = str(
                row["definition_kind"]
            )

        roots = _identity_rows(
            payload.get("roots"), context="V2 root", identity_field="root_id"
        )
        for row in roots:
            if (
                set(row) != {
                    "root_id", "kind", "origin", "original_rva",
                    "target_symbol",
                }
                or not isinstance(row.get("kind"), str)
                or not isinstance(row.get("origin"), str)
                or not isinstance(row.get("original_rva"), int)
                or isinstance(row.get("original_rva"), bool)
                or row["original_rva"] < 0
            ):
                _fail("V2 root is malformed")
        root_ids = {str(row["root_id"]) for row in roots}
        symbols = _identity_rows(
            payload.get("active_symbols"), context="V2 active symbol",
            identity_field="symbol_id",
        )
        symbol_ids = {str(row["symbol_id"]) for row in symbols}
        referenced_domain_ids: set[str] = set()
        for row in symbols:
            if set(row) != {
                "symbol_id", "kind", "original_rva", "resolution",
                "definition_id", "root_ids", "domain_ids",
            }:
                _fail("V2 active-symbol fields are incomplete")
            symbol_roots = row.get("root_ids")
            symbol_domains = row.get("domain_ids")
            definition_id = row.get("definition_id")
            resolution = _mapping(row.get("resolution"), "V2 symbol resolution")
            if (
                not isinstance(symbol_roots, list)
                or symbol_roots != sorted(set(symbol_roots))
                or not set(symbol_roots) <= root_ids
                or not isinstance(symbol_domains, list)
                or symbol_domains != sorted(set(symbol_domains))
                or not symbol_roots and not symbol_domains
                or not isinstance(row.get("kind"), str)
                or not isinstance(row.get("original_rva"), (int, type(None)))
                or isinstance(row.get("original_rva"), bool)
                or isinstance(row.get("original_rva"), int)
                and row["original_rva"] < 0
                or not isinstance(resolution.get("kind"), str)
                or definition_id is not None and definition_id not in definition_ids
                or (
                    resolution.get("kind") == "semantic_definition"
                    and definition_id != definition_by_symbol.get(str(row["symbol_id"]))
                )
            ):
                _fail("V2 active-symbol resolution or provenance is malformed")
            referenced_domain_ids.update(str(item) for item in symbol_domains)
        for row in roots:
            if row.get("target_symbol") not in symbol_ids:
                _fail("V2 root target is not active")

        may_reach = _mapping(payload.get("may_reach"), "V2 may reach")
        if (
            set(may_reach) != {
                "widened_by_dynamic_dispatch", "direct_control_edges_sha256",
                "may_symbol_ids_sha256", "admitted_domain_sha256s",
            }
            or not isinstance(may_reach.get("widened_by_dynamic_dispatch"), bool)
            or _sha256(
                may_reach.get("direct_control_edges_sha256"),
                "V2 direct-edge binding",
            ) != may_reach.get("direct_control_edges_sha256")
            or _sha256(
                may_reach.get("may_symbol_ids_sha256"),
                "V2 may-symbol binding",
            ) != canonical_sha256_v3(sorted(symbol_ids))
            or not isinstance(may_reach.get("admitted_domain_sha256s"), list)
            or may_reach["admitted_domain_sha256s"]
            != sorted(set(may_reach["admitted_domain_sha256s"]))
        ):
            _fail("V2 may-reach binding is malformed or stale")

        relocations = _identity_rows(
            payload.get("active_relocations"), context="V2 relocation",
            identity_field="relocation_id",
        )
        unresolved_relocation_subjects: set[str] = set()
        for row in relocations:
            if set(row) != {
                "relocation_id", "kind", "source_symbol", "site", "addend",
                "offset", "required_view", "selector_value", "status",
                "target_symbols",
            }:
                _fail("V2 relocation fields are incomplete")
            targets = row.get("target_symbols")
            status = row.get("status")
            site = row.get("site")
            if (
                row.get("source_symbol") not in symbol_ids
                or not isinstance(targets, list)
                or targets != sorted(set(targets))
                or not set(targets) <= symbol_ids
                or status not in {
                    "resolved", "external_declaration", "runtime_obligation",
                    "checked_infeasible", "unresolved_reachable",
                }
            ):
                _fail("V2 active relocation is unresolved or disconnected")
            if status == "runtime_obligation":
                source = str(row["source_symbol"])
                prefix = "original:function:"
                if (
                    row.get("kind") != "indirect_call"
                    or not source.startswith(prefix)
                    or not isinstance(site, Mapping)
                    or not isinstance(site.get("call_id"), int)
                    or isinstance(site.get("call_id"), bool)
                    or targets
                ):
                    _fail("V2 unresolved relocation is not runtime-dispatchable")
                unresolved_relocation_subjects.add(
                    f"{source[len(prefix):]}:call:{site['call_id']}"
                )
            elif status == "checked_infeasible" and (
                row.get("kind") != "direct_control" or targets
            ):
                _fail("V2 infeasible relocation classification is malformed")

        objects = _identity_rows(
            payload.get("active_objects"), context="V2 active object",
            identity_field="object_id",
        )
        for row in objects:
            if (
                set(row) != {
                    "object_id", "semantic_symbol_id", "root_ids", "domain_ids"
                }
                or row.get("semantic_symbol_id") not in symbol_ids
                or not isinstance(row.get("root_ids"), list)
                or not set(row["root_ids"]) <= root_ids
                or not isinstance(row.get("domain_ids"), list)
                or not row["root_ids"] and not row["domain_ids"]
            ):
                _fail("V2 active object is malformed or disconnected")
            referenced_domain_ids.update(
                str(item) for item in row["domain_ids"]
            )

        requirements = _identity_rows(
            payload.get("definition_requirements"),
            context="V2 definition requirement", identity_field="symbol_id",
        )
        if {str(row["symbol_id"]) for row in requirements} != symbol_ids:
            _fail("V2 definition requirements are not total")
        for row in requirements:
            providers = row.get("allowed_provider_kinds")
            dependencies = row.get("dependency_contract_sha256s")
            if (
                set(row) != {
                    "symbol_id", "definition_id", "allowed_provider_kinds",
                    "dependency_contract_sha256s",
                }
                or row.get("definition_id") not in {
                    None, definition_by_symbol.get(str(row["symbol_id"]))
                }
                or not isinstance(providers, list)
                or providers != sorted(set(providers))
                or not set(providers) <= _PROVIDER_KINDS
                or not isinstance(dependencies, list)
                or dependencies != sorted(set(dependencies))
                or any(
                    _sha256(item, "requirement dependency contract") != item
                    for item in dependencies
                )
            ):
                _fail("V2 definition requirement is malformed")

        domains = _identity_rows(
            payload.get("admitted_domains"), context="V2 admitted domain",
            identity_field="domain_sha256",
        )
        domain_ids = set()
        for row in domains:
            domain_id = _sha256(row.get("domain_sha256"), "domain identity")
            targets = row.get("targets")
            kind = row.get("kind")
            if kind == "frame_compatible_transfer_entry_rvas":
                common_malformed = (
                    not isinstance(targets, list) or not targets
                    or targets != sorted(set(targets))
                    or any(
                        not isinstance(item, int) or isinstance(item, bool)
                        or item < 0 for item in targets
                    )
                )
                malformed = (
                    set(row) != {
                        "kind", "physical_frame", "targets", "domain_sha256",
                    }
                    or row.get("physical_frame")
                    != "logical_machine_state_v2"
                )
            elif kind == "checked_callback_transfer_entry_rvas":
                common_malformed = (
                    not isinstance(targets, list) or not targets
                    or targets != sorted(set(targets))
                    or any(
                        not isinstance(item, int) or isinstance(item, bool)
                        or item < 0 for item in targets
                    )
                )
                malformed = (
                    set(row) != {
                        "kind", "protocol_id", "protocol_sha256",
                        "physical_signature_sha256", "targets",
                        "domain_sha256",
                    }
                    or not isinstance(row.get("protocol_id"), str)
                    or not row.get("protocol_id")
                    or _sha256(
                        row.get("protocol_sha256"), "callback protocol identity"
                    ) != row.get("protocol_sha256")
                    or _sha256(
                        row.get("physical_signature_sha256"),
                        "callback physical signature identity",
                    ) != row.get("physical_signature_sha256")
                )
            elif kind == "checked_indirect_callable_targets_v3":
                guest_targets = row.get("guest_transfer_entry_rvas")
                external_targets = row.get("external_loader_targets")
                interface_targets = row.get("external_interface_targets")
                selection = row.get("selection")
                common_malformed = (
                    not isinstance(guest_targets, list) or not guest_targets
                    or guest_targets != sorted(set(guest_targets))
                    or any(
                        not isinstance(item, int) or isinstance(item, bool)
                        or item < 0 for item in guest_targets
                    )
                    or not isinstance(external_targets, list)
                    or not isinstance(interface_targets, list)
                )
                malformed = (
                    set(row) != {
                        "kind", "logical_guest_frame",
                        "resolved_environment_sha256",
                        "guest_transfer_entry_rvas", "external_loader_targets",
                        "external_interface_targets",
                        "selection", "domain_sha256",
                    }
                    or row.get("logical_guest_frame")
                    != "logical_machine_state_v2"
                    or _sha256(
                        row.get("resolved_environment_sha256"),
                        "callable-domain environment identity",
                    ) != row.get("resolved_environment_sha256")
                    or row.get("resolved_environment_sha256")
                    != bindings.get("resolved_external_environment_sha256")
                    or isinstance(external_targets, list)
                    and external_targets != sorted(
                        external_targets, key=canonical_sha256_v3
                    )
                    or isinstance(interface_targets, list)
                    and interface_targets != sorted(
                        interface_targets, key=canonical_sha256_v3
                    )
                    or selection != {
                        "guest": "active_code_capability_address",
                        "external": "checked_loader_code_capability",
                        "interface": (
                            "live_factory_interface_vtable_method_capability"
                        ),
                        "ambiguity": "reject",
                        "no_match": "reject",
                    }
                )
                seen_external: set[tuple[str, str]] = set()
                for raw_external in (
                    external_targets if isinstance(external_targets, list)
                    else []
                ):
                    external = _mapping(
                        raw_external, "callable-domain external target"
                    )
                    identity = _mapping(
                        external.get("identity"),
                        "callable-domain external identity",
                    )
                    identity_key = _import_identity_key(identity)
                    frame_id = external.get("physical_frame_id")
                    if (
                        set(external) != {
                            "identity", "import_kind", "cell_index", "iat_rva",
                            "contract_sha256", "physical_frame_id",
                            "physical_frame_sha256",
                        }
                        or identity_key is None
                        or identity_key in seen_external
                        or external.get("import_kind") not in {
                            "ordinary", "delay", "dynamic_export",
                        }
                        or (
                            external.get("import_kind") in {"ordinary", "delay"}
                            and (
                                not isinstance(external.get("cell_index"), int)
                                or isinstance(external.get("cell_index"), bool)
                                or external["cell_index"] < 0
                                or not isinstance(external.get("iat_rva"), int)
                                or isinstance(external.get("iat_rva"), bool)
                                or external["iat_rva"] < 0
                            )
                        )
                        or (
                            external.get("import_kind") == "dynamic_export"
                            and (
                                external.get("cell_index") is not None
                                or external.get("iat_rva") is not None
                            )
                        )
                        or not isinstance(frame_id, str) or not frame_id
                        or _sha256(
                            external.get("contract_sha256"),
                            "callable-domain external contract",
                        ) != external.get("contract_sha256")
                        or _sha256(
                            external.get("physical_frame_sha256"),
                            "callable-domain physical frame",
                        ) != external.get("physical_frame_sha256")
                    ):
                        malformed = True
                    if identity_key is not None:
                        seen_external.add(identity_key)
                seen_interface: set[tuple[str, str, int]] = set()
                for raw_interface in (
                    interface_targets if isinstance(interface_targets, list)
                    else []
                ):
                    interface = _mapping(
                        raw_interface, "callable-domain interface target"
                    )
                    method = _mapping(
                        interface.get("method"),
                        "callable-domain interface method",
                    )
                    protocol = _mapping(
                        method.get("external_protocol"),
                        "callable-domain interface protocol",
                    )
                    profile_sha256 = interface.get("profile_sha256")
                    interface_id = interface.get("interface_id")
                    slot = protocol.get("slot")
                    contract_sha256 = interface.get(
                        "method_contract_sha256"
                    )
                    core = {
                        key: value for key, value in interface.items()
                        if key != "method_contract_sha256"
                    }
                    interface_key = (profile_sha256, interface_id, slot)
                    if (
                        set(interface) != {
                            "profile_id", "profile_sha256", "interface_id",
                            "method", "method_contract_sha256",
                        }
                        or _sha256(
                            profile_sha256, "interface profile identity"
                        ) != profile_sha256
                        or not isinstance(interface_id, str)
                        or not interface_id
                        or protocol.get("kind") != "pe32-interface-method"
                        or protocol.get("profile_id")
                        != interface.get("profile_id")
                        or protocol.get("profile_sha256") != profile_sha256
                        or protocol.get("interface_id") != interface_id
                        or not isinstance(slot, int)
                        or isinstance(slot, bool)
                        or slot < 0
                        or protocol.get("offset") != slot * 4
                        or interface_key in seen_interface
                        or _sha256(
                            contract_sha256,
                            "interface method contract identity",
                        ) != canonical_sha256_v3(core)
                    ):
                        malformed = True
                        continue
                    seen_interface.add(interface_key)
            else:
                common_malformed = True
                malformed = True
            if common_malformed or malformed:
                _fail("V2 admitted-domain catalog is malformed")
            if canonical_sha256_v3({
                key: value for key, value in row.items()
                if key != "domain_sha256"
            }) != domain_id:
                _fail("V2 admitted-domain identity is stale")
            domain_ids.add(domain_id)
        if not referenced_domain_ids <= domain_ids:
            _fail("V2 may-reach provenance names an unknown admitted domain")
        if may_reach["admitted_domain_sha256s"] != sorted(domain_ids):
            _fail("V2 may-reach admitted-domain binding is stale")

        obligations = _identity_rows(
            payload.get("residual_obligations"), context="V2 obligation",
            identity_field="obligation_id",
        )
        obligation_ids = set()
        dispatch_subjects: set[str] = set()
        callback_subjects: set[str] = set()
        for row in obligations:
            if set(row) != {
                "obligation_id", "class", "subjects",
                "semantic_contract_sha256", "admitted_domain",
                "evidence_dependencies", "allowed_provider_kinds",
            }:
                _fail("V2 obligation fields are incomplete")
            domain = _mapping(row.get("admitted_domain"), "obligation domain")
            subjects = row.get("subjects")
            evidence_dependencies = row.get("evidence_dependencies")
            if (
                domain.get("kind") == "catalog_reference"
                and domain.get("domain_sha256") not in domain_ids
            ):
                _fail("V2 obligation names an unknown admitted domain")
            providers = row.get("allowed_provider_kinds")
            if (
                row.get("class") not in _OBLIGATION_CLASSES
                or not isinstance(subjects, list) or not subjects
                or subjects != sorted(set(subjects))
                or any(not isinstance(item, str) or not item for item in subjects)
                or not isinstance(evidence_dependencies, list)
                or not evidence_dependencies
                or evidence_dependencies != sorted(set(evidence_dependencies))
                or any(
                    not isinstance(item, str) or not item
                    for item in evidence_dependencies
                )
                or not isinstance(providers, list) or not providers
                or providers != sorted(set(providers))
                or not set(providers) <= _PROVIDER_KINDS
            ):
                _fail("V2 obligation provider inventory is malformed")
            _sha256(
                row.get("semantic_contract_sha256"),
                "V2 obligation semantic contract",
            )
            _check_content_identity(
                row, identity_field="obligation_id",
                prefix="residual-obligation-v2:",
            )
            obligation_ids.add(str(row["obligation_id"]))
            if row.get("class") in {
                "internal_code_dispatch", "indirect_external_callthrough",
            }:
                subjects = row.get("subjects")
                if not isinstance(subjects, list):
                    _fail("V2 dispatch obligation subjects are malformed")
                dispatch_subjects.update(
                    str(subject) for subject in subjects
                    if isinstance(subject, str)
                )
            elif row.get("class") == "callback_capability_publication":
                callback_subjects.update(
                    str(subject) for subject in subjects
                    if isinstance(subject, str)
                )
        obligations_by_id = {
            str(row["obligation_id"]): row for row in obligations
        }
        if not unresolved_relocation_subjects <= dispatch_subjects:
            _fail("V2 unresolved relocations lack runtime dispatch obligations")
        if (
            may_reach["widened_by_dynamic_dispatch"]
            and not dispatch_subjects and not callback_subjects
        ):
            _fail("V2 dynamic-dispatch widening state is stale")

        frontiers = _identity_rows(
            payload.get("analysis_frontiers"), context="V2 analysis frontier",
            identity_field="frontier_id",
        )
        for row in frontiers:
            if (
                set(row) != {
                    "frontier_id", "class", "subject", "diagnostic_sha256",
                    "obligation_ids",
                }
                or not isinstance(row.get("class"), str)
                or not isinstance(row.get("subject"), str)
                or not isinstance(row.get("obligation_ids"), list)
                or not row["obligation_ids"]
                or not set(row["obligation_ids"]) <= obligation_ids
            ):
                _fail("V2 analysis frontier has no checked obligation")
            _sha256(row.get("diagnostic_sha256"), "V2 diagnostic identity")
            _check_content_identity(
                row, identity_field="frontier_id",
                prefix="analysis-frontier-v2:",
            )

        holes = _identity_rows(
            payload.get("semantic_holes"), context="V2 semantic hole",
            identity_field="hole_id",
        )
        for row in holes:
            if set(row) != {
                "hole_id", "code", "subject", "evidence_sha256"
            } or not isinstance(row.get("code"), str) or not isinstance(
                row.get("subject"), str
            ):
                _fail("V2 semantic-hole fields are incomplete")
            _sha256(row.get("evidence_sha256"), "V2 hole evidence")
            _check_content_identity(
                row, identity_field="hole_id", prefix="semantic-hole-v2:"
            )
        status = payload.get("status")
        if (
            status not in {"complete", "incomplete"}
            or (status == "complete") != (not holes)
            or require_complete and holes
            or status == "complete" and any(
                row.get("definition_id") is None
                or not row.get("allowed_provider_kinds")
                for row in requirements
            )
        ):
            _fail("V2 semantic-completeness status is inconsistent")

        provenance = _mapping(
            payload.get("link_provenance"), "V2 link provenance"
        )
        if set(provenance) != {
            "algorithm", "root_inventory_sha256",
            "relocation_inventory_sha256",
            "runtime_dependency_inventory_sha256",
        }:
            _fail("V2 link provenance fields are incomplete")
        if provenance.get("algorithm") != MAY_LINK_ALGORITHM_V1:
            _fail("V2 link provenance algorithm is unsupported")
        for field in (
            "root_inventory_sha256", "relocation_inventory_sha256",
            "runtime_dependency_inventory_sha256",
        ):
            if _sha256(provenance.get(field), f"V2 {field}") != provenance[field]:
                _fail("V2 link provenance is malformed")

        counts = _mapping(payload.get("counts"), "V2 counts")
        direct_edge_count = counts.get("direct_control_edges")
        if (
            not isinstance(direct_edge_count, int)
            or isinstance(direct_edge_count, bool) or direct_edge_count < 0
        ):
            _fail("V2 direct-edge count is malformed")
        expected_counts = {
            "definitions": len(definitions),
            "roots": len(roots),
            "active_symbols": len(symbols),
            "direct_control_edges": direct_edge_count,
            "active_relocations": len(relocations),
            "active_objects": len(objects),
            "definition_requirements": len(requirements),
            "residual_obligations": len(obligations),
            "admitted_domains": len(domains),
            "semantic_holes": len(holes),
            "analysis_frontiers": len(frontiers),
        }
        if counts != expected_counts:
            _fail("linked-semantic-module V2 counts are stale")
        effects = _mapping(payload.get("effects"), "V2 effects")
        if set(effects) != {
            "runtime_providers", "external_contracts", "indirect_targets",
            "callbacks", "code_capabilities", "exceptions",
            "export_capabilities", "import_uses", "nonlocal_transitions",
            "lifecycle",
        } or any(not isinstance(value, list) for value in effects.values()):
            _fail("V2 effect projection is malformed")
        runtime_effects = _identity_rows(
            effects["runtime_providers"], context="V2 runtime-provider effect",
            identity_field="effect_id",
        )
        expected_runtime_symbols = {
            str(row["symbol_id"]): row for row in symbols
            if _mapping(
                row.get("resolution"), "active symbol resolution"
            ).get("kind") == "qualified_platform_primitive"
            and definition_kind_by_symbol.get(str(row["symbol_id"]))
            == "qualified_platform_primitive"
        }
        observed_runtime_symbols: set[str] = set()
        for row in runtime_effects:
            if set(row) != {
                "effect_id", "kind", "provider_id", "symbol_id",
                "definition_id", "qualified_platform_sha256",
                "provider_contract", "provider_contract_sha256",
                "root_ids", "domain_ids",
            }:
                _fail("V2 runtime-provider effect fields are incomplete")
            symbol_id = str(row.get("symbol_id"))
            symbol = expected_runtime_symbols.get(symbol_id)
            contract = _mapping(
                row.get("provider_contract"), "runtime-provider contract"
            )
            if (
                row.get("kind") != "qualified_runtime_provider_effect_v2"
                or symbol is None or symbol_id in observed_runtime_symbols
                or row.get("definition_id") != symbol.get("definition_id")
                or row.get("provider_id")
                != _mapping(
                    symbol.get("resolution"), "runtime symbol resolution"
                ).get("provider_id")
                or contract.get("provider") != row.get("provider_id")
                or contract.get("layer") != "transfer_plan"
                or _sha256(
                    row.get("qualified_platform_sha256"),
                    "runtime qualified-platform identity",
                ) != bindings.get("qualified_platform_sha256")
                or _sha256(
                    row.get("provider_contract_sha256"),
                    "runtime-provider contract identity",
                ) != canonical_sha256_v3(dict(contract))
                or row.get("root_ids") != symbol.get("root_ids")
                or row.get("domain_ids") != symbol.get("domain_ids")
            ):
                _fail("V2 runtime-provider effect is malformed or disconnected")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="runtime-provider-effect-v2:",
            )
            observed_runtime_symbols.add(symbol_id)
        if observed_runtime_symbols != set(expected_runtime_symbols):
            _fail("V2 runtime-provider effects are not total")
        exception_effects = _identity_rows(
            effects["exceptions"], context="V2 exception effect",
            identity_field="effect_id",
        )
        expected_exception_symbols = {
            str(row["symbol_id"]): row for row in symbols
            if row.get("kind") == "exception_transition"
            and _mapping(
                row.get("resolution"), "active exception resolution"
            ).get("definition_kind") == "checked_exception_transition"
        }
        observed_exception_symbols: set[str] = set()
        for row in exception_effects:
            if set(row) != {
                "effect_id", "kind", "symbol_id", "definition_id",
                "occurrence", "transition", "native_exception",
                "root_ids", "domain_ids",
            }:
                _fail("V2 exception-effect fields are incomplete")
            symbol_id = str(row.get("symbol_id"))
            symbol = expected_exception_symbols.get(symbol_id)
            occurrence = _mapping(
                row.get("occurrence"), "exception occurrence"
            )
            transition = _mapping(
                row.get("transition"), "checked exception transition"
            )
            native_exception = _mapping(
                row.get("native_exception"), "native exception contract"
            )
            transition_id = transition.get("transition_id")
            source_transfer_id = occurrence.get("unit_id")
            disposition = transition.get("disposition")
            handler_unit_id = transition.get("handler_unit_id")
            handler_rva = transition.get("handler_rva")
            resumption_unit_id = transition.get("resumption_unit_id")
            resumption_rva = transition.get("resumption_rva")
            unwind_unit_ids = transition.get("unwind_unit_ids")
            routing_authority = _mapping(
                transition.get("routing_authority"),
                "checked exception routing authority",
            )
            routing_kind = routing_authority.get("kind")
            if routing_kind == "checked_exception_protocol_v1":
                protocol_sha256 = _sha256(
                    routing_authority.get("protocol_sha256"),
                    "checked exception protocol identity",
                )
                if (
                    set(routing_authority) != {
                        "kind", "protocol_id", "protocol_sha256",
                    }
                    or routing_authority.get("protocol_id") != (
                        f"checked-exception-protocol-v1:{protocol_sha256}"
                    )
                    or disposition not in {"handled", "terminates"}
                    or not isinstance(transition.get("state_projection"), Mapping)
                    or (
                        disposition == "terminates"
                        and resumption_unit_id is None
                    )
                ):
                    _fail("checked exception protocol routing is malformed")
            elif routing_kind == "launch_policy":
                if (
                    set(routing_authority) != {
                        "kind", "launch_policy_payload_sha256",
                    }
                    or _sha256(
                        routing_authority.get("launch_policy_payload_sha256"),
                        "exception launch-policy identity",
                    ) != routing_authority.get(
                        "launch_policy_payload_sha256"
                    )
                    or disposition != "terminates"
                    or handler_unit_id is not None
                    or resumption_unit_id is not None
                    or unwind_unit_ids != []
                    or transition.get("state_projection") is not None
                ):
                    _fail("launch-policy exception routing is malformed")
            elif routing_kind == "transfer_static_infeasibility":
                if (
                    set(routing_authority) != {
                        "kind", "transition_sha256",
                    }
                    or routing_authority.get("transition_sha256")
                    != transition.get("transition_sha256")
                    or disposition != "infeasible"
                    or handler_unit_id is not None
                    or resumption_unit_id is not None
                    or unwind_unit_ids != []
                    or transition.get("state_projection") is not None
                ):
                    _fail("statically infeasible exception routing is malformed")
            else:
                _fail("checked exception routing authority is unsupported")
            handler_symbol = (
                None if handler_unit_id is None
                else next((
                    candidate for candidate in symbols
                    if candidate.get("symbol_id")
                    == f"original:function:{handler_unit_id}"
                ), None)
            )
            resumption_symbol = (
                None if resumption_unit_id is None
                else next((
                    candidate for candidate in symbols
                    if candidate.get("symbol_id")
                    == f"original:function:{resumption_unit_id}"
                ), None)
            )
            if (
                row.get("kind") != "checked_exception_transition_effect_v2"
                or symbol is None or symbol_id in observed_exception_symbols
                or row.get("definition_id") != symbol.get("definition_id")
                or set(occurrence) != {
                    "unit_id", "source_rva", "occurrence_kind",
                    "effect_index", "call_index", "fault_index",
                    "fault_sha256", "operation",
                }
                or not isinstance(source_transfer_id, str)
                or f"original:function:{source_transfer_id}" not in symbol_ids
                or not isinstance(occurrence.get("source_rva"), int)
                or isinstance(occurrence.get("source_rva"), bool)
                or occurrence["source_rva"] < 0
                or occurrence.get("occurrence_kind")
                not in {"effect", "call"}
                or not isinstance(occurrence.get("effect_index"), int)
                or isinstance(occurrence.get("effect_index"), bool)
                or occurrence["effect_index"] < 0
                or occurrence.get("call_index") is not None
                and (
                    not isinstance(occurrence.get("call_index"), int)
                    or isinstance(occurrence.get("call_index"), bool)
                    or occurrence["call_index"] < 0
                )
                or not isinstance(occurrence.get("fault_index"), int)
                or isinstance(occurrence.get("fault_index"), bool)
                or occurrence["fault_index"] < 0
                or _sha256(
                    occurrence.get("fault_sha256"), "exception fault identity"
                ) != occurrence.get("fault_sha256")
                or not isinstance(occurrence.get("operation"), str)
                or not occurrence.get("operation")
                or not isinstance(transition_id, str) or not transition_id
                or _sha256(
                    transition.get("transition_sha256"),
                    "exception transition identity",
                ) != transition.get("transition_sha256")
                or disposition not in {
                    "handled", "infeasible", "terminates",
                }
                or (handler_unit_id is None) != (handler_rva is None)
                or (resumption_unit_id is None) != (resumption_rva is None)
                or (disposition == "handled") != (handler_unit_id is not None)
                or disposition in {"infeasible", "terminates"}
                and handler_unit_id is not None
                or handler_unit_id is not None
                and (
                    not isinstance(handler_unit_id, str)
                    or not handler_unit_id
                    or not isinstance(handler_rva, int)
                    or isinstance(handler_rva, bool)
                    or handler_rva < 0
                    or handler_symbol is None
                    or handler_symbol.get("original_rva") != handler_rva
                )
                or resumption_unit_id is not None
                and (
                    not isinstance(resumption_unit_id, str)
                    or not resumption_unit_id
                    or not isinstance(resumption_rva, int)
                    or isinstance(resumption_rva, bool)
                    or resumption_rva < 0
                    or resumption_symbol is None
                    or resumption_symbol.get("original_rva") != resumption_rva
                )
                or not isinstance(unwind_unit_ids, list)
                or len(set(unwind_unit_ids)) != len(unwind_unit_ids)
                or any(
                    not isinstance(unit_id, str)
                    or not unit_id
                    or f"original:function:{unit_id}" not in symbol_ids
                    for unit_id in unwind_unit_ids
                )
                or native_exception.get("kind") != "native_exception"
                or row.get("root_ids") != symbol.get("root_ids")
                or row.get("domain_ids") != symbol.get("domain_ids")
            ):
                _fail("V2 exception effect is malformed or disconnected")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="exception-transition-effect-v2:",
            )
            observed_exception_symbols.add(symbol_id)
        if observed_exception_symbols != set(expected_exception_symbols):
            _fail("V2 exception effects are not total")
        external_effects = _identity_rows(
            effects["external_contracts"], context="V2 external effect",
            identity_field="effect_id",
        )
        expected_external_symbols = {
            str(row["symbol_id"]): row for row in symbols
            if _mapping(
                row.get("resolution"), "active symbol resolution"
            ).get("kind") == "checked_external_contract"
        }
        observed_external_symbols: set[str] = set()
        for row in external_effects:
            if set(row) != {
                "effect_id", "kind", "symbol_id", "definition_id",
                "semantic_role", "declaration_role", "identity",
                "contract_sha256",
                "physical_frame_id",
                "physical_frame_sha256", "allowed_outcomes",
                "external_service_protocol", "root_ids", "domain_ids",
            }:
                _fail("V2 external-effect fields are incomplete")
            symbol_id = str(row.get("symbol_id"))
            symbol = expected_external_symbols.get(symbol_id)
            semantic_role = row.get("semantic_role")
            identity = _mapping(
                row.get("identity"), "external-effect identity"
            )
            service = row.get("external_service_protocol")
            service_behavior = (
                service.get("behavior") if isinstance(service, Mapping)
                else None
            )
            service_outcome = (
                service_behavior.get("outcome")
                if isinstance(service_behavior, Mapping) else None
            )
            if (
                row.get("kind") != "checked_external_contract_effect_v2"
                or symbol is None or symbol_id in observed_external_symbols
                or row.get("definition_id") != symbol.get("definition_id")
                or row.get("contract_sha256")
                != _mapping(
                    symbol.get("resolution"), "external symbol resolution"
                ).get("contract_sha256")
                or _import_identity_key(identity) is None
                or _sha256(
                    row.get("contract_sha256"), "external contract identity"
                ) != row.get("contract_sha256")
                or semantic_role not in {
                    "external_function", "loader_import_slot",
                }
                or row.get("declaration_role") not in {
                    "machine_import", "loader_service",
                }
                or service is not None and (
                    not isinstance(service, Mapping)
                    or service.get("format")
                    != CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT
                    or service.get("kind") not in {
                        "nonlocal_unwind", "unhandled_exception_filter",
                    }
                    or service_outcome not in {"normal", "nonlocal"}
                    or semantic_role == "external_function"
                    and service_outcome not in row.get("allowed_outcomes", [])
                )
                or semantic_role == "external_function"
                and symbol.get("kind") != "external_function"
                or semantic_role == "loader_import_slot"
                and symbol.get("kind") != "unclassified_import"
                or semantic_role == "external_function" and (
                    not isinstance(row.get("physical_frame_id"), str)
                    or not row.get("physical_frame_id")
                    or _sha256(
                        row.get("physical_frame_sha256"),
                        "external physical frame",
                    ) != row.get("physical_frame_sha256")
                    or not isinstance(row.get("allowed_outcomes"), list)
                    or not row["allowed_outcomes"] and status == "complete"
                    or row["allowed_outcomes"]
                    != sorted(set(row["allowed_outcomes"]))
                    or not set(row["allowed_outcomes"]) <= {
                        "normal", "no_return", "exceptional", "nonlocal",
                    }
                )
                or semantic_role == "loader_import_slot" and (
                    row.get("physical_frame_id") is not None
                    or row.get("physical_frame_sha256") is not None
                    or row.get("allowed_outcomes") is not None
                )
                or row.get("root_ids") != symbol.get("root_ids")
                or row.get("domain_ids") != symbol.get("domain_ids")
            ):
                _fail("V2 external effect is malformed or disconnected")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="external-contract-effect-v2:",
            )
            observed_external_symbols.add(symbol_id)
        if observed_external_symbols != set(expected_external_symbols):
            _fail("V2 external effects are not total")
        lifecycle_effects = _identity_rows(
            effects["lifecycle"], context="V2 lifecycle effect",
            identity_field="effect_id",
        )
        lifecycle_active_by_symbol = {
            str(row["symbol_id"]): row for row in symbols
        }
        external_by_symbol = {
            str(row["symbol_id"]): row for row in external_effects
            if row.get("semantic_role") == "external_function"
        }
        expected_no_return_sites: set[tuple[str, int, int, str]] = set()
        for relocation in relocations:
            if relocation.get("kind") != "external_call":
                continue
            targets = relocation.get("target_symbols")
            site = _mapping(
                relocation.get("site"), "external-call relocation site"
            )
            if not isinstance(targets, list) or len(targets) != 1:
                _fail("external-call relocation target is ambiguous")
            target = str(targets[0])
            external = external_by_symbol.get(target)
            if external is None or external.get("allowed_outcomes") != [
                "no_return"
            ]:
                continue
            expected_no_return_sites.add((
                str(relocation["source_symbol"]),
                int(site["call_id"]), int(site["instruction_rva"]), target,
            ))
        observed_no_return_sites: set[tuple[str, int, int, str]] = set()
        for row in lifecycle_effects:
            if set(row) != {
                "effect_id", "kind", "source_symbol_id",
                "source_transfer_id", "target_symbol_id", "call_id",
                "instruction_rva", "external_identity",
                "external_contract_sha256", "physical_frame_id",
                "physical_frame_sha256", "allowed_outcome",
                "root_ids", "domain_ids",
            }:
                _fail("V2 lifecycle-effect fields are incomplete")
            source = lifecycle_active_by_symbol.get(
                str(row.get("source_symbol_id"))
            )
            target = external_by_symbol.get(str(row.get("target_symbol_id")))
            identity = _mapping(
                row.get("external_identity"), "lifecycle external identity"
            )
            call_id = row.get("call_id")
            instruction_rva = row.get("instruction_rva")
            site_key = (
                str(row.get("source_symbol_id")), int(call_id or 0),
                int(instruction_rva or 0), str(row.get("target_symbol_id")),
            )
            if (
                row.get("kind") != "checked_external_no_return_effect_v2"
                or source is None or source.get("kind") != "function"
                or row.get("source_symbol_id")
                != f"original:function:{row.get('source_transfer_id')}"
                or target is None or target.get("allowed_outcomes")
                != ["no_return"]
                or not isinstance(call_id, int) or isinstance(call_id, bool)
                or call_id < 0
                or not isinstance(instruction_rva, int)
                or isinstance(instruction_rva, bool) or instruction_rva < 0
                or _import_identity_key(identity)
                != _import_identity_key(_mapping(
                    target.get("identity"), "target external identity"
                ))
                or row.get("external_contract_sha256")
                != target.get("contract_sha256")
                or row.get("physical_frame_id")
                != target.get("physical_frame_id")
                or row.get("physical_frame_sha256")
                != target.get("physical_frame_sha256")
                or row.get("allowed_outcome") != "no_return"
                or row.get("root_ids") != source.get("root_ids")
                or row.get("domain_ids") != source.get("domain_ids")
                or site_key in observed_no_return_sites
            ):
                _fail("V2 lifecycle effect is malformed or disconnected")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="external-no-return-effect-v2:",
            )
            observed_no_return_sites.add(site_key)
        if observed_no_return_sites != expected_no_return_sites:
            _fail("V2 lifecycle effects are not total")
        nonlocal_effects = _identity_rows(
            effects["nonlocal_transitions"],
            context="V2 nonlocal effect",
            identity_field="effect_id",
        )
        observed_nonlocal_sources: set[str] = set()
        contract_fields = {
            "kind", "source_transfer_id", "source_rva",
            "target_transfer_id", "target_rva",
            "target_function_entry_transfer_id",
            "target_function_entry_rva", "call_id",
            "value_expression_id", "cleanup",
        }
        for row in nonlocal_effects:
            if set(row) != {
                "effect_id", *contract_fields,
                "source_symbol_id", "target_symbol_id",
                "target_function_entry_symbol_id", "obligation_id",
                "root_ids", "domain_ids",
            }:
                _fail("V2 nonlocal-effect fields are incomplete")
            source_symbol_id = str(row.get("source_symbol_id"))
            target_symbol_id = str(row.get("target_symbol_id"))
            entry_symbol_id = str(
                row.get("target_function_entry_symbol_id")
            )
            source = lifecycle_active_by_symbol.get(source_symbol_id)
            target = lifecycle_active_by_symbol.get(target_symbol_id)
            entry = lifecycle_active_by_symbol.get(entry_symbol_id)
            obligation = obligations_by_id.get(str(row.get("obligation_id")))
            cleanup = row.get("cleanup")
            contract = {
                key: row[key] for key in contract_fields
            }
            admitted_domain = (
                obligation.get("admitted_domain")
                if isinstance(obligation, Mapping) else None
            )
            if (
                row.get("kind") != "checked_nonlocal_outcome_protocol_v2"
                or source is None or source.get("kind") != "function"
                or target is None or target.get("kind") != "function"
                or entry is None or entry.get("kind") != "function"
                or source_symbol_id
                != f"original:function:{row.get('source_transfer_id')}"
                or target_symbol_id
                != f"original:function:{row.get('target_transfer_id')}"
                or entry_symbol_id != (
                    "original:function:"
                    f"{row.get('target_function_entry_transfer_id')}"
                )
                or row.get("source_rva") != source.get("original_rva")
                or row.get("target_rva") != target.get("original_rva")
                or row.get("target_function_entry_rva")
                != entry.get("original_rva")
                or not isinstance(row.get("call_id"), int)
                or isinstance(row.get("call_id"), bool)
                or row["call_id"] < 0
                or not isinstance(row.get("value_expression_id"), int)
                or isinstance(row.get("value_expression_id"), bool)
                or row["value_expression_id"] < 0
                or cleanup != {
                    "kind": "expire_abandoned_ingress_and_call_frames",
                    "generation": "current_thread_invocation",
                }
                or obligation is None
                or obligation.get("class") != "checked_exceptions_outcomes"
                or obligation.get("semantic_contract_sha256")
                != canonical_sha256_v3(contract)
                or admitted_domain != {
                    "kind": "checked_nonlocal_ancestor_route_v2",
                    "source_rva": row.get("source_rva"),
                    "target_rva": row.get("target_rva"),
                    "target_function_entry_rva": row.get(
                        "target_function_entry_rva"
                    ),
                }
                or row.get("root_ids") != source.get("root_ids")
                or row.get("domain_ids") != source.get("domain_ids")
                or source_symbol_id in observed_nonlocal_sources
            ):
                _fail("V2 nonlocal effect is malformed or disconnected")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="checked-nonlocal-transition-v2:",
            )
            observed_nonlocal_sources.add(source_symbol_id)
        export_effects = _identity_rows(
            effects["export_capabilities"], context="V2 export capability",
            identity_field="effect_id",
        )
        observed_export_aliases: set[tuple[int, str | None]] = set()
        for row in export_effects:
            if set(row) != {
                "effect_id", "kind", "logical_image_id", "target_rva",
                "target_symbol_id", "exports", "boundary_subject_id",
                "checked_call_protocol_id", "physical_frame_id",
                "physical_frame_sha256", "physical_frame", "root_ids",
                "domain_ids",
            }:
                _fail("V2 export-capability fields are incomplete")
            target = lifecycle_active_by_symbol.get(
                str(row.get("target_symbol_id"))
            )
            frame = _mapping(
                row.get("physical_frame"), "export physical frame"
            )
            aliases = row.get("exports")
            if (
                row.get("kind") != "checked_export_capability_effect_v2"
                or target is None or target.get("kind") != "function"
                or row.get("target_rva") != target.get("original_rva")
                or not isinstance(row.get("logical_image_id"), str)
                or not row.get("logical_image_id")
                or not isinstance(aliases, list) or not aliases
                or not isinstance(row.get("boundary_subject_id"), str)
                or not row.get("boundary_subject_id")
                or not isinstance(row.get("checked_call_protocol_id"), str)
                or not row.get("checked_call_protocol_id")
                or row.get("physical_frame_id") != frame.get("id")
                or _sha256(
                    row.get("physical_frame_sha256"),
                    "export physical-frame identity",
                ) != canonical_sha256_v3(dict(frame))
                or row.get("root_ids") != target.get("root_ids")
                or row.get("domain_ids") != target.get("domain_ids")
            ):
                _fail("V2 export capability is malformed or disconnected")
            for raw_alias in aliases:
                alias = _mapping(raw_alias, "export capability alias")
                ordinal = alias.get("ordinal")
                name = alias.get("name")
                alias_key = (int(ordinal or 0), name)
                if (
                    set(alias) != {"name", "ordinal"}
                    or not isinstance(ordinal, int) or isinstance(ordinal, bool)
                    or ordinal < 0
                    or name is not None
                    and (not isinstance(name, str) or not name)
                    or alias_key in observed_export_aliases
                ):
                    _fail("V2 export capability alias is malformed or duplicated")
                observed_export_aliases.add(alias_key)
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="export-capability-effect-v2:",
            )
        import_effects = _identity_rows(
            effects["import_uses"], context="V2 import-use effect",
            identity_field="effect_id",
        )
        active_by_symbol = {
            str(row["symbol_id"]): row for row in symbols
        }
        observed_import_slots: set[str] = set()
        observed_import_code_sites: set[tuple[str, int, int]] = set()
        for row in import_effects:
            if set(row) != {
                "effect_id", "kind", "logical_image_id", "slot_id",
                "import_kind", "iat_rva", "identity", "use_kind",
                "loader_slot_symbol_id", "loader_slot_definition_id",
                "callable_symbol_id", "callable_definition_id",
                "external_contract_sha256", "importer_physical_frame_id",
                "importer_physical_frame_sha256", "required_permissions",
                "minimum_extent", "sites", "root_ids", "domain_ids",
            }:
                _fail("V2 import-use effect fields are incomplete")
            slot_id = row.get("slot_id")
            loader_symbol = active_by_symbol.get(
                str(row.get("loader_slot_symbol_id"))
            )
            callable_symbol = active_by_symbol.get(
                str(row.get("callable_symbol_id"))
            ) if row.get("callable_symbol_id") is not None else None
            identity = _mapping(
                row.get("identity"), "import-use external identity"
            )
            sites = row.get("sites")
            if (
                row.get("kind") != "checked_import_use_effect_v2"
                or not isinstance(slot_id, str) or not slot_id
                or slot_id in observed_import_slots
                or row.get("import_kind") not in {"ordinary", "delay"}
                or not isinstance(row.get("iat_rva"), int)
                or isinstance(row.get("iat_rva"), bool)
                or row["iat_rva"] < 0
                or _import_identity_key(identity) is None
                or row.get("use_kind") not in {
                    "code", "data", "ambiguous",
                }
                or loader_symbol is None
                or loader_symbol.get("kind") != "unclassified_import"
                or row.get("loader_slot_definition_id")
                != loader_symbol.get("definition_id")
                or row.get("external_contract_sha256")
                != _mapping(
                    loader_symbol.get("resolution"),
                    "loader import-slot resolution",
                ).get("contract_sha256")
                or row.get("use_kind") == "code" and (
                    callable_symbol is None
                    or callable_symbol.get("kind") != "external_function"
                    or row.get("callable_definition_id")
                    != callable_symbol.get("definition_id")
                    or row.get("external_contract_sha256")
                    != _mapping(
                        callable_symbol.get("resolution"),
                        "import callable resolution",
                    ).get("contract_sha256")
                    or _sha256(
                        row.get("external_contract_sha256"),
                        "import-use external contract",
                    ) != row.get("external_contract_sha256")
                )
                or row.get("use_kind") != "code" and (
                    row.get("callable_symbol_id") is not None
                    or row.get("callable_definition_id") is not None
                    or row.get("importer_physical_frame_id") is not None
                    or row.get("importer_physical_frame_sha256") is not None
                    or row.get("external_contract_sha256") is not None
                    and _sha256(
                        row.get("external_contract_sha256"),
                        "import-use external contract",
                    ) != row.get("external_contract_sha256")
                )
                or not isinstance(sites, list) or not sites
                or sites != sorted(sites, key=canonical_sha256_v3)
            ):
                _fail("V2 import-use effect is malformed or disconnected")
            expected_roots: set[str] = set()
            expected_domains: set[str] = set()
            for raw_site in sites:
                site = _mapping(raw_site, "V2 import-use site")
                source = active_by_symbol.get(str(site.get("source_symbol_id")))
                if (
                    source is None or source.get("kind") != "function"
                    or site.get("source_symbol_id")
                    != f"original:function:{site.get('transfer_id')}"
                    or site.get("root_ids") != source.get("root_ids")
                    or site.get("domain_ids") != source.get("domain_ids")
                ):
                    _fail("V2 import-use site provenance is disconnected")
                expected_roots.update(str(item) for item in site["root_ids"])
                expected_domains.update(
                    str(item) for item in site["domain_ids"]
                )
                if site.get("kind") == "code_call":
                    call_id = site.get("call_id")
                    instruction_rva = site.get("instruction_rva")
                    if (
                        not isinstance(call_id, int)
                        or isinstance(call_id, bool)
                        or not isinstance(instruction_rva, int)
                        or isinstance(instruction_rva, bool)
                    ):
                        _fail("V2 import code-use site is malformed")
                    observed_import_code_sites.add((
                        str(site["source_symbol_id"]),
                        call_id,
                        instruction_rva,
                    ))
            if (
                row.get("root_ids") != sorted(expected_roots)
                or row.get("domain_ids") != sorted(expected_domains)
                or not set(expected_roots) <= root_ids
                or not set(expected_domains) <= domain_ids
                or row.get("use_kind") == "code" and (
                    not isinstance(row.get("importer_physical_frame_id"), str)
                    or not row.get("importer_physical_frame_id")
                    or _sha256(
                        row.get("importer_physical_frame_sha256"),
                        "import-use physical frame",
                    ) != row.get("importer_physical_frame_sha256")
                )
            ):
                _fail("V2 import-use aggregate provenance is stale")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="import-use-effect-v2:",
            )
            observed_import_slots.add(slot_id)
        blocked_import_code_subjects = {
            str(row["subject"])
            for row in holes
            if row.get("code") == "checked_import_code_contract_unresolved"
        }
        expected_import_code_sites = set()
        for relocation in relocations:
            if relocation.get("kind") != "external_call":
                continue
            site = _mapping(
                relocation.get("site"), "external-call relocation site"
            )
            call_id = site.get("call_id")
            instruction_rva = site.get("instruction_rva")
            if (
                not isinstance(call_id, int) or isinstance(call_id, bool)
                or not isinstance(instruction_rva, int)
                or isinstance(instruction_rva, bool)
            ):
                _fail("external-call relocation site is malformed")
            source_symbol_id = str(relocation["source_symbol"])
            if _import_code_use_subject(
                source_symbol_id=source_symbol_id,
                call_id=call_id,
                instruction_rva=instruction_rva,
            ) not in blocked_import_code_subjects:
                expected_import_code_sites.add((
                    source_symbol_id, call_id, instruction_rva,
                ))
        if observed_import_code_sites != expected_import_code_sites:
            _fail("V2 import code-use effects are not total")
        dispatch_effects = _identity_rows(
            effects["indirect_targets"], context="V2 dispatch effect",
            identity_field="effect_id",
        )
        dispatch_obligations = {
            str(row["obligation_id"]): row for row in obligations
            if row.get("class") in {
                "internal_code_dispatch", "indirect_external_callthrough",
            }
        }
        observed_dispatch_obligations: set[str] = set()
        for row in dispatch_effects:
            if set(row) != {
                "effect_id", "kind", "source_symbol_id",
                "source_transfer_id", "site_kind", "call_id",
                "instruction_rva", "semantic_contract",
                "admitted_domain", "obligation_id",
            }:
                _fail("V2 dispatch-effect fields are incomplete")
            obligation_id = row.get("obligation_id")
            obligation = dispatch_obligations.get(str(obligation_id))
            domain = _mapping(
                row.get("admitted_domain"), "dispatch-effect domain"
            )
            semantic_contract = _mapping(
                row.get("semantic_contract"), "dispatch semantic contract"
            )
            site_kind = row.get("site_kind")
            call_id = row.get("call_id")
            expected_subject = (
                f"{row.get('source_transfer_id')}:terminator"
                if site_kind == "terminator" else
                f"{row.get('source_transfer_id')}:call:{call_id}"
            )
            expected_kind = (
                "logical_machine_state_indirect_dispatch_v2"
                if site_kind == "terminator" else
                "checked_indirect_callable_dispatch_v2"
            )
            expected_class = (
                "internal_code_dispatch"
                if site_kind == "terminator" else
                "indirect_external_callthrough"
            )
            if (
                row.get("kind") != expected_kind
                or row.get("source_symbol_id") not in symbol_ids
                or row.get("source_symbol_id")
                != f"original:function:{row.get('source_transfer_id')}"
                or site_kind not in {"call", "terminator"}
                or site_kind == "call" and (
                    not isinstance(call_id, int) or isinstance(call_id, bool)
                )
                or site_kind == "terminator" and call_id is not None
                or not isinstance(row.get("instruction_rva"), int)
                or isinstance(row.get("instruction_rva"), bool)
                or domain.get("kind") != "catalog_reference"
                or domain.get("domain_sha256") not in domain_ids
                or obligation is None
                or obligation.get("class") != expected_class
                or obligation.get("subjects") != [expected_subject]
                or obligation.get("admitted_domain") != domain
                or obligation.get("semantic_contract_sha256")
                != canonical_sha256_v3(dict(semantic_contract))
            ):
                _fail("V2 dispatch effect is malformed or disconnected")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix=(
                    "internal-dispatch-effect-v2:"
                    if site_kind == "terminator" else
                    "indirect-callable-effect-v2:"
                ),
            )
            observed_dispatch_obligations.add(str(obligation_id))
        if observed_dispatch_obligations != set(dispatch_obligations):
            _fail("V2 dispatch effects and obligations are not total")
        callback_effects = _identity_rows(
            effects["callbacks"], context="V2 callback effect",
            identity_field="effect_id",
        )
        callback_obligations = {
            str(row["obligation_id"]): row for row in obligations
            if row.get("class") == "callback_capability_publication"
        }
        observed_callback_obligations: set[str] = set()
        for row in callback_effects:
            if set(row) != {
                "effect_id", "kind", "source_symbol_id",
                "source_transfer_id", "call_id", "instruction_rva",
                "external_identity", "external_contract_sha256",
                "callback_protocol_id", "callback_protocol_sha256",
                "callback_source", "action", "lifetime", "delivery",
                "instance", "admitted_domain", "obligation_id",
            }:
                _fail("V2 callback-effect fields are incomplete")
            obligation_id = row.get("obligation_id")
            obligation = callback_obligations.get(str(obligation_id))
            domain = _mapping(
                row.get("admitted_domain"), "callback-effect domain"
            )
            identity = _mapping(
                row.get("external_identity"), "callback external identity"
            )
            source = _mapping(
                row.get("callback_source"), "callback value source"
            )
            effect_contract = {
                key: value for key, value in row.items()
                if key not in {"effect_id", "obligation_id"}
            }
            expected_subject = (
                f"{row.get('source_transfer_id')}:call:{row.get('call_id')}"
            )
            if (
                row.get("kind")
                != "checked_callback_capability_publication_v2"
                or row.get("source_symbol_id") not in symbol_ids
                or row.get("source_symbol_id")
                != f"original:function:{row.get('source_transfer_id')}"
                or not isinstance(row.get("call_id"), int)
                or isinstance(row.get("call_id"), bool)
                or not isinstance(row.get("instruction_rva"), int)
                or isinstance(row.get("instruction_rva"), bool)
                or _import_identity_key(identity) is None
                or _sha256(
                    row.get("external_contract_sha256"),
                    "callback external contract",
                ) != row.get("external_contract_sha256")
                or not isinstance(row.get("callback_protocol_id"), str)
                or not row.get("callback_protocol_id")
                or _sha256(
                    row.get("callback_protocol_sha256"),
                    "callback protocol",
                ) != row.get("callback_protocol_sha256")
                or source.get("kind") not in {
                    "argument_word", "argument_pointee",
                }
                or not isinstance(source.get("argument"), int)
                or isinstance(source.get("argument"), bool)
                or source.get("argument") < 0
                or not isinstance(source.get("sentinels"), list)
                or not isinstance(row.get("action"), str)
                or not isinstance(row.get("lifetime"), str)
                or not isinstance(row.get("delivery"), Mapping)
                or not isinstance(row.get("instance"), Mapping)
                or domain.get("kind") != "catalog_reference"
                or domain.get("domain_sha256") not in domain_ids
                or obligation is None
                or obligation.get("subjects") != [expected_subject]
                or obligation.get("admitted_domain") != domain
                or obligation.get("semantic_contract_sha256")
                != canonical_sha256_v3(effect_contract)
            ):
                _fail("V2 callback effect is malformed or disconnected")
            _check_content_identity(
                row, identity_field="effect_id",
                prefix="callback-publication-effect-v2:",
            )
            observed_callback_obligations.add(str(obligation_id))
        if observed_callback_obligations != set(callback_obligations):
            _fail("V2 callback effects and obligations are not total")
        if effects["code_capabilities"]:
            _fail("V2 must not retain partial V1 code-capability rows")
        return cls(payload)

    @classmethod
    def load(
        cls, path: Path, *, require_complete: bool = False,
    ) -> "LinkedSemanticModuleV2":
        source = Path(path)
        parsed = cls.parse(
            _load_json(source, "linked semantic module V2"),
            require_complete=require_complete,
        )
        semantic_path = source.parent / "semantic-object.json"
        if not semantic_path.is_file():
            return parsed
        semantic = SemanticObjectV1.load(semantic_path)
        bindings = parsed.payload["bindings"]
        if (
            bindings.get("semantic_object_sha256") != semantic.identity
            or bindings.get("semantic_object_content_sha256")
            != sha256_file(semantic_path)
            or bindings.get("executable_transfer_plan_sha256")
            != semantic.payload["members"]["transfer_plan"]["identity"]
            or parsed.payload["definitions"] != _definition_catalog(semantic)
            or parsed.payload["may_reach"]["direct_control_edges_sha256"]
            != canonical_sha256_v3(
                semantic.transfer_plan["direct_control_edges"]
            )
            or parsed.payload["counts"]["direct_control_edges"]
            != len(semantic.transfer_plan["direct_control_edges"])
        ):
            _fail("linked-semantic-module V2 package is stale")
        package_members = {
            str(role): source.parent / str(member["path"])
            for role, member in semantic.payload["members"].items()
        }
        package_members["semantic_object"] = semantic_path
        return replace(
            parsed,
            package_root=source.parent,
            package_members=package_members,
            semantic_object=semantic,
        )

    def require_member(self, role: str) -> Path:
        """Return one member of a validated packaged V2 semantic module."""

        if self.package_root is None or self.package_members is None:
            _fail("linked-semantic-module V2 is not a packaged module")
        path = self.package_members.get(role)
        if path is None:
            _fail(f"linked-semantic-module V2 has no {role!r} member")
        if not path.exists():
            _fail(f"linked-semantic-module V2 member {role!r} is absent")
        return path
