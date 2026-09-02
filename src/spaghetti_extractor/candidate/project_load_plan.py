"""Checked target-to-target PE32 import resolution from linked semantics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..calls.frame import physical_frame_abi_sha256_v1
from ..errors import ToolkitInputError
from ..pe32.formats import PE32_PROJECT_INTENT_FORMAT, PE32_PROJECT_LOAD_PLAN_FORMAT
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..util import sha256_file, write_json


_OWNERSHIP = frozenset({"target", "runtime"})
_IMPLEMENTATIONS = frozenset({"behavioral_c", "native_host"})


def _object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{label} must be an object")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolkitInputError(f"{label} must be nonempty text")
    return value


def _basename(value: object, label: str) -> str:
    text = _text(value, label)
    if Path(text).name != text:
        raise ToolkitInputError(f"{label} must be a basename")
    return text


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        ch not in "0123456789abcdef" for ch in value
    ):
        raise ToolkitInputError(f"{label} must be lowercase SHA-256")
    return value


def _resolved_physical_frame_v3(
    environment: Mapping[str, Any], frame_id: object,
) -> Mapping[str, Any] | None:
    if not isinstance(frame_id, str) or not frame_id:
        return None
    boundary_rows = list(environment.get("canonical_boundaries", []))
    for catalog_name in (
        "machine_import_contracts", "loader_service_contracts",
    ):
        for contract in environment.get(catalog_name, []):
            if isinstance(contract, Mapping):
                boundary_rows.append(contract.get("boundary"))
    matches = []
    for raw in boundary_rows:
        if not isinstance(raw, Mapping):
            continue
        artifacts = raw.get("artifacts")
        frame_artifact = (
            artifacts.get("physical_call_frame_v3")
            if isinstance(artifacts, Mapping)
            else raw.get("physical_call_frame_v3")
        )
        frame = (
            frame_artifact.get("payload")
            if isinstance(frame_artifact, Mapping)
            and isinstance(frame_artifact.get("payload"), Mapping)
            else frame_artifact
        )
        if isinstance(frame, Mapping) and frame.get("id") == frame_id:
            matches.append(frame)
    unique_matches = {
        canonical_sha256_v3(frame): frame for frame in matches
    }
    if len(unique_matches) > 1:
        raise ToolkitInputError(
            "resolved environment conflicts on a physical call frame identity"
        )
    return next(iter(unique_matches.values())) if unique_matches else None


def _active_object_rows_v2(
    linked: LinkedSemanticModuleV2,
) -> list[dict[str, Any]]:
    """Project active object authority without reconstructing link semantics."""

    semantic = linked.semantic_object
    if semantic is None:
        raise ToolkitInputError(
            "project linked-semantic-module V2 has no semantic-object member"
        )
    active_by_id = {
        str(row["object_id"]): row
        for row in linked.payload["active_objects"]
    }
    anchors_by_rule: dict[str, list[dict[str, object]]] = {}
    for anchor in semantic.machine_object_authority.data_export_anchors:
        anchors_by_rule.setdefault(anchor.rule_id, []).append(
            anchor.to_payload()
        )
    rows = []
    for rule in semantic.machine_object_authority.rules:
        active = active_by_id.get(rule.identity)
        if active is None:
            continue
        rows.append({
            **rule.to_payload(),
            "semantic_symbol_id": active["semantic_symbol_id"],
            "root_ids": list(active["root_ids"]),
            "domain_ids": list(active["domain_ids"]),
            "data_export_anchors": anchors_by_rule.get(rule.identity, []),
        })
    if {row["id"] for row in rows} != set(active_by_id):
        raise ToolkitInputError(
            "project linked-semantic-module V2 active objects are not total"
        )
    return rows


def _load_linked_module_v2(path: Path) -> LinkedSemanticModuleV2:
    linked = LinkedSemanticModuleV2.load(Path(path))
    semantic = linked.semantic_object
    if semantic is None:
        raise ToolkitInputError(
            "project linked-semantic-module V2 package is not closed"
        )
    if semantic.resolved_external_environment is None:
        raise ToolkitInputError(
            "project linked-semantic-module V2 has no resolved environment"
        )
    return linked

def write_pe32_project_load_plan(
    *,
    intent: Path,
    linked_semantic_modules: Mapping[str, Path],
    out: Path,
) -> dict[str, Any]:
    """Resolve declared target edges and leave environment edges to the host."""

    raw_intent = _object(Path(intent), "project intent")
    project = _parse_project_intent(raw_intent)
    linked_paths = dict(linked_semantic_modules)
    linked = {
        image_id: _load_linked_module_v2(Path(path))
        for image_id, path in linked_paths.items()
    }
    semantic_objects = {
        image_id: module.semantic_object
        for image_id, module in linked.items()
    }
    interface_paths = {
        image_id: semantic.module_interface_path
        for image_id, semantic in semantic_objects.items()
        if semantic is not None
    }
    modules = {
        image_id: _module_interface(path, expected_image_id=image_id)
        for image_id, path in interface_paths.items()
    }
    export_capabilities = {
        image_id: list(module.payload["effects"]["export_capabilities"])
        for image_id, module in linked.items()
    }
    import_uses = {
        image_id: {
            str(row["slot_id"]): row
            for row in module.payload["effects"]["import_uses"]
        }
        for image_id, module in linked.items()
    }
    linked_objects = {
        image_id: _active_object_rows_v2(module)
        for image_id, module in linked.items()
    }
    resolved_environments = {
        image_id: semantic.resolved_external_environment.payload
        for image_id, semantic in semantic_objects.items()
        if semantic is not None
        and semantic.resolved_external_environment is not None
    }
    declared_ids = {
        row["image_id"]
        for row in project["images"]
        if row["ownership"] == "target"
    }
    if set(linked) != declared_ids:
        raise ToolkitInputError(
            "linked-module IDs differ from target-owned project images: "
            f"missing={sorted(declared_ids - set(linked))!r}, "
            f"extra={sorted(set(linked) - declared_ids)!r}"
        )
    aliases: dict[str, str] = {}
    specifications = {row["image_id"]: row for row in project["images"]}
    blockers: list[dict[str, Any]] = []
    environment_targets: dict[tuple[str, str], list[str]] = {}
    for image_id, semantic in semantic_objects.items():
        if semantic is None or semantic.resolved_external_environment is None:
            raise ToolkitInputError(
                "project linked semantic package lost its resolved environment"
            )
        environment = semantic.resolved_external_environment.payload
        target = environment["target"]
        key = (str(target["abi"]), str(target["data_layout"]))
        environment_targets.setdefault(key, []).append(image_id)
        if environment["status"] != "complete":
            blockers.append({
                "category": "target_resolved_environment_incomplete",
                "image_id": image_id,
            })
    if len(environment_targets) != 1:
        blockers.append({
            "category": "cross_image_target_abi_layout_mismatch",
            "targets": [
                {"abi": abi, "data_layout": layout, "image_ids": sorted(ids)}
                for (abi, layout), ids in sorted(environment_targets.items())
            ],
        })
    for row in project["images"]:
        for alias in (row["filename"], *row["aliases"]):
            normalized = alias.lower()
            prior = aliases.get(normalized)
            if prior is not None and prior != row["image_id"]:
                blockers.append({
                    "category": "module_alias_ambiguous",
                    "alias": normalized,
                    "images": sorted({prior, row["image_id"]}),
                })
            else:
                aliases[normalized] = row["image_id"]

    edges: list[dict[str, Any]] = []
    for importer_id in sorted(modules):
        interface = modules[importer_id]
        module_slots = [
            *interface["imports"],
            *(
                cell
                for descriptor in interface["delay_imports"]
                for cell in descriptor["cells"]
            ),
        ]
        for slot in module_slots:
            request = {
                "dll": str(slot["dll"]).lower(),
                "symbol": slot["symbol"],
                "ordinal": slot["ordinal"],
            }
            provider_id = aliases.get(request["dll"])
            if provider_id is None:
                resolution = {
                    "kind": "host_loader",
                    "requested_dll": request["dll"],
                }
            elif specifications[provider_id]["ownership"] == "runtime":
                resolution = {
                    "kind": "host_loader",
                    "requested_dll": request["dll"],
                    "declared_runtime_image_id": provider_id,
                }
            else:
                exported = _resolve_export(modules[provider_id], request)
                if exported is None:
                    blockers.append({
                        "category": "target_export_missing",
                        "slot_id": slot["slot_id"],
                        "provider_image_id": provider_id,
                        "request": request,
                    })
                    resolution = {"kind": "unresolved"}
                elif exported["kind"] == "forwarder":
                    resolution = {
                        "kind": "target_forwarder",
                        "provider_image_id": provider_id,
                        "export": exported,
                    }
                else:
                    compatibility = None
                    importer_use = import_uses[importer_id].get(slot["slot_id"])
                    if importer_use is None:
                        blockers.append({
                            "category": "cross_image_edge_authority_missing",
                            "slot_id": slot["slot_id"],
                        })
                    elif exported["kind"] == "code":
                        providers = [
                            row
                            for row in export_capabilities[provider_id]
                            if any(
                                alias.get("ordinal") == exported["ordinal"]
                                and (
                                    request["symbol"] is None
                                    or alias.get("name") == request["symbol"]
                                )
                                for alias in row.get("exports", [])
                            )
                        ]
                        importer_frame_id = importer_use.get(
                            "importer_physical_frame_id"
                        )
                        importer_physical_frame = _resolved_physical_frame_v3(
                            resolved_environments[importer_id],
                            importer_frame_id,
                        )
                        if (
                            importer_use.get("use_kind") != "code"
                            or len(providers) != 1
                            or importer_physical_frame is None
                            or not isinstance(importer_frame_id, str)
                        ):
                            blockers.append({
                                "category": (
                                    "cross_image_iat_use_ambiguous"
                                    if importer_use.get("use_kind") == "ambiguous"
                                    else "cross_image_code_authority_invalid"
                                ),
                                "slot_id": slot["slot_id"],
                            })
                        else:
                            provider_frame = providers[0]["physical_frame_id"]
                            importer_abi = physical_frame_abi_sha256_v1(
                                importer_physical_frame
                            )
                            provider_abi = physical_frame_abi_sha256_v1(
                                providers[0]["physical_frame"]
                            )
                            compatibility = {
                                "kind": "code",
                                "import_use_id": importer_use["effect_id"],
                                "importer_physical_frame_id": importer_frame_id,
                                "provider_physical_frame_id": provider_frame,
                                "importer_physical_abi_sha256": importer_abi,
                                "provider_physical_abi_sha256": provider_abi,
                                "compatible": importer_abi == provider_abi,
                            }
                            if not compatibility["compatible"]:
                                blockers.append({"category": "cross_image_code_protocol_mismatch", "slot_id": slot["slot_id"]})
                    elif exported["kind"] == "data":
                        anchors = [
                            {
                                **anchor,
                                "object_permissions": obj["permissions"],
                                "available_extent": (
                                    int(obj["extent"])
                                    - int(anchor["byte_offset"])
                                ),
                            }
                            for obj in linked_objects[provider_id]
                            for anchor in obj.get("data_export_anchors", [])
                            if any(
                                alias.get("ordinal") == exported["ordinal"]
                                and (
                                    request["symbol"] is None
                                    or alias.get("name") == request["symbol"]
                                )
                                for alias in anchor.get("aliases", [])
                            )
                        ]
                        if (
                            importer_use.get("use_kind") != "data"
                            or len(anchors) != 1
                        ):
                            blockers.append({
                                "category": (
                                    "cross_image_iat_use_ambiguous"
                                    if importer_use.get("use_kind") == "ambiguous"
                                    else "cross_image_data_authority_invalid"
                                ),
                                "slot_id": slot["slot_id"],
                            })
                        else:
                            required = importer_use["required_permissions"]
                            minimum = importer_use["minimum_extent"]
                            anchor = anchors[0]
                            compatible = (
                                isinstance(required, int) and not isinstance(required, bool) and required > 0
                                and isinstance(minimum, int) and not isinstance(minimum, bool) and minimum > 0
                                and anchor["object_permissions"] & required == required
                                and anchor["available_extent"] >= minimum
                            )
                            compatibility = {
                                "kind": "data",
                                "import_use_id": importer_use["effect_id"],
                                "required_permissions": required,
                                "minimum_extent": minimum, "provider_anchor_id": anchor["id"],
                                "compatible": compatible,
                            }
                            if not compatible:
                                blockers.append({"category": "cross_image_data_protocol_mismatch", "slot_id": slot["slot_id"]})
                    resolution = {
                        "kind": "target_image",
                        "provider_image_id": provider_id,
                        "export": exported,
                        "compatibility": compatibility,
                    }
            edges.append({
                "slot_id": slot["slot_id"],
                "importer_image_id": importer_id,
                "iat_rva": slot["iat_rva"],
                "request": request,
                "resolution": resolution,
            })

    known_slots = {row["slot_id"] for row in edges}
    extra_import_uses = sorted({
        slot_id
        for rows in import_uses.values()
        for slot_id in rows
        if slot_id not in known_slots
    })
    if extra_import_uses:
        blockers.append({
            "category": "cross_image_import_use_unreachable",
            "slot_ids": extra_import_uses,
        })

    payload = {
        "format": PE32_PROJECT_LOAD_PLAN_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "project_id": project["project_id"],
        "root_image_id": project["root_image_id"],
        "intent": {
            "path": Path(intent).name,
            "sha256": sha256_file(intent),
        },
        "images": [
            {
                **specifications[image_id],
                "interface_sha256": (
                    sha256_file(interface_paths[image_id])
                    if image_id in interface_paths else None
                ),
                "linked_semantic_module_sha256": (
                    linked[image_id].identity
                    if image_id in linked else None
                ),
                "resolved_external_environment_sha256": (
                    linked[image_id].payload["bindings"][
                        "resolved_external_environment_sha256"
                    ] if image_id in linked else None
                ),
                "resolved_external_environment_content_sha256": (
                    linked[image_id].payload["bindings"][
                        "resolved_external_environment_content_sha256"
                    ] if image_id in linked else None
                ),
                "pe_sha256": (
                    modules[image_id]["identity"]["pe_sha256"]
                    if image_id in modules else None
                ),
            }
            for image_id in sorted(specifications)
        ],
        "target_distribution_roots": project["target_distribution_roots"],
        "host_environment": project["host_environment"],
        "edges": edges,
        "blockers": blockers,
        "counts": {
            "images": len(specifications),
            "target_images": sum(
                row["ownership"] == "target" for row in project["images"]
            ),
            "import_slots": len(edges),
            "target_edges": sum(
                row["resolution"]["kind"].startswith("target_") for row in edges
            ),
            "host_edges": sum(
                row["resolution"]["kind"] == "host_loader" for row in edges
            ),
            "blockers": len(blockers),
        },
        "policy": {
            "host_loader_resolution": True,
            "duplicate_logical_import_slots": "preserved",
            "unknown_target_local_module": "fail_until_classified",
            "layout_compatibility": "not_promised",
        },
    }
    payload["plan_sha256"] = canonical_sha256_v3(payload)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "project-load-plan.json", payload)
    return payload

def _parse_project_intent(raw: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "format", "project_id", "root_image_id", "images",
        "target_distribution_roots", "host_environment",
    }
    if set(raw) != expected or raw.get("format") != PE32_PROJECT_INTENT_FORMAT:
        raise ToolkitInputError("project intent has unsupported format or fields")
    project_id = _text(raw.get("project_id"), "project ID")
    root = _text(raw.get("root_image_id"), "root image ID")
    images_raw = raw.get("images")
    if not isinstance(images_raw, list) or not images_raw:
        raise ToolkitInputError("project intent images must be a nonempty list")
    images: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(images_raw):
        if not isinstance(value, Mapping) or set(value) != {
            "image_id", "filename", "aliases", "ownership", "implementation"
        }:
            raise ToolkitInputError(f"project image {index} has invalid fields")
        image_id = _text(value.get("image_id"), f"project image {index} ID")
        if image_id in seen:
            raise ToolkitInputError(f"duplicate project image ID {image_id!r}")
        seen.add(image_id)
        filename = _basename(value.get("filename"), f"project image {index} filename")
        raw_aliases = value.get("aliases")
        if not isinstance(raw_aliases, list):
            raise ToolkitInputError(f"project image {index} aliases must be a list")
        aliases = sorted({_basename(item, "module alias") for item in raw_aliases})
        ownership = value.get("ownership")
        implementation = value.get("implementation")
        if ownership not in _OWNERSHIP or implementation not in _IMPLEMENTATIONS:
            raise ToolkitInputError(f"project image {index} policy is invalid")
        if ownership == "runtime" and implementation != "native_host":
            raise ToolkitInputError("runtime-owned images must use native_host")
        images.append({
            "image_id": image_id,
            "filename": filename,
            "aliases": aliases,
            "ownership": ownership,
            "implementation": implementation,
        })
    if root not in seen:
        raise ToolkitInputError("project root image is not declared")
    roots = raw.get("target_distribution_roots")
    if not isinstance(roots, list) or any(not isinstance(item, str) for item in roots):
        raise ToolkitInputError("target distribution roots must be strings")
    environment = raw.get("host_environment")
    if not isinstance(environment, Mapping) or set(environment) != {"id", "sha256"}:
        raise ToolkitInputError("host environment binding is malformed")
    return {
        "format": PE32_PROJECT_INTENT_FORMAT,
        "project_id": project_id,
        "root_image_id": root,
        "images": images,
        "target_distribution_roots": list(roots),
        "host_environment": {
            "id": _text(environment.get("id"), "host environment ID"),
            "sha256": _sha256(environment.get("sha256"), "host environment SHA-256"),
        },
    }

def _resolve_export(interface: Mapping[str, Any], request: Mapping[str, Any]) -> Mapping[str, Any] | None:
    export_directory = interface.get("export_directory")
    if not isinstance(export_directory, Mapping) or not isinstance(export_directory.get("slots"), list):
        raise ToolkitInputError("module interface has no exact EAT geometry")
    matches = []
    for row in export_directory["slots"]:
        if not isinstance(row, Mapping) or row.get("kind") == "hole":
            continue
        if request["symbol"] is not None and request["symbol"] in row.get("names", []):
            matches.append(row)
        elif request["ordinal"] is not None and row.get("ordinal") == request["ordinal"]:
            matches.append(row)
    if len(matches) > 1:
        raise ToolkitInputError("module export identity is ambiguous")
    return matches[0] if matches else None

def _module_interface(path: Path, *, expected_image_id: str) -> dict[str, Any]:
    interface = Pe32ModuleInterfaceV2.load(
        path,
        expected_image_id=expected_image_id,
        require_complete=True,
    )
    return dict(interface.payload)
