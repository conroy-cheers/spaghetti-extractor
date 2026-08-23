"""Machine-IR fallback runtime generation commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..candidate.interpreter import write_spx_interpreter_package
from ..candidate.behavioral_c import write_spx_behavioral_c_package
from ..candidate.engine import write_spx_native_engine_package
from ..candidate.runtime import write_spx_native_runtime_package
from ..candidate.module_composer import compose_pe32_native_module
from ..candidate.native_ingress import (
    write_native_ingress_link_receipt,
    write_native_ingress_plan,
    write_pe32_loader_surface_receipt,
    write_pe32_machine_object_authority_v2,
    write_pe32_module_deployment,
)
from ..candidate.project import (
    write_pe32_module_interface,
    write_pe32_observed_load_graph,
    write_pe32_project_completion,
    write_pe32_project_load_plan,
)
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "candidate-module-interface":
        command.add_argument("--image-id", required=True)
        path_argument(command, "original_pe", required=True)
        path_argument(command, "load_image_contract", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_pe32_module_interface(
            image_id=a.image_id,
            original_pe=a.original_pe,
            load_image_contract=a.load_image_contract,
            out=a.out,
        )

    if name == "candidate-project-load-plan":
        path_argument(command, "intent", required=True)
        path_argument(command, "out", required=True)
        command.add_argument(
            "--module-interface", action="append", default=[], required=True,
            metavar="IMAGE_ID=PATH",
        )
        command.add_argument(
            "--native-ingress-plan", action="append", default=[],
            metavar="IMAGE_ID=PATH",
        )
        path_argument(command, "edge_authorities")
        return lambda a: write_pe32_project_load_plan(
            intent=a.intent,
            module_interfaces=_path_mapping(a.module_interface, "module interface"),
            native_ingress_plans=_path_mapping(a.native_ingress_plan, "native ingress plan"),
            edge_authorities=(
                None
                if a.edge_authorities is None
                else {
                    str(row["slot_id"]): row
                    for row in _json_array(a.edge_authorities, "edge authorities")
                }
            ),
            out=a.out,
        )

    if name == "candidate-object-authority":
        path_argument(command, "module_interface", required=True)
        path_argument(command, "refinements")
        path_argument(command, "out", required=True)
        return lambda a: write_pe32_machine_object_authority_v2(
            module_interface=a.module_interface,
            refinements=() if a.refinements is None else _json_array(a.refinements, "object refinements"),
            out=a.out,
        )

    if name == "candidate-native-ingress-plan":
        path_argument(command, "module_interface", required=True)
        path_argument(command, "behavioral_roots", required=True)
        path_argument(command, "object_authority", required=True)
        path_argument(command, "ingress_authorities", required=True)
        path_argument(command, "out", required=True)
        command.add_argument("--outcome-protocol", action="append", default=[], required=True)
        command.add_argument("--seh-protocol", action="append", default=[])
        command.add_argument("--runtime-tls-bytes", type=int, default=0)
        command.add_argument("--private-stack-size", type=int)
        return lambda a: write_native_ingress_plan(
            module_interface=a.module_interface,
            behavioral_roots=a.behavioral_roots,
            object_authority=a.object_authority,
            ingress_authorities=_json_array(a.ingress_authorities, "ingress authorities"),
            outcome_protocols=[_json_object(Path(path), "outcome protocol") for path in a.outcome_protocol],
            seh_protocols=[_json_object(Path(path), "SEH protocol") for path in a.seh_protocol],
            runtime_tls_bytes=a.runtime_tls_bytes,
            private_stack_size=a.private_stack_size,
            out=a.out,
        )

    if name == "candidate-native-ingress-link":
        path_argument(command, "native_ingress_plan", required=True)
        path_argument(command, "linked_module", required=True)
        path_argument(command, "symbols", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_native_ingress_link_receipt(
            native_ingress_plan=a.native_ingress_plan,
            linked_module=a.linked_module,
            symbols={str(key): int(value) for key, value in _json_object(a.symbols, "linked symbols").items()},
            out=a.out,
        )

    if name == "candidate-compose-module":
        for argument in (
            "base_candidate", "base_composition_manifest",
            "original_module_interface", "native_ingress_plan",
            "native_ingress_link_receipt", "out",
        ):
            path_argument(command, argument, required=True)
        command.add_argument("--candidate-filename", required=True)
        return lambda a: compose_pe32_native_module(
            base_candidate=a.base_candidate,
            base_composition_manifest=a.base_composition_manifest,
            original_module_interface=a.original_module_interface,
            native_ingress_plan=a.native_ingress_plan,
            native_ingress_link_receipt=a.native_ingress_link_receipt,
            out=a.out,
            candidate_filename=a.candidate_filename,
        )

    if name == "candidate-loader-surface-check":
        for argument in (
            "original_module_interface", "native_ingress_plan",
            "native_ingress_link_receipt", "composition_manifest",
            "candidate_module", "candidate_module_interface", "out",
        ):
            path_argument(command, argument, required=True)
        return lambda a: write_pe32_loader_surface_receipt(
            original_module_interface=a.original_module_interface,
            native_ingress_plan=a.native_ingress_plan,
            native_ingress_link_receipt=a.native_ingress_link_receipt,
            composition_manifest=a.composition_manifest,
            candidate_module=a.candidate_module,
            candidate_module_interface=a.candidate_module_interface,
            out=a.out,
        )

    if name == "candidate-module-deployment":
        for argument in (
            "original_module_interface", "behavioral_c_completion",
            "native_ingress_plan", "native_ingress_link_receipt",
            "exact_runtime_qualification", "loader_surface_receipt",
            "candidate_static_assurance", "candidate_module",
            "candidate_module_interface", "out",
        ):
            path_argument(command, argument, required=True)
        return lambda a: write_pe32_module_deployment(
            original_module_interface=a.original_module_interface,
            behavioral_c_completion=a.behavioral_c_completion,
            native_ingress_plan=a.native_ingress_plan,
            native_ingress_link_receipt=a.native_ingress_link_receipt,
            exact_runtime_qualification=a.exact_runtime_qualification,
            loader_surface_receipt=a.loader_surface_receipt,
            candidate_static_assurance=a.candidate_static_assurance,
            candidate_module=a.candidate_module,
            candidate_module_interface=a.candidate_module_interface,
            out=a.out,
        )
    if name == "candidate-project-completion":
        path_argument(command, "load_plan", required=True)
        path_argument(command, "observed_load_graph")
        path_argument(command, "out", required=True)
        command.add_argument(
            "--module-deployment", action="append", default=[], required=True,
            metavar="IMAGE_ID=PATH",
        )
        return lambda a: write_pe32_project_completion(
            load_plan=a.load_plan,
            module_deployments=_path_mapping(
                a.module_deployment, "module deployment"
            ),
            observed_load_graph=a.observed_load_graph,
            out=a.out,
        )

    if name == "candidate-observed-load-graph":
        path_argument(command, "load_plan", required=True)
        path_argument(command, "observation", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_pe32_observed_load_graph(
            load_plan=a.load_plan,
            observation=a.observation,
            out=a.out,
        )

    if name == "candidate-generate-behavioral-c":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "out", required=True)
        path_argument(command, "layout_intent")
        path_argument(command, "runtime_qualification")
        command.add_argument(
            "--entry-rva",
            action="append",
            default=[],
            type=lambda value: int(value, 0),
            help="checked function root RVA; repeat for multiple roots",
        )
        return lambda a: write_spx_behavioral_c_package(
            machine_ir=a.machine_ir,
            out=a.out,
            entry_rvas=a.entry_rva,
            layout_intent=a.layout_intent,
            runtime_qualification=a.runtime_qualification,
        )

    if name == "candidate-generate-interpreter":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_spx_interpreter_package(
            machine_ir=a.machine_ir,
            out=a.out,
        )

    if name == "candidate-generate-engine":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "machine_ir_manifest", required=True)
        path_argument(command, "native_ingress_plan", required=True)
        path_argument(command, "canonical_external_sites", required=True)
        path_argument(command, "callback_authority", required=True)
        path_argument(command, "root_closure", required=True)
        path_argument(command, "target_certificates", required=True)
        path_argument(command, "parametric_summaries", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_spx_native_engine_package(
            machine_ir=a.machine_ir,
            machine_ir_manifest=a.machine_ir_manifest,
            native_ingress_plan=a.native_ingress_plan,
            canonical_external_sites=a.canonical_external_sites,
            callback_authority=a.callback_authority,
            root_closure=a.root_closure,
            target_certificates=a.target_certificates,
            parametric_summaries=a.parametric_summaries,
            out=a.out,
        )

    if name == "candidate-generate-runtime":
        path_argument(command, "interpreter_package", required=True)
        path_argument(command, "native_engine_package", required=True)
        path_argument(command, "external_profile")
        path_argument(command, "out", required=True)
        return lambda a: write_spx_native_runtime_package(
            interpreter_package=a.interpreter_package,
            native_engine_package=a.native_engine_package,
            external_profile=a.external_profile,
            out=a.out,
        )

    raise ValueError(f"unsupported runtime command: {name}")


def _path_mapping(values: list[str], label: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        image_id, separator, raw_path = value.partition("=")
        if not separator or not image_id or not raw_path or image_id in result:
            raise ValueError(f"invalid or duplicate {label} binding {value!r}")
        result[image_id] = Path(raw_path)
    return result


def _json_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _json_array(path: Path, label: str) -> list[dict[str, object]]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must be an array of objects")
    return value


__all__ = ["configure_command"]
