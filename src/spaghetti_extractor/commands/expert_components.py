"""Checked component contract, source, qualification, and composition commands."""

from __future__ import annotations

import argparse
import json

from ..components.configuration import compose_component_configuration
from ..components.adapter import build_component_adapter_plan
from ..components.contracts import build_lift_unit_contract
from ..components.evidence import produce_component_evidence
from ..components.qualification import qualify_lift_unit
from ..components.resolution import resolve_component_catalog
from ..components.runtime import build_component_runtime_package
from ..components.source import build_component_source_package
from .common import Handler, keyed_paths, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "component-resolve":
        path_argument(command, "proposals", required=True)
        path_argument(command, "intent", required=True)
        path_argument(command, "out", required=True)
        return lambda a: resolve_component_catalog(
            proposals=a.proposals, intent=a.intent, out=a.out
        )

    if name == "component-contract-build":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "reconstruction_plan", required=True)
        path_argument(command, "resolution", required=True)
        command.add_argument("--lift-unit-id", required=True)
        path_argument(command, "review")
        path_argument(command, "external_sites")
        path_argument(command, "out", required=True)
        return lambda a: build_lift_unit_contract(
            machine_ir=a.machine_ir,
            reconstruction_plan=a.reconstruction_plan,
            resolution=a.resolution,
            lift_unit_id=a.lift_unit_id,
            review=a.review,
            external_sites=a.external_sites,
            out_dir=a.out,
        )

    if name == "component-source-package":
        command.add_argument("--lift-unit-id", required=True)
        command.add_argument("--file", action="append", required=True)
        command.add_argument("--shared-input", action="append", default=[])
        command.add_argument("--entry-symbol", required=True)
        command.add_argument(
            "--entry-abi",
            choices=("logical-c-v1", "logical-object-c-v1"),
            default="logical-c-v1",
        )
        path_argument(command, "out", required=True)
        return lambda a: build_component_source_package(
            lift_unit_id=a.lift_unit_id,
            files=keyed_paths(a.file),
            shared_inputs=keyed_paths(a.shared_input),
            entry={"abi": a.entry_abi, "symbol": a.entry_symbol},
            out_dir=a.out,
        )

    if name == "component-adapter-build":
        path_argument(command, "contract", required=True)
        path_argument(command, "implementation", required=True)
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "out", required=True)
        return lambda a: build_component_adapter_plan(
            contract=a.contract,
            implementation=a.implementation,
            machine_ir=a.machine_ir,
            out_dir=a.out,
        )

    if name == "component-evidence-produce":
        path_argument(command, "contract", required=True)
        path_argument(command, "implementation", required=True)
        path_argument(command, "adapter_plan", required=True)
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "verification", required=True)
        path_argument(command, "compiler", required=True)
        path_argument(command, "out", required=True)
        return lambda a: produce_component_evidence(
            contract=a.contract,
            implementation=a.implementation,
            adapter_plan=a.adapter_plan,
            machine_ir=a.machine_ir,
            verification=json.loads(a.verification.read_text(encoding="utf-8")),
            compiler=a.compiler,
            out=a.out,
        )

    if name == "component-qualify":
        path_argument(command, "contract", required=True)
        path_argument(command, "implementation", required=True)
        path_argument(command, "evidence", required=True)
        path_argument(command, "adapter_plan", required=True)
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "verification", required=True)
        path_argument(command, "out", required=True)
        return lambda a: qualify_lift_unit(
            contract=a.contract,
            implementation=a.implementation,
            evidence=a.evidence,
            adapter_plan=a.adapter_plan,
            machine_ir=a.machine_ir,
            verification=json.loads(a.verification.read_text(encoding="utf-8")),
            out=a.out,
        )

    if name == "component-compose":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "resolution", required=True)
        command.add_argument("--configuration-id", required=True)
        command.add_argument("--contract", action="append", default=[])
        command.add_argument("--implementation", action="append", default=[])
        command.add_argument("--qualification", action="append", default=[])
        command.add_argument("--adapter-plan", action="append", default=[])
        path_argument(command, "out", required=True)
        return lambda a: compose_component_configuration(
            machine_ir=a.machine_ir,
            resolution=a.resolution,
            configuration_id=a.configuration_id,
            contracts=keyed_paths(a.contract),
            implementations=keyed_paths(a.implementation),
            qualifications=keyed_paths(a.qualification),
            adapter_plans=keyed_paths(a.adapter_plan),
            out=a.out,
        )

    if name == "component-runtime-build":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "activation_plan", required=True)
        command.add_argument("--contract", action="append", default=[])
        command.add_argument("--implementation", action="append", default=[])
        command.add_argument("--qualification", action="append", default=[])
        command.add_argument("--adapter-plan", action="append", default=[])
        path_argument(command, "interpreter_package", required=True)
        path_argument(command, "out", required=True)
        return lambda a: build_component_runtime_package(
            machine_ir=a.machine_ir,
            activation_plan=a.activation_plan,
            contracts=keyed_paths(a.contract),
            implementations=keyed_paths(a.implementation),
            qualifications=keyed_paths(a.qualification),
            adapter_plans=keyed_paths(a.adapter_plan),
            interpreter_package=a.interpreter_package,
            out_dir=a.out,
        )

    raise ValueError(f"unsupported component command: {name}")


__all__ = ["configure_command"]
