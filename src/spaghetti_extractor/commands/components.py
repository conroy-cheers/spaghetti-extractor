"""Component discovery, contract, source, qualification, and composition commands."""

from __future__ import annotations

import argparse
import json

from ..component_discovery import write_component_proposals
from ..components.configuration import compose_component_configuration_v3
from ..components.contracts import build_lift_unit_contract_v2
from ..components.evidence import produce_component_evidence_v3
from ..components.qualification import qualify_lift_unit_v3
from ..components.resolution import resolve_component_catalog_v2
from ..components.runtime import build_component_runtime_package_v3
from ..components.source import build_component_source_package_v2
from .common import Handler, keyed_paths, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "stage-b-discover-components":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "reconstruction_plan", required=True)
        command.add_argument("--max-units", type=int, default=512)
        command.add_argument("--max-candidates-per-seed", type=int, default=12)
        path_argument(command, "out", required=True)
        return lambda a: write_component_proposals(
            machine_ir=a.machine_ir,
            reconstruction_plan=a.reconstruction_plan,
            out=a.out,
            max_units=a.max_units,
            max_candidates_per_seed=a.max_candidates_per_seed,
        )

    if name == "stage-b-resolve-components":
        path_argument(command, "proposals", required=True)
        path_argument(command, "intent", required=True)
        path_argument(command, "out", required=True)
        return lambda a: resolve_component_catalog_v2(
            proposals=a.proposals, intent=a.intent, out=a.out
        )

    if name == "stage-b-build-component-contract":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "reconstruction_plan", required=True)
        path_argument(command, "resolution", required=True)
        command.add_argument("--lift-unit-id", required=True)
        path_argument(command, "review")
        path_argument(command, "out", required=True)
        return lambda a: build_lift_unit_contract_v2(
            machine_ir=a.machine_ir,
            reconstruction_plan=a.reconstruction_plan,
            resolution=a.resolution,
            lift_unit_id=a.lift_unit_id,
            review=a.review,
            out_dir=a.out,
        )

    if name == "stage-b-package-component-source":
        command.add_argument("--lift-unit-id", required=True)
        command.add_argument("--file", action="append", required=True)
        command.add_argument("--shared-input", action="append", default=[])
        command.add_argument("--entry-symbol", required=True)
        path_argument(command, "out", required=True)
        return lambda a: build_component_source_package_v2(
            lift_unit_id=a.lift_unit_id,
            files=keyed_paths(a.file),
            shared_inputs=keyed_paths(a.shared_input),
            entry={"abi": "logical-c-v1", "symbol": a.entry_symbol},
            out_dir=a.out,
        )

    if name == "stage-b-produce-component-evidence":
        path_argument(command, "contract", required=True)
        path_argument(command, "implementation", required=True)
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "verification", required=True)
        path_argument(command, "compiler", required=True)
        path_argument(command, "out", required=True)
        return lambda a: produce_component_evidence_v3(
            contract=a.contract,
            implementation=a.implementation,
            machine_ir=a.machine_ir,
            verification=json.loads(a.verification.read_text(encoding="utf-8")),
            compiler=a.compiler,
            out=a.out,
        )

    if name == "stage-b-qualify-component":
        path_argument(command, "contract", required=True)
        path_argument(command, "implementation", required=True)
        path_argument(command, "evidence", required=True)
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "verification", required=True)
        path_argument(command, "out", required=True)
        return lambda a: qualify_lift_unit_v3(
            contract=a.contract,
            implementation=a.implementation,
            evidence=a.evidence,
            machine_ir=a.machine_ir,
            verification=json.loads(a.verification.read_text(encoding="utf-8")),
            out=a.out,
        )

    if name == "stage-b-compose-components":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "resolution", required=True)
        command.add_argument("--configuration-id", required=True)
        command.add_argument("--contract", action="append", default=[])
        command.add_argument("--implementation", action="append", default=[])
        command.add_argument("--qualification", action="append", default=[])
        path_argument(command, "out", required=True)
        return lambda a: compose_component_configuration_v3(
            machine_ir=a.machine_ir,
            resolution=a.resolution,
            configuration_id=a.configuration_id,
            contracts=keyed_paths(a.contract),
            implementations=keyed_paths(a.implementation),
            qualifications=keyed_paths(a.qualification),
            out=a.out,
        )

    if name == "stage-b-build-component-runtime":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "activation_plan", required=True)
        command.add_argument("--contract", action="append", default=[])
        command.add_argument("--implementation", action="append", default=[])
        command.add_argument("--qualification", action="append", default=[])
        path_argument(command, "interpreter_package", required=True)
        path_argument(command, "out", required=True)
        return lambda a: build_component_runtime_package_v3(
            machine_ir=a.machine_ir,
            activation_plan=a.activation_plan,
            contracts=keyed_paths(a.contract),
            implementations=keyed_paths(a.implementation),
            qualifications=keyed_paths(a.qualification),
            interpreter_package=a.interpreter_package,
            out_dir=a.out,
        )

    raise ValueError(f"unsupported component command: {name}")


__all__ = ["configure_command"]
