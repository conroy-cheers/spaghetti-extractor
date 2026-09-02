"""Low-level transfer, semantic-boundary, and project commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..candidate.behavioral_c import write_spx_behavioral_c_package
from ..candidate.native_ingress import (
    write_pe32_machine_object_authority_v2,
)
from ..candidate.project import (
    write_pe32_module_interface,
    write_pe32_observed_load_graph,
    write_pe32_project_completion,
    write_pe32_project_load_plan,
)
from ..transfer.plan import write_executable_transfer_plan
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "candidate-transfer-plan":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "machine_ir_manifest", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_executable_transfer_plan(
            machine_ir=a.machine_ir,
            machine_ir_manifest=a.machine_ir_manifest,
            out=a.out,
        )

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
            "--linked-semantic-module", action="append", default=[],
            required=True,
            metavar="IMAGE_ID=PATH",
        )
        return lambda a: write_pe32_project_load_plan(
            intent=a.intent,
            linked_semantic_modules=_path_mapping(
                a.linked_semantic_module, "linked semantic module"
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

    if name == "candidate-project-completion":
        path_argument(command, "load_plan", required=True)
        path_argument(command, "observed_load_graph")
        path_argument(command, "out", required=True)
        command.add_argument(
            "--native-realization", action="append", default=[], required=True,
            metavar="IMAGE_ID=PATH",
        )
        return lambda a: write_pe32_project_completion(
            load_plan=a.load_plan,
            native_realizations=_path_mapping(
                a.native_realization, "native realization"
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
        path_argument(command, "transfer_plan", required=True)
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
            transfer_plan=a.transfer_plan,
            out=a.out,
            entry_rvas=a.entry_rva,
            layout_intent=a.layout_intent,
            runtime_qualification=a.runtime_qualification,
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


def _json_array(path: Path, label: str) -> list[dict[str, object]]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must be an array of objects")
    return value


__all__ = ["configure_command"]
