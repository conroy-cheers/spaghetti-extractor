"""Machine-IR fallback runtime generation commands."""

from __future__ import annotations

import argparse

from ..candidate.interpreter import write_stage_b_interpreter_package
from ..candidate.engine import write_stage_b_native_engine_package
from ..candidate.runtime import write_stage_b_native_runtime_package
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "stage-b-generate-interpreter":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_stage_b_interpreter_package(
            machine_ir=a.machine_ir,
            out=a.out,
        )

    if name == "stage-b-generate-native-engine":
        path_argument(command, "machine_ir", required=True)
        path_argument(command, "machine_ir_manifest", required=True)
        command.add_argument("--entry-rva", type=lambda value: int(value, 0), required=True)
        path_argument(command, "canonical_external_sites", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_stage_b_native_engine_package(
            machine_ir=a.machine_ir,
            machine_ir_manifest=a.machine_ir_manifest,
            entry_rva=a.entry_rva,
            canonical_external_sites=a.canonical_external_sites,
            out=a.out,
        )

    if name == "stage-b-generate-native-runtime":
        path_argument(command, "interpreter_package", required=True)
        path_argument(command, "native_engine_package", required=True)
        path_argument(command, "external_profile")
        path_argument(command, "out", required=True)
        return lambda a: write_stage_b_native_runtime_package(
            interpreter_package=a.interpreter_package,
            native_engine_package=a.native_engine_package,
            external_profile=a.external_profile,
            out=a.out,
        )

    raise ValueError(f"unsupported runtime command: {name}")


__all__ = ["configure_command"]
