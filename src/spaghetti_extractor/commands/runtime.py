"""Machine-IR fallback runtime generation commands."""

from __future__ import annotations

import argparse

from ..stage_b_interpreter_backend import write_stage_b_interpreter_package
from ..stage_b_native_engine import write_stage_b_native_engine_package
from ..stage_b_native_runtime import write_stage_b_native_runtime_package
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "stage-b-generate-interpreter":
        path_argument(command, "state_machine")
        path_argument(command, "machine_ir")
        path_argument(command, "out", required=True)
        command.add_argument(
            "--allow-deferred-potential-transfers", action="store_true"
        )
        return lambda a: write_stage_b_interpreter_package(
            state_machine=a.state_machine,
            machine_ir=a.machine_ir,
            out=a.out,
            allow_deferred_potential_transfers=a.allow_deferred_potential_transfers,
        )

    if name == "stage-b-generate-native-engine":
        path_argument(command, "state_machine")
        path_argument(command, "machine_ir")
        command.add_argument("--entry-rva", type=lambda value: int(value, 0), required=True)
        path_argument(command, "callable_external_contract")
        path_argument(command, "out", required=True)
        command.add_argument(
            "--allow-deferred-potential-transfers", action="store_true"
        )
        return lambda a: write_stage_b_native_engine_package(
            state_machine=a.state_machine,
            machine_ir=a.machine_ir,
            entry_rva=a.entry_rva,
            callable_external_contract=a.callable_external_contract,
            allow_deferred_potential_transfers=a.allow_deferred_potential_transfers,
            out=a.out,
        )

    if name == "stage-b-generate-native-runtime":
        path_argument(command, "interpreter_package", required=True)
        path_argument(command, "native_engine_package", required=True)
        path_argument(command, "external_profile")
        path_argument(command, "callable_external_contract")
        path_argument(command, "out", required=True)
        return lambda a: write_stage_b_native_runtime_package(
            interpreter_package=a.interpreter_package,
            native_engine_package=a.native_engine_package,
            external_profile=a.external_profile,
            callable_external_contract=a.callable_external_contract,
            out=a.out,
        )

    raise ValueError(f"unsupported runtime command: {name}")


__all__ = ["configure_command"]
