from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path

from spaghetti_extractor.cli import _build_parser, main
from spaghetti_extractor.commands.manifest import (
    COMMANDS_BY_NAME,
    SUPPORTED_COMMANDS,
)
from spaghetti_extractor.python_module_index import build_python_module_index


RETIRED_COMMANDS = (
    "stage-b-record-candidate",
    "stage-b-validate-candidate",
    "stage-b-explain-delta",
    "stage-b-bind-source-project",
    "stage-b-resolve-component-catalog-v2",
    "stage-b-build-component-contract-v2",
    "stage-b-package-component-source-v2",
    "stage-b-qualify-component-v2",
    "stage-b-compose-components-v2",
)


class PublicCliTests(unittest.TestCase):
    def test_cli_index_uses_manifest_as_dynamic_import_authority(self) -> None:
        repository = Path(__file__).parents[3]
        index = build_python_module_index(repository)
        modules = index["modules"]
        self.assertIsInstance(modules, dict)
        row = modules["spaghetti_extractor.cli"]
        self.assertEqual(
            set(row["dependencies"]),
            {
                "spaghetti_extractor",
                "spaghetti_extractor.commands.common",
                "spaghetti_extractor.commands.manifest",
                *(spec.group for spec in SUPPORTED_COMMANDS),
            },
        )

    def test_manifest_is_the_exact_top_level_command_surface(self) -> None:
        parser = _build_parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        self.assertEqual(tuple(subparsers.choices), tuple(COMMANDS_BY_NAME))
        self.assertEqual(
            tuple(command.name for command in SUPPORTED_COMMANDS),
            tuple(COMMANDS_BY_NAME),
        )
        for retired in RETIRED_COMMANDS:
            self.assertNotIn(retired, subparsers.choices)

    def test_every_manifest_command_is_configured_by_its_group(self) -> None:
        for spec in SUPPORTED_COMMANDS:
            with self.subTest(command=spec.name):
                parser = _build_parser(selected_command=spec.name)
                subparsers = next(
                    action
                    for action in parser._actions
                    if isinstance(action, argparse._SubParsersAction)
                )
                self.assertTrue(
                    callable(subparsers.choices[spec.name].get_default("handler"))
                )

    def test_retired_commands_fail_as_unknown_commands(self) -> None:
        for retired in RETIRED_COMMANDS:
            with self.subTest(command=retired):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        main([retired])

    def test_importing_cli_does_not_import_command_groups_or_backends(self) -> None:
        program = r"""
import sys
import spaghetti_extractor.cli
forbidden = {
    "spaghetti_extractor.commands.static_analysis",
    "spaghetti_extractor.commands.runtime",
    "spaghetti_extractor.stage_b_native_engine",
    "spaghetti_extractor.stage_b_interpreter_backend",
}
loaded = sorted(forbidden.intersection(sys.modules))
raise SystemExit("eager imports: " + repr(loaded) if loaded else 0)
"""
        completed = subprocess.run(
            [sys.executable, "-c", program],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_command_help_loads_only_its_phase_group(self) -> None:
        program = r"""
import contextlib
import io
import sys
from spaghetti_extractor.cli import main
with contextlib.redirect_stdout(io.StringIO()):
    try:
        main(["stage-a-smoke-contract", "--help"])
    except SystemExit as exc:
        if exc.code != 0:
            raise
required = "spaghetti_extractor.commands.static_analysis"
forbidden = {
    "spaghetti_extractor.commands.runtime",
    "spaghetti_extractor.commands.components",
    "spaghetti_extractor.stage_b_native_engine",
}
if required not in sys.modules:
    raise SystemExit("selected command group was not loaded")
loaded = sorted(forbidden.intersection(sys.modules))
raise SystemExit("unrelated imports: " + repr(loaded) if loaded else 0)
"""
        completed = subprocess.run(
            [sys.executable, "-c", program],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_active_command_keeps_argument_errors_at_exit_two(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "2"):
                main(["stage-a-smoke-contract"])


if __name__ == "__main__":
    unittest.main()
