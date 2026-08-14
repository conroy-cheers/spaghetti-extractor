from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.cli import _build_parser, main
from spaghetti_extractor.commands.manifest import (
    COMMANDS_BY_NAME,
    SUPPORTED_COMMANDS,
)
from spaghetti_extractor.python_module_index import (
    build_python_module_index,
    declared_public_command_roots,
)


TESTKIT = {"commands": ("*",)}


RETIRED_COMMANDS = (
    "stage-a-check-isa-conformance-worker",
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

OPERATOR_COMMANDS = (
    "project analyze",
    "project status",
    "project check",
    "component build",
    "candidate build",
    "candidate test",
)


def _subcommands(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    return next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )


def _command_parser(
    parser: argparse.ArgumentParser, command: str
) -> argparse.ArgumentParser:
    namespace, name = command.split(" ", 1)
    return _subcommands(_subcommands(parser).choices[namespace]).choices[name]


class PublicCliTests(unittest.TestCase):
    def test_cli_index_keeps_role_roots_out_of_dispatcher_closure(self) -> None:
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
            },
        )
        self.assertTrue(
            all(spec.group not in row["dependencies"] for spec in SUPPORTED_COMMANDS)
        )

    def test_literal_roles_expose_operator_and_expert_implementation_roots(self) -> None:
        repository = Path(__file__).parents[3]
        roots = {
            (root.module, root.role, root.owner)
            for root in declared_public_command_roots(repository)
        }
        self.assertEqual(
            {
                owner
                for module, role, owner in roots
                if module == "spaghetti_extractor.commands.workflows"
                and role == "operator"
            },
            {f"command:{command}" for command in OPERATOR_COMMANDS},
        )
        self.assertIn(
            (
                "spaghetti_extractor.commands.static_analysis",
                "proposal",
                "command:expert stage-a-inventory-binary",
            ),
            roots,
        )

    def test_manifest_is_the_exact_namespaced_command_surface(self) -> None:
        parser = _build_parser()
        namespaces = _subcommands(parser)
        self.assertEqual(
            tuple(namespaces.choices),
            ("project", "component", "candidate", "expert"),
        )
        self.assertEqual(
            tuple(command.name for command in SUPPORTED_COMMANDS),
            tuple(COMMANDS_BY_NAME),
        )
        self.assertEqual(
            tuple(
                command.name
                for command in SUPPORTED_COMMANDS
                if command.role == "operator"
            ),
            OPERATOR_COMMANDS,
        )
        for spec in SUPPORTED_COMMANDS:
            self.assertIsNotNone(_command_parser(parser, spec.name))
        for retired in RETIRED_COMMANDS:
            self.assertNotIn(retired, _subcommands(namespaces.choices["expert"]).choices)

    def test_flat_leaf_commands_have_no_compatibility_aliases(self) -> None:
        expert_commands = [
            spec.implementation_name
            for spec in SUPPORTED_COMMANDS
            if spec.path[0] == "expert"
        ]
        for command in expert_commands:
            with self.subTest(command=command):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        main([command, "--help"])

    def test_public_commands_are_not_versioned_implementation_names(self) -> None:
        offenders = [
            command.implementation_name
            for command in SUPPORTED_COMMANDS
            if command.implementation_name.endswith(("-v1", "-v2", "-v3"))
            or "-worker" in command.implementation_name
        ]
        self.assertEqual(offenders, [])

    def test_every_manifest_command_is_configured_by_its_group(self) -> None:
        for spec in SUPPORTED_COMMANDS:
            with self.subTest(command=spec.name):
                parser = _build_parser(selected_command=spec.name)
                self.assertTrue(
                    callable(_command_parser(parser, spec.name).get_default("handler"))
                )

    def test_retired_commands_fail_as_unknown_commands(self) -> None:
        for retired in RETIRED_COMMANDS:
            with self.subTest(command=retired):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        main([retired])
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        main(["expert", retired])

    def test_importing_cli_does_not_import_command_groups_or_backends(self) -> None:
        program = r"""
import sys
import spaghetti_extractor.cli
forbidden = {
    "spaghetti_extractor.commands.workflows",
    "spaghetti_extractor.commands.static_analysis",
    "spaghetti_extractor.commands.runtime",
    "spaghetti_extractor.candidate.engine",
    "spaghetti_extractor.candidate.interpreter",
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
        main(["expert", "stage-a-smoke-contract", "--help"])
    except SystemExit as exc:
        if exc.code != 0:
            raise
required = "spaghetti_extractor.commands.static_analysis"
forbidden = {
    "spaghetti_extractor.commands.runtime",
    "spaghetti_extractor.commands.components",
    "spaghetti_extractor.candidate.engine",
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
                main(["expert", "stage-a-smoke-contract"])

    def test_operator_workflows_dispatch_only_to_stable_nix_surfaces(self) -> None:
        cases = (
            (
                ["project", "analyze", "jq"],
                ["build", "./targets#project-analyze-jq"],
            ),
            (
                ["project", "status", "gnu-hello"],
                ["eval", "--json", "./targets#lib.targetMetadata.gnu-hello"],
            ),
            (
                ["project", "check", "dxball"],
                ["run", "./targets#test", "--", "dxball"],
            ),
            (
                ["project", "check", "jq", "--acceptance"],
                ["run", "./targets#test", "--", "--acceptance", "jq"],
            ),
            (
                ["component", "build", "gnu-hello"],
                ["build", "./targets#component-build-gnu-hello"],
            ),
            (
                ["candidate", "build", "jq"],
                [
                    "build",
                    "./targets#legacyPackages.x86_64-linux.candidateBuilds.jq",
                ],
            ),
            (
                ["candidate", "test", "jq"],
                [
                    "build",
                    "./targets#legacyPackages.x86_64-linux.candidateTests.jq",
                ],
            ),
        )
        prefix = [
            "nix",
            "--extra-experimental-features",
            "nix-command flakes ca-derivations",
        ]
        for arguments, suffix in cases:
            with self.subTest(arguments=arguments):
                with patch(
                    "spaghetti_extractor.commands.workflows.subprocess.run"
                ) as run:
                    run.return_value.returncode = 0
                    self.assertEqual(main(arguments), 0)
                run.assert_called_once_with(prefix + suffix, check=False)

    def test_operator_workflow_accepts_an_explicit_target_flake(self) -> None:
        with patch(
            "spaghetti_extractor.commands.workflows.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            self.assertEqual(
                main(
                    [
                        "component",
                        "build",
                        "gnu-hello",
                        "--target-flake",
                        "path:/tmp/consumer",
                    ]
                ),
                0,
            )
        run.assert_called_once_with(
            [
                "nix",
                "--extra-experimental-features",
                "nix-command flakes ca-derivations",
                "build",
                "path:/tmp/consumer#component-build-gnu-hello",
            ],
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
