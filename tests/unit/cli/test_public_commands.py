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
from spaghetti_extractor.build_support.python_module_index import (
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
    "component list",
    "component status",
    "component build",
    "component check",
    "candidate list",
    "candidate status",
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
                "spaghetti_extractor.commands.proposal_static",
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
    "spaghetti_extractor.commands.proposal_static",
    "spaghetti_extractor.commands.diagnostic_contracts",
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
required = "spaghetti_extractor.commands.diagnostic_contracts"
forbidden = {
    "spaghetti_extractor.commands.runtime",
    "spaghetti_extractor.commands.expert_components",
    "spaghetti_extractor.commands.proposal_static",
    "spaghetti_extractor.candidate.engine",
    "spaghetti_extractor.reference_contract.generation",
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

    def test_operator_workflows_select_explicit_products(self) -> None:
        index = {
            "defaultConfiguration": "default",
            "components": {
                "units": {"leaf": {"kind": "component", "label": "Leaf"}},
                "configurations": {"default": {"kind": "configuration"}},
            },
            "candidate": {
                "configurations": ["default"],
                "testSuites": {"public": {"configurationId": "default"}},
            },
        }
        cases = (
            (["project", "analyze", "jq"], "project.analysis", False),
            (["project", "check", "dxball"], "project.regressionCheck", True),
            (["project", "check", "jq", "--acceptance"], "project.acceptanceCheck", True),
            (["component", "build", "gnu-hello", "leaf"], 'components.units."leaf".workPackage', False),
            (["component", "build", "gnu-hello"], 'components.configurations."default".runtime', False),
            (["component", "check", "gnu-hello", "leaf"], 'components.units."leaf".check', True),
            (["candidate", "build", "jq"], 'candidate.builds."default"', False),
            (["candidate", "test", "jq"], "candidate.allTests", True),
            (["candidate", "test", "jq", "--suite", "public"], 'candidate.tests."public"', True),
        )
        for arguments, suffix, no_link in cases:
            with self.subTest(arguments=arguments), patch(
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value=index,
            ), patch(
                "spaghetti_extractor.commands.workflows._build", return_value=0
            ) as build:
                self.assertEqual(main(arguments), 0)
                build.assert_called_once()
                called_args, called_kwargs = build.call_args
                self.assertEqual(called_args[1], suffix)
                self.assertEqual(called_kwargs.get("no_link", False), no_link)

    def test_project_status_reads_unified_progress_and_is_informational(self) -> None:
        report = {
            "format": "spaghetti-extractor-project-progress-v1",
            "configuration_id": "whole-project",
            "status": "incomplete",
            "authorizing": False,
            "static_ready": False,
            "authority": {"status": "incomplete", "authorizing": False},
            "counts": {"primary_frontiers": 1, "dependent_occurrences": 8},
            "primary_frontiers": [{
                "status": "incomplete",
                "family": "isa-qualification-v3",
                "code": "isa_qualification_evidence_missing",
                "record_id": "unit:1",
                "dependent_occurrences": 8,
                "source_location": {"rva_start": 0x1000},
                "next_action": "qualify the form",
            }],
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._realize_json",
            return_value=report,
        ), contextlib.redirect_stdout(output):
            self.assertEqual(main(["project", "status", "gnu-hello"]), 0)
        self.assertIn("frontiers=1", output.getvalue())
        self.assertIn("rva=0x1000", output.getvalue())
        self.assertIn("configuration=whole-project", output.getvalue())

    def test_component_list_is_index_only(self) -> None:
        index = {
            "components": {
                "units": {"leaf": {"kind": "component", "label": "Leaf"}},
                "configurations": {"default": {"kind": "configuration", "label": "Default"}},
            }
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), contextlib.redirect_stdout(output):
            self.assertEqual(main(["component", "list", "gnu-hello"]), 0)
        self.assertIn("leaf", output.getvalue())
        self.assertIn("default", output.getvalue())

    def test_candidate_test_without_declared_suites_is_a_usage_error(self) -> None:
        index = {
            "defaultConfiguration": "default",
            "candidate": {"configurations": ["default"], "testSuites": {}},
        }
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["candidate", "test", "gnu-hello"]), 2)

    def test_candidate_list_reports_configurations_and_test_suites(self) -> None:
        index = {
            "defaultConfiguration": "default",
            "candidate": {
                "configurations": ["default", "minimal"],
                "testSuites": {
                    "public": {"configurationId": "default"},
                },
            },
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), contextlib.redirect_stdout(output):
            self.assertEqual(main(["candidate", "list", "gnu-hello"]), 0)
        self.assertIn("default", output.getvalue())
        self.assertIn("tests=public", output.getvalue())
        self.assertIn("minimal", output.getvalue())

    def test_candidate_status_selects_one_configuration_progress_report(self) -> None:
        index = {
            "defaultConfiguration": "default",
            "candidate": {
                "configurations": ["default", "minimal"],
                "testSuites": {},
            },
        }
        report = {
            "format": "spaghetti-extractor-project-progress-v1",
            "configuration_id": "minimal",
            "status": "ready",
            "static_ready": True,
            "authority": {"status": "complete", "authorizing": True},
            "counts": {"primary_frontiers": 0, "dependent_occurrences": 0},
            "primary_frontiers": [],
            "next_action": "build candidate configuration minimal",
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_json",
            return_value=report,
        ) as realize, contextlib.redirect_stdout(output):
            self.assertEqual(
                main(
                    [
                        "candidate",
                        "status",
                        "gnu-hello",
                        "--configuration",
                        "minimal",
                    ]
                ),
                0,
            )
        self.assertEqual(
            realize.call_args.args[1], 'candidate.statuses."minimal"'
        )
        self.assertIn("static-ready=true", output.getvalue())

    def test_operator_workflow_accepts_an_explicit_target_flake(self) -> None:
        index = {
            "defaultConfiguration": "default",
            "components": {
                "units": {"leaf": {}},
                "configurations": {"default": {}},
            },
        }
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._build", return_value=0
        ) as build:
            self.assertEqual(
                main(
                    [
                        "component",
                        "build",
                        "gnu-hello",
                        "leaf",
                        "--target-flake",
                        "path:/tmp/consumer",
                    ]
                ),
                0,
            )
        args = build.call_args.args[0]
        self.assertEqual(args.target_flake, "path:/tmp/consumer")
        self.assertEqual(
            build.call_args.args[1], 'components.units."leaf".workPackage'
        )

    def test_operator_installables_quote_dotted_dynamic_identifiers(self) -> None:
        from spaghetti_extractor.commands.workflows import _operator_attribute

        args = argparse.Namespace(target="target.with.dots")
        self.assertEqual(
            _operator_attribute(
                args,
                'candidate.tests."suite.with.dots"',
            ),
            'legacyPackages.x86_64-linux.operatorTargets.'
            '"target.with.dots".candidate.tests."suite.with.dots"',
        )


if __name__ == "__main__":
    unittest.main()
