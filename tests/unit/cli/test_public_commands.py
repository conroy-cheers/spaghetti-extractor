from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
import sys
import tempfile
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
    "spaghetti-extractor-export-opaque-reconstruction",
    "spaghetti-extractor-export-reference-contract",
    "spaghetti-extractor-smoke-contract",
    "spaghetti-extractor-explain-contract",
    "spaghetti-extractor-diff-contract",
    "isa-check-conformance-worker",
    "spaghetti-extractor-record-candidate",
    "spaghetti-extractor-validate-candidate",
    "spaghetti-extractor-explain-delta",
    "spaghetti-extractor-bind-source-project",
    "spaghetti-extractor-resolve-component-catalog-v2",
    "component-contract-build-v2",
    "component-source-package-v2",
    "component-qualify-v2",
    "component-compose-v2",
)

OPERATOR_COMMANDS = (
    "project analyze",
    "project status",
    "project check",
    "component list",
    "component status",
    "component build",
    "component bind",
    "component check",
    "component relation",
    "call status",
    "call inspect",
    "call propose",
    "call adopt",
    "call check",
    "library status",
    "library inspect",
    "library adopt",
    "library check",
    "candidate list",
    "candidate status",
    "candidate build",
    "candidate check",
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
                "command:expert static-inventory-binary",
            ),
            roots,
        )

    def test_manifest_is_the_exact_namespaced_command_surface(self) -> None:
        parser = _build_parser()
        namespaces = _subcommands(parser)
        self.assertEqual(
            tuple(namespaces.choices),
            ("project", "component", "call", "library", "candidate", "expert"),
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
        main(["expert", "static-program-export", "--help"])
    except SystemExit as exc:
        if exc.code != 0:
            raise
required = "spaghetti_extractor.commands.proposal_static"
forbidden = {
    "spaghetti_extractor.commands.runtime",
    "spaghetti_extractor.commands.expert_components",
    "spaghetti_extractor.commands.diagnostic_contracts",
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
                main(["expert", "static-program-export"])

    def test_native_engine_command_exposes_only_static_closed_inputs(self) -> None:
        parser = _build_parser(
            selected_command="expert candidate-generate-engine"
        )
        command = _command_parser(
            parser, "expert candidate-generate-engine"
        )
        actions = {action.dest: action for action in command._actions}

        self.assertNotIn("state_machine", actions)
        self.assertNotIn("allow_deferred_potential_transfers", actions)
        for name in (
            "machine_ir",
            "machine_ir_manifest",
            "canonical_external_sites",
            "entry_rva",
            "out",
        ):
            self.assertTrue(actions[name].required, name)

    def test_operator_workflows_select_explicit_products(self) -> None:
        index = {
            "hasComponents": True,
            "defaultConfiguration": "default",
            "components": {
                "units": {
                    "leaf": {
                        "kind": "component",
                        "label": "Leaf",
                        "hasActivationReceipt": True,
                    }
                },
                "configurations": {"default": {"kind": "configuration"}},
            },
            "candidate": {
                "configurations": ["default"],
                "testSuites": {"public": {"configurationId": "default"}},
            },
            "libraries": {"configured": True, "selections": []},
        }
        cases = (
            (["project", "analyze", "jq"], "project.analysis", False),
            (["project", "check", "dxball"], "project.regressionCheck", True),
            (["project", "check", "jq", "--acceptance"], "project.acceptanceCheck", True),
            (["component", "build", "gnu-hello", "leaf"], 'components.units."leaf".build', False),
            (["component", "build", "gnu-hello"], 'components.configurations."default".runtime', False),
            (["component", "check", "gnu-hello", "leaf"], 'components.units."leaf".check', True),
            (["library", "check", "gnu-hello"], "libraries.check", True),
            (["candidate", "build", "jq"], 'candidate.builds."default"', False),
            (["candidate", "check", "jq"], 'candidate.checks."default"."hybrid"', True),
            (
                ["candidate", "check", "jq", "--mode", "portable"],
                'candidate.checks."default"."portable"',
                True,
            ),
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

    def test_library_check_accepts_the_public_island_id(self) -> None:
        island = "library-island-v4:" + "a" * 64
        index = {
            "libraries": {"configured": True, "selections": ["a" * 64]},
        }
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._build", return_value=0
        ) as build:
            self.assertEqual(
                main(["library", "check", "fixture", "--selection", island]),
                0,
            )
        self.assertEqual(
            build.call_args.args[1], f'libraries.checks."{"a" * 64}"'
        )
        self.assertTrue(build.call_args.kwargs["no_link"])

    def test_component_status_reads_the_canonical_checked_status(self) -> None:
        index = {
            "hasComponents": True,
            "defaultConfiguration": "default",
            "components": {
                "units": {"leaf": {
                    "kind": "component",
                    "label": "Leaf",
                    "hasActivationReceipt": True,
                }},
                "configurations": {"default": {"kind": "configuration"}},
            },
        }
        report = {"status": "ready", "counts": None, "next_action": None}
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_json",
            return_value=report,
        ) as realize, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["component", "status", "fixture", "leaf"]), 0)
            self.assertEqual(
                realize.call_args.args[1], 'components.units."leaf".status'
            )

    def test_component_development_status_selects_the_local_progress_leaf(self) -> None:
        index = {
            "hasComponents": True,
            "defaultConfiguration": "default",
            "components": {
                "units": {"leaf": {"kind": "component", "label": "Leaf"}},
                "configurations": {"default": {"kind": "configuration"}},
            },
        }
        report = {"status": "incomplete", "counts": None, "next_action": None}
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_json",
            return_value=report,
        ) as realize, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "component",
                        "status",
                        "fixture",
                        "leaf",
                        "--development",
                    ]
                ),
                0,
            )
        self.assertEqual(
            realize.call_args.args[1],
            'components.units."leaf".developmentStatus',
        )

    def test_component_development_status_rejects_configurations(self) -> None:
        index = {
            "hasComponents": True,
            "defaultConfiguration": "default",
            "components": {
                "units": {"leaf": {"kind": "component", "label": "Leaf"}},
                "configurations": {"default": {"kind": "configuration"}},
            },
        }
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "component",
                        "status",
                        "fixture",
                        "--configuration",
                        "default",
                        "--development",
                    ]
                ),
                2,
            )

    def test_project_status_reads_authority_only_status(self) -> None:
        report = {
            "format": "spaghetti-extractor-project-status-v2",
            "status": "incomplete",
            "authorizing": False,
            "authority_ready": False,
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
        ) as realize, contextlib.redirect_stdout(output):
            self.assertEqual(main(["project", "status", "gnu-hello"]), 0)
        self.assertEqual(realize.call_args.args[1], "project.status")
        self.assertEqual(realize.call_args.args[2], "project-status.json")
        self.assertIn("frontiers=1", output.getvalue())
        self.assertIn("rva=0x1000", output.getvalue())
        self.assertIn("authority-ready=false", output.getvalue())
        self.assertNotIn("configuration=", output.getvalue())

    def test_library_status_reads_checked_operator_artifact(self) -> None:
        report = {
            "status": "incomplete",
            "adoption_status": "ready",
            "recognition_status": "incomplete",
            "counts": {
                "releases": 2,
                "islands": 12,
                "identity_complete": 4,
                "boundary_complete": 1,
                "implementation_complete": 1,
                "ready_adoptions": 1,
                "adoption_intents": 2,
            },
            "selections": [],
            "primary_blockers": [],
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._realize_json",
            return_value=report,
        ) as realize, contextlib.redirect_stdout(output):
            self.assertEqual(main(["library", "status", "gnu-hello"]), 0)
        self.assertEqual(realize.call_args.args[1], "libraries.status")
        self.assertEqual(realize.call_args.args[2], "library-status.json")
        self.assertIn("islands=12", output.getvalue())
        self.assertIn("adoption=ready", output.getvalue())
        self.assertIn("recognition=incomplete", output.getvalue())
        self.assertIn("ready=1/2", output.getvalue())

    def test_library_adoption_is_tracked_idempotent_and_refuses_stale_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "targets"
            bundle = corpus / "gnu-hello"
            bundle.mkdir(parents=True)
            (bundle / "target.json").write_text(
                json.dumps(
                    {
                        "format": "spaghetti-extractor-target-bundle-v3",
                        "id": "gnu-hello",
                        "display_name": "GNU Hello",
                        "input": {"kind": "pe32", "expected_sha256": "a" * 64},
                        "paths": {
                            "nix": "default.nix",
                            "components": None,
                            "libraries": "intent/libraries",
                        },
                        "workflow": {"default_configuration": None},
                    }
                ),
                encoding="utf-8",
            )
            island_id = "library-island-v4:" + "b" * 64
            report = {
                "islands": [
                    {
                        "id": island_id,
                        "hypotheses_sha256": "c" * 64,
                        "recipes": [
                            {
                                "recipe_id": "portable-runtime",
                                "implementation_id": "implementation:" + "d" * 64,
                            }
                        ],
                    }
                ]
            }
            arguments = [
                "library", "adopt", "gnu-hello",
                "--target-flake", str(corpus),
                "--island", island_id,
                "--recipe", "portable-runtime",
            ]
            with patch(
                "spaghetti_extractor.commands.workflows._realize_json",
                return_value=report,
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 0)
                self.assertEqual(main(arguments), 0)
            outputs = list((bundle / "intent" / "libraries").glob("*.json"))
            self.assertEqual(len(outputs), 1)
            intent = json.loads(outputs[0].read_text(encoding="utf-8"))
            self.assertEqual(intent["format"], "spaghetti-extractor-library-adoption-intent-v1")
            outputs[0].write_text("{}\n", encoding="utf-8")
            with patch(
                "spaghetti_extractor.commands.workflows._realize_json",
                return_value=report,
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 2)
    def test_component_list_is_index_only(self) -> None:
        index = {
            "hasComponents": True,
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

    def test_component_list_exposes_analysis_proposals_before_intent(self) -> None:
        index = {
            "hasComponents": False,
            "defaultConfiguration": None,
            "components": {"units": {}, "configurations": {}},
        }
        proposals = {
            "proposals": [
                {
                    "id": "proposal:entry",
                    "proposal_kinds": ["singleton"],
                    "membership": {"rva_start": 0x1000, "rva_end": 0x1010},
                }
            ]
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_json",
            return_value=proposals,
        ) as realize, contextlib.redirect_stdout(output):
            self.assertEqual(main(["component", "list", "fixture"]), 0)
        realize.assert_called_once()
        self.assertIn("component intent: not configured", output.getvalue())
        self.assertIn("proposal:entry", output.getvalue())
        self.assertIn("0x1000-0x1010", output.getvalue())

    def test_component_and_candidate_builds_fail_cleanly_before_intent(self) -> None:
        index = {
            "hasComponents": False,
            "defaultConfiguration": None,
            "components": {"units": {}, "configurations": {}},
            "candidate": {"configurations": [], "testSuites": {}},
        }
        for command in (
            ["component", "build", "fixture"],
            ["candidate", "build", "fixture"],
            ["candidate", "check", "fixture"],
        ):
            with self.subTest(command=command), patch(
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value=index,
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(command), 2)

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
            "format": "spaghetti-extractor-candidate-status-v2",
            "configuration_id": "minimal",
            "status": "ready",
            "structural_ready": True,
            "configuration_ready": True,
            "build_ready": True,
            "structural": {"status": "complete", "executable": True},
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
        self.assertEqual(realize.call_args.args[2], "candidate-status.json")
        self.assertIn("build-ready=true", output.getvalue())

    def test_operator_workflow_accepts_an_explicit_target_flake(self) -> None:
        index = {
            "hasComponents": True,
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
            build.call_args.args[1], 'components.units."leaf".build'
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
