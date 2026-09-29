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
from types import SimpleNamespace
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
    "expert candidate-authority-build",
    "expert candidate-authority-check",
    "expert candidate-generate-interpreter",
    "expert candidate-generate-engine",
    "expert candidate-generate-runtime",
    "expert candidate-native-ingress-plan",
    "expert component-resolve",
    "expert component-contract-build",
    "expert component-source-package",
    "expert component-adapter-build",
    "expert component-evidence-produce",
    "expert component-qualify",
    "expert component-compose",
)

OPERATOR_COMMANDS = (
    "project analyze",
    "project status",
    "project check",
    "component list",
    "component status",
    "component build",
    "component start",
    "component check",
    "boundary status",
    "boundary inventory",
    "boundary inspect",
    "boundary propose",
    "boundary adopt",
    "boundary check",
    "library status",
    "library inspect",
    "library adopt",
    "library check",
    "candidate list",
    "candidate status",
    "candidate policy",
    "candidate build",
    "candidate export",
    "candidate test",
)


from .public_command_fixture import _operator_status, _subcommands, _command_parser

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
            (
                "project",
                "component",
                "boundary",
                "library",
                "candidate",
                "expert",
            ),
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
    "spaghetti_extractor.candidate.runtime_core",
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
    "spaghetti_extractor.commands.diagnostic_contracts",
    "spaghetti_extractor.candidate.runtime_core",
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

    def test_operator_group_defers_domain_codecs_until_a_product_is_read(self) -> None:
        program = r"""
import sys
import spaghetti_extractor.commands.workflows
forbidden = {
    "spaghetti_extractor.components.work_package_v6",
    "spaghetti_extractor.semantic_link.module_v2",
    "spaghetti_extractor.semantic_providers.qualification_v2",
    "spaghetti_extractor.semantic_providers.selection_v2",
}
loaded = sorted(forbidden.intersection(sys.modules))
raise SystemExit("eager domain codecs: " + repr(loaded) if loaded else 0)
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

    def test_operator_workflows_select_explicit_products(self) -> None:
        index = {
            "defaultConfiguration": "default",
            "components": {
                "units": {
                    "leaf": {
                        "label": "Leaf",
                        "entryRvas": [4096],
                        "products": ["qualification", "workPackage"],
                    }
                },
            },
            "candidate": {
                "configurations": {
                    "default": {
                        "mode": "hybrid",
                        "products": ["realization", "selection"],
                    }
                },
                "testSuites": {"public": {"configurationId": "default"}},
            },
            "libraries": {"selections": {}},
        }
        cases = (
            (["project", "analyze", "jq"], "project.analysis", False),
            (["project", "check", "dxball"], "project.regressionCheck", True),
            (["project", "check", "jq", "--acceptance"], "project.acceptanceCheck", True),
            (["component", "build", "gnu-hello", "leaf"], 'components.units."leaf".workPackage', False),
            (["library", "check", "gnu-hello"], "libraries.check", True),
            (["candidate", "build", "jq"], 'candidate.configurations."default".realization', False),
            (["candidate", "test", "jq"], "candidate.allTests", True),
            (["candidate", "test", "jq", "--suite", "public"], 'candidate.testSuites."public"', True),
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

    def test_component_check_requires_a_complete_bound_qualification(self) -> None:
        index = {
            "components": {
                "units": {
                    "leaf": {"products": ["qualification"]},
                },
            },
        }
        qualification = SimpleNamespace(
            provider_id="fixture.leaf.portable-c",
            payload={"status": "complete", "blockers": []},
        )
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_artifact",
            return_value=(Path("/tmp/qualification"), {}),
        ) as realize, patch(
            "spaghetti_extractor.semantic_providers.qualification_v2."
            "SemanticProviderQualificationV2.parse",
            return_value=qualification,
        ):
            self.assertEqual(
                main(["component", "check", "fixture", "leaf"]), 0
            )
        self.assertEqual(
            realize.call_args.args[1], 'components.units."leaf".qualification'
        )

    def test_complete_check_reuses_evidence_without_a_region_selection(self) -> None:
        index = {'components': {'units': {'leaf': {'products': ['proofCheckFor']}}}}
        qualification = SimpleNamespace(provider_id='fixture.leaf.portable-c',
                                        payload={'status': 'complete', 'blockers': []})
        retained = '/nix/store/' + 'a'*32 + '-proof'
        arguments = ['component', 'check', 'fixture', 'leaf', '--reuse-proof', '/retained',
                     '--query-timeout', '30', '--json']
        with patch('spaghetti_extractor.commands.workflows._operator_index', return_value=index), patch(
                'spaghetti_extractor.operator.proof_check.retain_component_proof', return_value=retained) as retain, patch(
                'spaghetti_extractor.commands.workflows._realize_artifact',
                return_value=(Path('/tmp/qualification.json'), {})) as realize, patch(
                'spaghetti_extractor.semantic_providers.qualification_v2.SemanticProviderQualificationV2.parse',
                return_value=qualification):
            for status, expected in [('complete', 0), ('incomplete', 1)]:
                qualification.payload['status'] = status
                with self.subTest(status=status), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(arguments), expected)
                    self.assertEqual(json.loads(output.getvalue())['status'], status)
                self.assertEqual(realize.call_args.args[2], 'semantic-provider-qualification.json')
                self.assertEqual(realize.call_args.kwargs['apply_arguments'], {
                    'obligations': None, 'queryTimeoutSeconds': 30, 'previousQueryEvidencePath': retained})
                self.assertEqual(retain.call_args.kwargs['component_id'], 'leaf')
            qualification.provider_id = 'fixture.foreign.portable-c'
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(arguments), 2)
        for flags in (['--source'], ['--conditional'], ['--local-contracts'], ['--comparison-package', '/fixture']):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), patch(
                    'spaghetti_extractor.commands.workflows._operator_index') as discover:
                self.assertEqual(main(arguments + flags), 2)
                discover.assert_not_called()

    def test_boundary_adopt_directs_components_to_component_start(self) -> None:
        with patch(
            "spaghetti_extractor.commands.workflows._boundary_subject",
            return_value={
                "canonicalSubject": "component:leaf",
                "kind": "component",
            },
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([
                "boundary", "adopt", "fixture", "component:leaf",
                "--output", "/tmp/unused-component-intent.json",
            ]), 2)

    def test_component_seed_is_an_alias_only_when_its_entry_rva_is_authored(self) -> None:
        from spaghetti_extractor.commands.workflows import _boundary_subject

        args = SimpleNamespace(subject="component-seed:0x1000")
        boundaries = {
            "subjects": {
                "component:leaf": {
                    "kind": "component",
                    "products": ["source"],
                },
            },
        }
        components = {
            "units": {
                "leaf": {"entryRvas": [4096]},
            },
        }
        with patch(
            "spaghetti_extractor.commands.workflows._boundary_index",
            return_value=boundaries,
        ), patch(
            "spaghetti_extractor.commands.workflows._component_index",
            return_value=components,
        ):
            resolved = _boundary_subject(args)
        self.assertEqual(resolved["canonicalSubject"], "component:leaf")
        self.assertNotIn("dynamic", resolved)

        with patch(
            "spaghetti_extractor.commands.workflows._boundary_index",
            return_value={"subjects": {}},
        ), patch(
            "spaghetti_extractor.commands.workflows._component_index",
            return_value=components,
        ), self.assertRaisesRegex(ValueError, "has no boundary product"):
            _boundary_subject(args)

        components["units"]["leaf"]["entryRvas"] = [8192]
        with patch(
            "spaghetti_extractor.commands.workflows._boundary_index",
            return_value=boundaries,
        ), patch(
            "spaghetti_extractor.commands.workflows._component_index",
            return_value=components,
        ):
            unresolved = _boundary_subject(args)
        self.assertTrue(unresolved["dynamic"])

    def test_library_check_accepts_the_public_island_id(self) -> None:
        island = "library-island-v4:" + "a" * 64
        index = {
            "libraries": {"selections": {"a" * 64: {"products": ["check"]}}},
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
            build.call_args.args[1], f'libraries.selections."{"a" * 64}".check'
        )
        self.assertTrue(build.call_args.kwargs["no_link"])

    def test_component_status_reads_the_canonical_checked_status(self) -> None:
        index = {
            "components": {
                "units": {"leaf": {
                    "label": "Leaf",
                    "entryRvas": [4096],
                    "products": ["qualification", "workPackage"],
                }},
            },
        }
        report = _operator_status("component:leaf", authority="held")
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_artifact",
            return_value=(Path("/tmp/qualification"), {}),
        ) as realize, contextlib.redirect_stdout(io.StringIO()):
            with patch(
                "spaghetti_extractor.commands.workflows.project_component_qualification",
                return_value=(report, []),
            ):
                self.assertEqual(main(["component", "status", "fixture", "leaf"]), 0)
            self.assertEqual(
                realize.call_args.args[1], 'components.units."leaf".qualification'
            )

    def test_component_development_status_selects_the_local_progress_leaf(self) -> None:
        index = {
            "components": {
                "units": {"leaf": {
                    "label": "Leaf",
                    "entryRvas": [4096],
                    "products": ["workPackage"],
                }},
            },
        }
        report = _operator_status("component:leaf", state="incomplete")
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_artifact",
            return_value=(Path("/tmp/work-package"), {}),
        ) as realize, contextlib.redirect_stdout(io.StringIO()):
            with patch(
                "spaghetti_extractor.commands.workflows.project_component_work_package",
                return_value=(report, []),
            ):
                self.assertEqual(
                    main([
                        "component", "status", "fixture", "leaf", "--development",
                    ]),
                    0,
                )
        self.assertEqual(
            realize.call_args.args[1],
            'components.units."leaf".workPackage',
        )

    def test_component_development_status_rejects_configurations(self) -> None:
        index = {
            "components": {
                "units": {"leaf": {"label": "Leaf", "products": []}},
            },
        }
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "2"):
                main(
                    [
                        "component",
                        "status",
                        "fixture",
                        "--configuration",
                        "default",
                        "--development",
                    ]
                )

    def test_project_status_reads_semantic_module_work_view(self) -> None:
        report = _operator_status(
            "module:gnu-hello",
            state="incomplete",
            blockers=[{
                "family": "semantic-link",
                "code": "isa_qualification_evidence_missing",
                "count": 1,
                "example_location": "unit:1",
            }],
        )
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value={"libraries": {"selections": {}}},
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_json",
            return_value=report,
        ) as realize, contextlib.redirect_stdout(output):
            self.assertEqual(main(["project", "status", "gnu-hello"]), 0)
        self.assertEqual(realize.call_args.args[1], "project.status")
        self.assertEqual(realize.call_args.args[2], "project-status.json")
        self.assertIn("blockers=1", output.getvalue())
        self.assertIn("[unit:1]", output.getvalue())
        self.assertIn("authority=not-applicable", output.getvalue())
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
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value={"libraries": {"selections": {}}},
        ), patch(
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

    def test_unconfigured_library_workflow_fails_before_realization(self) -> None:
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value={"libraries": None},
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_json"
        ) as realize, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["library", "status", "jq"]), 2)
        realize.assert_not_called()

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
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value={"libraries": {"selections": {}}},
            ), patch(
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
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value={"libraries": {"selections": {}}},
            ), patch(
                "spaghetti_extractor.commands.workflows._realize_json",
                return_value=report,
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 2)
    def test_component_list_is_index_only(self) -> None:
        index = {
            "components": {
                "units": {"leaf": {
                    "label": "Leaf",
                    "entryRvas": [4096],
                    "products": ["workPackage"],
                }},
            }
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), contextlib.redirect_stdout(output):
            self.assertEqual(main(["component", "list", "gnu-hello"]), 0)
        self.assertIn("leaf", output.getvalue())
        self.assertNotIn("configuration", output.getvalue())

    def test_json_list_commands_emit_the_complete_validated_index(self) -> None:
        index = {
            "format": "spaghetti-extractor-operator-index-v1",
            "targetId": "fixture",
            "defaultConfiguration": "faithful",
            "project": {"products": []},
            "components": {"products": ["proposals"], "units": {}},
            "boundaries": {"products": [], "subjects": {}},
            "libraries": None,
            "candidate": {
                "products": [],
                "configurations": {},
                "testSuites": {},
            },
        }
        for namespace in ("component", "candidate"):
            with self.subTest(namespace=namespace), patch(
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value=index,
            ), patch(
                "spaghetti_extractor.commands.workflows._realize_json"
            ) as realize:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        main([namespace, "list", "fixture", "--json"]), 0
                    )
                self.assertEqual(json.loads(output.getvalue()), index)
                realize.assert_not_called()

    def test_component_list_exposes_analysis_proposals_before_intent(self) -> None:
        index = {
            "defaultConfiguration": "faithful",
            "components": {"units": {}},
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

    def test_component_absence_does_not_hide_the_faithful_candidate(self) -> None:
        index = {
            "defaultConfiguration": "faithful",
            "components": {"units": {}},
            "candidate": {
                "configurations": {
                    "faithful": {
                        "mode": "faithful",
                        "products": ["realization", "selection"],
                    }
                },
                "testSuites": {},
            },
        }
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._build", return_value=0
        ) as build:
            self.assertEqual(main(["candidate", "build", "fixture"]), 0)
        self.assertEqual(
            build.call_args.args[1], 'candidate.configurations."faithful".realization'
        )
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "2"):
                main(["component", "build", "fixture"])


    def test_operator_workflow_accepts_an_explicit_target_flake(self) -> None:
        index = {
            "components": {
                "units": {"leaf": {"products": ["workPackage"]}},
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
                'candidate.testSuites."suite.with.dots"',
            ),
            'legacyPackages.x86_64-linux.operatorTargets.'
            '"target.with.dots".candidate.testSuites."suite.with.dots"',
        )


if __name__ == "__main__":
    unittest.main()
