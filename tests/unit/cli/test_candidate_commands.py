from __future__ import annotations
import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch
from spaghetti_extractor.cli import main
TESTKIT = {"commands": ("*",)}


from .public_command_fixture import _operator_status

class CandidateCliTests(unittest.TestCase):
    def test_candidate_proof_hints_use_current_parameterized_products(self) -> None:
        row = {'mode': 'hybrid', 'selectedComponentIds': ['leaf'],
               'products': ['realization', 'realizationFor', 'selection', 'selectionFor']}
        index = {'defaultConfiguration': 'default', 'candidate': {'configurations': {'default': row}}}
        retained = '/nix/store/' + 'a'*32 + '-proof'
        with patch('spaghetti_extractor.commands.workflows._operator_index', return_value=index), patch(
                'spaghetti_extractor.operator.proof_check.retain_component_proof', return_value=retained) as retain, patch(
                'spaghetti_extractor.commands.workflows._build', return_value=0) as build, patch(
                'spaghetti_extractor.commands.workflows._realize_artifact',
                return_value=(Path('/tmp/selection'), {'ready_for_realization': True})) as realize, patch(
                'spaghetti_extractor.commands.workflows.project_candidate_selection',
                return_value=(_operator_status('configuration:gnu-hello:default'), [])):
            for action, mocked, product in [('build', build, 'realizationFor'), ('status', realize, 'selectionFor')]:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(['candidate', action, 'gnu-hello', '--reuse-proof', 'leaf=/retained']), 0)
                self.assertEqual(mocked.call_args.args[1], f'candidate.configurations."default".{product}')
                self.assertEqual(mocked.call_args.kwargs['apply_arguments'],
                                 {'proofEvidenceByComponent': {'leaf': retained}})
                self.assertEqual(retain.call_args.kwargs['component_id'], 'leaf')
            for flags in (['foreign=/retained'], ['leaf='], ['leaf'], ['leaf=/one', 'leaf=/two']):
                retain.reset_mock(); build.reset_mock()
                command = ['candidate', 'build', 'gnu-hello']
                for flag in flags: command.extend(['--reuse-proof', flag])
                with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(command), 2)
                retain.assert_not_called(); build.assert_not_called()
            row['products'] = ['realization', 'selection']
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['candidate', 'build', 'gnu-hello', '--reuse-proof', 'leaf=/retained']), 2)
            retain.assert_not_called(); build.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()), patch(
                'spaghetti_extractor.operator.experimental.build_candidate_experiment') as experimental:
            self.assertEqual(main(['candidate', 'build', 'gnu-hello', '--reuse-proof', 'leaf=/retained',
                                  '--experimental-comparison', '/comparison']), 2)
            experimental.assert_not_called()

    def test_candidate_test_without_declared_suites_is_a_usage_error(self) -> None:
        index = {
            "defaultConfiguration": "default",
            "candidate": {"configurations": {"default": {}}, "testSuites": {}},
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
                "configurations": {
                    "default": {"mode": "hybrid"},
                    "minimal": {"mode": "portable"},
                },
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
        report = _operator_status("configuration:gnu-hello:minimal")
        index = {
            "defaultConfiguration": "default",
            "candidate": {
                "configurations": {
                    "default": {"mode": "hybrid"},
                    "minimal": {"mode": "portable"},
                },
            },
        }
        output = io.StringIO()
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_artifact",
            return_value=(Path("/tmp/selection"), {"ready_for_realization": True}),
        ) as realize, contextlib.redirect_stdout(output):
            with patch(
                "spaghetti_extractor.commands.workflows.project_candidate_selection",
                return_value=({
                    **report,
                    "provider_coverage": {
                        "portable_progress": "partial",
                        "fallback_free": False,
                        "definitions": {
                            "selected": 3,
                            "by_kind": {
                                "qualified_portable_c": 1,
                                "generated_behavioral_c": 2,
                                "external_environment": 0,
                                "qualified_runtime": 0,
                                "pinned_binary": 0,
                            },
                        },
                    },
                }, []),
            ):
                self.assertEqual(
                    main([
                        "candidate", "status", "gnu-hello",
                        "--configuration", "minimal",
                    ]),
                    0,
                )
        self.assertEqual(
            realize.call_args.args[1],
            'candidate.configurations."minimal".selection',
        )
        self.assertEqual(realize.call_args.args[2], "implementation-selection.json")
        self.assertIn("realization-ready=true", output.getvalue())
        self.assertIn("exact-selection=complete", output.getvalue())
        self.assertIn("portable-progress=partial", output.getvalue())
        self.assertIn("fallback-free=false", output.getvalue())
        self.assertIn("portable-c=1", output.getvalue())
        self.assertIn("generated-c=2", output.getvalue())

    def test_candidate_status_uses_the_indexed_default_selection(self) -> None:
        report = _operator_status("configuration:gnu-hello:default")
        index = {
            "defaultConfiguration": "default",
            "candidate": {"configurations": {"default": {"mode": "hybrid"}}},
        }
        with patch(
            "spaghetti_extractor.commands.workflows._operator_index",
            return_value=index,
        ), patch(
            "spaghetti_extractor.commands.workflows._realize_artifact",
            return_value=(Path("/tmp/selection"), {"ready_for_realization": True}),
        ) as realize, contextlib.redirect_stdout(io.StringIO()):
            with patch(
                "spaghetti_extractor.commands.workflows.project_candidate_selection",
                return_value=(report, []),
            ):
                self.assertEqual(main(["candidate", "status", "gnu-hello"]), 0)
        self.assertEqual(
            realize.call_args.args[1],
            'candidate.configurations."default".selection',
        )
