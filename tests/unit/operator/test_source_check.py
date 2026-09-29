"""A blocked component gets real source feedback without gaining qualification."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from tests.unit.cli.test_component_review import review_fixture

TESTKIT = {"commands": ("component check",)}


class ComponentSourceCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host compiler unavailable")
        self.compiler = Path(compiler)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        review_fixture(self.root)
        self.interface = self.root / "interface"
        self.interface.mkdir()
        shutil.copyfile(self.root / "interface.json", self.interface / "component-interface-intent-v1.json")
        self.source = self.root / "source"
        self.output = self.root / "feedback"
        self.valid = ('#include "portable-component-implementation.h"\n'
                      'void authored_run(spx_leaf_context_v5 *context) { (void)context; }\n')
        self._source(self.valid)

    def _source(self, text: str) -> None:
        path = self.root / "authored.c"
        path.write_text(text)
        build_component_source_package(lift_unit_id="leaf", files={"components/leaf.c": path},
            shared_inputs={}, operation_symbols={"run": "authored_run"}, out_dir=self.source)

    def _check(self) -> dict:
        # Both slots use the provisioned host compiler here. The public Nix
        # phase additionally exercises its pinned PE32 cross compiler.
        return write_component_source_check(target_id="fixture", component_id="leaf",
            interface_package=self.interface, source_package=self.source,
            host_compiler=self.compiler, pe32_compiler=self.compiler, out=self.output)

    def _public(self, *flags: str) -> tuple[int, str]:
        output = io.StringIO()
        with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                "components": {"units": {"leaf": {"products": ["sourceCheck"]}}}}), patch(
                "spaghetti_extractor.commands.workflows._realize_artifact", return_value=(
                    self.output / "source-check.json", json.loads((self.output / "source-check.json").read_text()))
                ) as realize, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = main(["component", "check", "fixture", "leaf", *flags])
            if "--source" in flags:
                self.assertEqual(realize.call_args.args[1], 'components.units."leaf".sourceCheck')
            else:
                realize.assert_not_called()
        return result, output.getvalue()

    def test_valid_source_is_non_authorizing_and_default_check_still_fails(self) -> None:
        result = self._check()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["counts"]["authority_held"], 0)
        code, text = self._public("--source", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["status"]["scope"], "component-source")
        code, text = self._public()
        self.assertEqual(code, 2)
        self.assertIn("no provider qualification product", text)
        self.assertFalse((self.output / "object-manifest.json").exists())
        self.assertEqual(list(self.output.rglob("*.o")), [])

    def test_interface_workspace_checks_current_c_before_driver_preparation(self) -> None:
        authored=self.root/'interface-authoring'
        source=self.root/'authoring.c';source.write_text(self.valid)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['component','start','unregistered','leaf','--interface-intent',str(self.root/'interface.json'),
                '--operation-symbol','run=authored_run','--source-file','source/component.c='+str(source),
                '--output',str(authored)]),0)
        self.assertIn('--authoring-workspace',(authored/'AUTHORING.md').read_text())
        (authored/'prepare.py').write_text('raise AssertionError("source review must not run the comparison recipe")\n')
        helper=authored/'source/helpers/state.h';helper.parent.mkdir()
        helper.write_text('static volatile unsigned scratch;\n')
        body=authored/'source/component.c'
        body.write_text('#include "helpers/state.h"\n'+self.valid.replace('(void)context;', '++scratch; (void)context;'))
        def check(*options):
            stdout=io.StringIO()
            # As in _check(), the unit fixture uses the host compiler in both
            # slots. The real authoring handoff exercises the PE32 toolchain.
            with patch('spaghetti_extractor.components.comparison_environment._executable',return_value=self.compiler), \
                    patch('spaghetti_extractor.commands.workflows._operator_index',side_effect=AssertionError('no target build')), \
                    contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stdout):
                code=main(['component','check','unregistered','leaf','--source','--authoring-workspace',str(authored),*options])
            return code,stdout.getvalue()
        retained=self.root/'early-feedback'
        code,text=check('--output',str(retained),'--json')
        self.assertEqual(code,2,text)
        report=json.loads(text)
        self.assertEqual(report['status']['status'],'incomplete')
        self.assertEqual(report['status']['counts']['authority_held'],0)
        feedback=json.loads((retained/'compiler-checks.json').read_text())
        self.assertTrue(all(row['status']=='checked' for row in feedback['checks']))
        issue=next(row for row in feedback['source_profile']['issues'] if row['code']=='restricted_c_volatile_storage')
        self.assertEqual(issue['source'],dict(path='helpers/state.h',line=1))
        saved=(retained/'inputs/source/sources/helpers/state.h').read_bytes()
        # Repair the profile issue, then diagnose an ordinary C error without
        # requiring an output folder or any original/runtime setup.
        helper.write_text('enum { SCRATCH = 0 };\n')
        body.write_text(self.valid+'\n#error early_authoring_failure\n')
        code,text=check()
        self.assertEqual(code,2,text);self.assertIn('early_authoring_failure',text)
        body.write_text(self.valid)
        # Source review regenerates declarations; it does not trust edited
        # editor headers or execute the unconfigured preparation recipe.
        (authored/'generated/portable-component-implementation.h').write_text('#error stale_editor_header\n')
        code,text=check()
        self.assertEqual(code,0,text);self.assertIn('host/PE32 compilation and C profile',text)
        self.assertIn('prepare an executable original/source comparison',text)
        self.assertEqual((retained/'inputs/source/sources/helpers/state.h').read_bytes(),saved)
        self.assertFalse((authored/'comparison-plan.json').exists())
        self.assertEqual(list(retained.rglob('*.o')),[])
        code,text=check('--local-contracts')
        self.assertEqual(code,2,text);self.assertIn('cannot select comparison cases',text)

    def test_compile_error_reports_authored_file_and_repair_clears_it(self) -> None:
        self._source(self.valid + "#error operator_seeded_error\n")
        self.assertEqual(self._check()["status"], "violated")
        code, text = self._public("--source")
        self.assertEqual(code, 2)
        self.assertIn("components/leaf.c:3", text)
        self.assertIn("operator_seeded_error", text)
        self._source(self.valid)
        self.assertEqual(self._check()["status"], "complete")
        self.assertEqual(self._public("--source")[0], 0)

    def test_formal_profile_error_is_separate_from_practical_compilation(self) -> None:
        self._source(self.valid.replace("(void)context;", "volatile int value = 0; (void)value; (void)context;"))
        self.assertEqual(self._check()["status"], "complete")
        code, text = self._public("--source")
        self.assertEqual(code, 0)
        self.assertIn("formal source eligibility: incomplete", text)
        feedback = json.loads((self.output / "compiler-checks.json").read_text())
        self.assertEqual(feedback['practical_profile']['status'], 'satisfied')
        issue = next(row for row in feedback['source_profile']['issues'] if row["code"] == "restricted_c_volatile_storage")
        self.assertEqual(issue["source"]["line"], 2)

    def test_stale_source_and_foreign_interface_reject_before_compilation(self) -> None:
        (self.source / "sources/components/leaf.c").write_text("changed")
        with self.assertRaisesRegex(ValueError, "stale"):
            self._check()
        self._source(self.valid)
        with self.assertRaisesRegex(ValueError, "another component"):
            write_component_source_check(target_id="fixture", component_id="other",
                interface_package=self.interface, source_package=self.source,
                host_compiler=self.root / "must-not-run", pe32_compiler=self.root / "must-not-run", out=self.output)

    def test_rebound_details_reject(self) -> None:
        self._check()
        path = self.output / "source-check-details.json"
        details = json.loads(path.read_text())
        details["source"]["sha256"] = "0" * 64
        path.write_text(json.dumps(details))
        code, text = self._public("--source")
        self.assertEqual(code, 2)
        self.assertIn("details are stale", text)

    def test_local_timeout_stays_incomplete_and_does_not_hide_a_counterexample(self) -> None:
        timeout = {"status": "incomplete", "code": "cbmc_timeout", "kind": "frame", "detail": "exceeded 30 seconds"}
        failure = {"status": "violated", "code": "cbmc_properties_violated", "kind": "input_dependence",
                   "operation_id": "run", "detail": "spx-local-input-dependence"}
        for rows, expected in (([timeout], "incomplete"), ([timeout, failure], "violated")):
            with self.subTest(expected=expected), patch(
                    "spaghetti_extractor.operator.source_check.check_readonly_source_contracts",
                    return_value={"status": "incomplete", "authorizing": False, "checks": rows}):
                result = write_component_source_check(target_id="fixture", component_id="leaf",
                    interface_package=self.interface, source_package=self.source,
                    host_compiler=self.compiler, pe32_compiler=self.compiler,
                    cbmc=self.compiler, out=self.output)
            self.assertEqual(result["status"], expected)
            self.assertEqual(result["counts"]["authority_held"], 0)
            details = json.loads((self.output / "source-check-details.json").read_text())
            self.assertTrue(any(row["status"] == "incomplete" and row["code"] == "cbmc_timeout"
                                for row in details["blockers"]))
