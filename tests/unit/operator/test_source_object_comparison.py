"""Actual Hello machine code with caller-owned storage, through source checking."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_object_machine_model import render_object_machine_model
from spaghetti_extractor.components.bisimulation_readonly_model import mutable_checker_options
from spaghetti_extractor.components.bisimulation_shared_original_check import (
    OBJECT_POLICY, checked_object_original_transition, checked_shared_original_transition,
)
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from tests.unit.components.test_object_source_contracts import FIXTURE, SYMBOLS, bundle


TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": ("tests/fixtures/hello-quoting-state",)}


def read(path):
    return json.loads(path.read_text())


def check(root, source):
    (root/"interface").mkdir(parents=True)
    shutil.copyfile(FIXTURE/"component-interface-intent-v1.json", root/"interface/component-interface-intent-v1.json")
    (root/"quoting.c").write_text(source)
    build_component_source_package(lift_unit_id="quoting-style", files={"quoting.c": root/"quoting.c"},
        shared_inputs={}, operation_symbols=SYMBOLS, out_dir=root/"source")
    return write_component_source_check(target_id="gnu-hello", component_id="quoting-style",
        interface_package=root/"interface", source_package=root/"source", out=root/"feedback",
        host_compiler=Path(shutil.which("cc")), pe32_compiler=Path(shutil.which("cc")),
        cbmc=Path(shutil.which("cbmc")), contract_workspace=root/"contracts", contract_timeout_seconds=60,
        original_comparison={"exact_c_slice": FIXTURE/"character-exact",
            "binding_intent": read(FIXTURE/"character-binding.json"),
            "machine_domain": read(FIXTURE/"character-domain.json")})


class SourceObjectComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.source = (FIXTURE/"quoting-style.c").read_text()
        cls.status = check(cls.root/"baseline", cls.source)
        cls.output = cls.root/"baseline/feedback"
        if cls.status["status"] != "complete":
            raise AssertionError((cls.output/"source-check-details.json").read_text())
        cls.certificate = read(cls.output/"local-contract.json")
        cls.result = read(cls.output/"original-comparison/result.json")

    def validate(self, result=None):
        return checked_object_original_transition(self.result if result is None else result,
            artifacts=self.output/"original-comparison", certificate=self.certificate,
            source_artifacts=self.output/"local-contract-models")

    def test_public_result_is_bound_to_the_complete_original_and_stays_conditional(self):
        from spaghetti_extractor.components.bisimulation_object_call import checked_object_call_supplier
        self.assertEqual(self.result["policy"], OBJECT_POLICY)
        self.assertFalse(self.result["authorizing"])
        self.assertFalse(self.result["activation_authorized"])
        self.assertEqual(self.result["runtime_compatibility"], "unverified")
        self.assertEqual(self.certificate["status"], "satisfied")
        exact = self.result["bindings"]["exact_c_slice"]
        self.assertEqual(exact["root_unit_ids"], exact["root_context_unit_ids"])
        self.assertEqual(len(exact["root_unit_ids"]), 7)
        with patch("subprocess.run", side_effect=AssertionError("validation must not compile or solve")):
            transition = self.validate()
            supplier = checked_object_call_supplier(self.output)
        self.assertEqual(transition["operation_id"], "set_character")
        self.assertEqual(supplier['transition'], transition)
        self.assertFalse(supplier['activation_authorized'])
        self.assertEqual(supplier['contract']['entry_rva'], 0x50e1)
        self.assertEqual(supplier['contract']['arguments'][0], {
            'id': 'options', 'interpretation': 'view', 'minimum_extent': 40,
            'nullable': True, 'permissions': 3, 'entry_stack_offset': 4})
        self.assertEqual(supplier['contract']['private_writes'], [[-4, 4]])
        self.assertEqual(supplier['contract']['shared_views'], {
            'defaults': {'address': 0x4301c0, 'extent': 40, 'permissions': 3}})
        self.assertEqual(supplier['contract_sha256'], canonical_sha256_v3(supplier['contract']))
        feedback = read(self.output/"compiler-checks.json")["local_contract"]
        self.assertFalse(feedback["qualified_connected_summary"])
        self.assertEqual(feedback["original_comparison"]["transition_domain_sha256"], transition["domain_sha256"])
        with self.assertRaises(ValueError):
            checked_shared_original_transition(self.result, artifacts=self.output/"original-comparison",
                certificate=self.certificate, source_artifacts=self.output/"local-contract-models")

    def test_public_caller_consumes_current_object_facts_and_detects_missing_frame_guarantees(self):
        from spaghetti_extractor.operator.source_operation_call_check import checked_caller_supplier
        with patch('subprocess.run',side_effect=AssertionError('supplier validation must not compile or solve')):
            facts,summary=checked_caller_supplier(self.output,['ebx','edi','esi'])
            _,missing=checked_caller_supplier(self.output,['ecx'])
        self.assertEqual(facts['original_entry_rva'],0x50e1)
        self.assertEqual(summary['consumer_requirements']['status'],'compatible')
        self.assertEqual(facts['normal_return']['preserved_fields'],['ebx','edi','esi'])
        self.assertEqual(missing['consumer_requirements']['status'],'requires-recheck')
        self.assertEqual(missing['consumer_requirements']['missing_guarantees'],['state.ecx==initial.ecx'])
        self.assertEqual(facts['original_transfer_plan_sha256'],
            self.result['bindings']['exact_c_slice']['bindings']['executable_transfer_plan_sha256'])

    def test_changed_model_or_omitted_properties_cannot_retain_the_transition(self):
        changed = copy.deepcopy(self.result)
        changed["checks"][0]["property_ids"].pop()
        changed["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in changed.items() if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "successful properties"):
            self.validate(changed)
        path = self.output/"original-comparison/pair.c"
        original = path.read_bytes()
        try:
            path.write_text(path.read_text().replace("spx-object-machine-register-frame", "omitted-frame"))
            with self.assertRaisesRegex(ValueError, "model meaning"):
                self.validate()
        finally:
            path.write_bytes(original)

    def test_a_wrong_result_passes_source_frames_but_fails_original_equivalence(self):
        root = self.root/"wrong"
        status = check(root, self.source.replace("return old;", "return old ^ 1U;"))
        self.assertEqual(read(root/"feedback/local-contract.json")["status"], "satisfied")
        result = read(root/"feedback/original-comparison/result.json")
        self.assertEqual(status["status"], "violated", result)
        self.assertTrue(any(row.get("detail") == "spx-object-result-equivalence" for row in result["checks"]))

    def test_null_caller_stack_and_last_address_byte_are_admitted(self):
        root = self.root/"witness"
        shutil.copytree(self.output/"original-comparison", root)
        path = root/"pair.c"
        source = path.read_text()
        marker = "  spx_runtime rt={.context=&m,"
        self.assertEqual(source.count(marker), 1)
        source = source.replace(marker, '''
  __CPROVER_assert(env->inputs[1].reference.object!=0U,"null-input-admitted");
  __CPROVER_assert(!(env->inputs[1].reference.object!=0U &&
      env->inputs[1].address==initial.esp+20U && env->inputs[1].extent==48U),"caller-stack-input-admitted");
  __CPROVER_assert(initial.esp!=UINT32_MAX-15U,"last-stack-byte-admitted");
''' + marker)
        path.write_text(source)
        compile_command = self.result["commands"][0]["command"]
        compiled = subprocess.run(compile_command, cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        entry = self.result["models"]["entry"]
        # These explicit counterexamples witness the conditional domain.
        # The unmodified model above separately checks every safety property.
        command = [shutil.which("cbmc"), "model.goto", "--function", entry, *mutable_checker_options(16),
                   "--property", "spx_object_original.assertion.1", "--property", "spx_object_original.assertion.2",
                   "--property", "spx_object_original.assertion.3"]
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 10, result.stderr+result.stdout[-1000:])
        rows = [row for block in json.loads(result.stdout) for row in block.get("result", [])]
        self.assertEqual({row["description"] for row in rows if row["status"] == "FAILURE"},
                         {"null-input-admitted", "caller-stack-input-admitted", "last-stack-byte-admitted"})

    def test_frame_edits_cannot_hide_overlapping_arguments_or_arbitrary_results(self):
        inputs = {"bundle": bundle(), "operation_id": "set_character", "symbol": SYMBOLS["set_character"],
                  "binding_intent": read(FIXTURE/"character-binding.json"),
                  "machine_domain": read(FIXTURE/"character-domain.json")}
        for field, value in (("private_writes", [{"offset": 0, "bytes": 4}]),
                             ("clobbers", ["eax"]), ("stack_delta", 0)):
            changed = copy.deepcopy(inputs["machine_domain"])
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                render_object_machine_model(**{**inputs, "machine_domain": changed})
