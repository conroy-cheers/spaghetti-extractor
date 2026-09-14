"""The existing source-check workflow exposes local proofs without authority."""
from __future__ import annotations

import contextlib
import io
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from tests.unit.components.test_bisimulation_readonly_model import COMPARISON, fixed_readonly_bundle
from tests.unit.components.test_bisimulation_mutable_model import COPY, mutable_bundle
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_mutable_source_contracts
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_services_v5 import _c_identifier
from spaghetti_extractor.components.bisimulation_source_contract_reuse import consumed_memory_contract


TESTKIT = {"fixtures": ("cbmc", "compiler"), "commands": ("component check",),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",
                         "tests/fixtures/hand-defined-boundaries/resource-text",
                         "profiles/pe32-user32-resource-text-runtime-v1.json")}


class SourceLocalContractTests(unittest.TestCase):
    def check(self, root, body, *, bundle=None, unwind=16, component_id="memory-regions-equal", dependencies=()):
        if not all(shutil.which(tool) for tool in ("cc", "cbmc", "goto-cc", "goto-instrument")):
            self.skipTest("source and proof compilers are unavailable")
        interface = root / "interface"
        interface.mkdir()
        bundle = fixed_readonly_bundle() if bundle is None else bundle
        if bundle.intent.component_id != component_id:
            intent = bundle.intent
            bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.create(
                component_id=component_id, schema=intent.schema, state=intent.state, operations=intent.operations,
                effects=intent.effects, services=intent.services, protocol_states=intent.protocol_states,
                initial_protocol_state=intent.initial_protocol_state))
        (interface / "component-interface-intent-v1.json").write_text(json.dumps(bundle.intent.to_payload()))
        source = root / "authored.c"
        source.write_text('#include "portable-component-implementation.h"\n' + f'''
uint8_t regions_equal(spx_{_c_identifier(component_id)}_context_v5 *context,
 const spx_view_v5 *left, const spx_view_v5 *right, uint32_t count) {{
''' + body + '\n}\n')
        build_component_source_package(lift_unit_id=component_id, files={"authored.c": source},
            shared_inputs={}, operation_symbols={"compare": "regions_equal"}, out_dir=root / "source")
        return write_component_source_check(target_id="fixture", component_id=component_id,
            interface_package=interface, source_package=root / "source",
            host_compiler=Path(shutil.which("cc")), pe32_compiler=Path(shutil.which("cc")),
            cbmc=Path(shutil.which("cbmc")), out=root / "feedback", contract_workspace=root / "workspace",
            contract_unwind=unwind,
            local_contract_dependencies=[{"package":path,"operation_id":"compare"} for _,path in dependencies])

    def test_public_dependency_product_reports_bound_contracts_without_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            leaf, parent = root/'leaf', root/'parent'
            leaf.mkdir()
            parent.mkdir()
            bundle = mutable_bundle(extents=(1,1))
            self.assertEqual(self.check(leaf,COPY,bundle=bundle,component_id='leaf')['status'],'complete')
            status = self.check(parent,
                'return spx_component_logical_leaf_compare(context->services->context,left,right,count);',
                bundle=bundle,component_id='parent',dependencies=[('leaf',leaf/'feedback')])
            self.assertEqual(status['status'],'complete')
            local = json.loads((parent/'feedback/local-contract.json').read_text())
            validate_mutable_source_contracts(local,artifacts=parent/'feedback/local-contract-models')
            output=io.StringIO()
            with patch('spaghetti_extractor.commands.workflows._operator_index',return_value={
                    'components':{'units':{'parent':{'products':['sourceContractCheck']}}}}), patch(
                    'spaghetti_extractor.commands.workflows._realize_artifact',return_value=(parent/'feedback/source-check.json',status)), contextlib.redirect_stdout(output):
                result=main(['component','check','fixture','parent','--source','--local-contracts','--json'])
            self.assertEqual(result,0,output.getvalue())
            feedback=json.loads(output.getvalue())['local_contract']
            self.assertFalse(feedback['authorizing'])
            self.assertFalse(feedback['qualified_connected_summary'])
            self.assertEqual(feedback['dependencies'][0]['source_contract_sha256'],
                             local['summary_dependencies'][0]['certificate']['receipt_sha256'])
            self.assertEqual(feedback['dependencies'][0]['component_id'],'leaf')
            self.assertEqual(feedback['dependencies'][0]['consumed_contract_sha256'],
                             canonical_sha256_v3(consumed_memory_contract(local['summary_dependencies'][0])))

    def test_public_flag_selects_local_product_with_no_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = self.check(root, COMPARISON)
            self.assertEqual(status["status"], "complete")
            self.assertEqual(status["counts"]["authority_held"], 0)
            output = io.StringIO()
            with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                "components": {"units": {"memory-regions-equal": {"products": ["sourceCheck", "sourceContractCheck"]}}}}), patch(
                "spaghetti_extractor.commands.workflows._realize_artifact", return_value=(root / "feedback/source-check.json", status)
            ) as realize, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = main(["component", "check", "fixture", "memory-regions-equal", "--source", "--local-contracts", "--json"])
            self.assertEqual(result, 0, output.getvalue())
            self.assertEqual(realize.call_args.args[1], 'components.units."memory-regions-equal".sourceContractCheck')
            self.assertEqual(json.loads(output.getvalue())["status"]["subjects"][0]["authority"], "not-applicable")
            local = json.loads((root / "feedback/local-contract.json").read_text())
            self.assertEqual(local["status"], "satisfied")
            self.assertIs(local["authorizing"], False)
            for model in local["models"]:
                name = model["operation_id"] + "-" + model["kind"]
                for field, suffix in (("raw_goto_sha256", ".goto"),
                                      ("checked_goto_sha256", "-checked.goto" if model["kind"] == "frame" else ".goto")):
                    copied = root / "feedback/local-contract-models" / (name + suffix)
                    self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(), model[field])
            self.assertFalse((root / "feedback/object-manifest.json").exists())

    def test_restored_view_write_is_visible_as_a_local_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = self.check(root, '(void)context; (void)right; (void)count; '
                'spx_view_v5 *w=(spx_view_v5 *)left; w->extent ^= 1U; w->extent ^= 1U; return 0;')
            self.assertEqual(status["status"], "violated")
            details = json.loads((root / "feedback/source-check-details.json").read_text())
            self.assertTrue(any(row["family"] == "source-local-contract" and row["status"] == "violated"
                                and "compare/frame" in row["diagnostic"] and "assignable" in row["diagnostic"]
                                for row in details["blockers"]), details)
            output = io.StringIO()
            with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                    "components": {"units": {"memory-regions-equal": {"products": ["sourceContractCheck"]}}}}), patch(
                    "spaghetti_extractor.commands.workflows._realize_artifact", return_value=(root / "feedback/source-check.json", status)
                    ), contextlib.redirect_stdout(output):
                code = main(["component", "check", "fixture", "memory-regions-equal", "--source", "--local-contracts", "--json"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["status"]["status"], "violated")
            self.assertEqual(status["counts"]["authority_held"], 0)

    def test_mutable_local_product_checks_retained_output_without_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = self.check(root, COPY, bundle=mutable_bundle(), unwind=10)
            self.assertEqual(status["status"], "complete")
            self.assertEqual(status["counts"]["authority_held"], 0)
            local = json.loads((root / "feedback/local-contract.json").read_text())
            self.assertEqual(local["checker_options"][8], "10")
            validate_mutable_source_contracts(local, artifacts=root / "feedback/local-contract-models")
            self.assertFalse((root / "feedback/object-manifest.json").exists())

    def test_local_flag_cannot_be_confused_with_provider_qualification(self):
        output = io.StringIO()
        with patch("spaghetti_extractor.commands.workflows._component_selection") as select, contextlib.redirect_stderr(output):
            result = main(["component", "check", "fixture", "unit", "--local-contracts"])
        self.assertEqual(result, 2)
        self.assertIn("requires --source", output.getvalue())
        select.assert_not_called()

    def test_selected_service_dependencies_are_visible_in_the_public_local_check(self):
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
        from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
        from tests.unit.components.test_shared_source_contracts import small_bundle, FIXTURE
        from tests.unit.components.test_shared_service_premises import binding

        if not all(shutil.which(tool) for tool in ("cc", "cbmc", "goto-cc", "goto-instrument")):
            self.skipTest("source and proof compilers are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = small_bundle()
            interface = root / "interface"
            interface.mkdir()
            (interface / "component-interface-intent-v1.json").write_text(json.dumps(bundle.intent.to_payload()))
            authored = root / "resource-text.c"
            authored.write_text((FIXTURE / "resource-text.c").read_text().replace("500U", "8U"))
            build_component_source_package(lift_unit_id="resource-text", files={"resource-text.c": authored},
                shared_inputs={}, operation_symbols={"get": "resource_text"}, out_dir=root / "source")
            selected = binding()
            status = write_component_source_check(target_id="fixture", component_id="resource-text",
                interface_package=interface, source_package=root / "source",
                host_compiler=Path(shutil.which("cc")), pe32_compiler=Path(shutil.which("cc")),
                cbmc=Path(shutil.which("cbmc")), out=root / "feedback", contract_workspace=root / "workspace",
                shared_contract={"relation_intent": json.loads((FIXTURE / "relation.json").read_text()),
                                 "maximum_calls": 1, "maximum_memory_events": 1},
                shared_service_bindings=[selected])
            self.assertEqual(status["status"], "complete")
            for json_output in (True, False):
                output = io.StringIO()
                with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                        "components": {"units": {"resource-text": {"products": ["sourceContractCheck"]}}}}), patch(
                        "spaghetti_extractor.commands.workflows._realize_artifact", return_value=(root / "feedback/source-check.json", status)
                        ), contextlib.redirect_stdout(output):
                    code = main(["component", "check", "fixture", "resource-text", "--source", "--local-contracts",
                                 *(["--json"] if json_output else [])])
                self.assertEqual(code, 0, output.getvalue())
                if json_output:
                    local = json.loads(output.getvalue())["local_contract"]
                    self.assertFalse(local["authorizing"])
                    self.assertFalse(local["qualified_connected_summary"])
                    effect = normalize_shared_service_bindings(bundle, [selected])[0]["external_effect_contract"]
                    self.assertEqual(local["service_dependencies"], [{
                        "service_id": "load_string", "external_contract_identity_sha256": selected["external_contract_identity_sha256"],
                        "abi_sha256": selected["abi_sha256"], "effect_contract_sha256": canonical_sha256_v3(effect)}])
                else:
                    self.assertIn("selected service contract: load_string", output.getvalue())
                    self.assertIn(selected["external_contract_identity_sha256"], output.getvalue())
