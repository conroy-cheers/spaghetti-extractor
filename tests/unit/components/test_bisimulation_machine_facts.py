"""Current machine cut facts must be proved, transported early, and rechecked after writes."""

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components.bisimulation import BisimulationSyncV1
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_harness import memory_projection_readers, _validate_static_slot_rvas
from spaghetti_extractor.components.bisimulation_projection import (
    incoming_machine_relations, machine_fact_metadata, validate_machine_fact_model,
)
from spaghetti_extractor.components.bisimulation_refinement import _required_assertion_descriptions
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.inductive_relation import CutpointDerivedRelationV1, _parse_relation_expression
from tests.unit.components import test_bisimulation_allocation_cuts as checks
from tests.unit.components.test_bisimulation_cutpoints import _cut_intent

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq", "profiles/pe32-kernel32-runtime-v1.json")}


def fact():
    return {"id": "target", "projection": {"kind": "register", "register": "ebx", "width": 32, "at": "entry"},
        "expression": {"op": "exact_projection", "projection": {"kind": "static_slot", "rva": 128, "width": 32, "at": "entry"}}}


def operation(derived=None):
    authored = _cut_intent().operations[0]
    return replace(authored, syncs=(BisimulationSyncV1.parse(
        {**authored.syncs[0].to_payload(), "derived": [fact() if derived is None else derived]}, "machine fact cut"),))


class MachineFactTests(unittest.TestCase):
    def test_projection_is_typed_current_and_not_a_source_expression(self):
        row = fact()
        self.assertEqual(CutpointDerivedRelationV1.parse(row, "fact").to_payload(), row)
        with self.assertRaises(ValueError):
            _parse_relation_expression(row["expression"], "source expression")
        for change in ({"width": 16}, {"at": "return"}, {"kind": "constant", "value": 3, "width": 32},
                       {"kind": "register", "register": "eip", "width": 32, "at": "entry"}):
            changed = copy.deepcopy(row)
            if "kind" in change:
                changed["expression"]["projection"] = change
            else:
                changed["expression"]["projection"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                CutpointDerivedRelationV1.parse(changed, "bad fact")
        with self.assertRaisesRegex(ValueError, "outside the proof image"):
            _validate_static_slot_rvas(operation().to_payload(), image_size=130)

    def check_barrier(self, *, write=False, reload=False, stack=False, constant=False, omit_incoming=False):
        row = fact()
        if constant:
            row['expression'] = {'op': 'const', 'value': 17, 'width': 32}
        if stack:
            row['expression']['projection'] = {'kind': 'stack', 'offset': 8, 'width': 32, 'at': 'entry'}
        authored = operation(row)
        world = _world_source(max_writes=2, max_private_writes=2, max_calls=1,
            max_atomics=1, max_shadow_bytes=1, max_nul_views=1, service_bindings=[], private_ranges=())
        source = world + '\n' + '\n'.join(memory_projection_readers(stack_facts=stack)) + '\n' + _render_proof_header(
            authored=authored, image_base=0x400000, unit_rvas={authored.syncs[0].exact_unit_id: 0x1010})
        source += '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_world_calls_equal(void) {return 1U;}
uint32_t spx_proof_world_atomics_equal(void) {return 1U;}
uint32_t spx_proof_world_connected_calls_equal(void) {return 1U;}
void spx_bisimulation_relation_witness(void) {}
void main(void) {
  uint32_t fault=0U, n=42U;
  spx_machine_state initial_state={0}; initial_state.ebx=17U; initial_state.esp=8388608U;
  spx_proof_reset_worlds(8388608U,256U);
'''
        if constant:
            source += '  __CPROVER_havoc_object(&initial_state.ebx);\n'
        if not omit_incoming:
            source += '\n'.join(incoming_machine_relations(authored.syncs[0], state="initial_state"))
        source += '''
  __CPROVER_assert(initial_state.ebx==spx_proof_exact_read(0,0x400080U,4U,&fault),
      "original execution receives the admitted current target");
  spx_proof_exact_input=initial_state;spx_proof_exact_output=initial_state;
  spx_proof_exact_output.edx=n;
  spx_proof_exact_result=(spx_step_result){SPX_BRANCH,0x1010U,0U};
'''
        if constant:
            source = source.replace('initial_state.ebx==spx_proof_exact_read(0,0x400080U,4U,&fault)',
                                    'initial_state.ebx==17U')
        if write and constant:
            source += '  spx_proof_exact_output.ebx=18U;\n'
        elif write:
            source += '''
  uint32_t alias=0x40007fU;
  spx_proof_write_world(&spx_exact_world,alias+1U,1U,18U,&fault);
  spx_proof_write_world(&spx_source_world,alias+1U,1U,18U,&fault);
'''
        if reload:
            source += '  spx_proof_exact_output.ebx=spx_proof_exact_read(0,0x400080U,4U,&fault);\n'
        source += '  SPX_PROOF_BEGIN(run);\n  SPX_PROOF_SYNC(cut,1,n);\n}\n'
        if stack:
            source = source.replace('0x400080U', '(initial_state.esp+8U)').replace('0x40007fU', '(initial_state.esp+7U)')
        return checks.AllocationCutTests().check(source)

    def test_checked_register_literal_is_available_before_exact_execution(self):
        for write, omitted, expected in ((False, False, 'satisfied'), (False, True, 'violated'),
                                        (True, False, 'violated')):
            with self.subTest(write=write, omitted=omitted):
                result = self.check_barrier(constant=True, write=write, omit_incoming=omitted)
                self.assertEqual(result['status'], expected, result.get('detail'))
                if omitted:
                    self.assertEqual(result['detail'], 'original execution receives the admitted current target')
                elif write:
                    self.assertEqual(result['detail'], 'spx-bisimulation-derived:cut:target')

    def test_stack_fact_uses_current_bytes_and_rejects_alias_mutation(self):
        for write, reload, expected in ((False, False, 'satisfied'), (True, False, 'violated'), (True, True, 'satisfied')):
            with self.subTest(write=write, reload=reload):
                result = self.check_barrier(write=write, reload=reload, stack=True)
                self.assertEqual(result['status'], expected, result.get('detail'))
                if expected == 'violated':
                    self.assertEqual(result['detail'], 'spx-bisimulation-derived:cut:target')

    def test_stack_fact_checks_address_before_wrapping_or_reading(self):
        world = _world_source(max_writes=1, max_private_writes=1, max_calls=1,
            max_atomics=1, max_shadow_bytes=1, max_nul_views=1, service_bindings=[], private_ranges=())
        source = world + '\n' + '\n'.join(memory_projection_readers(stack_facts=True))
        for direction in ('input', 'output'):
            for stack, offset, width, expected in ((0, -1, 1, 'violated'),
                    (4294967295, 1, 1, 'violated'), (4294967295, 0, 2, 'violated'),
                    (4294967295, 0, 1, 'satisfied'), (8388608, -4, 4, 'satisfied')):
                with self.subTest(direction=direction, stack=stack, offset=offset, width=width):
                    body = source + f'''\nvoid main(void) {{
  spx_proof_reset_worlds(8388608U,256U);
  (void)spx_proof_exact_{direction}_stack_read(UINT32_C({stack}),INT64_C({offset}),UINT32_C({width}));
}}\n'''
                    result = checks.AllocationCutTests().check(body)
                    self.assertEqual(result['status'], expected, result.get('detail'))
                    if expected == 'violated':
                        self.assertEqual(result['detail'], f'spx-bisimulation-exact-{direction}-stack-range')

    def test_stack_facts_require_both_readers_and_new_policy(self):
        row = fact()
        row['projection'] = {'kind': 'stack', 'offset': 0, 'width': 32, 'at': 'entry'}
        row['expression']['projection'] = {'kind': 'stack', 'offset': 36, 'width': 32, 'at': 'entry'}
        authored = operation(row)
        planned = {'operation_id': 'run', 'source': {'syncs': [authored.syncs[0].to_payload()]},
            'exact': {'control_edges': [{'source_unit_id': 'entry', 'target_unit_id': authored.syncs[0].exact_unit_id}]}}
        metadata = machine_fact_metadata(authored)
        required = _required_assertion_descriptions(authored=authored, proof_function='check',
            active_start_sync_id='cut', next_sync_ids={'cut'}, logical_projection={'results': [], 'state': []},
            continuous_acyclic=False, typed_call_positions=())
        model = {**metadata, 'obligation_id': 'sync:cut', 'selected_unit_ids': ['entry'],
                 'required_assertion_descriptions': required}
        validate_machine_fact_model(planned, model)
        document = {'proof_plan': {'operations': [planned]}, 'proof': {'models': {'operation_models': [{
            **metadata, 'operation_id': 'run', 'machine_image': {'image_size': 256}, 'obligation_models': [model]}]}}}
        program = (Path(__file__).parents[3] / TESTKIT['resources'][0]).read_text()
        mutations = ['none', 'policy', 'offset'] + [f'spx-bisimulation-exact-{direction}-{kind}'
            for direction in ('input', 'output') for kind in ('read', 'stack-range')]
        mutations += ['spx-bisimulation-derived:cut:target']
        for mutation in mutations:
            value = copy.deepcopy(document)
            plan = value['proof_plan']['operations'][0]
            segment = value['proof']['models']['operation_models'][0]['obligation_models'][0]
            if mutation == 'policy':
                segment['machine_fact_policy'] = 'checked-current-machine-cut-facts-v1'
            elif mutation == 'offset':
                plan['source']['syncs'][0]['derived'][0]['projection']['offset'] = -4097
            elif mutation != 'none':
                segment['required_assertion_descriptions'].remove(mutation)
            if mutation != 'none':
                with self.subTest(reader='python', mutation=mutation), self.assertRaises(ValueError):
                    validate_machine_fact_model(plan, segment)
            result = run_jq_reader([shutil.which('jq'), '-e', program+'\nspx_cut_capture_codecs'],
                input=json.dumps(value), text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0 if mutation == 'none' else 1, (mutation, result.stderr))

    def test_current_slot_fact_rejects_alias_mutation_and_accepts_reloaded_target(self):
        for write, reload, expected in ((False, False, "satisfied"), (True, False, "violated"), (True, True, "satisfied")):
            with self.subTest(write=write, reload=reload):
                result = self.check_barrier(write=write, reload=reload)
                self.assertEqual(result["status"], expected, result.get("detail"))
                if expected == "violated":
                    self.assertEqual(result["detail"], "spx-bisimulation-derived:cut:target")

    def test_models_and_independent_reader_require_policy_fact_and_read_checks(self):
        authored = operation()
        planned = {"operation_id": "run", "source": {"syncs": [authored.syncs[0].to_payload()]},
            "exact": {"control_edges": [{"source_unit_id": "entry", "target_unit_id": authored.syncs[0].exact_unit_id}]}}
        metadata = machine_fact_metadata(authored)
        validate_machine_fact_model(planned, metadata)
        with self.assertRaises(ValueError):
            validate_machine_fact_model(planned, {})
        with self.assertRaises(ValueError):
            validate_machine_fact_model(planned, {**metadata, "machine_image": {"image_size": 130}})
        required = _required_assertion_descriptions(authored=authored, proof_function="check",
            active_start_sync_id="cut", next_sync_ids={"cut"}, logical_projection={"results": [], "state": []},
            continuous_acyclic=False, typed_call_positions=())
        for name in ("spx-bisimulation-derived:cut:target", "spx-bisimulation-exact-input-read", "spx-bisimulation-exact-output-read"):
            self.assertIn(name, required)
        model = {**metadata, "obligation_id": "sync:cut", "selected_unit_ids": ["entry"],
                 "required_assertion_descriptions": required}
        document = {"proof_plan": {"operations": [planned]}, "proof": {"models": {"operation_models": [{
            **metadata, "operation_id": "run", "machine_image": {"image_size": 256}, "obligation_models": [model]}]}}}
        program = (Path(__file__).parents[3] / TESTKIT["resources"][0]).read_text()
        for mutation in ("none", "policy", "fact", "input-read", "output-read", "image-bounds"):
            value = copy.deepcopy(document)
            op = value["proof"]["models"]["operation_models"][0]
            segment = op["obligation_models"][0]
            if mutation == "policy":
                del segment["machine_fact_policy"]
            elif mutation == "image-bounds":
                op["machine_image"]["image_size"] = 130
            elif mutation != "none":
                name = "spx-bisimulation-derived:cut:target" if mutation == "fact" else "spx-bisimulation-exact-" + mutation
                segment["required_assertion_descriptions"].remove(name)
            result = run_jq_reader([shutil.which("jq"), "-e", program + "\nspx_cut_capture_codecs"],
                input=json.dumps(value), text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0 if mutation == "none" else 1, (mutation, result.stderr))
