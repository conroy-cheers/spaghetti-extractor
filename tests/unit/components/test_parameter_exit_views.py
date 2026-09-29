"""Input references supply checked machine outputs without extra C results."""

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components.bisimulation import build_component_proof_plan_v1
from spaghetti_extractor.components.bisimulation_harness import _exit_comparisons
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.machine_binding import LogicalMachineValueV1, OperationMachineBindingV1
from spaghetti_extractor.components.machine_overlay_result_views import parameter_exit_projections, validate_parameter_exit_model
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.semantic_paths import build_operation_path_model
from spaghetti_extractor.components.semantic_path_induction import build_inductive_segment_models
from spaghetti_extractor.transfer.model import _Action, _Transfer
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_nullable_input_views import input_overlay, native_source
from tests.unit.components.test_bisimulation import _unit

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': ('nix/jq/strong-contextual-proof.jq',)}


def exit_overlay(*, mutate=None, stack_result=False, faults=False):
    bundle, _, original = input_overlay(with_contract=True)
    machine = copy.deepcopy(original.machine_semantics[0].machine_projection)
    operation = machine['operation']
    operation['parameters'][0]['exit_projection'] = {'kind': 'register', 'register': 'ebx', 'width': 32, 'at': 'exit'}
    if stack_result:
        operation['results'][0]['projection'] = {'kind': 'stack', 'offset': 16, 'width': 32, 'at': 'exit'}
    if faults:
        operation['results'][0]['fault_outcomes'] = [{'logical_value': 4294967295, 'kind': 'memory_fault'}]
    if mutate:
        mutate(operation)
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[replace(original.machine_semantics[0], machine_projection=machine)])
    unit = operation['entry_unit_ids'][0]
    transfer = _Transfer(unit, 'a'*64, 'b'*64, 0x1000, (), (), (_Action('outcome_fallthrough', (0x1010,)),), (), ())
    overlay = render_component_machine_overlay_v5(bundle=bundle, contract=contract,
        operation_symbols={'run': 'authored_run'}, transfers=[transfer])
    return bundle, contract, overlay


class ParameterExitViewTests(unittest.TestCase):
    def test_complete_adapter_compiles_on_host_and_pe32(self):
        bundle, _, overlay = exit_overlay()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            for name, text in render_component_c_headers_v5(bundle, {'run': 'authored_run'}).items():
                (root/name).write_text(text)
            (root/'overlay.c').write_text(overlay.source)
            for compiler in ('cc', 'i686-w64-mingw32-gcc'):
                executable = shutil.which(compiler)
                self.assertIsNotNone(executable, compiler)
                result = subprocess.run([executable, '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I', str(root), '-c', str(root/'overlay.c'), '-o', str(root/'overlay.o')],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def check(self, body, *, consumer='return 7U;', failure=None, mutant=None, **options):
        bundle, _, overlay = exit_overlay(**options)
        code = overlay.source
        if mutant == 'omit-store':
            self.assertEqual(code.count('state->ebx = parameter_exit_scratch;'), 1)
            code = code.replace('state->ebx = parameter_exit_scratch;', '')
        code += '\nuint32_t authored_run(spx_owned_context_v5 *context, const spx_view_v5 *scratch) {\n'
        code += '(void)context; (void)scratch;\n' + consumer + '\n}\n'
        body = body.replace('OVERLAY', overlay.entries[0]['symbol'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            for name, text in render_component_c_headers_v5(bundle, {'run': 'authored_run'}).items():
                (root/name).write_text(text)
            source = root/'post.c'
            source.write_text(native_source(body, overlay=code))
            command = [shutil.which('cbmc'), str(source), '--json-ui', '--unwind', '17', '--sat-solver', 'cadical']
            result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check', '--undefined-shift-check'], timeout_seconds=40)
            self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
            if failure:
                self.assertEqual(result['detail'], failure)
            else:
                cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                    expected_functions=['main'], timeout_seconds=40)
                self.assertEqual(cover['status'], 'satisfied', cover)

    def test_null_and_arbitrary_live_interior_inputs_export_the_original_value(self):
        self.check('''
  state.ebx=77U;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_FALLTHROUGH && state.ebx==0U && state.eax==7U,"null parameter output");
  uint32_t size,offset;
  __CPROVER_assume(size>0U && size<=UINT32_MAX-4096U && offset<size);
  __CPROVER_assert(spx_native_add_external_range(4096U,size,100U,1U,7U,55U)==SPX_CALL_OK,"live input");
  pointer_word=4096U+offset;
  result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_FALLTHROUGH && state.ebx==pointer_word && state.eax==7U,
      "runtime-sized interior parameter output");
  __CPROVER_assert(byte_reads==0U && byte_writes==0U,"encoding grants or reconstructs no contents");
''', consumer='((spx_view_v5 *)scratch)->base=(spx_ref_v5){0}; return 7U;')

    def test_removed_transport_is_detected(self):
        body='''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"live input");pointer_word=4096U;state.ebx=99U;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_FALLTHROUGH && state.ebx==4096U,"caller scratch argument");
'''
        self.check(body)
        self.check(body, mutant='omit-store', failure='caller scratch argument')

    def test_expiry_and_address_reuse_do_not_revive_the_saved_reference(self):
        body='''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"live input");pointer_word=4096U;state.ebx=99U;state.eax=88U;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_MEMORY_FAULT && state.ebx==99U && state.eax==88U,
      "expired input publishes no machine outputs");
'''
        release='__CPROVER_assert(spx_native_release_external_range(4096U,101U)==SPX_CALL_OK,"release input");'
        for reuse in ('', '__CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"reuse address");'):
            with self.subTest(reuse=bool(reuse)):
                self.check(body, consumer=release+reuse+'return 7U;')

    def test_body_fault_and_failed_result_store_precede_parameter_publication(self):
        self.check('''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"live input");pointer_word=4096U;state.ebx=99U;state.eax=88U;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_MEMORY_FAULT && state.ebx==99U && state.eax==88U,
      "body fault skips parameter and result outputs");
''', faults=True, consumer='return UINT32_MAX;')
        self.check('''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"live input");pointer_word=4096U;state.ebx=99U;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_MEMORY_FAULT && state.ebx==99U && byte_writes==0U,
      "failed result store skips parameter output");
''', stack_result=True)

    def test_alias_writes_remain_current_after_pointer_export(self):
        self.check('''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"live input");pointer_word=4099U;bytes[3]=4U;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_FALLTHROUGH && state.ebx==4099U && bytes[3]==91U && byte_writes==1U,
      "post output preserves alias writes");
''', consumer='spx_view_v5 alias=*scratch; __CPROVER_assert(spx_view_write_u8(&alias,0U,91U)==SPX_REF_OK,"alias write");return 7U;')

    def test_binding_roundtrip_conflicts_and_legacy_path_rejection(self):
        bundle, contract, _ = exit_overlay()
        operation = contract.machine_semantics[0].machine_projection['operation']
        parsed = OperationMachineBindingV1.parse(operation, 'post operation')
        self.assertEqual(parsed.to_payload(), operation)
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle, contract=contract))
        with self.assertRaisesRegex(ValueError, 'contextual machine-state'):
            build_operation_path_model(operation, interface, [])
        with self.assertRaisesRegex(ValueError, 'contextual machine-state'):
            build_inductive_segment_models(operation, interface, None, None, None, [])
        for target in ('eax', 'esp', 'ebp'):
            def conflict(op):op['parameters'][0]['exit_projection']['register']=target
            with self.subTest(target=target), self.assertRaises(ValueError):exit_overlay(mutate=conflict)
        row = copy.deepcopy(operation['parameters'][0]);row['exit_projection']['width']=16
        with self.assertRaises(ValueError):LogicalMachineValueV1.parse(row, 'narrow output')
        bad = copy.deepcopy(operation)
        bad['results'][0]['exit_projection']=bad['parameters'][0]['exit_projection']
        with self.assertRaisesRegex(ValueError, 'only supported on parameters'):
            OperationMachineBindingV1.parse(bad, 'result output')

    def test_both_readers_require_the_declared_parameter_output(self):
        _, contract, _ = exit_overlay()
        operation = contract.machine_semantics[0].machine_projection['operation']
        exits = parameter_exit_projections(operation)
        comparisons = _exit_comparisons(operation)
        parameter = next(row for row in comparisons if row['id']=='parameter:scratch')
        self.assertIn('ebx', parameter['left']);self.assertIn('SPX_RETURN', parameter['condition'])
        description='spx-bisimulation-exit-observable:run:parameter:scratch'
        model={'operation_id':'run','required_assertion_descriptions':[description]}
        validate_parameter_exit_model(exits,model)
        jq=Path('nix/jq/strong-contextual-proof.jq').read_text()
        for missing in (False, True):
            changed=copy.deepcopy(model)
            if missing:changed['required_assertion_descriptions']=[]
            if missing:
                with self.assertRaisesRegex(ValueError,'checked machine output'):validate_parameter_exit_model(exits,changed)
            checked=run_jq_reader([shutil.which('jq'),'-e',jq+'\n.model | spx_parameter_exit_model('+json.dumps(exits)+')'],
                input=json.dumps({'model':changed}),text=True,capture_output=True)
            self.assertEqual(checked.returncode,1 if missing else 0,checked.stderr)

    def test_plan_binds_parameter_output_and_invalidates_changed_destination(self):
        bundle, contract, _ = exit_overlay()
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle, contract=contract))
        operation = copy.deepcopy(contract.machine_semantics[0].machine_projection['operation'])
        unit = operation['entry_unit_ids'][0]
        operation['units'] = [_unit(unit, 0x1000, [0x1010])]
        def plan():
            return build_component_proof_plan_v1(component_id='owned', semantic_contract_sha256='a'*64,
                interface=interface, operations=[operation], operation_sources={'run': 'SPX_PROOF_BEGIN(run); return 7U;'},
                source_package_sha256='b'*64, intent=None)
        first = plan()
        self.assertEqual(first['operations'][0]['parameter_exit_projections'], parameter_exit_projections(operation))
        operation['parameters'][0]['exit_projection']['register'] = 'edx'
        second = plan()
        self.assertNotEqual(first['plan_sha256'], second['plan_sha256'])
        self.assertEqual(second['operations'][0]['parameter_exit_projections'][0]['projection']['register'], 'edx')


if __name__ == '__main__':unittest.main()
