"""Explicit error results preserve machine outcomes and logical caller channels."""
import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.boundary._canonical import BoundaryModelError
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_binding import LogicalMachineValueV1, OperationMachineBindingV1
from spaghetti_extractor.components.machine_binding_schema import ComponentMachineBindingError
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract
from spaghetti_extractor.transfer.model import _Action, _Transfer
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

ROOT = Path(__file__).parents[3]
TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json",
    "targets/gnu-hello/intent/bindings-v5/ascii-to-lower.json")}
CASES = [{"logical_value": 4294967294, "kind": "external_fault"},
         {"logical_value": 4294967295, "kind": "memory_fault"}]


def fixture(*, cases=CASES, mutate=None):
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(json.loads(
        (ROOT / TESTKIT['resources'][0]).read_text())))
    original = json.loads((ROOT / TESTKIT['resources'][1]).read_text())
    operations = original['operations']
    operation = operations[0]['machine_projection']['operation']
    operation['parameters'][0]['projection'] = {'kind': 'register', 'register': 'ecx', 'width': 32, 'at': 'entry'}
    if cases is not None:
        operation['results'][0]['fault_outcomes'] = copy.deepcopy(cases)
    if mutate:
        mutate(operation)
    binding = ComponentMachineBindingIntentV1.create(component_id='ascii-to-lower', operations=operations, blockers=[])
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[item.semantics for item in binding.operations])
    transfers = [_Transfer(unit, 'a'*64, 'b'*64, int(unit.split('-')[-2], 16), (), (),
        (_Action('outcome_return', ()),), (), ()) for unit in operations[0]['transfer_ids']]
    overlay = render_component_machine_overlay_v5(bundle=bundle, contract=contract,
        operation_symbols={'convert': 'convert'}, transfers=transfers)
    return bundle, binding, overlay


class FaultOutcomeTests(unittest.TestCase):
    def test_stack_result_preserves_effects_faults_and_normal_epilogue(self):
        # A structural component may finish with its result in a caller local,
        # before the compiler has moved that value into the return register.
        for offset in (16, -12):
            with self.subTest(offset=offset):
                bundle, _, overlay = fixture(mutate=lambda op: op['results'][0].update(
                    projection={'kind': 'stack', 'at': 'exit', 'offset': offset, 'width': 32}))
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root/'state-machine-runtime.h').write_text(exact_runtime_header())
                    for name, content in render_component_c_headers_v5(bundle, {'convert': 'convert'}).items():
                        (root/name).write_text(content)
                    model = root/'check.c'
                    model.write_text(overlay.source + '''
static uint32_t effects, writes, reads, address_seen, value_seen, deny;
uint32_t convert(spx_ascii_to_lower_context_v5 *context, uint32_t value) {
  (void)context; effects++; return value;
}
static void write_word(void *context, uint32_t address, uint32_t width,
                       uint32_t value, uint32_t *fault) {
  (void)context;
  __CPROVER_assert(effects == 1U && reads == 0U && width == 4U,
      "result write follows application and precedes continuation");
  writes++; address_seen=address; value_seen=value; *fault=deny;
}
static uint32_t read_word(void *context, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)context; (void)address; (void)width; reads++; *fault=0U; return 0x1234U;
}
int main(void) {
  uint32_t value, esp, missing;
  __CPROVER_assume(esp <= UINT32_MAX-4U);
  __CPROVER_assume(missing <= 1U);
  spx_runtime runtime={0}; runtime.read=read_word;
  runtime.write=missing ? 0 : write_word;
  spx_machine_state state={0}; state.esp=esp; state.eax=73U; state.ecx=value;
  uint32_t nondet_deny; deny=nondet_deny;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(effects==1U && state.eax==73U,"stack result preserves application effects and unrelated register");
  if (value==UINT32_MAX || value==UINT32_MAX-1U) {
    __CPROVER_assert(result.kind==(value==UINT32_MAX ? SPX_MEMORY_FAULT : SPX_EXTERNAL_FAULT),
        "explicit fault precedes result storage");
    __CPROVER_assert(writes==0U && reads==0U && state.esp==esp,"fault does not publish result or return");
  } else if (missing || deny) {
    __CPROVER_assert(result.kind==SPX_MEMORY_FAULT && reads==0U && state.esp==esp,
        "unwritable result cannot continue");
    __CPROVER_assert(writes==(missing ? 0U : 1U),"missing writer does not get called");
  } else {
    __CPROVER_assert(writes==1U && value_seen==value &&
        address_seen==(uint32_t)(esp + UINT32_C(OFFSET)),"normal result uses current stack and IA32 address arithmetic");
    __CPROVER_assert(result.kind==SPX_RETURN && result.value==0x1234U &&
        reads==1U && state.esp==esp+4U,"normal result keeps return epilogue");
  }
}
'''.replace('OVERLAY', overlay.entries[0]['symbol']).replace('OFFSET', str(offset & 0xffffffff)))
                    result = run_cbmc_properties(command=[shutil.which('cbmc'), str(model), '-I', str(root),
                        '--json-ui', '--unwind', '2', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                        '--signed-overflow-check', '--sat-solver', 'cadical'], timeout_seconds=30)
                    self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_binding_roundtrip_and_identity_include_cases(self):
        _, binding, _ = fixture()
        projection = binding.operations[0].semantics.machine_projection['operation']
        parsed = OperationMachineBindingV1.parse(projection, 'operation')
        self.assertEqual(parsed.to_payload(), projection)
        self.assertNotEqual(binding.intent_sha256, fixture(cases=None)[1].intent_sha256)
        self.assertNotEqual(binding.intent_sha256, fixture(cases=[CASES[1]])[1].intent_sha256)

    def test_invalid_cases_and_parameter_placement_reject(self):
        for cases in ([], None, [{'logical_value': True, 'kind': 'memory_fault'}],
                      [{'logical_value': 2**32, 'kind': 'memory_fault'}],
                      [{'logical_value': 0, 'kind': 'return'}], [CASES[1], CASES[1]], list(reversed(CASES))):
            row = {'id': 'result', 'projection': {'kind': 'register', 'register': 'eax', 'width': 32, 'at': 'exit'},
                   'fault_outcomes': cases}
            with self.subTest(cases=cases), self.assertRaises(ComponentMachineBindingError):
                LogicalMachineValueV1.parse(row, 'result')
        with self.assertRaisesRegex(BoundaryModelError, 'only supported on results'):
            fixture(mutate=lambda op: op['parameters'][0].update(fault_outcomes=CASES))
        with self.assertRaisesRegex(BoundaryModelError, 'unencoded exit word'):
            fixture(mutate=lambda op: op['results'][0].update(encoding={'op': 'projected_value'}))
        for phase, width in [('entry', 32), ('call', 32), ('exit', 16), ('exit', 64)]:
            with self.subTest(phase=phase, width=width), self.assertRaisesRegex(
                    BoundaryModelError, 'unencoded exit word'):
                fixture(mutate=lambda op: op['results'][0].update(projection={
                    'kind': 'stack', 'at': phase, 'offset': 16, 'width': width}))

    def test_generated_native_and_logical_adapters_preserve_all_result_cases(self):
        compiler = shutil.which('cc')
        if compiler is None or shutil.which('cbmc') is None:
            self.skipTest('C compiler and CBMC required')
        bundle, _, overlay = fixture()
        symbol = overlay.entries[0]['symbol']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            for name, content in render_component_c_headers_v5(bundle, {'convert': 'convert'}).items():
                (root/name).write_text(content)
            (root/'overlay.c').write_text(overlay.source)
            compiled = subprocess.run([compiler, '-std=c11', '-I', str(root), '-c', str(root/'overlay.c'),
                                       '-o', str(root/'overlay.o')], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            model = root/'check.c'
            model.write_text(overlay.source + '''
static uint32_t effects, return_reads;
uint32_t convert(spx_ascii_to_lower_context_v5 *context, uint32_t value) {
  (void)context; effects++; return value;
}
static uint32_t read_word(void *context, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)context; (void)address; (void)width; *fault=0U; return_reads++; return 0x1234U;
}
void main(void) {
  uint32_t value;
  spx_runtime runtime={0};runtime.read=read_word;
  spx_machine_state state={0};state.esp=0x800000U;state.eax=73U;state.ecx=value;
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(effects==1U,"operation effects precede outcome mapping");
  if(value==UINT32_MAX || value==UINT32_MAX-1U) {
    __CPROVER_assert(result.kind==(value==UINT32_MAX ? SPX_MEMORY_FAULT : SPX_EXTERNAL_FAULT),"explicit machine fault");
    __CPROVER_assert(state.eax==73U && state.esp==0x800000U && return_reads==0U,"fault skips normal result and return epilogue");
  } else {
    __CPROVER_assert(result.kind==SPX_RETURN && result.value==0x1234U && state.eax==value,"ordinary result preserved");
    __CPROVER_assert(state.esp==0x800004U && return_reads==1U,"normal return epilogue retained");
  }
  uint32_t memory_fault=0U, service_fault=0U;
  spx_component_service_context_v1 caller={&runtime,&state,&memory_fault,&service_fault};
  uint32_t logical=spx_component_logical_ascii_to_lower_convert(&caller,value);
  __CPROVER_assert(logical==value && effects==2U,"logical call preserves value and effects");
  __CPROVER_assert(memory_fault==(value==UINT32_MAX) && service_fault==(value==UINT32_MAX-1U),"logical caller fault channel");
}
'''.replace('OVERLAY', symbol))
            result = run_cbmc_properties(command=[shutil.which('cbmc'), str(model), '-I', str(root), '--json-ui',
                '--unwind', '2', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--sat-solver', 'cadical'], timeout_seconds=30)
            self.assertEqual(result['status'], 'satisfied', result.get('detail'))
