"""Generated indirect service adapters preserve a checked import-slot target."""

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_typed_services import (
    build_typed_proof_service_thunk_renderer, _trusted_adapter_lowering_receipt,
)
from spaghetti_extractor.components.bisimulation_service_targets import checked_typed_external_target, typed_external_target_lines
from spaghetti_extractor.components.contextual_bisimulation import _trusted_adapter_lowering_used
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.machine_binding import ServiceMachineBindingV1
from spaghetti_extractor.components.machine_overlay_external_v5 import _captured_external_target_lines, _entry_target_capture_lines
from spaghetti_extractor.components.machine_overlay_services_v5 import _service_setup_lines
from spaghetti_extractor.components.semantic_external_transducers import checked_captured_external_target_guard
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from . import test_hand_defined_boundaries as shared_fixture
from . import test_bisimulation_call_ranges as range_fixture
from . import test_bisimulation_service_effects as effects_fixture

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text", "nix/jq/strong-contextual-proof.jq",
    "profiles/pe32-kernel32-runtime-v1.json", "profiles/pe32-kernel32-terminated-byte-read-v1.json")}


def slot_binding():
    return {**range_fixture.buffer_binding(), "symbol": "load_string",
        "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
        "captured_target_projection": {"kind": "static_slot", "rva": 0xe158, "width": 32, "at": "entry"}}


def fixture(register=None, sampling=None):
    bundle = shared_fixture.shared_buffer_bundle()
    interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
    binding = slot_binding()
    if register is not None:
        binding["captured_target_projection"] = {"kind": "register", "register": register, "width": 32, "at": "entry"}
    if sampling is not None:
        binding['target_sampling'] = sampling
    renderer = build_typed_proof_service_thunk_renderer(interface=interface, service_bindings=[binding])
    return bundle, interface, binding, "\n".join(renderer(bundle, binding, {}))


def check_target(*, before="", after="", repair="", erase=False, register=None, sampling=None):
    bundle, interface, binding, thunk = fixture(register, sampling)
    component = bundle.interface.identity.replace('-', '_')
    setup = '\n'.join(_service_setup_lines(bundle=bundle, component=component,
        service_bindings=[binding], context_expression='&logical_context', runtime_expression='&source',
        state_expression='&portable', memory_fault_expression='&fault', fault_expression='&service_fault'))
    if erase:
        thunk = thunk.replace("  spx_proof_typed_service_target(spx_typed_target);", "")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_cbmc_stdint(root / "stdint.h")
        (root / "state-machine-runtime.h").write_text(exact_runtime_header())
        for name, content in render_component_c_headers_v5(bundle, {"get": "get"}).items():
            (root / name).write_text(content)
        source = root / "target.c"
        source.write_text('#include "state-machine-runtime.h"\n#include "portable-component-implementation.h"\n'
            '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + _world_source(
                max_writes=8, max_private_writes=1, max_calls=1, max_atomics=1, max_shadow_bytes=1,
                max_nul_views=1, reference_origin_capacity=1, service_bindings=[binding], private_ranges=()) + '''
typedef struct {
  spx_runtime *runtime;
  spx_machine_state *state;
  uint32_t *memory_fault, *service_fault;
  struct {uint32_t physical_word,target_rva;} callback_result;
  struct {uint32_t value,fault;} entry_targets[1];
} spx_component_service_context_v1;
uint32_t spx_component_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  if (rt->read == 0) { *fault = 1U; return 0U; }
  return rt->read(rt->context, address, width, fault);
}
''' + thunk + '''
int main(void) {
  spx_proof_reset_worlds(0x800000U, 256U);
  uint32_t fault=0U, service_fault=0U, target=0x123456U;
  spx_machine_state input={.esp=0x800000U}, output, portable={0};
  spx_runtime exact=spx_proof_runtime(&spx_exact_world), source=spx_proof_runtime(&spx_source_world);
  exact.image_base=source.image_base=0x400000U;
  spx_machine_reference_v1 issued;
  __CPROVER_assert(source.resolve_reference(source.context,0x413d20U,500U,3U,0,0U,0U,&issued)==SPX_BOUNDARY_OK,
      "fixture borrowed buffer");
  spx_view_v5 view={0};
  view.base=(spx_ref_v1){issued.domain,issued.object,issued.generation,issued.offset,issued.extent,issued.permissions};
  view.extent=500U;view.element_width=1U;
  spx_proof_exact_write(0,0x40e158U,4U,target,&fault);
  spx_proof_source_write(0,0x40e158U,4U,target,&fault);
''' + (f"portable.{register}=target;\n" if register else "") +
            f'spx_{component}_context_v5 logical_context={{0}};\n' + setup + before + '''
  spx_stack_input args[4]={{0,4,7},{4,4,31},{8,4,0x413d20U},{12,4,500}};
  spx_call_event event={.kind=SPX_CALL_INDIRECT,.instruction_rva=100U,.return_rva=105U,
      .target_rva=target,.stack_inputs=args,.stack_input_count=4};
  spx_proof_exact_external_call(&exact,&event,&input,&output);
''' + after + '''
  uint32_t result=load_string(&service_context,7U,31U,&view,500U);
  __CPROVER_assert(fault==0U && service_fault==0U && result==output.eax,"typed slot target response");
''' + repair + '''
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"typed slot target public memory");
}
''')
        return run_cbmc_properties(command=[shutil.which("cbmc"), str(source), "--json-ui", "--trace",
            "--unwind", "3", "--unwinding-assertions", "--bounds-check", "--pointer-check",
            "--signed-overflow-check", "--sat-solver", "cadical"], timeout_seconds=45)


class ServiceTargetTests(unittest.TestCase):
    def test_production_capture_is_per_invocation_and_retains_read_faults(self):
        projection = slot_binding()['captured_target_projection']
        capture = '\n'.join(_entry_target_capture_lines(projection, index=0))
        target = '\n'.join(_captured_external_target_lines(projection, entry_index=0))
        source = '''#include <stdint.h>
typedef struct {uint32_t image_base;} runtime;
typedef struct {uint32_t esp;} state;
typedef struct {runtime *runtime;state *state;struct {uint32_t value,fault;} entry_targets[1];} context;
static uint32_t current,read_fault,reads;
static uint32_t spx_component_read(runtime *rt,uint32_t address,uint32_t width,uint32_t *fault){
 (void)rt;(void)address;(void)width;reads++;*fault=read_fault;return current;
}
static context capture(runtime *rt,state *s){context service_context={.runtime=rt,.state=s};
''' + capture + '''
 return service_context;
}
static uint32_t invoke(context *service,uint32_t *result){
''' + target + '''
 *result=captured_external_target;return 0U;
spx_service_memory_fail:return 1U;
spx_service_fail:return 2U;
}
uint32_t nondet_u32(void);
int main(void){runtime rt={0x400000U};state s={0};uint32_t result=0U;
 uint32_t first=nondet_u32(),second=nondet_u32();
 __CPROVER_assume(first!=0U && second!=0U && first!=second);
 current=first;context outer=capture(&rt,&s);
 current=second;context nested=capture(&rt,&s);
 current=0U;read_fault=1U;
 __CPROVER_assert(invoke(&outer,&result)==0U && result==first,"outer capture survives nested call and slot change");
 __CPROVER_assert(invoke(&nested,&result)==0U && result==second,"nested capture is independent");
 __CPROVER_assert(reads==2U,"calls never reread the slot");
 context failed=capture(&rt,&s);current=first;read_fault=0U;
 __CPROVER_assert(invoke(&failed,&result)==1U,"capture read fault cannot be repaired by a later slot read");
 context next=capture(&rt,&s);
 __CPROVER_assert(invoke(&next,&result)==0U && result==first,"a new invocation captures again");
 current=0U;context null=capture(&rt,&s);current=second;
 __CPROVER_assert(invoke(&null,&result)==2U,"null capture remains a service fault");
 rt.image_base=0xfffffff0U;uint32_t before=reads;context wrap=capture(&rt,&s);
 __CPROVER_assert(reads==before && invoke(&wrap,&result)==1U,"wrapping capture fails before reading");
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture.c';path.write_text(source)
            result=run_cbmc_properties(command=[shutil.which('cbmc'),str(path),'--json-ui','--trace',
                '--unwind','3','--unwinding-assertions','--bounds-check','--pointer-check','--sat-solver','cadical'],
                timeout_seconds=30)
        self.assertEqual(result['status'],'satisfied',result)

    def test_operation_entry_sampling_survives_mutation_and_detects_wrong_capture(self):
        mutation = '''
  spx_proof_exact_write(0,0x40e158U,4U,0U,&fault);
  spx_proof_source_write(0,0x40e158U,4U,0U,&fault);
'''
        result = check_target(sampling='operation_entry', before=mutation)
        self.assertEqual(result['status'], 'satisfied', result)
        wrong = check_target(sampling='operation_entry', before=mutation,
            after='service_context.entry_targets[0].value ^= 1U;')
        self.assertEqual(wrong['status'], 'violated', wrong)
        self.assertIn('typed-call-fields', wrong['detail'])
        failed = check_target(sampling='operation_entry', after='service_context.entry_targets[0].fault=1U;')
        self.assertEqual(failed['status'], 'violated', failed)
        self.assertIn('typed-target-entry-readable', failed['detail'])

    def test_sampling_is_explicit_and_bound_in_both_readers(self):
        program = Path('nix/jq/strong-contextual-proof.jq').read_text()
        for sampling in ('service_call', 'operation_entry', None, 'first_call', 1):
            binding = slot_binding(); binding['target_sampling'] = sampling
            valid = sampling in ('service_call', 'operation_entry')
            if valid:
                checked_typed_external_target(binding)
            else:
                with self.assertRaisesRegex(ValueError, 'captured_target_unsupported'):
                    checked_typed_external_target(binding)
            p = run_jq_reader([shutil.which('jq'), program+'\nspx_typed_external_target_supported'],
                input=json.dumps(binding), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(p.stdout), valid)
            provider = {'kind': 'external_call', 'events': [{'unit_id': 'unit', 'event_index': 0}],
                'identity': {'dll': 'fixture.dll', 'symbol': 'call', 'ordinal': None},
                'target_projection': binding['captured_target_projection'], 'target_sampling': sampling}
            row = {'service_id': 'call', 'mediation': 'direct', 'provider': provider}
            if valid: ServiceMachineBindingV1.parse(row, 'fixture')
            else:
                with self.assertRaises(ValueError): ServiceMachineBindingV1.parse(row, 'fixture')
        provider.pop('target_projection'); provider['target_sampling'] = 'operation_entry'
        with self.assertRaisesRegex(ValueError, 'target projection'):
            ServiceMachineBindingV1.parse(row, 'fixture')

    def test_resumed_regions_require_capture_transport_instead_of_resampling(self):
        from spaghetti_extractor.components.bisimulation_harness import _render_harness
        with self.assertRaisesRegex(ValueError, 'entry_target_cut_transport_unsupported'):
            _render_harness(interface=None, authored=None, machine_image={}, operation_projection={},
                overlay_entry={}, functions=[{'sync_id': 'loop'}], max_writes=1, max_private_writes=1,
                max_calls=1, max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
                service_bindings=[{**slot_binding(), 'target_sampling': 'operation_entry'}],
                connected_summaries=[], include_finite_control=False)

    def test_entry_register_target_matches_and_detects_wrong_or_erased_transport(self):
        self.assertEqual(check_target(register="esi")["status"], "satisfied")
        wrong = check_target(register="esi", after="portable.esi = target + 1U;")
        self.assertEqual(wrong["status"], "violated", wrong)
        self.assertIn("typed-call-fields", wrong["detail"])
        erased = check_target(register="esi", after="portable.esi = target + 1U;", erase=True)
        self.assertEqual(erased["status"], "satisfied", erased)
        null = check_target(register="esi", after="portable.esi = 0U;")
        self.assertEqual(null["status"], "violated", null)
        self.assertIn("typed-target-register-nonnull", null["detail"])

    def test_both_readers_validate_complete_entry_register_recipes(self):
        program = Path("nix/jq/strong-contextual-proof.jq").read_text()
        for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
            binding = fixture(register)[2]
            for change in ({}, {"register": "eip"}, {"width": 16}, {"at": "exit"}, {"rva": 0}):
                selected = copy.deepcopy(binding)
                selected["captured_target_projection"].update(change)
                if change:
                    with self.assertRaisesRegex(ValueError, "captured_target_unsupported"):
                        checked_typed_external_target(selected)
                else:
                    self.assertEqual(checked_typed_external_target(selected), selected["captured_target_projection"])
                    self.assertIn(f"service->state->{register}", "\n".join(_captured_external_target_lines(selected["captured_target_projection"])))
                p = run_jq_reader([shutil.which("jq"), program+"\nspx_typed_external_target_supported"],
                    input=json.dumps(selected), text=True, capture_output=True, check=True, timeout=10)
                self.assertEqual(json.loads(p.stdout), not change)

    def test_failed_slot_read_keeps_the_native_memory_fault_channel(self):
        binding=slot_binding()
        native='\n'.join(_captured_external_target_lines(binding['captured_target_projection']))
        typed='\n'.join(typed_external_target_lines(binding,zero_result='return 0U;')[0])
        prefix='''#include <stdint.h>
typedef struct {uint32_t image_base;} runtime;
typedef struct {runtime *runtime;uint32_t *memory_fault,*service_fault;} context;
static uint32_t failed_read,target,diagnostics;
static uint32_t spx_component_read(runtime *rt,uint32_t address,uint32_t width,uint32_t *fault) {
 (void)rt;(void)address;(void)width;*fault=failed_read;return target;
}
static uint32_t spx_proof_typed_service_public_range(uint32_t address,uint32_t width) {
 (void)address;(void)width;return 1U;
}
static uint32_t native_target(context *service) {
 uint32_t memory_fault=0U;
''' + native + '''
 return 3U;
spx_service_memory_fail:return 1U;
spx_service_fail:return 2U;
}
/* Observe the retained premise diagnostic to compare the downstream fault
   channel. This helper neither drops the production assertion nor qualifies
   an invocation whose target-slot premise fails. */
#define __CPROVER_assert(condition,message) (diagnostics += !(condition))
static uint32_t typed_target(context *spx_typed_service) {
 uint32_t spx_typed_fault=0U;
'''
        suffix='''
 return 3U;
}
#undef __CPROVER_assert
uint32_t nondet_u32(void);
int main(void) {
 failed_read=nondet_u32();target=nondet_u32();
 __CPROVER_assume(failed_read<=1U);
 runtime rt={0x400000U};uint32_t memory=0U,service_fault=0U;
 context service={&rt,&memory,&service_fault};
 uint32_t original=native_target(&service),result=typed_target(&service);
 __CPROVER_assert((original==1U && memory==1U && service_fault==0U && result==0U) ||
  (original==2U && memory==0U && service_fault==1U && result==0U) ||
  (original==3U && memory==0U && service_fault==0U && result==3U),
  "typed target preserves native fault kind");
 __CPROVER_assert(diagnostics==(original!=3U),"invalid target remains a failed premise");
}
'''
        wrong=typed.replace(
            '*(spx_typed_fault != UINT32_C(0) ? spx_typed_service->memory_fault :\n'
            '        spx_typed_service->service_fault)', '*spx_typed_service->service_fault')
        self.assertNotEqual(wrong,typed)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);_write_cbmc_stdint(root/'stdint.h')
            for body,expected in [(typed,'satisfied'),(wrong,'violated')]:
                source=root/'channels.c';source.write_text(prefix+body+suffix)
                result=run_cbmc_properties(command=[shutil.which('cbmc'),str(source),'--json-ui','--trace',
                    '--stop-on-fail','--bounds-check','--pointer-check','--signed-overflow-check',
                    '--sat-solver','cadical'],timeout_seconds=30)
                self.assertEqual(result['status'],expected,result)
                if expected=='violated':self.assertEqual(result['detail'],'typed target preserves native fault kind',result)

    def test_string_effect_requires_explicit_profile_selection(self):
        from spaghetti_extractor.external.machine_import_profiles import load_machine_import_profile_set
        base = Path("profiles/pe32-kernel32-runtime-v1.json")
        selected = Path("profiles/pe32-kernel32-terminated-byte-read-v1.json")
        initial = load_machine_import_profile_set([base]).by_identity()
        combined = load_machine_import_profile_set([base, selected]).by_identity()
        identity = next(key for key in initial if key.value == "lstrlenA")
        self.assertNotIn("memory_effect", initial[identity].contract)
        self.assertEqual(combined[identity].contract["result_register_relations"][0]["relation"], "terminated_byte_offset")
        self.assertEqual({key: row.contract for key, row in initial.items() if key != identity},
                         {key: row.contract for key, row in combined.items() if key != identity})

    def test_existing_static_slot_projection_is_a_checked_service_boundary(self):
        projection = slot_binding()["captured_target_projection"]
        provider = {"kind": "external_call", "events": [{"unit_id": "unit", "event_index": 0}],
            "identity": {"dll": "kernel32.dll", "symbol": "lstrlenA", "ordinal": None}, "target_projection": projection}
        parsed = ServiceMachineBindingV1.parse({"service_id": "length", "mediation": "direct", "provider": provider}, "fixture")
        self.assertEqual(parsed.provider["target_projection"], projection)
        guard = checked_captured_external_target_guard(projection,
            machine_event={"kind": "indirect_call", "target": {"op": "reg", "name": "ebx", "width": 32}})
        self.assertEqual(guard["args"][1], {"op": "entry_projection", "projection": projection})
        native = "\n".join(_captured_external_target_lines(projection))
        self.assertIn("service->runtime->image_base", native)
        self.assertIn("UINT64_C(4294967292)", native)

    def test_generated_thunk_transports_slot_without_an_entry_register_assumption(self):
        result = check_target()
        self.assertEqual(result["status"], "satisfied", result)
        result = check_target(after="spx_proof_exact_write(0,0x40e158U,4U,99U,&fault);",
                              repair="spx_proof_source_write(0,0x40e158U,4U,99U,&fault);")
        self.assertEqual(result["status"], "satisfied", result)

    def test_equal_memory_does_not_hide_an_original_target_retained_before_a_slot_change(self):
        before = """
  spx_proof_exact_write(0,0x40e158U,4U,99U,&fault);
  spx_proof_source_write(0,0x40e158U,4U,99U,&fault);
"""
        result = check_target(before=before)
        self.assertEqual(result["status"], "violated", result)
        self.assertIn("typed-call-fields", result["detail"])
        mutant = check_target(before=before, erase=True)
        self.assertEqual(mutant["status"], "satisfied", mutant)

    def test_equal_null_loaded_target_and_current_slot_do_not_admit_a_call(self):
        # The real cleanup boundary can preserve EBX == current IAT word while
        # both are zero. Value correspondence must not mint a code capability.
        result = check_target(before="""
  target = 0U;
  spx_proof_exact_write(0,0x40e158U,4U,target,&fault);
  spx_proof_source_write(0,0x40e158U,4U,target,&fault);
""")
        self.assertEqual(result["status"], "violated", result)
        self.assertIn("spx-bisimulation-call-target-valid:", result["detail"])

    def test_null_fault_private_slot_and_wrapping_address_fail_closed(self):
        for change, diagnostic in (
            ("source.image_base=0xfffff000U;", "typed-target-slot-address"),
            ("source.image_base=0x800000U-0xe158U;", "typed-target-slot-address"),
            ("source.read=0;", "typed-target-slot-readable-nonnull"),
            ("spx_proof_source_write(0,0x40e158U,4U,0U,&fault);", "typed-target-slot-readable-nonnull")):
            with self.subTest(change=change):
                result = check_target(after=change)
                self.assertEqual(result["status"], "violated", result)
                self.assertIn(diagnostic, result["detail"])

    def test_both_readers_require_target_transport_and_reject_malformed_recipes(self):
        bundle, interface, binding, thunk = fixture()
        receipt = _trusted_adapter_lowering_receipt(interface=interface, service_bindings=[binding],
            production_overlay_source="fixture", proof_overlay_source=thunk)
        program = Path("nix/jq/strong-contextual-proof.jq").read_text()
        for omitted in (None, "bisimulation_service_targets.py", "machine_binding.py"):
            model = {"interface_sha256": interface.sha256, "machine_overlay_sha256": receipt["production_overlay_sha256"],
                "proof_overlay_sha256": receipt["proof_overlay_sha256"], "trusted_adapter_lowering": copy.deepcopy(receipt)}
            altered = model["trusted_adapter_lowering"]
            if omitted:
                renderer = altered["renderer"]
                renderer["implementation_files"] = [row for row in renderer["implementation_files"] if row["path"] != omitted]
                renderer["implementation_closure_sha256"] = canonical_sha256_v3(renderer["implementation_files"])
                effects_fixture.rehash_model(model)
                with self.assertRaisesRegex(ValueError, "renderer closure"): _trusted_adapter_lowering_used(model)
            else:
                self.assertTrue(_trusted_adapter_lowering_used(model))
            p = run_jq_reader([shutil.which("jq"), program+"\nspx_typed_adapter_renderer_inventory"],
                input=json.dumps(altered), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(p.stdout), omitted is None)
        for change in ({}, {"kind": "register"}, {"rva": True}, {"rva": 0xffffffff},
                       {"rva": -1}, {"width": 16}, {"at": "call"}, {"extra": True}):
            selected = copy.deepcopy(binding); selected["captured_target_projection"].update(change)
            if change:
                with self.assertRaisesRegex(ValueError, "captured_target_unsupported"): checked_typed_external_target(selected)
            else:
                checked_typed_external_target(selected)
            p = run_jq_reader([shutil.which("jq"), program+"\nspx_typed_external_target_supported"],
                input=json.dumps(selected), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(p.stdout), not change)
