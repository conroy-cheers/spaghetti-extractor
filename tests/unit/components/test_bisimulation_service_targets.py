"""Generated indirect service adapters preserve a checked import-slot target."""

import copy
import json
import shutil
import subprocess
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
from spaghetti_extractor.components.machine_overlay_external_v5 import _captured_external_target_lines
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


def fixture():
    bundle = shared_fixture.shared_buffer_bundle()
    interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
    binding = slot_binding()
    renderer = build_typed_proof_service_thunk_renderer(interface=interface, service_bindings=[binding])
    return bundle, interface, binding, "\n".join(renderer(bundle, binding, {}))


def check_target(*, before="", after="", repair="", erase=False):
    bundle, interface, binding, thunk = fixture()
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
  spx_component_service_context_v1 context={&source,&portable,&fault,&service_fault};
  spx_machine_reference_v1 issued;
  __CPROVER_assert(source.resolve_reference(source.context,0x413d20U,500U,3U,0,0U,0U,&issued)==SPX_BOUNDARY_OK,
      "fixture borrowed buffer");
  spx_view_v5 view={0};
  view.base=(spx_ref_v1){issued.domain,issued.object,issued.generation,issued.offset,issued.extent,issued.permissions};
  view.extent=500U;view.element_width=1U;
  spx_proof_exact_write(0,0x40e158U,4U,target,&fault);
  spx_proof_source_write(0,0x40e158U,4U,target,&fault);
''' + before + '''
  spx_stack_input args[4]={{0,4,7},{4,4,31},{8,4,0x413d20U},{12,4,500}};
  spx_call_event event={.kind=SPX_CALL_INDIRECT,.instruction_rva=100U,.return_rva=105U,
      .target_rva=target,.stack_inputs=args,.stack_input_count=4};
  spx_proof_exact_external_call(&exact,&event,&input,&output);
''' + after + '''
  uint32_t result=load_string(&context,7U,31U,&view,500U);
  __CPROVER_assert(fault==0U && service_fault==0U && result==output.eax,"typed slot target response");
''' + repair + '''
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"typed slot target public memory");
}
''')
        return run_cbmc_properties(command=[shutil.which("cbmc"), str(source), "--json-ui", "--trace",
            "--unwind", "3", "--unwinding-assertions", "--bounds-check", "--pointer-check",
            "--signed-overflow-check", "--sat-solver", "cadical"], timeout_seconds=45)


class ServiceTargetTests(unittest.TestCase):
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
            p = subprocess.run([shutil.which("jq"), program+"\nspx_typed_adapter_renderer_inventory"],
                input=json.dumps(altered), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(p.stdout), omitted is None)
        for change in ({}, {"kind": "register"}, {"rva": True}, {"rva": 0xffffffff},
                       {"rva": -1}, {"width": 16}, {"at": "call"}, {"extra": True}):
            selected = copy.deepcopy(binding); selected["captured_target_projection"].update(change)
            if change:
                with self.assertRaisesRegex(ValueError, "captured_target_unsupported"): checked_typed_external_target(selected)
            else:
                checked_typed_external_target(selected)
            p = subprocess.run([shutil.which("jq"), program+"\nspx_typed_external_target_supported"],
                input=json.dumps(selected), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(p.stdout), not change)
