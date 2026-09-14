"""Hand-defined cuts reconstruct local service views without replaying the prefix."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components import bisimulation_memory_facts as memory_facts
from spaghetti_extractor.components.bisimulation import BisimulationSyncV1, ComponentBisimulationError
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_harness import memory_projection_readers
from spaghetti_extractor.components.bisimulation_local_views import (
    local_view_specs, local_view_metadata, runtime_source, validate_local_view_model, byte_read_checks,
    input_owner_description, LEGACY_POLICY,
)
from spaghetti_extractor.components.bisimulation_view_extent import _VIEW_ADMISSION_SOURCE
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties, run_cbmc_cover
from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.machine_overlay_result_views import result_view_runtime_helpers
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_allocation_calls import inputs
from tests.unit.components.test_bisimulation_allocation_cuts import sources
from tests.unit.components.test_bisimulation_lifetime_admission import interface_fixture

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": (
    "profiles/pe32-kernel32-runtime-v1.json", "nix/jq/strong-contextual-proof.jq")}


def authored_view(*, invariant=None, filled_suffix=False):
    authored, recipe, world = sources(1, memory_fact_capacity=int(filled_suffix))
    payload = authored.syncs[0].to_payload()
    payload["captures"] = [{"kind": "source_state", "id": "scratch", "mode": "native_view",
        "projection": {"kind": "view", "at": "entry",
            "base": {"kind": "register", "register": "ebx", "width": 32, "at": "entry"},
            "extent": {"kind": "origin_remainder"},
            "requested_extent": {"kind": "constant", "value": 1, "width": 32},
            "authority": {"id": "scratch", "kind": "external", "lifetime": "allocation"}},
        "encoding": {"op": "view", "access": "read_write", "nullable": False}, "decoding": None}]
    payload["invariant"] = {"op": "eq", "args": [{"op": "byte_extent", "name": "scratch"},
                            {"op": "const", "value": 16, "width": 32}]}
    if filled_suffix:
        payload['memory_facts'] = [{'id': 'tail', 'kind': 'filled_suffix', 'view': 'scratch',
            'start': {'op': 'const', 'value': 4, 'width': 32}, 'byte': 0}]
    if invariant is not None:
        payload["invariant"] = invariant
    authored = replace(authored, syncs=(BisimulationSyncV1.parse(payload, "local scratch cut"),))
    authority, _, _ = inputs()
    specs = local_view_specs(authored, component_id="counter",
        overlay_entry={"object_authority_selectors": {"scratch": "text"}}, authority=authority)
    return authored, specs, recipe, world


GLOBALS = '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_world_calls_equal(void) { return 1U; }
uint32_t spx_proof_world_atomics_equal(void) { return 1U; }
uint32_t spx_proof_world_connected_calls_equal(void) { return 1U; }
void spx_bisimulation_relation_witness(void) {}
'''


class LocalViewCutTests(unittest.TestCase):
    def check(self, body, *, header=None, witness=None, filled_suffix=False):
        authored, specs, recipe, world = authored_view(filled_suffix=filled_suffix)
        prefix = world + memory_facts.source(authored, specs, inputs()[0]) + _VIEW_ADMISSION_SOURCE + runtime_source()
        prefix += '\n'.join(memory_projection_readers())
        prefix += '\n'.join(result_view_runtime_helpers(proof_codec_symbol=specs["symbol"]))
        prefix += '\n' + spx_portable_reference_runtime_v5_source() + GLOBALS
        prefix += f'''
static spx_runtime runtime;
static void start(void) {{
  spx_proof_reset_worlds(8388608U,256U);
  spx_proof_allocation row={{.base=4096U,.size=16U,.family={recipe['family']}U,
      .generation=2U,.live=1U,.native_rule_selector={recipe['native_rule_selector']}U,
      .native_generation=42U,.birth_class_selector={recipe['birth_class_selector']}U}};
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_exact_world,&row)==SPX_BOUNDARY_OK &&
      spx_proof_restore_allocation_input(&spx_source_world,&row)==SPX_BOUNDARY_OK,"paired incoming storage");
  runtime=spx_proof_runtime(&spx_source_world);
  spx_proof_bind_local_view_runtime(&runtime);
  spx_proof_exact_input.esp=spx_proof_exact_output.esp=8388608U;
  spx_proof_exact_input.ebx=spx_proof_exact_output.ebx=4096U;
  spx_proof_exact_result=(spx_step_result){{SPX_BRANCH,0x1010U,0U}};
}}
static uint32_t codec(spx_view_v5 *view, uint32_t construct) {{
  return {specs['symbol']}(spx_proof_local_view_runtime(),view,4096U,1U,UINT64_MAX,3U,"text",0U,construct);
}}
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            for name, source in render_component_c_headers_v5(interface_fixture(buffer_view=True), {"run": "authored_run"}).items():
                (root / name).write_text(source)
            path = root / "local.c"
            path.write_text('#include "state-machine-runtime.h"\n#include "portable-component.h"\n'
                '#ifndef SPX_TEST_COVER\n#define __CPROVER_cover(condition) ((void)0)\n#endif\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + prefix + (header or "") + body)
            common=[shutil.which("cbmc"),str(path),"--json-ui","--unwind","4","--sat-solver","cadical",
                    *reference_authority_unwind_arguments(inputs()[0])]
            result = run_cbmc_properties(command=[*common,"--trace",
                "--unwind", "4", "--unwinding-assertions", "--bounds-check", "--pointer-check",
                "--signed-overflow-check", "--undefined-shift-check", "--sat-solver", "cadical"],
                timeout_seconds=40)
            if witness and result["status"] == "satisfied":
                cover=run_cbmc_cover(command=[*common,"-DSPX_TEST_COVER","--cover","cover"],
                    expected_functions=[witness],timeout_seconds=40)
                self.assertEqual(cover["status"],"satisfied",cover)
            return result

    def test_public_cut_checks_current_suffix_even_when_paired_writes_agree(self):
        authored, specs, _, _ = authored_view(filled_suffix=True)
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id: 0x1010}, active_start_sync_id="cut",
            active_target_sync_ids={"cut"}, local_havoc={"cut": ["scratch"]}, local_view_specs=specs)
        name = memory_facts.symbols(authored.syncs[0], authored.syncs[0].memory_facts[0])
        body = """
static void lifted(void) {
  spx_view_v5 scratch={0};
  SPX_PROOF_BEGIN(run);
  __CPROVER_assert(0,"resumption skips prefix");
  for (;;) {
    SPX_PROOF_SYNC(cut,scratch.extent==16U,scratch);
    uint32_t fault=0U;
    __CPROVER_assert(spx_view_write_u8(&scratch,5U,BYTE)==SPX_REF_OK,"write through current local view");
    spx_proof_exact_write(0,4101U,1U,BYTE,&fault);
  }
}
int main(void) {
  start(); FACT_initialize(&spx_proof_exact_input);
  spx_proof_start=1U; lifted();
}
""".replace('FACT', name)
        for byte, status in ((0, 'satisfied'), (7, 'violated')):
            result = self.check(body.replace('BYTE', str(byte)+'U'), header=header, filled_suffix=True)
            self.assertEqual(result['status'], status, result.get('detail'))
            if byte:
                self.assertIn('memory-fact-contents', result.get('detail', ''))

    def test_resume_restores_a_local_view_and_current_alias_bytes_without_prefix_execution(self):
        authored, specs, _, _ = authored_view()
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id: 0x1010}, active_start_sync_id="cut",
            active_target_sync_ids=set(), local_havoc={"cut": ["scratch"]}, local_view_specs=specs)
        result = self.check('''
static void lifted(void) {
  spx_view_v5 scratch={0};
  SPX_PROOF_BEGIN(run);
  __CPROVER_assert(0,"original allocating prefix must be absent from resumed execution");
  SPX_PROOF_SYNC(cut,scratch.extent==16U,scratch);
  spx_view_v5 alias=scratch;
  uint32_t index=spx_nondet_u32(),fault=0U; uint8_t byte=0U;
  __CPROVER_assume(index<16U);
  __CPROVER_assert(spx_view_read_u8(&alias,index,&byte)==SPX_REF_OK &&
      byte==spx_proof_initial_byte(4096U+index),"resumed view exposes current bytes through a copied alias");
  __CPROVER_assert(spx_view_write_u8(&scratch,index,91U)==SPX_REF_OK,"resumed local write");
  spx_proof_exact_write(0,4096U+index,1U,91U,&fault);
  __CPROVER_assert(spx_view_read_u8(&alias,index,&byte)==SPX_REF_OK && byte==91U,
      "copied alias observes the local edit");
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"paired outgoing contents and lifetime");
  __CPROVER_cover(1);
}
int main(void) { start(); spx_proof_start=1U; lifted(); }
''', header=header, witness="lifted")
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_stack_capture_uses_incoming_bytes_and_successor_reads_use_current_bytes(self):
        authored, specs, _, _ = authored_view()
        payload = authored.syncs[0].to_payload()
        payload["captures"].append({"kind":"source_state","id":"counter","mode":"machine_codec",
            "projection":{"kind":"stack","offset":16,"width":32,"at":"entry"},
            "encoding":{"op":"state_input","name":"counter"},"decoding":{"op":"projected_value"}})
        authored = replace(authored, syncs=(BisimulationSyncV1.parse(payload, "stack cut"),))
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id:0x1010}, active_start_sync_id="cut",
            active_target_sync_ids={"cut"}, local_havoc={"cut":["counter","scratch"]},
            local_view_specs=specs)
        body = '''
static uint32_t incoming;
static void lifted(void) {
  uint32_t counter=0U; spx_view_v5 scratch={0};
  SPX_PROOF_BEGIN(run);
  __CPROVER_assert(0,"resumption skips prefix");
  for (;;) {
    SPX_PROOF_SYNC(cut,scratch.extent==16U,scratch,counter);
    __CPROVER_assert(counter==incoming,"stack capture reads entry memory");
    ++counter;
  }
}
int main(void) {
  start();
  incoming=spx_proof_exact_input_read(8388624U,4U);
  uint32_t fault=0U;
  spx_proof_exact_write(0,8388624U,4U,incoming+1U,&fault);
  __CPROVER_assert(fault==0U,"original updates its private stack counter");
  __CPROVER_assert(spx_proof_exact_input_read(8388624U,4U)==incoming &&
      spx_proof_exact_output_read(8388624U,4U)==incoming+1U,"entry and successor memory stay distinct");
  spx_proof_start=1U; lifted();
}
'''
        result = self.check(body, header=header)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_local_byte_invariant_uses_incoming_and_current_memory(self):
        # Same paired writes can preserve memory correspondence while violating
        # a successor's content premise. Neither birth zeros nor entry bytes
        # may substitute for the changed last byte at the successor.
        invariant = {"op": "eq", "args": [
            {"op": "byte_read", "name": "scratch", "index": {"op": "const", "value": 15, "width": 32}},
            {"op": "const", "value": 0, "width": 32}]}
        authored, specs, _, _ = authored_view(invariant=invariant)
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id: 0x1010}, active_start_sync_id="cut",
            active_target_sync_ids={"cut"}, local_havoc={"cut": ["scratch"]}, local_view_specs=specs)
        body = '''
static void lifted(void) {
  spx_view_v5 scratch={0};
  SPX_PROOF_BEGIN(run);
  __CPROVER_assert(0,"resumed region skips allocation");
  for (;;) {
    SPX_PROOF_SYNC(cut,1,scratch);
    uint8_t byte=99U;
    __CPROVER_assert(spx_view_read_u8(&scratch,15U,&byte)==SPX_REF_OK && byte==0U,
        "incoming content premise constrains actual current source storage");
    __CPROVER_assert(spx_view_write_u8(&scratch,WRITE_INDEX,91U)==SPX_REF_OK,"paired source edit");
    __CPROVER_cover(1);
  }
}
int main(void) {
  start(); uint32_t fault=0U;
  __CPROVER_assume(spx_proof_exact_input_read(4111U,1U)==0U);
  spx_proof_exact_write(0,4096U+WRITE_INDEX,1U,91U,&fault);
  spx_proof_start=1U; lifted();
}
'''
        for index in (0, 15):
            with self.subTest(index=index):
                result = self.check(body.replace("WRITE_INDEX", str(index)+"U"), header=header,
                                    witness="lifted" if index == 0 else None)
                self.assertEqual(result["status"], "satisfied" if index == 0 else "violated", result.get("detail"))
                if index == 15:
                    self.assertEqual(result["detail"], "spx-bisimulation-invariant:cut")

    def test_local_byte_invariant_cannot_assume_an_out_of_bounds_read(self):
        invariant = {"op": "eq", "args": [
            {"op": "byte_read", "name": "scratch", "index": {"op": "const", "value": 16, "width": 32}},
            {"op": "const", "value": 0, "width": 32}]}
        authored, specs, _, _ = authored_view(invariant=invariant)
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id: 0x1010}, active_start_sync_id="cut",
            active_target_sync_ids=set(), local_havoc={"cut": ["scratch"]}, local_view_specs=specs)
        result = self.check('''
static void lifted(void) {
  spx_view_v5 scratch={0}; SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(cut,1,scratch);
}
int main(void) { start(); spx_proof_start=1U; lifted(); }
''', header=header)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-native-view-byte-access")

    def test_local_address_invariant_uses_current_coordinate_and_retains_codec_checks(self):
        invariant = {"op": "eq", "args": [
            {"op": "bytes_address", "name": "scratch"},
            {"op": "const", "value": 4096, "width": 32}]}
        authored, specs, _, _ = authored_view(invariant=invariant)
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id: 0x1010}, active_start_sync_id="cut",
            active_target_sync_ids={"cut"}, local_havoc={"cut": ["scratch"]}, local_view_specs=specs)
        body = '''
static void lifted(void) {
  spx_view_v5 scratch={0}; SPX_PROOF_BEGIN(run);
  for (;;) {
    SPX_PROOF_SYNC(cut,1,scratch);
    __CPROVER_assert(codec(&scratch,0U),"restored address has its checked descriptor");
    __CPROVER_cover(1);
    MUTATION
  }
}
int main(void) { start(); spx_proof_start=1U; lifted(); }
'''
        moved = f'''spx_proof_exact_output.ebx=4104U;
    __CPROVER_assert({specs['symbol']}(spx_proof_local_view_runtime(),&scratch,
        4104U,1U,UINT64_MAX,3U,"text",0U,1U),"construct valid interior view");'''
        for mutation, failure in (("", None), (moved, "spx-bisimulation-invariant:cut"),
                                  ("scratch.base.generation++;", "spx-bisimulation-capture:cut:scratch")):
            with self.subTest(mutation=mutation):
                result = self.check(body.replace("MUTATION", mutation), header=header,
                    witness="lifted" if failure is None else None)
                self.assertEqual(result["status"], "violated" if failure else "satisfied", result.get("detail"))
                if failure:
                    self.assertEqual(result["detail"], failure)

    def test_outgoing_codec_checks_every_descriptor_part_and_runtime_identity(self):
        template = '''
int main(void) {
  start(); spx_view_v5 view={0}; spx_runtime other=runtime;
  __CPROVER_assert(codec(&view,1U),"construct canonical service view");
  __CPROVER_assert(codec(&view,0U),"canonical descriptor roundtrip");
  MUTATION
  __CPROVER_assert(!codec(&view,0U),"changed descriptor or runtime rejected");
}
'''
        for mutation in ("view.extent=15U;", "view.element_width=2U;", "view.base.generation++;",
                         "view.base.offset++;", "view.read=0;", "view.write=0;",
                         "view.context=&other;", "view.access_context=&other;", "runtime.read=0;",
                         "spx_source_world.allocations[0].live=0U;"):
            with self.subTest(mutation=mutation):
                result = self.check(template.replace("MUTATION", mutation))
                self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_ordinary_constructor_and_observer_keep_failure_returns(self):
        _, specs, _, _ = authored_view()
        symbol = specs["symbol"]
        result = self.check(f'''
void failure_returns(void) {{ __CPROVER_cover(1); }}
int main(void) {{
  start(); spx_view_v5 view={{0}};
  __CPROVER_assert(codec(&view,1U), "ordinary constructor succeeds");
  for (uint32_t mode=0U; mode<2U; ++mode) {{
    __CPROVER_assert(!{symbol}(&runtime,&view,4096U,17U,UINT64_MAX,3U,"text",0U,mode),
        "oversized request reports failure");
    __CPROVER_assert(!{symbol}(&runtime,&view,4096U,1U,17U,3U,"text",0U,mode),
        "oversized visible span reports failure");
    __CPROVER_assert(!{symbol}(0,&view,4096U,1U,16U,3U,"text",0U,mode),
        "missing runtime reports failure");
  }}
  spx_source_world.allocations[0].live=0U;
  __CPROVER_assert(!codec(&view,0U) && !codec(&view,1U), "expired reference reports failure");
  failure_returns();
}}
''', witness="failure_returns")
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_assumed_restoration_stops_failure_before_havoced_callbacks_escape(self):
        result = self.check('''
void restored_input(void) { __CPROVER_cover(1); }
int main(void) {
  start(); spx_view_v5 view;
  __CPROVER_havoc_object(&view);
  if (spx_nondet_u32() & 1U) {
    spx_source_world.allocations[0].live=0U;
    (void)codec(&view,2U);
    __CPROVER_assert(0,"rejected restoration must not return havoced callbacks");
  } else {
    __CPROVER_assume(codec(&view,2U));
    __CPROVER_assert(codec(&view,0U),"restored descriptor retains full observer checks");
    uint64_t byte=0U;
    __CPROVER_assert(view.read(view.access_context,view.base,0U,1U,&byte)==0U,
        "restored live callbacks remain usable");
    restored_input();
  }
}
''', witness="restored_input")
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_actual_outgoing_barrier_rejects_a_changed_local_descriptor(self):
        authored, specs, _, _ = authored_view()
        header = _render_proof_header(authored=authored, image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id: 0x1010}, active_target_sync_ids={"cut"},
            local_view_specs=specs)
        body = '''
int main(void) {
  start(); spx_view_v5 scratch={0};
  SPX_PROOF_BEGIN(run);
  __CPROVER_assert(codec(&scratch,1U),"existing generated service descriptor");
  MUTATION
  SPX_PROOF_SYNC(cut,scratch.extent==16U,scratch);
}
'''
        for changed in (False, True):
            result = self.check(body.replace("MUTATION", "scratch.read=0;" if changed else ""), header=header)
            self.assertEqual(result["status"], "violated" if changed else "satisfied", result.get("detail"))
            if changed:
                self.assertEqual(result["detail"], "spx-bisimulation-capture:cut:scratch")

    def test_schema_requires_explicit_native_semantics_and_disjoint_capture_storage(self):
        authored, _, _, _ = authored_view()
        payload = authored.syncs[0].to_payload()
        self.assertEqual(BisimulationSyncV1.parse(payload,"cut").to_payload(),payload)
        for mutation in ("word", "parameter", "access", "nullable"):
            value = copy.deepcopy(payload)
            capture = value["captures"][0]
            if mutation == "word": capture["decoding"]={"op":"projected_value"}
            elif mutation == "parameter": capture["kind"]="parameter"
            elif mutation == "access": capture["encoding"]["access"]="none"
            else: capture["encoding"]["nullable"]=1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                BisimulationSyncV1.parse(value,"cut")
        value=copy.deepcopy(payload)
        value["captures"].append({"kind":"source_state","id":"extent","mode":"machine_codec",
            "projection":{"kind":"register","register":"ecx","width":32,"at":"entry"},
            "encoding":{"op":"state_input","name":"extent"},"decoding":{"op":"projected_value"}})
        value["source_bindings"]={"extent":{"root":"scratch","members":[{"access":"direct","name":"extent"}]}}
        with self.assertRaisesRegex(ComponentBisimulationError,"overlaps"):
            BisimulationSyncV1.parse(value,"cut")

    def test_descriptor_check_runs_after_an_aliased_scalar_capture_is_restored(self):
        authored, specs, _, _ = authored_view()
        payload=authored.syncs[0].to_payload()
        payload["captures"].append({"kind":"source_state","id":"width","mode":"machine_codec",
            "projection":{"kind":"register","register":"ecx","width":32,"at":"entry"},
            "encoding":{"op":"state_input","name":"width"},"decoding":{"op":"projected_value"}})
        payload["source_bindings"]={"width":{"root":"alias","members":[{"access":"pointer","name":"element_width"}]}}
        authored=replace(authored,syncs=(BisimulationSyncV1.parse(payload,"aliased cut"),))
        header=_render_proof_header(authored=authored,image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id:0x1010},active_start_sync_id="cut",
            active_target_sync_ids=set(),local_havoc={"cut":["scratch"]},local_view_specs=specs)
        result=self.check('''
static void lifted(void) {
  spx_view_v5 scratch={0}; spx_view_v5 *alias=&scratch;
  SPX_PROOF_BEGIN(run);
  SPX_PROOF_SYNC(cut,1,scratch,alias->element_width);
}
int main(void) { start(); spx_proof_start=1U; spx_proof_exact_input.ecx=2U; lifted(); }
''',header=header)
        self.assertEqual(result["status"],"violated",result.get("detail"))
        self.assertEqual(result["detail"],"spx-bisimulation-native-view-input:cut:scratch")

    def test_owner_substitution_rejects_corruption_and_preserves_lifetime_checks(self):
        authored,specs,_,_=authored_view()
        header=_render_proof_header(authored=authored,image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id:0x1010},active_start_sync_id="cut",
            active_target_sync_ids=set(),local_havoc={"cut":["scratch"]},local_view_specs=specs)
        guard='      __CPROVER_assert((scratch).access_context == __CPROVER_spx_cut_owner,'
        self.assertEqual(header.count(guard),1)
        corrupted=header.replace(guard,'      scratch.access_context = 0; '+chr(92)+'\n'+guard)
        body='''
static void lifted(void) {
  spx_view_v5 scratch={0}; SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(cut,1,scratch);
}
int main(void) { start(); spx_proof_start=1U; lifted(); }
'''
        result=self.check(body,header=corrupted)
        self.assertEqual(result['status'],'violated',result.get('detail'))
        self.assertEqual(result['detail'],input_owner_description('cut','scratch'))
        expired='''
static void expire_owner(void) {
  spx_runtime expired=spx_proof_runtime(&spx_source_world);
  spx_proof_bind_local_view_runtime(&expired);
}
'''+body.replace('start(); spx_proof_start','start(); expire_owner(); spx_proof_start')
        result=self.check(expired,header=header)
        self.assertEqual(result['status'],'violated',result.get('detail'))
        self.assertIn('dead object',result.get('detail',''))

    def test_owner_substitution_preserves_a_nullable_empty_view(self):
        authored,_,_,_=authored_view(invariant={"op":"eq","args":[
            {"op":"byte_extent","name":"scratch"},{"op":"const","value":0,"width":32}]})
        payload=authored.syncs[0].to_payload();payload['captures'][0]['encoding']['nullable']=True
        authored=replace(authored,syncs=(BisimulationSyncV1.parse(payload,'nullable cut'),))
        specs=local_view_specs(authored,component_id='counter',
            overlay_entry={'object_authority_selectors':{'scratch':'text'}},authority=inputs()[0])
        header=_render_proof_header(authored=authored,image_base=4194304,
            unit_rvas={authored.syncs[0].exact_unit_id:0x1010},active_start_sync_id='cut',
            active_target_sync_ids=set(),local_havoc={'cut':['scratch']},local_view_specs=specs)
        result=self.check('''
static void lifted(void) {
  spx_view_v5 scratch={0}; SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(cut,1,scratch);
  __CPROVER_assert(scratch.base.object==0U && scratch.access_context==0 && scratch.extent==0U,
      "nullable view retains its empty descriptor");
  __CPROVER_cover(1);
}
int main(void) { start(); spx_proof_exact_input.ebx=0U; spx_proof_start=1U; lifted(); }
''',header=header,witness='lifted')
        self.assertEqual(result['status'],'satisfied',result.get('detail'))

    def test_readers_require_policy_and_resumed_codec_check(self):
        authored, _, _, _ = authored_view()
        planned={"operation_id":"run","source":{"syncs":[authored.syncs[0].to_payload()]},
                 "exact":{"control_edges":[]}}
        metadata={**local_view_metadata(authored),"allocation_history_policy":"bounded-allocation-history-checked-class-current-memory-v2",
                  "maximum_input_allocations":1}
        validate_local_view_model(planned,metadata)
        with self.assertRaises(ValueError): validate_local_view_model(planned,{})
        owner_check=input_owner_description("cut","scratch")
        checks=["spx-bisimulation-allocation-history-input:cut","spx-bisimulation-native-view-input:cut:scratch",owner_check]
        model={**metadata,"obligation_id":"sync:cut","selected_unit_ids":[],"required_assertion_descriptions":checks}
        document={"proof_plan":{"operations":[planned]},"proof":{"models":{"operation_models":[
            {**metadata,"operation_id":"run","obligation_models":[model]}]}}}
        module=Path(__file__).resolve().parents[3]/"nix/jq/strong-contextual-proof.jq"
        for bad in (False,True):
            value=copy.deepcopy(document)
            if bad: value["proof"]["models"]["operation_models"][0]["obligation_models"][0]["required_assertion_descriptions"]=checks[:1]
            result=subprocess.run([shutil.which("jq"),"-e",module.read_text()+"\nspx_cut_capture_codecs"],
                input=json.dumps(value),text=True,capture_output=True)
            self.assertEqual(result.returncode,1 if bad else 0,result.stderr)

        for legacy in (False,True):
            value=copy.deepcopy(document)
            operation=value["proof"]["models"]["operation_models"][0]
            model=operation["obligation_models"][0]
            model["required_assertion_descriptions"].remove(owner_check)
            if legacy:
                operation["local_view_cut_policy"]=model["local_view_cut_policy"]=LEGACY_POLICY
                validate_local_view_model(planned,model)
            else:
                with self.assertRaisesRegex(ValueError,"owner substitution"):
                    validate_local_view_model(planned,model)
            result=subprocess.run([shutil.which("jq"),"-e",module.read_text()+"\nspx_cut_capture_codecs"],
                input=json.dumps(value),text=True,capture_output=True)
            self.assertEqual(result.returncode,0 if legacy else 1,result.stderr)

        byte_invariant={"op":"eq","args":[{"op":"byte_read","name":"scratch",
            "index":{"op":"const","width":32,"value":0}}, {"op":"const","width":32,"value":0}]}
        planned["source"]["syncs"][0]["invariant"]=byte_invariant
        byte_checks=byte_read_checks(planned["source"]["syncs"][0])
        self.assertEqual(byte_checks,{"spx-bisimulation-native-view-byte-access"})
        from spaghetti_extractor.components.bisimulation_refinement import _required_assertion_descriptions
        byte_authored, _, _, _=authored_view(invariant=byte_invariant)
        required=_required_assertion_descriptions(authored=byte_authored,proof_function="main",
            active_start_sync_id="cut",next_sync_ids=set(),logical_projection={"results":[],"state":[]},
            continuous_acyclic=False,typed_call_positions=[])
        self.assertTrue(byte_checks <= set(required))
        self.assertIn(owner_check,required)
        for bad in (False,True):
            value=copy.deepcopy(document)
            model=value["proof"]["models"]["operation_models"][0]["obligation_models"][0]
            model["required_assertion_descriptions"]=checks + ([] if bad else sorted(byte_checks))
            if bad:
                with self.assertRaisesRegex(ValueError,"content read"):
                    validate_local_view_model(planned,model)
            else:
                validate_local_view_model(planned,model)
            result=subprocess.run([shutil.which("jq"),"-e",module.read_text()+"\nspx_cut_capture_codecs"],
                input=json.dumps(value),text=True,capture_output=True)
            self.assertEqual(result.returncode,1 if bad else 0,result.stderr)
