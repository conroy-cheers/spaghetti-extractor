"""Borrowed nullable parameter descriptors retain their native meaning at real cuts."""

import copy
import json
import shutil
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components.bisimulation import BisimulationSyncV1
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_local_views import local_view_specs,local_view_metadata,validate_local_view_model,LEGACY_POLICY
from spaghetti_extractor.components.bisimulation_refinement import _required_assertion_descriptions
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.machine_overlay_result_views import _input_view_decoder_source
from tests.unit.components.test_bisimulation_allocation_calls import inputs
from tests.unit.components.test_bisimulation_local_views import authored_view
from tests.unit.components import test_bisimulation_local_views as local_views_fixture
from tests.unit.components.test_bisimulation_nullable_inputs import input_model
from tests.unit.components.test_nullable_input_views import input_overlay, projection
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.bisimulation_harness import _entry_preconditions

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'profiles/pe32-kernel32-runtime-v1.json', 'nix/jq/strong-contextual-proof.jq')}


def parameter_view(*, alias_field=False, byte_invariant=False):
    authored,_,_,_=authored_view()
    payload=authored.syncs[0].to_payload()
    capture=payload['captures'][0]
    capture.update(kind='parameter',projection=projection())
    capture['encoding']['nullable']=True
    payload['invariant']={'op':'eq','args':[{'op':'const','value':0,'width':32}]*2}
    if byte_invariant:
        payload['invariant']={'op':'eq','args':[{'op':'byte_read','name':'scratch','index':{'op':'const','value':0,'width':32}},
            {'op':'const','value':7,'width':32}]}
    if alias_field:
        payload['captures'].append({'kind':'source_state','id':'width','mode':'machine_codec',
            'projection':{'kind':'register','register':'ecx','width':32,'at':'entry'},
            'encoding':{'op':'state_input','name':'width'},'decoding':{'op':'projected_value'}})
        payload['source_bindings']={'width':{'root':'alias','members':[{'access':'pointer','name':'element_width'}]}}
    authored=replace(authored,syncs=(BisimulationSyncV1.parse(payload,'borrowed parameter'),))
    _,_,parameters=input_model()
    specs=local_view_specs(authored,component_id='counter',overlay_entry={'object_authority_selectors':{'scratch':'text'}},
        authority=inputs()[0],parameter_specs=parameters)
    return authored,specs


def header(authored,specs,*,outgoing=True,havoc=None):
    return _render_proof_header(authored=authored,image_base=4194304,
        unit_rvas={authored.syncs[0].exact_unit_id:0x1010},active_start_sync_id='cut',
        active_target_sync_ids={'cut'} if outgoing else set(),local_havoc={'cut':havoc or []},local_view_specs=specs)


DECODE=_input_view_decoder_source()+'''
static spx_view_v5 borrowed(uint32_t address) {
  spx_view_v5 view={0};
  __CPROVER_assert(!spx_component_input_view_decode(&runtime,address,1U,3U,"text",&view),"native input decoder");
  return view;
}
'''


class ParameterViewCutTests(unittest.TestCase):
    def test_public_lowering_requires_current_binding_and_preserves_null_domain(self):
        bundle, _, contract = input_overlay(with_contract=True)
        payload = _logical_projection(bundle, contract=contract)
        interface = ProofKernelComponentInterface.parse(payload)
        logical_type = interface.type_index()[interface.operations[0].parameters[0].type_id]
        self.assertEqual(logical_type.extent_kind, 'origin_remainder')
        self.assertIsNone(logical_type.fixed_extent)
        self.assertTrue(logical_type.nullable)
        self.assertEqual(ProofKernelComponentInterface.parse(interface.to_payload()), interface)
        machine = contract.machine_semantics[0].machine_projection['operation']
        preconditions = '\n'.join(_entry_preconditions(interface, 'run', machine, shared_views=True))
        self.assertIn('== UINT32_C(0) || spx_proof_view_admitted', preconditions)
        with self.assertRaisesRegex(ValueError, 'nullable logical view contract'):
            _logical_projection(bundle)
        for invalid in (replace(contract, interface_sha256='0'*64), replace(contract, machine_semantics=())):
            with self.assertRaisesRegex(ValueError, 'current, total operation bindings'):
                _logical_projection(bundle, contract=invalid)
        altered = copy.deepcopy(machine)
        altered['parameters'][0]['projection']['extent'] = {'kind':'constant','value':1,'width':32}
        semantics = replace(contract.machine_semantics[0], machine_projection={
            **contract.machine_semantics[0].machine_projection, 'operation': altered})
        with self.assertRaisesRegex(ValueError, 'origin-remainder'):
            _logical_projection(bundle, contract=replace(contract, machine_semantics=(semantics,)))

    def test_remaining_extent_cannot_escape_direct_borrowed_byte_input_scope(self):
        bundle, _, contract = input_overlay(with_contract=True)
        original = _logical_projection(bundle, contract=contract)
        interface = ProofKernelComponentInterface.parse(original)
        identity = interface.operations[0].parameters[0].type_id
        for key, value in [('nullable', False), ('ownership', 'owned'), ('element_type_id', 'u32')]:
            changed = copy.deepcopy(original)
            next(row for row in changed['types'] if row['id'] == identity)[key] = value
            with self.assertRaises(ValueError):ProofKernelComponentInterface.parse(changed)
        changed = copy.deepcopy(original)
        changed['operations'][0]['results'][0]['type_id'] = identity
        with self.assertRaisesRegex(ValueError, 'direct operation-input'):
            ProofKernelComponentInterface.parse(changed)

    def check(self,body,*,authored=None,specs=None,outgoing=True,failure=None,witness=None):
        if authored is None:authored,specs=parameter_view()
        result=local_views_fixture.LocalViewCutTests().check(DECODE+body,header=header(authored,specs,outgoing=outgoing),witness=witness)
        self.assertEqual(result['status'],'violated' if failure else 'satisfied',result.get('detail'))
        if failure:self.assertIn(failure,result['detail'])

    def test_resume_uses_borrowed_descriptor_and_current_alias_bytes(self):
        self.check('''
static void lifted(const spx_view_v5 *scratch) {
  SPX_PROOF_BEGIN(run);
  __CPROVER_assert(0,"resumption must skip allocating prefix");
  SPX_PROOF_SYNC(cut,1,scratch);
  spx_view_v5 alias=*scratch;uint8_t byte=0U;uint32_t fault=0U,index=spx_nondet_u32();
  __CPROVER_assume(index<16U);
  __CPROVER_assert(spx_view_read_u8(scratch,index,&byte)==SPX_REF_OK &&
      byte==spx_proof_exact_input_read(4096U+index,1U),"borrowed parameter exposes current bytes");
  __CPROVER_assert(spx_view_write_u8(&alias,index,91U)==SPX_REF_OK,"write through copied alias");
  spx_proof_exact_write(0,4096U+index,1U,91U,&fault);
  __CPROVER_assert(!fault && spx_view_read_u8(scratch,index,&byte)==SPX_REF_OK && byte==91U,
      "borrowed parameter sees alias write");
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"paired contents after alias edit");
  __CPROVER_cover(1);
}
int main(void) {
  start();__CPROVER_assume(spx_proof_exact_input_read(8388620U,4U)==4096U);
  spx_view_v5 view=borrowed(4096U);spx_proof_start=1U;lifted(&view);
}
''',outgoing=False,witness='lifted')

    def test_null_and_live_parameters_cross_incoming_and_outgoing_barriers(self):
        for address in (0,4096):
            with self.subTest(address=address):
                self.check('''
static void lifted(const spx_view_v5 *scratch) {
  SPX_PROOF_BEGIN(run);
  __CPROVER_assert(0,"resumption skips prefix");
  for (;;) { SPX_PROOF_SYNC(cut,1,scratch); __CPROVER_cover(1); }
}
int main(void) {
  start();__CPROVER_assume(spx_proof_exact_input_read(8388620U,4U)==ADDRESS);
  spx_view_v5 view=borrowed(ADDRESS);spx_proof_start=1U;lifted(&view);
}
'''.replace('ADDRESS',str(address)+'U'),witness='lifted')

    def test_incoming_observer_checks_corruption_without_repair_or_assumption(self):
        for mutation in ('view.element_width=2U;','view.read=0;','view.access_context=0;'):
            with self.subTest(mutation=mutation):
                self.check('''
static void lifted(const spx_view_v5 *scratch) { SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(cut,1,scratch); }
int main(void) {
  start();__CPROVER_assume(spx_proof_exact_input_read(8388620U,4U)==4096U);
  spx_view_v5 view=borrowed(4096U); MUTATION spx_proof_start=1U;lifted(&view);
}
'''.replace('MUTATION',mutation),outgoing=False,failure='native-view-input:cut:scratch')

    def test_alias_restoration_cannot_corrupt_borrowed_descriptor(self):
        authored,specs=parameter_view(alias_field=True)
        self.check('''
static void lifted(const spx_view_v5 *scratch) {
  spx_view_v5 *alias=(spx_view_v5 *)scratch;
  SPX_PROOF_BEGIN(run);SPX_PROOF_SYNC(cut,1,scratch,alias->element_width);
}
int main(void) {
  start();__CPROVER_assume(spx_proof_exact_input_read(8388620U,4U)==4096U);
  spx_view_v5 view=borrowed(4096U);spx_proof_exact_input.ecx=2U;
  spx_proof_start=1U;lifted(&view);
}
''',authored=authored,specs=specs,outgoing=False,failure='native-view-input:cut:scratch')

    def test_outgoing_current_contents_and_lifetime_are_separate_obligations(self):
        for mutation,diagnostic in (
                ('spx_proof_source_write(0,4100U,1U,8U,&fault);','capture-reference-memory:cut:scratch'),
                ('spx_source_world.allocations[0].live=0U;','capture:cut:scratch')):
            with self.subTest(mutation=mutation):
                self.check('''
static void lifted(const spx_view_v5 *scratch) {
  SPX_PROOF_BEGIN(run);
  for (;;) { SPX_PROOF_SYNC(cut,1,scratch); uint32_t fault=0U; MUTATION }
}
int main(void) {
  start();__CPROVER_assume(spx_proof_exact_input_read(8388620U,4U)==4096U);
  __CPROVER_assume(spx_proof_exact_input_read(4100U,1U)==7U);
  spx_view_v5 view=borrowed(4096U);spx_proof_start=1U;lifted(&view);
}
'''.replace('MUTATION',mutation),failure=diagnostic)

    def test_parameter_byte_invariant_uses_borrowed_pointer_form(self):
        authored,specs=parameter_view(byte_invariant=True)
        self.check('''
static void lifted(const spx_view_v5 *scratch) {
  SPX_PROOF_BEGIN(run);SPX_PROOF_SYNC(cut,1,scratch);
  uint8_t byte=0U;__CPROVER_assert(spx_view_read_u8(scratch,0U,&byte)==SPX_REF_OK && byte==7U,
      "borrowed byte invariant constrains current storage");__CPROVER_cover(1);
}
int main(void) {
  start();__CPROVER_assume(spx_proof_exact_input_read(8388620U,4U)==4096U);
  spx_view_v5 view=borrowed(4096U);spx_proof_start=1U;lifted(&view);
}
''',authored=authored,specs=specs,outgoing=False,witness='lifted')

    def test_both_readers_require_owner_policy_and_outgoing_contents(self):
        authored,_=parameter_view();sync=authored.syncs[0]
        planned={'operation_id':'run','source':{'syncs':[sync.to_payload()]},'exact':{'control_edges':[
            {'source_unit_id':sync.exact_unit_id,'target_unit_id':sync.exact_unit_id}]}}
        metadata={**local_view_metadata(authored),'allocation_history_policy':'bounded-allocation-history-checked-class-current-memory-v2',
            'maximum_input_allocations':1}
        checks=_required_assertion_descriptions(authored=authored,proof_function='main',active_start_sync_id='cut',next_sync_ids={'cut'},
            logical_projection={'results':[],'state':[]},continuous_acyclic=False,typed_call_positions=[])
        model={**metadata,'obligation_id':'sync:cut','selected_unit_ids':[sync.exact_unit_id],'required_assertion_descriptions':checks}
        module=Path(__file__).resolve().parents[3]/'nix/jq/strong-contextual-proof.jq'
        for mutation in (None,'owner','memory','legacy'):
            changed=copy.deepcopy(model)
            if mutation=='owner':changed['required_assertion_descriptions'].remove('spx-bisimulation-native-view-input-owner:cut:scratch')
            if mutation=='memory':changed['required_assertion_descriptions'].remove('spx-bisimulation-capture-reference-memory:cut:scratch')
            if mutation=='legacy':changed['local_view_cut_policy']=LEGACY_POLICY
            if mutation:
                with self.assertRaises(ValueError):validate_local_view_model(planned,changed)
            else:validate_local_view_model(planned,changed)
            document={'proof_plan':{'operations':[planned]},'proof':{'models':{'operation_models':[
                {**metadata,'operation_id':'run','obligation_models':[changed]}]}}}
            result=subprocess.run([shutil.which('jq'),'-e',module.read_text()+'\nspx_cut_capture_codecs'],
                input=json.dumps(document),text=True,capture_output=True)
            self.assertEqual(result.returncode,1 if mutation else 0,result.stderr)

    def test_cut_requires_bound_decoder_and_stable_parameter_binding(self):
        authored,specs=parameter_view()
        with self.assertRaisesRegex(BisimulationRefinementError,'bound input decoder'):
            local_view_specs(authored,component_id='counter',overlay_entry={'object_authority_selectors':{'scratch':'text'}},authority=inputs()[0])
        with self.assertRaisesRegex(BisimulationRefinementError,'stable canonical argument'):
            header(authored,specs,havoc=['scratch'])


if __name__=='__main__':unittest.main()
