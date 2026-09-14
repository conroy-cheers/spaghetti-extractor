"""Check the conditional access abstraction against actual native predicates."""

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_assurance import (
    checked_implemented_runtime_assurance, runtime_assurance_defines,
)
from spaghetti_extractor.components.bisimulation_connected import _connected_replay_source
from spaghetti_extractor.components.bisimulation_native_admission import native_admission_assurance
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_memory_access import access_fixture_source

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


def world():
    return _world_source(max_writes=2, max_private_writes=2, max_calls=1, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, service_bindings=[], private_ranges=(),
        image_size=0x4000, runtime_assurance=native_admission_assurance())


def fixture(body):
    return ('#include "state-machine-runtime.h"\n'
            '#define SPX_PROOF_IMAGE_BASE 0x400000U\n'
            '#define __CPROVER_uninterpreted_spx_native_residual_access residual_access\n' +
            access_fixture_source('') + world() + '''
uint32_t residual_access(uint32_t address,uint32_t width,uint32_t write_access) {
  uint32_t saved=spx_native_context_value.external_range_count;
  spx_native_context_value.external_range_count=0U;
  uint32_t allowed=write_access ? spx_native_write_allowed(address,width) :
                                 spx_native_read_allowed(address,width);
  spx_native_context_value.external_range_count=saved;
  return allowed;
}
static void setup(uint32_t live) {
  start();spx_proof_reset_worlds(0x800000U,256U);
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world,4096U,16U,1U,0U,1U)==SPX_BOUNDARY_OK,
      "create tracked proof allocation");
  spx_exact_world.allocations[0].native_rule_selector=1U;
  spx_exact_world.allocations[0].native_generation=1U;
  spx_exact_world.allocations[0].live=live;
  spx_source_world=spx_exact_world;
  spx_native_context_value.external_range_count=live;
  spx_native_context_value.external_ranges[0]=(spx_native_external_range){4096U,16U};
}
''' + body)


class NativeAdmissionTests(unittest.TestCase):
    def check(self, source):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            _write_cbmc_stdint(root/'stdint.h')
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            (root/'check.c').write_text(source)
            return run_cbmc_properties(command=[shutil.which('cbmc'),str(root/'check.c'),
                *runtime_assurance_defines(native_admission_assurance()),
                '--json-ui','--trace','--stop-on-fail','--unwind','6','--unwinding-assertions',
                '--bounds-check','--pointer-check','--signed-overflow-check','--undefined-shift-check',
                '--sat-solver','cadical'],timeout_seconds=40)

    def test_native_map_agreement_for_arbitrary_spans_and_allocation_liveness(self):
        result=self.check(fixture('''uint32_t nondet_u32(void);
int main(void) {
 uint32_t live=nondet_u32();__CPROVER_assume(live<=1U);setup(live);
 uint32_t address=nondet_u32(),width=nondet_u32();
 __CPROVER_assert(spx_proof_native_access(&spx_exact_world,address,width,0U)==
   spx_native_read_allowed(address,width),"native read admission correspondence");
 __CPROVER_assert(spx_proof_native_access(&spx_exact_world,address,width,1U)==
   spx_native_write_allowed(address,width),"native write admission correspondence");
}'''))
        self.assertEqual(result['status'],'satisfied',result)

    def test_memory_callbacks_check_permissions_before_private_history(self):
        result=self.check(fixture('''int main(void) {
 setup(1U);uint32_t fault=0U;
 spx_exact_world.private_low=spx_source_world.private_low=0U;
 spx_exact_world.private_high=spx_source_world.private_high=5120U;
 spx_proof_exact_write(0,0U,1U,255U,&fault);
 __CPROVER_assert(fault && !spx_exact_world.private_write_count && !spx_exact_world.write_count,
   "null write faults before private effects");
 spx_proof_source_write(0,0U,1U,255U,&fault);
 __CPROVER_assert(fault && !spx_source_world.private_write_count && !spx_source_world.write_count,
   "source null write follows same permission rule");
 (void)spx_proof_exact_read(0,0U,1U,&fault);
 __CPROVER_assert(fault,"null read faults despite private footprint");
 spx_proof_exact_write(0,4096U,1U,255U,&fault);
 __CPROVER_assert(!fault,"registered allocation remains writable");
 __CPROVER_assert(spx_proof_exact_read(0,4096U,1U,&fault)==255U && !fault,
   "permitted write preserves current byte");
 spx_proof_source_write(0,0x401000U,1U,255U,&fault);
 __CPROVER_assert(fault,"residual code mapping remains nonwritable");
 (void)spx_proof_source_read(0,0x401000U,1U,&fault);
 __CPROVER_assert(!fault,"residual code mapping remains readable");
 spx_proof_source_write(0,0x2000U,1U,255U,&fault);
 __CPROVER_assert(fault,"untracked nonnull address is not an automatic grant");
 (void)spx_proof_source_read(0,UINT32_MAX,1U,&fault);
 __CPROVER_assert(fault,"native exclusive end rule is retained");
}'''))
        self.assertEqual(result['status'],'satisfied',result)

    def test_priority_override_requires_its_explicit_contract_premise(self):
        result=self.check(fixture('''int main(void) {
 setup(1U);access_overrides[0]=2U;
 __CPROVER_assert(spx_proof_native_access(&spx_exact_world,4096U,1U,1U)==
   spx_native_write_allowed(4096U,1U),"dropping priority closure changes permission");
}'''))
        self.assertEqual(result['status'],'violated',result)
        self.assertEqual(result['detail'],'dropping priority closure changes permission',result)

    def test_release_correspondence_cannot_be_replaced_by_retained_bytes(self):
        result=self.check(fixture('''int main(void) {
 setup(0U);spx_native_context_value.external_range_count=1U;
 __CPROVER_assert(spx_proof_native_access(&spx_exact_world,4096U,1U,0U)==
   spx_native_read_allowed(4096U,1U),"stale native registration violates release correspondence");
}'''))
        self.assertEqual(result['status'],'violated',result)
        self.assertEqual(result['detail'],'stale native registration violates release correspondence',result)

    def test_unguarded_null_mapping_is_not_an_admissible_instantiation(self):
        result=self.check(fixture('''int main(void) {
 setup(0U);spx_native_context_value.stack_low=0U;
 __CPROVER_assert(spx_proof_native_access(&spx_exact_world,0U,1U,1U)==
   spx_native_write_allowed(0U,1U),"null closure premise is necessary");
}'''))
        self.assertEqual(result['status'],'violated',result)
        self.assertEqual(result['detail'],'null closure premise is necessary',result)

    def test_conditional_selection_requires_exact_contract_identity(self):
        good=native_admission_assurance()
        self.assertEqual(checked_implemented_runtime_assurance(good),good)
        for field,value in [('revision',2),('contract_sha256','0'*64)]:
            wrong=copy.deepcopy(good);wrong['contracts'][0][field]=value
            with self.assertRaises(BisimulationRefinementError):
                checked_implemented_runtime_assurance(wrong)

    def test_reachable_connected_summary_fails_until_context_transport_exists(self):
        generated='\n'.join(_connected_replay_source(
            [{'summary_id':0,'summary_capacity':1,'summary_strategy':'scalar-body-free-v1'}],
            max_writes=1,max_calls=1,max_atomics=1,runtime_assurance=native_admission_assurance()))
        # Compile the actual generated context accessor; the rest of the replay
        # implementation is unreachable and needs its separate supplier fixture.
        end=generated.index('uint32_t spx_proof_connected_is_replay(')
        common=('#include "state-machine-runtime.h"\n'
            'typedef struct {uint32_t replay;} spx_proof_world;\n'
            'static spx_proof_world spx_exact_world,spx_source_world;\n'+generated[:end])
        active=self.check(common+'''int main(void) {
 spx_runtime runtime={.context=&spx_source_world};
 spx_proof_connected_service_prefix service={&runtime};
 (void)spx_proof_connected_world(&service);
}''')
        self.assertEqual(active['status'],'violated',active)
        self.assertEqual(active['detail'],'spx-bisimulation-native-admission-summary-context-unqualified',active)
        inactive=self.check(common+'int main(void) { __CPROVER_assert(1,"unused supplier does not block a region"); }')
        self.assertEqual(inactive['status'],'satisfied',inactive)
