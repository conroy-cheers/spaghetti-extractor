"""Finite source prefixes transport freshly created locals and retain call obligations."""
import unittest

from spaghetti_extractor.components.bisimulation_source_region_transport import check_source_region_observer_transport
from spaghetti_extractor.components.bisimulation_source_region_calls import match_source_region_calls
from .test_source_region_transport import SourceRegionTransportTests

TESTKIT={'fixtures':('cbmc','compiler')}
BODY='''uint32_t run(int value) {
 BEGIN;
 CUT(entry);
 uint32_t count=0;
 uint8_t a;
 int (*callback)(uint32_t,uint8_t*)=read_byte;
 for (uint32_t k=0;k<2U;++k) {
  if(callback(count,&a))return 0xFFFFFFFFU;
  ++count;
 }
 CUT(next);
 return count;
}
'''
LOCAL='''static void observe(uint32_t cut,uint32_t count,const uint8_t *a){
 __CPROVER_assert(cut==3U && count==2U && a!=0,"prefix-exit");
}
#define BEGIN do {} while (0)
#define CUT(id) LOCAL_##id
#define LOCAL_entry __CPROVER_assert(1,"source-cut-invariant")
#define LOCAL_next do {__CPROVER_assert(1,"source-cut-invariant:next"); observe(3U,count,&a);return 3U;} while (0)
'''


class SourceEntryObserverTests(unittest.TestCase):
    inventories=SourceRegionTransportTests.inventories

    def check(self,*,local=LOCAL,body=BODY,original_body=BODY,captured=('run::1::count','run::1::a'),control_graph=True):
        return check_source_region_observer_transport(**self.inventories(local=local,body=body,original_body=original_body),
            function='run',entry_sync='entry',restored_locals={},cut_results={'next':3},observer='observe',
            observer_arguments=[('run::1::count',False),('run::1::a',True)],captured_locals=captured,control_graph=control_graph)

    def test_finite_prefix_and_computed_calls_need_separate_execution_evidence(self):
        result=self.check()
        self.assertTrue(result['control_graph_only'])
        self.assertFalse(result['execution_obligations_checked'])
        self.assertFalse(result['authorizing'])
        inventory=result['dependency_inventory']
        self.assertFalse(inventory['acyclic'])
        self.assertFalse(inventory['progress_checked'])
        self.assertFalse(inventory['invocation_multiplicity_checked'])
        self.assertTrue(inventory['cycle_frontiers'])
        self.assertEqual([r['callee'] for r in inventory['calls']],[None])
        with self.assertRaisesRegex(ValueError,'cannot reuse single-invocation'):
            match_source_region_calls(inventory,prefix_calls=[r['payload'] for r in inventory['calls']])

    def test_default_transport_still_requires_direct_acyclic_calls(self):
        with self.assertRaisesRegex(ValueError,'indirect call|progress rule'):
            self.check(control_graph=False)

    def test_changed_iteration_count_does_not_match_the_original_body(self):
        with self.assertRaisesRegex(ValueError,'body instruction differs'):
            self.check(body=BODY.replace('k<2U','k<3U'))

    def test_capture_must_be_declared_and_use_the_actual_outgoing_local(self):
        with self.assertRaisesRegex(ValueError,'not a selected automatic'):
            self.check(captured=())
        with self.assertRaisesRegex(ValueError,'different local'):
            self.check(local=LOCAL.replace('observe(3U,count,&a)','observe(3U,count+1U,&a)'))

    def test_persistent_storage_is_not_an_automatic_outgoing_capture(self):
        body=BODY.replace('uint32_t count=0','static uint32_t count=0')
        with self.assertRaisesRegex(ValueError,'matching automatic storage'):
            self.check(body=body,original_body=body)

    def test_unknown_and_duplicate_outgoing_captures_fail_closed(self):
        for captures in [('run::1::missing','run::1::a'),('run::1::count','run::1::count')]:
            with self.subTest(captures=captures),self.assertRaisesRegex(ValueError,'outgoing'):
                self.check(captured=captures)
