"""Selected service domains and footprints must fit the hand-defined boundary."""
import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings, shared_service_contract_index
from .test_external_argument_domains import selected_service
from .test_shared_source_contracts import small_bundle, check_shared
from .test_hand_defined_boundaries import FIXTURE

TESTKIT = {'fixtures': ('cbmc','compiler'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text','profiles/pe32-user32-resource-text-runtime-v1.json')}


def binding():
    selected,behavior=selected_service()
    return {'service_id':'load_string','provider_kind':'external_call','argument_offsets':[0,4,8,12],
        'external_contract_identity_sha256':behavior.identity_sha256(),'abi_sha256':'a'*64,
        'external_effect_contract':{**selected.contract,'argument_words':4}}


class SharedServicePremiseTests(unittest.TestCase):
    def test_call_sites_do_not_change_the_local_service_premise(self):
        first=binding();second=copy.deepcopy(first)
        first['events']=[{'source_rva':1}];second['events']=[{'source_rva':2}]
        expected=normalize_shared_service_bindings(small_bundle(),[first])
        self.assertEqual(expected,normalize_shared_service_bindings(small_bundle(),[first,second]))
        second['external_contract_identity_sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'inconsistent'):
            normalize_shared_service_bindings(small_bundle(),[first,second])

    def test_unsupported_transport_and_footprint_arguments_reject(self):
        for mutation in ('offsets','transducer','scalar-base','view-size','missing'):
            row=binding()
            if mutation=='offsets':row['argument_offsets']=[0,4,12,8]
            elif mutation=='transducer':row['argument_transducers']=[{}]
            elif mutation=='scalar-base':row['external_effect_contract']['memory_footprints'][0]['base_argument']=0
            elif mutation=='view-size':row['external_effect_contract']['memory_footprints'][0]['size']['argument']=2
            else:row['service_id']='absent'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                normalize_shared_service_bindings(small_bundle(),[row])
        with self.assertRaises(ValueError):
            shared_service_contract_index(small_bundle(),[])

    def test_selected_domain_and_buffer_extent_are_proved_at_each_service_call(self):
        if not all(shutil.which(tool) for tool in ('goto-cc','goto-instrument','cbmc')):
            self.skipTest('CBMC tools unavailable')
        contracts=normalize_shared_service_bindings(small_bundle(),[binding()])
        original=(FIXTURE/'resource-text.c').read_text().replace('500U','8U')
        for count,expected in ((8,'satisfied'),(9,'incomplete'),(0,'incomplete')):
            with self.subTest(count=count),tempfile.TemporaryDirectory() as directory:
                result=check_shared(Path(directory),original.replace('8U',str(count)+'U'),service_contracts=contracts)
                self.assertEqual(result['status'],expected,
                    [(r.get('kind'),r.get('detail')) for r in result['checks']])
                if count!=8:
                    self.assertTrue(any(r.get('kind') in {'frame','input_dependence'} and r['status']=='violated'
                                        for r in result['checks']))
