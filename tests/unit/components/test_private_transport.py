"""Private byte transport rejects lost contents, wrong coordinates and stale aliases."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_private_transport import (
    cleanup_private_transport_domain, private_transport_header, check_private_transport_header, private_cell_layout,
)
from spaghetti_extractor.components.bisimulation_private_transport_template import TEMPLATE
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-entry/admission-excerpts.json'
TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('tests/fixtures/metapad-cleanup-entry',)}


class PrivateTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.models = json.loads(FIXTURE.read_text())['model_excerpts']
        cls.domain = cleanup_private_transport_domain(cls.models)

    def query(self, name, *, source=TEMPLATE, domain=None):
        root = self.root/name; root.mkdir()
        (root/'admission.c').write_text(source)
        (root/'private-layout.h').write_text(private_transport_header(self.domain if domain is None else domain))
        subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', 'admission.c',
            '--function', 'check_admission', '-o', 'model.goto'], cwd=root, capture_output=True, check=True)
        return run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function', 'check_admission',
            *checker_options(20, None)], cwd=root, timeout_seconds=90, output_prefix=root/'query')

    def test_inductive_byte_relation_and_real_saved_frame_pass(self):
        result = self.query('baseline')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        self.assertGreater(result['properties'], 100)
        self.assertEqual([len(self.domain['layouts'][n]['cells']) for n in ['entry', 'loop', 'tail']], [11, 3, 19])
        self.assertNotIn('spx_sub_', TEMPLATE)
        self.assertNotIn('authored.c', TEMPLATE)

    def test_discarding_unrepresented_private_bytes_is_not_transport(self):
        source = TEMPLATE.replace(' project(bytes,tail_cells,', ' bytes[0]=0U;\n project(bytes,tail_cells,')
        self.assertNotEqual(source, TEMPLATE)
        result = self.query('lost-byte', source=source)
        self.assertEqual(result['status'], 'violated')
        self.assertIn('cut-preserved-private-bytes', result['detail'])

    def test_wrong_stack_coordinate_breaks_the_saved_frame(self):
        domain = deepcopy(self.domain); domain['layouts']['loop']['anchor_delta'] += 4
        result = self.query('wrong-anchor', domain=domain)
        self.assertEqual(result['status'], 'violated')

    def test_wrong_scalar_store_cannot_change_the_independent_byte_store(self):
        source = TEMPLATE.replace('values[field]=width==4U ? value : value&((1U<<(8U*width))-1U);',
            'values[field]=(width==4U ? value : value&((1U<<(8U*width))-1U))^1U;')
        self.assertNotEqual(source, TEMPLATE)
        result = self.query('wrong-store', source=source)
        self.assertEqual(result['status'], 'violated')
        raw = json.loads((self.root/'wrong-store/query.stdout').read_text())
        failed = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
        self.assertIn('private-cell-byte-relation', failed)

    def test_overlapping_private_cells_need_coherent_alias_updates(self):
        domain = deepcopy(self.domain)
        domain['layouts']['entry']['cells'][1]['offset'] = domain['layouts']['entry']['cells'][0]['offset'] + 2
        result = self.query('stale-alias', domain=domain)
        self.assertEqual(result['status'], 'violated')
        self.assertIn('private-cell-byte-relation', result['detail'])

    def test_header_and_unsupported_accessor_changes_fail_closed(self):
        header = private_transport_header(self.domain)
        check_private_transport_header(header, self.domain)
        with self.assertRaisesRegex(ValueError, 'tables differ'):
            check_private_transport_header(header.replace('#define PRIVATE_SIZE 76U', '#define PRIVATE_SIZE 80U'), self.domain)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            check_private_transport_header(header+'__CPROVER_assume(0);\n', self.domain)
        with self.assertRaisesRegex(ValueError, 'unsupported cell effect'):
            private_cell_layout(self.models['entry'].replace('m->word_0=value;', 'm->word_0=value+1U;'), anchor_delta=0)
        with self.assertRaisesRegex(ValueError, 'narrows before'):
            private_cell_layout(self.models['entry'].replace('m->word_0=value;', 'm->word_0=(uint8_t)value;'), anchor_delta=0)
        with self.assertRaisesRegex(ValueError, 'guard precedence'):
            private_cell_layout(self.models['tail'].replace('m->stack-56', 'm->stack-60'), anchor_delta=-12)
        with self.assertRaisesRegex(ValueError, 'outside the checked writable'):
            private_cell_layout(self.models['tail']+'\nvoid service(struct machine *m){m->word_18=0U;}\n', anchor_delta=-12)
        with self.assertRaisesRegex(ValueError, 'address escapes'):
            private_cell_layout(self.models['tail']+'\nvoid service(struct machine *m){escape(&m->word_0);}\n', anchor_delta=-12)


if __name__ == '__main__':
    unittest.main()
