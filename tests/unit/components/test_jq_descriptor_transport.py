"""A private descriptor change preserves native payload bits and live aliases."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

TESTKIT = {'fixtures': ('compiler',), 'resources': ('tests/fixtures/jq-array-storage',)}


class JqDescriptorTransportTests(unittest.TestCase):
    def test_native_and_unpacked_descriptors_preserve_metadata_payload_and_aliases(self):
        fixture = Path(__file__).resolve().parents[3] / 'tests/fixtures/jq-array-storage'
        reports = {}
        with tempfile.TemporaryDirectory() as temporary:
            for layout in ('value-layout.h', 'unpacked-value-layout.h'):
                with self.subTest(layout=layout):
                    binary = Path(temporary) / layout.removesuffix('.h')
                    compiled = subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(fixture), '-DVALUE_LAYOUT_HEADER="'+layout+'"',
                        str(fixture/'descriptor-roundtrip.c'), '-o', str(binary)], capture_output=True, text=True)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    executed = subprocess.run([str(binary)], capture_output=True, text=True)
                    self.assertEqual(executed.returncode, 0, executed.stderr)
                    reports[layout] = json.loads(executed.stdout)
                    self.assertEqual(reports[layout]['cases'], 46080)
                    self.assertTrue(reports[layout]['live_alias_preserved'])
        native, unpacked = reports['value-layout.h'], reports['unpacked-value-layout.h']
        self.assertEqual(native['native_size'], native['private_size'])
        self.assertNotEqual(unpacked['native_size'], unpacked['private_size'])
        self.assertNotEqual(unpacked['native_payload_offset'], unpacked['private_payload_offset'])
        self.assertEqual(native['native_size'], unpacked['native_size'])
        self.assertEqual(native['native_elements_offset'], unpacked['native_elements_offset'])
