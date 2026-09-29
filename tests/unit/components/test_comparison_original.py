"""Operator-selected original ranges use the existing semantic recovery pipeline."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

from spaghetti_extractor.components.comparison_original import native_entry_header, recover_original_c
from spaghetti_extractor.util import sha256_file
from tests.pe_fixtures import pe32_image


class OriginalRecoveryTests(unittest.TestCase):
    def test_native_entry_uses_reviewed_range_and_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            original=Path(directory)/'original.exe'
            original.write_bytes(pe32_image(bytes.fromhex('8b4c240431c001c84975fbc3')))
            arguments=dict(original=original,expected_sha256=sha256_file(original),
                module='original.dll',entry_rva=0x1000,end_rva=0x100c)
            header=native_entry_header(**arguments)
            self.assertIn('prefix[5]={0x8b,0x4c,0x24,0x04,0x31}',header)
            self.assertIn('saved[12]',header)
            self.assertIn('image+0x1000',header)
            self.assertIn('hook->entry[i]!=0xcc',header)
            with self.assertRaisesRegex(ValueError,'digest'):
                native_entry_header(**{**arguments,'expected_sha256':'0'*64})
            with self.assertRaisesRegex(ValueError,'five bytes'):
                native_entry_header(**{**arguments,'end_rva':0x1004})
            with self.assertRaisesRegex(ValueError,'executable bytes'):
                native_entry_header(**{**arguments,'end_rva':0x3000})

    def test_native_entry_keeps_relocated_words_and_disjoint_cold_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            original=Path(directory)/'original.exe'
            code=(b'\x55\xb8'+struct.pack('<I',0x403000)).ljust(0x20,b'\x90')
            code+=struct.pack('<IIHH',0x1000,12,0x3002,0)
            data=bytearray(pe32_image(code))
            struct.pack_into('<II',data,0x98+96+5*8,0x1020,12)
            struct.pack_into('<H',data,0x96,0x010e)  # Relocations are present.
            original.write_bytes(data)
            arguments=dict(original=original,expected_sha256=sha256_file(original),
                module=None,entry_rva=0x1000,end_rva=0x1010,additional_ranges=((0x1010,0x1013),))
            header=native_entry_header(**arguments)
            self.assertIn('prefix[6]={0x55,0xb8,0x00,0x30,0x40,0x00}',header)
            self.assertIn('0x00403000U+(uint32_t)(uintptr_t)image-0x00400000U',header)
            self.assertIn('memcpy(prefix+2,&address,4)',header)
            self.assertIn('fragment=image+0x1010',header)
            self.assertIn('memset(fragment,0xcc,3)',header)
            self.assertIn('i=0x1010;i<0x1013',header)
            self.assertIn('GetModuleHandleA(NULL)',header)
            with self.assertRaisesRegex(ValueError,'overlap'):
                native_entry_header(**{**arguments,'additional_ranges':((0x100f,0x1013),)})
            with self.assertRaisesRegex(ValueError,'manual C binding'):
                native_entry_header(**{**arguments,'end_rva':0x1005})
            struct.pack_into('<H',data,0x200+0x20+8,0x1002)
            original.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'manual C binding'):
                native_entry_header(**{**arguments,'expected_sha256':sha256_file(original)})

    def test_selected_loop_retains_original_instructions_and_source_locations(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=root/'original.exe'
            original.write_bytes(pe32_image(bytes.fromhex('8b4c240431c001c84975fbc3')))
            report=recover_original_c(original=original,expected_sha256=sha256_file(original),
                boundaries={0x1000:[(0x1000,0x1006),(0x1006,0x100b),(0x100b,0x100c)]},output=root/'recovered')
            self.assertEqual(set(report['source_map']),{0x1000,0x1006,0x100b})
            for row in report['source_map'].values():
                self.assertTrue((root/'recovered'/row['file']).is_file())
                self.assertGreaterEqual(row['line_end'],row['line_start'])
            rows=json.loads((root/'recovered/semantic-inputs.json').read_text())
            self.assertTrue(all(row['status']=='reimplementable' for row in rows))
            self.assertEqual(sha256_file(root/'recovered/behavioral-fn-00001000.c'),
                report['files']['behavioral-fn-00001000.c'])
            self.assertFalse(report['strong_qualification'])

    def test_bad_selection_or_unsupported_instruction_does_not_publish_c(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=root/'original.exe'
            original.write_bytes(pe32_image(bytes.fromhex('0f0b')))
            common=dict(original=original,expected_sha256=sha256_file(original),output=root/'recovered')
            with self.assertRaisesRegex(ValueError,'overlap'):
                recover_original_c(boundaries={0x1000:[(0x1000,0x1002),(0x1001,0x1002)]},**common)
            with self.assertRaisesRegex(ValueError,'0x1000.*ud2'):
                recover_original_c(boundaries={0x1000:[(0x1000,0x1002)]},**common)
            self.assertFalse((root/'recovered').exists())


if __name__=='__main__':unittest.main()
