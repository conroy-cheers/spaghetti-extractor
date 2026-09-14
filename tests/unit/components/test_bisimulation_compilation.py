"""Fresh proof workspaces retain exact compiled identity and source semantics."""

import hashlib
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_execution import _run_compile
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class StableCompilationTests(unittest.TestCase):
    def test_complete_contextual_receipt_reuses_queries_in_a_fresh_workspace(self):
        if not all(shutil.which(name) for name in ('cbmc', 'goto-cc', 'bwrap')):
            self.skipTest('Nix compiler and namespace tools required')
        from tests.unit.components import test_bisimulation_normal_exits as fixture
        from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / 'first'
            first.mkdir()
            captured = {}
            def check(**kwargs):
                captured.update(kwargs)
                return check_bisimulation_refinement(**kwargs)
            with patch.object(fixture, 'check_bisimulation_refinement', side_effect=check):
                original = fixture.check_normal_exit(first, cbmc=Path(shutil.which('cbmc')))
            self.assertEqual(original['status'], 'satisfied', original)
            with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process',
                       side_effect=AssertionError('unchanged complete model executed a fresh query')):
                repeated = check_bisimulation_refinement(**{**captured,
                    'diagnostic_root': root / 'second', 'previous_query_evidence': first})
            self.assertEqual(repeated['status'], 'satisfied', repeated)
            self.assertEqual(original['checks'], repeated['checks'])

    def test_concurrent_workspaces_preserve_bytes_external_includes_and_file_strings(self):
        if not all(shutil.which(name) for name in ('cbmc', 'goto-cc', 'bwrap')):
            self.skipTest('Nix compiler and namespace tools required')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authored = root / 'authored'
            authored.mkdir()
            header = authored / 'value.h'
            header.write_text('#define VALUE 7U\n')
            source = authored / 'operation.c'
            source.write_text('#include "value.h"\n'
                              'unsigned operation(void) { return VALUE; }\n'
                              'const char *filename(void) { return __FILE__; }\n')
            def compile_at(name):
                workspace = root / name
                workspace.mkdir()
                unit = workspace / 'proof.c'
                unit.write_text(f'#include "{source}"\n'
                    'void check(void) { __CPROVER_assert(operation() == 7U, "result");\n'
                    '__CPROVER_assert(filename()[0] == 47, "authored absolute filename preserved"); }\n')
                model = workspace / 'model.goto'
                command = [shutil.which('goto-cc'), '--i386-win32', '-I', str(authored), str(unit), '-o', str(model)]
                self.assertIsNone(_run_compile(command, 30, workspace=workspace))
                return model
            with ThreadPoolExecutor(max_workers=2) as pool:
                first, second = list(pool.map(compile_at, ('first', 'second')))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            result = run_cbmc_properties(command=[shutil.which('cbmc'), str(first), '--json-ui',
                '--function', 'check'], timeout_seconds=15)
            self.assertEqual(result['status'], 'satisfied', result)
            header.write_text('#define VALUE 8U\n')
            changed = compile_at('changed')
            self.assertNotEqual(hashlib.sha256(first.read_bytes()).digest(),
                                hashlib.sha256(changed.read_bytes()).digest())
            result = run_cbmc_properties(command=[shutil.which('cbmc'), str(changed), '--json-ui',
                '--function', 'check'], timeout_seconds=15)
            self.assertEqual(result['status'], 'violated', result)
