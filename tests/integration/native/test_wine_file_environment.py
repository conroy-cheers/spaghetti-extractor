"""File effects and lifetimes are shared by SDK and portable candidate binaries."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
from spaghetti_extractor.testkit import fixture

TESTKIT = {'fixtures': ('compiler', 'headless-wine')}


class WineFileEnvironmentTests(unittest.TestCase):
    def test_candidate_files_failures_preservation_and_lifetimes(self):
        compiler = fixture('compiler') / 'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine') / 'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='wine-files-') as temporary:
            root = Path(temporary)
            backend = wine_test_backend()
            for path in [*backend['adapter_files'].values(), *backend['include_files'].values()]:
                shutil.copyfile(path, root / path.name)
            source = Path(__file__).resolve().parents[2] / 'fixtures/wine-files/consumer.c'
            shutil.copyfile(source, root / 'consumer.c')
            (root / 'file.bin').write_bytes(bytes(range(12)))
            for name, defines in [('sdk', []), ('binding', ['-DUSE_BINDING'])]:
                built = subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-static', *defines, 'consumer.c', *backend['adapter_files'], '-ldsound', '-luser32',
                    '-o', name + '.exe'], cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root / 'wine'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')

            def run(name, mode, expected=0):
                result = subprocess.run([str(runner), str(root / (name + '.exe')), mode],
                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, expected, result.stderr)
                return json.loads(result.stdout) if not expected else result.stderr

            controlled = run('sdk', 'controlled')
            self.assertEqual(controlled, run('binding', 'controlled'))
            self.assertNotEqual(controlled, run('binding', 'defect'))
            leak = run('binding', 'leak')
            self.assertEqual([h['live'] for h in controlled['platform']['file_handles']], [0, 1])
            self.assertEqual([h['live'] for h in leak['platform']['file_handles']], [1, 1])
            reads = [c for c in controlled['platform']['calls'] if bytes.fromhex(c['api']) == b'ReadFile']
            self.assertEqual(reads[1]['transferred'], 2)
            self.assertEqual(reads[1]['written_mask'], 255)
            self.assertEqual(reads[2]['transferred'], 0)
            self.assertEqual(reads[2]['written_mask'], 0)
            self.assertTrue(all(c['preserved'] and c['output_preserved'] for c in reads))
            self.assertEqual(reads[-1]['byte_mask_runs'], [[12, 255], [1012, 0]])
            self.assertEqual(bytes.fromhex(reads[-1]['data']), bytes(range(12)) + bytes(1012))
            for mode in ('native', 'incoming', 'native-incoming', 'security', 'native-security', 'native-unbound'):
                observed = run('sdk', mode)
                self.assertEqual(observed, run('binding', mode))
                if 'incoming' in mode:
                    self.assertEqual(observed['platform']['calls'][0]['position_before'], 2)
                if mode == 'native-unbound':
                    self.assertEqual(observed['platform']['calls'][-1]['handle_known'], 0)
            for name in ('sdk', 'binding'):
                self.assertIn('synchronous', run(name, 'unsupported', 78))
                self.assertIn('unbound handle', run(name, 'native-unbound-strict', 78))
