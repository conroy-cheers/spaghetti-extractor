"""Two candidate binaries share platform interception, including buffer contents."""
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


class WineTestEnvironmentTests(unittest.TestCase):
    def test_candidate_bindings_memory_failures_and_real_wine(self):
        compiler = fixture('compiler') / 'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine') / 'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='wine-services-') as temporary:
            root = Path(temporary)
            backend = wine_test_backend()
            for path in [*backend['adapter_files'].values(), *backend['include_files'].values()]:
                shutil.copyfile(path, root / path.name)
            source = Path(__file__).resolve().parents[2] / 'fixtures/wine-sound/consumer.c'
            shutil.copyfile(source, root / 'consumer.c')
            for name, defines in [('sdk', []), ('binding', ['-DUSE_BINDING'])]:
                built = subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-static', *defines, 'consumer.c', *backend['adapter_files'], '-ldsound', '-luser32',
                    '-o', name + '.exe'], cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root / 'wine'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')

            def run(name, mode):
                result = subprocess.run([str(runner), str(root / (name + '.exe')), mode],
                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)

            controlled = run('sdk', 'controlled')
            self.assertEqual(controlled, run('binding', 'controlled'))
            defect = run('binding', 'defect')
            self.assertNotEqual(controlled, defect)
            changed = [(a, b) for a, b in zip(controlled['platform']['calls'], defect['platform']['calls']) if a != b]
            self.assertEqual(len(changed), 1)
            reference, offset, size = changed[0][0]['data_slice_ref']
            read = bytes.fromhex(controlled['platform']['calls'][reference - 1]['data'])
            self.assertEqual((offset, size), (11, 16))
            self.assertEqual(read[offset:offset + size], bytes([0x38]) * 8 + bytes([0x71]) * 8)
            self.assertNotEqual(read[offset:offset + size], bytes.fromhex(changed[0][1]['data']))
            wrong_window = run('binding', 'wrong-window')
            changed = [(a, b) for a, b in zip(controlled['platform']['calls'], wrong_window['platform']['calls']) if a != b]
            self.assertEqual(len(changed), 1)
            self.assertEqual((changed[0][0]['window'], changed[0][1]['window']), (1, 2))
            self.assertEqual(run('sdk', 'native'), run('binding', 'native'))
            for name in ('sdk', 'binding'):
                result = subprocess.run([str(runner), str(root / (name + '.exe')), 'unsupported'],
                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 78, result.stderr)
                self.assertIn('IDirectSoundBuffer.GetCaps', result.stderr)
