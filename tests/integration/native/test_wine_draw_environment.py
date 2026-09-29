"""Candidate-neutral surfaces retain pixels, descriptor history and lifetimes."""
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


class WineDrawEnvironmentTests(unittest.TestCase):
    def test_surfaces_through_sdk_and_portable_bindings(self):
        compiler = fixture('compiler') / 'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine') / 'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='wine-draw-') as temporary:
            root = Path(temporary)
            backend = wine_test_backend()
            for path in [*backend['adapter_files'].values(), *backend['include_files'].values()]:
                shutil.copyfile(path, root / path.name)
            source = Path(__file__).resolve().parents[2] / 'fixtures/wine-draw/consumer.c'
            shutil.copyfile(source, root / 'consumer.c')
            for name, defines in [('sdk', []), ('binding', ['-DUSE_BINDING'])]:
                built = subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-static', *defines, 'consumer.c', *backend['adapter_files'], '-lddraw', '-luser32',
                    '-o', name + '.exe'], cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root / 'wine'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')

            def run(name, mode, expected=0):
                result = subprocess.run([str(runner), str(root / (name + '.exe')), mode],
                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, expected, result.stderr)
                return json.loads(result.stdout) if expected == 0 else result.stderr

            controlled = run('sdk', 'controlled')
            self.assertEqual(controlled, run('binding', 'controlled'))
            # Reconstruct every patch and verify all pixel bytes independently
            # of agreement between the two bindings.
            payloads = []
            unlocks = []
            for call in controlled['platform']['calls']:
                data = bytes.fromhex(call.get('data', ''))
                if 'data_ref' in call:
                    data = payloads[call['data_ref'] - 1]
                if 'data_delta_ref' in call:
                    data = bytearray(payloads[call['data_delta_ref'] - 1])
                    for patch in call['data_delta']:
                        value = bytes.fromhex(patch['data'])
                        data[patch['offset']:patch['offset'] + len(value)] = value
                    data = bytes(data)
                payloads.append(data)
                if bytes.fromhex(call['api']).decode() == 'IDirectDrawSurface.Unlock':
                    unlocks.append(data)
            self.assertEqual(unlocks[0], bytes([0x31]) * 180)
            expected = bytearray(unlocks[0])
            for y in range(1, 4):
                for x in range(1, 5):
                    expected[(y * 9 + x) * 4:(y * 9 + x + 1) * 4] = bytes.fromhex('78563400')
            self.assertEqual(unlocks[1], expected)
            self.assertEqual(unlocks[2], bytes([0x52]) * 16)
            for mode in ('negative', 'failures', 'native', 'borrowed'):
                self.assertEqual(run('sdk', mode), run('binding', mode))
            borrowed = run('sdk', 'borrowed')
            wrong = run('binding', 'borrowed-wrong-input')
            self.assertEqual(borrowed['platform']['calls'][0]['input_object'], 7)
            self.assertEqual(wrong['platform']['calls'][0]['input_object'], 8)
            defect = run('binding', 'defect')
            self.assertNotEqual(controlled['platform']['surfaces'], defect['platform']['surfaces'])
            for name in ('sdk', 'binding'):
                self.assertIn('surface lock event or flags', run(name, 'unsupported', 78))
                self.assertIn('expired DirectDraw receiver', run(name, 'expired', 78))
