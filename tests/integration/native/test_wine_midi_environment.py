"""Queued MIDI, callbacks and failure effects are candidate-neutral services."""
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


class WineMidiEnvironmentTests(unittest.TestCase):
    def test_stream_completion_reset_and_candidate_bindings(self):
        compiler = fixture('compiler') / 'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine') / 'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='wine-midi-') as temporary:
            root = Path(temporary)
            backend = wine_test_backend()
            for path in [*backend['adapter_files'].values(), *backend['include_files'].values()]:
                shutil.copyfile(path, root / path.name)
            source = Path(__file__).resolve().parents[2] / 'fixtures/wine-midi/consumer.c'
            shutil.copyfile(source, root / 'consumer.c')
            for name, defines in [('sdk', []), ('binding', ['-DUSE_BINDING']), ('plain', ['-DNO_INTERCEPTION'])]:
                built = subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-static', *defines, 'consumer.c', *backend['adapter_files'], '-ldsound', '-luser32', '-lwinmm',
                    '-o', name + '.exe'], cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root / 'wine'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')

            def run(name, mode, expected=0):
                result = subprocess.run([str(runner), str(root / (name + '.exe')), mode],
                    cwd=root, env=environment, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, expected, result.stderr)
                return json.loads(result.stdout) if not expected else result.stderr

            for mode in ('controlled', 'failures'):
                observed = run('sdk', mode)
                self.assertEqual(observed, run('binding', mode))
                self.assertEqual(observed['done'], 3)
                self.assertTrue(all(not h['prepared'] and not h['queued'] for h in observed['platform']['midi_headers']))
            calls = run('binding', 'controlled')['platform']['calls']
            references = [c['data_ref'] for c in calls if 'data_ref' in c]
            self.assertTrue(references)
            self.assertTrue(all(bytes.fromhex(calls[i - 1]['data']) == bytes(11) + b'\x02' for i in references))
            corrupted = run('binding', 'payload-defect')['platform']['calls']
            self.assertTrue(any(c.get('data') == (bytes(4) + b'\x01' + bytes(6) + b'\x02').hex() for c in corrupted))
            self.assertEqual(run('binding', 'defect')['done'], 2)
            publication = run('sdk', 'failed-publication')
            self.assertEqual(publication, run('binding', 'failed-publication'))
            self.assertTrue(publication['open_published'])
            self.assertFalse(publication['platform']['midi_streams'][0]['live'])
            deferred = run('sdk', 'deferred-reset')
            self.assertEqual(deferred, run('binding', 'deferred-reset'))
            self.assertEqual(deferred['cleanup_results'], [65, 65])
            self.assertTrue(all(h['prepared'] and h['storage_retired'] and not h['queued']
                                for h in deferred['platform']['midi_headers']))
            disposed = run('sdk', 'unsafe-free-record')
            self.assertEqual(disposed, run('binding', 'unsafe-free-record'))
            self.assertTrue(disposed['platform']['midi_invalid_disposal_experiment'])
            self.assertTrue(all(h['queued'] and h['storage_retired'] and h['storage_invalid_disposal']
                                for h in disposed['platform']['midi_headers']))
            translated = run('sdk', 'header-storage')
            self.assertEqual(translated, run('binding', 'header-storage'))
            self.assertTrue(all(h['storage_retired'] and not h['queued']
                                for h in translated['platform']['midi_headers']))
            for mode in ('native', 'native-reset'):
                native = run('sdk', mode)
                self.assertEqual(native, run('binding', mode))
                plain = run('plain', mode)
                self.assertEqual({k: v for k, v in native.items() if k != 'platform'},
                                 {k: v for k, v in plain.items() if k != 'platform'})
            for name in ('sdk', 'binding'):
                for mode, diagnostic in [('bad-schedule', 'next queued header'),
                                         ('unsafe-free', 'MIDI-retained'), ('unsupported', 'null or function'),
                                         ('retired-callback', 'header storage has been retired'),
                                         ('retired-api', 'header storage was disposed'),
                                         ('header-storage-bounds', 'binding exceeds allocation'),
                                         ('header-storage-move', 'cannot move retained')]:
                    self.assertIn(diagnostic, run(name, mode, 78))
