"""Mapped bytes and allocation lifetimes use the same backend for every candidate."""
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


class WineStorageEnvironmentTests(unittest.TestCase):
    def test_mapping_and_locked_storage_consumers(self):
        compiler = fixture('compiler') / 'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine') / 'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='wine-storage-') as temporary:
            root = Path(temporary)
            backend = wine_test_backend()
            for path in [*backend['adapter_files'].values(), *backend['include_files'].values()]:
                shutil.copyfile(path, root / path.name)
            source = Path(__file__).resolve().parents[2] / 'fixtures/wine-storage/consumer.c'
            shutil.copyfile(source, root / 'consumer.c')
            (root / 'file.bin').write_bytes(bytes([3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8]))
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

            for mode in ('controlled', 'failures', 'native'):
                observed = run('sdk', mode)
                self.assertEqual(observed, run('binding', mode))
                self.assertTrue(all(not x['live'] for x in observed['platform']['allocations']))
                self.assertEqual([x['live'] for x in observed['platform']['mapped_views']], [0, 0, 0])
            leak = run('binding', 'leak')
            self.assertEqual([x['live'] for x in leak['platform']['mapped_views']], [0, 1, 0])
