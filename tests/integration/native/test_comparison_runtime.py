"""Actual Wine prefixes isolate sides and fresh runs while preserving suite state."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from spaghetti_extractor.testkit import fixture

TESTKIT = {'fixtures': ('compiler', 'headless-wine'),
           'resources': ('src', 'tests/fixtures/native/runtime-state.c',
                         'tests/fixtures/native/runtime-isolation.py')}


class ComparisonRuntimeTests(unittest.TestCase):
    def test_registry_and_relative_files_in_private_suite_shared_runtimes(self):
        compiler = fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        fixture('headless-wine')  # Owns Wine and the grouped headless desktop tools.
        desktop = shutil.which('spaghetti-headless-wayland')
        self.assertIsNotNone(desktop)
        native = Path(__file__).parents[2]/'fixtures/native'
        with tempfile.TemporaryDirectory(prefix='wine-runtime-') as temporary:
            root = Path(temporary)
            binary = root/'probe.exe'
            built = subprocess.run([str(compiler), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                str(native/'runtime-state.c'), '-ladvapi32', '-o', str(binary)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            for repeat in range(2):
                output = root/str(repeat)
                ran = subprocess.run([desktop, sys.executable, str(native/'runtime-isolation.py'),
                    str(binary), str(output)], capture_output=True, text=True, timeout=120,
                    env=dict(os.environ, WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe='))
                # This console-only fixture shares the other native tests'
                # offline profile; production keeps the caller's Wine settings.
                startup_logs = '\n'.join(f'{p.name}: {p.read_text(errors="replace")[-2000:]}'
                    for p in output.rglob('prefix-start-*.stderr'))
                self.assertEqual(ran.returncode, 0, ran.stderr+'\n'+startup_logs)
                result = json.loads((output/'isolation.json').read_text())
                self.assertEqual(result['status'], 'pass')
                self.assertEqual([row['observed'] for row in result['observations']],
                    [{'registry':0,'file':0}]*2 + [{'registry':1,'file':1}]*2)
                self.assertTrue(all(row['returncode']==0 and not row['timed_out']
                    and not row.get('cancelled',False) for row in result['timings'] if 'command' in row))
                self.assertEqual(len([row for row in result['timings']
                    if row['phase']=='runtime-startup-wall']), 1)
