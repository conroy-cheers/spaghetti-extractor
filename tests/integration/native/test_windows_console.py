"""Real CRT output and the reusable portable sink agree on a UTF-8 terminal."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from spaghetti_extractor.testkit import fixture

TESTKIT={'fixtures':('compiler','headless-wine','terminal-screen'),
         'resources':('src','tests/fixtures/portable-runtime','tests/fixtures/native')}


class WindowsConsoleTests(unittest.TestCase):
    def test_unicode_controls_wrapping_and_mixed_streams(self):
        compiler=fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        fixture('headless-wine')
        reader=fixture('terminal-screen')/'bin/terminal-screen'
        fixtures=Path(__file__).parents[2]/'fixtures';backend=fixtures/'portable-runtime'
        with tempfile.TemporaryDirectory(prefix='console-runtime-') as temporary:
            root=Path(temporary)
            for name in ('console-probe.c','windows-1252.c','windows-1252.h','windows-argv.c',
                         'windows-argv.h','windows-1252-best-fit.h'):
                shutil.copyfile(backend/name,root/name)
            shutil.copyfile(fixtures/'native/console-launch.c',root/'console-launch.c')
            commands=[
                [str(compiler),'-std=c11','-O2','-Wall','-Wextra','-Werror','-static','console-probe.c','-o','original.exe'],
                [str(compiler),'-std=c11','-O2','-Wall','-Wextra','-Werror','-static','-municode','console-launch.c','-o','console-launch.exe'],
                [shutil.which('cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','console-probe.c',
                 'windows-1252.c','windows-argv.c','-o','portable']]
            for command in commands:
                built=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=60)
                self.assertEqual(built.returncode,0,built.stderr)
            ran=subprocess.run([shutil.which('spaghetti-headless-wayland'),sys.executable,
                str(backend/'console-probe.py'),str(root),str(reader)],capture_output=True,text=True,timeout=180,
                env={**os.environ,'WINEDLLOVERRIDES':'mscoree,mshtml,winemenubuilder.exe='})
            details=(root/'mismatch.json').read_text() if (root/'mismatch.json').exists() else ''
            self.assertEqual(ran.returncode,0,ran.stderr+'\n'+details)
            result=json.loads((root/'console-probe.json').read_text())
            self.assertEqual(result['status'],'match');self.assertEqual(len(result['cases']),168)
            self.assertTrue(all(row['match'] for row in result['cases']))


if __name__=='__main__':unittest.main()
