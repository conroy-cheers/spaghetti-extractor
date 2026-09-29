"""Shared runtime lifecycle: cleanup on startup failure, cancellation and timeout."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.comparison_runtime import wine_sessions


class WineSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prefix = self.root/'prefix'
        self.prefix.mkdir()
        self.server = self.root/'server'
        self.server.write_text('#!'+sys.executable+'\n'
            'import os,sys,time\n'
            'from pathlib import Path\n'
            'prefix=Path(os.environ["WINEPREFIX"])\n'
            'with (prefix/"calls").open("a") as f: f.write(sys.argv[1]+"\\n")\n'
            'if sys.argv[1]==os.environ.get("FAIL_FLAG"): sys.exit(3)\n'
            'if sys.argv[1]==os.environ.get("HANG_FLAG"): time.sleep(10)\n')
        self.server.chmod(0o755)
        self.environment = {**os.environ, 'WINEPREFIX':str(self.prefix)}
        self.timings = []
        # Stand-in executable only: this test launches no Wine application.
        self.wayland = patch.dict(os.environ, {'WAYLAND_DISPLAY':'test-headless'})
        self.wayland.start()
        self.addCleanup(self.wayland.stop)

    def session(self, persistent=True):
        return wine_sessions(server=str(self.server), environments={'case':self.environment},
            cwd=self.root, logs=self.root, timeout=0.15, timings=self.timings,
            persistent=persistent)

    def calls(self):
        return (self.prefix/'calls').read_text().splitlines()

    def test_explicit_persistence_and_cleanup(self):
        with self.session():
            self.assertEqual(self.calls(), ['-p'])
        self.assertEqual(self.calls(), ['-p','-k','-w'])
        self.assertEqual([r['phase'] for r in self.timings], ['runtime-setup','runtime-teardown','runtime-teardown'])

    def test_startup_failure_still_cleans_up(self):
        self.environment['FAIL_FLAG']='-p'
        with self.assertRaisesRegex(ValueError,'startup failed'):
            with self.session():
                self.fail('entered failed runtime')
        self.assertEqual(self.calls(), ['-p','-k','-w'])

    def test_cleanup_timeout_is_bounded_and_wait_still_runs(self):
        self.environment['HANG_FLAG']='-k'
        start=time.monotonic()
        with self.assertRaisesRegex(ValueError,'cleanup failed'):
            with self.session():
                pass
        self.assertLess(time.monotonic()-start,2)
        self.assertEqual(self.calls(), ['-p','-k','-w'])
        self.assertTrue(self.timings[1]['timed_out'])

    def test_cancellation_restores_signal_handler_and_cleans_up(self):
        original=signal.getsignal(signal.SIGTERM)
        with self.assertRaises(SystemExit) as caught:
            with self.session():
                os.kill(os.getpid(),signal.SIGTERM)
        self.assertEqual(caught.exception.code,143)
        self.assertEqual(signal.getsignal(signal.SIGTERM),original)
        self.assertEqual(self.calls(), ['-p','-k','-w'])

    def test_body_failure_is_not_hidden_by_cleanup_failure(self):
        self.environment['FAIL_FLAG']='-w'
        with self.assertRaisesRegex(RuntimeError,'body failed') as caught:
            with self.session():
                raise RuntimeError('body failed')
        self.assertIn('cleanup failed',caught.exception.__notes__[0])
        self.assertEqual(self.calls(), ['-p','-k','-w'])

    def test_nonpersistent_session_still_owns_teardown(self):
        with self.session(persistent=False):
            self.assertFalse((self.prefix/'calls').exists())
        self.assertEqual(self.calls(), ['-k','-w'])

    def test_no_desktop_or_shared_prefix_is_rejected_before_launch(self):
        with patch.dict(os.environ,{'WAYLAND_DISPLAY':''}):
            with self.assertRaisesRegex(ValueError,'headless Wayland'):
                with self.session():
                    self.fail('ran outside desktop')
        with self.assertRaisesRegex(ValueError,'distinct'):
            with wine_sessions(server=str(self.server), environments={'a':self.environment,'b':self.environment},
                    cwd=self.root, logs=self.root,timeout=0.1,timings=[],persistent=True):
                self.fail('shared comparison prefix')
        self.assertFalse((self.prefix/'calls').exists())

    def test_disposable_prefix_removed_only_after_successful_shutdown(self):
        with wine_sessions(server=str(self.server), environments={'case':self.environment},
                cwd=self.root,logs=self.root,timeout=0.15,timings=self.timings,
                persistent=False,dispose_prefixes=True):
            (self.prefix/'scratch').write_text('disposable')
        self.assertFalse(self.prefix.exists())
        self.assertEqual(self.timings[-1]['phase'],'runtime-disposal')
        self.assertTrue((self.root/'server-wait-case.stdout').exists())
        self.prefix.mkdir()
        self.environment['FAIL_FLAG']='-w'
        with self.assertRaisesRegex(ValueError,'cleanup failed'):
            with wine_sessions(server=str(self.server), environments={'case':self.environment},
                    cwd=self.root,logs=self.root,timeout=0.15,timings=[],
                    persistent=False,dispose_prefixes=True):
                pass
        self.assertTrue(self.prefix.exists())

    def test_host_runtime_also_unwinds_on_sigterm(self):
        original=signal.getsignal(signal.SIGTERM)
        with self.assertRaises(SystemExit) as caught:
            with wine_sessions(server=None,environments={},cwd=self.root,logs=self.root,
                    timeout=0.1,timings=[],persistent=False):
                os.kill(os.getpid(),signal.SIGTERM)
        self.assertEqual(caught.exception.code,143)
        self.assertEqual(signal.getsignal(signal.SIGTERM),original)

    def paired_boot(self, *, mode='pass', timeout=2, runner=None):
        peer = self.root/'peer'
        peer.mkdir()
        boot = self.root/'boot'
        boot.write_text('#!'+sys.executable+'\n'+'''
import os, signal, time
from pathlib import Path
prefix = Path(os.environ['WINEPREFIX'])
(prefix/'boot.pid').write_text(str(os.getpid()))
(prefix/'started').touch()
deadline = time.monotonic() + 1
while not (Path(os.environ['PEER'])/'started').exists():
    if time.monotonic() > deadline: raise SystemExit(8)
    time.sleep(0.002)
mode = os.environ.get('BOOT_MODE', 'pass')
if mode == 'fail': raise SystemExit(7)
if mode == 'hang': time.sleep(10)
if mode == 'cancel':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.kill(int(os.environ['PARENT']), signal.SIGTERM)
    time.sleep(0.05)
    os.kill(int(os.environ['PARENT']), signal.SIGTERM)
time.sleep(0.1)
(prefix/'finished').touch()
print('ready')
''')
        boot.chmod(0o755)
        # Teardown must never race a still-running boot, on either side.
        with self.server.open('a') as script:
            script.write('''
if sys.argv[1] == '-k' and (prefix/'boot.pid').exists():
    try: os.kill(int((prefix/'boot.pid').read_text()), 0)
    except ProcessLookupError: pass
    else: sys.exit(9)
''')
        environments = {
            'original': {**self.environment, 'PEER':str(peer), 'BOOT_MODE':mode, 'PARENT':str(os.getpid())},
            'source': {**self.environment, 'WINEPREFIX':str(peer), 'PEER':str(self.prefix)},
        }
        return wine_sessions(server=str(self.server), environments=environments,
            cwd=self.root, logs=self.root, timeout=timeout, timings=self.timings,
            persistent=False, dispose_prefixes=True, runner=str(runner or boot))

    def assert_boot_cleanup(self):
        self.assertFalse(self.prefix.exists())
        self.assertFalse((self.root/'peer').exists())
        teardown = [row for row in self.timings if row['phase']=='runtime-teardown']
        self.assertEqual(len(teardown), 4)
        self.assertTrue(all(row['returncode']==0 and not row['timed_out'] for row in teardown))

    def test_prefix_boots_overlap_but_both_finish_before_cases(self):
        # The rendezvous fails under serial startup; no wall-time threshold is
        # needed to establish concurrency or to allow a loaded test machine.
        with self.paired_boot():
            self.assertTrue((self.prefix/'finished').exists())
            self.assertTrue((self.root/'peer/finished').exists())
        self.assert_boot_cleanup()
        startup = [row for row in self.timings if row['phase']=='runtime-startup']
        self.assertEqual([row['runtime'] for row in startup], ['original','source'])
        wall = [row for row in self.timings if row['phase']=='runtime-startup-wall']
        self.assertEqual(len(wall), 1)
        self.assertEqual(wall[0]['max_concurrency'], 2)
        self.assertEqual(wall[0]['overlaps'], ['runtime-startup'])

    def test_failed_boot_joins_peer_before_teardown(self):
        with self.assertRaisesRegex(ValueError, 'startup failed for original'):
            with self.paired_boot(mode='fail'):
                self.fail('entered failed runtime')
        self.assertTrue((self.root/'prefix-start-source.stdout').is_file())
        startup = [row for row in self.timings if row['phase']=='runtime-startup']
        self.assertTrue(startup[1]['cancelled'])
        self.assert_boot_cleanup()

    def test_boot_timeout_retains_both_logs_and_cleans_up(self):
        with self.assertRaisesRegex(ValueError, 'startup failed for original'):
            with self.paired_boot(mode='hang', timeout=0.5):
                self.fail('entered timed-out runtime')
        startup = [row for row in self.timings if row['phase']=='runtime-startup']
        self.assertEqual([row['timed_out'] for row in startup], [True,False])
        self.assertTrue((self.root/'prefix-start-original.stderr').is_file())
        self.assertEqual((self.root/'prefix-start-source.stdout').read_text(), 'ready\n')
        self.assert_boot_cleanup()

    def test_cancellation_during_parallel_boot_joins_before_cleanup(self):
        original = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(SystemExit) as caught:
            with self.paired_boot(mode='cancel'):
                self.fail('entered cancelled runtime')
        self.assertEqual(caught.exception.code, 143)
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)
        for side in ('original','source'):
            self.assertTrue((self.root/f'prefix-start-{side}.stdout').is_file())
        startup = [row for row in self.timings if row['phase']=='runtime-startup']
        self.assertTrue(any(row['cancelled'] for row in startup))
        self.assert_boot_cleanup()

    def test_boot_launch_error_still_disposes_both_owned_prefixes(self):
        with self.assertRaises(FileNotFoundError):
            with self.paired_boot(runner=self.root/'missing'):
                self.fail('entered failed runtime')
        self.assert_boot_cleanup()
