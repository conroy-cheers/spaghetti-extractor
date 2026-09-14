"""Finite actual-service validation of the real save and UI consumer network.

These tests execute retained original callers and ordinary C with the production
cleanup adapters. Explicit image mapping, fixture-owned stack admission and a
controlled EDIT subclass remain explicit; passing does not qualify arbitrary caller reachability,
UI reentrancy/nonreturn, or replace the conditional local proofs.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from spaghetti_extractor.testkit import fixture
from tests.integration.native.consumer_runtime_adapter import FIXTURE, prepare

TESTKIT = {'fixtures': ('compiler', 'headless-wine'),
    'resources': ('tests/fixtures/metapad-consumer-runtime', 'tests/fixtures/metapad-cleanup-runtime',
                  'tests/fixtures/metapad-authored-call', 'tests/fixtures/metapad-cleanup-save',
                  'tests/fixtures/metapad-cleanup-replace', 'tests/fixtures/native-image-shared-transport',
                  'tests/fixtures/hand-defined-boundaries/resource-text')}
SOURCES = ['runtime-test.c', 'cleanup.c', 'portable-reference-runtime.c',
    'original-save/behavioral-fn-00005c2a.c', 'original-replace/behavioral-fn-0000b18e.c',
    'original-replace/behavioral-support.c', 'save/bridge.c', 'save/prepare-save.c',
    'replace/bridge.c', 'replace/replace-selection.c', 'resource/bridge.c', 'resource/resource-text.c']


class ConsumerRuntimeAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='consumer-runtime-adapter-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        start = time.monotonic()
        prepare(cls.root)
        print(json.dumps({'consumer_runtime_timing':{'phase':'preparation','seconds':time.monotonic()-start}}))
        cls.compiler = fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        cls.runner = fixture('headless-wine')/'bin/spaghetti-headless-wine'
        cls.environment = dict(os.environ, WINEPREFIX=str(cls.root/'wine-prefix'), WINEDEBUG='-all',
            WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')

    def compile(self, name, replacements=None):
        sources = list(SOURCES)
        for original, text in (replacements or {}).items():
            file = Path(original); changed = file.with_name(name+'-'+file.name)
            (self.root/changed).write_text(text)
            sources[sources.index(original)] = str(changed)
        objects = []; start = time.monotonic()
        for index, source in enumerate(sources):
            obj = name+'-'+str(index)+'.o'; objects.append(obj)
            result = subprocess.run([str(self.compiler), '-std=c11', '-O1', '-include', 'stdint.h', '-I', '.',
                '-Werror=incompatible-pointer-types', '-c', source, '-o', obj],
                cwd=self.root, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
        print(json.dumps({'consumer_runtime_timing':{'phase':'compiler','case':name,'seconds':time.monotonic()-start}}))
        start = time.monotonic()
        result = subprocess.run([str(self.compiler), '-Wl,--image-base,0x10000000', *objects, '-o', name+'.exe'],
                                cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        print(json.dumps({'consumer_runtime_timing':{'phase':'link','case':name,'seconds':time.monotonic()-start}}))
        return self.root/(name+'.exe')

    def run_fixture(self, exe, error=None):
        start = time.monotonic()
        result = subprocess.run([str(self.runner), str(exe)], capture_output=True, text=True,
            timeout=60, env=self.environment)
        print(json.dumps({'consumer_runtime_timing':{'phase':'runtime','case':exe.stem,
            'seconds':time.monotonic()-start,'returncode':result.returncode}}))
        self.assertEqual(result.returncode, 0 if error is None else 42, result.stderr)
        if error is None:
            self.assertIn('15 cases, 30 original/C runs', result.stdout)
        else:
            self.assertIn('CONTRACT MISMATCH: '+error, result.stderr)

    def test_actual_consumers_current_memory_ui_results_and_lifetimes(self):
        self.run_fixture(self.compile('baseline'))

    def test_window_read_before_cleanup_misses_real_focus_callback_update(self):
        file = 'replace/replace-selection.c'; source = (self.root/file).read_text()
        start, end = source.index('  uint64_t window;'), source.index('  uint32_t result =')
        block = source[start:end]; changed = source[:start]+source[end:]
        changed = changed.replace('  if (mode != 2U', block+'  if (mode != 2U')
        self.run_fixture(self.compile('stale-handle', {file:changed}), 'current edit handle at delivery')

    def test_missing_release_registration_leaves_a_stale_scratch_origin(self):
        file = 'runtime-test.c'; source = (self.root/file).read_text()
        before = 'spx_native_release_external_range(a,22067U)==SPX_CALL_OK'
        self.assertEqual(source.count(before), 1)
        self.run_fixture(self.compile('missing-release', {file:source.replace(before, '1')}),
            'network scratch origin expired after release')

    def test_stale_text_generation_cannot_reach_actual_sendmessage(self):
        file = 'runtime-test.c'; source = (self.root/file).read_text()
        before = ' require(context->runtime->realize_reference(context->runtime->context,&ref,1U,0U,0U,&address)'
        self.assertEqual(source.count(before), 1)
        self.run_fixture(self.compile('stale-origin', {file:source.replace(before, ' ref.generation++;\n'+before)}),
            'source UI text lifetime')

    def test_wrong_count_arithmetic_rejects_at_the_real_wraparound_case(self):
        file = 'save/prepare-save.c'; source = (self.root/file).read_text()
        self.assertIn('(uint32_t)previous - removed', source)
        self.run_fixture(self.compile('wrong-count', {file:source.replace('(uint32_t)previous - removed', '(uint32_t)previous + removed')}),
            'network current length and uint32 arithmetic')

    def test_missing_mode_guard_rejects_when_cleanup_would_fault(self):
        file = 'replace/replace-selection.c'; source = (self.root/file).read_text()
        self.assertIn('mode != 2U && mode != 3U', source)
        self.run_fixture(self.compile('wrong-mode', {file:source.replace('mode != 2U && mode != 3U', 'mode != 3U')}),
            'network outcome')

    def test_wrong_caption_image_origin_rejects_at_view_admission(self):
        file = 'replace/bridge.c'; source = (self.root/file).read_text()
        before = '4252580U,500U,1U,"image:metapad:section:1"'
        self.assertIn(before, source)
        self.run_fixture(self.compile('wrong-caption', {file:source.replace(before, before.replace('section:1', 'section:2'))}),
            'consumer live view admission')

    def test_resource_contents_changed_after_loading_reject_before_notice(self):
        file = 'resource/resource-text.c'; source = (self.root/file).read_text()
        before = '  return buffer;'
        self.assertEqual(source.count(before), 1)
        mutation = '  context->state.buffer.write(context->state.buffer.access_context, context->state.buffer.base, 0, 1, 0);\n'
        self.run_fixture(self.compile('wrong-resource', {file:source.replace(before, mutation+before)}),
            'actual current resource contents')

    def test_checked_neighbor_loop_edit_uses_the_same_actual_resource_contract(self):
        source = (FIXTURE/'resource-text-loop.c').read_text()
        self.run_fixture(self.compile('neighbor-loop', {'resource/resource-text.c':source}))

    def test_removed_image_must_be_removed_from_reference_admission(self):
        file = 'runtime-test.c'; source = (self.root/file).read_text()
        before = 'spx_native_context_value.image_size=0U;'
        self.assertEqual(source.count(before), 1)
        self.run_fixture(self.compile('stale-image', {file:source.replace(before, '')}),
            'removed image reference rejects')
