"""Actual cleanup C and the complete generated adapter use real PE32 services.

Finite runtime validation only: notice delivery is suppressed, image references
and private-memory admission use a fixture, and two null-allocation outcomes are
injected. This neither proves original equivalence nor qualifies actual callers.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.testkit import fixture
from tests.integration.native.cleanup_runtime_adapter import prepare

TESTKIT = {'fixtures': ('compiler', 'headless-wine'),
    'resources': ('tests/fixtures/metapad-cleanup-runtime', 'tests/fixtures/metapad-authored-call')}


class CleanupRuntimeAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='cleanup-runtime-adapter-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.inputs = prepare(cls.root)
        cls.compiler = fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        cls.runner = fixture('headless-wine')/'bin/spaghetti-headless-wine'
        cls.environment = dict(os.environ, WINEPREFIX=str(cls.root/'wine-prefix'), WINEDEBUG='-all',
            WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')

    def compile(self, name, *, source=None, runtime=None):
        source_name, runtime_name = 'cleanup.c', 'runtime-test.c'
        if source is not None:
            source_name = name+'-cleanup.c'; (self.root/source_name).write_text(source)
        if runtime is not None:
            runtime_name = name+'-runtime.c'; (self.root/runtime_name).write_text(runtime)
        result = subprocess.run([str(self.compiler), '-std=c11', '-O1', '-include', 'stdint.h',
            '-Werror=incompatible-pointer-types', '-Wl,--image-base,0x10000000', runtime_name,
            source_name, 'portable-reference-runtime.c', '-o', name+'.exe'], cwd=self.root,
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.root/(name+'.exe')

    def run_fixture(self, exe, *, error=None):
        result = subprocess.run([str(self.runner), str(exe)], capture_output=True, text=True,
            timeout=60, env=self.environment)
        self.assertEqual(result.returncode, 0 if error is None else 42, result.stderr)
        if error is None:
            self.assertIn('complete cleanup adapter: six cases', result.stdout)
        else:
            self.assertIn('CONTRACT MISMATCH: '+error, result.stderr)

    def test_complete_operation_with_current_adapter_and_actual_services(self):
        self.run_fixture(self.compile('baseline'))

    def test_wrong_ordinary_c_allocation_flag_rejects(self):
        original = (self.root/'cleanup.c').read_text()
        source = original.replace('context->services->context, 64U, length + 1U',
            'context->services->context, 0U, length + 1U')
        self.assertNotEqual(source, original)
        self.run_fixture(self.compile('wrong-flags', source=source), error='actual zeroed allocation flags')

    def test_missing_native_release_registration_rejects(self):
        original = (self.root/'runtime-test.c').read_text()
        old = 'spx_native_release_external_range(a,22067U)==SPX_CALL_OK'
        self.assertEqual(original.count(old), 1)
        source = original.replace(old, '1')
        self.run_fixture(self.compile('missing-release', runtime=source),
            error='returned scratch origin expired after release')

    def test_complete_service_header_rejects_pre_refinement_abi(self):
        previous = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(self.inputs['previous_interface_intent']))
        old = render_component_c_headers_v5(previous, {'cleanup': 'cleanup'})
        current = (self.root/'portable-component.h').read_text()
        self.assertNotEqual(old['portable-component.h'], current)
        # The implementation header alone stayed identical: it cannot establish
        # compatibility of the included service table's result types.
        self.assertEqual(old['portable-component-implementation.h'],
            (self.root/'portable-component-implementation.h').read_text())
        before = self.root/'old-abi'; before.mkdir()
        for name, text in old.items():
            (before/name).write_text(text)
        (before/'state-machine-runtime.h').write_bytes((self.root/'state-machine-runtime.h').read_bytes())
        (before/'overlay.c').write_bytes((self.root/'overlay.c').read_bytes())
        result = subprocess.run([str(self.compiler), '-std=c11', '-fsyntax-only',
            '-Werror=incompatible-pointer-types', 'overlay.c'], cwd=before,
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('incompatible', result.stderr)
