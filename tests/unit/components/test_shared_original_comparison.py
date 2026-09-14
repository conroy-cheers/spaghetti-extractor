"""Real retained machine behavior against edited ordinary C, in a named domain.

These checks are conditional experiments. They do not register a runtime contract
or import their results as provider qualification.
"""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_assurance import checked_implemented_runtime_assurance
from spaghetti_extractor.components.bisimulation_readonly_model import mutable_checker_options
from .shared_original_model import render_shared_machine_model, shared_machine_runtime_contract
from spaghetti_extractor.components.cbmc_backend import bind_smt_solver, run_cbmc_properties, solver_arguments
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from spaghetti_extractor.transfer.behavioral_c_render import behavioral_c_support_source
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_shared_service_premises import binding as ordinary_service_binding

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'z3'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'profiles/pe32-user32-resource-text-runtime-v1.json')}
FIXTURE = Path(__file__).parents[3] / TESTKIT['resources'][0]
ORIGINAL = FIXTURE / 'original-machine'


def inputs():
    boundary = json.loads((ORIGINAL/'boundary.json').read_text())
    intent = ComponentInterfaceIntentV1.parse(json.loads((FIXTURE/'interface.json').read_text()))
    bundle = compile_component_interface_v5(intent)
    return dict(bundle=bundle, operation_id='get', symbol='resource_text', **{
        key: boundary[key] for key in ('shared_contract', 'binding_intent', 'service_bindings', 'machine_domain')})


def loop_edit(source):
    start, end = source.index('  uint64_t module;'), source.index('  spx_view_v5 buffer =')
    return source[:start] + '''  uint32_t module=0U;
  for (uint32_t i=0; i<4U; ++i) {
    uint8_t byte;
    if (spx_view_read_u8(&context->state.module,i,&byte)) return (spx_view_v5){0};
    module |= (uint32_t)byte << (8U*i);
  }
''' + source[end:]


class SharedOriginalComparisonTests(unittest.TestCase):
    def check_source(self, source, *, domain=None, machine_edit=None, arguments=None):
        arguments = inputs() if arguments is None else arguments
        if domain is not None:
            arguments['machine_domain'] = domain
        generated, entry = render_shared_machine_model(**arguments)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            (root/'behavioral-support.c').write_text(behavioral_c_support_source())
            for name, text in render_component_c_headers_v5(arguments['bundle'], {'get':'resource_text'}).items():
                (root/name).write_text(text)
            shutil.copyfile(ORIGINAL/'behavioral-c.h', root/'behavioral-c.h')
            original = (ORIGINAL/'behavioral-fn-00001284.c').read_text()
            (root/'original.c').write_text(original if machine_edit is None else machine_edit(original))
            (root/'pair.c').write_text(generated)
            (root/'source.c').write_text(source)
            compiled = subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', '-I', '.',
                'pair.c', 'source.c', 'original.c', 'behavioral-support.c', '--function', entry,
                '-o', 'model.goto'], cwd=root, text=True, capture_output=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            options = mutable_checker_options(16)
            position = options.index('--sat-solver')
            options[position:position+2] = solver_arguments(bind_smt_solver(Path(shutil.which('z3'))))
            return run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function', entry, *options],
                cwd=root, timeout_seconds=60, output_prefix=root/'query')

    def test_retained_original_and_loop_edit(self):
        source = (ORIGINAL/'resource-text.c').read_text()
        for body in (source, loop_edit(source)):
            with self.subTest(loop=body != source):
                result = self.check_source(body)
                self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_changed_arguments_alias_and_failure_behavior_are_rejected(self):
        source = (ORIGINAL/'resource-text.c').read_text()
        cases = [
            (source.replace('(uint32_t)module, id,', '(uint32_t)module, id+1U,'), 'service-arguments'),
            (loop_edit(source).replace('i<4U', 'i<3U'), 'service-arguments'),
            (source.replace('return buffer;', 'return context->state.module;'), 'authored-result-alias'),
            (source.replace('  context->services->load_string', '  uint32_t loaded=context->services->load_string').replace(
                '  return buffer;', '  if (!loaded) return (spx_view_v5){0};\n  return buffer;'), 'authored-result-alias')]
        for body, failure in cases:
            with self.subTest(failure=failure):
                result = self.check_source(body)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn(failure, result['detail'])

    def test_original_register_frame_is_checked(self):
        source = (ORIGINAL/'resource-text.c').read_text()
        def corrupt(text):
            token = '  state->original_rva = 0x00001284U;'
            self.assertEqual(text.count(token), 1)
            return text.replace(token, token+'\n  state->ebx ^= 1U;')
        result = self.check_source(source, machine_edit=corrupt)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('register-frame', result['detail'])

    def test_undeclared_original_stack_write_is_rejected(self):
        domain = inputs()['machine_domain']
        domain['private_writes'] = []
        result = self.check_source((ORIGINAL/'resource-text.c').read_text(), domain=domain)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('writable-frame', json.dumps(result))

    def test_original_inputs_and_generated_support_match_retained_slice(self):
        boundary = json.loads((ORIGINAL/'boundary.json').read_text())
        expected = {row['path']: row['sha256'] for row in boundary['provenance']['exact_slice']['files']}
        actual = {'state-machine-runtime.h': exact_runtime_header(), 'behavioral-support.c': behavioral_c_support_source()}
        actual.update({name: (ORIGINAL/name).read_text() for name in ('behavioral-c.h','behavioral-fn-00001284.c')})
        for name, contents in actual.items():
            self.assertEqual(hashlib.sha256(contents.encode()).hexdigest(), expected[name], name)
        self.assertEqual(hashlib.sha256((ORIGINAL/'resource-text.c').read_bytes()).hexdigest(),
                         boundary['provenance']['source_sha256'])
        self.assertEqual(inputs()['bundle'].intent.intent_sha256, boundary['provenance']['interface_intent_sha256'])

    def test_experimental_runtime_cannot_authorize_existing_qualification(self):
        contract = shared_machine_runtime_contract()
        with self.assertRaisesRegex(ValueError, 'exact implemented contracts'):
            checked_implemented_runtime_assurance({'kind':'conditional-runtime-contracts', 'contracts':[
                {'id':contract['id'], 'revision':contract['revision'], 'contract_sha256':canonical_sha256_v3(contract)}]})

    def test_return_address_cannot_be_replaced_by_a_logical_input(self):
        arguments = inputs()
        binding = copy.deepcopy(arguments['binding_intent'])
        binding['operations'][0]['machine_projection']['operation']['parameters'][0]['projection']['offset'] = 0
        binding['intent_sha256'] = canonical_sha256_v3({k:v for k,v in binding.items() if k != 'intent_sha256'})
        arguments['binding_intent'] = binding
        with self.assertRaisesRegex(ValueError, 'full admitted stack word'):
            render_shared_machine_model(**arguments)

    def test_domain_must_admit_a_stack_outside_the_image(self):
        arguments = inputs()
        arguments['machine_domain'].update(image_base=1, image_size=2**32-1)
        with self.assertRaisesRegex(ValueError, 'image/private frame is unsupported'):
            render_shared_machine_model(**arguments)

    def test_service_event_metadata_is_data_not_generated_c(self):
        for value in ('0); __CPROVER_assume(0); (0', True, -1, 2**32):
            arguments = inputs()
            arguments['service_bindings'][0]['events'][0]['instruction_rva'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'event metadata is unsupported'):
                render_shared_machine_model(**arguments)

    def test_equivalence_needs_no_invented_service_output_termination(self):
        arguments = inputs()
        selected = ordinary_service_binding()
        arguments['service_bindings'][0].update({key:selected[key] for key in (
            'external_effect_contract', 'external_contract_identity_sha256')})
        arguments['shared_contract']['service_contracts'] = normalize_shared_service_bindings(
            arguments['bundle'], arguments['service_bindings'])
        relation = arguments['shared_contract']['relation_intent']
        requirement = relation['operations'][0]['requirements'][0]
        requirement['expression'] = requirement['expression']['args'][0]
        relation['intent_sha256'] = canonical_sha256_v3({k:v for k,v in relation.items() if k != 'intent_sha256'})
        source = (ORIGINAL/'resource-text.c').read_text()
        for body in (source, loop_edit(source)):
            with self.subTest(loop=body != source):
                result = self.check_source(body, arguments=arguments)
                self.assertEqual(result['status'], 'satisfied', result.get('detail'))
