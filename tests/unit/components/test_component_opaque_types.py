"""Opaque C tags have one identity across services and operation prototypes."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.service_authoring import signature

TESTKIT = {'fixtures': ('compiler',)}


def opaque_bundle():
    rows = [signature('run', [('cell', 'cell')], 'u32'),
            signature('update', [('cell', 'cell'), ('value', 'u32')], 'unit'),
            signature('read', [('cell', 'cell')], 'u32')]
    schema = BoundarySchemaV1.create(schema_id='opaque', types=[
        {'id': 'u32', 'kind': 'integer', 'width_bits': 32, 'signed': False},
        {'id': 'unit', 'kind': 'void'},
        {'id': 'cell', 'kind': 'opaque', 'nominal_id': 'fixture.cell'},
        *(row[0] for row in rows)], signatures=[row[1] for row in rows])
    sig = schema.signature_index['run']
    intent = ComponentInterfaceIntentV1.create(component_id='opaque', schema=schema,
        state=[], effects=[], protocol_states=['ready'], initial_protocol_state='ready',
        services=[{'id': name, 'signature_id': name, 'effect_ids': [],
                   'interaction_contract_id': 'fixture.'+name} for name in ('update', 'read')],
        operations=[{'id': 'run', 'signature_id': 'run', 'pre_states': ['ready'], 'post_states': ['ready'],
            'source_values': [v.to_payload() for v in (*sig.parameters, *sig.results)],
            'projection_entries': [{'source_id': v.identity, 'target': {
                'root': root, 'value_id': v.identity, 'fields': []}}
                for root, values in [('parameter', sig.parameters), ('result', sig.results)] for v in values],
            'effect_ids': [], 'allowed_service_ids': ['update', 'read'], 'lifecycle_bindings': [],
            'lifecycle_additional_roots': {'state': []}, 'checked_interaction_contract_ids': []}])
    return compile_component_interface_v5(intent)


class OpaqueTypeTests(unittest.TestCase):
    def compile(self, compiler_name):
        compiler = shutil.which(compiler_name)
        self.assertIsNotNone(compiler, compiler_name+' is required by the compiler fixture')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, content in render_component_c_headers_v5(opaque_bundle(), {'run': 'lifted'}).items():
            (root/name).write_text(content)
        # The generated headers and conformance unit must stand alone, before
        # any target implementation supplies a definition of the opaque tag.
        (root/'header.c').write_text('#include "portable-component.h"\n')
        (root/'lifted.c').write_text('''#include "portable-component-implementation.h"
struct spx_opaque_cell_v5 { uint32_t value; };
uint32_t lifted(spx_opaque_context_v5 *context, struct spx_opaque_cell_v5 *cell) {
    context->services->update(context->services->context, cell, 42U);
    return context->services->read(context->services->context, cell);
}
static void update(void *context, struct spx_opaque_cell_v5 *cell, uint32_t value) {
    (void)context; cell->value = value;
}
static uint32_t read_cell(void *context, struct spx_opaque_cell_v5 *cell) {
    (void)context; return cell->value;
}
int main(void) {
    struct spx_opaque_cell_v5 cell = {0};
    const spx_opaque_services_v5 services = {.update = update, .read = read_cell};
    spx_opaque_context_v5 context = {.services = &services};
    return lifted(&context, &cell) == 42U && cell.value == 42U ? 0 : 1;
}
''')
        built = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
            str(root/'header.c'), str(root/'lifted.c'), str(root/'component-conformance.c'),
            '-o', str(root/'run')], capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        return root/'run'

    def test_host_standalone_headers_conformance_and_service_calls(self):
        executable = self.compile('cc')
        run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_pe32_standalone_headers_conformance_and_service_types(self):
        self.compile('i686-w64-mingw32-gcc')
