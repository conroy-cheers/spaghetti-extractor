"""Prepare binary-derived region operations with no game or neighboring bodies."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, component_interface
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent
PE_SHA256 = '191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES = dict(reset=(0xd520, 0xd54e), define=(0xd550, 0xd58d), hit=(0xd590, 0xd5db))
TYPES = [dict(id='unit', kind='void'), dict(id='u32', kind='integer', width_bits=32, signed=False),
         dict(id='region_table', kind='opaque', nominal_id='dxball.region.table')]
OPERATIONS = {name: [('table', 'region_table')] + [(key, 'u32') for key in keys]
              for name, keys in dict(reset=['requested'], define=['index', 'left', 'top', 'right', 'bottom'], hit=['x', 'y']).items()}


def signature(name, names=True):
    return ', '.join(('region_table *' if kind == 'region_table' else 'uint32_t ') + (key if names else '')
                     for key, kind in OPERATIONS[name])


def bridge_spec():
    return dict(adapters={}, transports={}, native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "regions-runtime.h"\n'
    for index, name in enumerate(OPERATIONS):
        result = 'uint32_t' if name == 'hit' else 'void'
        args = ', '.join(key for key, _ in OPERATIONS[name])
        text += f'''{result} fixture_regions_{name}({signature(name)}) {{
    regions_enter({index}); spx_hit_regions_context_v5 context={{0}};
    {"return " if name == "hit" else ""}lifted_regions_{name}(&context,{args});
}}
'''
    return text


def runtime_header():
    text = '#ifndef DXBALL_REGIONS_RUNTIME_H\n#define DXBALL_REGIONS_RUNTIME_H\n#include "regions-state.h"\nvoid regions_enter(unsigned);\n'
    for name in OPERATIONS:
        text += ('uint32_t' if name == 'hit' else 'void') + ' fixture_regions_' + name + '(' + signature(name, False) + ');\n'
    return text + '#endif\n'


def cases():
    names = ['editor-palette', 'reset-framing', 'signed-reset', 'overlapping-edges',
             'signed-coordinates', 'disabled-inverted', 'count-boundaries', 'generated-1', 'generated-2']
    return [dict(id=name, arguments=[str(i)]) for i, name in enumerate(names)]


def prepare(original, editor_package, output):
    started = time.monotonic()
    if sha256_file(original) != PE_SHA256:
        raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    interface = component_interface(component_id='hit-regions', types=TYPES, services={},
        operations={name: OperationDefinition(parameters, 'u32' if name == 'hit' else 'unit', [])
                    for name, parameters in OPERATIONS.items()})
    write_json(output/'interface.json', interface.to_payload())
    write_json(output/'bridge.json', bridge_spec())
    (output/'bridge.c').write_text(bridge())
    (output/'regions-runtime.h').write_text(runtime_header())
    # Reuse declarations only. No neighboring component implementation is needed.
    sources = {'regions.c': HERE/'regions.c', 'regions-state.h': HERE/'regions-state.h'}
    pending = ['editor-state.h']
    while pending:
        name = pending.pop()
        if name in sources:
            continue
        path = editor_package/'source'/name
        sources[name] = path
        pending += re.findall(r'^#include "([^"]+)"', path.read_text(), re.MULTILINE)
    args = ['component', 'start', 'dxball', 'hit-regions', '--interface-intent', str(output/'interface.json'),
        '--service-bridge', str(output/'bridge.json'), '--assumption-file', str(HERE/'BOUNDARY.md'),
        '--remove-source', 'source/component.c', '--output', str(output/'authoring')]
    for name in RANGES:
        args += ['--operation-symbol', name+'=lifted_regions_'+name]
    for name, path in sources.items():
        args += ['--source-file', 'source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *args], capture_output=True, text=True)
    (output/'start.stdout').write_text(ran.stdout)
    (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:
        raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries = {**{'regions_'+name: span for name, span in RANGES.items()}, 'startup': (0xeaa0, 0xeaa5)}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,
        expected_sha256=PE_SHA256, module=None, entry_rva=lo, end_rva=hi, installer='install_'+name)
        for name, (lo, hi) in entries.items()))
    environment = native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name: output/'authoring/source'/name for name in sources},
        operation_symbols={name: 'lifted_regions_'+name for name in RANGES}, target_id='dxball', component_id='hit-regions',
        adapter_files={'runtime.c': HERE/'runtime.c', 'bridge.c': output/'bridge.c'},
        include_files={'native-image.h': output/'native-image.h', 'regions-runtime.h': output/'regions-runtime.h',
            **native_adapter_headers('pe32-entry-hook.h'), **observation_headers()},
        **{**environment, 'runtime_files': {**environment['runtime_files'], 'DXBall.exe': original}},
        original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(), observation_fields=['regions'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Actual region entries over a borrowed editor table; full storage observations without game startup or neighboring bodies.',
        service_bridge=bridge_spec(), export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-regions.dll', symbol='dx_regions_anchor'),
        output=output/'hit-regions')
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, cases=len(cases()),
        original_source_consulted=False, tool_internal_changes=False, neighboring_component_bodies=0))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'editor_package', 'output'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    prepare(a.original.resolve(), a.editor_package.resolve(), a.output.resolve())
