"""Prepare binary-derived sprite font units using existing public facilities."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent
CLEANUP = HERE.parent/'dxball-cleanup-blind'
spec = importlib.util.spec_from_file_location('cleanup_preparation', CLEANUP/'prepare.py')
cleanup = importlib.util.module_from_spec(spec); spec.loader.exec_module(cleanup)
TYPES = [*cleanup.TYPES, *[dict(id='font_'+name, kind='opaque', nominal_id='dxball.font.'+name)
    for name in ('state', 'bytes', 'rect')]]
STATE = [('state', 'font_state')]
PARAMETERS = dict(select=STATE+[('bank', 'u32')], find=STATE+[('character', 'u32')],
    measure=STATE+[('length', 'u32'), ('text', 'font_bytes')],
    glyph=STATE+[('character', 'u32'), ('x', 'u32'), ('y', 'u32')],
    line=STATE+[('x', 'u32'), ('y', 'u32'), ('length', 'u32'), ('text', 'font_bytes')],
    center=STATE+[('x', 'u32'), ('y', 'u32'), ('length', 'u32'), ('text', 'font_bytes')],
    blit=STATE+[('destination', 'font_rect'), ('source', 'cleanup_surface'), ('rectangle', 'font_rect')])
RESULTS = {name: 'unit' if name in ('select', 'blit') else 'u32' for name in PARAMETERS}
OPERATIONS = dict(metrics=['select', 'find', 'measure'], render=['glyph', 'line', 'center'])
SERVICES = dict(metrics=[], render=['find', 'measure', 'blit'])
RANGES = dict(font_select=(0xbd80, 0xbd8a), font_find=(0xc660, 0xc6a6),
    font_measure=(0xc760, 0xc80d), font_glyph=(0xc5a0, 0xc651),
    font_line=(0xc6b0, 0xc714), font_center=(0xc720, 0xc752))
C_TYPES = dict(font_state='font_state *', font_bytes='font_bytes *', u32='uint32_t')


def cases():
    rows = [dict(id='mode-'+str(mode), arguments=list(map(str, [17, mode, 7]))) for mode in range(8)]
    for length in (0, 1, 0x80000000, 0xffffffff):
        rows.append(dict(id='length-'+str(length), arguments=list(map(str, [0xfffffffd, 0, length]))))
    seed = 0x71833a
    for i in range(8):
        seed = (1664525*seed+1013904223) & 0xffffffff
        rows.append(dict(id='generated-'+str(i), arguments=list(map(str, [seed, i % 5, 7]))))
    return rows


def bridge_spec(unit):
    return dict(adapters={key: dict(symbol='font_service_'+key, kind='portable', context=True,
        outcomes={'return': None}) for key in SERVICES[unit]}, transports={}, native_symbol=None)


def bridge(unit):
    text = '#include "portable-component-implementation.h"\n#include "font-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for name in OPERATIONS[unit]:
        parameters = ', '.join(C_TYPES[t]+' '+n for n, t in PARAMETERS[name])
        arguments = ', '.join(n for n, _ in PARAMETERS[name])
        result = 'void' if RESULTS[name] == 'unit' else 'uint32_t'
        prefix = '' if result == 'void' else 'uint32_t result = '
        suffix = '' if result == 'void' else 'return result;'
        text += f'''{result} fixture_font_{name}({parameters}) {{
    font_enter({list(PARAMETERS).index(name)});
    spx_font_{unit}_services_v5 services = spx_font_{unit}_bind_services(NULL);
    spx_font_{unit}_context_v5 context = {{0}}; context.services = &services;
    spx_font_{unit}_services_begin();
    {prefix}lifted_font_{name}(&context, {arguments});
    spx_font_{unit}_services_end(); {suffix}
}}
'''
    return text


def prepare(original, cleanup_package, output):
    started = time.monotonic()
    if sha256_file(original) != cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    native_header = '\n'.join(native_entry_header(original=original, expected_sha256=cleanup.PE_SHA256,
        module=None, entry_rva=lo, end_rva=hi, installer='install_'+name)
        for name, (lo, hi) in {**cleanup.RANGES, **RANGES}.items())
    (output/'native-image.h').write_text(native_header)
    definitions = {name: ServiceDefinition.create(identity='dxball.font.'+name,
        types=TYPES, parameters=PARAMETERS[name], result=RESULTS[name], resources=[],
        effects=['dxball.font.'+name], outcomes=['return'],
        unobserved=['Synchronous ordinary C adapter; explicit object and interaction observations. '
                    'No checked heap summary or production DirectDraw qualification.'])
        for name in SERVICES['render']}
    environment = native_environment(); packages = {}; commands = []
    for number, unit in enumerate(OPERATIONS):
        identity = 'font-'+unit; setup = output/(unit+'-setup'); setup.mkdir()
        selected = {key: definitions[key] for key in SERVICES[unit]}
        interface = component_interface(component_id=identity, types=TYPES, services=selected,
            operations={name: OperationDefinition(PARAMETERS[name], RESULTS[name], SERVICES[unit])
                        for name in OPERATIONS[unit]})
        write_json(setup/'interface.json', interface.to_payload())
        catalog = service_catalog(selected).to_payload() if selected else None
        write_json(setup/'services.json', catalog); write_json(setup/'bridge.json', bridge_spec(unit))
        (setup/'bridge.c').write_text(bridge(unit))
        (setup/'case-unit.h').write_text(f'#define DX_UNIT 2\n#define FONT_UNIT {number}\n')
        workspace = output/(unit+'-authoring')
        args = ['component', 'start', 'dxball', identity, '--interface-intent', str(setup/'interface.json'),
            '--service-bridge', str(setup/'bridge.json'), '--assumption-file', str(HERE/'BOUNDARY.md'),
            '--remove-source', 'source/component.c', '--output', str(workspace)]
        for name in OPERATIONS[unit]: args += ['--operation-symbol', name+'=lifted_font_'+name]
        for name, path in {unit+'.c': HERE/(unit+'.c'), 'font-state.h': HERE/'font-state.h',
                           'cleanup-state.h': CLEANUP/'cleanup-state.h'}.items():
            args += ['--source-file', 'source/'+name+'='+str(path)]
        if selected: args += ['--service-catalog', str(setup/'services.json')]
        phase = time.monotonic()
        result = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *args], capture_output=True, text=True)
        (setup/'start.stdout').write_text(result.stdout); (setup/'start.stderr').write_text(result.stderr)
        commands.append(dict(arguments=args, exit_code=result.returncode, seconds=time.monotonic()-phase))
        write_json(output/'commands.json', commands)
        if result.returncode: raise RuntimeError('inspect '+str(setup/'start.stderr'))
        bindings = bind_dependencies(consumers={'cleanup': cleanup_package} if unit == 'metrics' else None,
            services={name: packages['metrics'] for name in ('find', 'measure')} if unit == 'render' else None)
        destination = output/identity
        prepare_comparison_package(interface_package=workspace/'interface.json',
            source_files={name: workspace/'source'/name for name in (unit+'.c', 'font-state.h', 'cleanup-state.h')},
            operation_symbols={name: 'lifted_font_'+name for name in OPERATIONS[unit]},
            target_id='dxball', component_id=identity,
            adapter_files={'font-runtime.c': HERE/'font-runtime.c', 'bridge.c': setup/'bridge.c'},
            include_files={'font-runtime.h': HERE/'font-runtime.h', 'font-state.h': HERE/'font-state.h',
                'cleanup-runtime.c': CLEANUP/'runtime.c', 'runtime.h': CLEANUP/'runtime.h',
                'cleanup-state.h': CLEANUP/'cleanup-state.h', 'case-unit.h': setup/'case-unit.h',
                'native-image.h': output/'native-image.h', **native_adapter_headers('pe32-entry-hook.h'), **observation_headers()},
            **{**environment, 'runtime_files': {**environment['runtime_files'], 'DXBall.exe': original}},
            original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(),
            observation_fields=['before_cleanup', 'font', 'after_cleanup'], assumptions=[(HERE/'BOUNDARY.md').read_text()],
            scope='Binary-derived sprite font metrics/rendering with unchanged native callers and lifted cleanup; controlled graphics service.',
            service_catalog=catalog, service_bridge=bridge_spec(unit), **bindings,
            export_adapters=['adapters/bridge.c'],
            representation=dict(group=dict(id='dxball-font', label='Shared sprite font state',
                members=['font-metrics', 'font-render']), revision='portable-objects-v1',
                inputs={'layout': 'source/font-state.h', 'objects': 'source/cleanup-state.h',
                        'runtime-contract': 'headers/font-runtime.h'}),
            program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe',
                library='dx-font.dll', symbol='dx_font_anchor'), output=destination)
        packages[unit] = destination
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started,
        original_sha256=cleanup.PE_SHA256, original_source_consulted=False,
        tool_internal_changes=False, operations=OPERATIONS, cases_per_component=len(cases())))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path); parser.add_argument('cleanup_package', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args(); prepare(args.original.resolve(), args.cleanup_package.resolve(), args.output.resolve())
