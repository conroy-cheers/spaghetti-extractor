"""Prepare a real title animation boundary using existing font/drawing units."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
FONT = HERE.parent/'dxball-sprite-font'
spec = importlib.util.spec_from_file_location('title_font_preparation', FONT/'prepare.py')
font = importlib.util.module_from_spec(spec); spec.loader.exec_module(font)
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

RANGES = dict(scroll=(0xa780, 0xa84e), wave=(0xa6c0, 0xa77a), wobble=(0xa850, 0xa970), cycle=(0xa970, 0xaa4a))
TYPES = [*font.TYPES, dict(id='title_state', kind='opaque', nominal_id='dxball.title.state')]
SERVICES = dict(select_font=[('state', 'font_state'), ('bank', 'u32')],
    destination=[('state', 'font_state'), ('surface', 'cleanup_surface')],
    glyph=[('state', 'font_state'), ('character', 'u32'), ('x', 'u32'), ('y', 'u32')],
    blit_fast=[('state', 'title_state'), ('destination', 'cleanup_surface'), ('x', 'u32'), ('y', 'u32'),
        ('source', 'cleanup_surface'), ('rectangle', 'font_rect'), ('flags', 'u32')],
    apply_palette=[('state', 'title_state'), ('first', 'u32'), ('count', 'u32')])


def bridge_spec():
    return dict(adapters={name: dict(symbol='title_'+name, kind='portable', context=True,
        outcomes={'return': None}) for name in SERVICES}, transports={}, native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "title-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for number, name in enumerate(RANGES):
        text += f'''void fixture_title_{name}(title_state *state) {{
    title_enter({number});
    spx_title_animation_services_v5 services = spx_title_animation_bind_services(NULL);
    spx_title_animation_context_v5 context = {{0}}; context.services = &services;
    spx_title_animation_services_begin(); lifted_title_{name}(&context, state); spx_title_animation_services_end();
}}
'''
    return text


def cases():
    rows = [dict(id=f'mode-{mode}-phase-{phase}', arguments=['17', str(mode), str(phase)])
        for mode in range(7) for phase in (0, 339)]
    return rows + [dict(id='signed-phase-'+str(phase), arguments=['1024', '0', str(phase & 0xffffffff)])
        for phase in (-380, -360, -20, 359)]


def prepare(original, drawing_package, output):
    started = time.monotonic()
    if sha256_file(original) != font.cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    definitions = {name: ServiceDefinition.create(identity='dxball.title.'+name, types=TYPES,
        parameters=parameters, result='u32' if name == 'glyph' else 'unit', resources=[],
        effects=['dxball.title.'+name], outcomes=['return'],
        unobserved=['Synchronous existing object views, buffered state and admitted numeric domain in BOUNDARY.md.'])
        for name, parameters in SERVICES.items()}
    used = dict(scroll=['select_font', 'destination', 'glyph', 'blit_fast'], wave=['blit_fast'],
        wobble=['blit_fast'], cycle=['apply_palette'])
    interface = component_interface(component_id='title-animation', types=TYPES, services=definitions,
        operations={name: OperationDefinition([('state', 'title_state')], 'unit', used[name]) for name in RANGES})
    catalog = service_catalog(definitions).to_payload()
    write_json(output/'interface.json', interface.to_payload()); write_json(output/'services.json', catalog)
    write_json(output/'bridge.json', bridge_spec()); (output/'bridge.c').write_text(bridge())
    sources = {'title.c': HERE/'title.c', 'title-state.h': HERE/'title-state.h',
        'flow-state.h': HERE.parent/'dxball-game-flow/flow-state.h',
        'pcx-state.h': HERE.parent/'dxball-pcx/pcx-state.h',
        'asset-state.h': FONT/'asset-state.h', 'font-state.h': FONT/'font-state.h',
        'cleanup-state.h': font.CLEANUP/'cleanup-state.h'}
    command = ['component', 'start', 'dxball', 'title-animation', '--interface-intent', str(output/'interface.json'),
        '--service-catalog', str(output/'services.json'), '--service-bridge', str(output/'bridge.json'),
        '--assumption-file', str(HERE/'BOUNDARY.md'), '--remove-source', 'source/component.c', '--output', str(output/'authoring')]
    for name in RANGES: command += ['--operation-symbol', name+'=lifted_title_'+name]
    for name, path in sources.items(): command += ['--source-file', 'source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *command], capture_output=True, text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    header = (drawing_package/'headers/native-image.h').read_text()+'\n'
    header += '\n'.join(native_entry_header(original=original, expected_sha256=font.cleanup.PE_SHA256,
        module=None, entry_rva=lo, end_rva=hi, installer='install_title_'+name) for name, (lo, hi) in RANGES.items())
    (output/'native-image.h').write_text(header)
    includes = {p.relative_to(drawing_package/'headers').as_posix(): p for p in (drawing_package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h': output/'native-image.h', 'title-runtime.h': HERE/'title-runtime.h',
        'title-native.h': HERE/'title-native.h'})
    bindings = bind_dependencies(services={'destination': drawing_package,
        'select_font': dict(package=drawing_package, id='font-metrics'),
        'glyph': dict(package=drawing_package, id='font-render')})
    environment = native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name: output/'authoring/source'/name for name in sources},
        operation_symbols={name: 'lifted_title_'+name for name in RANGES}, target_id='dxball', component_id='title-animation',
        adapter_files={'runtime.c': HERE/'runtime.c', 'bridge.c': output/'bridge.c'}, include_files=includes,
        **{**environment, 'runtime_files': {**environment['runtime_files'], 'DXBall.exe': original}},
        original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(),
        observation_fields=['title', 'pixels', 'palettes', 'calls', 'font_blits'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Binary-derived scrolling/waves/palette cycles with connected font/drawing components and live pixel storage.',
        service_catalog=catalog, service_bridge=bridge_spec(), **bindings, export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-title.dll', symbol='dx_title_anchor'),
        output=output/'title-animation')
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, cases=len(cases()),
        original_source_consulted=False, tool_internal_changes=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'drawing_package', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(args.original.resolve(), args.drawing_package.resolve(), args.output.resolve())
