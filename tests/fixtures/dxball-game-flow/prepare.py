"""Author the binary-derived game dispatcher through the public component path."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
LIFECYCLE = HERE.parent/'dxball-sprite-lifecycle'
spec = importlib.util.spec_from_file_location('flow_lifecycle_preparation', LIFECYCLE/'prepare.py')
lifecycle = importlib.util.module_from_spec(spec); spec.loader.exec_module(lifecycle)
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

RANGES = dict(frame=(0xab10, 0xabe4), key=(0xabf0, 0xac5c), enter=(0xac60, 0xaca0),
    leave=(0xaca0, 0xad0c), redraw=(0xaad0, 0xab10), restore=(0xaaa0, 0xaac9),
    check_surfaces=(0xaa50, 0xaa9f), shutdown=(0xae50, 0xae80))
SCENES = dict(enter=[0xae80, 0x4120, 0x3570, 0x9410, 0xa0b0],
    update=[0xb1f0, 0x44d0, 0x3750, 0x96a0, 0xa510],
    key=[0xb2a0, 0x4ad0, 0x3a00, 0x98e0, 0xa5f0],
    leave=[0xbbf0, 0x8f70, 0x3f30, 0xbbf0, 0xa610],
    redraw=[0xaf80, 0x43d0, 0x3660, 0x9510, 0xa200])
STATE = [('state', 'flow_state')]
PARAMETERS = {name: STATE+([('key' if name == 'key' else 'reason', 'u32')]
    if name in ('key', 'leave', 'shutdown') else []) for name in RANGES}
SERVICES = dict(initialize=STATE,
    **{'scene_'+name: STATE+[('scene', 'u32')]+([('key' if name == 'key' else 'reason', 'u32')]
        if name in ('key', 'leave') else []) for name in SCENES},
    **{name: STATE+[('surface', 'cleanup_surface')] for name in ('surface_status', 'surface_restore', 'release')},
    **{name: STATE+[('audio', 'flow_audio')] for name in ('audio_status', 'audio_restore')},
    restore_banks=[('state', 'asset_state')])
RESULTS = {name: 'u32' if name in ('surface_status', 'surface_restore', 'audio_status') else 'unit' for name in SERVICES}
TYPES = [*lifecycle.asset.ASSET_TYPES, *[dict(id='flow_'+name, kind='opaque', nominal_id='dxball.flow.'+name)
    for name in ('state', 'audio')]]


def bridge_spec():
    return dict(adapters={name: dict(symbol='flow_'+name, kind='portable', context=True,
        outcomes={'return': None}) for name in SERVICES}, transports={}, native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "flow-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for number, (name, parameters) in enumerate(PARAMETERS.items()):
        result = 'uint32_t' if name == 'frame' else 'void'
        signature = ', '.join(('uint32_t' if kind == 'u32' else kind+' *')+' '+key for key, kind in parameters)
        arguments = ', '.join(key for key, _ in parameters)
        text += f'''{result} fixture_flow_{name}({signature}) {{
    flow_enter({number});
    spx_game_flow_services_v5 services = spx_game_flow_bind_services(NULL);
    spx_game_flow_context_v5 context = {{0}}; context.services = &services;
    spx_game_flow_services_begin();
    {'' if result == 'void' else 'uint32_t result = '}lifted_flow_{name}(&context, {arguments});
    spx_game_flow_services_end(); {'' if result == 'void' else 'return result;'}
}}
'''
    return text


def cases():
    rows = [dict(id=f'scene-{scene}-mode-{mode}', arguments=[str(scene), str(mode)])
            for scene in (0, 1, 2, 3, 4, 5, 0xffffffff) for mode in (0, 2, 3)]
    return rows+[dict(id=f'recovery-{mode}', arguments=['4', str(mode)])
                 for mode in (1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)]


def prepare(original, lifecycle_package, output):
    started = time.monotonic()
    if sha256_file(original) != lifecycle.asset.cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    definitions = {name: ServiceDefinition.create(identity='dxball.flow.'+name, types=TYPES,
        parameters=parameters, result=RESULTS[name], resources=[], effects=['dxball.flow.'+name], outcomes=['return'],
        unobserved=['Synchronous shared-state services; see BOUNDARY.md for admitted status/lifetime behavior.'])
        for name, parameters in SERVICES.items()}
    used = dict(frame=list(SERVICES), key=['scene_key'], enter=['scene_enter'], leave=['scene_leave'],
        redraw=['scene_redraw'], restore=['surface_restore', 'restore_banks', 'scene_redraw'],
        check_surfaces=['surface_status', 'surface_restore', 'restore_banks', 'scene_redraw'],
        shutdown=['scene_leave', 'release'])
    interface = component_interface(component_id='game-flow', types=TYPES, services=definitions,
        operations={name: OperationDefinition(parameters, 'u32' if name == 'frame' else 'unit', used[name])
                    for name, parameters in PARAMETERS.items()})
    catalog = service_catalog(definitions).to_payload()
    write_json(output/'interface.json', interface.to_payload()); write_json(output/'services.json', catalog)
    write_json(output/'bridge.json', bridge_spec()); (output/'bridge.c').write_text(bridge())
    sources = {'flow.c': HERE/'flow.c', 'flow-state.h': HERE/'flow-state.h',
        **{name: lifecycle_package/'source'/name for name in ('asset-state.h', 'font-state.h', 'cleanup-state.h')}}
    arguments = ['component', 'start', 'dxball', 'game-flow', '--interface-intent', str(output/'interface.json'),
        '--service-catalog', str(output/'services.json'), '--service-bridge', str(output/'bridge.json'),
        '--assumption-file', str(HERE/'BOUNDARY.md'), '--remove-source', 'source/component.c', '--output', str(output/'authoring')]
    for name in PARAMETERS: arguments += ['--operation-symbol', name+'=lifted_flow_'+name]
    for name, path in sources.items(): arguments += ['--source-file', 'source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *arguments], capture_output=True, text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    ranges = {'flow_'+name: bounds for name, bounds in RANGES.items()}
    ranges['flow_initialize'] = (0xad10, 0xad18)
    for name, entries in SCENES.items():
        for scene, address in enumerate(entries):
            if name == 'leave' and scene == 3: continue
            ranges[f'scene_{name}_{scene}'] = (address, address+8)
    header = (lifecycle_package/'headers/native-image.h').read_text()+'\n'
    header += '\n'.join(native_entry_header(original=original, expected_sha256=sha256_file(original), module=None,
        entry_rva=lo, end_rva=hi, installer='install_'+name) for name, (lo, hi) in ranges.items())
    (output/'native-image.h').write_text(header)
    includes = {p.relative_to(lifecycle_package/'headers').as_posix(): p
                for p in (lifecycle_package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h': output/'native-image.h', 'lifecycle-runtime.c': LIFECYCLE/'runtime.c',
        'flow-native.h': HERE/'flow-native.h', 'flow-runtime.h': HERE/'flow-runtime.h', 'flow-state.h': HERE/'flow-state.h'})
    environment = native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name: output/'authoring/source'/name for name in sources},
        operation_symbols={name: 'lifted_flow_'+name for name in PARAMETERS}, target_id='dxball', component_id='game-flow',
        adapter_files={'runtime.c': HERE/'runtime.c', 'bridge.c': output/'bridge.c'}, include_files=includes,
        **{**environment, 'runtime_files': {**environment['runtime_files'],
            **{p.name: p for p in (lifecycle_package/'runtime').iterdir() if p.is_file()}}},
        original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(),
        observation_fields=['flow', 'objects', 'assets', 'after_cleanup'], assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Native frame/scene/recovery dispatch with callback mutation, connected sprite restoration and controlled scene/platform services.',
        service_catalog=catalog, service_bridge=bridge_spec(),
        **bind_dependencies(services={'restore_banks': lifecycle_package}), export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-flow.dll', symbol='dx_flow_anchor'),
        output=output/'game-flow')
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, operations=list(RANGES),
        cases=len(cases()), original_source_consulted=False, tool_internal_changes=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'lifecycle_package', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(args.original.resolve(), args.lifecycle_package.resolve(), args.output.resolve())
