"""Author capture/restoration against the existing asset/font/cleanup network."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
FONT = HERE.parent/'dxball-sprite-font'
sys.path.insert(0, str(FONT))
spec = importlib.util.spec_from_file_location('asset_preparation', FONT/'prepare-assets.py')
asset = importlib.util.module_from_spec(spec); spec.loader.exec_module(asset)
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

RANGES = dict(capture=(0xbe10, 0xc076), restore=(0xbd00, 0xbd59))
BASE_SERVICES = ('dispose', 'allocate_sprite', 'create', 'color_key', 'describe')
PARAMETERS = dict(capture=[('state', 'asset_state'), ('drawing', 'font_state'),
    *[(name, 'u32') for name in ('slot', 'x', 'y', 'width', 'height')]], restore=asset.STATE)
SERVICE_PARAMETERS = {**{name: asset.PARAMETERS[name] for name in BASE_SERVICES},
    'copy': asset.STATE+[('drawing', 'font_state'), ('sprite', 'cleanup_sprite'), ('rectangle', 'font_rect')],
    'restore_surface': asset.STATE+[('surface', 'cleanup_surface')], 'reload': asset.STATE+[('bank', 'u32')]}


def bridge_spec():
    return dict(adapters={name: dict(symbol='trial_dispose' if name == 'dispose' else
        ('asset_' if name in BASE_SERVICES else 'lifecycle_')+name,
        kind='portable', context=True, outcomes={'return': None}) for name in SERVICE_PARAMETERS},
        transports={}, native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "lifecycle-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for number, (name, parameters) in enumerate(PARAMETERS.items()):
        result = 'uint32_t' if name == 'capture' else 'void'
        signature = ', '.join(('uint32_t' if t == 'u32' else t+' *')+' '+n for n, t in parameters)
        arguments = ', '.join(n for n, _ in parameters)
        text += f'''{result} fixture_sprite_{name}({signature}) {{
    lifecycle_enter({number});
    spx_sprite_lifecycle_services_v5 services = spx_sprite_lifecycle_bind_services(NULL);
    spx_sprite_lifecycle_context_v5 context = {{0}}; context.services = &services;
    spx_sprite_lifecycle_services_begin();
    {'' if result == 'void' else 'uint32_t result = '}lifted_sprite_{name}(&context, {arguments});
    spx_sprite_lifecycle_services_end(); {'' if result == 'void' else 'return result;'}
}}
'''
    return text


def cases():
    return [dict(id=f'seed-{seed}-mode-{mode}', arguments=[str(seed), str(mode)])
            for seed in (0, 1, 2, 0xffffffff) for mode in range(4)]


def prepare(original, loader_package, output):
    started = time.monotonic()
    if sha256_file(original) != asset.cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    definitions = {name: ServiceDefinition.create(identity='dxball.sprite.lifecycle.'+name,
        types=asset.ASSET_TYPES, parameters=parameters,
        result=asset.RESULTS.get(name, 'u32' if name in ('copy', 'restore_surface') else 'unit'),
        nullable_result=name == 'allocate_sprite', resources=[], effects=['dxball.sprite.lifecycle.'+name],
        outcomes=['return'], unobserved=['Synchronous shared sprite/graphics/loader boundary described in BOUNDARY.md.'])
        for name, parameters in SERVICE_PARAMETERS.items()}
    interface = component_interface(component_id='sprite-lifecycle', types=asset.ASSET_TYPES, services=definitions,
        operations={'capture': OperationDefinition(PARAMETERS['capture'], 'u32', [*BASE_SERVICES, 'copy']),
                    'restore': OperationDefinition(PARAMETERS['restore'], 'unit', ['restore_surface', 'reload'])})
    catalog = service_catalog(definitions).to_payload()
    write_json(output/'interface.json', interface.to_payload()); write_json(output/'services.json', catalog)
    write_json(output/'bridge.json', bridge_spec()); (output/'bridge.c').write_text(bridge())
    arguments = ['component', 'start', 'dxball', 'sprite-lifecycle', '--interface-intent', str(output/'interface.json'),
        '--service-catalog', str(output/'services.json'), '--service-bridge', str(output/'bridge.json'),
        '--assumption-file', str(HERE/'BOUNDARY.md'), '--remove-source', 'source/component.c', '--output', str(output/'authoring')]
    for name in PARAMETERS: arguments += ['--operation-symbol', name+'=lifted_sprite_'+name]
    sources = {'lifecycle.c': HERE/'lifecycle.c', 'asset-state.h': FONT/'asset-state.h',
        'font-state.h': FONT/'font-state.h', 'cleanup-state.h': asset.CLEANUP/'cleanup-state.h'}
    for name, path in sources.items(): arguments += ['--source-file', 'source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *arguments], capture_output=True, text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,
        expected_sha256=asset.cleanup.PE_SHA256, module=None, entry_rva=lo, end_rva=hi, installer='install_'+name)
        for name, (lo, hi) in {**asset.cleanup.RANGES, **asset.RANGES, **asset.ASSET_RANGES, **RANGES}.items()))
    (output/'case-unit.h').write_text('#define DX_UNIT 2\n#define FONT_UNIT 1\n')
    includes = {name: FONT/name for name in ('asset-runtime.c', 'asset-runtime.h', 'asset-state.h',
                                          'font-runtime.c', 'font-runtime.h', 'font-state.h')}
    includes.update({'lifecycle-runtime.h': HERE/'lifecycle-runtime.h', 'runtime.h': asset.CLEANUP/'runtime.h',
        'cleanup-runtime.c': asset.CLEANUP/'runtime.c', 'cleanup-state.h': asset.CLEANUP/'cleanup-state.h',
        'case-unit.h': output/'case-unit.h', 'native-image.h': output/'native-image.h',
        **native_adapter_headers('pe32-entry-hook.h'), **observation_headers()})
    environment = native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name: output/'authoring/source'/name for name in sources},
        operation_symbols={name: 'lifted_sprite_'+name for name in PARAMETERS},
        target_id='dxball', component_id='sprite-lifecycle',
        adapter_files={'runtime.c': HERE/'runtime.c', 'bridge.c': output/'bridge.c'}, include_files=includes,
        **{**environment, 'runtime_files': {**environment['runtime_files'], 'DXBall.exe': original,
            **{name: loader_package/'runtime'/name for name in ('Sysfont.sbk', 'Sfont.sbk', 'Thefont.sbk')}}},
        original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(),
        observation_fields=['captured', 'restored', 'lifecycle', 'after_cleanup'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Binary-derived capture and restoration with real bank assets, connected C loader/font/cleanup and controlled graphics services.',
        service_catalog=catalog, service_bridge=bridge_spec(),
        **bind_dependencies(consumers={'loader-consumer': loader_package},
                            services={'dispose': dict(id='cleanup-dispose', package=loader_package)}),
        export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-lifecycle.dll', symbol='dx_lifecycle_anchor'),
        output=output/'sprite-lifecycle')
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started,
        original_source_consulted=False, tool_internal_changes=False, cases=len(cases())))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'loader_package', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(args.original.resolve(), args.loader_package.resolve(), args.output.resolve())
