"""Extend the font network with a binary-derived sprite-bank loader."""
import argparse
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json
from prepare import CLEANUP, HERE, RANGES, TYPES, cleanup

ASSET_TYPES = [*TYPES, *[dict(id='asset_'+name, kind='opaque', nominal_id='dxball.asset.'+name)
    for name in ('state', 'file', 'name', 'buffer', 'view')]]
STATE = [('state', 'asset_state')]
PARAMETERS = dict(select=cleanup.SPECS['select'], dispose=cleanup.SPECS['dispose'],
    open=STATE+[('name', 'asset_name')], read=STATE+[('buffer', 'asset_buffer'), ('size', 'u32'), ('count', 'u32')],
    close=STATE, allocate_pixels=STATE+[('bytes', 'u32')], allocate_sprite=STATE,
    free_pixels=STATE+[('buffer', 'asset_buffer')], create=STATE+[('sprite', 'cleanup_sprite'), ('caps', 'u32')],
    color_key=STATE+[('surface', 'cleanup_surface')],
    describe=STATE+[('surface', 'cleanup_surface'), ('view', 'asset_view')],
    lock=STATE+[('surface', 'cleanup_surface'), ('view', 'asset_view')], unlock=STATE+[('surface', 'cleanup_surface')])
RESULTS = dict(open='asset_file', read='u32', allocate_pixels='asset_buffer', allocate_sprite='cleanup_sprite',
               create='u32', describe='u32', lock='u32')
ASSET_RANGES = dict(load=(0xc080, 0xc510), asset_open=(0xe190, 0xe1a5), asset_read=(0xe580, 0xe585),
    asset_close=(0xdf50, 0xdf55), asset_allocate=(0xe2f0, 0xe304), asset_free=(0xe2a0, 0xe2ea))


def bridge_spec():
    return dict(adapters={name: dict(symbol=('trial_' if name in ('select', 'dispose') else 'asset_')+name,
        kind='portable', context=True, outcomes={'return': None}) for name in PARAMETERS},
        transports={}, native_symbol='bridge_load')


def bridge():
    return '''#include "portable-component-implementation.h"
#include "asset-runtime.h"
#include "comparison-service-bridge.h"
void fixture_sprite_load(asset_state *state, uint32_t bank, uint32_t mode, asset_name *name) {
    asset_enter(); bridge_load(state, bank, mode, name);
}
'''


def cases():
    rows = []
    for i, name in enumerate(('Sysfont.sbk', 'Sfont.sbk', 'Thefont.sbk')):
        rows.append(dict(id='asset-'+str(i), arguments=[str(i), str(i % 2), name, '0', '0']))
    rows += [dict(id='create-failure-'+str(n), arguments=['1', '0', 'Sysfont.sbk', str(n), '0']) for n in (1, 4)]
    rows.append(dict(id='retries', arguments=['2', '1', 'Sfont.sbk', '0', '2']))
    return rows


def prepare(original, font_package, assets, output):
    started = time.monotonic()
    if sha256_file(original) != cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    definitions = {name: ServiceDefinition.create(identity='dxball.asset.'+name,
        types=ASSET_TYPES, parameters=parameters, result=RESULTS.get(name, 'unit'), resources=[],
        effects=['dxball.asset.'+name], outcomes=['return'],
        nullable_result=name in ('open', 'allocate_pixels', 'allocate_sprite'),
        unobserved=['Explicit file/object/buffer adapter domain. Finite memory/lifetime observations; '
                    'no arbitrary allocator or DirectDraw equivalence.']) for name, parameters in PARAMETERS.items()}
    interface = component_interface(component_id='sprite-loader', types=ASSET_TYPES, services=definitions,
        parameters=STATE+[('bank', 'u32'), ('mode', 'u32'), ('name', 'asset_name')], result='unit')
    catalog = service_catalog(definitions).to_payload()
    write_json(output/'interface-intent.json', interface.to_payload()); write_json(output/'services.json', catalog)
    write_json(output/'bridge.json', bridge_spec()); (output/'bridge.c').write_text(bridge())
    args = ['component', 'start', 'dxball', 'sprite-loader', '--interface-intent', str(output/'interface-intent.json'),
        '--service-catalog', str(output/'services.json'), '--service-bridge', str(output/'bridge.json'),
        '--assumption-file', str(HERE/'ASSET-BOUNDARY.md'), '--operation-symbol', 'run=lifted_sprite_load',
        '--remove-source', 'source/component.c', '--output', str(output/'authoring')]
    sources = {'loader.c': HERE/'loader.c', 'asset-state.h': HERE/'asset-state.h', 'font-state.h': HERE/'font-state.h',
               'cleanup-state.h': CLEANUP/'cleanup-state.h'}
    for name, path in sources.items(): args += ['--source-file', 'source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *args], capture_output=True, text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original, expected_sha256=cleanup.PE_SHA256,
        module=None, entry_rva=lo, end_rva=hi, installer='install_'+name)
        for name, (lo, hi) in {**cleanup.RANGES, **RANGES, **ASSET_RANGES}.items()))
    (output/'case-unit.h').write_text('#define DX_UNIT 2\n#define FONT_UNIT 1\n')
    include = {name: HERE/name for name in ('asset-runtime.h', 'asset-state.h', 'font-runtime.c', 'font-runtime.h', 'font-state.h')}
    include.update({name: CLEANUP/name for name in ('runtime.h', 'cleanup-state.h')})
    include.update({'cleanup-runtime.c': CLEANUP/'runtime.c', 'case-unit.h': output/'case-unit.h',
        'native-image.h': output/'native-image.h', **native_adapter_headers('pe32-entry-hook.h'), **observation_headers()})
    environment = native_environment()
    bindings = bind_dependencies(consumers={'font-consumer': font_package},
        services={name: dict(id='cleanup-'+name, package=font_package) for name in ('select', 'dispose')})
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name: output/'authoring/source'/name for name in sources}, operation_symbols={'run': 'lifted_sprite_load'},
        target_id='dxball', component_id='sprite-loader',
        adapter_files={'asset-runtime.c': HERE/'asset-runtime.c', 'bridge.c': output/'bridge.c'}, include_files=include,
        **{**environment, 'runtime_files': {**environment['runtime_files'], 'DXBall.exe': original,
           **{name: assets/name for name in ('Sysfont.sbk', 'Sfont.sbk', 'Thefont.sbk')}}},
        original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(),
        observation_fields=['loaded', 'assets', 'after_cleanup'], assumptions=[(HERE/'ASSET-BOUNDARY.md').read_text()],
        scope='Original-x86 sprite-bank loader versus connected C loader, font and cleanup with real shipped assets and controlled graphics/allocation.',
        service_catalog=catalog, service_bridge=bridge_spec(), **bindings, export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-assets.dll', symbol='dx_asset_anchor'),
        output=output/'sprite-loader')
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, original_source_consulted=False,
        tool_internal_changes=False, assets={name: sha256_file(assets/name) for name in ('Sysfont.sbk', 'Sfont.sbk', 'Thefont.sbk')}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'font_package', 'assets', 'output'): p.add_argument(name, type=Path)
    a = p.parse_args(); prepare(a.original.resolve(), a.font_package.resolve(), a.assets.resolve(), a.output.resolve())
