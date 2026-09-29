"""Author the binary-derived PCX loader with buffered I/O and live pixel views."""
import argparse
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
FONT = HERE.parent/'dxball-sprite-font'
sys.path.insert(0, str(FONT))
spec = importlib.util.spec_from_file_location('pcx_asset_preparation', FONT/'prepare-assets.py')
asset = importlib.util.module_from_spec(spec); spec.loader.exec_module(asset)
from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

RANGES = dict(draw=(0x2490, 0x270d), palette_current=(0x2320, 0x23da), palette_staged=(0x23e0, 0x2481))
PARAMETERS = dict(draw=[('state', 'pcx_state'), ('surface', 'cleanup_surface'), ('name', 'asset_name'),
    ('palette', 'u32'), ('x', 'u32'), ('y', 'u32')],
    palette_current=[('state', 'pcx_state'), ('name', 'asset_name')],
    palette_staged=[('state', 'pcx_state'), ('name', 'asset_name')])
SERVICES = dict(open=[('name', 'asset_name')], refill=[('file', 'pcx_file')],
    seek=[('file', 'pcx_file'), ('offset', 'u32'), ('origin', 'u32')], close=[('file', 'pcx_file')],
    describe=[('surface', 'cleanup_surface'), ('view', 'pcx_view')],
    lock=[('surface', 'cleanup_surface'), ('view', 'pcx_view')],
    unlock=[('surface', 'cleanup_surface')], apply=[('state', 'pcx_state')])
RESULTS = dict(open='pcx_file', refill='u32', lock='u32')
TYPES = [*asset.ASSET_TYPES, *[dict(id='pcx_'+name, kind='opaque', nominal_id='dxball.pcx.'+name)
    for name in ('state', 'file', 'view')]]


def bridge_spec():
    return dict(adapters={name: dict(symbol='pcx_'+name, kind='portable', context=True,
        outcomes={'return': None}) for name in SERVICES}, transports={}, native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "pcx-runtime.h"\n#include "comparison-service-bridge.h"\n'
    types = dict(pcx_state='pcx_state *', cleanup_surface='font_surface *', asset_name='asset_name *', u32='uint32_t')
    for number, (name, parameters) in enumerate(PARAMETERS.items()):
        signature = ', '.join(types[kind]+' '+key for key, kind in parameters)
        arguments = ', '.join(key for key, _ in parameters)
        text += f'''void fixture_pcx_{name}({signature}) {{
    pcx_enter({number});
    spx_pcx_image_services_v5 services = spx_pcx_image_bind_services(NULL);
    spx_pcx_image_context_v5 context = {{0}}; context.services = &services;
    spx_pcx_image_services_begin(); lifted_pcx_{name}(&context, {arguments}); spx_pcx_image_services_end();
}}
'''
    return text


def inputs(assets, output):
    files = {p.name: p for p in sorted(assets.glob('*.pcx'))}
    rows = [dict(id=p.stem+'-palette-'+str(mode), arguments=[p.name, str(mode), '0', '0', '0'])
            for p in files.values() for mode in (1, 2)]
    def small(name, xmax, ymax, encoded, *, truncated=False):
        header = bytearray(128); struct.pack_into('<hh', header, 8, xmax, ymax)
        palette = bytes((i*17+3) % 256 for i in range(768))
        path = output/(name+'.pcx')
        path.write_bytes(bytes(header[:16]) if truncated else bytes(header)+bytes(encoded)+bytes([12])+palette)
        files[path.name] = path
        return path.name
    literal = small('literal', 4, 3, range(32))
    runs = small('runs', 4, 3, [0xc0, 29, 0xc5, 41, 0xc7, 199, 0xc8, 123])
    negative = small('negative', -2, 3, [19, 27])
    short = small('short', -1, -1, [], truncated=True)
    for identity, name, palette, x, y, mode in (
        ('literal-none', literal, 0, 0, 0, 0), ('zero-run-overshoot', runs, 2, 0, 0, 1),
        ('left-top-clipping', runs, 1, 0xfffffffe, 0xffffffff, 2),
        ('right-bottom-clipping', runs, 2, 15, 8, 0), ('offscreen', literal, 0, 40, 50, 0),
        ('signed-coordinate', literal, 3, 0x80000000, 0, 0), ('negative-header', negative, 0, 0, 0, 1),
        ('short-stream', short, 0, 0, 0, 2), ('lock-description-change', literal, 1, 1, 1, 3),
        ('palette-alias-write', runs, 1, 0, 0, 4)):
        rows.append(dict(id=identity, arguments=list(map(str, (name, palette, x, y, mode)))))
    return files, rows


def prepare(original, assets, output):
    started = time.monotonic()
    if sha256_file(original) != asset.cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    files, cases = inputs(assets, output)
    definitions = {name: ServiceDefinition.create(identity='dxball.pcx.'+name, types=TYPES,
        parameters=parameters, result=RESULTS.get(name, 'unit'), resources=[], effects=['dxball.pcx.'+name],
        outcomes=['return'], unobserved=['Live buffered-file/pixel-view ownership and explicit domain in BOUNDARY.md.'])
        for name, parameters in SERVICES.items()}
    used = dict(draw=list(SERVICES), palette_current=['open', 'seek', 'refill', 'close', 'apply'],
                palette_staged=['open', 'seek', 'refill', 'close'])
    interface = component_interface(component_id='pcx-image', types=TYPES, services=definitions,
        operations={name: OperationDefinition(parameters, 'unit', used[name]) for name, parameters in PARAMETERS.items()})
    catalog = service_catalog(definitions).to_payload()
    write_json(output/'interface.json', interface.to_payload()); write_json(output/'services.json', catalog)
    write_json(output/'bridge.json', bridge_spec()); (output/'bridge.c').write_text(bridge())
    sources = {'pcx.c': HERE/'pcx.c', 'pcx-state.h': HERE/'pcx-state.h',
        'asset-state.h': FONT/'asset-state.h', 'font-state.h': FONT/'font-state.h',
        'cleanup-state.h': asset.CLEANUP/'cleanup-state.h'}
    arguments = ['component', 'start', 'dxball', 'pcx-image', '--interface-intent', str(output/'interface.json'),
        '--service-catalog', str(output/'services.json'), '--service-bridge', str(output/'bridge.json'),
        '--assumption-file', str(HERE/'BOUNDARY.md'), '--remove-source', 'source/component.c', '--output', str(output/'authoring')]
    for name in PARAMETERS: arguments += ['--operation-symbol', name+'=lifted_pcx_'+name]
    for name, path in sources.items(): arguments += ['--source-file', 'source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *arguments], capture_output=True, text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    ranges = {'pcx_'+name: bounds for name, bounds in RANGES.items()}
    ranges.update(startup=(0xeaa0, 0xeaa5), pcx_open=(0xe190, 0xe1a5), pcx_refill=(0xdfd0, 0xdfd8),
                  pcx_seek=(0xe0c0, 0xe0c8), pcx_close=(0xdf50, 0xdf58))
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,
        expected_sha256=sha256_file(original), module=None, entry_rva=lo, end_rva=hi, installer='install_'+name)
        for name, (lo, hi) in ranges.items()))
    environment = native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name: output/'authoring/source'/name for name in sources},
        operation_symbols={name: 'lifted_pcx_'+name for name in PARAMETERS}, target_id='dxball', component_id='pcx-image',
        adapter_files={'runtime.c': HERE/'runtime.c', 'bridge.c': output/'bridge.c'},
        include_files={'pcx-runtime.h': HERE/'pcx-runtime.h', 'native-image.h': output/'native-image.h',
            **native_adapter_headers('pe32-entry-hook.h'), **observation_headers()},
        **{**environment, 'runtime_files': {**environment['runtime_files'], 'DXBall.exe': original, **files}},
        original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases,
        observation_fields=['pixels', 'after_draw', 'after_palettes', 'files', 'services'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Binary-derived PCX decoder/palette loading, real assets and generated malformed inputs, full pixel/palette observations and buffered I/O.',
        service_catalog=catalog, service_bridge=bridge_spec(), export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-pcx.dll', symbol='dx_pcx_anchor'),
        output=output/'pcx-image')
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, cases=len(cases),
        original_source_consulted=False, tool_internal_changes=False, assets={name: sha256_file(path) for name, path in files.items()}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'assets', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(args.original.resolve(), args.assets.resolve(), args.output.resolve())
