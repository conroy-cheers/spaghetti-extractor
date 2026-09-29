"""Public component preparation from manual binary-only cleanup boundaries.

Run in the lifting shell. This reads only the original executable and this
operator-authored directory; it never fetches or consults upstream game source.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header, recover_original_c
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent
PE_SHA256 = '191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
TYPES = [dict(id='unit', kind='void'), dict(id='u32', kind='integer', width_bits=32, signed=False),
         *[dict(id='cleanup_'+name, kind='opaque', nominal_id='dxball.cleanup.'+name)
           for name in ('state', 'sprite', 'surface')]]
STATE = [('state', 'cleanup_state')]
SPECS = {'select': STATE+[('bank', 'u32')], 'dispose': STATE+[('slot', 'u32')],
         'clear': STATE, 'release': STATE+[('surface', 'cleanup_surface')],
         'free_sprite': STATE+[('sprite', 'cleanup_sprite')]}
SERVICES = {'select': [], 'dispose': ['release', 'free_sprite'], 'clear': ['select', 'dispose']}
RANGES = {'select': (0xbd70, 0xbd7a), 'dispose': (0xc510, 0xc59e), 'clear': (0xbcc0, 0xbd00),
          'free': (0xe2a0, 0xe2ea), 'startup': (0xeaa0, 0xeaa5)}
BLOCKS = {0xbd70: [(0xbd70, 0xbd7a)],
          0xc510: [(0xc510, 0xc532), (0xc532, 0xc538), (0xc538, 0xc53e),
                   (0xc53e, 0xc562), (0xc562, 0xc57c), (0xc57c, 0xc59c), (0xc59c, 0xc59e)],
          0xbcc0: [(0xbcc0, 0xbcca), (0xbcca, 0xbcd8), (0xbcd8, 0xbcdb),
                   (0xbcdb, 0xbce1), (0xbce1, 0xbced), (0xbced, 0xbcfc), (0xbcfc, 0xbd00)]}
FIELDS = ['current_bank', 'banks', 'objects', 'surface_refs', 'guards', 'services']


def cases(name):
    rows = []
    def add(identity, seed=0, kind=1, slot=0, caller=0):
        rows.append(dict(id=identity, arguments=list(map(str, [seed, kind, slot, caller]))))
    if name == 'select':
        for seed in (0, 1, 2, 0x80000000, 0xffffffff): add('word-'+str(seed), seed)
        add('native-clear', 13, 3, caller=1)
    elif name == 'dispose':
        for kind in range(8):
            add('direct-kind-'+str(kind), 0, kind)
        for bank in range(3):
            for slot in (1, 127, 253, 254): add(f'bank-{bank}-slot-{slot}', bank, slot=slot)
        add('repeat', 2, caller=2)
        for kind in (0, 1, 2, 3, 5, 6, 7): add('native-clear-kind-'+str(kind), 7, kind, caller=1)
    else:
        for kind in (0, 1, 2, 3, 5, 6, 7): add('network-kind-'+str(kind), 7, kind)
        # Fixed generated cases: broad input words, independently seeded payloads
        # and counts. Oracle comparisons, not implementation-derived assertions.
        seed = 0x516ea2b9
        for i in range(16):
            seed = (1664525*seed+1013904223) & 0xffffffff
            add('generated-'+str(i), seed, (0, 1, 2, 3, 5, 6, 7)[i % 7])
    return rows


def bridge(name):
    parameters = 'cleanup_state *state'+(', uint32_t value' if name != 'clear' else '')
    arguments = 'state'+(', value' if name != 'clear' else '')
    text = '#include "portable-component-implementation.h"\n#include "runtime.h"\n#include "comparison-service-bridge.h"\n'
    text += f'void fixture_{name}({parameters}) {{ trial_enter({list(SERVICES).index(name)}); bridge_{name}({arguments}); }}\n'
    if name != 'clear':
        text += f'void trial_{name}(void *unused, {parameters}) {{ (void)unused; fixture_{name}({arguments}); }}\n'
    return text


def prepare(original, output):
    started = time.monotonic()
    if sha256_file(original) != PE_SHA256:
        raise ValueError('requires the pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    recovery = recover_original_c(original=original, boundaries=BLOCKS,
        expected_sha256=PE_SHA256, output=output/'machine-c')
    environment = native_environment()
    definitions = {name: ServiceDefinition.create(identity='dxball.cleanup.'+name,
        types=TYPES, parameters=parameters, result='unit', resources=[],
        effects=['dxball.cleanup.'+name], outcomes=['return'],
        unobserved=['Controlled synchronous services, explicit C identity/contents/lifetime observations; no checked heap summary or production allocator/DirectDraw semantics.'])
        for name, parameters in SPECS.items()}
    native_header = '\n'.join(native_entry_header(original=original, expected_sha256=PE_SHA256,
        module=None, entry_rva=lo, end_rva=hi, installer='install_'+name)
        for name, (lo, hi) in RANGES.items())
    (output/'native-image.h').write_text(native_header)
    assumptions = [(HERE/'BOUNDARY.md').read_text()]
    packages = {}; commands = []
    for number, (name, names) in enumerate(SERVICES.items()):
        identity = 'cleanup-'+name
        setup = output/(name+'-setup'); setup.mkdir()
        selected = {key: definitions[key] for key in names}
        intent = component_interface(component_id=identity, types=TYPES,
            parameters=SPECS[name], result='unit', services=selected)
        write_json(setup/'interface.json', intent.to_payload())
        catalog = service_catalog(selected).to_payload() if selected else None
        service_bridge = dict(adapters={key: dict(symbol='trial_'+key, kind='portable', context=True,
            outcomes={'return': None}) for key in names}, transports={}, native_symbol='bridge_'+name)
        write_json(setup/'services.json', catalog)
        write_json(setup/'bridge.json', service_bridge)
        (setup/'bridge.c').write_text(bridge(name))
        (setup/'case-unit.h').write_text('#define DX_UNIT '+str(number)+'\n')
        # Exercise the documented interface-first entry point before executable
        # setup. This workspace is an editable operator input, not evidence.
        workspace = output/(name+'-authoring')
        args = ['component', 'start', 'dxball', identity, '--interface-intent', str(setup/'interface.json'),
            '--service-bridge', str(setup/'bridge.json'),
            '--assumption-file', str(HERE/'BOUNDARY.md'), '--operation-symbol', 'run=lifted_cleanup_'+name,
            '--remove-source', 'source/component.c',
            '--source-file', 'source/'+name+'.c='+str(HERE/(name+'.c')),
            '--source-file', 'source/cleanup-state.h='+str(HERE/'cleanup-state.h'), '--output', str(workspace)]
        if selected: args += ['--service-catalog', str(setup/'services.json')]
        phase = time.monotonic()
        result = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *args], capture_output=True, text=True)
        (setup/'start.stdout').write_text(result.stdout); (setup/'start.stderr').write_text(result.stderr)
        commands.append(dict(arguments=args, exit_code=result.returncode, seconds=time.monotonic()-phase))
        write_json(output/'commands.json', commands)
        if result.returncode: raise RuntimeError('interface authoring failed: '+str(setup/'start.stderr'))
        bindings = bind_dependencies(services={key: packages[key] for key in names if key in packages})
        destination = output/identity
        prepare_comparison_package(interface_package=workspace/'interface.json',
            source_files={name+'.c': workspace/'source'/f'{name}.c', 'cleanup-state.h': workspace/'source/cleanup-state.h'},
            operation_symbols={'run': 'lifted_cleanup_'+name}, target_id='dxball', component_id=identity,
            adapter_files={'runtime.c': HERE/'runtime.c', 'bridge.c': setup/'bridge.c'},
            include_files={'runtime.h': HERE/'runtime.h', 'cleanup-state.h': HERE/'cleanup-state.h',
                'case-unit.h': setup/'case-unit.h', 'native-image.h': output/'native-image.h',
                **native_adapter_headers('pe32-entry-hook.h'), **observation_headers()},
            **{**environment, 'runtime_files': {**environment['runtime_files'], 'DXBall.exe': original}},
            original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(name),
            observation_fields=FIELDS, assumptions=assumptions,
            scope='Binary-only DX-Ball sprite cleanup; local and unchanged-native-consumer comparisons with controlled release/free services; no game startup.',
            service_catalog=catalog, service_bridge=service_bridge, **bindings,
            export_adapters=['adapters/bridge.c'],
            representation=dict(group=dict(id='dxball-cleanup', label='Sprite cleanup objects and tables',
                members=['cleanup-'+key for key in SERVICES]), revision='portable-objects-v1',
                inputs={'layout': 'source/cleanup-state.h', 'runtime-layout': 'headers/cleanup-state.h',
                        'runtime-contract': 'headers/runtime.h'}),
            program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe',
                library='dx-cleanup.dll', symbol='dx_cleanup_anchor'), output=destination)
        packages[name] = destination
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started,
        recovery=recovery['timings'], original_sha256=PE_SHA256, original_source_consulted=False,
        per_component_tool_internal_changes=False, cases={name: len(cases(name)) for name in SERVICES}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.original.resolve(), args.output.resolve())
