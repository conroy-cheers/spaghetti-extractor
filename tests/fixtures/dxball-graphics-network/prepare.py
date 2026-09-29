"""Prepare a connected DX-Ball experiment from pinned retained inputs.

Manual boundaries and C use the existing interface/service/comparison APIs. The
three small original helpers are recovered with the existing semantic extractor,
normalizer and Behavioral-C renderer. This is retained-C experimental evidence,
not an independently qualified transfer plan or native DirectDraw execution.
"""
import argparse
import json
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_package import comparison_preparation, load_comparison_package, prepare_comparison_package, retained_comparison_environment
from spaghetti_extractor.components.comparison_original import recover_original_c
from spaghetti_extractor.components.service_authoring import component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_environment import host_environment, observation_headers
from declarations import G, SPECS, TYPES, UNITS, definitions

HERE = Path(__file__).resolve().parent
PE_SHA256 = '191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
ROOT_SHA256 = '403920d3d89c6e15185aa6c54fc583fff8a2055f7bb4a09c6f312a9349d6368b'
HELPERS = {0xbc90: [(0xbc90, 0xbc99), (0xbc99, 0xbcb8), (0xbcb8, 0xbcbb)],
           0xbd60: [(0xbd60, 0xbd6a)],
           0xbd90: [(0xbd90, 0xbdcd), (0xbdcd, 0xbdcf)]}
ASSUMPTIONS = [
    'Pinned DX-Ball PE32, retained machine-derived initializer at cd5c, existing semantic extraction of bc90/bd60/bd90; no native-original or strong transfer qualification claim.',
    'Single-threaded entered frame with DF clear, readable/writable stack, three sprite banks, live declared sprite objects and in-range bank/slot indices.',
    'Explicit C transport preserves all selected scalar slots, all 786 bank words, real sprite contents and aliases; unrelated state outside this declared footprint is unobserved.',
    'Controlled resource services check handles and arguments, preserve nonzero HRESULT behavior and residual live resources; framebuffer/driver internals are unobserved.',
    'Selected synchronous hide/message callbacks replace the shared window with another live handle; arbitrary nested reentrancy, event dispatch and concurrency are outside scope.',
    'A retained outside-scope sprite loader populates one bank entry with the actual backbuffer object before the real blit consumer; no fake production call is added.',
    'Finite comparisons of state, aliases, service order/arguments, outcomes, resource/window lifetimes and controlled pixel effects are tested evidence, not a checked memory summary.',
]


def recover_helpers(pe, output, *, initializer=False, initializer_boundary=None):
    boundaries = dict(HELPERS)
    binding_path = initializer_boundary or HERE.parents[2]/'targets/dxball/intent/bindings-v5/directdraw-init.json'
    binding = json.loads(binding_path.read_text()) if initializer else None
    if initializer:
        operation = binding['operations'][0]
        if binding['component_id'] != 'directdraw-init' or operation['entry_rvas'] != [0xcd5c]:
            raise ValueError('review changed initializer boundary before recovery')
        boundaries[0xcd5c] = [tuple(int(part, 16) for part in unit.rsplit('-', 2)[1:])
                             for unit in operation['unit_ids']]
        if len(boundaries[0xcd5c]) != 65:
            raise ValueError('review changed initializer ownership before recovery')
    report=recover_original_c(original=pe,boundaries=boundaries,expected_sha256=PE_SHA256,output=output)
    if binding is not None:
        write_json(output/'initializer-boundary.json', binding)
    report['initializer_boundary_sha256']=sha256_file(output/'initializer-boundary.json') if initializer else None
    write_json(output/'recovery.json',report)


def cases(name):
    seeds = [0, 1, 7, 254, 0x2000000, 0x12345678, 0x80000000, 0xffffffff]
    rows = [dict(id='seed-'+str(seed), arguments=list(map(str, [seed, 0, 0, 1, 0, 0]))) for seed in seeds]
    if name == 'initialize':
        rows += [dict(id=f'failure-{point}-'+('positive' if positive else 'negative'),
                 arguments=list(map(str, [7+point, point, positive, 1, 0, 0])))
                 for point in range(1, 8) for positive in (0, 1)]
        rows += [dict(id=f'callback-{point}-{callback}',
                 arguments=list(map(str, [0x2000001, point, 0, 1, callback, 0])))
                 for point in (1, 3, 7) for callback in (1, 2, 3)]
        rows += [dict(id=f'normal-mode-{mode}-caps-failure-{failure}',
                 arguments=list(map(str, [0x2000001, 0, 0, mode, 0, failure])))
                 for mode in (0, 1, 2) for failure in (0, 1)]
    return rows


def bridge(name):
    params, result = SPECS[name]
    ctype = lambda kind: 'dx_graphics *' if kind == G else 'uint32_t'
    signature = ', '.join(ctype(kind)+' '+key for key, kind in params)
    args = ', '.join(key for key, _ in params)
    returns = 'void' if result == 'unit' else 'uint32_t'
    call = f'bridge_graphics_{name}({args})'
    body = call+';' if result == 'unit' else 'return '+call+';'
    text = '#include "portable-component-implementation.h"\n#include "runtime.h"\n#include "comparison-service-bridge.h"\n'
    text += f'{returns} fixture_graphics_{name}({signature}) {{ dx_enter({list(UNITS).index(name)}); {body} }}\n'
    if name in ('reset', 'bind'):
        text += f'void dx_{name}(void *unused, {signature}) {{ (void)unused; fixture_graphics_{name}({args}); }}\n'
    return text


def prepare(base, pe, output, *, initializer_boundary=None):
    with comparison_preparation(output) as staged:
        _prepare(base, pe, staged, published_output=output,
                 initializer_boundary=initializer_boundary)
    print(output/'graphics-initialize')


def _prepare(base, pe, output, *, published_output, initializer_boundary=None):
    started = time.monotonic()
    if sha256_file(pe) != PE_SHA256:
        raise ValueError('requires the pinned DX-Ball executable')
    if base is None:
        original = None
        environment = host_environment()
    elif base.is_file():
        original = base
        environment = host_environment()
    else:
        base_plan, _ = load_comparison_package(base)
        if base_plan['target_id'] != 'dxball':
            raise ValueError('requires the DX-Ball comparison environment')
        original = base/'adapters/behavioral-fn-0000cd5c.c'
        environment = retained_comparison_environment(base)
    if original is not None and sha256_file(original) != ROOT_SHA256:
        raise ValueError('requires the pinned DX-Ball executable and retained initializer')
    # Host C execution of retained machine semantics needs no Wine runtime.
    if environment['runner'] is not None:
        raise ValueError('requires the retained host-C comparison environment')
    exact = output/'original-helpers'
    recover_helpers(pe, exact, initializer=base is None, initializer_boundary=initializer_boundary)
    if original is None:
        original = exact/'behavioral-fn-0000cd5c.c'
    services = definitions()
    packages = {}
    for number, (name, names) in enumerate(UNITS.items()):
        identity = 'graphics-'+name
        setup = output/(identity+'-setup'); setup.mkdir()
        (setup/'bridge.c').write_text(bridge(name))
        (setup/'case-unit.h').write_text('#define DX_CASE_UNIT '+str(number)+'\n')
        selected = {key: services[key] for key in names}
        params, result = SPECS[name]
        intent = component_interface(component_id=identity, types=TYPES,
            parameters=params, result=result, services=selected)
        suppliers = list(packages) if name == 'initialize' else []
        bindings = bind_dependencies(services={key: packages[key] for key in suppliers if key != 'blit'},
                                     consumers={key: packages[key] for key in suppliers if key == 'blit'})
        adapters = {'driver.c': HERE/'driver.c', 'runtime.c': HERE/'runtime.c',
                    'bridge.c': setup/'bridge.c', 'behavioral-fn-0000cd5c.c': original,
                    **{path.name: path for path in sorted(exact.glob('*.c')) if path.name != 'behavioral-dispatch.c'}}
        headers = {**observation_headers(), 'runtime.h': HERE/'runtime.h', 'graphics-state.h': HERE/'graphics-state.h',
                   'case-unit.h': setup/'case-unit.h',
                   **{path.name: path for path in sorted(exact.glob('*.h'))},
                   'helper-recovery.json': exact/'recovery.json', 'helper-semantics.json': exact/'semantic-inputs.json'}
        if base is None:
            headers['initializer-boundary.json'] = exact/'initializer-boundary.json'
        oracle_files = ['adapters/'+key for key in adapters if key.startswith('behavioral-')]
        oracle_files += ['headers/'+key for key in ('behavioral-c.h', 'state-machine-runtime.h', 'helper-recovery.json', 'helper-semantics.json')]
        if base is None:
            oracle_files.append('headers/initializer-boundary.json')
        # Runtime recovery timings are nonsemantic; retain them outside the bound
        # package rather than making each preparation invalidate all neighbors.
        recovery = json.loads((exact/'recovery.json').read_text()); recovery.pop('seconds'); recovery.pop('timings')
        write_json(setup/'helper-recovery.json', recovery)
        headers['helper-recovery.json'] = setup/'helper-recovery.json'
        destination = output/identity
        prepare_comparison_package(interface_package=intent,
            source_files={name+'.c': HERE/(name+'.c'), 'graphics-state.h': HERE/'graphics-state.h'},
            operation_symbols={'run': 'lifted_graphics_'+name}, target_id='dxball', component_id=identity,
            adapter_files=adapters, include_files=headers, original_files=oracle_files+['runtime/DXBall.exe'],
            oracle_kind='retained-c', cases=cases(name),
            observation_fields=['results', 'state', 'banks', 'resources', 'windows', 'pixels', 'services'],
            assumptions=ASSUMPTIONS, scope='DX-Ball connected initialization, shared sprite tables and live surface consumer; controlled retained-C execution.',
            **bindings, export_adapters=['adapters/bridge.c'],
            service_catalog=service_catalog(selected).to_payload() if selected else None,
            service_bridge=dict(adapters={key: dict(symbol='dx_'+key, kind='portable', context=True,
                outcomes={'return': None}) for key in names}, transports={}, native_symbol='bridge_graphics_'+name),
            representation=dict(group=dict(id='dxball-graphics', label='Shared graphics and sprite state',
                members=['graphics-'+key for key in UNITS]), revision='portable-sprite-pointers-v1',
                inputs={'layout': 'headers/graphics-state.h', 'source-layout': 'source/graphics-state.h',
                        'runtime-contract': 'headers/runtime.h'}),
            output=destination, **{**environment, 'runtime_files': {'DXBall.exe': pe}})
        packages[name] = destination
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started,
        base=str(base) if base is not None else None, original_sha256=PE_SHA256, root_c_sha256=sha256_file(original),
        fresh_initializer_recovery=base is None,
        packages={key: str(published_output/path.relative_to(output)) for key, path in packages.items()},
        manual_inputs=['operation boundaries and frame', 'shared-state layout and observations',
            'service declarations', 'C implementations and platform/transport adapters', 'finite cases'],
        generated=['identities', 'interfaces', 'headers and service bridges', 'dependency selection', 'original helper C'],
        per_unit_tool_internal_changes=False, strong_qualification=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path, nargs='?', help='optional pinned initializer C or retained package; otherwise recover from PE and reviewed boundaries')
    parser.add_argument('original_pe', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--initializer-boundary',type=Path,help='reviewed initializer binding for an external operator project')
    args = parser.parse_args()
    prepare(args.base.resolve() if args.base else None, args.original_pe.resolve(), args.output.resolve(),
            initializer_boundary=args.initializer_boundary.resolve() if args.initializer_boundary else None)
