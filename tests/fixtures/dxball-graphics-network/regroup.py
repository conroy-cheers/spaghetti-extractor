"""Group the reviewed reset and bind entries without changing their algorithms.

This operator recipe preserves the initializer/blit C, original execution setup
and state transport. The new local driver exercises both existing entries. Only
the two supplier context type names and their ordinary C bridge change.
"""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies, contract_identity
from spaghetti_extractor.components.comparison_package import (
    comparison_preparation, load_comparison_package, prepare_comparison_package,
    retained_comparison_environment, revise_comparison_package,
)
from spaghetti_extractor.components.service_authoring import OperationDefinition, component_interface
from spaghetti_extractor.util import write_json
from declarations import SPECS, TYPES


def prepare(packages, consumer, output):
    started = time.monotonic()
    caller, _ = load_comparison_package(consumer)
    selected = {unit['id']: unit for unit in caller.get('dependencies', [])}
    if ((caller['target_id'], caller['component_id']) != ('dxball', 'graphics-initialize')
            or set(selected) != {'graphics-reset', 'graphics-bind', 'graphics-blit'}):
        raise ValueError('requires the reviewed four-component graphics selection')
    plans = {}
    for name, unit in selected.items():
        plan, _ = load_comparison_package(packages/name)
        if contract_identity(packages/name, plan) != contract_identity(consumer, unit):
            raise ValueError('review the changed local/consumer boundary before regrouping: '+name)
        plans[name] = plan
    representation = {**caller['representation'],
        'group': {**caller['representation']['group'],
                  'members': ['graphics-blit', 'graphics-initialize', 'graphics-state']},
        'revision': caller['representation']['revision']+'-grouped-reset-bind'}
    with comparison_preparation(output) as staged:
        setup = staged/'setup'; setup.mkdir()
        for name in ('reset', 'bind'):
            source = consumer/('dependencies/graphics-'+name+'/source/'+name+'.c')
            (setup/(name+'.c')).write_text(source.read_text().replace(
                'spx_graphics_'+name+'_context_v5', 'spx_graphics_state_context_v5'))
        bridge = setup/'bridge.c'
        bridge.write_text('''#include "portable-component-implementation.h"
#include "runtime.h"
void fixture_graphics_reset(dx_graphics *state) {
  spx_graphics_state_context_v5 context = {0};
  dx_enter(0); lifted_graphics_reset(&context, state);
}
void fixture_graphics_bind(dx_graphics *state, uint32_t surface) {
  spx_graphics_state_context_v5 context = {0};
  dx_enter(1); lifted_graphics_bind(&context, state, surface);
}
void dx_reset(void *unused, dx_graphics *state) {
  (void)unused; fixture_graphics_reset(state);
}
void dx_bind(void *unused, dx_graphics *state, uint32_t surface) {
  (void)unused; fixture_graphics_bind(state, surface);
}
''')
        local = packages/'graphics-reset'; plan = plans['graphics-reset']
        driver = (local/'adapters/driver.c').read_text()
        old = 'if (source) fixture_graphics_reset(state); else original_reset(state);'
        if driver.count(old) != 1:
            raise ValueError('review the changed local driver before grouping its entries')
        (setup/'driver.c').write_text(driver.replace(old, '''if (source) {
    fixture_graphics_reset(state); fixture_graphics_bind(state,args[0]);
    dx_check_selected(1,0);
  } else { original_reset(state); original_bind(state,args[0]); }'''))
        interface = component_interface(component_id='graphics-state', types=TYPES,
            operations={name: OperationDefinition(parameters=SPECS[name][0], result=SPECS[name][1])
                        for name in ('reset', 'bind')}, services={})
        adapters = {path.removeprefix('adapters/'): local/path for path in plan['adapters']}
        adapters.update({'bridge.c': bridge, 'driver.c': setup/'driver.c'})
        headers = {p.relative_to(local/'headers').as_posix(): p
                   for p in (local/'headers').rglob('*') if p.is_file()}
        group = staged/'graphics-state'
        prepare_comparison_package(interface_package=interface,
            source_files={name+'.c': setup/(name+'.c') for name in ('reset', 'bind')}
                         | {'graphics-state.h': local/'source/graphics-state.h'},
            operation_symbols={name: 'lifted_graphics_'+name for name in ('reset', 'bind')},
            target_id='dxball', component_id='graphics-state', adapter_files=adapters,
            include_files=headers, original_files=list(plan['original']['files']),
            oracle_kind=plan['original']['kind'], cases=plan['cases'],
            observation_fields=plan['observation_fields'], assumptions=plan['assumptions'],
            scope='DX-Ball reset and bind grouped as two complete entries; local sequential state observations.',
            representation=representation, export_adapters=['adapters/bridge.c'], output=group,
            **retained_comparison_environment(local))
        blit = staged/'graphics-blit'; local = packages/'graphics-blit'
        unit = selected['graphics-blit']; plan = plans['graphics-blit']
        adapters = {p.removeprefix('adapters/'): local/p for p in plan['adapters']}
        adapters.update({Path(p).name: consumer/p for p in unit['adapters']})
        revise_comparison_package(package=local, output=blit, representation=representation,
            source_files={p.removeprefix('dependencies/graphics-blit/source/'): consumer/p for p in unit['sources']},
            adapter_files=adapters)
        bindings = bind_dependencies(services={'reset': group, 'bind': group}, consumers={'blit': blit})
        revise_comparison_package(package=consumer, output=staged/'graphics-initialize',
            remove_dependencies=sorted(selected), representation=representation, **bindings)
        write_json(staged/'regrouping.json', dict(status='prepared', authority=False,
            before=['graphics-reset', 'graphics-bind'], after='graphics-state',
            original_entries={'reset': '0xbc90', 'bind': '0xbd60'},
            control_flow_cuts_changed=False, algorithms_preserved=True,
            initializer_and_blit_c_preserved=True, comparisons_required=True,
            seconds=time.monotonic()-started))
    print(output/'graphics-initialize')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages', type=Path, help='matching local graphics workspaces')
    parser.add_argument('consumer', type=Path, help='edited or native initializer workspace')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.packages.resolve(), args.consumer.resolve(), args.output.resolve())
