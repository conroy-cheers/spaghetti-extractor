"""Prepare a connected object lifecycle from retained jq inputs, without rebuilding a pilot."""
import argparse
from pathlib import Path
import time

from declarations import definitions, SPECS, TYPES, UNITS
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import comparison_preparation, load_comparison_package, prepare_comparison_package, retained_comparison_environment
from spaghetti_extractor.components.service_authoring import component_interface, service_catalog
from spaghetti_extractor.util import write_json

HERE = Path(__file__).resolve().parent
ARRAY = HERE.parent/'jq-array-storage'
ORIGINAL = '50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'
RANGES = {'create': (0x25f23, 0x26021), 'release': (0x2a696, 0x2a7e3), 'unshare': (0x2a7e3, 0x2ab32)}
SYMBOLS = {'allocate': 'object_allocate', 'dispose': 'object_dispose', 'copy': 'object_copy_value',
    'release_value': 'object_release_value', 'create': 'object_create', 'release_object': 'object_release'}


def prepare(base, output):
    started = time.monotonic(); plan, _ = load_comparison_package(base)
    if plan['target_id'] != 'jq' or plan['original']['files'].get('runtime/libjq-1.dll') != ORIGINAL:
        raise ValueError('requires retained inputs for the reviewed jq PE32 DLL')
    services = definitions(); packages = {}
    with comparison_preparation(output) as stage:
        entries = {}
        for name, (entry, end) in RANGES.items():
            path = stage/(name+'-entry.h')
            path.write_text(native_entry_header(original=base/'runtime/libjq-1.dll', expected_sha256=ORIGINAL,
                module='libjq-1.dll', entry_rva=entry, end_rva=end, installer='install_object_'+name))
            entries[path.name] = path
        for name, names in UNITS.items():
            identity = 'object-'+name
            interface = component_interface(component_id=identity, types=TYPES, parameters=SPECS[name][0],
                result=SPECS[name][1], services={key: services[key] for key in names})
            bridge = stage/(name+'-bridge.c')
            bridge.write_text('#include "portable-component-implementation.h"\n#include "object-storage-native.h"\n'
                             '#include "comparison-service-bridge.h"\n')
            selected = {'create': packages['create'], 'release_object': packages['release']} if name == 'unshare' else {}
            bindings = bind_dependencies(services=selected)
            recursion = []
            if name == 'release':
                bindings['requirements'].append(dict(id='nested-objects', supplier=identity, contract_sha256='self',
                                                    kind='internal', service=None))
                recursion = [dict(id='jq-object-destruction', members=[identity], mode='synchronous-comparison', progress='unproved')]
            source = {'object-storage.h': HERE/'object-storage.h', 'value-layout.h': ARRAY/'unpacked-value-layout.h',
                      'native-storage.h': ARRAY/'native-storage.h'}
            cases = [dict(id='shared-holes-growth', arguments=['shared']),
                     dict(id='unique-holder-alias', arguments=['unique']),
                     dict(id='interpreter', arguments=['program'])]
            if name != 'release': cases.append(dict(id='allocation-failure', arguments=['nomem-'+name]))
            destination = stage/identity
            prepare_comparison_package(interface_package=interface, target_id='jq', component_id=identity,
                source_files={name+'.c': HERE/(name+'.c'), **source}, operation_symbols={'run': 'lifted_object_'+name},
                adapter_files={'driver.c': HERE/'driver.c', 'bridge.c': bridge, 'allocation-observer.c': ARRAY/'allocation-observer.c'},
                include_files={**entries, **native_adapter_headers('pe32-entry-hook.h', 'pe32-import-hook.h'),
                    'object-storage-native.h': HERE/'object-storage-native.h', 'object-runtime.h': HERE/'object-runtime.h',
                    'allocation-observer.h': ARRAY/'allocation-observer.h', 'jv.h': base/'headers/jv.h',
                    'jq.h': base/'headers/jq.h', 'COPYING.jq': ARRAY/'COPYING.jq', 'BOUNDARY.md': HERE/'BOUNDARY.md'},
                original_files=['runtime/libjq-1.dll'], oracle_kind='native-original', cases=cases,
                observation_fields=['sample', 'allocation_lifetime'], assumptions=[(HERE/'BOUNDARY.md').read_text()],
                scope='Connected object creation, destruction and copy-on-write through private native entries and interpreter consumers.',
                service_catalog=service_catalog({key: services[key] for key in names}).to_payload(),
                service_bridge=dict(native_symbol='fixture_object_'+name, transports={}, adapters={key: dict(
                    symbol=SYMBOLS[key], kind='portable', context=True, outcomes={'return': None}) for key in names}),
                export_adapters=['adapters/bridge.c'], recursion_groups=recursion, **bindings,
                representation=dict(group=dict(id='jq-object-storage', label='Live jq object tables',
                    members=['object-'+key for key in UNITS]), revision='unpacked-values-native-object-table-v1',
                    inputs={'value-layout': 'source/value-layout.h', 'native-storage': 'source/native-storage.h',
                            'object-layout': 'source/object-storage.h'}),
                output=destination, **retained_comparison_environment(base))
            packages[name] = destination
        write_json(stage/'preparation.json', dict(seconds=time.monotonic()-started, original_sha256=ORIGINAL,
            reused=['value representation and copy/release declarations', 'allocation observer', 'entry adapters',
                    'comparison composition and normal public edit/check/export'],
            new_checker_or_compiler_rules=False, model_seconds=0, solver_seconds=0))
    print(output/'object-unshare')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); prepare(args.base.resolve(), args.output.resolve())
