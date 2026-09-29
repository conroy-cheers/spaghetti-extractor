"""Reuse the live-object boundary for a consuming, copy-on-write deletion."""
import argparse
import json
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_environment import retained_service_inputs
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import comparison_preparation, load_comparison_package, prepare_comparison_package
from spaghetti_extractor.components.resource_authoring import component_resource_checks
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface, service_catalog, service_resource_roles, service_types
from spaghetti_extractor.util import write_json

HERE = Path(__file__).resolve().parent
ORIGINAL = '50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'


def prepare(base, output):
    started = time.monotonic()
    plan, _ = load_comparison_package(base)
    if plan['component_id'] != 'object-get' or plan['original']['files'].get('runtime/libjq-1.dll') != ORIGINAL:
        raise ValueError('requires the reviewed pinned jq object-get local workspace')
    services, shared = retained_service_inputs(base, names=['release', 'hash'], native_symbol='fixture_object_delete',
        adapters=['value-runtime.c', 'allocation-observer.c'],
        headers=['jv.h', 'jq.h', 'value-transport.h', 'value-runtime-impl.h', 'allocation-observer.h',
                 'object-native.h', 'COPYING.jq', 'pe32-entry-hook.h', 'pe32-import-hook.h', 'binary-driver.h'])
    types = service_types(services, types=[dict(id='i32', kind='integer', width_bits=32, signed=True),
        dict(id='mutable_object_table', kind='opaque', nominal_id='jq.exclusive-object-table')])
    specs = {
        'unshare': ([('value', 'jv_value'), ('view', 'mutable_object_table')], 'jv_value', 'object_unshare_view'),
        'equal': ([('key', 'jv_value'), ('view', 'mutable_object_table'), ('index', 'i32')], 'u32', 'object_mutable_equal'),
        'erase': ([('view', 'mutable_object_table'), ('index', 'i32')], 'unit', 'object_erase_slot'),
    }
    for name, (parameters, result, symbol) in specs.items():
        roles = service_resource_roles(parameters, consumes=['value'] if name == 'unshare' else [],
            borrows=['key'] if name == 'equal' else [], produces=result == 'jv_value',
            resource_kind='jq-reference', provider_domain='libjq')
        services[name] = ServiceDefinition.create(identity='jq.object.mutable.' + name, types=types,
            parameters=parameters, result=result, resources=roles, effects=['jq.object.mutable.' + name],
            outcomes=['return'], nonlocal_outcomes=['nomem'] if name == 'unshare' else [],
            unobserved=['Exclusive live table, stored references and allocation failure are reviewed executable premises.'])
        shared['service_bridge']['adapters'][name] = dict(symbol=symbol, kind='native', outcomes={'return': None})
    interface = component_interface(component_id='object-delete', services=services,
        parameters=[('value', 'jv_value'), ('key', 'jv_value')], result='jv_value')
    resources = component_resource_checks(interface, consumes=['value', 'key'], produces=['result'],
        resource_kind='jq-reference', provider_domain='libjq', service_id='value-transport',
        interaction_contract_id='object-delete.reference-transfer', instrumented_sides=['source'],
        unobserved=['Direct table writes and lower allocation/reference behavior are compared, not proved.'],
        nonlocal_allowances={'nomem': dict(max_untransferred=3, max_retained=0)})
    shared['service_catalog'] = service_catalog(services).to_payload()
    table = {'key' + str(i): {'value': i} for i in range(32)}
    rows = [[table, key] for key in ('key0', 'key17', 'missing')]
    rows += [[{'null': None, 'nested': [1, {'keep': 2}]}, 'null'], [{}, 'absent']]
    with comparison_preparation(output) as staged:
        bridge = staged / 'bridge.c'
        bridge.write_text('#include "portable-component-implementation.h"\n#include "object-mutable-native.h"\n'
                          '#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
        entry = staged / 'native-entry.h'
        entry.write_text(native_entry_header(original=base / 'runtime/libjq-1.dll', expected_sha256=ORIGINAL,
            module='libjq-1.dll', entry_rva=0x2b1e4, end_rva=0x2b2e3))
        shared['adapter_files'].update({'driver.c': HERE / 'driver.c', 'bridge.c': bridge, 'native-unshare.c': HERE / 'native-unshare.c'})
        shared['include_files'].update({'object-mutable-native.h': HERE / 'object-mutable-native.h',
                                       'native-entry.h': entry, 'BOUNDARY.md': HERE / 'BOUNDARY.md'})
        prepare_comparison_package(interface_package=interface, target_id='jq', component_id='object-delete',
            source_files={'delete.c': HERE / 'delete.c', 'object-mutable-view.h': HERE / 'object-mutable-view.h',
                          'object-view.h': base / 'source/object-view.h'},
            operation_symbols={'run': 'lifted_object_delete'}, original_files=['runtime/libjq-1.dll'], oracle_kind='native-original',
            cases=[dict(id='shared-table', arguments=[json.dumps(rows), 'null', 'batch']),
                   dict(id='unique-owner', arguments=['{"a":{"n":7},"b":[1,2]}', '"a"', 'unique-address']),
                   dict(id='program', arguments=['. as $before | del(.key17) | .key0.value=99 | '
                       '[.key17, .key0.value, $before.key17.value, $before.key0.value, getpath(["key31","value"])]',
                       json.dumps(table), 'program'])],
            observation_fields=['samples', 'allocation_lifetime'], assumptions=[(HERE / 'BOUNDARY.md').read_text()],
            scope='Consuming object deletion with real copy-on-write, mutable bucket links and interpreter callers.',
            resource_checks=resources, export_adapters=['adapters/bridge.c', 'adapters/native-unshare.c'],
            output=staged / 'object-delete', **shared)
        write_json(staged / 'preparation.json', dict(seconds=time.monotonic() - started, new_tool_internals=False,
            services_reused=['release', 'hash'], adapters_reused=['object layout', 'live value transport', 'allocation observer', 'binary driver'],
            model_seconds=0, solver_seconds=0))
    print(output / 'object-delete')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.base.resolve(), args.output.resolve())
