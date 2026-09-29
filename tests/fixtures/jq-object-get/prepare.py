"""Prepare a consuming object lookup with a borrowed live table and shared services."""
import argparse
import json
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_environment import retained_service_inputs
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import comparison_preparation, load_comparison_package, prepare_comparison_package
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.resource_authoring import component_resource_checks
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface, service_catalog, service_resource_roles
from spaghetti_extractor.util import write_json

HERE = Path(__file__).resolve().parent
ORIGINAL = '50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'


def prepare(network, output):
    started = time.monotonic()
    plan, _ = load_comparison_package(network)
    if plan['target_id'] != 'jq' or plan['original']['files'].get('runtime/libjq-1.dll') != ORIGINAL:
        raise ValueError('requires the reviewed pinned jq path network')
    unit = next(row for row in plan['dependencies'] if row['id'] == 'value-get')
    intent = ComponentInterfaceIntentV1.parse(json.loads((network / unit['interface']).read_text()))
    types = [row.to_payload() for row in intent.schema.types if row.kind != 'function']
    types.append(dict(id='object_table', kind='opaque', nominal_id='jq.borrowed-object-table'))
    headers = {name: 'headers/' + name for name in ('jv.h', 'jq.h', 'value-transport.h',
        'value-runtime-impl.h', 'allocation-observer.h', 'pe32-entry-hook.h', 'pe32-import-hook.h')}
    headers['COPYING.jq'] = 'dependencies/string-slice/headers/COPYING.jq'
    services, shared = retained_service_inputs(network, component_id='value-get', names=['release'],
        native_symbol='fixture_object_get',
        adapters={name: 'adapters/' + name for name in ('value-runtime.c', 'allocation-observer.c')}, headers=headers)
    shared['service_bridge']['adapters']['release']['symbol'] = 'jv_free'
    specs = {
        'contents': ([('value', 'jv_value'), ('view', 'object_table')], 'unit', 'object_contents'),
        'hash': ([('key', 'jv_value')], 'u32', 'object_key_hash'),
        'equal': ([('key', 'jv_value'), ('view', 'object_table'), ('index', 'i32')], 'u32', 'object_key_equal'),
        'copy_value': ([('view', 'object_table'), ('index', 'i32')], 'jv_value', 'object_value_copy'),
        'invalid': ([], 'jv_value', 'jv_invalid'),
    }
    for name, (parameters, result, symbol) in specs.items():
        roles = service_resource_roles(parameters, borrows=[n for n, t in parameters if t == 'jv_value'],
            produces=result == 'jv_value', resource_kind='jq-reference', provider_domain='libjq')
        services[name] = ServiceDefinition.create(identity='jq.object.' + name, types=types,
            parameters=parameters, result=result, resources=roles, effects=['jq.object.' + name],
            outcomes=['return'], nonlocal_outcomes=[],
            unobserved=['Shared table applicability, view lifetime and temporary reference changes are reviewed C adapter premises.'])
        shared['service_bridge']['adapters'][name] = dict(symbol=symbol, kind='native', outcomes={'return': None})
    interface = component_interface(component_id='object-get', types=types,
        parameters=[('value', 'jv_value'), ('key', 'jv_value')], result='jv_value', services=services)
    resources = component_resource_checks(interface, consumes=['value', 'key'], produces=['result'],
        resource_kind='jq-reference', provider_domain='libjq', service_id='value-transport',
        interaction_contract_id='object-get.reference-transfer', instrumented_sides=['source'],
        unobserved=['Borrowed table reads, aliases and native internals are compared, not proved.'])
    table = {'key' + str(i): {'value': i} for i in range(32)}
    rows = [[table, key] for key in ('key0', 'key17', 'missing')]
    rows += [[{'null': None, 'nested': [1, {'keep': 2}]}, 'null'], [{}, 'absent']]
    with comparison_preparation(output) as staged:
        bridge = staged / 'bridge.c'
        bridge.write_text('#include "portable-component-implementation.h"\n#include "object-native.h"\n'
                          '#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
        entry = staged / 'native-entry.h'
        entry.write_text(native_entry_header(original=network / 'runtime/libjq-1.dll', expected_sha256=ORIGINAL,
            module='libjq-1.dll', entry_rva=0x2a3e5, end_rva=0x2a559))
        shared['adapter_files'].update({'driver.c': HERE / 'driver.c', 'bridge.c': bridge})
        shared['include_files'].update({'object-native.h': HERE / 'object-native.h', 'BOUNDARY.md': HERE / 'BOUNDARY.md',
            'native-entry.h': entry, 'binary-driver.h': HERE.parent / 'jq-value-transport/binary-driver.h'})
        shared['service_catalog'] = service_catalog(services).to_payload()
        prepare_comparison_package(interface_package=interface, target_id='jq', component_id='object-get',
            source_files={'get.c': HERE / 'get.c', 'object-view.h': HERE / 'object-view.h'},
            operation_symbols={'run': 'lifted_object_get'}, original_files=['runtime/libjq-1.dll'], oracle_kind='native-original',
            cases=[dict(id='shared-table', arguments=[json.dumps(rows), 'null', 'batch']),
                   dict(id='unique-owner', arguments=['{"a":{"n":7}}', '"a"', 'unique']),
                   dict(id='program', arguments=['. as $before | .key0.value=99 | del(.key17) | '
                       '[.key0.value, .key17, $before.key0.value, $before.key17.value, getpath(["key31","value"])]',
                       json.dumps(table), 'program'])],
            observation_fields=['samples', 'allocation_lifetime'], assumptions=[(HERE / 'BOUNDARY.md').read_text()],
            resource_checks=resources, scope='Complete object lookup over live shared table storage and interpreter callers.',
            export_adapters=['adapters/bridge.c'], output=staged / 'object-get', **shared)
        write_json(staged / 'preparation.json', dict(seconds=time.monotonic() - started, new_tool_internals=False,
            services_reused=['release'], adapters_reused=['value transport', 'allocation observer', 'binary driver'],
            selected_neighbor_bodies=0, model_seconds=0, solver_seconds=0))
    print(output / 'object-get')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('network', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.network.resolve(), args.output.resolve())
