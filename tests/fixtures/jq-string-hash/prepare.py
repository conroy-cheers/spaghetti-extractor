"""Prepare the consuming cached-string hash used by the lifted object lookup."""
import argparse
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
    if plan['target_id'] != 'jq' or plan['original']['files'].get('runtime/libjq-1.dll') != ORIGINAL:
        raise ValueError('requires the pinned jq object-lookup comparison')
    services, shared = retained_service_inputs(base, names=['release'], native_symbol='fixture_string_hash',
        adapters=['value-runtime.c', 'allocation-observer.c'],
        headers=['jv.h', 'value-transport.h', 'value-runtime-impl.h', 'allocation-observer.h',
                 'COPYING.jq', 'pe32-entry-hook.h', 'pe32-import-hook.h'])
    types = service_types(services, types=[dict(id='u32', kind='integer', width_bits=32, signed=False),
        dict(id='hash_view', kind='opaque', nominal_id='jq.borrowed-string-hash-view')])
    parameters = [('value', 'jv_value'), ('view', 'hash_view')]
    services['view'] = ServiceDefinition.create(identity='jq.hash.view', types=types, parameters=parameters,
        result='unit', resources=service_resource_roles(parameters, borrows=['value'],
            resource_kind='jq-reference', provider_domain='libjq'), effects=['jq.string-cache-view'], outcomes=['return'],
        unobserved=['View points into the live shared allocation; direct reads and cache writes are C adapter premises.'])
    services['seed'] = ServiceDefinition.create(identity='jq.hash.seed', types=types, parameters=[], result='u32',
        resources=[], effects=['jq.process-hash-seed'], outcomes=['return'],
        unobserved=['Backend owns once-initialization and entropy; calls are single-threaded.'])
    interface = component_interface(component_id='string-hash', services=services,
        parameters=[('value', 'jv_value')], result='u32')
    resources = component_resource_checks(interface, consumes=['value'], produces=[], resource_kind='jq-reference',
        provider_domain='libjq', service_id='value-transport', interaction_contract_id='string-hash.reference-transfer',
        instrumented_sides=['source'], unobserved=['Direct shared-cache writes and seed-service internals are not proved.'])
    shared['service_catalog'] = service_catalog(services).to_payload()
    shared['service_bridge']['adapters'].update({name: dict(symbol=symbol, kind='native', outcomes={'return': None})
        for name, symbol in [('view', 'hash_view'), ('seed', 'spx_string_hash_seed')]})
    with comparison_preparation(output) as staged:
        bridge = staged / 'bridge.c'
        bridge.write_text('#include "portable-component-implementation.h"\n#include "hash-native.h"\n'
                          '#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
        entry = staged / 'native-entry.h'
        entry.write_text(native_entry_header(original=base / 'runtime/libjq-1.dll', expected_sha256=ORIGINAL,
            module='libjq-1.dll', entry_rva=0x29d78, end_rva=0x29e0a))
        shared['adapter_files'].update({'driver.c': HERE / 'driver.c', 'native-seed.c': HERE / 'native-seed.c', 'bridge.c': bridge})
        shared['include_files'].update({'hash-native.h': HERE / 'hash-native.h', 'native-entry.h': entry,
                                       'BOUNDARY.md': HERE / 'BOUNDARY.md'})
        prepare_comparison_package(interface_package=interface, target_id='jq', component_id='string-hash',
            source_files={'hash.c': HERE / 'hash.c', 'hash-view.h': HERE / 'hash-view.h'},
            operation_symbols={'run': 'lifted_string_hash'}, original_files=['runtime/libjq-1.dll'], oracle_kind='native-original',
            cases=[dict(id='retained-zero', arguments=['0', 'retained']),
                   dict(id='retained-high', arguments=['4294967295', 'retained']),
                   dict(id='unique', arguments=['305419896', 'unique'])],
            observation_fields=['samples', 'allocation_lifetime'], assumptions=[(HERE / 'BOUNDARY.md').read_text()],
            resource_checks=resources, export_adapters=['adapters/bridge.c', 'adapters/native-seed.c'],
            scope='Complete consuming string hash, cached and uncached live strings; mutable shared cache and explicit seed service.',
            output=staged / 'string-hash', **shared)
        write_json(staged / 'preparation.json', dict(seconds=time.monotonic() - started,
            new_tool_internals=False, services_reused=['release'], adapters_reused=['live value transport', 'allocation observer'],
            model_seconds=0, solver_seconds=0))
    print(output / 'string-hash')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.base.resolve(), args.output.resolve())
