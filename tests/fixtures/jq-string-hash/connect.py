"""Supply a retained object lookup's borrowed hash service with this consuming unit."""
import argparse
import copy
from pathlib import Path
import tempfile

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package


def connect(network, supplier, output):
    plan, _ = load_comparison_package(network)
    unit = plan if plan['component_id'] == 'object-get' else next(
        row for row in plan.get('dependencies', []) if row['id'] == 'object-get')
    if plan['target_id'] != 'jq' or len(unit['adapters']) != 1:
        raise ValueError('requires the reviewed jq object-get adapter')
    if any(row.get('id') == 'hash' for row in unit.get('requirements', [])):
        raise ValueError('hash already has a supplier; use dependency-source or named requirement refinement')
    added = bind_dependencies(services={'hash': supplier})
    bridge = copy.deepcopy(unit['service_bridge'])
    if bridge['adapters']['hash']['symbol'] != 'object_key_hash':
        raise ValueError('review the changed object hash adapter before connecting')
    bridge['adapters']['hash']['symbol'] = 'object_lifted_hash'
    source = (network / unit['adapters'][0]).read_text()
    marker = '#include "comparison-service-bridge.h"'
    if source.count(marker) != 1:
        raise ValueError('review the changed object service bridge before connecting')
    with tempfile.TemporaryDirectory(prefix='jq-object-hash-') as temporary:
        adapter = Path(temporary) / 'bridge.c'
        adapter.write_text(source.replace(marker,
            'extern uint32_t fixture_string_hash(jv);\n'
            'static uint32_t object_lifted_hash(jv key) { return fixture_string_hash(jv_copy(key)); }\n' + marker))
        revise_comparison_package(package=network, component_id='object-get', output=output,
            dependencies=added['dependencies'], requirements=[*unit.get('requirements', []), *added['requirements']],
            service_bridge=bridge, adapter_files={'bridge.c': adapter})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('network', type=Path)
    parser.add_argument('supplier', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    connect(args.network.resolve(), args.supplier.resolve(), args.output.resolve())
    print(args.output.resolve())
