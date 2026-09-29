"""Prepare complete xpalloc with manual C boundaries and existing public APIs."""
import argparse
import json
from pathlib import Path
import random
import shutil
import time

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import service_catalog
from spaghetti_extractor.util import sha256_file, write_json
from declarations import boundary

HERE = Path(__file__).resolve().parent
ASSUMPTIONS = [
    'The original oracle is the complete retained PE32 xpalloc body; native binary execution remains unverified.',
    'Incoming count is nonnegative; additional and element width are positive signed PE32 values; a negative maximum is unbounded.',
    'The count cell is live, disjoint from the block and private stack; a nonnull old block has count times width readable bytes.',
    'The allocator models sizes, block identities, lifetime and a 64-byte prefix; remaining large-block contents are not observed.',
    'Resize preserves existing contents, may move, and never returns null; modeled allocation failures escape without returning.',
    'The C object/address bridge is synchronous and nonreentrant; actual CRT failure handling and native admission are not checked.',
    'Target arithmetic remains 32-bit and the small-allocation threshold is 64 bytes on every host.',
]


def cases():
    limit = 2147483647
    rows = [(previous, 1, 0xffffffff, width)
        for previous in (0, 1, 7, 8, 43, 64, 65, 1073741824, 1431655765, limit-1, limit)
        for width in (1, 3, 8, 65, limit)]
    rows += [(previous, additional, maximum, width)
        for previous, additional, width in [(0, 1, 1), (1, 1, 8), (8, 8, 8), (64, 17, 3), (limit-1, 2, 1)]
        for maximum in (0, 1, previous, limit, 0x80000000)]
    randomizer = random.Random(0x63ac)
    rows += [(randomizer.randrange(limit+1), randomizer.choice([1, 17, limit]),
              randomizer.choice([0xffffffff, limit, 1, 65]), randomizer.choice([1, 3, 8, 65, limit]))
             for _ in range(32)]
    result = []
    for number, row in enumerate(dict.fromkeys(rows)):
        previous, _, _, width = row
        for present in (0, 1):
            if present and previous*width > limit:
                continue
            for mode in (0, 1, 2):
                result.append(dict(id=f'edge-{number}-old-{present}-mode-{mode}',
                    arguments=list(map(str, [*row, present, mode, number+17]))))
    return result


def prepare(exact, output, compiler):
    started = time.monotonic()
    manifest = json.loads((exact/'component-exact-c-slice-v1.json').read_text())
    assert manifest['slice_sha256'] == canonical_sha256_v3({k: v for k, v in manifest.items() if k != 'slice_sha256'})
    assert len(manifest['root_unit_ids']) == 25 and manifest['root_unit_ids'] == manifest['root_context_unit_ids']
    for row in manifest['files']:
        assert sha256_file(exact/row['path']) == row['sha256']
    intent, services = boundary()
    originals = {name: exact/name for name in ('behavioral-fn-000063ac.c', 'behavioral-support.c')}
    headers = {name: exact/name for name in ('behavioral-c.h', 'state-machine-runtime.h', 'component-exact-c-slice-v1.json')}
    prepare_comparison_package(interface_package=intent,
        source_files={'grow.c': HERE/'grow.c', 'allocation-objects.h': HERE/'allocation-objects.h'},
        operation_symbols={'run': 'allocation_grow'}, target_id='gnu-hello', component_id='allocation-grow',
        adapter_files={'driver.c': HERE/'driver.c', 'bridge.c': HERE/'bridge.c', **originals},
        include_files={'runtime.h': HERE/'runtime.h', 'allocation-objects.h': HERE/'allocation-objects.h', **headers},
        original_files=[*['adapters/'+name for name in originals], *['headers/'+name for name in headers]],
        oracle_kind='retained-c', cases=cases(),
        observation_fields=['result', 'outcome', 'count', 'event', 'lifetime', 'sizes', 'prefixes'],
        assumptions=ASSUMPTIONS, scope='Complete PE32 xpalloc decisions with controlled resize/failure and finite heap observations.',
        export_adapters=['adapters/bridge.c'], service_catalog=service_catalog(services).to_payload(),
        service_bridge=dict(adapters={key: dict(symbol='allocation_'+key, kind='portable', context=True,
            outcomes={'return': None}) for key in services}, transports={}, native_symbol='bridge_allocation_grow'),
        compiler=compiler, runner=None, server=None, link_files={}, runtime_files={}, output=output)
    write_json(output.parent/'allocation-preparation.json', dict(seconds=time.monotonic()-started,
        original_manifest_sha256=sha256_file(exact/'component-exact-c-slice-v1.json'),
        cases=len(cases()), original_units=25, owned_return=True, callee_bodies_present=False,
        new_checker_rules=False, strong_qualification=False))
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exact', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(prepare(args.exact.resolve(), args.output.resolve(), Path(shutil.which('cc'))))
