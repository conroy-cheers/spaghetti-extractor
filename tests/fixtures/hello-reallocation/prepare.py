"""Retain complete rpl_realloc and prepare the existing local C comparison flow."""
import argparse
import json
from pathlib import Path
import shutil
import time

from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json
from declarations import interface

HERE = Path(__file__).resolve().parent
PLAN_SHA256 = '7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11'
PE_SHA256 = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
ASSUMPTIONS = [
    'Complete retained PE32 rpl_realloc, including normalization, both errno paths and its own return; CRT supplier bodies are absent.',
    'Byte requests retain their full unsigned 32-bit target representation; the original rejects the high-bit range and normalizes zero to one.',
    'An old block is null or a live allocator-owned object, disjoint from the errno cell and private stack. Returning null preserves that old allocation.',
    'Raw resize may return null, preserve location, or move; successful resize preserves the minimum of old and new lengths. Local observations cover at most a 64-byte prefix.',
    'The borrowed errno view is a live readable/writable four-byte cell for this synchronous call; the adapter preserves its contents and writes immediately.',
    'Services do not deliver callbacks or mutate unrelated frames; source object/address transport is synchronous and nonreentrant.',
    'Metadata-only large allocations, controlled failures, prefixes, aliases and lifetimes are finite evidence; actual large native allocation and strong heap correspondence are not established.',
]


def cases():
    return [dict(id=f'bytes-{size}-old-{present}-mode-{mode}-seed-{seed}',
        arguments=list(map(str, [size, present, mode, seed])))
        for size in (0, 1, 2, 63, 64, 65, 128, 192, 256, 2147483647, 2147483648, 4294967295)
        for present in (0, 1) for mode in (0, 1, 2) for seed in (0, 7, 85)]


def prepare(plan_path, partition_path, output, compiler):
    started = time.monotonic()
    if sha256_file(plan_path) != PLAN_SHA256:
        raise ValueError('reallocation requires the pinned Hello transfer plan')
    partition = json.loads(partition_path.read_text())
    if partition['pe_sha256'] != PE_SHA256:
        raise ValueError('partition belongs to a different executable')
    owner = next(row for row in partition['units'] if row['id'] == 'rpl-realloc-00008db8')
    if owner['rva_ranges'] != [[0x8db8, 0x8e10]]:
        raise ValueError('review changed rpl_realloc ownership before preparation')
    _, transfers = load_executable_transfer_plan(plan_path, require_complete=False)
    loaded = time.monotonic()
    owned = [row for row in transfers if 0x8db8 <= row.rva_start < 0x8e0f]
    assert len(owned) == 9
    assert {call.symbol for row in owned for call in row.calls} == {'realloc', '_errno'}
    output.mkdir(parents=True, exist_ok=False)
    exact = output/'exact'
    manifest = write_component_exact_c_slice_v1(component_id='allocation-reallocate', transfers=transfers,
        operations=[dict(operation_id='reallocate', unit_ids=[row.identity for row in owned], entry_rvas=[0x8db8])],
        intent=None, executable_transfer_plan_sha256=PLAN_SHA256, out=exact)
    assert manifest['root_unit_ids'] == manifest['root_context_unit_ids']
    assert [row['path'] for row in manifest['files'] if row['path'].startswith('behavioral-fn-')] == ['behavioral-fn-00008db8.c']
    rendered = time.monotonic()
    original = {name: exact/name for name in ('behavioral-fn-00008db8.c', 'behavioral-support.c')}
    headers = {name: exact/name for name in ('behavioral-c.h', 'state-machine-runtime.h', 'component-exact-c-slice-v1.json')}
    objects = HERE.parent/'hello-allocation-growth/allocation-objects.h'
    prepare_comparison_package(interface_package=interface(), target_id='gnu-hello', component_id='allocation-reallocate',
        source_files={'reallocate.c': HERE/'reallocate.c', 'allocation-objects.h': objects},
        operation_symbols={'reallocate': 'allocation_reallocate'},
        adapter_files={**original, **{name: HERE/name for name in ('driver.c', 'bridge.c')}},
        include_files={**headers, 'allocation-objects.h': objects, 'reallocate-runtime.h': HERE/'reallocate-runtime.h'},
        original_files=[*['adapters/'+name for name in original], *['headers/'+name for name in headers]],
        oracle_kind='retained-c', cases=cases(), observation_fields=['result', 'events', 'errno', 'lifetime', 'sizes', 'prefixes', 'frames'],
        assumptions=ASSUMPTIONS, scope='Complete PE32 reallocation normalization and errno effects with controlled allocator contents/lifetimes.',
        export_adapters=['adapters/bridge.c'], compiler=compiler, runner=None, server=None,
        link_files={}, runtime_files={}, output=output/'allocation-reallocate')
    write_json(output/'preparation.json', dict(plan=str(plan_path), plan_sha256=PLAN_SHA256, original_sha256=PE_SHA256,
        ownership=owner, owned_transfers=9, owned_return=True, supplier_bodies_present=False,
        load_seconds=loaded-started, render_seconds=rendered-loaded, package_seconds=time.monotonic()-rendered,
        cases=len(cases()), strong_qualification=False))
    return output/'allocation-reallocate'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'partition', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(prepare(args.plan.resolve(), args.partition.resolve(), args.output.resolve(), Path(shutil.which('cc'))))
