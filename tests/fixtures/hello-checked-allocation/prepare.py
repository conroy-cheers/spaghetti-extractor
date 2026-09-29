"""Prepare a manually merged allocation family with complete shared-tail ownership."""
import argparse
import json
from pathlib import Path
import shutil
import time

from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_environment import observation_headers
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.service_authoring import service_catalog
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json
from declarations import ALIASES, OPERATIONS, SHARED, boundary

HERE = Path(__file__).resolve().parent
PLAN = '7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11'
PE = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
ASSUMPTIONS = [
    'Eight complete PE32 checked allocator operations own their shared check_nonnull tail; xcharalloc and xnrealloc are alternate machine entries, not extra synthetic C APIs.',
    'Size/count words preserve all 32-bit target bit patterns, including the indexed variants; lower services decide their admissible sizes and arithmetic.',
    'Nullable old blocks are live and allocator-owned; lower services preserve declared logical aliases, contents and lifetime, or return null without consuming the old block.',
    'Allocator and errno effects are supplied by explicit synchronous adapters; the wrapper preserves those effects and does not retain object proxies after returning.',
    'The allocation-failure service never returns. C handlers observe nomem delivery; actual CRT process termination, callbacks, reentrancy and concurrency are outside this scope.',
    'Controlled lower services are absent as original bodies. Local metadata and 64-byte prefixes are finite observations, not a checked heap or allocator summary.',
]


def entries():
    return [(name, start) for name, (start, _, _, _) in OPERATIONS.items()] + [
        (name, start) for name, ranges in ALIASES.items() for start, _ in ranges]


def cases():
    rows = []
    for name, entry in entries():
        index = list(OPERATIONS).index(name)
        for a, b in [(0, 1), (1, 0), (7, 3), (64, 8), (2147483647, 1), (2147483648, 2), (4294967295, 4294967295)]:
            for present in ((0, 1) if name.startswith('resize') else (0,)):
                for mode in range(3):
                    for seed in (7, 85):
                        rows.append(dict(id=f'entry-{entry:x}-a-{a}-b-{b}-old-{present}-mode-{mode}-seed-{seed}',
                            arguments=list(map(str, [index, entry, a, b, present, mode, seed]))))
    return rows


def prepare(plan_path, partition_path, output, compiler):
    started = time.monotonic()
    if sha256_file(plan_path) != PLAN:
        raise ValueError('checked allocation requires the pinned transfer plan')
    partition = json.loads(partition_path.read_text())
    ranges = [SHARED, *[(a, b) for a, b, _, _ in OPERATIONS.values()],
              *[pair for pairs in ALIASES.values() for pair in pairs]]
    if partition['pe_sha256'] != PE or any(
            sum(row['rva_ranges'] == [[start, end]] for row in partition['units']) != 1 for start, end in ranges):
        raise ValueError('review changed ownership before preparing the allocation family')
    _, transfers = load_executable_transfer_plan(plan_path, require_complete=False)
    loaded = time.monotonic()
    owned = [row for row in transfers if any(start <= row.rva_start < end for start, end in ranges)]
    suppliers = {supplier for _, _, supplier, _ in OPERATIONS.values()} | {0x658c}
    assert {call.target_rva for row in owned for call in row.calls} == suppliers
    output.mkdir(parents=True, exist_ok=False)
    operations = []
    for name, (start, end, _, _) in OPERATIONS.items():
        local_ranges = [SHARED, (start, end), *ALIASES.get(name, [])]
        operations.append(dict(operation_id=name,
            unit_ids=[row.identity for row in owned if any(a <= row.rva_start < b for a, b in local_ranges)],
            entry_rvas=[start, *[a for a, _ in ALIASES.get(name, [])]]))
    exact = output/'exact'
    manifest = write_component_exact_c_slice_v1(component_id='checked-allocation', transfers=transfers,
        operations=operations, intent=None, executable_transfer_plan_sha256=PLAN,
        summary_entry_rvas=sorted(suppliers), out=exact)
    assert manifest['root_unit_ids'] == manifest['root_context_unit_ids']
    assert not manifest['internal_direct_call_closure']['unit_ids']
    original = {p.name: p for p in exact.glob('*.c')
                if p.name == 'behavioral-support.c' or p.name.startswith('behavioral-fn-')}
    headers = {p.name: p for p in exact.iterdir() if p.suffix in ('.h', '.json')}
    dispatch = ['static spx_step_result original_step(spx_runtime *r, spx_machine_state *s, uint32_t entry) {',
                '  switch(entry) {']
    for function in manifest['functions']:
        dispatch.extend('  case '+hex(rva)+':' for rva in function['unit_rvas'])
        dispatch.append('    return '+function['symbol']+'(r,s,entry);')
    dispatch += ['  default: return (spx_step_result){SPX_UNIMPLEMENTED, entry, 0};', '  }', '}']
    (output/'checked-original.h').write_text('\n'.join(dispatch)+'\n')
    rendered = time.monotonic()
    interface, services = boundary()
    bridge = dict(native_symbol=None, transports={}, adapters={
        name: dict(symbol='adapter_'+name, kind='portable', context=True, outcomes={'return': None})
        for name in services})
    catalog = service_catalog(services)
    objects = HERE.parent/'hello-allocation-growth/allocation-objects.h'
    prepare_comparison_package(interface_package=interface, target_id='gnu-hello', component_id='checked-allocation',
        source_files={'checked.c': HERE/'checked.c', 'allocation-objects.h': objects},
        operation_symbols={name: 'checked_'+name for name in OPERATIONS},
        adapter_files={**original, **{name: HERE/name for name in ('driver.c', 'bridge.c')}},
        include_files={**headers, **observation_headers(), 'allocation-objects.h': objects, 'checked-runtime.h': HERE/'checked-runtime.h',
            'checked-original.h': output/'checked-original.h'},
        original_files=[*['adapters/'+name for name in original], *['headers/'+name for name in headers], 'headers/checked-original.h'],
        oracle_kind='retained-c', cases=cases(), observation_fields=['result', 'outcome', 'events', 'errno', 'lifetime', 'sizes', 'prefixes', 'frames'],
        assumptions=ASSUMPTIONS, scope='Complete checked allocation family, shared tail and machine aliases; controlled lower services and nonlocal failure.',
        export_adapters=['adapters/bridge.c'], service_catalog=catalog.to_payload(), service_bridge=bridge,
        compiler=compiler, runner=None, server=None, link_files={}, runtime_files={}, output=output/'checked-allocation')
    coverage=json.loads((output/'checked-allocation/generated/service-coverage.json').read_text())
    write_json(output/'preparation.json', dict(plan=str(plan_path), plan_sha256=PLAN, original_sha256=PE,
        ranges=ranges, operation_entries=entries(), supplier_entries=sorted(suppliers), owned_transfers=len(owned),
        shared_return_owned=True, supplier_bodies_present=False, service_coverage=coverage,
        load_seconds=loaded-started, render_seconds=rendered-loaded, package_seconds=time.monotonic()-rendered,
        cases=len(cases()), strong_qualification=False))
    return output/'checked-allocation'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'partition', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(prepare(args.plan.resolve(), args.partition.resolve(), args.output.resolve(), Path(shutil.which('cc'))))
