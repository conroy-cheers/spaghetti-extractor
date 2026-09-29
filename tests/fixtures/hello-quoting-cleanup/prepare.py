"""Retain and compare the complete cleanup body with a controlled release service."""
import argparse
import json
from pathlib import Path
import shutil
import time

from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json
from declarations import interface, representation

HERE = Path(__file__).resolve().parent
PLAN_SHA256 = '7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11'
PE_SHA256 = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
ASSUMPTIONS = [
    'Complete retained PE32 quotearg_free body, including loop, globals, all three release sites and its zero return; the release supplier body is absent.',
    'Live cache table with at least one record, count 0..64, and distinct live owned buffers or null; the immortal initial buffer appears only in slot zero.',
    'The table and initial record may alias; a distinct initial record may retain an old buffer alias. Released buffers and tables have observed lifetime and poisoned contents.',
    'Synchronous returning release consumes a live allocation or accepts null, preserves errno, and does not mutate the cache globals or deliver callbacks.',
    'The local release service is controlled, not the selected free implementation. Native connected comparison separately executes the selected free supplier.',
    'State, call-time globals, release order, contents, lifetimes, fixed surrounding bytes and repeated cleanup are finite observations, not a checked heap summary.',
]


def prepare(plan_path, partition_path, output, compiler):
    started = time.monotonic()
    if sha256_file(plan_path) != PLAN_SHA256:
        raise ValueError('cleanup boundary requires the pinned Hello transfer plan')
    partition = json.loads(partition_path.read_text())
    if partition['pe_sha256'] != PE_SHA256:
        raise ValueError('partition belongs to a different executable')
    owner = next(row for row in partition['units'] if row['id'] == 'quotearg-free-000052f2')
    if owner['rva_ranges'] != [[0x52f2, 0x5374]]:
        raise ValueError('review the changed cleanup ownership before preparation')
    _, transfers = load_executable_transfer_plan(plan_path, require_complete=False)
    loaded = time.monotonic()
    owned = [row for row in transfers if 0x52f2 <= row.rva_start < 0x5374]
    callees = sorted({call.target_rva for row in owned for call in row.calls if call.kind == 'internal_call'})
    assert len(owned) == 13 and callees == [0x1b34]
    output.mkdir(parents=True, exist_ok=False)
    exact = output/'exact'
    manifest = write_component_exact_c_slice_v1(component_id='quote-cleanup', transfers=transfers,
        operations=[dict(operation_id='cleanup', unit_ids=[row.identity for row in owned], entry_rvas=[0x52f2])],
        intent=None, executable_transfer_plan_sha256=PLAN_SHA256, summary_entry_rvas=callees, out=exact)
    assert manifest['root_unit_ids'] == manifest['root_context_unit_ids']
    assert not (exact/'behavioral-fn-00001b34.c').exists()
    rendered = time.monotonic()
    originals = {name: exact/name for name in ('behavioral-fn-000052f2.c', 'behavioral-support.c')}
    headers = {name: exact/name for name in ('behavioral-c.h', 'state-machine-runtime.h', 'component-exact-c-slice-v1.json')}
    objects = HERE.parent/'hello-quoting-state/slots/quote-objects.h'
    cases = [dict(id=f'count-{count}-mode-{mode}-seed-{seed}', arguments=list(map(str, [count, mode, seed])))
             for count in (0, 1, 2, 4, 16, 24, 64) for mode in range(8) for seed in (0, 85, 170, 255)]
    prepare_comparison_package(interface_package=interface(), component_id='quote-cleanup', target_id='gnu-hello',
        source_files={'cleanup.c': HERE/'cleanup.c', 'quote-objects.h': objects},
        operation_symbols={'cleanup': 'quote_cleanup'},
        adapter_files={**originals, **{name: HERE/name for name in ('driver.c', 'bridge.c')}},
        include_files={**headers, 'cleanup-runtime.h': HERE/'cleanup-runtime.h', 'quote-objects.h': objects},
        original_files=[*['adapters/'+name for name in originals], *['headers/'+name for name in headers]],
        oracle_kind='retained-c', cases=cases,
        observation_fields=['returns', 'cache', 'initial', 'events', 'alive', 'contents', 'frames'],
        assumptions=ASSUMPTIONS, scope='Complete shared-cache cleanup with controlled body-absent release and repeated invocation.',
        representation=representation(),
        export_adapters=['adapters/bridge.c'], compiler=compiler, runner=None, server=None,
        link_files={}, runtime_files={}, output=output/'quote-cleanup')
    write_json(output/'preparation.json', dict(plan=str(plan_path), plan_sha256=PLAN_SHA256,
        partition_sha256=sha256_file(partition_path), original_sha256=PE_SHA256, ownership=owner,
        owned_transfers=13, supplier_bodies_present=False, owned_return=True,
        load_seconds=loaded-started, render_seconds=rendered-loaded,
        package_seconds=time.monotonic()-rendered, cases=len(cases), strong_qualification=False))
    return output/'quote-cleanup'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'partition', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(prepare(args.plan.resolve(), args.partition.resolve(), args.output.resolve(), Path(shutil.which('cc'))))
