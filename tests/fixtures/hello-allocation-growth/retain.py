"""Extract only the complete xpalloc operation from the retained Hello plan."""
import argparse
import json
from pathlib import Path
import time

from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json

PLAN_SHA256 = '7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11'
PE_SHA256 = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'partition', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    plan, partition_path, out = args.plan.resolve(), args.partition.resolve(), args.output.resolve()
    start = time.monotonic()
    if sha256_file(plan) != PLAN_SHA256:
        raise ValueError('this manual boundary requires the pinned Hello transfer plan')
    partition = json.loads(partition_path.read_text())
    if partition['pe_sha256'] != PE_SHA256:
        raise ValueError('partition belongs to a different executable')
    unit = next(u for u in partition['units'] if u['id'] == 'xpalloc-000063ac')
    _, transfers = load_executable_transfer_plan(plan, require_complete=False)
    loaded = time.monotonic()
    owned = [t for t in transfers if any(lo <= t.rva_start < hi for lo, hi in unit['rva_ranges'])]
    callees = sorted({c.target_rva for t in owned for c in t.calls if c.kind == 'internal_call'})
    assert len(owned) == 25 and callees == [0x6257, 0x658c]
    out.mkdir(parents=True, exist_ok=False)
    exact = write_component_exact_c_slice_v1(component_id='allocation-grow', transfers=transfers,
        operations=[dict(operation_id='run', unit_ids=[t.identity for t in owned], entry_rvas=[0x63ac])],
        intent=None, executable_transfer_plan_sha256=PLAN_SHA256, summary_entry_rvas=callees, out=out/'exact')
    assert exact['root_unit_ids'] == exact['root_context_unit_ids']
    assert not any(row['path'] == f'behavioral-fn-{rva:08x}.c' for row in exact['files'] for rva in callees)
    write_json(out/'retention.json', dict(plan=str(plan), plan_sha256=PLAN_SHA256, pe_sha256=PE_SHA256,
        partition_sha256=sha256_file(partition_path), ownership=unit, callees=callees,
        slice_sha256=exact['slice_sha256'], load_seconds=loaded-start, render_seconds=time.monotonic()-loaded,
        compiler_runs=0, model_runs=0, solver_runs=0, link_runs=0, strong_qualification=False))
    print(out/'exact')


if __name__ == '__main__':
    main()
