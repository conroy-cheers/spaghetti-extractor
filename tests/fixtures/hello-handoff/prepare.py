"""Prepare the connected Hello selection from original inputs and dev-shell tools.

No comparison result, completed workflow, pilot execution or proof is an input.
Manual ownership, C declarations and adapters remain in their existing recipes.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_environment import native_environment

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
REPO = HERE.parents[2]
PE = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
PLAN = '7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11'


def prepare(original, plan, output, *, program_observer=False):
    started = time.monotonic()
    if sha256_file(original) != PE or sha256_file(plan) != PLAN:
        raise ValueError('requires the reviewed original Hello executable and transfer plan')
    environment = native_environment()
    output.mkdir(parents=True, exist_ok=False)
    _, transfers = load_executable_transfer_plan(plan, require_complete=False)
    loaded = time.monotonic()
    # Full original operations, including the quoting cold abort fragment.
    definitions = [
        ('quote-slots', 'quote', 0x4eb3, [(0x4eb3, 0x5078), (0x14645, 0x1464a)], 40, 'quoting/exact'),
        ('preserve-errno-free', 'release', 0x1b34, [(0x1b34, 0x1ba0)], 10, 'quoting/rpl-free-exact'),
        ('allocation-grow', 'run', 0x63ac, [(0x63ac, 0x6462)], 25, 'growth/exact'),
    ]
    retained = []
    for identity, operation, entry, ranges, count, directory in definitions:
        owned = [row for row in transfers if any(a <= row.rva_start < b for a, b in ranges)]
        if len(owned) != count:
            raise ValueError(f'review changed {identity} ownership before preparing the network')
        suppliers = sorted({call.target_rva for row in owned for call in row.calls if call.kind == 'internal_call'})
        manifest = write_component_exact_c_slice_v1(component_id=identity, transfers=transfers,
            operations=[dict(operation_id=operation, unit_ids=[row.identity for row in owned], entry_rvas=[entry])],
            intent=None, executable_transfer_plan_sha256=PLAN, summary_entry_rvas=suppliers,
            out=output/'originals'/directory)
        if manifest['root_unit_ids'] != manifest['root_context_unit_ids']:
            raise ValueError(f'{identity} includes unreviewed original context')
        retained.append(dict(component=identity, ranges=ranges, units=count, suppliers=suppliers,
                             slice_sha256=manifest['slice_sha256']))
    rendered = time.monotonic()
    del transfers
    partition = REPO/'targets/gnu-hello/intent/whole-program-partition.json'
    commands = []

    def recipe(name, *args):
        command = [sys.executable, str(FIXTURES/name), *map(str, args)]
        before = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        index = len(commands)
        (output/f'{index:02d}.stdout').write_text(result.stdout)
        (output/f'{index:02d}.stderr').write_text(result.stderr)
        commands.append(dict(command=command, exit_code=result.returncode, seconds=time.monotonic()-before))
        write_json(output/'commands.json', commands)
        print(name, result.returncode, flush=True)
        if result.returncode:
            raise RuntimeError(f'{name} failed; inspect {output}/{index:02d}.stderr')

    recipe('hello-allocation-growth/network.py', output/'originals/quoting', output/'originals/growth/exact', output/'base')
    for name, directory in [('hello-quoting-cleanup', 'cleanup'), ('hello-reallocation', 'reallocate'),
                            ('hello-checked-allocation', 'checked')]:
        recipe(name+'/prepare.py', plan, partition, output/directory)
    recipe('hello-multibyte/prepare.py', original, output/'conversion')
    recipe('hello-quote-engine/prepare.py', original, output/'engine',
           '--multibyte-package', output/'conversion/multibyte-conversion')
    recipe('hello-quote-engine/prepare.py', original, output/'original-runtime-engine')
    recipe('hello-native-quoting/prepare.py', output/'base', original, output/'native', '--component-packages',
        '--cleanup-package', output/'cleanup/quote-cleanup', '--reallocate-package', output/'reallocate/allocation-reallocate',
        '--checked-allocation-package', output/'checked/checked-allocation', '--quote-engine-package', output/'engine/quote-buffer',
        *(['--program-observer'] if program_observer else []))
    write_json(output/'preparation.json', dict(status='pass', seconds=time.monotonic()-started,
        plan_loading_seconds=loaded-started, original_rendering_seconds=rendered-loaded,
        original_sha256=PE, plan_sha256=PLAN, partition_sha256=sha256_file(partition), originals=retained,
        tools={k:dict(path=str(environment[k]), sha256=sha256_file(environment[k])) for k in ('compiler','runner','server')},
        runtime_files={k:sha256_file(v) for k,v in environment['runtime_files'].items()},
        historical_comparison_inputs=False, new_proof_rules=False, strong_qualification=False,
        original_startup=False, whole_program_complete=False))
    print(output/'native/quote-slots', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'plan', 'output'): parser.add_argument(name, type=Path)
    parser.add_argument('--program-observer', action='store_true',
                        help='also enable the separate normal-program-entry experiment')
    args = parser.parse_args()
    try:
        prepare(args.original.resolve(), args.plan.resolve(), args.output.resolve(), program_observer=args.program_observer)
    except (ValueError, FileNotFoundError, RuntimeError) as error:
        parser.exit(2, f'{parser.prog}: {error}\n')
