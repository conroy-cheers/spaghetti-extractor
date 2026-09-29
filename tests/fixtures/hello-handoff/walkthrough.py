"""Run the existing eight-component edit/replay/reuse workflow from fresh packages."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import write_json

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run the whole walkthrough inside spaghetti-headless-wayland')
    packages, output = args.packages.resolve(), args.output.resolve()
    preparation = json.loads((packages/'preparation.json').read_text())
    if preparation['status'] != 'pass' or preparation['historical_comparison_inputs']:
        raise ValueError('requires the fresh-input preparation recipe')
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    commands, neighbors = [], {}

    def run(arguments):
        command = [sys.executable, *map(str, arguments)]
        before = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=900)
        index = len(commands)
        (output/f'{index:02d}.stdout').write_text(result.stdout)
        (output/f'{index:02d}.stderr').write_text(result.stderr)
        commands.append(dict(command=command, exit_code=result.returncode, seconds=time.monotonic()-before))
        write_json(output/'commands.json', commands)
        print(json.dumps(dict(command=index, exit_code=result.returncode, seconds=commands[-1]['seconds'])), flush=True)
        if result.returncode:
            raise RuntimeError(f'command {index} failed; inspect {output}')

    for parent, identity in [('base','allocation-grow'), ('base','preserve-errno-free'),
                             ('cleanup','quote-cleanup'), ('reallocate','allocation-reallocate'),
                             ('checked','checked-allocation')]:
        destination = output/identity
        run(['-m','spaghetti_extractor','component','check','gnu-hello',identity,
             '--comparison-package',packages/parent/identity,'--output',destination])
        assert load_comparison_result(destination)['status'] == 'match'
        neighbors[identity] = destination
    command = [HERE.parent/'hello-multibyte/walkthrough.py', packages/'conversion/multibyte-conversion',
        packages/'engine/quote-buffer', packages/'native/quote-slots', packages/'original-runtime-engine/quote-buffer',
        output/'connected']
    for identity, path in neighbors.items(): command += ['--component-comparison', identity+'='+str(path)]
    run(command)
    connected = json.loads((output/'connected/audit.json').read_text())
    assert connected['status'] == 'pass'
    write_json(output/'audit.json', dict(status='pass', seconds=time.monotonic()-started,
        preparation_seconds=preparation['seconds'], public_commands=5+connected['commands'],
        comparisons=5+connected['comparisons'], native_cases=connected['native_cases'],
        historical_comparison_inputs=False, strong_qualification=False,
        original_startup=False, whole_program_complete=False))


if __name__ == '__main__':
    main()
