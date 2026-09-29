"""Public local edit, meaningful defect, retained replay and neighbor reuse."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); output = args.output.resolve()
    if not os.environ.get('WAYLAND_DISPLAY'): raise RuntimeError('requires headless Wayland')
    output.mkdir(parents=True, exist_ok=False); commands = []; results = {}

    def run(name, argv, expected=0):
        started = time.monotonic(); argv = list(map(str, argv))
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=600)
        (output/(name+'.stdout')).write_text(completed.stdout)
        (output/(name+'.stderr')).write_text(completed.stderr)
        commands.append(dict(name=name, argv=argv, seconds=time.monotonic()-started, exit_code=completed.returncode))
        (output/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        print(name, completed.returncode, round(commands[-1]['seconds'], 3), flush=True)
        if completed.returncode != expected: raise RuntimeError(completed.stdout[-3000:]+completed.stderr[-3000:])
        return completed.stdout

    cli = [sys.executable, '-m', 'spaghetti_extractor']
    run('prepare', [sys.executable, HERE/'prepare.py', args.base.resolve(), output/'prepared'])
    run('start', [*cli, 'component', 'start', 'jq', 'object-unshare', '--comparison-package',
        output/'prepared/object-unshare', '--output', output/'work'])

    def check(name, expected=0, case=None):
        text = run(name, [*cli, 'component', 'check', 'jq', 'object-unshare',
            '--comparison-package', output/'work', '--history', output/'checks',
            *(['--case', case] if case else [])], expected)
        root = (output/'checks/latest').resolve()
        result = json.loads((root/'comparison-result.json').read_text())
        results[name] = dict(path=str(root), status=result['status'], work_counts=result['work_counts'],
            timings=result['timings'], first_differences=[row.get('first_difference') for row in result['cases']])
        return text, result

    _, baseline = check('baseline')
    source = output/'work/source/unshare.c'; original = source.read_text()
    # Values stay correct while the transferred input reference leaks.
    assert original.count('services->release_object(services->context, &original);') == 1
    source.write_text(original.replace('services->release_object(services->context, &original);', '(void)original;'))
    text, wrong = check('leaked-reference', 2, 'shared-holes-growth')
    assert wrong['status'] == 'mismatch' and wrong['work_counts']['compiler'] == 1
    source.write_text(original)
    _, repaired = check('repair')
    assert repaired['status'] == 'match' and repaired['work_counts']['compiler'] == 1
    replay = shlex.split(next(line.partition('replay: ')[2] for line in text.splitlines() if 'replay: ' in line))
    run('retained-replay', [*cli, *replay[1:]], 2)
    _, warm = check('warm')
    assert not any(warm['work_counts'].values())
    report = dict(status='pass', results=results, commands=commands,
        preparation=json.loads((output/'prepared/preparation.json').read_text()),
        scope='Three connected object lifecycle bodies, private PE32 entries and real interpreter callers; no universal qualification.',
        original_cases=len(baseline['cases']), new_checker_or_compiler_rules=False)
    (output/'walkthrough.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__': main()
