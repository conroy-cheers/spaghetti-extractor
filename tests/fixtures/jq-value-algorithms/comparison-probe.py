"""Compare the portable C API's integer results with retained native observations."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(project, build, native, output, qemu=None):
    output.mkdir(parents=True)
    report = json.loads((build / 'build.json').read_text())
    if report['status'] != 'built':
        raise ValueError('requires a successful standalone build')
    if json.loads((native / 'comparison-result.json').read_text())['status'] != 'match':
        raise ValueError('requires a matching retained native comparison')
    for name, digest in report['input_sha256s'].items():
        if sha(project / name) != digest:
            raise ValueError('project changed since build: ' + name)
    for name, digest in report['object_sha256s'].items():
        if sha(project / name) != digest:
            raise ValueError('object changed since build: ' + name)
    rows = [json.loads(line) for line in (build / 'compiler-phases.jsonl').read_text().splitlines()]
    link = next(row['arguments'] for row in rows
                if row['phase'] == 'program-link' and row['arguments'][-1] == 'live-values')
    source = Path(__file__).with_suffix('.c')
    cc = report['tools']['cc']['path']
    command = [cc, '-Ibackends/jq/src', *link]
    command[command.index('build/live-values.o')] = str(source)
    command[-1] = str(output / 'probe')
    link_inputs = {name: sha(project / name) for name in command if name.endswith(('.o', '.a'))}
    subprocess.run(command, cwd=project, check=True, capture_output=True)
    plan = json.loads((native / 'inputs/comparison-plan.json').read_text())
    results = []
    for index, case in enumerate(plan['cases']):
        if case['arguments'][0] != 'compare':
            continue
        observation = native / 'cases' / f'{index:04d}-original.stdout'
        expected = json.loads(observation.read_text())['result']['value']
        argv = ([str(qemu)] if qemu else []) + [str(output / 'probe'), *case['arguments'][1:]]
        ran = subprocess.run(argv, capture_output=True, check=True, text=True)
        actual = int(ran.stdout)
        results.append(dict(id=case['id'], expected=expected, actual=actual,
                            status='match' if expected == actual else 'mismatch',
                            native_observation_sha256=sha(observation)))
    result = dict(status='match' if all(row['status'] == 'match' for row in results) else 'mismatch',
                  results=results, source_sha256=sha(source), executable_sha256=sha(output / 'probe'),
                  native_comparison_sha256=sha(native / 'comparison-result.json'),
                  build_sha256=sha(build / 'build.json'), command=command,
                  link_input_sha256s=link_inputs,
                  emulator=str(qemu) if qemu else None)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'], len(results), 'exact C comparison results')
    return result['status']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'build', 'native', 'output'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--qemu', type=Path)
    args = parser.parse_args()
    status = run(args.project.resolve(), args.build.resolve(), args.native.resolve(), args.output.resolve(), args.qemu)
    raise SystemExit(0 if status == 'match' else 2)
