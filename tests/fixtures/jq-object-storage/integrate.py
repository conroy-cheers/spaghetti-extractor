"""Carry compared object lifecycle C into an existing ordinary jq source project."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PORTABLE = HERE.parent/'jq-portable'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('comparison', type=Path); parser.add_argument('project', type=Path)
    parser.add_argument('output', type=Path); parser.add_argument('--prior-build', type=Path, required=True)
    parser.add_argument('--runner', type=Path)
    args = parser.parse_args(); output = args.output.resolve(); project = output/'project'
    output.mkdir(parents=True, exist_ok=False)
    comparison = args.comparison.resolve(); commands = []
    read = lambda path: json.loads(path.read_text())
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    shutil.copytree(args.project.resolve(), project, symlinks=True,
        ignore=shutil.ignore_patterns('lifted.before-update-*'))
    original = read(project/'lifted/source-export.json')
    neighbors = {p.relative_to(project).as_posix(): [sha(p), p.stat().st_mtime_ns]
        for p in (project/'lifted/build').glob('*.o')}

    def run(name, argv, env=None):
        started = time.monotonic(); argv = list(map(str, argv))
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=600, env=env)
        (output/(name+'.stdout')).write_text(completed.stdout); (output/(name+'.stderr')).write_text(completed.stderr)
        commands.append(dict(name=name, argv=argv, seconds=time.monotonic()-started, exit_code=completed.returncode))
        (output/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        print(name, completed.returncode, round(commands[-1]['seconds'], 3), flush=True)
        if completed.returncode: raise RuntimeError(completed.stdout[-4000:]+completed.stderr[-4000:])
        return completed.stdout

    cli = [sys.executable, '-m', 'spaghetti_extractor']
    accepted = [arg for name in ('object-create', 'object-release', 'object-unshare')
        for arg in ('--accept-boundary-change', name)]
    run('export', [*cli, 'candidate', 'export', 'jq', '--comparison', comparison,
        '--output', project/'lifted', '--update-components', *accepted])
    run('bindings', [sys.executable, PORTABLE/'refresh.py', project, '--bindings', HERE/'portable-bindings.json'])
    prior = read(args.prior_build.resolve())
    tool_args = [argument for name in ('cc', 'ar', 'ranlib') for argument in ('--'+name, prior['tools'][name]['path'])]
    host = [arg.removeprefix('CONFIGURE_FLAGS=--host=') for arg in prior['command'] if arg.startswith('CONFIGURE_FLAGS=--host=')]
    run('build', [sys.executable, PORTABLE/'build.py', project, output/'build', *tool_args,
        *(['--host', host[0]] if host else [])])
    result = read(comparison/'comparison-result.json')
    row = next((i, row) for i, row in enumerate(result['cases']) if row['id'] == 'interpreter')
    expected = row[1]['observations']['original']['sample']
    query = '{"key0":{"nested":[1,2]},"key3":{"child":3}} | '+\
        '. as $old | .key0.nested[0]=99 | del(.key3) | .added={x:[4,5]} | [.,$old]'
    text = run('program', [*([args.runner.resolve()] if args.runner else []), project/'jq', '-nc', query],
        env=dict(os.environ, SPX_COMPONENT_COUNTS=str(output/'calls.json')))
    assert json.loads(text) == expected
    counts = read(output/'calls.json')
    assert all(counts[name] > 0 for name in ('object-create', 'object-release', 'object-unshare'))
    published = read(project/'lifted/source-export.json')
    assert all(published['components'][name] == unit for name, unit in original['components'].items())
    assert neighbors == {name: [sha(project/name), (project/name).stat().st_mtime_ns] for name in neighbors}
    build = read(output/'build/build.json')
    report = dict(status='pass', project=str(project), retained_neighbor_objects=len(neighbors),
        original_comparison=str(comparison), component_calls=counts, build=build, commands=commands,
        scope='Normal source-assisted jq program; object creation/release/unsharing replaced, remaining backend retained.',
        whole_jq_lift=False, strong_qualification=False)
    (output/'integration.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__': main()
