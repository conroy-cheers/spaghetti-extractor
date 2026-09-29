"""Replay retained native key observations through the program's input adapters."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(project, runner):
    executable = project/'program-input-check'
    results, inputs = [], {}
    for component, operation in [('menu-scene', 'key'), ('title-scene', 'key')]:
        path = project/'lifted/components'/component/'interface.json'
        interface = json.loads(path.read_text())
        entry = next(item for item in interface['operations'] if item['id'] == operation)
        if entry['allowed_service_ids']:
            raise ValueError('input-only adapter requires an empty service set: '+component)
        inputs[str(path.relative_to(project))] = digest(path)
    for kind, filename in [('menu', 'menu-cases.json'), ('title', 'scene-cases.json')]:
        path = project/filename
        inputs[filename] = digest(path)
        for case in json.loads(path.read_text()):
            mode = int(case['arguments'][1])
            if kind == 'menu':
                states = case['expected']['menu']['states']
                before, after = states[1]['scene'][0]['state'], states[2]['scene'][0]['state']
                control = states[1]['fields'][1]
                key = [0x20, 0x70, 0xabcd0070, 0x71][mode % 4]
            else:
                states = case['expected']['scene_state']['scene']
                before, after = states[1]['state'], states[2]['state']
                control, key = mode % 2, 0xfeed
            shift = mode % 2
            arguments = [kind, control, shift, key, before[10], before[11]]
            run = subprocess.run([*([str(runner)] if runner else []), str(executable),
                                  *map(str, arguments)], capture_output=True, text=True, timeout=10)
            if run.returncode:
                raise ValueError(case['id']+': source input check failed: '+run.stderr[-2000:])
            actual = json.loads(run.stdout)
            expected = dict(pending=after[10], next=after[11], control=control, shift=shift,
                            reader_control=control, reader_shift=shift, other_unchanged=True)
            if actual != expected:
                raise ValueError(case['id']+': input difference: '+repr(dict(expected=expected, actual=actual)))
            results.append(dict(case=case['id'], arguments=arguments, observations=actual))
    result = dict(status='match', authorizing=False,
        scope='Retained menu/title key outcomes through source input adapters, modifier read views and independent owners. '
              'Does not execute the full scene dispatcher or window-event backend.',
        inputs=inputs, executable_sha256=digest(executable), cases=results)
    (project/'program/input-validation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(f'{len(results)} retained native key outcomes match; stale input views refresh without changing another owner.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--runner', type=Path)
    args = parser.parse_args()
    check(args.project.resolve(), args.runner)
