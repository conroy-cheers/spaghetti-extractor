"""Public representation migration, discrepancy repair and connected assembly.

Run inside spaghetti-headless-wayland. This orchestrates the existing preparers
and public commands; the shared comparison/selection machinery checks behavior.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file

HERE = Path(__file__).resolve().parent
REVISION = 'unpacked-descriptors-native-arrays-v1'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise RuntimeError('requires a headless Wayland desktop')
    base, out = args.base.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands, results = [], {}

    def run(arguments, *, expected=0):
        command = [sys.executable, *map(str, arguments)]
        number = len(commands)
        started = time.monotonic()
        process = subprocess.run(command, capture_output=True, text=True)
        (out/f'{number:02d}.stdout').write_text(process.stdout)
        (out/f'{number:02d}.stderr').write_text(process.stderr)
        commands.append(dict(command=command, exit_code=process.returncode,
                             seconds=time.monotonic()-started))
        (out/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        print(json.dumps(dict(command=number, exit_code=process.returncode,
                              seconds=commands[-1]['seconds'])), flush=True)
        if process.returncode != expected:
            raise RuntimeError(f'command {number}: expected {expected}, got {process.returncode}; inspect {out}')
        return process.stdout+'\n'+process.stderr

    def public(arguments, **kwargs):
        return run(['-m', 'spaghetti_extractor', *arguments], **kwargs)

    def prepare(label, layout=None):
        arrays, paths = out/(label+'-arrays'), out/(label+'-paths')
        arguments = [HERE/'prepare.py', base, arrays]
        if layout:
            arguments += ['--descriptor-layout', layout, '--descriptor-revision', REVISION]
        run(arguments)
        run([HERE.parent/'jq-path-network/prepare.py', base, paths,
             '--resource-checks', '--array-storage-packages', arrays])
        return arrays, paths

    def check(label, package, *, previous=None, case=None, dependency=None,
              expected=0, rejection=False):
        arguments = ['component', 'check', 'jq', 'path-set' if package.name == 'path-set-network'
                     or package.name == 'inputs' else 'path-get',
                     '--comparison-package', package, '--output', out/label]
        if previous:
            arguments += ['--reuse-comparison', out/previous]
        if case:
            arguments += ['--case', case]
        if dependency:
            arguments += ['--dependency-package', 'storage-set='+str(dependency)]
        message = public(arguments, expected=expected)
        if rejection:
            assert ('dependency contract changed' in message or 'incompatible representation selection' in message), message
            assert not list((out/label).rglob('*.o'))
            assert not (out/label/'build/comparison.exe').exists()
            return
        result = load_comparison_result(out/label)
        results[label] = result
        return result

    native_arrays, native_paths = prepare('native')
    arrays, paths = prepare('unpacked', HERE/'unpacked-value-layout.h')
    # The native get service uses no authored array descriptor, so its local
    # evidence can survive this migration. This is service-conformance evidence,
    # not an independent theorem for the authored path caller.
    for label, storage in [('native', native_arrays), ('unpacked', arrays)]:
        run([HERE.parent/'jq-path-controlled/prepare.py', base, out/(label+'-controlled'),
             '--array-storage-packages', storage])
    check('service-baseline', out/'native-controlled/service')
    check('native-baseline', native_paths/'path-set-network')
    changed = check('representation-changed', paths/'path-set-network', previous='native-baseline')
    assert changed['status'] == 'match' and changed['reuse']['status'] == 'invalidated'
    assert changed['work_counts']['execution'] and not changed['work_counts']['solver']
    old_plan, old_interface = load_comparison_package(native_arrays/'storage-set')
    new_plan, new_interface = load_comparison_package(arrays/'storage-set')
    assert old_interface.intent_sha256 == new_interface.intent_sha256
    assert old_plan['representation']['revision'] != new_plan['representation']['revision']
    check('mixed-revision', paths/'path-set-network', dependency=native_arrays/'storage-set',
          expected=2, rejection=True)
    draft = out/'mixed-bytes-draft'
    public(['component', 'start', 'jq', 'storage-set', '--comparison-package', arrays/'storage-set', '--output', draft])
    header = draft/'source/value-layout.h'
    header.write_text(header.read_text()+'\n/* independently changed representation bytes */\n')
    check('mixed-bytes', paths/'path-set-network', dependency=draft, expected=2, rejection=True)

    # Change every member coherently through the preparer. Selection is valid;
    # runtime comparison must detect that losing a slice offset is incorrect.
    correct = (HERE/'unpacked-value-layout.h').read_text()
    needle = '{value.u, value.size, value.offset,'
    assert correct.count(needle) == 1
    layout = out/'edited-value-layout.h'
    layout.write_text(correct.replace(needle, '{value.u, value.size, 0,'))
    _, broken_paths = prepare('broken', layout)
    wrong = check('wrong-conversion', broken_paths/'path-set-network', case='slice-nested', expected=2)
    assert wrong['status'] == 'mismatch'
    layout.write_text(correct)
    repaired_arrays, repaired_paths = prepare('repaired', layout)
    replay = check('retained-replay', out/'wrong-conversion/inputs', case='slice-nested', expected=2)
    assert replay['cases'][0]['first_difference'] == wrong['cases'][0]['first_difference']
    repaired = check('representation-repaired', repaired_paths/'path-set-network', previous='representation-changed')
    service = check('service-reused', out/'unpacked-controlled/service', previous='service-baseline')
    for result in (repaired, service):
        assert result['reuse']['status'] == 'reused' and not any(result['work_counts'].values())
    assert all(result['formal_check']['status'] == 'not-requested' for result in results.values())

    # Exercise an ordinary algorithm edit after migration and reuse the existing
    # assembly recipe, including fresh checks for all selected components.
    run([HERE/'walkthrough.py', repaired_arrays, out/'editing',
         '--path-package', repaired_paths/'path-set-network'])
    run([HERE/'assemble.py', repaired_arrays, repaired_paths, out/'editing', out/'assembly'])
    report = dict(status='pass', authorizing=False, whole_program_complete=False,
        scope='Private jq descriptor migration; native backing-array layout and outside-scope services retained',
        same_operation_signature=True, mixed_revision_rejected_before_compilation=True,
        changed_shared_bytes_rejected_before_compilation=True,
        manual_changes=['private descriptor C fields and load/store conversion',
                        'explicit representation revision supplied to package preparer'],
        per_component_tool_internal_changes=False,
        results={name:dict(status=result['status'], receipt_sha256=result['receipt_sha256'],
                          work_counts=result['work_counts'], reuse=result['reuse'], timings=result['timings'])
                 for name, result in results.items()},
        editing='editing/audit.json', assembly='assembly/audit.json',
        producers={str(p):sha256_file(p) for directory in [HERE, HERE.parent/'jq-path-network',
                    HERE.parent/'jq-path-controlled'] for p in sorted(directory.iterdir()) if p.is_file()})
    (out/'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(status='pass', commands=len(commands), authorizing=False)))


if __name__ == '__main__':
    main()
