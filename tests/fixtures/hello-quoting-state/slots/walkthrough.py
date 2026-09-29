"""Public edit/check/reuse walkthrough for the controlled complete quoting network."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json


def walkthrough(root):
    evidence = root/'walkthrough'; evidence.mkdir()
    draft, child = root/'draft', root/'release-supplier'
    env = dict(os.environ)
    # These overrides otherwise make compiler dependency discovery incomplete.
    # Restrict only the fixture subprocess environment; change no user settings.
    removed = [n for n in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'GCC_EXEC_PREFIX', 'COMPILER_PATH') if env.pop(n, None)]
    records = []

    def check(name, *, previous=None, supplier=False, expected=0):
        command = [sys.executable, '-m', 'spaghetti_extractor', 'component', 'check', 'gnu-hello', 'quote-slots',
                   '--comparison-package', str(draft), '--output', str(evidence/name)]
        if previous is not None: command += ['--reuse-comparison', str(evidence/previous)]
        if supplier: command += ['--dependency-package', 'preserve-errno-free='+str(child)]
        started = time.monotonic()
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
        (evidence/(name+'.stdout')).write_text(result.stdout)
        (evidence/(name+'.stderr')).write_text(result.stderr)
        record = {'name': name, 'command': command, 'seconds': time.monotonic()-started, 'exit_code': result.returncode}
        records.append(record)
        assert result.returncode == expected, (record, result.stdout, result.stderr)
        path = evidence/name/'comparison-result.json'
        if not path.is_file(): return result.stdout+result.stderr
        checked = load_comparison_result(evidence/name)
        record.update(result_sha256=sha256_file(path), status=checked['status'], work_counts=checked['work_counts'],
                      phases=checked['timings'], authorizing=checked['authorizing'])
        compiled = evidence/name/'build/compilation.json'
        if compiled.is_file():
            record['translation_units'] = [{'source': u['source'], 'reused': u['reused']}
                                          for u in json.loads(compiled.read_text())['units']]
        return checked

    baseline = check('baseline')
    assert baseline['status'] == 'match' and len(baseline['cases']) == 128
    unchanged = check('unchanged', previous='baseline')
    assert unchanged['reuse']['status'] == 'reused' and all(v == 0 for v in unchanged['work_counts'].values())
    child_source = child/'source/preserve-errno-free.c'
    original_child = child_source.read_text()
    before = 'uint32_t restored = read_cell(&cell) == 0U ? second : first;'
    assert original_child.count(before) == 1
    child_source.write_text(original_child.replace(before,
        'uint32_t restored = first;\n  if (read_cell(&cell) == 0U) restored = second;'))
    edited = check('supplier-edited', previous='baseline', supplier=True)
    assert edited['status'] == 'match'
    compilation = json.loads((evidence/'supplier-edited/build/compilation.json').read_text())
    assert [u['source'] for u in compilation['units'] if not u['reused']] == [
        'dependencies/preserve-errno-free/source/preserve-errno-free.c']
    parent_source = draft/'source/quote-slots.c'
    original_parent = parent_source.read_text()
    assert original_parent.count('options->flags | 1U') == 1
    parent_source.write_text(original_parent.replace('options->flags | 1U', 'options->flags'))
    wrong = check('wrong-parent', previous='supplier-edited', supplier=True, expected=2)
    assert wrong['status'] == 'mismatch' and any(c.get('first_difference') for c in wrong['cases'])
    parent_source.write_text(original_parent)
    repaired = check('repaired', previous='supplier-edited', supplier=True)
    assert repaired['reuse']['status'] == 'reused' and all(v == 0 for v in repaired['work_counts'].values())
    plan_path = child/'comparison-plan.json'; original_plan = plan_path.read_text()
    plan = json.loads(original_plan); plan['assumptions'].append('Deliberate additional unestablished precondition.')
    write_json(plan_path, plan)
    try:
        message = check('incompatible-contract', supplier=True, expected=2)
        assert 'dependency contract changed' in message
    finally:
        plan_path.write_text(original_plan)
    result = {'status': 'public finite author/edit/check/reuse workflow passed',
        'activation_authorized': False, 'whole_component_complete': False,
        'formal_proof': 'not requested; persistent object and lifetime composition unsupported',
        'steps': records, 'removed_subprocess_environment_overrides': removed,
        'source_sha256s': {str(p): sha256_file(p) for p in Path(__file__).parent.iterdir() if p.is_file()},
        'remaining': ['Checked persistent object/alias/lifetime and reference transport.',
                      'Conditional premises discharged through native qualification.',
                      'All whole-target G1-G7 acceptance exits.']}
    write_json(evidence/'validation.json', result)
    print(json.dumps({'status': result['status'], 'steps': [
        {k: r[k] for k in ('name', 'seconds', 'exit_code', 'status', 'work_counts') if k in r} for r in records]}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared_public_root', type=Path)
    walkthrough(parser.parse_args().prepared_public_root.resolve())
