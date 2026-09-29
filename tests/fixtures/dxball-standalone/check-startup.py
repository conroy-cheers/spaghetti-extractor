"""Compare connected program startup storage with retained native observations."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def check(project, comparison, runner):
    report = comparison/'cases/0000-original.report.json'
    native = json.loads(report.read_text())['observations']
    executable = project/'program-startup-check'
    with tempfile.TemporaryDirectory(prefix='dxball-program-startup-') as temporary:
        work = Path(temporary)
        for name in ['score.dat', 'default.bds']:
            matches = [p for p in (comparison/'inputs/runtime').iterdir()
                       if p.name.casefold() == name]
            if len(matches) != 1:
                raise ValueError('missing or ambiguous retained asset: '+name)
            shutil.copyfile(matches[0], work/name)
        run = subprocess.run([*([str(runner)] if runner else []), str(executable)],
                             cwd=work, capture_output=True, text=True, timeout=60)
        if run.returncode:
            raise ValueError('source startup check failed: '+run.stderr[-2000:])
        actual = json.loads(run.stdout)
        (project/'program/startup-actual.json').write_text(json.dumps(actual, indent=2)+'\n')
        expected = dict(scores_initialized=native['score_table'][0]['records'],
            scores_loaded=native['score_table'][1]['records'],
            boards=native['boards'][0]['bytes'][:800],
            saved_boards=native['boards'][0]['bytes'][800:],
            selected_board=native['boards'][1]['bytes'][:800],
            sine=native['math_policy']['sine'], cosine=native['math_policy']['cosine'],
            shared_owners=[1]*8, selected=[2, 2, 1])
        for name, value in expected.items():
            if actual[name] != value:
                raise ValueError('source/native startup difference: '+name)
    result = dict(status='match', authorizing=False,
        scope='Program-owned startup connections and storage; no desktop entry or platform backend claim.',
        native_report_sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        compared_fields=list(expected), observations=actual)
    (project/'program/startup-validation.json').write_text(json.dumps(result, indent=2)+'\n')
    print('Connected source startup matches native score, board and numeric storage; shared owners remain consistent.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('comparison', type=Path)
    parser.add_argument('--runner', type=Path)
    args = parser.parse_args()
    check(args.project.resolve(), args.comparison.resolve(), args.runner)
