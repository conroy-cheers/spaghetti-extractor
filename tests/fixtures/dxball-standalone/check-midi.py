"""Run the assembled SDK/MDS consumer with separate application/Wine streams.

Invoke inside the existing headless Wayland environment. The output retains each
case, including a failed reproduction; no game startup or pilot build is needed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil

from spaghetti_extractor.components.comparison_build import observed_command
from spaghetti_extractor.components.comparison_capture import build_capture, capture_command, collect_capture
from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import sha256_file


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--compiler', required=True)
    p.add_argument('--wine', required=True)
    p.add_argument('--server', required=True)
    cases = ('controlled', 'provider-link', 'provider-flags', 'fail-open', 'native', 'native-reset', 'native-loop')
    p.add_argument('--case', action='append', choices=cases)
    args = p.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    build, runtime, logs, prefix = (root/name for name in ('build', 'runtime', 'logs', 'prefix'))
    for path in (build, runtime, logs, prefix, runtime/'tmp'):
        path.mkdir()
    shutil.copyfile(args.image, runtime/'candidate.exe')
    environment = {**os.environ, 'WINEPREFIX': str(prefix), 'WINEDEBUG': '-all',
                   'WINEDLLOVERRIDES': 'mscoree,mshtml,winemenubuilder.exe='}
    timings = []
    if not build_capture(compiler=args.compiler, output=build, env=environment, timeout=60, timings=timings):
        raise ValueError('capture build failed; inspect retained log')
    results = {}
    with wine_sessions(server=args.server, runner=args.wine, environments={'candidate': environment},
            cwd=runtime, logs=logs, timeout=30, timings=timings, persistent=True, dispose_prefixes=True):
        for name in args.case or cases:
            command, env = capture_command([args.wine, str(runtime/'candidate.exe'), name],
                runtime=runtime, launcher=build/'spaghetti-capture.exe', env=environment, timeout=15)
            result = observed_command(command, cwd=runtime, env=env, timeout=20,
                output=logs/name, phase='midi-execution', timings=timings)
            collect_capture(runtime=runtime, prefix=logs/name, execution=result)
            if (logs/(name+'.stderr')).stat().st_size:
                result['observation_error'] = 'unexpected application stderr; inspect retained diagnostic'
            if not result['returncode'] and not result['timed_out'] and not result.get('observation_error'):
                result['observations'] = json.loads((logs/(name+'.stdout')).read_text())
            results[name] = result
    passed = all(not r['returncode'] and not r['timed_out'] and not r.get('observation_error') for r in results.values())
    report = {'status': 'pass' if passed else 'failed', 'image_sha256': sha256_file(args.image),
              'cases': results, 'timings': timings, 'scope': 'Windows SDK adapter and lifted MDS stream C'}
    (root/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'status': report['status'], 'cases': {k: v['returncode'] for k, v in results.items()}}))
    return int(not passed)


if __name__ == '__main__':
    raise SystemExit(main())
