"""Exercise one candidate through ordinary desktop messages in owned Wine."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import threading

from spaghetti_extractor.components.comparison_build import observed_command
from spaghetti_extractor.components.comparison_capture import build_capture, capture_command, collect_capture
from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import sha256_file


@contextmanager
def snapshots(runtime, logs, output, timings, observations):
    """Service synchronized driver requests without entering the candidate."""
    control = runtime/'desktop-control'
    control.mkdir()
    output.mkdir()
    stopped = threading.Event()

    def serve():
        request = control/'snapshot.request'
        while not stopped.wait(.02):
            if not request.exists():
                continue
            sequence = -1
            row = {'status': 'failed'}
            try:
                sequence_text, name, x, y, width, height = request.read_text().split()
                sequence = int(sequence_text)
                row.update(sequence=sequence, name=name, client_rect=list(map(int, (x, y, width, height))))
                if sequence < 0 or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.png', name) is None:
                    raise ValueError('snapshot needs a nonnegative sequence and a PNG basename')
                capture = os.environ.get('SPAGHETTI_DESKTOP_CAPTURE')
                if not capture:
                    raise ValueError('snapshot requires spaghetti-headless-wayland --capture')
                command = observed_command([capture, str(output/name)], cwd=runtime,
                    env=dict(os.environ), timeout=7, output=logs/f'snapshot-{sequence}',
                    phase='desktop-capture', timings=timings, cancel_event=stopped)
                if command['returncode'] or command['timed_out'] or command['cancelled']:
                    raise ValueError('compositor capture failed; inspect snapshot command log')
                image = output/name
                if image.read_bytes()[:8] != b'\x89PNG\r\n\x1a\n':
                    raise ValueError('compositor capture is not a PNG image')
                row.update(status='captured', sha256=sha256_file(image), bytes=image.stat().st_size)
            except Exception as error:
                row['error'] = str(error)
            observations.append(row)
            request.unlink()
            response = control/'snapshot.done.tmp'
            response.write_text(f'{sequence} {int(row["status"] == "captured")}\n')
            response.replace(control/'snapshot.done')

    worker = threading.Thread(target=serve, name='desktop-capture')
    worker.start()
    try:
        yield
    finally:
        stopped.set()
        worker.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('actions', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--wine', required=True)
    parser.add_argument('--server', required=True)
    parser.add_argument('--env', action='append', default=[], metavar='NAME=VALUE')
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    build, runtime, logs, prefix = (root/name for name in ('build', 'runtime', 'logs', 'prefix'))
    for path in (build, logs, prefix):
        path.mkdir()
    if args.assets:
        shutil.copytree(args.assets, runtime)
    else:
        runtime.mkdir()
    (runtime/'tmp').mkdir(exist_ok=True)
    shutil.copyfile(args.image, runtime/'candidate.exe')
    shutil.copyfile(args.actions, runtime/'actions.txt')
    shutil.copyfile(Path(__file__).with_name('driver.c'), build/'driver.c')
    timings = []
    env = {**os.environ, 'WINEPREFIX': str(prefix), 'WINEDEBUG': '-all',
           'WINEDLLOVERRIDES': 'mscoree,mshtml,winemenubuilder.exe='}
    for item in args.env:
        key, value = item.split('=', 1)
        if key in {'WINEPREFIX', 'WAYLAND_DISPLAY', 'DISPLAY'}:
            raise ValueError('desktop ownership cannot be overridden')
        env[key] = value
    result = observed_command([args.compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-static',
        'driver.c', '-lgdi32', '-o', 'desktop-driver.exe'], cwd=build, env=env, timeout=60,
        output=logs/'driver-build', phase='compiler', timings=timings)
    if result['returncode'] or result['timed_out']:
        raise ValueError('desktop driver compilation failed; inspect retained log')
    if not build_capture(compiler=args.compiler, output=build, env=env, timeout=60, timings=timings):
        raise ValueError('standard-handle capture compilation failed; inspect retained log')
    shutil.copyfile(build/'desktop-driver.exe', runtime/'desktop-driver.exe')
    inputs = {str(path.relative_to(runtime)): sha256_file(path)
              for path in sorted(runtime.rglob('*')) if path.is_file()}
    (root/'inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    captures = []
    with wine_sessions(server=args.server, runner=args.wine, environments={'candidate': env},
            cwd=runtime, logs=logs, timeout=args.timeout, timings=timings,
            persistent=True, dispose_prefixes=True):
        command, execution_env = capture_command([args.wine, str(runtime/'desktop-driver.exe'),
            '.\\candidate.exe', 'actions.txt'], runtime=runtime, launcher=build/'spaghetti-capture.exe',
            env=env, timeout=args.timeout)
        with snapshots(runtime, logs, root/'captures', timings, captures):
            result = observed_command(command, cwd=runtime, env=execution_env, timeout=args.timeout+5,
                output=logs/'execution', phase='program-execution', timings=timings)
        collect_capture(runtime=runtime, prefix=logs/'execution', execution=result)
        driver_report = runtime/'desktop-driver.json'
        if driver_report.is_file():
            result['desktop'] = json.loads(driver_report.read_text())
        else:
            result['observation_error'] = 'desktop driver did not retain its completion report'
        if any(row['status'] != 'captured' for row in captures):
            result['observation_error'] = 'one or more compositor snapshots failed; inspect snapshot observations'
        desktop = Path(os.environ['XDG_RUNTIME_DIR'])
        for name in ('weston.log', 'compositor.stderr', 'audio.log'):
            if (desktop/name).is_file():
                shutil.copyfile(desktop/name, logs/('desktop-'+name))
    report = {'execution': result, 'timings': timings, 'snapshots': captures}
    (root/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(result))
    return int(bool(result['returncode'] or result['timed_out'] or result.get('observation_error')))


if __name__ == '__main__':
    raise SystemExit(main())
