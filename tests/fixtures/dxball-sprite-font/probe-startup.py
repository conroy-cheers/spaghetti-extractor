"""Inspect the untouched game in a private headless desktop before integration."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import time

from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import write_json


def run(assets, output):
    if not os.environ.get('WAYLAND_DISPLAY'): raise ValueError('run in spaghetti-headless-wayland')
    output.mkdir(parents=True, exist_ok=False); runtime = output/'runtime'; shutil.copytree(assets, runtime)
    tools = native_environment(); compiler = tools['compiler']; runner = tools['runner']; server = tools['server']
    subprocess.run([str(compiler), str(Path(__file__).with_name('probe-window.c')), '-o', str(runtime/'probe.exe'),
                    '-lgdi32', '-luser32'], check=True)
    prefix = output/'wine'; prefix.mkdir(); env = {**os.environ, 'WINEPREFIX': str(prefix), 'WINEDEBUG': '-all'}
    timings = []; started = time.monotonic()
    with wine_sessions(server=str(server), environments={'probe': env}, cwd=runtime, logs=output,
                       timeout=30, timings=timings, persistent=True, runner=str(runner), dispose_prefixes=True):
        with (output/'game.stdout').open('wb') as out, (output/'game.stderr').open('wb') as err:
            game = subprocess.Popen([str(runner), 'DXBall.exe'], cwd=runtime, env=env, stdout=out, stderr=err)
            try:
                probe = subprocess.run([str(runner), 'probe.exe'], cwd=runtime, env=env, capture_output=True, timeout=20)
                (output/'probe.stdout').write_bytes(probe.stdout); (output/'probe.stderr').write_bytes(probe.stderr)
                try: code = game.wait(timeout=5)
                except subprocess.TimeoutExpired: game.terminate(); code = game.wait(timeout=5)
            finally:
                if game.poll() is None: game.kill(); game.wait()
    write_json(output/'probe.json', dict(seconds=time.monotonic()-started, game_exit=code, probe_exit=probe.returncode,
        original_startup=True, selected_replacements=False, timings=timings))
    print(probe.stdout.decode(errors='replace'), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('assets', type=Path); p.add_argument('output', type=Path)
    a = p.parse_args(); run(a.assets.resolve(), a.output.resolve())
