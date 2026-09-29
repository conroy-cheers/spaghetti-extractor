"""Try real game entry with a bounded external window controller."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_package import revise_comparison_package
from spaghetti_extractor.util import write_json
from prepare import HERE


def prepare(package, assets, output):
    output.mkdir(parents=True, exist_ok=False)
    environment = native_environment()
    subprocess.run([str(environment['compiler']), str(HERE/'probe-window.c'), '-o', str(output/'probe.exe'),
                    '-lgdi32', '-luser32'], check=True)
    # The public runner seam can own an ordinary external GUI controller. Wine
    # prefix startup commands pass through; application runs retain its output.
    runner = output/'gui-runner'
    runner.write_text('#!'+sys.executable+'\n'+f'''import os,sys,subprocess
from pathlib import Path
wine={str(environment['runner'])!r}
args=sys.argv[1:]
if os.environ.get('SPX_COMPARISON_SIDE') not in ('plain','original','source'):
    os.execv(wine,[wine,*args])
game=subprocess.Popen([wine,*args])
try:
    with open('tmp/controller.log','wb') as out:
        control=subprocess.run([wine,'probe.exe','--drive'],stdout=out,stderr=out,timeout=24)
    code=game.wait(timeout=5)
    if control.returncode: sys.exit(87)
    sys.exit(code)
finally:
    if game.poll() is None: game.terminate();game.wait(timeout=3)
''')
    runner.chmod(0o755)
    include = {p.relative_to(package/'headers').as_posix(): p for p in (package/'headers').rglob('*') if p.is_file()}
    revise_comparison_package(package=package, output=output/'package',
        adapter_files={'normal-runtime.c': HERE/'normal-runtime.c', 'bridge.c': package/'adapters/bridge.c'},
        include_files=include,
        **{**environment, 'runner': runner, 'runtime_files': {**environment['runtime_files'],
            **{p.name: p for p in assets.iterdir() if p.is_file()}, 'probe.exe': output/'probe.exe'}},
        cases=[dict(id='startup-input-close', arguments=[])],
        observation_fields=['exit_code', 'stdout', 'stderr', 'state'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-normal.dll',
            symbol='dx_normal_anchor', process=dict(exit_codes=[0], drive='P')),
        scope='Attempted normal DX-Ball startup, external input/close, selected metrics and cleanup using original heap/DirectDraw.',
        assumptions=[
            'Pinned original entry and TLS are preserved. The untouched original, instrumented original and selected C run in separate prefixes through the same external window controller.',
            'This live adapter assumes single-threaded game operations, valid unique sprite slots, and original allocator/DirectDraw services. It transports actual sprite identities and metadata rather than reconstructing fake objects.',
            'Only the first 32 metric calls and up to 64 text bytes per call are observed; total selected entry counts are diagnostics. No complete frame, audio, clock or input replay claim.',
            'The controller waits for a visible game window, posts F2 and a click, then requests WM_CLOSE. Subsequent timings are wall-clock based; this is an integration probe, not a deterministic simulation.',
            *json.loads((package/'comparison-plan.json').read_text())['assumptions']])
    write_json(output/'preparation.json', dict(original_entry_preserved=True, source_body_traps=True,
        live_object_transport=True, strong_qualification=False, whole_game_portable=False))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'assets', 'output'): p.add_argument(name, type=Path)
    a = p.parse_args(); prepare(a.package.resolve(), a.assets.resolve(), a.output.resolve())
