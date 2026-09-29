"""Run selected game control with actual scenes and frame-counted external input."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE = Path(__file__).resolve().parent


def prepare(package, lifecycle_normal, drawing_package, assets, output):
    output.mkdir(parents=True, exist_ok=False)
    environment = native_environment()
    subprocess.run([str(environment['compiler']), '-std=c11', '-Wall', '-Wextra', '-Werror', '-municode',
        str(HERE/'probe-flow.c'), '-o', str(output/'probe-flow.exe'), '-luser32'], check=True)
    runner = output/'gui-runner'
    runner.write_text('#!'+sys.executable+'\n'+f'''import os,sys,subprocess
wine={str(environment['runner'])!r}
args=sys.argv[1:]
if os.environ.get('SPX_COMPARISON_SIDE') not in ('plain','original','source'):
    os.execv(wine,[wine,*args])
# Win32 CreateProcess takes a Windows image pathname, including for the launcher.
if args[0].startswith('/'):
    args[0]='Z:'+args[0].replace('/',chr(92))
with open('tmp/controller.log','wb') as log:
    ran=subprocess.run([wine,'probe-flow.exe',*args],stdout=log,timeout=42)
sys.exit(ran.returncode)
''')
    runner.chmod(0o755)
    includes = {p.relative_to(lifecycle_normal/'headers').as_posix(): p
                for p in (lifecycle_normal/'headers').rglob('*') if p.is_file()}
    includes.update({p.relative_to(package/'headers').as_posix(): p
                     for p in (package/'headers').rglob('*') if p.is_file()})
    original = package/'runtime/DXBall.exe'
    header = (package/'headers/native-image.h').read_text()
    for name, lo, hi in (('sprite_destination', 0xbd60, 0xbd6a), ('sprite_transparent', 0xbd90, 0xbdcf),
                         ('sprite_opaque', 0xbdd0, 0xbe0f)):
        header += '\n'+native_entry_header(original=original, expected_sha256=sha256_file(original), module=None,
            entry_rva=lo, end_rva=hi, installer='install_'+name)
    (output/'native-image.h').write_text(header); includes['native-image.h'] = output/'native-image.h'
    includes['lifecycle-normal-runtime.c'] = HERE.parent/'dxball-sprite-lifecycle/normal-runtime.c'
    binding = bind_dependencies(consumers={'drawing-consumer': drawing_package})
    binding['requirements'] += json.loads((package/'comparison-plan.json').read_text())['requirements']
    revise_comparison_package(package=package, output=output/'package',
        adapter_files={'normal-runtime.c': HERE/'normal-runtime.c', 'bridge.c': package/'adapters/bridge.c'},
        include_files=includes, **binding, runner=runner,
        runtime_files={**environment['runtime_files'], **{p.name: p for p in assets.iterdir() if p.is_file()},
                       'probe-flow.exe': output/'probe-flow.exe'},
        cases=[dict(id='counted-frame-input-close', arguments=[])],
        observation_fields=['exit_code', 'stdout', 'stderr', 'state'],
        program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe', library='dx-flow-normal.dll',
            symbol='dx_normal_anchor', process=dict(exit_codes=[0], drive='P')),
        scope='Normal DX-Ball with C game control and sprite network, actual native services and external frame-counted input.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'All three sides use a hardware execution breakpoint at the original main-loop frame call site, before either a wrapper or the selected implementation. The external debugger counts frames, reads scene/readiness state and posts ordinary window messages; it never writes application code or data. Debugger pause time remains observable to wall clocks.',
            'The same counted input protocol drives untouched original, instrumented original and selected C. The test is a bounded startup/menu/game/close sequence, not arbitrary input equivalence.',
            'Original startup, scene bodies, allocation, audio and DirectDraw remain native services. Audio GetStatus is assumed to write its status result, as required by the component boundary.',
            'Observe the first 32 outer flow calls, 32 metrics, 128 outer graphics calls and 24 lifecycle calls. Nested implementation calls are diagnostic counts, with all previous graphics/lifecycle observations retained.',
            'Native object views share existing storage/identity transport. Actual source components execute synchronously on the game thread; whole-program portability and complete pixel/audio observation remain open.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    names = ('package', 'lifecycle_normal', 'drawing_package', 'assets', 'output')
    for name in names: parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(*(getattr(args, name).resolve() for name in names))
