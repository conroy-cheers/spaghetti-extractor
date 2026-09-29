"""Run the application shell with the retained normal DX-Ball component network."""
import argparse
from pathlib import Path
import runpy
import subprocess
import sys
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    environment=native_environment()
    subprocess.run([str(environment['compiler']),'-std=c11','-Wall','-Wextra','-Werror','-municode',
        '-DSPX_GAMEPLAY_CLOSE_FRAMES=64','-DSPX_GAMEPLAY_LAUNCH=1',str(HERE.parent/'dxball-game-flow/probe-flow.c'),
        '-o',str(output/'probe-flow.exe'),'-luser32'],check=True)
    runner=output/'gui-runner'
    runner.write_text('#!'+sys.executable+'\n'+f'''import os,sys,subprocess
wine={str(environment['runner'])!r}
args=sys.argv[1:]
if os.environ.get('SPX_COMPARISON_SIDE') not in ('plain','original','source'):os.execv(wine,[wine,*args])
if args[0].startswith('/'):args[0]='Z:'+args[0].replace('/',chr(92))
with open('tmp/controller.log','wb') as log:
    ran=subprocess.run([wine,'probe-flow.exe',*args],stdout=log,timeout=42)
sys.exit(ran.returncode)
''');runner.chmod(0o755)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    headers.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=AUTHOR['PE_SHA256'],module=None,entry_rva=lo,end_rva=hi,
        installer='install_shell_'+name) for name,(lo,hi) in AUTHOR['RANGES'].items()))
    headers.update({'native-image.h':output/'native-image.h','shell-runtime.h':package/'headers/shell-runtime.h',
        'shell-native.h':HERE/'shell-native.h','warning-normal-runtime.c':HERE.parent/'dxball-warning/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=headers,
        **bind_dependencies(consumers={'game-consumer':game}),runner=runner,
        runtime_files={**{p.name:p for p in (game/'runtime').iterdir() if p.is_file()},'probe-flow.exe':output/'probe-flow.exe'},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-shell-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal launch with portable WinMain/window dispatch and the preceding thirty-three-component selection; all prior program observations retained. Inspect diagnostics for reached shell entries.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The native platform backend retains actual Win32/DirectDraw, clocks, sound and unlifted helpers; this is mixed execution, not a standalone portable game.',
            'Shell transport only reads/writes its reviewed shared fields, resources and palette, including before graphics setup. Existing owners handle their other fields at their own service boundaries.',
            'The hardware-breakpoint input driver counts outer frame calls at their shared entry and waits for their return. Its schedule does not depend on an instruction inside the replaced WinMain or count original-body observation wrappers twice.',
            'All previous state, pixel, palette, input and ordered game observations are retained. Platform-generated message sequences and raw handle values are not compared in this workload; exact message/interaction and lifetime comparisons are the independent application-shell cases.',
            'Internal acquire/release calls in portable C do not cross public entry wrappers. Entry counts are diagnostics and cannot alone establish branch coverage. Finite concrete comparisons do not grant strong qualification.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
