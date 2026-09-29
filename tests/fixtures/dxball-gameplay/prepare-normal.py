"""Use the existing frame-counted game driver with the checked gameplay C."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('play_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);game_plan,_=load_comparison_package(game)
    environment=native_environment()
    subprocess.run([str(environment['compiler']),'-std=c11','-Wall','-Wextra','-Werror','-municode',
        str(HERE.parent/'dxball-game-flow/probe-flow.c'),'-o',str(output/'probe-flow.exe'),'-luser32'],check=True)
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
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    lo,hi=preparation.RANGES['update']
    entries=dict(play_update=(lo,hi),paddle_input_now=(0xdb20,0xdb7b),
        paddle_input_random=(0xae20,0xae2d),paddle_input_draw=(0x67b0,0x69b3))
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=preparation.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,
        installer='install_'+name) for name,(lo,hi) in entries.items()))
    includes.update({'native-image.h':output/'native-image.h','play-runtime.h':package/'headers/play-runtime.h',
        'play-native.h':HERE/'play-native.h','paddle-inputs.h':HERE/'paddle-inputs.h',
        'regions-normal-runtime.c':HERE.parent/'dxball-regions/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'game-consumer':game}),runner=runner,
        runtime_files={**{p.name:p for p in (game/'runtime').iterdir() if p.is_file()},'probe-flow.exe':output/'probe-flow.exe'},
        cases=[dict(id='counted-gameplay-frames-close',arguments=[])],observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-play-normal.dll',symbol='dx_normal_anchor',
            process=dict(exit_codes=[0],drive='P')),
        scope='Normal title/menu/gameplay/close with the C gameplay frame and the preceding twenty-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Controlled helpers are explicitly replaced by actual native physics, allocation, audio and the selected graphics network. Local cases retain the independently executable helper/callback scenarios.',
            'The retained paddle renderer receives identical explicit clock and random inputs on the observed original and source sides. Its clock advances by 64 per frame from 0xf0000000 and its random choice is frame modulo limit. Input order, arguments and results are compared. Outside that synchronous helper the actual clocks/random implementation remain active. The untouched control checks normal startup/output/exit, not equality of uncontrolled random pixels.',
            'The existing counted input driver advances through six gameplay frames before close. All three sides use ordinary window messages and read-only hardware breakpoints; application code/data are not modified by the driver.',
            'Live typed views copy complete reachable ball, shot and event records and links around each synchronous service. Previously borrowed objects that leave the roots are not dereferenced. Native allocation identity across an unobserved allocate/free cycle inside a helper is not qualified by these snapshots.',
            'The observer admits up to 64 encountered addresses per object kind and 32 outer gameplay frames. It retains payloads, pointer identities, pending-cell bytes, frame fields and pixel hashes. Absolute clock readings are diagnostic, with controlled clock behavior compared locally.',
            'The native floating profile is nearest rounding with 53-bit x87 precision, checked at frame entry. Full gameplay helper bodies, startup, portable platform backends and complete playthrough coverage remain open.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
