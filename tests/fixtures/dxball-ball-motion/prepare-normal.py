"""Run ball creation and launched motion in the existing normal-game network."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('motion_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);environment=native_environment()
    sources={p.name:p for p in (game/'source').iterdir() if p.is_file()}
    sources['play-state.h']=HERE.parent/'dxball-gameplay/play-state.h'
    revise_comparison_package(package=game,output=output/'game',source_files=sources,
        adapter_files={'normal-runtime.c':HERE.parent/'dxball-gameplay/normal-runtime.c','bridge.c':game/'adapters/bridge.c'})
    game=output/'game'
    subprocess.run([str(environment['compiler']),'-std=c11','-Wall','-Wextra','-Werror','-municode',
        '-DSPX_GAMEPLAY_CLOSE_FRAMES=16','-DSPX_GAMEPLAY_LAUNCH=1',str(HERE.parent/'dxball-game-flow/probe-flow.c'),
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
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=preparation.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_motion_'+name)
        for name,(lo,hi) in preparation.RANGES.items()))
    includes.update({'native-image.h':output/'native-image.h','motion-runtime.h':package/'headers/motion-runtime.h',
        'motion-native.h':HERE/'motion-native.h','play-normal-runtime.c':HERE.parent/'dxball-gameplay/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'game-consumer':game}),runner=runner,
        runtime_files={**{p.name:p for p in (game/'runtime').iterdir() if p.is_file()},'probe-flow.exe':output/'probe-flow.exe'},
        cases=[dict(id='launch-motion-sixteen-frames-close',arguments=[])],observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-motion-normal.dll',symbol='dx_normal_anchor',process=dict(exit_codes=[0],drive='P')),
        scope='Normal launch and sixteen gameplay frames through the selected ball-motion, frame and existing twenty-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Native allocation, particles, brick actions, audio and special effects remain real services. Source and original share the same reachable ball, sprite and board views; fresh allocations are registered without reading uninitialized links.',
            'The existing frame-counted input driver posts a launch press/release and closes after sixteen gameplay frames. It uses ordinary window messages and read-only hardware breakpoints, with no driver writes to game code or data.',
            'The preceding explicit paddle-only clock/random schedule remains in force and is observed. Other services use the real environment. The untouched control checks startup/output/exit; observed pixel equivalence is conditional on the declared inputs.',
            'The observer retains up to 128 outer motion calls, complete reachable ball payloads/links, board bytes and scalar state. Existing frame observations retain pixels. Snapshot identities do not qualify unobserved allocation reuse or unrestricted heap lifetimes.',
            'The complete game, physics effects and portable platform backends remain unfinished; the workload demonstrates launch/motion, not a complete playthrough.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
