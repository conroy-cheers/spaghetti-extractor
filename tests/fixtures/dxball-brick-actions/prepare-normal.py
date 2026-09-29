"""Integrate brick lifecycles into normal launched gameplay through real services."""
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
spec=importlib.util.spec_from_file_location('normal_bricks',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);environment=native_environment()
    game_headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    game_headers['play-normal-runtime.c']=HERE.parent/'dxball-gameplay/normal-runtime.c'
    game_headers['paddle-inputs.h']=HERE.parent/'dxball-gameplay/paddle-inputs.h'
    revise_comparison_package(package=game,output=output/'game',include_files=game_headers,
        adapter_files={'normal-runtime.c':HERE.parent/'dxball-ball-motion/normal-runtime.c','bridge.c':game/'adapters/bridge.c'})
    game=output/'game'
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
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    entries={**preparation.RANGES,'seed':(0xae30,0xae49)}
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=preparation.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_brick_'+name)
        for name,(lo,hi) in entries.items())+'\n'+native_entry_header(original=package/'runtime/DXBall.exe',
            expected_sha256=preparation.PE_SHA256,module=None,entry_rva=0xdb80,end_rva=0xdb9f,installer='install_palette_elapsed'))
    includes.update({'native-image.h':output/'native-image.h','brick-runtime.h':package/'headers/brick-runtime.h',
        'motion-normal-runtime.c':HERE.parent/'dxball-ball-motion/normal-runtime.c','palette-inputs.h':HERE/'palette-inputs.h'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'game-consumer':game}),runner=runner,
        runtime_files={**{p.name:p for p in (game/'runtime').iterdir() if p.is_file()},'probe-flow.exe':output/'probe-flow.exe'},
        cases=[dict(id='launched-brick-collision-sixty-four-frames-close',arguments=[])],observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-bricks-normal.dll',symbol='dx_normal_anchor',process=dict(exit_codes=[0],drive='P')),
        scope='Normal launch and sixty-four gameplay frames through brick rules/effects and the preceding twenty-two-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Native allocation, audio, debris and particle bodies remain real services; existing C board/rendering/damage components are selected. Fresh allocations preserve raw payload bytes without traversing uninitialized links.',
            'The counted input driver launches a ball and closes after sixty-four gameplay frames, using only ordinary window messages and read-only hardware breakpoints. The existing paddle-only clock/random schedule is retained and observed.',
            'Random initialization at 0x40ae30 receives the explicit clock input 1 on its calling thread. The native initializer and CRT generator bodies remain active. Seed inputs and subsequent CRT state are compared. Outside initialization and the preceding paddle schedule, the actual clocks/random implementation remains active. Untouched control execution checks startup/output/exit rather than equality of uncontrolled random pixels.',
            'The frame palette elapsed/now operations receive clock input 0xf0000000 plus 16 per gameplay frame. The native elapsed and palette-cycle bodies remain active, and each supplied clock value is observed. This controls the actual environment input at that service boundary; other helpers and delay loops retain their clocks. Palette and pixel observations remain compared.',
            'Normal observations compare initialized effect fields, links, full board/pending bytes, parent frame/motion state and pixels. Three uninitialized flash padding bytes and the unused blast tile word are preserved but not treated as deterministic outputs; initialized-byte preservation is compared locally.',
            'Live views follow reachable objects, with 64 encountered addresses per kind, 128 outer brick/motion calls and 64 observed frames. Unobserved allocator reuse inside native helpers is not strongly qualified. Other whole-program observers retain their previously declared bounded coverage.',
            'This is practical execution evidence, not full-game completion or strong qualification. Every integration discrepancy must be reducible to an independently executable local or connected case.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
