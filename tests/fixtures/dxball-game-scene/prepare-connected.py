"""Connect gameplay scene entry/redraw/input to the existing progression bodies."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
game=module('connected_game',HERE/'prepare.py')
progress=module('connected_progress',HERE.parent/'dxball-progression/prepare.py')

def prepare(package,consumer,output):
    output.mkdir(parents=True,exist_ok=False)
    services=('destination','text','damage','sprite','stop_sound','pan','play_sound','wait','palette','create_ball')
    entries={**{'following_'+n:progress.RANGES[n] for n in ('draw','restart')},
        **{'following_service_'+n:(progress.HOOKS[n],progress.HOOKS[n]+8) for n in services}}
    (output/'native-image.h').write_text((package/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=game.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    (output/'connected-runtime.c').write_text('#define GAME_CONNECTED 1\n#include "game-local-runtime.c"\n')
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','game-local-runtime.c':HERE/'runtime.c',
        'progress-consumer.h':HERE/'progress-consumer.h','connected-native.h':HERE/'connected-native.h',
        'progress-runtime.h':consumer/'headers/progress-runtime.h'})
    revise_comparison_package(package=package,output=output/'package',adapter_files={'runtime.c':output/'connected-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files=includes,**bind_dependencies(consumers={'progression-consumer':consumer}),
        cases=[dict(id='scene-progression-'+name,arguments=[str(24+i)]) for i,name in enumerate(['entry','pause-resume','cheats-restart'])],
        assumptions=[(HERE/'BOUNDARY.md').read_text(),'Actual scene entry/redraw and progression restart/score drawing execute over the same objects. Redraw dispatch recurses through the actual scene implementation. Remaining services are controlled and observed, including ball allocation and board loading. No full-game startup is used.'],
        scope='Connected gameplay scene/progression entry, score drawing, pause/resume and restart with shared mutable state.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','consumer','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.consumer.resolve(),a.output.resolve())
