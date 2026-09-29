"""Connect actual gameplay frames to score, life and level transitions."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
progress=module('connected_progress',HERE/'prepare.py')
play=module('connected_play',HERE.parent/'dxball-gameplay/prepare.py')

def prepare(package,frame,output):
    output.mkdir(parents=True,exist_ok=False)
    excluded={'refresh_score','next_board','advance_stage','stop_sound','play_sound','wait'}
    entries={'frame_update':play.RANGES['update'],**{'frame_service_'+n:(v,v+8) for n,v in play.HOOKS.items() if n not in excluded}}
    (output/'native-image.h').write_text((package/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=progress.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    (output/'connected-runtime.c').write_text('#define PROGRESS_CONNECTED 1\n#include "progress-local-runtime.c"\n')
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','progress-local-runtime.c':HERE/'runtime.c','frame-progress.h':HERE/'frame-progress.h',
        'play-runtime.h':frame/'headers/play-runtime.h'})
    revise_comparison_package(package=package,output=output/'package',adapter_files={'runtime.c':output/'connected-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files=includes,**bind_dependencies(consumers={'frame-consumer':frame}),
        cases=[dict(id='frame-'+name,arguments=[str(33+i)]) for i,name in enumerate(['life-restart','level-restart','game-over','final-level','paused'])],
        assumptions=[(HERE/'BOUNDARY.md').read_text(),'Actual frames drive score refresh, next-board and round-transition bodies over the same shared objects. Controlled movement requests actual life loss; allocation, cleanup, board loading, graphics and remaining helpers are observed services. Each scenario runs up to four frames, stopping at the score-scene transition. No complete game startup is used.'],
        scope='Two-component frame/progression network with shared score/life/board/palette state and cleanup/restart across frames.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','frame','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.frame.resolve(),a.output.resolve())
