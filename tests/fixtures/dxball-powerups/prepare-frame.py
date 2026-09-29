"""Connect actual pickup collection and gameplay frames to powerup actions."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
power=module('connected_power',HERE/'prepare.py')
pickup=module('connected_pickup',HERE.parent/'dxball-pickups/prepare.py')
play=module('connected_play',HERE.parent/'dxball-gameplay/prepare.py')

def prepare(package,pickup_package,frame,output):
    output.mkdir(parents=True,exist_ok=False)
    excluded={'move_pickups','draw_pickups','split','power','free_event','stop_sound','play_sound','spawn_debris'}
    entries={'frame_update':play.RANGES['update'],**{'frame_service_'+n:(v,v+8) for n,v in play.HOOKS.items() if n not in excluded},
        **{'connected_pickup_'+n:v for n,v in pickup.RANGES.items()},
        **{'connected_pickup_service_'+n:(v,v+8) for n,v in pickup.HOOKS.items() if n in ('pan','overlap','particle','sprite','lose_life')}}
    (output/'native-image.h').write_text((package/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=power.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    (output/'connected-runtime.c').write_text('#define POWER_CONNECTED 1\n#include "power-local-runtime.c"\n')
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','power-local-runtime.c':HERE/'runtime.c','frame-power.h':HERE/'frame-power.h',
        'pickup-runtime.h':pickup_package/'headers/pickup-runtime.h','pickup-state.h':pickup_package/'source/pickup-state.h',
        'play-runtime.h':frame/'headers/play-runtime.h'})
    revise_comparison_package(package=package,output=output/'package',adapter_files={'runtime.c':output/'connected-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files=includes,**bind_dependencies(consumers={'pickup-consumer':pickup_package,'frame-consumer':frame}),
        cases=[dict(id='frame-'+name,arguments=[str(30+i)]) for i,name in enumerate(['split','super','expand','soften','detonate','release','paused'])],
        assumptions=[(HERE/'BOUNDARY.md').read_text(),'Four actual frames collect an actual pickup and execute the corresponding powerup action over the same shared objects. Graphics, movement, overlap, rebound and other helpers are controlled and observed. The paused case preserves the pickup. No complete game startup is used.'],
        scope='Three-component frame/pickup/powerup network with actual collection, allocation, board mutation and cleanup over four frames per case.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','pickup_package','frame','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.pickup_package.resolve(),a.frame.resolve(),a.output.resolve())
