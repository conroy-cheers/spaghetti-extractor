"""Connect actual frame and pickup consumers to paddle movement and drawing."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
play=module('connected_frame',HERE.parent/'dxball-gameplay/prepare.py')
pickup=module('connected_pickups',HERE.parent/'dxball-pickups/prepare.py')

def prepare(package,frame,pickups,output):
    output.mkdir(parents=True,exist_ok=False)
    excluded=('move_paddle','draw_paddle','move_pickups','draw_pickups','elapsed','now','random','sprite',
        'next_board','spawn_debris','stop_sound','play_sound','free_event')
    entries={'frame_update':play.RANGES['update'],
        **{'frame_service_'+n:(v,v+8) for n,v in play.HOOKS.items() if n not in excluded},
        **{'connected_pickup_'+n:r for n,r in pickup.RANGES.items()},
        **{'connected_pickup_service_'+n:(v,v+8) for n,v in pickup.HOOKS.items() if n not in ('move_paddle','random')}}
    (output/'native-image.h').write_text((package/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=play.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    (output/'connected-runtime.c').write_text('#define PADDLE_CONNECTED 1\n#include "paddle-local-runtime.c"\n')
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','paddle-local-runtime.c':HERE/'runtime.c',
        'frame-paddle.h':HERE/'frame-paddle.h','play-runtime.h':frame/'headers/play-runtime.h','pickup-runtime.h':pickups/'headers/pickup-runtime.h'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'runtime.c':output/'connected-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'frame-consumer':frame,'pickup-consumer':pickups}),
        cases=[dict(id='frame-'+n,arguments=[str(21+i)]) for i,n in enumerate(['grow','shrink','tiny','windowed'])],
        assumptions=[(HERE/'BOUNDARY.md').read_text(),'Eight frames use the actual frame, pickup and paddle components over the same shared views. Controlled overlap collects one real pickup and invokes paddle movement through resizing; other services are controlled and observed.'],
        scope='Three-component frame/pickup/paddle consumer over shared state, without application startup.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','frame','pickups','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.frame.resolve(),a.pickups.resolve(),a.output.resolve())
