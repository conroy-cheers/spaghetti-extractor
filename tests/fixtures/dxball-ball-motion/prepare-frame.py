"""Connect the existing frame to the ball-motion component without game startup."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('play_preparation',HERE.parent/'dxball-gameplay/prepare.py')
play=importlib.util.module_from_spec(spec);spec.loader.exec_module(play)

def prepare(package,frame,output):
    output.mkdir(parents=True,exist_ok=False)
    hooks={n:v for n,v in play.HOOKS.items() if n not in ('move_balls','random','stop_sound','play_sound','free_event')}
    entries={'frame_update':play.RANGES['update'],**{'frame_service_'+n:(v,v+8) for n,v in hooks.items()}}
    (output/'native-image.h').write_text((package/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=play.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    (output/'connected-runtime.c').write_text('#define MOTION_FRAME_CONSUMER 1\n#include "motion-local-runtime.c"\n')
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','motion-local-runtime.c':HERE/'runtime.c',
        'frame-motion.h':HERE/'frame-motion.h','play-runtime.h':frame/'headers/play-runtime.h'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'runtime.c':output/'connected-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'frame-consumer':frame}),
        cases=[dict(id='frame-'+name,arguments=[str(i)]) for i,name in [(1,'attached'),(2,'launch'),(3,'flight'),(7,'fallen-ball'),(12,'brick-up'),(19,'service-mutation')]],
        assumptions=[(HERE/'BOUNDARY.md').read_text(),'The original or lifted frame calls the original or lifted five-operation motion subsystem over identical shared C views. Two frames exercise each retained scenario; other frame helpers are controlled and their calls observed.'],
        scope='Two-frame connected gameplay/ball-motion consumer over shared objects, without application startup.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','frame','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.frame.resolve(),a.output.resolve())
