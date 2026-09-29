"""Revise frame/brick memory boundaries using retained inputs and public APIs."""
import argparse
import json
from pathlib import Path
import runpy
import time

from spaghetti_extractor.components.comparison_package import revise_comparison_package
from spaghetti_extractor.util import write_json

HERE=Path(__file__).resolve().parent
PLAY=HERE.parent/'dxball-gameplay'
FRAME=runpy.run_path(str(PLAY/'prepare.py'))
BRICK=runpy.run_path(str(HERE/'prepare.py'))
MEMORY_CASES=['event-saved-alias','event-pending-occupied','event-signed-neighbors',
    'event-wrapped-position','event-live-center-callback','event-expiry-callback']

def files(directory):
    return {p.relative_to(directory).as_posix():p for p in directory.rglob('*') if p.is_file()}

def incoming_reviews(package,identity,interface,catalog,assumptions,reviewed):
    plan=json.loads((package/'comparison-plan.json').read_text())
    unit=next(row for row in plan['dependencies'] if row['id']==identity)
    old=json.loads((package/unit['interface']).read_text())
    # Only these three contract inputs are revised here. Avoid re-reviewing an
    # unchanged contract when rerunning this recipe after an adapter-only edit.
    unchanged=(old['intent_sha256']==interface.intent_sha256 and
        unit['service_catalog']==catalog and unit['assumptions']==assumptions)
    return [] if unchanged else list(reviewed)

def frame_revision(package,output,scratch,*,nested=False,reviewed=()):
    leaf=package/'dependencies/gameplay-frame' if nested else package
    interface,catalog=FRAME['declarations']()
    sources=files(leaf/'source');sources['play.c']=PLAY/'play.c'
    headers=files(leaf/'headers');headers['play-runtime.h']=scratch/'play-runtime.h'
    adapters={'bridge.c':scratch/'play-bridge.c'}
    if not nested:adapters['runtime.c']=PLAY/'runtime.c'
    assumptions=[(PLAY/'BOUNDARY.md').read_text()]
    revise_comparison_package(package=package,output=output,
        **({'component_id':'gameplay-frame','reviewed_requirements':incoming_reviews(
            package,'gameplay-frame',interface,catalog,assumptions,reviewed)} if nested else {}),
        interface=interface,source_files=sources,adapter_files=adapters,include_files=headers,
        service_catalog=catalog,service_bridge=FRAME['bridge_spec'](),assumptions=assumptions)

def prepare(package,output,kind):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    (output/'play-bridge.c').write_text(FRAME['bridge']())
    (output/'play-runtime.h').write_text(FRAME['runtime_header']())
    (output/'brick-bridge.c').write_text(BRICK['bridge']())
    (output/'brick-runtime.h').write_text(BRICK['runtime_header']())
    if kind=='frame':
        frame_revision(package,output/'package',output)
    else:
        # These are manually reviewed call sites, not automatic compatibility
        # claims. Retained callers keep their argument/control flow; the runtime
        # now supplies the byte services using the same live memory owners.
        reviewed=['brick-actions/frame-consumer'] if kind=='connected' else ['ball-motion/game-consumer']
        frame_revision(package,output/'frame-selection',output,nested=True,reviewed=reviewed)
        selected=output/'frame-selection'
        leaf=selected if kind=='connected' else selected/'dependencies/brick-actions'
        interface,catalog=BRICK['declarations']()
        sources=files(leaf/'source');sources['brick.c']=HERE/'brick.c'
        headers=files(leaf/'headers');headers['brick-runtime.h']=output/'brick-runtime.h'
        adapters={'bridge.c':output/'brick-bridge.c'}
        extra={}
        if kind=='connected':
            if 'brick-local-runtime.c' not in headers:raise ValueError('requires retained connected brick inputs')
            headers.update({'brick-local-runtime.c':HERE/'runtime.c','connected.h':HERE/'connected.h',
                'play-runtime.h':output/'play-runtime.h'})
            adapters['runtime.c']=selected/'adapters/runtime.c'
            extra.update(cases=[dict(id='frame-'+n,arguments=[str(21+i)]) for i,n in enumerate(
                ['layered-brick','blast-chain','unbreakable','sparks'])]+[
                dict(id=n,arguments=[str(33+i)]) for i,n in enumerate(MEMORY_CASES)],
                scope='Actual frame, motion and brick bodies: four collision cases and six raw-coordinate event lifecycles, without game startup.')
        else:
            extra.update(component_id='brick-actions',reviewed_requirements=incoming_reviews(
                selected,'brick-actions',interface,catalog,[(HERE/'BOUNDARY.md').read_text()],['pickup-lifecycle/game-consumer']))
        revise_comparison_package(package=selected,output=output/('package' if kind=='connected' else 'brick-selection'),
            interface=interface,source_files=sources,adapter_files=adapters,include_files=headers,
            service_catalog=catalog,service_bridge=BRICK['bridge_spec'](),
            assumptions=[(HERE/'BOUNDARY.md').read_text()],**extra)
        if kind=='normal':
            selected=output/'brick-selection';headers=files(selected/'headers')
            if not {'play-normal-runtime.c','brick-normal-runtime.c'}<=headers.keys():
                raise ValueError('requires retained normal gameplay network')
            headers.update({'play-normal-runtime.c':PLAY/'normal-runtime.c','brick-normal-runtime.c':HERE/'normal-runtime.c',
                'play-runtime.h':output/'play-runtime.h','brick-runtime.h':output/'brick-runtime.h'})
            revise_comparison_package(package=selected,output=output/'package',include_files=headers)
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,kind=kind,
        retained_environment=str(package),original_source_consulted=False,tool_internal_changes=False))

def assemble(project,frame,brick,connected):
    runpy.run_path(str(PLAY/'assemble.py'))['assemble'](project,frame)
    runpy.run_path(str(HERE/'assemble.py'))['assemble'](project,brick,connected)
    providers=[('ball-motion','frame-motion.h'),('pickups','frame-pickups.h'),('particles','frame-particles.h'),
        ('paddle','frame-paddle.h'),('shots','frame-shots.h'),('explosions','frame-explosions.h'),
        ('powerups','frame-power.h'),('progression','frame-progress.h')]
    for folder,name in providers:
        target=project/'common'/name
        if target.is_file():
            text=(HERE.parent/('dxball-'+folder)/name).read_text()
            if target.read_text()!=text:target.write_text(text)
    stubs=project/'common/history-stubs.h'
    if stubs.is_file():
        text=runpy.run_path(str(HERE.parent/'dxball-warning/assemble.py'))['history_stubs']()
        if stubs.read_text()!=text:stubs.write_text(text)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('kind',choices=['frame','connected','normal'])
    p.add_argument('package',type=Path);p.add_argument('output',type=Path)
    a=sub.add_parser('assemble')
    for name in ('project','frame','brick','connected'):a.add_argument(name,type=Path)
    args=parser.parse_args()
    if args.command=='prepare':prepare(args.package.resolve(),args.output.resolve(),args.kind)
    else:assemble(args.project.resolve(),args.frame.resolve(),args.brick.resolve(),args.connected.resolve())
