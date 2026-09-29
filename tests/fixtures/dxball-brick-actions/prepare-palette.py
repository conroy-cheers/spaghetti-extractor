"""Reduce palette timing to an actual frame/native-helper comparison."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
def prepare(frame,output,unequal=False):
    output.mkdir(parents=True,exist_ok=False)
    text=(HERE/'palette-runtime.c').read_text()
    if unequal:text='#define PALETTE_UNEQUAL_INPUT 1\n'+text
    (output/'runtime.c').write_text(text)
    includes={p.relative_to(frame/'headers').as_posix():p for p in (frame/'headers').rglob('*') if p.is_file()}
    includes['frame-local-runtime.c']=HERE.parent/'dxball-gameplay/runtime.c'
    revise_comparison_package(package=frame,output=output/'package',
        adapter_files={'runtime.c':output/'runtime.c','bridge.c':frame/'adapters/bridge.c'},include_files=includes,
        cases=[dict(id=name,arguments=[str(i)]) for i,name in enumerate(['paused-before-deadline','paused-at-deadline','running-before-deadline','running-at-deadline'])],
        assumptions=['The native/lifted frame invokes the actual native elapsed and palette-cycle helpers with equal explicit clock inputs. A local palette object observes SetEntries and complete palette storage, without DirectDraw or game startup. Other frame services retain their controlled local implementations.',
            'The negative variant supplies the source a clock one tick later, exposing the palette deadline difference independently of a whole-program workload.'],
        scope='Frame palette timing and native palette mutation at running/paused deadlines, without application startup.')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('frame',type=Path);p.add_argument('output',type=Path);p.add_argument('--unequal',action='store_true')
    a=p.parse_args();prepare(a.frame.resolve(),a.output.resolve(),a.unequal)
