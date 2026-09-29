"""Reduce live pickup randomness to the original helper under either brick C."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
def prepare(package,output,unequal=False):
    output.mkdir(parents=True,exist_ok=False)
    text=(HERE/'pickup-runtime.c').read_text()
    if unequal:text='#define PICKUP_UNEQUAL_INPUT 1\n'+text
    (output/'runtime.c').write_text(text)
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes['brick-local-runtime.c']=HERE/'runtime.c'
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'runtime.c':output/'runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        cases=[dict(id=name,arguments=[str(100+i)]) for i,name in enumerate(['pickup-seed-1-fast','pickup-seed-2-fast','pickup-seed-1-slow','pickup-seed-2-slow'])],
        scope='Real native pickup helper and CRT random generator under original or lifted brick hit, without game startup; explicit seed inputs and observed effects.',
        assumptions=['The actual 0x406ef0 helper receives the retained collision coordinates (18,12), tile 14 and impact velocity (1,-2). Its native CRT generator is seeded with 1 or 2; seed 1 produces the pickup branch and seed 2 does not. Native allocations are backed by local initialized storage; particles, rendering and sound are observed services.',
            'The negative variant deliberately supplies the source a different seed to reproduce the missing-input class of the live discrepancy. Neither variant qualifies the unlifted pickup helper or full game.'])
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('package',type=Path);p.add_argument('output',type=Path);p.add_argument('--unequal',action='store_true')
    a=p.parse_args();prepare(a.package.resolve(),a.output.resolve(),a.unequal)
