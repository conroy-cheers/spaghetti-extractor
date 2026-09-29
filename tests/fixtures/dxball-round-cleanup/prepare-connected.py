"""Connect actual round transitions to typed object disposal and restart."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package

HERE=Path(__file__).resolve().parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
rounds=module('connected_rounds',HERE/'prepare.py')
progress=module('connected_progress',HERE.parent/'dxball-progression/prepare.py')

def prepare(package,consumer,output):
    output.mkdir(parents=True,exist_ok=False)
    excluded={'clear_objects','fade','clear'}
    entries={**{'connected_progress_'+n:r for n,r in progress.RANGES.items()},
        **{'connected_service_'+n:(v,v+8) for n,v in progress.HOOKS.items() if n not in excluded}}
    (output/'native-image.h').write_text((package/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=rounds.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    (output/'connected-runtime.c').write_text('#define ROUND_CONNECTED 1\n#include "round-local-runtime.c"\n')
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','round-local-runtime.c':HERE/'runtime.c',
        'progress-consumer.h':HERE/'progress-consumer.h','connected-run.h':HERE/'connected-run.h',
        'progress-runtime.h':consumer/'headers/progress-runtime.h'})
    revise_comparison_package(package=package,output=output/'package',adapter_files={'runtime.c':output/'connected-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files=includes,**bind_dependencies(consumers={'progression-consumer':consumer}),
        cases=[dict(id='transition-'+name,arguments=[str(28+i)]) for i,name in enumerate(['restart-twice','score-scene','last-life','free-callback-changes-life'])],
        assumptions=[(HERE/'BOUNDARY.md').read_text(),'Actual progression advance/lose/restart operations call actual cleanup across all nine lists. Other progression services are controlled and observed. Ball creation resumes after disposal; cleanup callbacks may change the subsequent game-over decision. No game startup is used.'],
        scope='Connected progression/cleanup with complete live-list disposal, service ordering, current-ball creation and callback-driven transition decisions.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','consumer','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.consumer.resolve(),a.output.resolve())
