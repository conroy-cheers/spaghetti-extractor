"""Select MDS event expansion in the retained 40-component normal program."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend

HERE=Path(__file__).resolve().parent

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    headers.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+(package/'headers/native-image.h').read_text())
    headers.update({'native-image.h':output/'native-image.h','mds-events-runtime.h':package/'headers/mds-events-runtime.h',
        'mds-events-state.h':package/'source/mds-events-state.h',
        'music-normal-runtime.c':HERE.parent/'dxball-music/normal-runtime.c'})
    backend=wine_test_backend()
    revise_comparison_package(package=game,output=output/'package',
        adapter_files={**backend['adapter_files'],'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':game/'adapters/bridge.c'},
        include_files={**headers,**backend['include_files']},program_entry_packages={'mds-events':package},
        runner=Path(plan['tools']['runner']['path']),runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},
        cases=plan['cases'],observation_fields=['exit_code','stdout','stderr','state'],
        program_driver={**plan['program_driver'],'library':'dx-mds-events-normal.dll'},
        scope='Normal game with MDS event expansion and the preceding 40 components selected; native MDS parser is the real consumer.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
