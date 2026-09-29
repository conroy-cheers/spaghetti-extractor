"""Add the loader to the retained selection, preserving the enclosing comparison."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend

HERE=Path(__file__).resolve().parent

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+(package/'headers/native-image.h').read_text())
    headers.update({'native-image.h':output/'native-image.h','mds-loader-runtime.h':package/'headers/mds-loader-runtime.h',
        'mds-loader-state.h':package/'source/mds-loader-state.h','loader-transport.c':HERE/'loader-transport.c',
        'mds-parser-normal-runtime.c':HERE.parent/'dxball-mds-parser/normal-runtime.c'})
    backend=wine_test_backend()
    revise_comparison_package(package=game,output=output/'package',
        adapter_files={**backend['adapter_files'],'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':game/'adapters/bridge.c'},
        include_files={**headers,**backend['include_files']},program_entry_packages={'mds-loader':package},
        program_driver={**plan['program_driver'],'library':'dx-mds-loader-normal.dll'},
        scope='Normal game with loader, parser, event expander and the preceding 40 components; original stream lifecycle remains the consumer.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
