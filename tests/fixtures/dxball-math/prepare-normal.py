"""Connect numeric component bodies to the retained normal game consumer."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
HERE=Path(__file__).resolve().parent

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+(package/'headers/native-image.h').read_text())
    headers.update({'native-image.h':output/'native-image.h','math-runtime.h':package/'headers/math-runtime.h',
        'math-state.h':package/'source/math-state.h','runtime-normal-runtime.c':HERE.parent/'dxball-runtime/normal-runtime.c'})
    revise_comparison_package(package=game,output=output/'package',
        adapter_files={**{p.relative_to(game/'adapters').as_posix():p for p in (game/'adapters').rglob('*') if p.is_file()},
            'normal-runtime.c':HERE/'normal-runtime.c'},include_files=headers,program_entry_packages={'math-support':package},
        program_driver={**plan['program_driver'],'library':'dx-math-normal.dll'},
        scope='Normal game with numeric initializer, table readers, projections and pan selected as C; existing caller observations retained.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
