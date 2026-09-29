"""Bind the missing palette operations into their retained real scene consumers."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+(package/'headers/native-image.h').read_text())
    headers.update({'native-image.h':output/'native-image.h','palette-runtime.h':package/'headers/palette-runtime.h',
        'palette-state.h':package/'source/palette-state.h','mds-stream-normal-runtime.c':HERE.parent/'dxball-mds-stream/normal-runtime.c'})
    revise_comparison_package(package=game,output=output/'package',
        adapter_files={**{p.relative_to(game/'adapters').as_posix():p for p in (game/'adapters').rglob('*') if p.is_file()},
            'normal-runtime.c':HERE/'normal-runtime.c'},
        include_files=headers,program_entry_packages={'palette-effects':package},
        program_driver={**plan['program_driver'],'library':'dx-palette-normal.dll'},
        scope='Normal game with palette effects and the preceding connected C selection; actual DirectDraw and application wait services.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
