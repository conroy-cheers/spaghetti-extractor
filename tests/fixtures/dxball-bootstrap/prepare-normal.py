"""Bind bootstrap into the retained application, score, board and scene network."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+(package/'headers/native-image.h').read_text())
    headers.update({'native-image.h':output/'native-image.h','bootstrap-runtime.h':package/'headers/bootstrap-runtime.h',
        'bootstrap-state.h':package/'source/bootstrap-state.h','palette-normal-runtime.c':HERE.parent/'dxball-palette/normal-runtime.c'})
    revise_comparison_package(package=game,output=output/'package',
        adapter_files={**{p.relative_to(game/'adapters').as_posix():p for p in (game/'adapters').rglob('*') if p.is_file()},
            'normal-runtime.c':HERE/'normal-runtime.c'},
        include_files=headers,program_entry_packages={'application-bootstrap':package},
        program_driver={**plan['program_driver'],'library':'dx-bootstrap-normal.dll'},
        scope='Normal game with bootstrap, palette creation and clear connected to preceding C selection; real DirectDraw resources and retained clock services.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
