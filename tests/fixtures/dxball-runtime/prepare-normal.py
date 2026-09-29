"""Connect clock, wait and random bodies to the retained game."""
import argparse
from pathlib import Path
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+(package/'headers/native-image.h').read_text())
    headers.update({'native-image.h':output/'native-image.h','runtime-support.h':package/'headers/runtime-support.h',
        'runtime-state.h':package/'source/runtime-state.h','bootstrap-normal-runtime.c':HERE.parent/'dxball-bootstrap/normal-runtime.c',
        'mds-transport.c':HERE.parent/'dxball-mds-parser/mds-transport.c'})
    revise_comparison_package(package=game,output=output/'package',
        adapter_files={**{p.relative_to(game/'adapters').as_posix():p for p in (game/'adapters').rglob('*') if p.is_file()},
            'normal-runtime.c':HERE/'normal-runtime.c'},
        include_files=headers,program_entry_packages={'runtime-support':package},
        program_driver={**plan['program_driver'],'library':'dx-runtime-normal.dll'},
        scope='Normal game with actual clock/wait/random bodies replaced; existing scoped external clock inputs retained, real counter and vertical-blank services.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
