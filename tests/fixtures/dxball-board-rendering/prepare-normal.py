"""Select the renderer through the existing editor's real clear/save workload."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('render_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False)
    game_plan,_=load_comparison_package(game);local_plan,_=load_comparison_package(package)
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    original=package/'runtime/DXBall.exe';header=(game/'headers/native-image.h').read_text()
    for name,(lo,hi) in preparation.RANGES.items():
        header+='\n'+native_entry_header(original=original,expected_sha256=sha256_file(original),module=None,
            entry_rva=lo,end_rva=hi,installer='install_render_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h':output/'native-image.h','render-runtime.h':package/'headers/render-runtime.h',
        'editor-normal-runtime.c':HERE.parent/'dxball-board-editor/normal-runtime.c'})
    bindings=bind_dependencies(consumers={'menu-consumer':dict(id='menu-scene',package=game),'game-consumer':game})
    selected={row['id'] for row in bindings['dependencies']}
    bindings['dependencies'] += [dict(id=row['id'],package=game)
        for row in local_plan.get('dependencies',[]) if row['id'] not in selected]
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        remove_dependencies=[row['id'] for row in local_plan.get('dependencies',[])],**bindings,
        runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=game_plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-render-normal.dll',
            symbol='dx_normal_anchor',process=game_plan['program_driver']['process']),
        scope='Real editor clear/save/close using the C board renderer and existing seventeen-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The controlled menu consumer is explicitly replaced by the live menu/scene/font objects and existing native graphics/damage services. The same board/menu/scene backing is transported before and after synchronous calls.',
            'Retain up to 64 outer rendering operations with full current-board bytes, scene/mode and destination/back/palette hashes. Internal cell calls are ordinary C calls. The existing editor/board/save observations and controller remain unchanged.',
            'Local cases exercise gameplay scene values and callback changes separately. This editor workload does not establish full gameplay or portable graphics/audio backends.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
