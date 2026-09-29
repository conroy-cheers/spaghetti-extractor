"""Select the editor through the real clear/save/close workload and native services."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.util import sha256_file

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('editor_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False)
    game_plan,_=load_comparison_package(game);local_plan,_=load_comparison_package(package)
    if game_plan['program_driver']['process'].get('mutable_files')!=['Default.bds']:
        raise ValueError('requires the prepared mutable-board save workload')
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    original=package/'runtime/DXBall.exe';header=(game/'headers/native-image.h').read_text()
    for name,(lo,hi) in preparation.RANGES.items():
        header+='\n'+native_entry_header(original=original,expected_sha256=sha256_file(original),module=None,
            entry_rva=lo,end_rva=hi,installer='install_editor_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h':output/'native-image.h','editor-runtime.h':package/'headers/editor-runtime.h',
        'editor-common.h':package/'headers/editor-common.h','editor-native.h':HERE/'editor-native.h',
        'board-normal-runtime.c':preparation.BOARDS/'normal-runtime.c'})
    # Explicitly review the controlled-to-live service handoff. Import the
    # existing live network; do not silently reuse its local-service assumptions.
    bindings=bind_dependencies(consumers={'menu-consumer':dict(id='menu-scene',package=game),'board-consumer':game})
    selected={row['id'] for row in bindings['dependencies']}
    bindings['dependencies'] += [dict(id=row['id'],package=game)
        for row in local_plan.get('dependencies',[]) if row['id'] not in selected]
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        remove_dependencies=[row['id'] for row in local_plan.get('dependencies',[])],**bindings,
        runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=game_plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-editor-normal.dll',
            symbol='dx_normal_anchor',process=game_plan['program_driver']['process']),
        scope='Normal DX-Ball editor clear/save/close using the C editor and the existing sixteen-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The local controlled menu/board consumers are explicitly replaced with the existing live network. Native CRT, region, cursor and board-rendering services remain selected. Full editor/board/menu/scene state is transported around synchronous services and reentry.',
            'The counted controller uses ordinary input and read-only checks. Default.bds is private mutable state. Up to 32 outer editor operations retain full current/saved boards, region records, input/scene state and surface/palette hashes. Internal C helper calls are not additional outer observations.',
            'The game-consumer scope and assumptions are retained in its dependency contract. The new editor C is selected here; local cases separately cover all seven entries and callbacks. This workload does not establish full gameplay, audio or platform portability.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
