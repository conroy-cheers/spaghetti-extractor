"""Select damage tracking through the existing real editor workload."""
import argparse
import importlib.util
from pathlib import Path

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('damage_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False)
    game_plan,_=load_comparison_package(game);local_plan,_=load_comparison_package(package)
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    original=package/'runtime/DXBall.exe';header=(game/'headers/native-image.h').read_text()
    for name,(lo,hi) in preparation.RANGES.items():
        header+='\n'+native_entry_header(original=original,expected_sha256=preparation.PE_SHA256,module=None,
            entry_rva=lo,end_rva=hi,installer='install_damage_'+name)
    (output/'native-image.h').write_text(header)
    includes.update({'native-image.h':output/'native-image.h','damage-runtime.h':package/'headers/damage-runtime.h',
        'damage-native.h':HERE/'damage-native.h','damage-observation.h':HERE/'damage-observation.h',
        'render-normal-runtime.c':HERE.parent/'dxball-board-rendering/normal-runtime.c'})
    bindings=bind_dependencies(consumers={'scene-consumer':dict(id='title-scene',package=game),'game-consumer':game})
    selected={row['id'] for row in bindings['dependencies']}
    bindings['dependencies'] += [dict(id=row['id'],package=game)
        for row in local_plan.get('dependencies',[]) if row['id'] not in selected]
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        remove_dependencies=[row['id'] for row in local_plan.get('dependencies',[])],**bindings,
        runner=Path(game_plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=game_plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-damage-normal.dll',
            symbol='dx_normal_anchor',process=game_plan['program_driver']['process']),
        scope='Real editor clear/save/close selecting damage tracking and the existing eighteen-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The controlled scene consumer is explicitly replaced by live scene/font objects and actual graphics, clock, wait and recovery services. The same editor, board, scene and queue backing is transported around synchronous calls.',
            'Retain up to 2048 outer damage calls with input arguments, results, state, full queue/key hashes and surface identities. Reset/restore/present/flush also retain pixel hashes. Internal helper calls are ordinary C calls. Existing editor and saved-file observations remain.',
            'Absolute wall-clock tick values are retained as diagnostics, not compared as deterministic program output. Local cases exercise controlled clock wrap, retry, recovery, callback mutation and exact queue bytes independently of this workload.',
            'Quiescent eight-bit surface reads and bounded counted editor input are admitted. Complete gameplay and portable platform backends remain separate delivery work.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
