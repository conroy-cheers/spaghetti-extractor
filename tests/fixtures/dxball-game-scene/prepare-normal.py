"""Select gameplay scene in the existing normal-game comparison."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('normal_gameplay_scene',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False)
    revise_comparison_package(package=game,output=output/'game',
        adapter_files={'normal-runtime.c':HERE.parent/'dxball-round-cleanup/normal-runtime.c','bridge.c':game/'adapters/bridge.c'})
    game=output/'game';plan,_=load_comparison_package(game)
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=preparation.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,
        installer='install_game_'+name) for name,(lo,hi) in preparation.RANGES.items()))
    includes.update({'native-image.h':output/'native-image.h','game-runtime.h':package/'headers/game-runtime.h',
        'round-normal-runtime.c':HERE.parent/'dxball-round-cleanup/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'game-consumer':game}),runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-game-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal launch and sixty-four gameplay frames with gameplay scene and the preceding thirty-one-component network selected.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Platform services use the existing native transport. Board load, restart, score drawing and redraw dispatch reach the selected existing component bodies.',
            'Outer-call snapshots retain complete existing shared-list observations, board/palette bytes, scene fields and sprite bank metadata. The 32-call record and prior object-map limits apply.',
            'The preceding launch/close workload and input schedules remain. Inspect selected_game_scene for actual coverage; selection alone does not establish execution.',
            'Every semantic integration mismatch requires a retained local or connected reproduction; concrete comparisons are not strong qualification.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
