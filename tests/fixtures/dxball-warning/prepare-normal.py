"""Select warning entries and history adapters in the retained normal game network."""
import argparse
from pathlib import Path
import runpy
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    headers.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=AUTHOR['PE_SHA256'],module=None,entry_rva=lo,end_rva=hi,
        installer='install_warning_'+name) for name,(lo,hi) in AUTHOR['RANGES'].items()))
    headers.update({'native-image.h':output/'native-image.h','warning-runtime.h':package/'headers/warning-runtime.h',
        'history.h':HERE/'history.h','game-normal-runtime.c':HERE.parent/'dxball-game-scene/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=headers,
        **bind_dependencies(consumers={'game-consumer':game}),runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-warning-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal launch and sixty-four gameplay frames with warning entries and the preceding thirty-two-component selection; inspect entry counts for coverage.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The compatibility backend uses the reviewed WinMain/flow/gameplay call path and its native import values, with live descriptor bytes across describe/lock/unlock. Other native platform services and prior schedules remain.',
            'Original warning entry history is captured before the new C wrapper and transported explicitly into its native body. Preceding original-side wrappers retain their instrumented contexts; canonical caller-history evidence is the separate unwrapped native frame experiment.',
            'Warning observations retain shared coordinates, rectangle, deadline, frame count, bank and surface; prior game observations are retained. A passing inactive warning draw is not expired-warning coverage.',
            'Out-of-grid queued-event consumption and a standalone portable platform/address-space backend remain separate outstanding work. Concrete comparisons are not strong qualification.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
