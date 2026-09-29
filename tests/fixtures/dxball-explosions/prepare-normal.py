"""Select explosion reset, creation and animation in the existing normal game."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('normal_explosions',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False)
    revise_comparison_package(package=game,output=output/'game',
        adapter_files={'normal-runtime.c':HERE.parent/'dxball-shots/normal-runtime.c','bridge.c':game/'adapters/bridge.c'})
    game=output/'game';plan,_=load_comparison_package(game)
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=preparation.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,
        installer='install_explosion_'+name) for name,(lo,hi) in preparation.RANGES.items()))
    includes.update({'native-image.h':output/'native-image.h','explosion-runtime.h':package/'headers/explosion-runtime.h',
        'shot-normal-runtime.c':HERE.parent/'dxball-shots/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'game-consumer':game}),runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-explosions-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal launch and sixty-four gameplay frames through explosion reset, creation and animation with the preceding twenty-seven-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Native allocation and termination remain real services. Sprite drawing reaches the lifted drawing/damage network. Existing lifted frame, motion, shot, paddle, pickup and particle components remain selected.',
            'The normal adapter maps concrete explosion records to the preceding opaque effect identities at each boundary, preserving the same native current/first slots. Reachable payloads and links are transported, not just pointer addresses.',
            'The preceding counted launch/close driver, random seed, paddle inputs and palette-clock schedule are retained. Application pixels, palettes, state and output remain compared; the untouched control checks startup/output/exit without claiming uncontrolled random pixel equality.',
            'Normal observations retain 512 outer explosion calls and 64 encountered addresses. Inspect selected_explosions for actual entry coverage; empty-list animation is not evidence of creation or allocator coverage.',
            'Independent direct and three-component consumers cover creation, expiry, callbacks and the frame level-advance decision. This finite normal workload is not full gameplay coverage or strong qualification.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
