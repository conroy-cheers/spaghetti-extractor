"""Select paddle movement and drawing in the existing normal game."""
import argparse
import importlib.util
from pathlib import Path
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('normal_paddles',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False)
    revise_comparison_package(package=game,output=output/'game',
        adapter_files={'normal-runtime.c':HERE.parent/'dxball-particles/normal-runtime.c','bridge.c':game/'adapters/bridge.c'})
    game=output/'game';plan,_=load_comparison_package(game)
    includes={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    includes.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=preparation.PE_SHA256,module=None,entry_rva=lo,end_rva=hi,
        installer='install_paddle_'+name) for name,(lo,hi) in preparation.RANGES.items()))
    includes.update({'native-image.h':output/'native-image.h','paddle-runtime.h':package/'headers/paddle-runtime.h',
        'particle-normal-runtime.c':HERE.parent/'dxball-particles/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        **bind_dependencies(consumers={'game-consumer':game}),runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-paddles-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal launch and sixty-four gameplay frames through paddle movement and drawing with the preceding twenty-five-component network.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Native cursor and DirectDraw calls remain real services. Existing lifted particle, pickup, brick, frame, motion, drawing and damage components remain selected. Shared paddle fields retain their existing owners.',
            'The preceding counted launch/close driver, random seed, paddle inputs and frame palette clock schedule are retained with their observations. Application pixels, palettes, state and output remain compared; the untouched control checks startup/output/exit without claiming uncontrolled random pixel equality.',
            'The wrapper transfers the existing native paddle clock/random scope to either implementation and retains its complete input observations. It retains 256 outer paddle records; other native heap and lifetime limits remain those of the preceding network.',
            'Resizing, rounding, clamping and callback changes are independently exercised locally and through a small frame consumer. This finite normal workload is not full gameplay coverage or strong qualification.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','game','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
