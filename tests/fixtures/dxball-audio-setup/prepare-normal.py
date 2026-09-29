"""Install sound initialization into the retained sound-bank/game selection."""
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
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
        installer='install_setup_'+name) for name,(lo,hi) in AUTHOR['RANGES'].items()))
    headers.update({'native-image.h':output/'native-image.h','setup-runtime.h':package/'headers/setup-runtime.h',
        'audio-normal-runtime.c':HERE.parent/'dxball-audio/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={**wine_test_backend()['adapter_files'],'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files={**headers,**wine_test_backend()['include_files']},
        remove_dependencies=['audio-bank'],
        **bind_dependencies(consumers={'shared-bank':game}),runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-audio-setup-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal initialize/focus sound setup through the actual selected sound bank and preceding thirty-six-component application; previous observations retained.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'This mixed backend retains actual DirectSound, native WAV loading, Win32/DirectDraw and remaining runtime helpers. It is not a standalone portable game.',
            'Sample-loader outputs must be live records with terminated names; pointer maps do not establish lifetime. Failed native WAV loading and its dangling slots require separate lifting/transport work.',
            'The preceding sound-bank backend requires successful complete GetStatus output, and display requires successful complete GetCaps output. Original-caller historical inputs on failed queries remain open backend work.',
            'Local consumers independently cover failed creation, retries, dialogs, nonlocal termination, callbacks, release and refocus without sound hardware or game startup. Normal observations retain all preceding fields and add setup before/after bank state.',
            'Release and load services call the existing real entry boundaries. Shared owners are synchronized after native providers; declarations do not grant checked summaries or strong qualification.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
