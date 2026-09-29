"""Integrate sound bank control with the retained display/application network."""
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
        installer='install_audio_'+name) for name,(lo,hi) in AUTHOR['RANGES'].items()))
    headers.update({'native-image.h':output/'native-image.h','audio-runtime.h':package/'headers/audio-runtime.h',
        'audio-native.h':HERE/'audio-native.h','display-normal-runtime.c':HERE.parent/'dxball-display/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={**wine_test_backend()['adapter_files'],'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files={**headers,**wine_test_backend()['include_files']},
        **bind_dependencies(consumers={'display-consumer':game}),runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-audio-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal sound bank control with the preceding thirty-five-component display/application selection; all previous application observations retained.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The mixed backend retains actual DirectSound sample/device creation, Win32/DirectDraw and remaining runtime helpers. It is not a standalone portable game.',
            'Incoming sample records are live and names terminate within the supplied payload. Native sample loading must publish live records. Pointer maps do not independently establish that lifecycle premise; loader failure/dangling-slot paths require their own boundary work.',
            'The source backend requires successful GetStatus with complete output before status is consumed. Failed queries stop explicitly because original-caller restore history transport is not yet supplied. The zero placeholder is not claimed to equal original history. Original restore-entry instrumentation captures and restores actual history before its C wrapper.',
            'Local comparisons independently cover supplied history, unwritten outputs, callbacks and resource lifetime. Normal traces observe slot/sample/buffer relationships and saved names; unconsumed allocator padding is not a deterministic observation.',
            'The previous display backend still requires successful complete GetCaps output. Callbacks and the frame input schedule retain preceding assumptions and observations. No declared effect grants checked summaries or strong qualification.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
