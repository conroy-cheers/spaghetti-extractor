"""Integrate complete display setup with the retained application shell/network."""
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
        installer='install_display_'+name) for name,(lo,hi) in AUTHOR['RANGES'].items()))
    headers.update({'native-image.h':output/'native-image.h','display-runtime.h':package/'headers/display-runtime.h',
        'display-native.h':HERE/'display-native.h','shell-normal-runtime.c':HERE.parent/'dxball-application/normal-runtime.c'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=headers,
        **bind_dependencies(consumers={'application-consumer':game}),runner=Path(plan['tools']['runner']['path']),
        runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-display-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal display setup with portable WinMain/window dispatch and the preceding thirty-four-component selection; prior application observations retained.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The native platform backend retains actual Win32/DirectDraw, sound and remaining runtime helpers; this is mixed execution, not a standalone portable game.',
            'The source backend requires GetCaps to return success and initialize both consumed output fields. It rejects failures explicitly because original-caller history transport is not yet supplied by this normal backend. Invocation-local placeholders are overwritten before component decisions; they are not asserted to be original historical values.',
            'Original entry history is captured before instrumentation and restored to the original body. Local comparisons independently cover supplied history, unwritten/partial capability outputs and failure paths on both architectures.',
            'The existing frame input driver counts outer call entry/return. Previous observations remain; display return, shared flags, surface aliases and table reset state are added. OS handle numbers and platform-generated message sequences are not deterministic observations.',
            'Callbacks execute through the actual selected application window procedure. Shared owners are synchronized through existing native adapters. No declaration alone grants checked summaries or strong qualification.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
