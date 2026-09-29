"""Use the real file-reader replacement in the preceding normal game selection."""
import argparse
from pathlib import Path
import runpy
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package,revise_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def prepare(package,game,output):
    output.mkdir(parents=True,exist_ok=False);plan,_=load_comparison_package(game)
    headers={p.relative_to(game/'headers').as_posix():p for p in (game/'headers').rglob('*') if p.is_file()}
    headers.update({p.name:p for p in (game/'source').glob('*.h')})
    (output/'native-image.h').write_text((game/'headers/native-image.h').read_text()+'\n'+native_entry_header(
        original=package/'runtime/DXBall.exe',expected_sha256=AUTHOR['PE_SHA256'],module=None,entry_rva=0xd9f0,end_rva=0xdb13,installer='install_file_reader'))
    headers.update({'native-image.h':output/'native-image.h','reader-runtime.h':package/'headers/reader-runtime.h',
        'wave-normal-runtime.c':HERE.parent/'dxball-wave/normal-runtime.c'})
    backend=wine_test_backend()
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={**backend['adapter_files'],'normal-runtime.c':HERE/'normal-runtime.c','bridge.c':package/'adapters/bridge.c'},
        include_files={**headers,**backend['include_files']},**bind_dependencies(consumers={'shared-game':game}),
        runner=Path(plan['tools']['runner']['path']),runtime_files={p.name:p for p in (game/'runtime').iterdir() if p.is_file()},cases=plan['cases'],
        observation_fields=['exit_code','stdout','stderr','state'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-reader-normal.dll',symbol='dx_normal_anchor',process=plan['program_driver']['process']),
        scope='Normal game execution with file reader, WAV loader and preceding component selection; shared candidate-neutral Win32 file and sound effects.',
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'Native allocation, Win32/DirectDraw/DirectSound, music and remaining application functions are retained. This is a mixed executable, not a standalone portable game.',
            'The WAV, bank and display boundaries of the preceding normal selection remain, including live typed records and complete successful GetStatus/GetCaps outputs.',
            'Normal native closes for resources acquired outside the observed file imports are forwarded and marked handle_known=0. Their identities/lifetimes are outside this file experiment; controlled local cases remain strict.',
            'Local cases cover file failure and partial reads independently. Normal execution supplies additional consumer evidence and preserves preceding observations.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('package','game','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.game.resolve(),a.output.resolve())
