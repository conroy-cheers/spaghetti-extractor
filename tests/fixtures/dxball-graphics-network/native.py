"""Prepare the graphics selection for public component checks against x86.

The original executable supplies its fixed-base image, not game startup. Existing
controlled services and observations remain the boundary. Preparation executes
neither side; edit/check/replay/reuse use the normal component commands.
"""
import argparse
from pathlib import Path
import tempfile
import time

import pefile

from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment
from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent
PE_SHA256 = '191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES = [(0xbc90, 0xbcbb), (0xbd60, 0xbd6a), (0xbd90, 0xbdcf), (0xcd5c, 0xd006)]
COMPONENTS = {'graphics-reset', 'graphics-bind', 'graphics-blit', 'graphics-initialize'}


def prepare(package, output):
    started = time.monotonic()
    plan, _ = load_comparison_package(package)
    if plan['target_id'] != 'dxball' or plan['component_id'] not in COMPONENTS:
        raise ValueError('requires a reviewed graphics-reset, graphics-bind, graphics-blit or graphics-initialize package')
    if plan.get('program_driver'):
        raise ValueError('this package already has a program driver; use component start/check directly')
    if '#ifndef DX_NATIVE_ORACLE' not in (package/'adapters/runtime.c').read_text():
        raise ValueError('prepare a current graphics package; retained adapters need the native-oracle seam')
    original = package/'runtime/DXBall.exe'
    if sha256_file(original) != PE_SHA256:
        raise ValueError('requires the reviewed DX-Ball original')
    pe = pefile.PE(str(original))
    if pe.OPTIONAL_HEADER.AddressOfEntryPoint != 0xeaa0 or pe.OPTIONAL_HEADER.ImageBase != 0x400000:
        raise ValueError('review changed native image boundaries')
    environment = native_environment()
    # Keep selected C/services/neighbors. Supply the new executable inputs through
    # the normal revision API; it owns hashes, composition and generated headers.
    row = lambda values: '{'+','.join(hex(v) for v in values)+'}'
    image_header=(
        'static const uint32_t native_ranges[4][2]={'+','.join(row((0x400000+a, b-a)) for a, b in RANGES)+'};\n'+
        'static const unsigned char native_prefixes[4][5]={'+','.join(row(pe.get_data(a, 5)) for a, _ in RANGES)+'};\n'+
        'static const unsigned char native_entry_prefix[5]='+row(pe.get_data(0xeaa0, 5))+';\n')
    with tempfile.TemporaryDirectory(prefix='dxball-native-inputs-') as temporary:
        image_path=Path(temporary)/'native-image.h';image_path.write_text(image_header)
        headers={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
        headers.update({'runtime.c':package/'adapters/runtime.c','native-image.h':image_path,
                        **native_adapter_headers('pe32-entry-hook.h','pe32-import-hook.h')})
        revise_comparison_package(package=package,output=output,
            adapter_files={'bridge.c':package/'adapters/bridge.c','driver.c':package/'adapters/driver.c',
                           'native-runtime.c':HERE/'native-runtime.c'},include_files=headers,
            **{**environment,'runtime_files':{'DXBall.exe':original,**environment['runtime_files']}},
            original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
            program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',
                                library='dx-components.dll',symbol='dx_graphics_anchor'),
            scope='DX-Ball original-x86 '+plan['component_id']+' versus selected C; redirected entry and controlled services, without game startup.',
            assumptions=[
                'Pinned fixed-base DX-Ball PE32; original execution calls the selected entries within bc90/bd60/bd90/cd5c; all four original bodies are trapped on the source side.',
                'An imported observer redirects process entry to the existing case driver; the adapter supplies the reviewed initializer frame. Normal game startup is not executed.',
                *plan['assumptions'][1:]])
    write_json(output/'native-preparation.json', dict(seconds=time.monotonic()-started,
        original_entry_redirected=True, game_startup=False, controlled_services=True,
        strong_qualification=False, whole_program_portable=False,
        producer_sha256=sha256_file(Path(__file__))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare'])
    parser.add_argument('package', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.package.resolve(), args.output.resolve())
