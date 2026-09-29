"""Reduce gameplay drawing differences to a frame/helper consumer with fixed inputs."""
import argparse
from pathlib import Path
import struct

from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import revise_comparison_package
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent


def prepare(package,assets,output):
    output.mkdir(parents=True,exist_ok=False)
    data=assets.read_bytes(); count=struct.unpack_from('<I',data)[0]; offset=4; sprites=[]; variants=[]
    for slot in range(1,count+1):
        width,height,character,baseline=struct.unpack_from('<IIBI',data,offset)
        offset+=13+width*height
        sprites.append(f'    [{slot}]={{0,0,{width},{height},0,0,0,{width},{height},{character},{baseline}}},')
        if 128<=slot<=131:variants.append(dict(random=slot-128,slot=slot,width=width,height=height))
    if offset!=len(data):raise ValueError('sprite bank extent differs')
    (output/'paddle-sprites.h').write_text('static uint32_t paddle_sprites['+str(count+1)+'][11]={\n'+'\n'.join(sprites)+'\n};\n')
    (output/'connected-runtime.c').write_text('#define PLAY_CONNECTED_PADDLE 1\n#include "frame-runtime.c"\n')
    original=package/'runtime/DXBall.exe'
    (output/'native-image.h').write_text((package/'headers/native-image.h').read_text()+'\n'+native_entry_header(
        original=original,expected_sha256=sha256_file(original),module=None,entry_rva=0x1200,end_rva=0x1280,installer='install_paddle_mark'))
    includes={p.relative_to(package/'headers').as_posix():p for p in (package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','frame-runtime.c':HERE/'runtime.c',
        'paddle-runtime.h':HERE/'paddle-runtime.h','paddle-sprites.h':output/'paddle-sprites.h'})
    revise_comparison_package(package=package,output=output/'package',
        adapter_files={'runtime.c':output/'connected-runtime.c','bridge.c':package/'adapters/bridge.c'},include_files=includes,
        cases=[dict(id=f'paddle-random-{i}',arguments=[str(16+i)]) for i in range(4)],
        assumptions=[(HERE/'BOUNDARY.md').read_text(),
            'The draw-paddle service executes the actual native helper, with sprite dimensions from Mball2.sbk SHA256 '+sha256_file(assets)+'.',
            'Graphics calls are observed without DirectDraw or game startup. Both frames receive the same controlled clock and random values. All four random sprite selections are compared.'],
        scope='Native/lifted gameplay frame connected to actual native paddle drawing, with explicit clock, random and graphics inputs.')
    write_json(output/'inputs.json',dict(asset_sha256=sha256_file(assets),sprite_count=count,
        variants=variants))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','assets','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.package.resolve(),a.assets.resolve(),a.output.resolve())
