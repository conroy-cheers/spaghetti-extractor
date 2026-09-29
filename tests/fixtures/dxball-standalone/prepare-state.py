"""Extract named initial data for the program owner; never export machine code."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile


PE_SHA256 = '191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
# Each mapping comes from the existing native boundary adapters. Other fields
# in the currently owned views are zero-initialized BSS or dynamic pointers.
WORDS = {
    'font.spacing': 0x4179f8,
    'title.palette_width': 0x417758,
    'title.palette_phase': 0x41775c,
    'damage.capability': 0x4179fc,
    'flow.first_frame': 0x417a00,
    'scene.presentation_mode': 0x417a04,
    'scene.no_hardware': 0x417a08,
    'runtime.random_seed': 0x417c74,
}


def prepare(image_path, output):
    digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
    if digest != PE_SHA256:
        raise ValueError('requires the pinned DX-Ball image')
    image = pefile.PE(str(image_path))
    mapped = image.get_memory_mapped_image()
    base = image.OPTIONAL_HEADER.ImageBase
    spans = []

    def data(address, size, field):
        section = image.get_section_by_rva(address - base)
        if section is None or section.Characteristics & 0x20000000:
            raise ValueError('initial data must come from a non-executable section')
        value = mapped[address-base:address-base+size]
        if len(value) != size:
            raise ValueError('initial data is outside the mapped image')
        spans.append(dict(field=field, address=f'{address:08x}', size=size,
                          sha256=hashlib.sha256(value).hexdigest()))
        return value

    message = mapped[0x4168b0-base:].split(b'\0', 1)[0]
    message = data(0x4168b0, len(message)+1, 'title.message')
    palette = struct.unpack('<66I', data(0x417650, 66*4, 'scene.palette_cycle'))
    stereo, = struct.unpack('<d', data(0x416068, 8, 'game.stereo_direction'))
    values = {field: struct.unpack('<I', data(address, 4, field))[0]
              for field, address in WORDS.items()}
    text = '/* Named data extracted from image SHA-256 ' + digest + '. */\n'
    text += 'static const unsigned char dxball_title_message[] = {\n'
    for offset in range(0, len(message), 20):
        text += '    ' + ','.join(str(v) for v in message[offset:offset+20]) + ',\n'
    text += '};\nstatic void dxball_seed_state(dxball_program *p) {\n'
    for field, value in values.items():
        text += f'    p->{field} = UINT32_C({value});\n'
    text += f'    p->game.stereo_direction = {stereo.hex()};\n'
    for i, value in enumerate(palette):
        text += f'    p->scene.palette_cycle[{i}] = UINT32_C({value});\n'
    text += '}\n'
    output.mkdir(parents=True, exist_ok=True)
    # Retain the pinned image's icon resources as ordinary Windows resource
    # data. Numeric types preserve the exact SDK-visible payloads in windres.
    resources = {}
    for kind in image.DIRECTORY_ENTRY_RESOURCE.entries:
        for name in kind.directory.entries:
            for language in name.directory.entries:
                key = (kind.id, name.id, language.id)
                if key in resources:
                    raise ValueError('duplicate Windows resource')
                resources[key] = language.data.struct
    expected = {(3, 1, 1033): 'icon-image.bin', (14, 101, 1033): 'icon-group.bin'}
    if resources.keys() != expected.keys():
        raise ValueError('review changed Windows resources before preparing the handoff')
    resource_text = '/* Original Windows resource payloads; no machine code. */\n'
    resource_text += 'LANGUAGE 9, 1\n'
    for key, name in expected.items():
        resource = resources[key]
        (output/name).write_bytes(data(base+resource.OffsetToData, resource.Size,
                                      'resource.'+'.'.join(map(str, key))))
        resource_text += f'{key[1]} {key[0]} "{name}"\n'
    (output/'windows-resources.rc').write_text(resource_text)
    (output/'program-seed.h').write_text(text)
    (output/'program-seed.json').write_text(json.dumps(dict(
        image_sha256=digest, spans=spans, words=values,
        scope='Named initial data only; no executable sections or runtime image dependency.'),
        indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.image, args.output)
