"""Load pinned Hello routines with the Windows loader, without process startup.

Only loader-header fields change. Every section and selected instruction stays
byte-identical on disk; Windows performs ordinary relocations/import resolution.
This is a native routine oracle under explicit initialization assumptions, not
untouched Hello startup or a deployable replacement binary.
"""
from pathlib import Path

import pefile

from spaghetti_extractor.util import sha256_file, sha256_bytes, write_json
from spaghetti_extractor.components.comparison_pe32_program import prepare_routine_image

ORIGINAL = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
OWNED = {'quote': [(0x4eb3, 0x5078), (0x14645, 0x1464a)],
         'growth': [(0x63ac, 0x6462)], 'release': [(0x1b34, 0x1ba0)]}


def prepare_image(original: Path, output: Path, *, include_cleanup=False, include_reallocate=False,
                  include_checked_allocation=False, include_terminal_failures=False, include_quote_engine=False,
                  include_multibyte=False, include_program=False):
    if include_terminal_failures and not include_checked_allocation:
        raise ValueError('terminal failure comparison requires the checked allocation family')
    if sha256_file(original) != ORIGINAL:
        raise ValueError('native quoting requires the pinned Hello PE32 executable')
    before = original.read_bytes()
    pe = pefile.PE(data=before)
    assert pe.FILE_HEADER.Machine == 0x14c and pe.OPTIONAL_HEADER.Magic == 0x10b
    assert pe.OPTIONAL_HEADER.SizeOfImage == 0x35000
    output.mkdir(parents=True, exist_ok=False)
    report=prepare_routine_image(original,output/'hello-routines.dll')
    declarations = []
    if include_program:
        declarations.extend(['#define HELLO_NATIVE_PROGRAM 1',
            f'#define HELLO_ORIGINAL_ENTRY {pe.OPTIONAL_HEADER.AddressOfEntryPoint}U',
            f'#define HELLO_ORIGINAL_TLS {pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress}U'])
    bodies = {}
    owned = {**OWNED, **({'cleanup': [(0x52f2, 0x5374)]} if include_cleanup else {}),
             **({'reallocate': [(0x8db8, 0x8e10)]} if include_reallocate else {})}
    if include_cleanup:
        declarations.append('#define HELLO_NATIVE_CLEANUP 1')
    if include_reallocate:
        declarations.append('#define HELLO_NATIVE_REALLOCATE 1')
    if include_quote_engine:
        declarations.append('#define HELLO_NATIVE_QUOTE_ENGINE 1')
        owned['quote_engine'] = [(0x36ea, 0x4eb3), (0x14640, 0x14645)]
    if include_multibyte:
        declarations.append('#define HELLO_NATIVE_MULTIBYTE 1')
        owned.update({'mb_decode32': [(0x6df3, 0x7211), (0x14658, 0x1465d)],
                      'mb_decode16': [(0x7214, 0x7315)], 'mb_initial': [(0x7318, 0x7331)],
                      'mb_reset': [(0x2b28, 0x2b35)]})
        for name, entry in [('mb_charset', 0x693c), ('mb_width', 0x141e0)]:
            declarations.append('static const unsigned char '+name+'_prefix[5] = {'+
                ','.join(hex(byte) for byte in pe.get_data(entry,5))+'};')
    if include_checked_allocation:
        declarations.append('#define HELLO_NATIVE_CHECKED_ALLOCATION 1')
        owned.update({name: [pair] for name, pair in {
            'checked_tail': (0x6220, 0x622d), 'checked_allocate': (0x622d, 0x6241),
            'checked_allocate_indexed': (0x6241, 0x6255), 'checked_resize': (0x6257, 0x6273),
            'checked_resize_indexed': (0x6273, 0x628f), 'checked_resize_array': (0x628f, 0x62b6),
            'checked_resize_array_indexed': (0x62b8, 0x62df), 'checked_allocate_zeroed': (0x6462, 0x6481),
            'checked_allocate_zeroed_indexed': (0x649c, 0x64bb), 'checked_failure': (0x658c, 0x6591),
            'checked_allocate_alias': (0x6255, 0x6257), 'checked_resize_array_alias': (0x62b6, 0x62b8),
        }.items()})
    if include_terminal_failures:
        declarations.append('#define HELLO_NATIVE_TERMINAL 1')
    for name, ranges in owned.items():
        bodies[name] = []
        for start, end in ranges:
            offset = pe.get_offset_from_rva(start)
            body = before[offset:offset+end-start]
            bodies[name].append(dict(start=start, end=end, sha256=sha256_bytes(body)))
        if name.endswith('_alias'):
            continue  # Two-byte entry branches are checked against their selected targets.
        prefix = pe.get_data(ranges[0][0], 5)
        declarations.append('static const unsigned char '+name+'_prefix[5] = {'+
            ','.join(hex(byte) for byte in prefix)+'};')
    (output/'native-image.h').write_text('\n'.join(declarations)+'\n')
    write_json(output/'image-preparation.json', dict(report,bodies=bodies))
    return output/'hello-routines.dll'
