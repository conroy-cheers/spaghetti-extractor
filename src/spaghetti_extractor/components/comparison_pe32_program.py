"""Prepare PE32 routine or program drivers for explicit experimental comparisons.

These helpers preserve section bytes; their distinct startup policies are explicit.
They are not the qualified native composer and grant no admission or proof authority.
"""
from pathlib import Path
import re
import struct

import pefile

from ..util import sha256_file, sha256_bytes, write_json


def prepare_routine_image(original: Path, output: Path) -> dict:
    """Make a PE32 EXE loadable as a DLL without executing its entry or TLS.

    The caller must establish the routine's initialization, ABI and live-state
    premises. Imports/relocations still use the normal Windows loader; retaining
    section bytes does not establish startup equivalence or valid heap contents.
    The returned diagnostic report can be bound as an original comparison input.
    """
    if original.resolve()==output.resolve():
        raise ValueError('routine image output must differ from the original')
    before=original.read_bytes();data=bytearray(before);pe=pefile.PE(data=before)
    if (pe.FILE_HEADER.Machine!=0x14c or pe.OPTIONAL_HEADER.Magic!=0x10b
            or pe.FILE_HEADER.Characteristics & 0x2000):
        raise ValueError('routine image requires an original PE32 executable')
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)<10 or pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:
        raise ValueError('routine image requires standard loader directories and no signature to invalidate')
    optional=pe.OPTIONAL_HEADER.get_file_offset()
    edits=[(pe.FILE_HEADER.get_file_offset()+18,'<H',(pe.FILE_HEADER.Characteristics|0x2000,),'load-as-DLL'),
        (optional+16,'<I',(0,),'omit-process-entry'),
        (optional+64,'<I',(0,),'unused-user-DLL-checksum'),
        (optional+96+9*8,'<II',(0,0),'omit-original-TLS-initialization')]
    changed=[]
    for offset,fmt,values,reason in edits:
        length=struct.calcsize(fmt);struct.pack_into(fmt,data,offset,*values)
        changed.append(dict(offset=offset,before=before[offset:offset+length].hex(),
            after=data[offset:offset+length].hex(),reason=reason))
    for section in pe.sections:
        lo,size=section.PointerToRawData,section.SizeOfRawData
        if before[lo:lo+size]!=data[lo:lo+size]:
            raise ValueError('routine image header changes overlap original section contents')
    output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(data)
    return dict(original_sha256=sha256_bytes(before),routine_image_sha256=sha256_file(output),
        edits=changed,sections_unchanged=True,startup_executed=False,tls_callbacks_executed=False,
        whole_program_equivalence=False)


def checked_program_driver(plan: dict):
    """Select an existing PE program as the comparison driver, with a built DLL."""
    driver = plan.get('program_driver')
    if driver is None:
        return None
    if (not isinstance(driver, dict) or set(driver)-{'process','entries'} != {'kind', 'image', 'library', 'symbol'}
            or driver['kind'] != 'pe32-import'
            or any(not isinstance(driver[k], str) for k in ('image', 'library', 'symbol'))):
        raise ValueError('program driver requires pe32-import, image, library and symbol')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.dll', driver['library']) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', driver['symbol']):
        raise ValueError('program driver needs simple DLL and export names')
    if driver['image'] not in plan['runtime_files'] or driver['image'] not in plan['original']['files']:
        raise ValueError('program driver image must be a bound original runtime input')
    if driver['library'].casefold() in {Path(p).name.casefold() for p in plan['runtime_files']}:
        raise ValueError('program driver library collides with a runtime input')
    if plan['tools']['runner'] is None:
        raise ValueError('PE32 program driver requires an explicit runner')
    from .comparison_composition import composition_entries
    composition_entries(plan)
    if 'process' in driver:
        process=driver['process']
        if not isinstance(process,dict) or not {'exit_codes'}<=set(process)<={'exit_codes','drive','mutable_files'}:
            raise ValueError('normal program comparison requires explicit accepted exit_codes')
        from .comparison_files import checked_mutable_files
        checked_mutable_files(driver, plan['runtime_files'])
        if 'drive' in process:
            if not isinstance(process['drive'],str) or not re.fullmatch(r'[D-Y]',process['drive']):
                raise ValueError('normal program drive must be one uppercase letter from D to Y')
            if plan['tools']['server'] is None:
                raise ValueError('normal program drive requires a managed Wine server and private prefix')
        codes=process['exit_codes']
        if (not isinstance(codes,list) or not codes or any(type(c) is not int or not 0<=c<=255 for c in codes)
                or len(set(codes))!=len(codes)):
            raise ValueError('normal program exit_codes must be unique runner exit statuses from 0 to 255')
        if plan.get('input_domain') is not None:
            raise ValueError('normal program comparisons use case arguments, not scalar fixture input domains')
        if any(Path(p).name.casefold()=='spaghetti-observation.json' for p in plan['runtime_files']):
            raise ValueError('program observation filename collides with a runtime input')
    return driver


def add_experimental_import(original: Path, library: Path, symbol: str, output: Path):
    name = library.name
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.dll', name) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', symbol):
        raise ValueError('experimental import needs simple DLL and export names')
    payload = pefile.PE(str(library))
    if payload.FILE_HEADER.Machine != 0x14c or not payload.FILE_HEADER.Characteristics & 0x2000:
        raise ValueError('experimental payload must be a PE32 DLL')
    if symbol.encode() not in [s.name for s in payload.DIRECTORY_ENTRY_EXPORT.symbols]:
        raise ValueError('experimental payload export is absent')
    before = original.read_bytes()
    pe = pefile.PE(data=before)
    if pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b or pe.FILE_HEADER.Characteristics & 0x2000:
        raise ValueError('requires an original PE32 program')
    if not pe.OPTIONAL_HEADER.AddressOfEntryPoint or pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:
        raise ValueError('requires an entry point and no signature to invalidate')
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].Size:
        raise ValueError('bound imports need an explicitly supported update')
    header = pe.sections[-1].get_file_offset() + 40
    if header + 40 > min(pe.OPTIONAL_HEADER.SizeOfHeaders, min(s.PointerToRawData for s in pe.sections if s.SizeOfRawData)):
        raise ValueError('no spare section-header space for the experimental import')
    if any(before[header:header+40]):
        raise ValueError('experimental section header would overwrite existing bytes')
    align = lambda value, size: (value + size - 1) // size * size
    rva = align(max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in pe.sections), pe.OPTIONAL_HEADER.SectionAlignment)
    body = bytearray()

    def append(value, alignment=1):
        body.extend(b'\0' * (align(len(body), alignment) - len(body)))
        result = rva + len(body)
        body.extend(value)
        return result

    imports = []
    for row in pe.DIRECTORY_ENTRY_IMPORT:
        if row.dll.decode().casefold() == name.casefold():
            raise ValueError('experimental import already exists')
        imports.append(row.struct.__pack__())
    dll_name = append(name.encode()+b'\0')
    hint_name = append(b'\0\0'+symbol.encode()+b'\0', 2)
    lookup = append(struct.pack('<II', hint_name, 0), 4)
    iat = append(struct.pack('<II', hint_name, 0), 4)
    imports += [struct.pack('<IIIII', lookup, 0, 0, dll_name, iat), bytes(20)]
    directory = append(b''.join(imports), 4)
    raw = align(len(before), pe.OPTIONAL_HEADER.FileAlignment)
    raw_size = align(len(body), pe.OPTIONAL_HEADER.FileAlignment)
    data = bytearray(before)
    allowed = set()

    def change(offset, fmt, *values):
        allowed.update(range(offset, offset+struct.calcsize(fmt)))
        struct.pack_into(fmt, data, offset, *values)

    change(header, '<8sIIIIIIHHI', b'.spxload', len(body), rva, raw_size, raw, 0, 0, 0, 0, 0xc0000040)
    change(pe.FILE_HEADER.get_file_offset()+2, '<H', len(pe.sections)+1)
    optional = pe.OPTIONAL_HEADER.get_file_offset()
    change(optional+8, '<I', pe.OPTIONAL_HEADER.SizeOfInitializedData+raw_size)
    change(optional+56, '<I', align(rva+len(body), pe.OPTIONAL_HEADER.SectionAlignment))
    change(optional+64, '<I', 0)
    change(optional+104, '<II', directory, len(imports)*20)
    data.extend(bytes(raw-len(data))+body+bytes(raw_size-len(body)))
    if any(i not in allowed for i in range(len(before)) if before[i] != data[i]):
        raise ValueError('unintended original byte change')
    after = pefile.PE(data=bytes(data))
    for section in pe.sections:
        start, size = section.PointerToRawData, section.SizeOfRawData
        if before[start:start+size] != data[start:start+size]:
            raise ValueError('original section bytes changed')
    if after.OPTIONAL_HEADER.AddressOfEntryPoint != pe.OPTIONAL_HEADER.AddressOfEntryPoint:
        raise ValueError('original entry point changed')
    for index in (5, 9):
        if after.OPTIONAL_HEADER.DATA_DIRECTORY[index].__pack__() != pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].__pack__():
            raise ValueError('original relocation/TLS directory changed')
    output.write_bytes(data)
    report = dict(original_sha256=sha256_file(original), library_sha256=sha256_file(library),
        executable_sha256=sha256_file(output), imported_library=name, imported_symbol=symbol,
        original_entry_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        original_tls_rva=pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress,
        original_sections_unchanged=True, original_entry_unchanged=True, original_tls_unchanged=True,
        authority='experimental-execution-only', strong_qualification=False)
    write_json(output.with_suffix('.preparation.json'), report)
    return report
