"""Recover retained machine C for manually defined comparison boundaries.

This packages the existing extractor, normalizer and renderer. It neither chooses
component boundaries nor qualifies the resulting C as a native-original oracle.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import time

from ..pe32.image import parse_pe_image
from ..pe32.model import BlockSide, ParsedPEImage
from ..pe32.queries import executable_section_covering_range
from ..reconstruction.state_machine import normalize_spx_semantic_transfer
from ..static_program.model import StaticUnitContext
from ..static_program.semantics.transfer import semantic_transfers
from ..transfer.behavioral_c_layout import build_behavioral_c_plan
from ..transfer.behavioral_c_render import behavioral_c_header, behavioral_c_translation_units
from ..transfer.plan import compile_transfer_rows
from ..transfer.runtime_abi import exact_runtime_header
from ..util import sha256_file, write_json


def native_entry_header(*, original: Path, expected_sha256: str, module: str | None,
                        entry_rva: int, end_rva: int,
                        additional_ranges: tuple[tuple[int, int], ...] = (),
                        installer: str = 'spx_install_component_entry') -> str:
    """Generate fixture entry glue for an explicitly reviewed PE32 operation.

    Reads the expected prefix from the pinned PE32; emits ordinary C using the
    installed interception helper, caller-independent storage and a trap check.
    Additional disjoint ranges (for example cold fragments) are trapped too. The
    installer accepts an ABI-correct replacement; its _at variant also accepts a
    loaded image address. Its _intact companion checks all removed ranges later.
    Keep the original image in the comparison's original_files as usual.

    This does not find boundaries or infer complete ownership, signatures, memory
    transport or observations. Shared tails/alternate entries need explicit C
    wiring. Entry-prefix HIGHLOW relocations follow the loaded image base; other
    relocation kinds and relocations crossing the body boundary need manual C.
    """
    if (not isinstance(installer,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',installer)
            or module is not None and (not isinstance(module,str) or not module or not module.isascii()
                or any(ord(c)<32 or ord(c)==127 for c in module))):
        raise ValueError('native entry needs a C installer name and an ASCII module name or None for the main image')
    if (type(entry_rva) is not int or type(end_rva) is not int
            or not 0<=entry_rva<end_rva<=2**32 or end_rva-entry_rva<5):
        raise ValueError('native entry needs a reviewed half-open body range of at least five bytes')
    binary=parse_pe_image(original)
    if binary.sha256!=expected_sha256:
        raise ValueError('native entry requires the reviewed original image digest')
    if binary.bitness!=32 or int(binary.pe.FILE_HEADER.Machine)!=0x14c:
        raise ValueError('native entry interception requires an x86 PE32 image')
    if not isinstance(additional_ranges,(tuple,list)) or any(
            not isinstance(span,(tuple,list)) or len(span)!=2
            or any(type(value) is not int for value in span)
            or not 0<=span[0]<span[1]<=2**32 for span in additional_ranges):
        raise ValueError('native entry additional ranges must be reviewed half-open PE32 ranges')
    ranges=sorted([(entry_rva,end_rva),*(tuple(span) for span in additional_ranges)])
    if any(left[1]>right[0] for left,right in zip(ranges,ranges[1:])):
        raise ValueError('native entry body ranges overlap; shared ownership needs a manual C binding')
    for start,end in ranges:
        section=executable_section_covering_range(binary,start,end)
        if (section is None or end>section.rva_start+section.raw_size
                or len(binary.pe.get_data(start,end-start))!=end-start):
            raise ValueError('native entry body must lie within file-backed executable bytes')
    prefix_bytes,relocations=_native_entry_prefix(binary,entry_rva,end_rva)
    prefix=','.join(f'0x{b:02x}' for b in prefix_bytes)
    adjustments=''.join(f'''  {{
    uint32_t address=0x{value:08x}U+(uint32_t)(uintptr_t)image-0x{binary.image_base:08x}U;
    memcpy(prefix+{offset},&address,4);
  }}
''' for offset,value in relocations)
    fragments=sorted(tuple(span) for span in additional_ranges)
    trap_fragments=''.join(f'''  {{
    DWORD old,ignored;
    unsigned char *fragment=image+{start:#x};
    if (!VirtualProtect(fragment,{end-start},PAGE_EXECUTE_READWRITE,&old)) return 0;
    memset(fragment,0xcc,{end-start});
    if (!VirtualProtect(fragment,{end-start},old,&ignored) ||
        !FlushInstructionCache(GetCurrentProcess(),fragment,{end-start})) return 0;
  }}
''' for start,end in fragments)
    check_fragments=''.join(f'''  for (size_t i={start:#x};i<{end:#x};++i)
    if ({installer}_image[i]!=0xcc) return 0;
''' for start,end in fragments)
    description=', '.join(f'[{start:#x}, {end:#x})' for start,end in ranges)
    module_c='NULL' if module is None else json.dumps(module)
    return f'''/* Reviewed original {expected_sha256}; body {description}.
 * Generated comparison glue only; ownership, ABI and state remain operator inputs. */
#ifndef SPX_GENERATED_{installer}_H
#define SPX_GENERATED_{installer}_H
#include "pe32-entry-hook.h"
static spx_fixture_entry_hook {installer}_hook;
static unsigned char *{installer}_image;
static inline int {installer}_intact(void) {{
  const spx_fixture_entry_hook *hook=&{installer}_hook;
  if (!{installer}_image || !hook->entry || hook->entry[0]!=0xe9) return 0;
  for (size_t i=5;i<hook->length;++i) if (hook->entry[i]!=0xcc) return 0;
{check_fragments}  return 1;
}}
static inline int {installer}_at(unsigned char *image,void (*replacement)(void)) {{
  static unsigned char saved[{end_rva-entry_rva}];
  unsigned char prefix[{len(prefix_bytes)}]={{{prefix}}};
  if (!image || {installer}_hook.entry) return 0;
{adjustments}  if (memcmp(image+{entry_rva:#x},prefix,sizeof(prefix))) return 0;
  if (!spx_fixture_redirect_address_body_with_storage(&{installer}_hook,image+{entry_rva:#x},
      prefix,sizeof(saved),replacement,saved,sizeof(saved))) return 0;
{trap_fragments}  {installer}_image=image;
  return {installer}_intact();
}}
static inline int {installer}(void (*replacement)(void)) {{
  return {installer}_at((unsigned char *)GetModuleHandleA({module_c}),replacement);
}}
#endif
'''


def _native_entry_prefix(binary: ParsedPEImage, entry: int, end: int) -> tuple[bytes, list[tuple[int, int]]]:
    """Include whole relocated words, even when the five-byte jump splits one."""
    prefix_end=entry+5;selected=[]
    relocations=sorted((row for block in getattr(binary.pe,'DIRECTORY_ENTRY_BASERELOC',())
        for row in block.entries if row.type),key=lambda row:row.rva)
    for row in relocations:
        width={1:2,2:2,3:4,4:2}.get(row.type,8)
        if row.rva+width<=entry:continue
        if row.rva>=prefix_end:break
        if (row.type!=3 or row.rva<entry or row.rva+4>end
                or selected and selected[-1]+4>row.rva):
            raise ValueError('native entry prefix has an unsupported or overlapping relocation; use a reviewed manual C binding')
        selected.append(row.rva);prefix_end=max(prefix_end,row.rva+4)
    prefix=binary.pe.get_data(entry,prefix_end-entry)
    return prefix,[(rva-entry,int.from_bytes(prefix[rva-entry:rva-entry+4],'little')) for rva in selected]


def recover_original_c(*, original: Path, boundaries: dict[int, list[tuple[int, int]]],
                       expected_sha256: str, output: Path) -> dict:
    """Render explicitly selected PE32 instruction ranges using existing semantics.

    Map each entry RVA to its half-open block ranges. Ranges must not overlap;
    shared tails are listed once. Entries and ranges are operator inputs, not
    inferred complete operations. The caller supplies live machine state, memory,
    external-call handling and observations through the existing runtime ABI.

    The output contains C, runtime headers, semantic inputs and a source map in
    recovery.json. Timings are diagnostic: exclude them from comparison inputs.
    Unsupported instructions reject without publishing a partial C selection.
    """
    started=time.monotonic()
    if output.exists():raise ValueError('original C recovery output must not already exist')
    if sha256_file(original)!=expected_sha256:
        raise ValueError('original C recovery requires the reviewed original image digest')
    if not isinstance(boundaries,dict) or not boundaries:
        raise ValueError('original C recovery requires explicit entry RVAs and block ranges')
    spans=[];mappings=[]
    for entry,ranges in boundaries.items():
        if (type(entry) is not int or not 0<=entry<2**32
                or not isinstance(ranges,(list,tuple)) or not ranges):
            raise ValueError('original C recovery requires each PE32 entry and its block ranges')
        for span in ranges:
            if (not isinstance(span,(list,tuple)) or len(span)!=2
                    or any(type(value) is not int for value in span)
                    or not 0<=span[0]<span[1]<=2**32):
                raise ValueError('original C recovery requires half-open PE32 block ranges')
            start,end=span;spans.append((start,end))
            mappings.append(StaticUnitContext(f'block-{start:08x}',BlockSide(start,end),'code',
                {'function':f'function-{entry:08x}'}))
    spans.sort()
    if any(left[1]>right[0] for left,right in zip(spans,spans[1:])):
        raise ValueError('original C block ranges overlap; list shared tails once')
    if set(boundaries)-{start for start,_ in spans}:
        raise ValueError('original C entries must start selected blocks')
    binary=parse_pe_image(original)
    if binary.bitness!=32:
        raise ValueError('retained comparison C currently requires a PE32 image')
    timings={'preparation':time.monotonic()-started}
    phase=time.monotonic();rows=semantic_transfers(binary,mappings)
    timings['extraction']=time.monotonic()-phase
    phase=time.monotonic()
    normalized=[normalize_spx_semantic_transfer(row) for row in rows]
    transfers,blockers=compile_transfer_rows(normalized,collect_blockers=True)
    timings['lowering']=time.monotonic()-phase
    if blockers:
        details=[f"{row['span']['rva_start']:#x}: {row.get('blocker') or row.get('blocking_instruction')}"
                 for row in rows if row.get('status')=='incomplete']
        if not details:details=[str((row.get('code'),row.get('message'))) for row in blockers]
        raise ValueError('retained-C recovery blocked: '+'; '.join(details[:8])+
            '; review the selected ranges or use an executable native-original oracle')
    phase=time.monotonic()
    plan=build_behavioral_c_plan(transfers,entry_rvas=list(boundaries))
    files,source_map=behavioral_c_translation_units(transfers,plan)
    files['behavioral-c.h']=behavioral_c_header(plan)
    files['state-machine-runtime.h']=exact_runtime_header()
    timings['rendering']=time.monotonic()-phase
    output.mkdir(parents=True,exist_ok=False)
    for name,text in files.items():(output/name).write_text(text)
    write_json(output/'semantic-inputs.json',rows)
    report=dict(original_sha256=expected_sha256,
        boundaries={hex(entry):ranges for entry,ranges in sorted(boundaries.items())},
        source_map=source_map,files={name:sha256_file(output/name) for name in files},
        semantic_input_sha256=sha256_file(output/'semantic-inputs.json'),
        seconds=time.monotonic()-started,timings=timings,strong_qualification=False)
    write_json(output/'recovery.json',report)
    return report
