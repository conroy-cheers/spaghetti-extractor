"""Compare builtins through real compilation and execution using retained inputs."""
from pathlib import Path
import argparse
import json
import runpy
import subprocess

import pefile
from cases import cases

from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def prepare(workspace, retained, output):
    here=Path(__file__).resolve().parent
    bindings=output.parent/'native-inputs';bindings.mkdir(exist_ok=True)
    rows=json.loads((here/'native-entries.json').read_text())
    # Reviewed builtin.c implementation span: private handlers and helpers are
    # trapped too, while the twelve entry prefixes remain available as hooks.
    ranges=sorted((row['entry_rva'],row['end_rva']) for row in rows)
    gaps=[];end=0x141d
    for first,last in ranges:
        if end<first:gaps.append((end,first))
        end=last
    header=''
    for row in rows:
        header += native_entry_header(original=retained/'runtime/libjq-1.dll',
            expected_sha256='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d',
            module='libjq-1.dll',entry_rva=row['entry_rva'],end_rva=row['end_rva'],
            installer='install_'+row['name'],
            additional_ranges=tuple(gaps) if row['name']=='builtins_bind' else ())
    header += 'static int install_entries(void) { return '+ ' && '.join(
        'install_'+row['name']+'((void (*)(void))spx_entry_'+row['name']+')' for row in rows)+'; }\n'
    header += 'static int entries_intact(void) { return '+ ' && '.join(
        'install_'+row['name']+'_intact()' for row in rows)+'; }\n'
    (bindings/'native-entry.h').write_text(header)
    environment=native_environment(retained)
    # Derive an ordinary linker import library from the retained runtime DLL.
    # Explicit DATA exports preserve imported encoding/syntax descriptor identity.
    image=pefile.PE(str(retained/'runtime/libonig-5.dll'))
    exports=[]
    for entry in image.DIRECTORY_ENTRY_EXPORT.symbols:
        if not entry.name:continue
        section=image.get_section_by_rva(entry.address)
        exports.append(entry.name.decode()+(' DATA' if not section.Characteristics & 0x20000000 else ''))
    image.close()
    definition=bindings/'onig.def';definition.write_text('LIBRARY libonig-5.dll\nEXPORTS\n'+'\n'.join(exports)+'\n')
    library=bindings/'libonig.dll.a'
    dlltool=environment['compiler'].with_name('i686-w64-mingw32-dlltool')
    subprocess.run([str(dlltool),'-d',str(definition),'-l',str(library)],check=True)
    environment['link_files']['libonig.dll.a']=library
    prepare_comparison_package(**runpy.run_path(str(workspace/'prepare.py'))['source_inputs'](),
        **environment,
        adapter_files={name:here/name for name in ('driver.c','entries.c','native-runtime.c')} | {
            'allocation-observer.c':here.parent/'jq-array-storage/allocation-observer.c'},
        include_files={**{p.name:p for p in (workspace/'headers').iterdir()},
            'entries.h':here/'entries.h','native-entry.h':bindings/'native-entry.h',
            'allocation-observer.h':here.parent/'jq-array-storage/allocation-observer.h',**native_adapter_headers()},
        original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
        cases=cases(),observation_fields=['contexts','allocation_lifetime'],
        assumptions=json.loads((workspace/'assumptions.json').read_text()),
        scope='Builtin registration, callback lifetime and value operations in two real jq compiler/interpreter contexts.',output=output)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('workspace','retained','output'):parser.add_argument(name,type=Path)
    args=parser.parse_args()
    prepare(args.workspace.resolve(),args.retained.resolve(),args.output.resolve())
