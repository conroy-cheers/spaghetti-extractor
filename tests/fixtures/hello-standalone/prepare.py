"""Assemble conventional Hello sources from compared components and a pinned option backend."""
import argparse
import json
from pathlib import Path
import shutil
import tarfile
import time

from spaghetti_extractor.candidate.source_export import export_comparison_sources
from spaghetti_extractor.candidate.source_export_bindings import load_source_export
from spaghetti_extractor.candidate.source_assembly import assembly_binding, retain_assembly_binding, write_assembly_binding
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
TAR_SHA='0d5f60154382fee10b114a1c34e785d8b1f492073ae2d3a6f7b147687b366aa0'


def prepare(comparisons, upstream_tar, output, source_export=None):
    if sha256_file(upstream_tar)!=TAR_SHA: raise ValueError('requires the pinned Hello 2.12.3 source archive')
    if bool(comparisons)==(source_export is not None):
        raise ValueError('choose comparison inputs or a standalone source export')
    retained=load_source_export(source_export) if source_export is not None else None
    if retained is not None and retained['target_id']!='gnu-hello':
        raise ValueError('requires a GNU Hello source export')
    started=time.monotonic(); output.mkdir(parents=True,exist_ok=False)
    shutil.copyfile(HERE/'PROJECT.md',output/'README.md')
    if retained is None:
        export_comparison_sources(comparisons=comparisons,target_id='gnu-hello',output=output/'lifted')
    else:
        for name in [*retained['files'],'source-export.json']:
            destination=output/'lifted'/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source_export/name,destination)
    selection=load_source_export(output/'lifted')
    if 'stream-close' not in selection['components']:
        raise ValueError('standalone stream policy requires a matching stream-close comparison; see hello-stream-close/README.md')
    application=output/'application'; application.mkdir()
    diagnostics=output/'diagnostics';diagnostics.mkdir()
    for name in ('fault-portable.c','allocation-fault.mk'):
        shutil.copyfile(HERE/name,diagnostics/name)
    shutil.copyfile(HERE.parent/'native/allocation-fault.h',diagnostics/'allocation-fault.h')
    for name in ('application.c','entry.c','services.h','allocation.c','string.c','release.c','runtime.c','stream.c'):
        shutil.copyfile(HERE/name,application/name)
    # The same adapter declaration used by jq carries grouped Hello entries.
    conversion=assembly_binding(dict(entries={'hello_reset':['reset'],'hello_decode16':['decode16']},
        sources={'conversion.c':'conversion.c'},headers={},replacements=[],
        lifetime='Explicit caller state or application-owned implicit16/implicit32 state survives calls. '
                 'Service/context wrappers live for the synchronous call; charset storage has static lifetime.'),
        base=HERE,operations=selection['components']['multibyte-conversion']['operation_symbols'])
    write_assembly_binding(conversion,application)
    runtime=output/'backends/windows-1252'; runtime.mkdir(parents=True)
    for name in ('windows-1252.c','windows-1252.h','windows-argv.c','windows-argv.h','windows-1252-best-fit.h','stream-view.h'):
        shutil.copyfile(HERE.parent/'portable-runtime'/name,runtime/name)
    shutil.copyfile(HERE.parent/'portable-runtime/README.md',runtime/'README.md')
    backend=output/'backends/gnulib-options'; backend.mkdir()
    names=('getopt.c','getopt1.c','getopt_int.h','getopt-core.h','getopt-ext.h','getopt-pfx-core.h','getopt-pfx-ext.h')
    with tarfile.open(upstream_tar) as archive:
        for name in names:
            (backend/name).write_bytes(archive.extractfile('hello-2.12.3/lib/'+name).read())
        (output/'COPYING.hello').write_bytes(archive.extractfile('hello-2.12.3/COPYING').read())
        header=archive.extractfile('hello-2.12.3/lib/getopt.in.h').read().decode()
        for key,value in {'GUARD_PREFIX':'SPX','PRAGMA_SYSTEM_HEADER':'','PRAGMA_COLUMNS':'',
                          'HAVE_GETOPT_H':'0','INCLUDE_NEXT':'include','NEXT_GETOPT_H':'<getopt.h>'}.items():
            header=header.replace('@'+key+'@',value)
        header=header.replace('/* The definition of _GL_ARG_NONNULL is copied here.  */',
                              '#define _GL_ARG_NONNULL(args) /* annotation only */')
        (backend/'getopt.h').write_text(header)
        cdefs=archive.extractfile('hello-2.12.3/lib/getopt-cdefs.in.h').read().decode().replace('@HAVE_SYS_CDEFS_H@','0')
        (backend/'getopt-cdefs.h').write_text(cdefs)
    (backend/'config.h').write_text('#ifndef SPX_OPTIONS_CONFIG_H\n#define SPX_OPTIONS_CONFIG_H\n'
        '#include <stdbool.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
        '#include "windows-1252.h"\n#define __GETOPT_PREFIX spx_\n#define GNULIB_TEXT_DOMAIN "spx"\n'
        '#if defined __GNUC__\n#define _GL_UNUSED __attribute__((unused))\n#else\n#define _GL_UNUSED\n#endif\n'
        '#define fprintf spx_target_fprintf\n#endif\n')
    (backend/'gettext.h').write_text('#define dgettext(domain,message) ((void)(domain), (message))\n')
    rules=[]; objects=[]
    common='-Iapplication -Ibackends/windows-1252 -Ibackends/gnulib-options'
    for name,unit in [('allocation','checked-allocation'),('conversion','multibyte-conversion'),
                      ('string','string-conversion'),('release','preserve-errno-free'),('stream','stream-close'),('application',None),('runtime',None)]:
        obj='build/'+name+'.o'; objects.append(obj)
        includes=common
        if unit: includes+=' -Ilifted/components/'+unit+'/sources/generated -Ilifted/components/'+unit+'/sources/source -Ilifted/components/'+unit+'/sources/headers'
        rules.append(f'{obj}: application/{name}.c application/services.h\n\t@mkdir -p build\n'
                     f'\t$(CC) $(CPPFLAGS) $(CFLAGS) {includes} -MMD -MP -c $< -o $@\n')
    for name,path in [('console','backends/windows-1252/windows-1252.c'),('arguments','backends/windows-1252/windows-argv.c'),('getopt','backends/gnulib-options/getopt.c'),('getopt1','backends/gnulib-options/getopt1.c')]:
        obj='build/'+name+'.o'; objects.append(obj)
        rules.append(f'{obj}: {path}\n\t@mkdir -p build\n\t$(CC) $(CPPFLAGS) $(CFLAGS) {common} -MMD -MP -c $< -o $@\n')
    for profile,flag in [('target',''),('utf8','-DSPX_UTF8_ARGUMENTS=1')]:
        rules.append(f'build/entry-{profile}.o: application/entry.c application/services.h\n\t@mkdir -p build\n'
            f'\t$(CC) $(CPPFLAGS) $(CFLAGS) {common} {flag} -MMD -MP -c $< -o $@\n')
    (output/'Makefile').write_text('\n\n'.join(['CC ?= cc','AR ?= ar',
        'CFLAGS ?= -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror',
        'OBJECTS := '+' '.join(objects),'.PHONY: all clean lifted-library','all: hello hello-utf8',
        'lifted-library:\n\t$(MAKE) -C lifted CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)"',
        'hello: $(OBJECTS) build/entry-target.o lifted-library\n\t$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) build/entry-target.o lifted/liblifted.a $(LDLIBS) -o $@',
        'hello-utf8: $(OBJECTS) build/entry-utf8.o lifted-library\n\t$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) build/entry-utf8.o lifted/liblifted.a $(LDLIBS) -o $@',
        *rules,'-include $(OBJECTS:.o=.d) build/entry-target.d build/entry-utf8.d',
        'clean:\n\t$(MAKE) -C lifted clean\n\trm -rf build hello hello.exe hello-utf8','']))
    write_json(output/'standalone-project.json',dict(version=1,authority='diagnostic-source-provenance',
        assembly_bindings={'multibyte-conversion':retain_assembly_binding(conversion,'application')},
        source_export_sha256=sha256_file(output/'lifted/source-export.json'), upstream_tar_sha256=TAR_SHA,
        source_assistance='Hello application control; unchanged GNU getopt implementation from the pinned source archive',
        backend_scope='Windows-1252 narrow arguments, target-width words and redirected CRLF; experimental POSIX UTF-8 console text; other code pages and general terminal controls unsupported',
        entry_profiles={'target':'narrow target byte arguments', 'utf8':'valid UTF-8 arguments converted by the portable Windows-1252 best-fit entry adapter'},
        assumptions=['Single-threaded finite command-line strings below the signed target allocation frontier.',
                     'MSVCRT setlocale(LC_ALL, empty) selects the observed Windows English_United States.1252 locale; Unix LC_ALL does not select it.',
                     'The lower conversion backend covers initial single-byte Windows-1252 state; native startup internals are replaced by host startup.',
                     'UTF-8 terminal output starts at column zero with fixed width and one writer; nonprinting controls outside BEL/BS/TAB/CR/LF, resizing and other writers are outside the tested profile.',
                     'Shared object transport is live; target allocation tokens are mapped rather than cast to host pointers.'],
        files={p.relative_to(output).as_posix():sha256_file(p) for p in output.rglob('*') if p.is_file()},
        seconds=time.monotonic()-started,strong_qualification=False,validated=False,producer_sha256=sha256_file(Path(__file__))))
    print(output)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    inputs=parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--comparison',type=Path,action='append')
    inputs.add_argument('--source-export',type=Path,help='assemble from an exported library without comparison packages or native runtime tools')
    parser.add_argument('--upstream-tar',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    prepare([p.resolve() for p in args.comparison or []],args.upstream_tar.resolve(),args.output.resolve(),
            args.source_export.resolve() if args.source_export else None)
