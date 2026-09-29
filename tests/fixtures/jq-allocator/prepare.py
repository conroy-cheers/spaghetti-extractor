"""Prepare the allocator trial from a reviewed authoring workspace and PE inputs.

No pilot rebuild. Uses the existing comparison API and ordinary C adapters.
Run in the lifting environment with --authoring, --environment, --pthread-library,
and --output. Native checks must run under spaghetti-headless-wayland.
"""
import argparse
import json
from pathlib import Path
import runpy
import tempfile

from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package

ORIGINAL_SHA = '50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'
ENTRIES = [
    ('jv_nomem_handler', 'void', 'jv_nomem_handler_f,void *', 0x2d5ff, 0x2d680),
    ('jv_mem_alloc', 'void *', 'size_t', 0x2d680, 0x2d69c),
    ('jv_mem_alloc_unguarded', 'void *', 'size_t', 0x2d69c, 0x2d6a1),
    ('jv_mem_calloc', 'void *', 'size_t,size_t', 0x2d6a1, 0x2d6ec),
    ('jv_mem_calloc_unguarded', 'void *', 'size_t,size_t', 0x2d6ec, 0x2d724),
    ('jv_mem_strdup', 'char *', 'const char *', 0x2d724, 0x2d740),
    ('jv_mem_strdup_unguarded', 'char *', 'const char *', 0x2d740, 0x2d745),
    ('jv_mem_free', 'void', 'void *', 0x2d745, 0x2d74a),
    ('jv_mem_realloc', 'void *', 'void *,size_t', 0x2d74a, 0x2d770),
]


def prepare(authoring, environment, pthread_library, output):
    fixture=Path(__file__).resolve().parent
    env=native_environment(environment)
    env['link_files']['libwinpthread.dll.a']=pthread_library
    with tempfile.TemporaryDirectory(prefix='jq-allocator-inputs-') as temporary:
        generated=Path(temporary)
        headers={path.name:path for path in (authoring/'headers').iterdir()}
        headers.update(native_adapter_headers('pe32-entry-hook.h','pe32-import-hook.h'))
        headers['jq.h']=environment/'headers/jq.h'
        headers['allocation-observer.h']=fixture.parent/'jq-array-storage/allocation-observer.h'
        declarations=['#include "jv.h"', '#include <stddef.h>']
        hooks=[];install=[];intact=[]
        for name,result,parameters,start,end in ENTRIES:
            declarations += [f'{result} {prefix}{name}({parameters});' for prefix in ('','replacement_')]
            hooks.append(native_entry_header(original=environment/'runtime/libjq-1.dll',
                expected_sha256=ORIGINAL_SHA,module='libjq-1.dll',entry_rva=start,end_rva=end,
                additional_ranges=((0x2d440,0x2d5ff),) if name=='jv_nomem_handler' else (),
                installer='install_'+name))
            install.append(f'if(!install_{name}((void (*)(void))replacement_{name})) ExitProcess(86);')
            intact.append('install_'+name+'_intact()')
        hooks += ['static void install_allocator_entries(void) { '+' '.join(install)+' }',
            'static int allocator_entries_intact(void) { return '+' && '.join(intact)+'; }']
        (generated/'allocator-entries.h').write_text('\n'.join(declarations)+'\n')
        (generated/'native-entries.h').write_text('\n'.join(hooks)+'\n')
        (generated/'entry-observation.h').write_text('''#define ALLOCATOR_ENTRY(name) replacement_##name
void allocator_entry_observation(unsigned);
''')
        # Keep real allocation accounting and add observation after frees during
        # worker/process teardown. The executable's metadata allocator is unhooked.
        observer=(fixture.parent/'jq-array-storage/allocation-observer.c').read_text()
        assert observer.count('    original_free(p);')==1
        observer=observer.replace('    original_free(p);','    original_free(p);\n    allocator_observer_release();')
        backend='void allocator_observer_release(void);\n'+observer+'''
void *runtime_memory_malloc(size_t size) { return observed_malloc(size); }
void *runtime_memory_calloc(size_t count,size_t size) { return observed_calloc(count,size); }
void *runtime_memory_realloc(void *pointer,size_t size) { return observed_realloc(pointer,size); }
char *runtime_memory_strdup(const char *text) { return observed_strdup(text); }
void runtime_memory_free(void *pointer) { observed_free(pointer); }
'''
        (generated/'memory-backend.c').write_text(backend)
        headers.update({path.name:path for path in generated.glob('*.h')})
        prepare_comparison_package(**runpy.run_path(str(authoring/'prepare.py'))['source_inputs'](), **env,
            adapter_files={'driver.c':fixture/'driver.c','entry.c':fixture/'entry.c',
                'memory-backend.c':generated/'memory-backend.c'}, include_files=headers,
            original_files=['runtime/libjq-1.dll'], oracle_kind='native-original',
            cases=[dict(id=name,arguments=[name]) for name in ('contexts','threads')],
            observation_fields=['events'], assumptions=json.loads((authoring/'assumptions.json').read_text())+[
                'Hooks are installed before workers exist. One active thread at a time exercises callback sharing, TLS isolation, longjmp, allocation bytes and cleanup. This does not establish all concurrent interleavings.',
                'The parent observes the child through complete CRT and DLL teardown. Concrete allocation backend and original pthread library are shared. All nine old entries and private allocator state helpers are disabled on the source side.'],
            scope='jq shared allocator provider: two real jq contexts, thread-local callbacks, worker and process cleanup, and all nine runtime entries.',
            output=output)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('authoring','environment','pthread-library','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    prepare(args.authoring.resolve(),args.environment.resolve(),args.pthread_library.resolve(),args.output.resolve())
