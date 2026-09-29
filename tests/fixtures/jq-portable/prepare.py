"""Export the compared jq subsystem and bind it into a pinned portable source backend."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

from binding_guides import write_binding_guides

from spaghetti_extractor.candidate.source_assembly import (assembly_binding, retain_assembly_binding, write_assembly_binding, definition_span)
from spaghetti_extractor.candidate.source_replacements import retire_definition
from spaghetti_extractor.candidate.source_export import export_comparison_sources
from spaghetti_extractor.candidate.source_export_bindings import load_source_export, render_source_service_bridges
from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
TAR_SHA='2be64e7129cecb11d5906290eba10af694fb9e3e7f9fc208a311dc33ca837eb0'
ORIGINAL_SHA='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'
PATCHES={
    'musl.patch':'a1af0592974bc04e8f70a66d9832724058d00434b71ac1fbb2eef2d79d51824a',
    'CVE-2026-32316.patch':'df75992772a5c3bc301f3ebcca1ff8a8f595f15e0c15fab3051df7da986d898e',
    'CVE-2026-33947.patch':'120cd1d9368f9ef2a5dc141ebd6118b006d6f6e2a0627d72fe345efc8c38e98e',
    'CVE-2026-33948.patch':'8d78a5c37b63b23bb52a533206b968e4268aad1cf7f0e3478084c3b1b4e3b44c',
    'CVE-2026-39979.patch':'8c1edf6e5967bdffbecd18a2624da3c6e0e41bd7e764eeda713f8631a424fcc8',
    'CVE-2026-40164.patch':'4a0aed9bfd3dd28f9e06bcc4d6f8f754890ff96fb957026762c30233fae7d04f',
    'disable-end-of-epoch-conversion-test.patch':'bbddcd314cad147649ad86f4bb3d97ce085ed9e29413f80064038d7e9f8ee7f0',
}
ENTRIES={'path-get':'jv_getpath','path-set':'jv_setpath','value-get':'jv_get',
         'value-set':'jv_set','string-slice':'jv_string_slice'}
# Defaults for the original handoff. New entries use --bindings, not recipe edits.
EXTRA_BINDINGS={
    'string-length':dict(native_symbol='jv_string_length_codepoints',backend_file='src/jv.c',headers={}),
    'string-byte-length':dict(native_symbol='jv_string_length_bytes',backend_file='src/jv.c',headers={}),
    'string-indexes':dict(native_symbol='jv_string_indexes',backend_file='src/jv.c',headers={
        'indexes-native.h':HERE.parent/'jq-string-indexes/indexes-native.h'}),
}
REMOVED={
    'jv.c':['jv_copy','jv_array_sized','jv_array_length','jv_array_get','jv_array_set','jv_array_slice','jv_string_slice'],
    'jv_aux.c':['jv_get','jv_set','jv_getpath','jv_setpath'],
}


def source_bindings(path=None, *, project=None, previous=None):
    """Resolve reviewed recipe inputs; retain headers in the ordinary project."""
    choices={**{name:dict(native_symbol=symbol) for name,symbol in ENTRIES.items()},
             **copy.deepcopy(EXTRA_BINDINGS)}
    choices['value-get']['service_symbols']={'string_slice':'jv_string_slice'}
    layers=[]
    if previous and 'source_bindings' in previous:
        layers.append((previous['source_bindings'],project))
    if path is not None:
        path=path.resolve();layers.append((json.loads(path.read_text()),path.parent))
    for declarations,base in layers:
        if not isinstance(declarations,dict):raise ValueError('bindings must map component names to reviewed choices')
        for identity,spec in declarations.items():
            if (not isinstance(identity,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]*',identity)
                    or not isinstance(spec,dict) or not spec or spec.keys()-{'native_symbol','backend_symbol','backend_file','headers','backend_headers','service_symbols','assembly','service_bridge'}):
                raise ValueError('invalid source binding declaration: '+str(identity))
            spec=copy.deepcopy(spec)
            for field in ('native_symbol','backend_symbol'):
                if field in spec and (not isinstance(spec[field],str)
                        or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',spec[field])):
                    raise ValueError('binding needs a C entry symbol: '+identity+'/'+field)
            if 'backend_file' in spec and (not isinstance(spec['backend_file'],str)
                    or not re.fullmatch(r'src/[A-Za-z0-9_-]+\.c',spec['backend_file'])):
                raise ValueError('binding backend_file must name src/FILE.c: '+identity)
            for field in ('headers','service_symbols'):
                if field not in spec:continue
                if not isinstance(spec[field],dict) or any(not isinstance(k,str) or not isinstance(v,str) or not v
                        for k,v in spec[field].items()):
                    raise ValueError('binding '+field+' must be a string mapping: '+identity)
            if 'headers' in spec:
                spec['headers']=binding_headers(spec['headers'],base,identity)
            if 'backend_headers' in spec:
                if not isinstance(spec['backend_headers'],dict) or any(
                        not isinstance(name,str) or not re.fullmatch(r'src/[A-Za-z0-9_-]+\.c',name)
                        for name in spec['backend_headers']):
                    raise ValueError('backend_headers must map src/FILE.c to reviewed headers: '+identity)
                spec['backend_headers']={name:binding_headers(headers,base,identity+'/'+name)
                    for name,headers in spec['backend_headers'].items()}
            if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',v) for v in spec.get('service_symbols',{}).values()):
                raise ValueError('service_symbols must name reviewed C adapters: '+identity)
            if 'assembly' in spec:
                spec['assembly']=assembly_binding(spec['assembly'],base=base)
            prior=choices.get(identity,{})
            # Selecting an explicit native entry returns to the generated bridge
            # mode; an old grouped adapter must not silently remain selected.
            if 'assembly' not in spec and 'native_symbol' in spec:
                prior={key:value for key,value in prior.items() if key!='assembly'}
            if 'service_symbols' in spec:
                spec['service_symbols']={**prior.get('service_symbols',{}),**spec['service_symbols']}
            choices[identity]={**prior,**spec}
    return choices


def retained_bindings(choices,components):
    return {identity:{**spec,**({'assembly':retain_assembly_binding(spec['assembly'],'bindings/'+identity)} if 'assembly' in spec else {}),'headers':{name:'bindings/'+name for name in spec.get('headers',{})},
                **({'backend_headers':{filename:{name:'backends/jq/'+Path(filename).with_name(name).as_posix() for name in headers}
                    for filename,headers in spec['backend_headers'].items()}} if 'backend_headers' in spec else {})}
            for identity,spec in choices.items() if identity in components}


def binding_headers(headers,base,identity):
    if not isinstance(headers,dict) or any(not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_-]+\.h',name)
            or not isinstance(path,str) or not path for name,path in headers.items()):
        raise ValueError('binding headers need plain .h filenames and explicit C paths: '+identity)
    return {name:(base/path).resolve() for name,path in headers.items()}


def backend_header_inputs(choices,components):
    """Collect explicit same-translation-unit adapters; share exact header bytes."""
    inputs={};destinations={}
    for identity in sorted(components):
        for filename,headers in choices.get(identity,{}).get('backend_headers',{}).items():
            for name,path in headers.items():
                if not path.is_file():
                    raise ValueError(f'backend binding {identity} requires header {name}: {path}')
                destination=Path(filename).with_name(name).as_posix();digest=sha256_file(path)
                if destination in destinations and destinations[destination]!=digest:
                    raise ValueError('backend binding headers disagree: '+destination)
                destinations[destination]=digest
                inputs.setdefault(filename,{})[name]=path
    return inputs


def write_backend_headers(output,choices,components,*,existing=None,previous=None):
    """Retain adapter C beside its backend TU, using the existing refresh proposal.

    Includes follow private backend definitions, so explicit C can expose services
    sharing that translation unit's state. No functions or semantics are inferred.
    A prior managed block must match its recorded declarations before replacement.
    Other backend text stays intact; return exact existing-file inputs for refresh
    to distinguish these surgical edits from replacement binding/build files.
    """
    existing=output if existing is None else existing
    selected=backend_header_inputs(choices,components)
    old={}
    for spec in (previous or {}).values():
        for filename,headers in spec.get('backend_headers',{}).items():
            if headers:old.setdefault(filename,set()).update(headers)
    opening='\n/* BEGIN lifted backend adapters */\n';closing='/* END lifted backend adapters */\n'
    def block(names):
        return opening+''.join('#include "'+name+'"\n' for name in sorted(names))+closing if names else ''
    replacements={};copies={};existing_inputs={}
    old_paths={Path(filename).with_name(name).as_posix() for filename,names in old.items() for name in names}
    for filename in sorted(selected.keys()|old.keys()):
        relative='backends/jq/'+filename
        path=output/relative
        origin=path if path.exists() else existing/relative
        data=origin.read_bytes();source=data.decode('utf-8')
        if origin==existing/relative:
            existing_inputs[relative]=hashlib.sha256(data).hexdigest()
        previous_block=block(old.get(filename,()))
        if previous_block:
            if source.count(previous_block)!=1:
                raise ValueError('backend adapter includes changed; reconcile the recorded block: '+relative)
            source=source.replace(previous_block,'',1)
        if opening in source or closing in source:
            raise ValueError('unrecorded backend adapter include block: '+relative)
        next_block=block(selected.get(filename,{}))
        replacements[relative]=source+('' if not next_block or source.endswith('\n') else '\n')+next_block
        for name,origin in selected.get(filename,{}).items():
            destination=Path(filename).with_name(name).as_posix();current=existing/'backends/jq'/destination
            if current.exists() and destination not in old_paths and sha256_file(current)!=sha256_file(origin):
                raise ValueError('backend adapter header collides with an existing file: '+destination)
            copies['backends/jq/'+destination]=origin
    for name,source in replacements.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source)
    for name,origin in copies.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        if path.resolve()!=origin.resolve():shutil.copyfile(origin,path)
    return existing_inputs


def function_span(source, name):
    """Locate one reviewed pinned C definition, skipping quoted/comment braces."""
    return definition_span(source, name)


def replaced_function(source, name):
    """Remove a reviewed body, retaining a declaration for formerly private callers.

    The operator supplies an ordinary C backend wrapper when its native signature
    differs from the component entry. This only makes that definition external;
    it neither generates ABI conversion nor infers compatible implementations.
    """
    source,record=retire_definition(source,name)
    return source,record['body']


def replacement_definitions(spec):
    if 'assembly' in spec:return spec['assembly']['replacements']
    if 'backend_file' not in spec:return []
    return [dict(file=spec['backend_file'],symbol=spec.get('backend_symbol',spec['native_symbol']))]


def replace_backend_operations(backend,extra):
    removed={}
    operations={'src/'+filename:list(names) for filename,names in REMOVED.items()}
    for spec in extra.values():
        for row in replacement_definitions(spec):
            operations.setdefault(row['file'],[]).append(row['symbol'])
    for filename,names in operations.items():
        path=backend/filename; source=path.read_text()
        for name in sorted(set(names)):
            source,record=retire_definition(source,name)
            removed[filename+':'+name]=dict(record,file=filename)
        if filename=='src/jv.c':
            start,end=function_span(source,'jv_free'); body=source[start:end]
            removed[filename+':jv_free']=dict(file=filename,symbol='jv_free',body_sha256=hashlib.sha256(body.encode()).hexdigest(),
                retained='non-array dispatch only, renamed backend_free; nested releases use selected jv_free')
            old='    case JV_KIND_ARRAY:\n      jvp_array_free(j);\n      break;'
            if body.count(old)!=1: raise ValueError('pinned foreign destructor dispatch changed')
            body=body.replace('void jv_free(', 'void backend_free(',1).replace(old,
                '    case JV_KIND_ARRAY:\n      abort(); /* forbidden backend crossing */')
            source=source[:start]+body+source[end:]
        path.write_text(source)
    return removed


def bind_import_identity(backend):
    changes={}
    for name,old,new in [
        ('main.c','jq_set_input_cb(jq, jq_util_input_next_input_cb, input_state);',
         'jq_set_input_cb(jq, spx_imported_input_callback, input_state);'),
        ('util.c','  assert(cb == jq_util_input_next_input_cb);',
         '  if (cb != jq_util_input_next_input_cb) spx_input_callback_assertion();')]:
        path=backend/'src'/name;source=path.read_text()
        if source.count(old)!=1:raise ValueError('pinned CLI callback boundary changed: '+name)
        changes[name]=dict(before_sha256=sha256_file(path),old=old,new=new)
        path.write_text('#include "import-runtime.h"\n'+source.replace(old,new))
    shutil.copyfile(HERE/'import-runtime.h',backend/'src/import-runtime.h')
    return changes


def checked_export(library,choices):
    """Check the selection supported by this reviewed portable backend recipe."""
    export=load_source_export(library)
    if export['target_id']!='jq' or any(row.get('original',{}).get('kind')!='native-original' or
            row.get('original',{}).get('files',{}).get('runtime/libjq-1.dll')!=ORIGINAL_SHA for row in export['comparisons']):
        raise ValueError('source export must retain the pinned jq original identities; re-export with current tooling')
    expected=set(ENTRIES)|{'storage-'+s for s in ('copy','release','create','length','get','set','slice')}
    extra_ids=export['components'].keys()-expected
    if expected-export['components'].keys():
        raise ValueError('requires the connected storage/path/string selection')
    for identity in sorted(extra_ids):
        if 'assembly' not in choices.get(identity,{}) and not {'native_symbol','backend_file'}<=choices.get(identity,{}).keys():
            raise ValueError('missing reviewed backend binding for '+identity+'; pass --bindings FILE (see jq-portable/README.md)')
    backend_header_inputs(choices,export['components'])
    headers={}
    for identity in sorted(export['components'].keys() & choices.keys()):
        spec=choices[identity]
        if identity in ENTRIES and spec.get('native_symbol')!=ENTRIES[identity]:
            raise ValueError('base entry needs a separate assembly: '+identity)
        for name,path in spec.get('headers',{}).items():
            if not path.is_file():
                raise ValueError(f'source backend binding {identity} requires header {name}: {path}; '
                                 'supply its reviewed C file before assembly')
            digest=sha256_file(path)
            if name in headers and headers[name]!=digest:raise ValueError('binding headers disagree: '+name)
            headers[name]=digest
    shared_layout={}
    for name in ('value-layout.h','native-storage.h'):
        hashes={sha256_file(p) for identity in expected if identity.startswith('storage-')
            for p in (library/'components'/identity/'sources').rglob(name)}
        if len(hashes)!=1:raise ValueError('storage components disagree on shared representation: '+name)
        shared_layout[name]=hashes.pop()
    return export,extra_ids,shared_layout


def prepare(comparison, upstream_tar, patches, output, extra_comparisons=(), source_export=None, bindings_file=None):
    started=time.monotonic()
    choices=source_bindings(bindings_file)
    if sha256_file(upstream_tar)!=TAR_SHA: raise ValueError('requires pinned jq 1.8.1 source archive')
    if [sha256_file(p) for p in patches]!=list(PATCHES.values()):
        raise ValueError('requires the seven original derivation patches in the recorded order')
    if (comparison is None)==(source_export is None) or (source_export is not None and extra_comparisons):
        raise ValueError('choose comparison inputs or a standalone source export')
    output.mkdir(parents=True,exist_ok=False)
    if source_export is None:
        export_comparison_sources(comparisons=[comparison,*extra_comparisons],target_id='jq',output=output/'lifted')
    else:
        retained=load_source_export(source_export)
        for name in [*retained['files'],'source-export.json']:
            destination=output/'lifted'/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source_export/name,destination)
    export,extra_ids,shared_layout=checked_export(output/'lifted',choices)
    backend=output/'backends/jq'; backend.parent.mkdir()
    with tarfile.open(upstream_tar) as archive:
        archive.extractall(backend.parent,filter='data')
    (backend.parent/'jq-1.8.1').rename(backend)
    provenance=output/'provenance'; provenance.mkdir()
    for name,path in zip(PATCHES,patches):
        saved=provenance/name; shutil.copyfile(path,saved)
        with (provenance/(name+'.log')).open('w') as log:
            subprocess.run(['patch','--batch','--forward','-p1','-i',str(saved)],cwd=backend,stdout=log,stderr=subprocess.STDOUT,check=True)
    removed=replace_backend_operations(backend,{name:choices[name] for name in sorted(extra_ids)})
    import_identity=bind_import_identity(backend)
    write_backend_headers(output,choices,export['components'])
    # Regenerate once at preparation, so the delivered build needs no autoconf.
    (backend/'scripts/version').write_text('#!/bin/sh\necho 1.8.1\n')
    with (provenance/'autoreconf.log').open('w') as log:
        subprocess.run(['autoreconf','-fi'],cwd=backend,stdout=log,stderr=subprocess.STDOUT,check=True)
    for path in backend.rglob('autom4te.cache'): shutil.rmtree(path)
    bindings=output/'bindings'; bindings.mkdir()
    for name in ('storage.c','string.c','import-runtime.c','live-values.c'):
        shutil.copyfile(HERE/name,bindings/name)
    diagnostics=output/'diagnostics'; diagnostics.mkdir()
    for name in ('failure.c','failure.mk'):
        shutil.copyfile(HERE/name,diagnostics/name)
    for name in ('allocation-observer.c','allocation-observer.h'):
        shutil.copyfile(HERE.parent/'jq-array-storage'/name,diagnostics/name)
    for name, path in native_adapter_headers().items():
        shutil.copyfile(path,diagnostics/name)
    for src,dest in [('jq-array-storage/native.h','array-native.h'),('jq-array-storage/path-bridge.h','array-path-bridge.h'),
            ('jq-path-network/native-api.h','native-api.h'),('jq-path-network/native-services.h','native-services.h'),
            ('jq-path-network/native-errors.c','native-errors.c'),('jq-path-network/native-slice.c','native-slice.c'),
            ('jq-string-slice/string-native.h','string-native.h'),('jq-string-slice/string-view.h','string-view.h'),
            ('jq-string-slice/string-storage.h','string-storage.h'),
            ('jq-value-transport/value-transport.h','value-transport.h')]:
        shutil.copyfile(HERE.parent/src,bindings/dest)
    # Copy every byte of a live native value, including real host pointers. This
    # is executable transport, not a claim that previous token checks apply.
    shutil.copyfile(HERE.parent/'jq-value-transport/raw-runtime.h',bindings/'raw-runtime.h')
    (bindings/'values.c').write_text('#include "jv.h"\n#include "portable-component-implementation.h"\n'
        '#include "value-transport.h"\n#include "raw-runtime.h"\n'
        'int spx_value_valid(spx_jv_value_v2 value) { return jv_is_valid(spx_value_borrow(value)); }\n')
    native_entries=write_component_bindings(output,output/'lifted',export,choices)
    write_json(output/'portable-project.json',dict(version=1,authority='diagnostic-source-provenance',
        source_export_sha256=sha256_file(output/'lifted/source-export.json'),upstream_tar_sha256=TAR_SHA,
        original_dll_sha256=ORIGINAL_SHA,patches=PATCHES,removed_operations=removed,native_entries=native_entries,
        source_bindings=retained_bindings(choices,export['components']),
        import_identity=import_identity,shared_layout_sha256s=shared_layout,
        source_assistance='Pinned jq CLI, parser, compiler, VM, objects, strings, numbers, allocation and lower services; bundled oniguruma.',
        representation='Unpacked authored array descriptors retain live native storage; path/string values copy complete 16-byte host descriptors. No heap reconstruction.',
        validation_scope='New source backend and live-value transport require program validation; PE32 comparison token observations are not inherited.',
        assumptions=['Single-threaded jq execution; live well-formed objects, 32-bit int and 16-byte jv.',
            'Array allocations stay within the explicit PE32 nonwrapping span; original undefined/corrupt-pointer cases are excluded.',
            'Portable host startup, filesystem and streams; finite redirected UTF-8 JSON workloads compared to original jq --binary.',
            'Unselected source backend is a dependency, not a lifted implementation or a proved service summary.'],
        files={p.relative_to(output).as_posix():sha256_file(p) for p in output.rglob('*') if p.is_file()},
        preparation_seconds=time.monotonic()-started,strong_qualification=False,whole_jq_lift=False,validated=False))
    print(output)


def write_component_bindings(output,library,export,choices):
    """Use the same reviewed entries/adapters for initial and incremental assembly."""
    bindings=output/'bindings';bindings.mkdir(parents=True,exist_ok=True)
    provenance=output/'provenance';provenance.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(HERE/'PROJECT.md',output/'README.md')
    for name in ('observations.c','observations.h','import-runtime.c'):
        shutil.copyfile(HERE/name,bindings/name)
    for name in ('windows-output.c','windows-output.h'):
        shutil.copyfile(HERE.parent/'portable-runtime'/name,bindings/name)
    for identity in sorted(export['components'].keys() & choices.keys()):
        for name,path in choices[identity].get('headers',{}).items():
            destination=bindings/name
            if destination.exists() and sha256_file(destination)!=sha256_file(path):
                raise ValueError('binding header would replace another adapter: '+name)
            if path.resolve()!=destination.resolve():shutil.copyfile(path,destination)
    units=export['components'];selected_bindings={}
    for identity,unit in units.items():
        spec=choices.get(identity,{})
        if 'assembly' in spec:
            spec['assembly']=assembly_binding(spec['assembly'],base=output,operations=unit['operation_symbols'])
            selected_bindings[identity]=spec.get('service_bridge',dict(native_symbol=None,adapters={},transports={}))
            continue
        references={json.dumps(row['service_bridge'],sort_keys=True) for row in unit.get('comparison_binding_references',[])}
        if 'service_bridge' in spec:
            binding=copy.deepcopy(spec['service_bridge'])
        elif len(references)==1 and 'null' not in references:
            binding=copy.deepcopy(json.loads(next(iter(references))))
        else:
            raise ValueError('supply portable service_bridge or assembly bindings for '+identity)
        binding['native_symbol']=spec.get('native_symbol',binding['native_symbol'])
        for service,symbol in spec.get('service_symbols',{}).items():
            if service not in binding['adapters']:raise ValueError('binding names an unknown service: '+identity+'/'+service)
            binding['adapters'][service]['symbol']=symbol
        selected_bindings[identity]=binding
    generated=render_source_service_bridges(library,bindings={name:binding for name,binding in selected_bindings.items()
        if 'assembly' not in choices.get(name,{}) or 'service_bridge' in choices[name]})
    (bindings/'component-observation-names.h').write_text('static const char *names[]={'+
        ','.join(json.dumps(name) for name in sorted(units))+'};\n')
    coverage={}; native_entries={};support_files={}; adapter_sources={}
    for identity in sorted(units):
        if 'assembly' in choices.get(identity,{}):
            spec=choices[identity]['assembly']
            adapter_sources[identity]=write_assembly_binding(spec,bindings/identity)
            native_entries[identity]=sorted(spec['entries'])
            support_files[identity]=[identity+'/'+name for name in [*spec['sources'],*spec['headers']]]
            coverage[identity]={'adapter_owned':['operation-entry-dispatch','context-state-and-lifetime','service-wiring']}
            if identity in generated:
                if 'services.generated.h' in spec['headers']:
                    raise ValueError('assembly header collides with generated service helpers: '+identity)
                (bindings/identity/'services.generated.h').write_text(generated[identity][0])
            continue
        native_entries[identity]=selected_bindings[identity]['native_symbol']
        rendered,coverage[identity]=generated[identity]
        entry=native_entries[identity]
        match=re.search(r'^.* '+re.escape(entry)+r'\([^\n]*\) \{\n',rendered,re.M)
        if not match: raise ValueError('generated entry is missing: '+entry)
        rendered=rendered[:match.end()]+('  static unsigned observation_slot;\n'
            f'  portable_component_entry({json.dumps(identity)}, &observation_slot);\n')+rendered[match.end():]
        prefix='#include "portable-component-implementation.h"\n#include "observations.h"\n'
        if identity.startswith('storage-'): headers=['runtime.h']
        elif identity not in ENTRIES and not selected_bindings[identity].get('transports'):
            headers=[]  # Explicit opaque/scalar adapters supply their own declarations.
        elif identity=='string-slice' or identity not in ENTRIES: headers=['string-native.h','value-transport.h']
        else: headers=['native-api.h','value-transport.h','native-services.h','array-path-bridge.h']
        headers+=sorted(choices.get(identity,{}).get('headers',{}))
        prefix+=''.join(f'#include "{name}"\n' for name in headers)
        support_files[identity]=[name for name in headers if name!='runtime.h']+[
            'storage.c' if identity.startswith('storage-') else 'values.c']
        (bindings/(identity+'.c')).write_text(prefix+'#define fputs portable_binding_message\n'+rendered+'#undef fputs\n')
    if any('parse_slice' in ([entry] if isinstance(entry,str) else entry) for entry in native_entries.values()):
        # The path adapters retain their existing value transport. Once the
        # range helper is selected, discard its old copied implementation.
        (bindings/'native-slice.c').write_text('#include "native-api.h"\n'
            'extern jv parse_slice(jv, jv, int *, int *);\n'
            'path_native_range path_slice_bounds(jv value, jv key) {\n'
            '    path_native_range range = {jv_invalid(), 0, 0};\n'
            '    range.status = parse_slice(value, key, &range.start, &range.end);\n'
            '    return range;\n}\n')
    else:
        # Removing that provider restores the retained fixture dependency too.
        shutil.copyfile(HERE.parent/'jq-path-network/native-slice.c',bindings/'native-slice.c')
    write_makefile(output,sorted(units),adapter_sources,native_entries)
    write_binding_guides(output,export,choices,selected_bindings,support_files)
    write_json(provenance/'service-coverage.json',coverage)
    return native_entries


def write_makefile(output,units,adapter_sources=None,native_entries=None):
    common='-Ibindings -Ibackends/jq/src -Ilifted/components/storage-copy/sources/source -Ilifted/components/storage-copy/sources/headers'
    rules=[]; objects=[]; process_objects=[]
    process_components={name for name,symbols in (native_entries or {}).items()
                        if 'main' in ([symbols] if isinstance(symbols,str) else symbols)}
    adapter_sources=adapter_sources or {}
    selected=[]
    for unit in units:
        selected.extend([(unit+'/'+Path(name).with_suffix('').as_posix(),unit) for name in adapter_sources[unit]]
                        if unit in adapter_sources else [(unit,unit)])
    for name,unit in selected+[(n,u) for n,u in [('storage',None),('string',None),('observations',None),('import-runtime',None),('windows-output',None),('native-errors','path-get'),('native-slice',None),('values','value-get')]]:
        obj='build/'+name+'.o';objects.append(obj);includes=common
        if unit in process_components:process_objects.append(obj)
        if unit:
            base='lifted/components/'+unit+'/sources/'
            includes+=' '+ ' '.join('-I'+base+n for n in ('generated','source','headers'))
            if unit in adapter_sources:includes+=' -Ibindings/'+unit
        rules.append(f'{obj}: bindings/{name}.c\n\t@mkdir -p '+('$(dir $@)' if '/' in name else 'build')+'\n'
            f'\t$(CC) $(CPPFLAGS) $(CFLAGS) {includes} -MMD -MP -c $< -o $@\n')
    (output/'Makefile').write_text('\n\n'.join([
        'CC ?= cc','AR ?= ar','RANLIB ?= ranlib','CFLAGS ?= -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror',
        'BACKEND_CFLAGS ?= -O2 -g0','CONFIGURE_FLAGS ?=','LDFLAGS ?=','OBJECTS := '+' '.join(objects),
        'LIBRARY_OBJECTS := '+('$(filter-out '+' '.join(process_objects)+',$(OBJECTS))' if process_objects else '$(OBJECTS)'),
        '.PHONY: all clean lifted-library','all: jq',
        'backends/build/Makefile:\n\tmkdir -p backends/build\n\tcd backends/build && CC="$(CC)" AR="$(AR)" RANLIB="$(RANLIB)" CFLAGS="$(BACKEND_CFLAGS)" LDFLAGS="$(LDFLAGS)" ../jq/configure --disable-shared --enable-static --with-oniguruma=builtin $(CONFIGURE_FLAGS)',
        'backends/build/backend.stamp: backends/build/Makefile $(wildcard backends/jq/src/*.[ch])\n\t$(MAKE) -C backends/build/vendor/oniguruma/src libonig.la\n\t$(MAKE) -C backends/build src/builtin.inc src/config_opts.inc src/version.h\n\t$(MAKE) -C backends/build libjq.la src/main.o\n\ttouch $@',
        'lifted-library:\n\t$(MAKE) -C lifted CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)"',
        'jq: $(OBJECTS) backends/build/backend.stamp lifted-library\n\t$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-Map,build/jq.map backends/build/src/main.o $(OBJECTS) -Wl,--start-group lifted/liblifted.a backends/build/.libs/libjq.a backends/build/vendor/oniguruma/src/.libs/libonig.a -Wl,--end-group -lm $(LDLIBS) -o $@',
        'build/live-values.o: bindings/live-values.c\n\t@mkdir -p build\n\t$(CC) $(CPPFLAGS) $(CFLAGS) -Ibackends/jq/src -MMD -MP -c $< -o $@',
        'live-values: build/live-values.o $(LIBRARY_OBJECTS) backends/build/backend.stamp lifted-library\n\t$(CC) $(CFLAGS) $(LDFLAGS) build/live-values.o $(LIBRARY_OBJECTS) -Wl,--start-group lifted/liblifted.a backends/build/.libs/libjq.a backends/build/vendor/oniguruma/src/.libs/libonig.a -Wl,--end-group -lm $(LDLIBS) -o $@',
        *rules,'-include $(OBJECTS:.o=.d)',
        'clean:\n\t$(MAKE) -C lifted clean\n\trm -rf build backends/build jq live-values','']))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    inputs=parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--comparison',type=Path)
    inputs.add_argument('--source-export',type=Path,help='assemble from a standalone exported library without comparison packages or native runtime tools')
    parser.add_argument('--extra-comparison',type=Path,action='append',default=[],help='add a compared operation with an implemented source-backend binding')
    parser.add_argument('--bindings',type=Path,help='reviewed entry/backend/header/service choices in JSON; header paths are relative to this file')
    parser.add_argument('--upstream-tar',type=Path)
    parser.add_argument('--patch',type=Path,action='append')
    parser.add_argument('--original-derivation',type=Path,help='retained nix derivation show JSON; obtains exact source and ordered patches')
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    if a.original_derivation:
        if a.upstream_tar or a.patch:parser.error('choose original derivation or explicit source/patch inputs')
        derivations=json.loads(a.original_derivation.read_text())
        derivations=derivations.get('derivations',derivations)
        if len(derivations)!=1:parser.error('requires one original derivation')
        environment=next(iter(derivations.values()))['env']
        a.upstream_tar=Path(environment['src']);a.patch=[Path(p) for p in environment['patches'].split()]
    if not a.upstream_tar or not a.patch:parser.error('requires the original derivation or source and ordered patches')
    prepare(a.comparison.resolve() if a.comparison else None,a.upstream_tar.resolve(),[p.resolve() for p in a.patch],a.output.resolve(),
        [p.resolve() for p in a.extra_comparison],a.source_export.resolve() if a.source_export else None,a.bindings)
