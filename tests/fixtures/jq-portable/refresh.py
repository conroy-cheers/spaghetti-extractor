"""Refresh reviewed jq bindings after exporting components into an existing project.

Uses retained/operator-supplied backend choices. No native execution, archive extraction
or configuration is needed. Backend edits retain current surrounding C; conflicting
generated binding/build files need a manual merge. Proposals and prior files are
retained so that merge does not require another prepared project.
"""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import time

from binding_guides import guide_files

from prepare import (ORIGINAL_SHA, PATCHES, TAR_SHA, checked_export,
                     retained_bindings, source_bindings, write_backend_headers, write_component_bindings, replacement_definitions)
from spaghetti_extractor.candidate.source_assembly import assembly_delta
from spaghetti_extractor.candidate.source_replacements import reconcile_definitions
from spaghetti_extractor.util import sha256_file, write_json


def binding_files(choices,components):
    """Files owned by selected adapters, separate from shared recipe support."""
    result=set()
    for name in components:
        spec=choices.get(name,{})
        result.add('bindings/'+name+'.md')
        if 'assembly' in spec:
            for field in ('sources','headers'):
                result.update('bindings/'+name+'/'+path for path in spec['assembly'][field])
            if 'service_bridge' in spec:result.add('bindings/'+name+'/services.generated.h')
        else:result.add('bindings/'+name+'.c')
        result.update('bindings/'+path for path in spec.get('headers',{}))
        for filename,headers in spec.get('backend_headers',{}).items():
            result.update('backends/jq/'+Path(filename).with_name(path).as_posix() for path in headers)
    return result


def refresh(project,keep_reviewed=(),bindings_file=None,restore_from=None):
    started=time.monotonic();project=project.resolve()
    manifest=project/'portable-project.json';previous_sha=sha256_file(manifest)
    previous=json.loads(manifest.read_text())
    if (previous.get('version')!=1 or previous.get('authority')!='diagnostic-source-provenance'
            or previous.get('upstream_tar_sha256')!=TAR_SHA
            or previous.get('original_dll_sha256')!=ORIGINAL_SHA or previous.get('patches')!=PATCHES):
        raise ValueError('requires an existing project from the pinned jq source recipe')
    choices=source_bindings(bindings_file,project=project,previous=previous)
    export,_,layout=checked_export(project/'lifted',choices)
    if layout!=previous['shared_layout_sha256s']:
        raise ValueError('shared storage layout changed; review the portable adapters before assembly')
    selected=export['components'];old_entries=previous['native_entries']
    added=sorted(selected.keys()-old_entries.keys())
    proposal=Path(tempfile.mkdtemp(prefix=project.name+'.binding-proposal-',dir=project.parent))
    keep_proposal=False
    try:
        entries=write_component_bindings(proposal,project/'lifted',export,choices)
        old_choices=previous.get('source_bindings',{})
        delta=assembly_delta(old_entries,entries,
            {name:replacement_definitions(old_choices.get(name,{})) for name in old_entries},
            {name:replacement_definitions(choices.get(name,{})) for name in selected})
        sources,removed=reconcile_definitions(project/'backends/jq',previous['removed_operations'],delta,
                                              restore_from=restore_from)
        backend_inputs={}
        for filename,source in sources.items():
            relative='backends/jq/'+filename
            backend_inputs[relative]=sha256_file(project/relative)
            destination=proposal/relative;destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_text(source)
        backend_inputs.update(write_backend_headers(proposal,choices,selected,
            existing=project,previous=previous.get('source_bindings')))
        retained=retained_bindings(choices,selected)
        binding_inputs_changed=(retained!=previous.get('source_bindings') or any(
            previous['files'].get('bindings/'+name)!=sha256_file(path)
            for identity in selected for name,path in choices.get(identity,{}).get('headers',{}).items()) or any(
            previous['files'].get('backends/jq/'+Path(filename).with_name(name).as_posix())!=sha256_file(path)
            for identity in selected for filename,headers in choices.get(identity,{}).get('backend_headers',{}).items()
            for name,path in headers.items()) or any(
            previous['files'].get('bindings/'+identity+'/'+name)!=sha256_file(path)
            for identity in selected for field in ('sources','headers')
            for name,path in choices.get(identity,{}).get('assembly',{}).get(field,{}).items()))
        candidates={p.relative_to(proposal).as_posix():sha256_file(p) for p in proposal.rglob('*') if p.is_file()}
        obsolete=binding_files(old_choices,old_entries)-binding_files(choices,selected)-candidates.keys()
        accepted=set(keep_reviewed)
        if accepted-candidates.keys():
            raise ValueError('review names a file outside the proposed integration: '+', '.join(sorted(accepted-candidates.keys())))
        changed=[];preserved=[];current={};conflicts=[];reviewed={};retained_backend=[]
        deleted=[]
        for name in sorted(obsolete):
            path=project/name
            if path.is_symlink() or not path.resolve().is_relative_to(project):
                raise ValueError('binding removal requires an ordinary project file: '+name)
            if not path.exists():continue
            current[name]=sha256_file(path)
            if current[name]!=previous['files'].get(name):conflicts.append(name)
            else:deleted.append(name)
        for name,digest in candidates.items():
            path=project/name
            if path.is_symlink() or not path.resolve().is_relative_to(project) or (path.exists() and not path.is_file()):
                raise ValueError('binding refresh requires an ordinary project file: '+name)
            current[name]=sha256_file(path) if path.exists() else None
            if name in backend_inputs and current[name]!=backend_inputs[name]:
                raise ValueError('backend changed while preparing binding refresh; retry: '+name)
            if current[name]==digest:continue
            prior=previous['files'].get(name)
            if name in backend_inputs:
                # The proposal starts with these exact current bytes and only
                # removes explicitly selected bodies or updates checked managed
                # includes. Surrounding operator edits are already preserved.
                changed.append(name)
                if current[name]!=prior:retained_backend.append(name)
            elif name in accepted and current[name] is not None:
                preserved.append(name);reviewed[name]=current[name]
            elif prior==digest and current[name] is not None:
                preserved.append(name)  # The recipe has no change to this operator-edited file.
            elif current[name]!=prior:
                conflicts.append(name)
            else:
                changed.append(name)
        if conflicts:
            keep_proposal=True
            raise ValueError('binding refresh would overwrite local edits: '+', '.join(sorted(conflicts))+
                '; no project files changed. Review proposed files in '+str(proposal)+
                ', merge affected bindings/build files, then rerun with --keep-reviewed FILE for each merge')
        export_sha=sha256_file(project/'lifted/source-export.json')
        if not changed and not deleted and not reviewed and not binding_inputs_changed and export_sha==previous['source_export_sha256']:
            return dict(status='unchanged',seconds=time.monotonic()-started,changed_files=[],preserved_local_edits=sorted(preserved))
        inventory={name:digest for name,digest in previous['files'].items() if not name.startswith('lifted/') and name not in obsolete}
        # Generated hashes remain the recipe baseline for future three-way
        # comparisons. Explicitly merged operator bytes are recorded separately.
        inventory.update({name:digest for name,digest in candidates.items() if name not in preserved or name in reviewed})
        inventory.update({'lifted/'+name:digest for name,digest in export['files'].items()})
        inventory['lifted/source-export.json']=export_sha
        backup=Path(tempfile.mkdtemp(prefix=project.name+'.before-bindings-',dir=project.parent))
        validation_required=(binding_inputs_changed or export_sha!=previous['source_export_sha256'] or
            bool((set(changed)|set(deleted)|reviewed.keys())-guide_files(selected)))
        result=dict(status='refreshed',added_components=added,changed_files=sorted(changed),
            removed_components=delta['removed_components'],removed_files=deleted,assembly_delta=delta,
            preserved_local_edits=sorted(preserved),reviewed_file_sha256s=reviewed,
            retained_backend_edits=sorted(retained_backend),
            binding_inputs_changed=binding_inputs_changed,
            backup=str(backup),program_validation_required=validation_required)
        metadata=dict(previous,files=inventory,source_export_sha256=export_sha,native_entries=entries,
            source_bindings=retained,removed_operations=removed,validated=False if validation_required else previous.get('validated',False),
            refresh=dict(result,previous_project_sha256=previous_sha))
        write_json(proposal/'portable-project.json',metadata)
        publication=[*changed,*deleted,'portable-project.json'];current['portable-project.json']=previous_sha
        # Check every generated input before publishing any change. Builds are
        # deliberately excluded; unchanged source/object mtimes remain intact.
        if any((sha256_file(project/name) if (project/name).exists() else None)!=digest for name,digest in current.items()):
            raise ValueError('project changed while preparing binding refresh; retry')
        for name in publication:
            if current[name] is not None:
                saved=backup/name;saved.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(project/name,saved)
        (backup/'new-files.txt').write_text(''.join(name+'\n' for name in publication if current[name] is None))
        applied=[]
        try:
            for name in publication:
                path=project/name;path.parent.mkdir(parents=True,exist_ok=True);applied.append(name)
                if name in deleted:path.unlink()
                else:shutil.copyfile(proposal/name,path)
        except BaseException:
            for name in reversed(applied):
                if current[name] is None:(project/name).unlink(missing_ok=True)
                else:shutil.copy2(backup/name,project/name)
            raise
        return dict(result,seconds=time.monotonic()-started)
    finally:
        if not keep_proposal:shutil.rmtree(proposal)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project',type=Path,help='existing source project whose lifted/ export has been updated')
    parser.add_argument('--keep-reviewed',action='append',default=[],metavar='FILE',
        help='retain this manually merged binding/build file, relative to the project (repeatable); recheck program integration')
    parser.add_argument('--bindings',type=Path,help='reviewed JSON choices for new/updated bindings; omitted choices reuse the retained project inputs')
    parser.add_argument('--restore-from',type=Path,help='original backend source tree for restoring legacy hash-only retirements; exact body hashes must match')
    args=parser.parse_args()
    try:result=refresh(args.project,args.keep_reviewed,args.bindings,args.restore_from)
    except ValueError as failure:parser.exit(2,str(failure)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))
    print('Portable component bindings: '+str(args.project.resolve()/'COMPONENTS.md'))
    if result.get('program_validation_required'):
        print('Rebuild with make and exercise affected program workloads; this refresh records source integration only.')
    else:
        print('No executable input changes from this refresh; existing validation keeps its prior scope.')
