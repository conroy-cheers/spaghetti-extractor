"""Retained translation-unit reuse with checked literal include search probes.

The existing comparison receipt binds this build metadata and its object files.
Only immutable Nix toolchains and understood preprocessing inputs are reusable;
unsupported constructs compile normally and retain a reason for the cache miss.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex

from ..util import sha256_file,sha256_text


DESKTOP_VARIABLES = frozenset({
    'DISPLAY', 'WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'XAUTHORITY',
    'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
    'PULSE_SERVER', 'PULSE_SINK', 'PULSE_SOURCE', 'PULSE_COOKIE', 'PULSE_CLIENTCONFIG',
    'SPAGHETTI_DESKTOP_CAPTURE',
})
SHELL_TEMP_VARIABLES = frozenset({'NIX_BUILD_TOP', 'TMPDIR', 'TMP', 'TEMP', 'TEMPDIR'})
SHELL_SESSION_VARIABLES = frozenset({'SHLVL'})
# The Python application chooses these to load its own installed/source modules.
# C tools get their packaged environment, not the operator launcher's import path.
PYTHON_VARIABLES = frozenset({
    'PYTHONPATH', 'PYTHONHOME', 'PYTHONHASHSEED', 'PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE',
})


def compiler_environment_exclusions() -> frozenset[str]:
    # Pure Nix builds use these paths to admit build inputs. Interactive shells
    # do not enforce that filtering; their disposable directories should not
    # become compiler inputs merely because the operator opened another shell.
    return DESKTOP_VARIABLES | PYTHON_VARIABLES | SHELL_SESSION_VARIABLES | (SHELL_TEMP_VARIABLES if os.environ.get('NIX_ENFORCE_PURITY') != '1' else frozenset())


def compiler_environment() -> dict[str,str]:
    """Keep C tool inputs separate from the Python launcher and shell/desktop state.

    These values are withheld from the actual compiler/linker, not merely
    ignored by the cache. Outside pure builds the compiler uses its default
    temporary directory. Shell nesting is also withheld: command redirection or
    a wrapper shell must not change the C tool's inherited nesting counter.
    All other variables remain inherited and hashed.
    Runtime processes and their execution evidence still use the full environment.
    """
    excluded=compiler_environment_exclusions()
    return {key:value for key,value in os.environ.items() if key not in excluded}


def configuration(plan):
    return dict(compiler=plan['tools']['compiler'],
        environment_sha256=sha256_text(json.dumps(compiler_environment(),sort_keys=True)),
        environment_exclusions=sorted(compiler_environment_exclusions()),
        engine_sha256s={p.name:sha256_file(p) for p in (Path(__file__),Path(__file__).with_name('comparison_build.py'))})


def path_key(package,path):
    # Keep lexical include paths: resolving a symlink here would discard the
    # very lookup whose target must be rechecked on the next invocation.
    package=Path(package)
    if not package.is_absolute():package=package.resolve()
    path=Path(path)
    if not path.is_absolute():path=package/path
    try:
        return '@/'+str(path.relative_to(package))
    except ValueError:
        return str(path)


def keyed_path(package,key):
    package=Path(package)
    if not package.is_absolute():package=package.resolve()
    return package/key[2:] if key.startswith('@/') else Path(key)


def file_state(package,key):
    path=keyed_path(package,key)
    # Internal snapshots prohibit symlinks. External toolchain/header symlinks
    # are allowed but their target and bytes are both part of the observation.
    resolved=path.resolve()
    target=path_key(package,resolved)
    if not path.exists():return dict(kind='absent',target=target)
    if not path.is_file():return dict(kind='non-file',target=target)
    # Probe contents matter only when actually read; those bytes are bound in
    # entry.inputs. Here existence/identity determines include resolution.
    return dict(kind='file',target=target)


def _uncomment(text):
    token=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',re.S)
    return token.sub(lambda m: ('\n'*m[0].count('\n')+' ') if m[0].startswith(('/',)) else m[0],text)


def include_names(text):
    """Conservatively scan even inactive literal directives and existence tests."""
    if re.search(r"\?\?[=/'()!<>-]",text):return [],['trigraph input requires fresh preprocessing']
    text=_uncomment(text.replace('\\\r\n','').replace('\\\n',''))
    unsupported=[];names=[]
    if re.search(r'\b__(?:DATE|TIME|TIMESTAMP)__\b|\b__has_embed\b|\.incbin\b|\.include\b|GCC\s+dependency',text):
        unsupported.append('time-dependent or external-input preprocessing requires recompilation')
    for match in re.finditer(r'^\s*(?:#|%:)\s*(include_next|include|import|embed)\b([^\n]*)',text,re.M):
        kind,argument=match.groups()
        literal=re.fullmatch(r'\s*(?:"([^"\n]+)"|<([^>\n]+)>)\s*',argument)
        if kind=='embed' or literal is None:
            unsupported.append('computed or unsupported include directive requires fresh preprocessing')
        else:names.append(literal[1] or literal[2])
    # Macro-defined existence predicates cannot be inferred from a depfile.
    for match in re.finditer(r'\b__has_include(?:_next)?\b',text):
        literal=re.match(r'\s*\(\s*(?:"([^"\n]+)"|<([^>\n]+)>)\s*\)',text[match.end():])
        if literal is None:unsupported.append('computed include-existence test requires fresh preprocessing')
        else:names.append(literal[1] or literal[2])
    return names,unsupported


def search_directories(stderr,package):
    directories=[];active=False;complete=False
    for line in stderr.splitlines():
        if line.startswith('#include ') and line.endswith(' search starts here:'):
            active=True
        elif line=='End of search list.':
            active=False;complete=True
        elif active:
            name=line.strip()
            if name.endswith(' (framework directory)'):return [],False
            directories.append(path_key(package,name))
        elif line.startswith(('ignoring nonexistent directory "','ignoring duplicate directory "')):
            directories.append(path_key(package,line.split('"',2)[1]))
    return sorted(set(directories)),complete


def unsupported_compiler_inputs(stderr):
    reasons=[]
    # Environment strings are hashed separately, but files selected by these
    # mechanisms would require their own dependency discovery.
    if any(os.environ.get(k) for k in ('LD_PRELOAD','LD_LIBRARY_PATH','GCC_EXEC_PREFIX','COMPILER_PATH')):
        reasons.append('external compiler loader or executable search overrides require recompilation')
    options=[]
    for line in stderr.splitlines():
        if line.startswith('COLLECT_GCC_OPTIONS='):
            options.extend(shlex.split(line.partition('=')[2]))
    if not options:
        reasons.append('compiler option expansion is unavailable for toolchain validation')
    prefixes=('-include','-imacros','-specs','--specs','-fplugin','-fprofile','-fauto-profile','-fmodules','-wrapper','@')
    if any(option.startswith(prefixes) for option in options):
        reasons.append('implicit, response, plugin or profile compiler inputs require fresh compilation')
    for index,option in enumerate(options):
        if option=='-B' and index+1<len(options) and not Path(options[index+1]).resolve().is_relative_to('/nix/store'):
            reasons.append('mutable compiler executable prefix requires recompilation')
    return reasons


def make_entry(*,package,name,unit,options,dependencies,object_path,stderr,plan):
    package=package.resolve()
    directories,complete=search_directories(stderr,package)
    unsupported=unsupported_compiler_inputs(stderr);probes=set();inputs={}
    searches={directory:set() for directory in directories};all_names=set()
    if not complete:unsupported.append('compiler did not expose a complete include search list')
    if not Path(plan['tools']['compiler']['path']).resolve().is_relative_to('/nix/store'):
        unsupported.append('mutable toolchain requires recompilation; use the provisioned Nix compiler for reuse')
    for key,digest in dependencies.items():
        inputs[key]=digest
        path=keyed_path(package,key)
        try:names,reasons=include_names(path.read_text())
        except UnicodeError:
            names=[];reasons=['nontext compiler input requires recompilation']
        unsupported.extend(reasons)
        searches.setdefault(path_key(package,path.parent),set()).update(names)
        all_names.update(names)
    # Each literal include needs the same compiler search directories, regardless
    # of how many headers mention it. Collect directory/name pairs before doing
    # path work; still retain each including file's own relative lookup.
    for directory in directories:searches[directory].update(all_names)
    for directory,names in searches.items():
        root=keyed_path(package,directory)
        for include in names:
            candidate=path_key(package,root/include)
            # The same immutable-store premise binds the Nix compiler and
            # its subordinate tools. Missing files cannot appear in these
            # directories. Actual read header bytes remain checked below.
            if candidate.startswith('/nix/store/') and Path(candidate).resolve().is_relative_to('/nix/store'):
                continue
            probes.add(candidate);probes.add(candidate+'.gch')
    # GCC may implicitly choose a precompiled header instead of the text input.
    # Watch their appearance and refuse reuse when one is already present.
    states={key:file_state(package,key) for key in sorted(probes)}
    if any(key.endswith('.gch') and state['kind']!='absent' for key,state in states.items()):
        unsupported.append('precompiled header selection requires fresh compilation')
    return dict(source=name,unit=unit,options=options,inputs=inputs,probes=states,
        unsupported=sorted(set(unsupported)),object=object_path.name,object_sha256=sha256_file(object_path))


def entry_valid(entry,*,package,name,unit,options,build,probe_states=None):
    """Check one object, optionally sharing path probes within a validation pass.

    Byte hashes remain checked for every entry. The caller discards probe states
    before another check or after invoking a compiler; this is not a persistent
    filesystem cache or a substitute for checking the current source snapshot.
    """
    package=package.resolve()
    if entry.get('unsupported') or any(entry.get(k)!=v for k,v in dict(source=name,unit=unit,options=options).items()):return False
    obj=build/entry['object']
    if obj.parent!=build or not obj.is_file() or sha256_file(obj)!=entry['object_sha256']:return False
    for key,digest in entry['inputs'].items():
        path=keyed_path(package,key)
        if not path.is_file() or sha256_file(path)!=digest:return False
    for key,state in entry['probes'].items():
        if probe_states is None:
            current=file_state(package,key)
        else:
            binding=(package,key)
            if binding not in probe_states:probe_states[binding]=file_state(package,key)
            current=probe_states[binding]
        if current!=state:return False
    return True


def load_cache(previous,plan,*,check_configuration=True):
    if previous is None:return None
    path=previous/'build/compilation.json'
    if not path.is_file():return None
    value=json.loads(path.read_text())
    if value.get('version')!=1 or (check_configuration and value.get('configuration')!=configuration(plan)):return None
    return value


def irrelevant_header_changes(*,previous,package,plan,changed,check_configuration=True):
    """Allow only header changes excluded by every still-valid compiler lookup."""
    from .comparison_build import compilation_units,compile_options
    package=package.resolve()
    cache=load_cache(previous,plan,check_configuration=check_configuration)
    if cache is None:return False,[]
    rows={r['source']:r for r in cache['units']}
    files=compilation_units(plan)
    if set(rows)!={name for name,_ in files}:return False,[]
    probe_states={}
    for name,unit in files:
        if not entry_valid(rows[name],package=package,name=name,unit=unit['id'],
                options=compile_options(plan,unit),build=previous/'build',probe_states=probe_states):return False,[]
    consumed={k[2:] for row in rows.values() for k in row['inputs'] if k.startswith('@/')}
    directories={d+'/' for _,unit in files for d in unit['include_directories']}
    return True,sorted(p for p in changed if p.endswith('.h') and p not in consumed and any(p.startswith(d) for d in directories))
