"""Run-local experimental admission guarded by content and lookup snapshots.

There is no persistent success cache or new authority artifact. Every public run
starts with the normal manifest reader. During that run all retained package
bytes, external compiler/tool inputs and include-lookup states must stay fixed.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..components.comparison_compile_cache import file_state, keyed_path
from ..components.comparison_package import load_comparison_package
from ..util import sha256_file
from .experimental_manifest import compiler_read_inputs, load_experimental_manifest


def _package_state(root: Path) -> dict:
    state={}
    for path in sorted(root.rglob('*')):
        name=path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f'experimental admission package contains a symbolic link: {name}')
        if path.is_dir():
            state[name]=('directory',)
        elif path.is_file():
            state[name]=('file',sha256_file(path))
        else:
            raise ValueError(f'experimental admission input is absent or not regular: {name}')
    return state


def _external_dependencies(root: Path) -> tuple[set[Path],set[Path]]:
    files=set();probes=set()
    manifest=json.loads((root/'experimental-execution.json').read_text())
    files.add(Path(manifest['symbols']['tool']['path']))
    for path in root.rglob('comparison-result.json'):
        result=json.loads(path.read_text())
        files.update(path for path,_ in compiler_read_inputs(path.parent,result))
        for tools in (result['tools'],result['formal_check'].get('tools',{})):
            files.update(Path(row['path']) for row in tools.values() if row is not None)
    # A reused comparison can depend on include absence/identity even when no
    # header was read. Guard these as lookup states, not invented content inputs.
    for path in root.rglob('compilation.json'):
        value=json.loads(path.read_text())
        if value.get('version')!=1:
            raise ValueError('experimental admission has an unsupported compiler input inventory')
        package=path.parent.parent/'inputs'
        for unit in value['units']:
            files.update(keyed_path(package,key) for key in unit['inputs'])
            probes.update(keyed_path(package,key) for key in unit['probes'])
    # Keep lexical paths so a retargeted external symlink is detected too.
    return ({p for p in files if not p.is_relative_to(root)},
            {p for p in probes if not p.is_relative_to(root)})


def _external_state(files: set[Path], probes: set[Path]) -> dict:
    state={}
    for path in sorted(files|probes):
        value=file_state(Path('/'),str(path))
        if path in files and value['kind']=='file':
            value={**value,'sha256':sha256_file(path)}
        state[str(path)]=value
    return state


class _ExperimentalAdmission:
    """A single checked package, private to one suite or direct case invocation."""

    def __init__(self, package: Path):
        self.package=package.resolve()
        self.package_state=_package_state(self.package)
        self.reuse_limitation=None
        try:
            self.external_files,self.external_probes=_external_dependencies(self.package)
            self.external_state=_external_state(self.external_files,self.external_probes)
        except (KeyError,TypeError,ValueError,OSError):
            # An unfamiliar optional build inventory can still be executable.
            # The normal reader decides admission; repeat it rather than guess
            # external dependencies or reject a valid older package for speed.
            self.reuse_limitation='external input inventory unavailable; repeat full admission'
        self.manifest=load_experimental_manifest(self.package)
        self.plan,_=load_comparison_package(self.package/'comparison/inputs')
        self.program_observations={}
        if self.plan.get('program_driver',{}).get('process'):
            graph=json.loads((self.package/'comparison/comparison-result.json').read_text())
            self.program_observations={row['id']:row['observations']['source'] for row in graph['cases']}
        self.check()  # Detect changes during full admission as well as later edits.
        if self.manifest!=json.loads((self.package/'experimental-execution.json').read_text()):
            raise ValueError('experimental manifest changed during admission')

    def check(self, case_id: str | None = None) -> None:
        if case_id is not None and case_id not in self.manifest['case_ids']:
            raise ValueError('experimental case is absent from the admitted suite')
        current=_package_state(self.package)
        if current!=self.package_state:
            changed=next(name for name in sorted(current.keys()|self.package_state.keys())
                if current.get(name)!=self.package_state.get(name))
            raise ValueError(f'experimental admission input changed during this run: {changed}')
        if self.reuse_limitation is not None:
            if load_experimental_manifest(self.package,case_id=case_id)!=self.manifest:
                raise ValueError('experimental manifest changed during this run')
            return
        current=_external_state(self.external_files,self.external_probes)
        if current!=self.external_state:
            changed=next(name for name in sorted(current) if current[name]!=self.external_state[name])
            raise ValueError(f'experimental admission external input changed during this run: {changed}')
