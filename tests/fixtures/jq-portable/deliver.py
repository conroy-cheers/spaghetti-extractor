"""Copy a reviewed, built jq selection into a clean standalone source project.

This is a target-owned packaging recipe, not a proof or activation receipt.
It preserves source/export provenance and omits build caches and old proposals.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def deliver(project, output):
    here = Path(__file__).resolve().parent
    exported = json.loads((project / 'lifted/source-export.json').read_text())
    for name, expected in exported['files'].items():
        if digest(project / 'lifted' / name) != expected:
            raise ValueError('uncompared exported source: ' + name)
    link_map = (project / 'build/jq.map').read_text()
    members = sorted(set(re.findall(r'^backends/build/\.libs/libjq\.a\(([^)]+)\)', link_map, re.M)))
    if set(members) != {'jv.o', 'jv_dtoa.o', 'lexer.o', 'decNumber.o', 'decContext.o'}:
        raise ValueError('review remaining backend implementations before delivery: ' + repr(members))
    output.mkdir(parents=True, exist_ok=False)
    selected = [project / name for name in ('Makefile', 'COMPONENTS.md', 'portable-project.json',
        'lifted/Makefile', 'lifted/README.md', 'lifted/source-export.json')]
    for name in ('bindings', 'diagnostics', 'lifted/components', 'provenance', 'backends/jq'):
        selected.extend(p for p in (project / name).rglob('*') if p.is_file())
    for source in sorted(selected):
        relative = source.relative_to(project)
        if (source.name.endswith(('~', '.orig', '.pyc')) or
                any(p in ('__pycache__', 'autom4te.cache', '.git') for p in relative.parts)):
            continue
        if source.is_symlink() or source.read_bytes()[:4] in (b'\x7fELF', b'MZ\x90\x00'):
            raise ValueError('unexpected binary or symlink in source delivery: ' + str(relative))
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    shutil.copy2(here / 'PROJECT.md', output / 'README.md')
    shutil.copy2(here / 'DELIVERY.md', output / 'DELIVERY.md')
    roles = {
        'decimal-conversion': ['backends/jq/src/jv_dtoa.c', 'backends/jq/src/jv_dtoa.h'],
        'decimal-arithmetic': ['backends/jq/vendor/decNumber'],
        'regular-expressions': ['backends/jq/vendor/oniguruma'],
        'generated-lexer': ['backends/jq/src/lexer.c', 'backends/jq/src/lexer.h', 'backends/jq/src/lexer.l'],
        'generated-parser-and-adaptations': ['lifted/components/language-parser/sources/source', 'backends/jq/src/parser.y'],
        'runtime-accessors': ['backends/jq/src/jv.c', *[
            p.relative_to(output).as_posix() for p in sorted((output / 'backends/jq/src').glob('*backend.h'))]],
    }
    inventory = {}
    for role, paths in roles.items():
        files = []
        for name in paths:
            p = output / name
            if p.is_dir():
                files.extend(q for q in p.rglob('*') if q.is_file())
            else:
                files.append(p)
        inventory[role] = {p.relative_to(output).as_posix(): digest(p) for p in sorted(files)}
    reuse = dict(authority='informational-source-inventory', source_assisted=True,
        generated_parser_handwritten=False, linked_backend_members=members, sources=inventory,
        selected_components=sorted(exported['components']),
        source_project_sha256=digest(project / 'portable-project.json'),
        source_export_sha256=digest(project / 'lifted/source-export.json'),
        source_link_map_sha256=digest(project / 'build/jq.map'),
        program_validation_required=True, strong_qualification=False)
    (output / 'provenance/library-reuse.json').write_text(json.dumps(reuse, indent=2, sort_keys=True) + '\n')
    # Keep the existing recipe's editable baseline consistent with the packaged
    # files; the source project's original receipt hash is retained above.
    metadata = json.loads((output / 'portable-project.json').read_text())
    metadata['files'] = {n: h for n, h in metadata['files'].items() if (output / n).is_file()}
    for name in ('README.md', 'DELIVERY.md', 'provenance/library-reuse.json'):
        metadata['files'][name] = digest(output / name)
    metadata['validated'] = False
    metadata['validation_scope'] = 'Clean source delivery requires its own build and program receipts; see DELIVERY.md.'
    (output / 'portable-project.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    print('Delivered', len(exported['components']), 'components and reviewed C libraries to', output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    deliver(args.project.resolve(), args.output.resolve())
