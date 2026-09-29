"""Review the host entry spelling, then reuse the existing source assembly recipe.

The backend has two mutually exclusive entry signatures sharing one body. The
host delivery uses main. Make that signature ordinary C before its reversible
retirement; retain the original text and exact edit in project provenance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def assemble(project):
    here = Path(__file__).resolve().parent
    path = project / 'backends/jq/src/main.c'
    text = path.read_text()
    start = '#ifdef WIN32\nint umain(int argc, char* argv[]);\n'
    end = '#endif\n  jq_state *jq = NULL;'
    marker = '/* Host process entry; original platform signatures retained in provenance. */\n'
    if start in text:
        first = text.index(start)
        last = text.index(end, first) + len('#endif\n')
        before = text[first:last]
        after = marker + 'int main(int argc, char* argv[]) {\n'
        replaced = text[:first] + after + text[last:]
        record = dict(before=before, after=after,
            before_file_sha256=hashlib.sha256(text.encode()).hexdigest(),
            after_file_sha256=hashlib.sha256(replaced.encode()).hexdigest(),
            scope='Host entry spelling only; selected body retired by the existing assembly recipe.')
        (project / 'provenance/cli-host-entry.json').write_text(json.dumps(record, indent=2) + '\n')
        path.write_text(replaced)
    elif marker not in text:
        raise ValueError('unrecognized backend CLI entry; review its platform adapter')
    subprocess.run([sys.executable, str(here.parent / 'jq-portable/refresh.py'), str(project),
        '--bindings', str(here / 'portable-bindings.json')], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    args = parser.parse_args()
    assemble(args.project.resolve())
