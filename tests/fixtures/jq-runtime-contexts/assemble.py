"""Make the conditional dtoa linkage ordinary, then use the existing recipe.

The standalone component supplies both entries externally on every host. Retain
the exact platform-spelling change before reversible function retirement.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def assemble(project):
    here = Path(__file__).resolve().parent
    path = project / 'backends/jq/src/jv_dtoa_tsd.c'
    text = path.read_text()
    before = '#ifndef WIN32\nstatic\n#endif\n'
    after = '/* Context lifecycle is supplied through external component entries. */\n'
    if before in text:
        if text.count(before) != 2:
            raise ValueError('unrecognized dtoa lifecycle linkage; review the source adapter')
        replaced = text.replace(before, after)
        record = dict(before=before, after=after, occurrences=2,
            before_file_sha256=hashlib.sha256(text.encode()).hexdigest(),
            after_file_sha256=hashlib.sha256(replaced.encode()).hexdigest(),
            scope='Linkage spelling only; selected bodies retired by the existing recipe.')
        (project / 'provenance/runtime-context-linkage.json').write_text(json.dumps(record, indent=2) + '\n')
        path.write_text(replaced)
    elif text.count(after) != 2:
        raise ValueError('unrecognized dtoa lifecycle source; review its platform adapter')
    subprocess.run([sys.executable, str(here.parent / 'jq-portable/refresh.py'), str(project),
        '--bindings', str(here / 'portable-bindings.json')], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    args = parser.parse_args()
    assemble(args.project.resolve())
