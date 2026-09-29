"""Normalize the retained pthread spelling, then use ordinary assembly refresh."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def assemble(project, bindings):
    here = Path(__file__).resolve().parent
    path = project / 'backends/jq/src/jq_test.c'
    text = path.read_text()
    before = ('#ifdef __MVS__\n        if (threads[a].__ != 0) {\n#else\n'
              '        if (threads[a] != 0) {\n#endif')
    after = '        if (threads[a] != 0) {'
    marker = '/* Reviewed ordinary pthread spelling for the standalone host profiles. */\n'
    if before in text:
        if text.count(before) != 1:
            raise ValueError('unrecognized pthread test source; review the adapter')
        replaced = marker + text.replace(before, after)
        record = dict(before=before, after=after, marker=marker,
            before_file_sha256=hashlib.sha256(text.encode()).hexdigest(),
            after_file_sha256=hashlib.sha256(replaced.encode()).hexdigest(),
            scope='Select the existing non-MVS pthread_t branch before reversible body retirement.')
        (project / 'provenance/test-runner-pthread-spelling.json').write_text(json.dumps(record, indent=2) + '\n')
        path.write_text(replaced)
    elif not text.startswith(marker):
        raise ValueError('unrecognized pthread test source; review the adapter')
    subprocess.run([sys.executable, str(here.parent / 'jq-portable/refresh.py'), str(project),
        '--bindings', str(bindings)], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--bindings', type=Path, default=Path(__file__).with_name('portable-bindings.json'))
    args = parser.parse_args()
    assemble(args.project.resolve(), args.bindings.resolve())
