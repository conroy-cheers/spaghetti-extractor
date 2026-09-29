"""Compare owned music resource assembly with retained native loader results."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_view(observed):
    """Project the existing PE32 observation onto the declared MDS C views."""
    if observed['results'] != [0] or len(observed['infos']) != 1:
        raise ValueError('expected one successful native load')
    record, = observed['infos']
    info = record['info']
    allocation, = observed['buffers']
    if not record['live'] or allocation['state'] != [info[4], len(bytes.fromhex(allocation['bytes'])), 1, 1]:
        raise ValueError('native loader did not retain locked owned storage')
    raw = bytes.fromhex(allocation['bytes'])
    buffers = []
    for i in range(info[7]):
        offset = i * (info[2] + 64)
        data, capacity, used, owner, flags, following = struct.unpack_from('<6I', raw, offset)
        if data != 0x10000000 + info[4] * 0x100000 + offset + 64 or owner != 0x90000000 + record['identity'] or following:
            raise ValueError('native header has a different payload or owner relationship')
        if used > capacity or offset + 64 + used > len(raw):
            raise ValueError('native header exceeds storage')
        buffers.append(dict(capacity=capacity, used=used, flags=flags,
                            payload=raw[offset+64:offset+64+used].hex()))
    return dict(result=0, info=info[:4]+info[5:],
                expand_calls=info[7] if info[3] & 1 else 0, buffers=buffers)


def check(project, assets, runner):
    executable = project/'program-resources-check'
    cases_file = project/'mds-loader-cases.json'
    cases = [case for case in json.loads(cases_file.read_text()) if case['id'].startswith('asset-')]
    if len(cases) != 12:
        raise ValueError('expected file and memory observations for six bundled MDS inputs')
    results, inputs = [], {cases_file.name: digest(cases_file)}
    for case in cases:
        mode, name = case['id'].removeprefix('asset-').split('-', 1)
        path = assets/name
        observed = case['expected']['mds_loader']
        if path.read_bytes() != bytes.fromhex(observed['input']):
            raise ValueError('retained input changed: '+name)
        inputs[str(path)] = digest(path)
        run = subprocess.run([*([str(runner)] if runner else []), str(executable), mode, str(path)],
                             capture_output=True, text=True, timeout=15)
        if run.returncode:
            raise ValueError(case['id']+': resource load failed: '+run.stderr[-2000:])
        actual, expected = json.loads(run.stdout), native_view(observed)
        if actual != expected:
            raise ValueError(case['id']+': owned resource metadata or event bytes differ')
        results.append(dict(case=case['id'], buffers=len(actual['buffers']),
                            event_bytes=sum(buffer['used'] for buffer in actual['buffers']),
                            observation_sha256=hashlib.sha256(run.stdout.encode()).hexdigest()))
    result = dict(status='match', authorizing=False,
        scope='Owned loader/parser/event composition: six immutable music assets in file and memory modes, '
              'including payload bytes, header ownership and input lifetime. File mode enters through music_load. '
              'Excludes playback, malformed inputs, allocation failure histories and general Win32 mapping semantics.',
        inputs=inputs, executable_sha256=digest(executable), cases=results)
    (project/'program/resources-validation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(f'{len(results)} native music-resource observations match through the owned C assembly.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('assets', type=Path)
    parser.add_argument('--runner', type=Path)
    args = parser.parse_args()
    check(args.project.resolve(), args.assets.resolve(), args.runner)
