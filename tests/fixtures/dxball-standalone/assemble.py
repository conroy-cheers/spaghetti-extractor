"""Connect program-owned state, startup and scenes in a source selection."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges


HERE = Path(__file__).resolve().parent


def untraced_program_headers(project, selection):
    """Match existing choices in batches; the reader validates the whole export."""
    pending = {identity: iter(reference['service_bridge']
                             for reference in unit['comparison_binding_references']
                             if reference.get('service_bridge') is not None)
               for identity, unit in selection['components'].items() if unit['required_services']}
    headers = {identity: (project/'bridges'/identity/'comparison-service-bridge.h').read_text()
               for identity in pending}
    bindings = {}
    while pending:
        choices = {identity: next(references, None) for identity, references in pending.items()}
        for identity, choice in choices.items():
            if choice is None:
                raise ValueError('review the changed service binding before selecting program tracing: '+identity)
        rendered = render_source_service_bridges(project/'lifted', bindings=choices)
        for identity, (header, _) in rendered.items():
            if header == headers[identity]:
                bindings[identity] = choices[identity]
                del pending[identity]
    return render_source_service_bridges(project/'lifted', bindings=bindings, trace_services=False) if bindings else {}


def program_bridges(project, selection, trace_services):
    """Keep local comparison consumers traced; normal execution has its own objects.

    Reuse only the exact already-selected service header. Binding references are
    not an automatic backend choice, and a hand-edited header needs fresh review.
    """
    objects = []
    rules = []
    makefile = (project/'Makefile').read_text()
    rendered = {} if trace_services else untraced_program_headers(project, selection)
    for identity, unit in sorted(selection['components'].items()):
        if trace_services or not unit['required_services']:
            objects.append('build/'+identity+'.o')
            continue
        existing = project/'bridges'/identity
        base = Path('program/bridges')/identity
        (project/base).mkdir(parents=True, exist_ok=True)
        for name, text in [('bridge.c', (existing/'bridge.c').read_text()),
                           ('comparison-service-bridge.h', rendered[identity][0])]:
            path = project/base/name
            if not path.exists() or path.read_text() != text:
                path.write_text(text)
        obj = 'build/program-bridge-'+identity+'.o'
        objects.append(obj)
        # The reviewed bridge can have additional include directories or flags.
        # Retain that compile recipe instead of reconstructing it from the export.
        original = 'build/'+identity+'.o'
        matches = re.findall(r'^'+re.escape(original)+r':[^\n]*\n(?:\t[^\n]*\n)+', makefile, re.M)
        if len(matches) != 1:
            raise ValueError('expected one existing bridge build rule: '+original)
        rule = obj+matches[0][len(original):]
        rule = re.sub(re.escape('bridges/'+identity)+r'(?=/|\s|$)', str(base), rule)
        rules.append(rule)
    return ' '.join(objects), '\n'.join(rules)


def assemble(project, image, *, trace_services=False):
    destination = project/'program'
    destination.mkdir(exist_ok=True)
    for name in ['program-state.h', 'program-state.c', 'startup-bindings.c',
                 'file-bindings.c', 'startup-check.c', 'flow-bindings.c',
                 'scene-bindings.c', 'menu-bindings.c', 'screen-bindings.c',
                 'editor-bindings.c', 'menu-input.c', 'title-input.c', 'input-check.c',
                 'gameplay-bindings.c', 'damage-bindings.c', 'library-bindings.c',
                 'round-clear.c', 'ownership-check.c', 'audio-bindings.c',
                 'mds-storage.h', 'mds-storage.c', 'mds-files.c', 'mds-bindings.c', 'resources-check.c',
                 'file-storage.h', 'resource-files.c', 'reader-entry.c', 'memory-bindings.c',
                 'win32-platform.h', 'win32-window.c', 'win32-draw.c', 'win32-sound.c', 'win32-midi.c', 'win32-entry.c',
                 'midi-check.c', 'check-midi.py', 'desktop-actions.txt',
                 'desktop-paused-actions.txt', 'desktop-editor-actions.txt',
                 'desktop-scores-actions.txt']:
        shutil.copyfile(HERE/name, destination/name)
    shutil.copyfile(HERE/'WINDOWS.md', project/'WINDOWS.md')
    shutil.copyfile(HERE.parent/'dxball-warning/history.h', destination/'warning-history.h')
    spec = importlib.util.spec_from_file_location('dxball_program_seed', HERE/'prepare-state.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.prepare(image, destination)
    # These are the existing comparison entry counters, not missing application
    # methods. Keep optional runtime diagnostics in the normal-entry project.
    hooks = {}
    for path in (project/'common').rglob('*.h'):
        for name, argument in re.findall(r'^void (\w+_enter)\((void|unsigned(?: \w+)?)\);', path.read_text(), re.M):
            shape = 'void' if argument == 'void' else 'unsigned'
            if name in hooks and hooks[name] != shape:
                raise ValueError('entry observer signature conflict: '+name)
            hooks[name] = shape
    observer = '#include <stdio.h>\n#include <stdint.h>\n'
    for name, argument in sorted(hooks.items()):
        observer += f'static uint64_t count_{name};\n'
        if argument == 'void':
            observer += f'void {name}(void) {{ ++count_{name}; }}\n'
        else:
            observer += f'void {name}(unsigned operation) {{ (void)operation; ++count_{name}; }}\n'
    observer += 'void dxball_program_observe_entries(FILE *output) {\n  fputs("{", output);\n'
    for i, name in enumerate(sorted(hooks)):
        fmt = (',' if i else '') + json.dumps(name) + ':%llu'
        observer += '  fprintf(output, '+json.dumps(fmt)+f', (unsigned long long)count_{name});\n'
    observer += '  fputs("}", output);\n}\n'
    (destination/'entry-observers.c').write_text(observer)
    selection = json.loads((project/'lifted/source-export.json').read_text())
    bridges, bridge_rules = program_bridges(project, selection, trace_services)
    makefile = project/'Makefile'
    text = makefile.read_text()
    marker = '# Program-owned state and startup assembly\n'
    if marker in text:
        text = text.split(marker, 1)[0]
    text += marker + '''program-objects = build/program-state.o build/program-startup.o build/program-files.o \\
    build/program-flow.o build/program-scene.o build/program-menu.o build/program-screen.o \\
    build/program-editor.o build/program-menu-input.o build/program-title-input.o \\
    build/program-gameplay.o build/program-damage.o build/program-library.o build/program-round-clear.o build/program-audio.o \\
    build/program-mds-storage.o build/program-mds-files.o build/program-mds.o \\
    build/program-resource-files.o build/program-reader-entry.o build/program-memory.o
program-state: libprogram-state.a
libprogram-state.a: $(program-objects)
\t$(AR) rcs $@ $(program-objects)
build/program-state.o: program/program-state.c program/program-state.h program/program-seed.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-startup.o: program/startup-bindings.c program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-files.o: program/file-bindings.c program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-startup-check.o: program/startup-check.c program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -MMD -MP -c $< -o $@
program-startup-check: build/program-startup-check.o libprogram-state.a build/score-table.o build/board-data.o build/math-support.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) -Wl,--gc-sections build/program-startup-check.o -Wl,--start-group libprogram-state.a build/score-table.o build/board-data.o build/math-support.o lifted/liblifted.a -Wl,--end-group -lm -o $@
build/program-%.o: program/%-bindings.c program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-menu-input.o: program/menu-input.c program/program-state.h lifted/components/menu-scene/sources/generated/portable-component-implementation.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -Ilifted/components/menu-scene/sources/generated -MMD -MP -c $< -o $@
build/program-title-input.o: program/title-input.c program/program-state.h lifted/components/title-scene/sources/generated/portable-component-implementation.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -Ilifted/components/title-scene/sources/generated -MMD -MP -c $< -o $@
build/program-input-check.o: program/input-check.c program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -MMD -MP -c $< -o $@
program-input-check: build/program-input-check.o libprogram-state.a lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/program-input-check.o -Wl,--start-group libprogram-state.a lifted/liblifted.a -Wl,--end-group -o $@
build/program-damage.o: program/damage-bindings.c program/program-state.h lifted/components/damage-tracking/sources/generated/portable-component-implementation.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Icommon -Iprogram -Ilifted/components/damage-tracking/sources/generated -MMD -MP -c $< -o $@
build/program-round-clear.o: program/round-clear.c program/program-state.h lifted/components/round-cleanup/sources/generated/portable-component-implementation.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -Ilifted/components/round-cleanup/sources/generated -MMD -MP -c $< -o $@
build/program-ownership-check.o: program/ownership-check.c program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -MMD -MP -c $< -o $@
program-ownership-check: build/program-ownership-check.o libprogram-state.a lifted/liblifted.a
\t$(CC) $(LDFLAGS) -Wl,--gc-sections build/program-ownership-check.o -Wl,--start-group libprogram-state.a lifted/liblifted.a -Wl,--end-group -o $@
build/program-mds-storage.o: program/mds-storage.c program/mds-storage.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-mds-files.o: program/mds-files.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-resources-check.o: program/resources-check.c program/program-state.h program/mds-storage.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -MMD -MP -c $< -o $@
program-resources-check: build/program-resources-check.o libprogram-state.a build/mds-loader.o build/mds-parser.o build/mds-events.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) -Wl,--gc-sections build/program-resources-check.o -Wl,--start-group libprogram-state.a build/mds-loader.o build/mds-parser.o build/mds-events.o lifted/liblifted.a -Wl,--end-group -o $@
build/program-resource-files.o: program/resource-files.c program/file-storage.h program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-reader-entry.o: program/reader-entry.c program/file-storage.h lifted/components/file-reader/sources/generated/portable-component-implementation.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Iprogram -Ilifted/components/file-reader/sources/generated -MMD -MP -c $< -o $@
'''
    text += bridge_rules+'\n# Normal program service tracing: '+('on' if trace_services else 'off')+'\n'
    text += 'desktop-bridges = '+bridges+'\n'
    text += 'WINDRES ?= $(patsubst %gcc,%windres,$(CC))\n'
    text += 'midi-program-bridges = '+' '.join(obj for obj in bridges.split()
        if obj.endswith(('mds-stream.o', 'mds-loader.o', 'mds-parser.o', 'mds-events.o')))+'\n'
    text += '''win32-objects = build/program-win32-entry.o build/program-win32-window.o build/program-win32-draw.o \\
    build/program-win32-sound.o build/program-win32-midi.o build/program-entry-observers.o
build/program-win32-%.o: program/win32-%.c program/win32-platform.h program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Icommon -Iprogram -MMD -MP -c $< -o $@
build/program-entry-observers.o: program/entry-observers.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -MMD -MP -c $< -o $@
build/program-resources.o: program/windows-resources.rc program/icon-image.bin program/icon-group.bin
\t@mkdir -p build
\t$(WINDRES) -Iprogram -i $< -o $@ -O coff
dxball.exe: Makefile $(win32-objects) build/program-resources.o libprogram-state.a $(desktop-bridges) lifted/liblifted.a
\t$(CC) $(LDFLAGS) -static -mwindows $(win32-objects) build/program-resources.o -Wl,--start-group libprogram-state.a $(desktop-bridges) lifted/liblifted.a -Wl,--end-group -lddraw -ldsound -lwinmm -lgdi32 -luser32 -lm -o $@
build/program-midi-check.o: program/midi-check.c program/win32-midi.c program/win32-platform.h program/program-state.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -ffunction-sections -fdata-sections -Icommon -Iprogram -MMD -MP -c $< -o $@
program-midi-check.exe: build/program-midi-check.o build/program-entry-observers.o libprogram-state.a $(midi-program-bridges) $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) -static -Wl,--gc-sections build/program-midi-check.o build/program-entry-observers.o -Wl,--start-group libprogram-state.a $(midi-program-bridges) lifted/liblifted.a -Wl,--end-group $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) -lddraw -ldsound -lwinmm -luser32 -o $@
'''
    makefile.write_text(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('image', type=Path)
    parser.add_argument('--trace-services', action='store_true', help='retain full service protocol traces in the normal program')
    args = parser.parse_args()
    assemble(args.project.resolve(), args.image.resolve(), trace_services=args.trace_services)
