"""Prepare the binary-derived title scene with existing shared-state components."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

import pefile

HERE = Path(__file__).resolve().parent
TITLE = HERE.parent/'dxball-title-animation'
spec = importlib.util.spec_from_file_location('scene_title_preparation', TITLE/'prepare.py')
title = importlib.util.module_from_spec(spec); spec.loader.exec_module(title)
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

RANGES = dict(enter=(0xa0b0, 0xa1fa), redraw=(0xa200, 0xa50e), update=(0xa510, 0xa5e1),
    key=(0xa5f0, 0xa605), leave=(0xa610, 0xa6ba))
TYPES = [*title.TYPES, dict(id='scene_state', kind='opaque', nominal_id='dxball.scene.state'),
    dict(id='asset_name', kind='opaque', nominal_id='dxball.asset.name')]
SURFACE = 'cleanup_surface'
SERVICES = dict(reset_damage=[], clear=[('surface', SURFACE), ('color', 'u32')],
    image=[('surface', SURFACE), ('name', 'asset_name'), ('palette', 'u32'), ('x', 'u32'), ('y', 'u32')],
    load_bank=[('bank', 'u32'), ('mode', 'u32'), ('name', 'asset_name')],
    select_bank=[('bank', 'u32')], select_font=[('bank', 'u32')],
    load_sound=[('slot', 'u32'), ('name', 'asset_name')], damage_background=[('surface', SURFACE)],
    damage_destination=[('surface', SURFACE)], color_key=[('surface', SURFACE), ('low', 'u32'), ('high', 'u32')],
    redraw_scene=[], play_sound=[('slot', 'u32'), ('a', 'u32'), ('b', 'u32'), ('c', 'u32')],
    fade=[('wait', 'u32'), ('step', 'u32'), ('first', 'u32'), ('last', 'u32'), ('direction', 'u32')],
    fill=[('surface', SURFACE), ('x1', 'u32'), ('y1', 'u32'), ('x2', 'u32'), ('y2', 'u32'), ('color', 'u32')],
    blit=[('destination', SURFACE), ('dr', 'font_rect'), ('source', SURFACE), ('sr', 'font_rect'), ('flags', 'u32')],
    wobble=[], scroll=[], wave=[], cycle=[],
    line=[('surface', SURFACE), ('x1', 'u32'), ('y1', 'u32'), ('x2', 'u32'), ('y2', 'u32'), ('color', 'u32')],
    sprite_destination=[('surface', SURFACE)],
    text=[('x', 'u32'), ('y', 'u32'), ('length', 'u32'), ('bytes', 'font_bytes')],
    center=[('x', 'u32'), ('y', 'u32'), ('length', 'u32'), ('bytes', 'font_bytes')],
    wait=[('count', 'u32')], restore_damage=[], present=[],
    rotate_palette=[('first', 'u32'), ('count', 'u32')], stop_sound=[('slot', 'u32')],
    release_banks=[], release_sounds=[], release_track=[])
USED = dict(enter=['reset_damage', 'clear', 'image', 'load_bank', 'select_bank', 'select_font', 'load_sound',
    'damage_background', 'damage_destination', 'color_key', 'redraw_scene', 'play_sound', 'fade'],
    redraw=['clear', 'fill', 'blit', 'damage_destination', 'wobble', 'line', 'sprite_destination', 'select_font', 'text', 'center'],
    update=['play_sound', 'wait', 'restore_damage', 'scroll', 'wave', 'present', 'rotate_palette', 'cycle'],
    key=[], leave=['stop_sound', 'fade', 'clear', 'blit', 'release_banks', 'release_sounds', 'release_track'])
# Only the controlled service entries need interception; selected callee bodies
# retain their previously checked ranges. Eight bytes covers relocated prefixes.
HOOKS = dict(reset_damage=0x1000, clear=0x2710, image=0x2490, load_bank=0xc080,
    load_sound=0x3000, damage_background=0x1630, damage_destination=0x1640, redraw_scene=0xaad0,
    play_sound=0x32b0, fade=0x2770, fill=0xd990, line=0xd850, wait=0x2240,
    restore_damage=0x1430, present=0x1650, rotate_palette=0x2ba0, stop_sound=0x3370,
    release_sounds=0x2f90, release_track=0x2200)
TEXT = dict(video_card=(0x4178d4,11), no_hardware=(0x4178b8,24), low_memory=(0x4178a4,16),
    high_refresh=(0x417888,25), compatible=(0x417868,28), hardware=(0x41784c,27), supported=(0x41783c,13),
    author=(0x417834,7), author_name=(0x417820,16), graphics=(0x417818,7), graphics_name=(0x417808,14),
    email=(0x417800,7), email_address=(0x4177e8,21), website=(0x4177bc,43), website_info=(0x417790,41))
C_TYPES = dict(u32='uint32_t', scene_state='scene_state *', cleanup_surface='font_surface *',
    font_rect='font_rect *', font_bytes='font_bytes *', asset_name='asset_name *')


def bridge_spec():
    return dict(adapters={name: dict(symbol='scene_'+name, kind='portable', context=True,
        outcomes={'return': None}) for name in SERVICES}, transports={}, native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "scene-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for number, name in enumerate(RANGES):
        parameter = ', uint32_t value' if name in ('key', 'leave') else ''
        argument = ', value' if parameter else ''
        text += f'''void fixture_scene_{name}(scene_state *state{parameter}) {{
    scene_enter({number});
    spx_title_scene_services_v5 services = spx_title_scene_bind_services(NULL);
    spx_title_scene_context_v5 context = {{0}}; context.services = &services;
    spx_title_scene_services_begin(); lifted_scene_{name}(&context, state{argument}); spx_title_scene_services_end();
}}
'''
    return text


def runtime_header():
    text = '#ifndef DXBALL_SCENE_RUNTIME_H\n#define DXBALL_SCENE_RUNTIME_H\n#include "scene-state.h"\nvoid scene_enter(unsigned);\n'
    for name in RANGES:
        text += 'void fixture_scene_'+name+'(scene_state *'+(', uint32_t' if name in ('key', 'leave') else '')+');\n'
    for name, parameters in SERVICES.items():
        text += 'void scene_'+name+'(void *, scene_state *'+''.join(', '+C_TYPES[t] for _, t in parameters)+');\n'
    return text+'#endif\n'


def cases():
    return [dict(id='scene-mode-'+str(mode), arguments=[str(17+mode), str(mode)]) for mode in range(12)]


def prepare(original, animation, output):
    started = time.monotonic()
    if sha256_file(original) != title.font.cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True, exist_ok=False)
    definitions = {name: ServiceDefinition.create(identity='dxball.scene.'+name, types=TYPES,
        parameters=[('state', 'scene_state'), *parameters], result='unit', resources=[],
        effects=['dxball.scene.'+name], outcomes=['return'], unobserved=['Shared objects and synchronous service contract in BOUNDARY.md.'])
        for name, parameters in SERVICES.items()}
    interface = component_interface(component_id='title-scene', types=TYPES, services=definitions,
        operations={name: OperationDefinition([('state', 'scene_state')]+([('value', 'u32')] if name in ('key', 'leave') else []),
            'unit', USED[name]) for name in RANGES})
    catalog = service_catalog(definitions).to_payload()
    write_json(output/'interface.json', interface.to_payload()); write_json(output/'services.json', catalog)
    write_json(output/'bridge.json', bridge_spec()); (output/'bridge.c').write_text(bridge())
    (output/'scene-runtime.h').write_text(runtime_header())
    binary = pefile.PE(str(original)); text = '/* Explicit display spans recovered from the pinned PE data. */\n'
    for name, (address, length) in TEXT.items():
        data = binary.get_data(address-0x400000, length)
        text += 'static const unsigned char scene_text_'+name+'[] = {'+','.join(str(b) for b in data)+'};\n'
    (output/'scene-text.h').write_text(text)
    sources = {p.name:p for p in (animation/'source').iterdir() if p.is_file() and p.suffix == '.h'}
    sources.update({'scene.c':HERE/'scene.c', 'scene-state.h':HERE/'scene-state.h', 'scene-text.h':output/'scene-text.h'})
    command = ['component', 'start', 'dxball', 'title-scene', '--interface-intent', str(output/'interface.json'),
        '--service-catalog', str(output/'services.json'), '--service-bridge', str(output/'bridge.json'),
        '--assumption-file', str(HERE/'BOUNDARY.md'), '--remove-source', 'source/component.c', '--output', str(output/'authoring')]
    for name in RANGES: command += ['--operation-symbol', name+'=lifted_scene_'+name]
    for name, path in sources.items(): command += ['--source-file', 'source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *command], capture_output=True, text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    header = (animation/'headers/native-image.h').read_text()+'\n'
    entries = {**{'scene_'+name:span for name,span in RANGES.items()}, **{'service_'+name:(rva,rva+8) for name,rva in HOOKS.items()}}
    header += '\n'.join(native_entry_header(original=original, expected_sha256=title.font.cleanup.PE_SHA256,
        module=None, entry_rva=lo, end_rva=hi, installer='install_'+name) for name,(lo,hi) in entries.items())
    (output/'native-image.h').write_text(header)
    includes = {p.relative_to(animation/'headers').as_posix():p for p in (animation/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h', 'scene-runtime.h':output/'scene-runtime.h',
        'scene-native.h':HERE/'scene-native.h', 'title-runtime.c':TITLE/'runtime.c'})
    environment = native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_scene_'+name for name in RANGES}, target_id='dxball', component_id='title-scene',
        adapter_files={'runtime.c':HERE/'runtime.c', 'bridge.c':output/'bridge.c'}, include_files=includes,
        **{**environment, 'runtime_files':{**environment['runtime_files'], 'DXBall.exe':original}},
        original_files=['runtime/DXBall.exe'], oracle_kind='native-original', cases=cases(),
        observation_fields=['scene_state', 'objects'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()], scope='Real title scene bodies with connected animation/font/cleanup and controlled platform services.',
        service_catalog=catalog, service_bridge=bridge_spec(), **bind_dependencies(consumers={'animation-consumer':animation}),
        export_adapters=['adapters/bridge.c'], program_driver=dict(kind='pe32-import', image='runtime/DXBall.exe',
            library='dx-scene.dll', symbol='dx_scene_anchor'), output=output/'title-scene')
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, cases=len(cases()),
        original_source_consulted=False, tool_internal_changes=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'animation', 'output'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); prepare(args.original.resolve(), args.animation.resolve(), args.output.resolve())
