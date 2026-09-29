"""Trace warning inputs through actual preceding native frame operations."""
import argparse
import json
from pathlib import Path
import runpy

HERE=Path(__file__).resolve().parent
COMMON=runpy.run_path(str(HERE/'probe-residue.py'))
HOOKS={**COMMON['HOOKS'],**dict(elapsed=0xdb80,damage=0x1200,refresh_score=0x8740,
    move_paddle=0x6730,move_balls=0x4e80,move_shots=0x69c0,move_pickups=0x7420,
    move_trails=0x7bf0,wait=0x2240,restore_damage=0x1430,advance_effects=0x6020,
    draw_explosions=0x6e10,draw_warning=0x8ed0,present=0x1650,advance_stage=0x8b40)}
NAMES=['paddle','ball','pickup','particle-descriptor','partial-descriptor','ball-then-pickup',
    'ball-import-addresses','pickup-import-addresses']

def review_queue_result(result):
    if (result.get('kind')!='native-warning-queue-alias-experiment'
            or result.get('original_sha256')!=COMMON['PE_SHA256']
            or result.get('whole_program_run') is not False or result.get('authored_replacement_selected') is not False):
        raise ValueError('requires the pinned native queue-alias experiment')
    if {case['observation']['saved_byte'] for case in result['cases']}!={0,7} or len(result['cases'])!=2:
        raise ValueError('requires empty and nonempty saved-byte cases')
    for case in result['cases']:
        row=case['observation'];execution=case['execution'];present=int(row['saved_byte']!=0)
        if execution['returncode'] or execution['timed_out'] or execution.get('observation_error'):
            raise ValueError('incomplete queue-alias case')
        if (row['queue']!=[0,84] or row['address']!=0x42d0f0 or row['saved_byte_offset']!=760
                or row['active_board_nonzero']!=0 or row['allocations']!=present or row['voice_pending']!=present
                or row['event']!=([1,0,84,0,0] if present else [0]*5)):
            raise ValueError('saved-board alias did not reproduce')
    return dict(status='native-cross-object-read-reproduced',native_cases=2,
        actual_native_queue=True,source_queue_run_outside_contract=False,
        coordinate=[0,84],read_address='0x42d0f0',owner='saved-board-1-row-18-column-0',
        requirement='Preserve original-address reads and live aliases when widening the queue contract.')

def review_result(result):
    if (result.get('kind')!='native-warning-provenance-experiment'
            or result.get('original_sha256')!=COMMON['PE_SHA256']
            or result.get('whole_program_run') is not False or result.get('authored_replacement_selected') is not False):
        raise ValueError('requires the pinned native provenance experiment')
    rows={case['observation']['mode']:case['observation'] for case in result['cases']}
    if len(result['cases'])!=8 or set(rows)!=set(range(8)):raise ValueError('requires all eight producer cases')
    expected={0:[1,84,0],1:[0,120,2],2:[120,2,1],3:[120,2,3],4:[120,5,0],5:[120,2,1]}
    for mode in (6,7):
        ebp,esi=rows[mode]['incoming_ebp_esi']
        if not ebp or not esi:raise ValueError('unresolved native imports')
        expected[mode]=[0,esi,ebp] if mode==6 else [esi,ebp,1]
    for case in result['cases']:
        row=case['observation'];execution=case['execution'];mode=row['mode'];y,grid_row,column=expected[mode]
        if execution['returncode'] or execution['timed_out'] or execution.get('observation_error'):
            raise ValueError('incomplete producer case: '+case['id'])
        if (row['count_transition']!=[1,0,1] or row['entry_words']!=expected[mode]
                or row['queue']!=[column,grid_row] or row['explosion']!=[column,y]
                or row['warning_calls']!=[1,1,15]):raise ValueError('unexpected producer relationship: '+case['id'])
        if row['queue_within_grid']!=(column<20 and grid_row<20):raise ValueError('invalid grid classification')
        if row['queue_address']!=((0x42ca60+grid_row*20+column)&0xffffffff):raise ValueError('invalid native address')
    return dict(status='native-producers-and-grid-contract-gap-reproduced',native_cases=8,
        producers=['paddle-locals-and-saved-ebx','sprite-saved-registers','particle-descriptor-bytes'],
        outside_grid_cases=[NAMES[m] for m,row in rows.items() if not row['queue_within_grid']],
        native_entry_words_seeded=False,frame_entry_registers='explicit-values-or-live-import-addresses',
        queue_body='controlled-observer-only',portable_state_provider='not-established',
        whole_program_run=False,replacement_equivalence='not-assessed')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original',type=Path,nargs='?');parser.add_argument('output',type=Path,nargs='?')
    parser.add_argument('--review',type=Path);parser.add_argument('--queue-alias',action='store_true')
    args=parser.parse_args()
    if args.review:
        if args.original or args.output:parser.error('--review does not take execution paths')
        result=json.loads(args.review.read_text())
        review=review_queue_result if result.get('kind')=='native-warning-queue-alias-experiment' else review_result
        print(json.dumps(review(result),indent=2))
    else:
        if not args.original or not args.output:parser.error('original and output are required')
        if args.queue_alias:
            options=dict(source=HERE/'queue-alias.c',hooks={**COMMON['HOOKS'],'allocate':0xdf40},
                scenarios=[('saved-empty',['0']),('saved-nonempty',['7'])],
                kind='native-warning-queue-alias-experiment',review=review_queue_result)
        else:
            options=dict(source=HERE/'frame-provenance.c',hooks=HOOKS,
                scenarios=[(name,[str(i)]) for i,name in enumerate(NAMES)],
                kind='native-warning-provenance-experiment',review=review_result)
        COMMON['run'](args.original.resolve(),args.output.resolve(),
            extra_sources={'entry-residue.c':HERE/'entry-residue.c'},**options)
