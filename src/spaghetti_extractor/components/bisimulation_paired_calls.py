"""Ordered paired calls over the existing sparse current-memory world.

This is checker runtime, not a summary producer or an admission rule. The enclosing
boundary must validate the supplier's corresponding outcomes/effects and establish
argument representation, live views, private-frame separation and runtime premises.
Only then may it supply a shared candidate outcome and use this abstraction.

The original and ordinary-C bodies choose their own call paths. A finite trace
checks identity, scalar arguments and current public bytes before coupling each
result and post-memory. Nothing here supplies a callee body or a target algorithm.
"""


def paired_call_runtime(capacity: int, *, argument_capacity: int, object_capacity: int = 0,
                        object_byte_capacity: int = 64, object_observation_sites: bool = False,
                        terminal_outcomes: bool = False, code_targets: bool = False) -> list[str]:
    if type(capacity) is not int or not 1 <= capacity <= 64:
        raise ValueError('paired call capacity must be between 1 and 64')
    if type(argument_capacity) is not int or not 1 <= argument_capacity <= 32:
        raise ValueError('paired argument capacity must be between 1 and 32')
    if type(object_capacity) is not int or not 0 <= object_capacity <= 32:
        raise ValueError('paired object capacity must be between 0 and 32')
    if type(object_observation_sites) is not bool:
        raise ValueError('paired object observation partition must be Boolean')
    if type(terminal_outcomes) is not bool:
        raise ValueError('paired terminal outcomes must be Boolean')
    if type(code_targets) is not bool:
        raise ValueError('paired code targets must be Boolean')
    target_field = ' uint32_t code_target;\n' if code_targets else ''
    target_parameter = 'uint32_t code_target, ' if code_targets else ''
    target_record = '  record->code_target=code_target;\n' if code_targets else ''
    target_check = ('  __CPROVER_assert(record->code_target==code_target,"spx-paired-code-target");\n'
                    if code_targets else '')
    terminal_field = ', terminal' if terminal_outcomes else ''
    terminal_trace = ', terminated[2]' if terminal_outcomes else ''
    terminal_entry = (' __CPROVER_assert(trace->terminated[side]==0U,"spx-paired-call-after-termination");\n'
                      if terminal_outcomes else '')
    terminal_tag = ('  __CPROVER_assert(!original_outcome.fault || !original_outcome.terminal,"spx-paired-disjoint-outcomes");\n'
                    if terminal_outcomes else '')
    terminal_update = ' trace->terminated[side]=record->outcome.terminal;\n' if terminal_outcomes else ''
    terminal_finish = (' __CPROVER_assert(trace->terminated[0]==trace->terminated[1],"spx-paired-final-termination");\n'
                       if terminal_outcomes else '')
    object_fields = object_parameters = object_check = object_record = ''
    memory_compare = '''  if((uint64_t)trace->probe<trace->private_low || (uint64_t)trace->probe>=trace->private_high)
   __CPROVER_assert(record->byte==spx_mutable_byte(world,trace->probe),"spx-paired-current-input-memory");'''
    memory_update = ' spx_mutable_event(world,0U,UINT64_C(4294967296),0U,1U,position);'
    prefix = []
    if object_capacity:
        from .bisimulation_paired_objects import paired_object_runtime
        prefix = paired_object_runtime(object_capacity, object_byte_capacity,
                                       observation_sites=capacity if object_observation_sites else 0)
        object_fields = f' uint32_t object_count;struct spx_paired_object_snapshot objects[{object_capacity}];\n'
        object_parameters = ', struct spx_paired_object *objects,uint32_t object_count'
        object_check = ' spx_paired_objects_check(objects,object_count);\n'
        object_record = ('  record->object_count=object_count;\n'
            '  spx_paired_objects_record(record->objects,objects,object_count,world,trace->probe);\n')
        memory_compare = ('  __CPROVER_assert(record->object_count==object_count,"spx-paired-object-count");\n'
            '  spx_paired_objects_compare(record->objects,objects,object_count,world,trace->probe'
            + (',position' if object_observation_sites else '') + ');')
        memory_update = ' spx_paired_objects_update(record->objects,objects,object_count,world,position,side);'
    return prefix + f'''
struct spx_paired_outcome {{ uint32_t value, fault{terminal_field}; }};
struct spx_paired_record {{
 uint32_t service, argument_count, arguments[{argument_capacity}];
 uint8_t byte;
{object_fields}{target_field} struct spx_paired_outcome outcome;
}};
struct spx_paired_trace {{
 uint32_t count[2], faulted[2], source_phase, probe{terminal_trace};
 uint64_t private_low, private_high;
 struct spx_paired_record records[{capacity}];
}};
static struct spx_paired_outcome spx_paired_invoke(struct spx_paired_trace *trace,
 struct spx_mutable_world *world, uint32_t side, uint32_t service,
 const uint32_t *arguments, uint32_t argument_count,
 {target_parameter}struct spx_paired_outcome original_outcome{object_parameters}) {{
 __CPROVER_assert(side<=1U && side==trace->source_phase,"spx-paired-call-phase");
 __CPROVER_assume(side<=1U && side==trace->source_phase);
 __CPROVER_assert(trace->faulted[side]==0U,"spx-paired-call-after-fault");
{terminal_entry} __CPROVER_assert(argument_count<={argument_capacity}U,"spx-paired-argument-capacity");
 __CPROVER_assume(argument_count<={argument_capacity}U);
 __CPROVER_assert(trace->private_low<=trace->private_high &&
  trace->private_high<=UINT64_C(4294967296),"spx-paired-private-span");
 uint32_t position=trace->count[side]++;
 __CPROVER_assert(position<{capacity}U,"spx-paired-call-capacity");
 __CPROVER_assume(position<{capacity}U);
{object_check} struct spx_paired_record *record=&trace->records[position];
 if(side==0U) {{
  __CPROVER_assert(original_outcome.fault<=1U,"spx-paired-outcome-tag");
{terminal_tag}{target_record}  record->service=service;record->argument_count=argument_count;
  for(uint32_t i=0;i<argument_count;i++)record->arguments[i]=arguments[i];
  record->byte=spx_mutable_byte(world,trace->probe);
{object_record}  record->outcome=original_outcome;
 }}else{{
  __CPROVER_assert(position<trace->count[0],"spx-paired-original-call-present");
  __CPROVER_assume(position<trace->count[0]);
{target_check}  __CPROVER_assert(record->service==service,"spx-paired-service-order");
  __CPROVER_assert(record->argument_count==argument_count,"spx-paired-argument-count");
  for(uint32_t i=0;i<argument_count;i++)
   __CPROVER_assert(record->arguments[i]==arguments[i],"spx-paired-call-arguments");
{memory_compare}
 }}
 /* The byte function is indexed by actual invocation position, not service ID.
  * Repeated invocations may produce different contents at the same address.
  * Faulting invocations also retain their corresponding partial public effects. */
{memory_update}
 trace->faulted[side]=record->outcome.fault;
{terminal_update} return record->outcome;
}}
static void spx_paired_begin_source(struct spx_paired_trace *trace) {{
 __CPROVER_assert(trace->source_phase==0U && trace->count[1]==0U,"spx-paired-single-source-phase");
 trace->source_phase=1U;
}}
static void spx_paired_finish(const struct spx_paired_trace *trace) {{
 __CPROVER_assert(trace->source_phase==1U && trace->count[0]==trace->count[1],"spx-paired-complete-call-trace");
 __CPROVER_assert(trace->faulted[0]==trace->faulted[1],"spx-paired-final-outcome");
{terminal_finish}}}
'''.strip().splitlines()
