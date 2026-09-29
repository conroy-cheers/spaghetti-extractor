"""Concrete handler scopes for adapter-delivered C nonlocal outcomes.

The adapter still performs the callback and setjmp/longjmp. This runtime records
its boundary and ends interrupted resource accounting without freeing objects or
relaxing allowances. The service reader checks every interrupted call's contract.
"""
from __future__ import annotations

import json


def nonlocal_outcomes(plan):
    units=[plan,*plan.get('dependencies',[])]
    return sorted({outcome for unit in units for contract in
        (unit.get('service_catalog') or {}).get('contracts',[])
        for outcome in contract['subject'].get('nonlocal_outcomes',[])})


def runtime_header(enabled):
    return '''#ifndef SPX_COMPARISON_SERVICES_H
#define SPX_COMPARISON_SERVICES_H
#include <stdint.h>
#define SPX_COMPARISON_NONLOCAL '''+str(int(enabled))+'''
/* Single-threaded adapter instrumentation. Catch only after the actual C jump.
 * Handler tokens name active invocations; each must end after normal or caught
 * completion. Pending calls must individually permit the observed outcome. */
uint32_t spx_service_handler_begin(void);
void spx_service_handler_catch(uint32_t handler, const char *outcome);
void spx_service_handler_end(uint32_t handler);
#endif
'''


def runtime_source(outcomes, resources=False):
    declarations=','.join(json.dumps(s) for s in outcomes)
    return '''#include "comparison-services.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
'''+('#include "comparison-resources.h"\n' if resources else '')+'''
static const char *const outcomes[] = {'''+declarations+'''};
static struct { uint32_t id, resource_frame; } handlers[256];
static uint32_t depth, next_handler;
static void fault(const char *message) {
  fprintf(stderr,"service handler instrumentation: %s\\n",message); exit(78);
}
static uint32_t resource_checkpoint(void) {
'''+('  return spx_resource_frame_checkpoint();' if resources else '  return 0;')+'''
}
static void event(uint32_t handler,const char *kind,const char *outcome) {
  fprintf(stderr,"SPX_SERVICE_HANDLER {\\"handler\\":%" PRIu32
    ",\\"event\\":\\"%s\\",\\"outcome\\":\\"%s\\"}\\n",handler,kind,outcome);
}
uint32_t spx_service_handler_begin(void) {
  if (depth==256 || next_handler==UINT32_MAX) fault("handler capacity exhausted");
  uint32_t id=++next_handler;
  handlers[depth].id=id;handlers[depth].resource_frame=resource_checkpoint();++depth;
  event(id,"begin","");return id;
}
void spx_service_handler_catch(uint32_t handler,const char *outcome) {
  if (!depth || handlers[depth-1].id!=handler) fault("catch is outside its active handler");
  int known=0;
  if (outcome) for (size_t i=0;i<sizeof(outcomes)/sizeof(outcomes[0]);++i)
    if (!strcmp(outcomes[i],outcome)) known=1;
  if (!known) fault("nonlocal outcome is undeclared");
'''+('  spx_resource_frame_unwind(handlers[depth-1].resource_frame);\n' if resources else '')+'''
  event(handler,"catch",outcome);
}
void spx_service_handler_end(uint32_t handler) {
  if (!depth || handlers[depth-1].id!=handler) fault("end is outside its active handler");
  if (resource_checkpoint()!=handlers[depth-1].resource_frame)
    fault("handler leaves pending resource frames");
  event(handler,"end","");--depth;
}
'''


def materialize_service_runtime(root,plan):
    outcomes=nonlocal_outcomes(plan)
    directories=[root/'generated',*[root/'dependencies'/u['id']/'generated' for u in plan.get('dependencies',[])]]
    for directory in directories:
        directory.mkdir(exist_ok=True,parents=True)
        (directory/'comparison-services.h').write_text(runtime_header(bool(outcomes)))
    if outcomes:
        from .comparison_resources import resource_contracts
        (root/'generated/comparison-services.c').write_text(runtime_source(outcomes,bool(resource_contracts(plan))))
