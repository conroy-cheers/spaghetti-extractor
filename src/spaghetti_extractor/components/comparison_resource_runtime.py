"""Small C reference-token observer used by selected comparison adapters.

The table tracks instrumented references, not a global heap. Adapters own native
storage and supply object identity hints. Losing a reference is observed, never
silently repaired; resource exhaustion is an instrumentation limitation.
"""
from __future__ import annotations

import json


def runtime_header(capacity,frame_capacity):
    return f'''#ifndef SPX_COMPARISON_RESOURCES_H
#define SPX_COMPARISON_RESOURCES_H
#include <stdint.h>
#define SPX_RESOURCE_CAPACITY {capacity}u
#define SPX_RESOURCE_FRAME_CAPACITY {frame_capacity}u
typedef struct {{ uint32_t slot, generation; }} spx_resource_token;
uint32_t spx_resource_frame_enter(const char *contract_sha256);
void spx_resource_frame_leave(uint32_t frame);
uint32_t spx_resource_frame_checkpoint(void);
void spx_resource_frame_unwind(uint32_t checkpoint);
spx_resource_token spx_resource_acquire(uint64_t object);
uint32_t spx_resource_slot(spx_resource_token token);
uint32_t spx_resource_borrow(spx_resource_token token);
void spx_resource_consume(spx_resource_token token);
void spx_resource_retain(spx_resource_token token);
#endif
'''


def runtime_source(contracts):
    declarations=',\n'.join('  '+json.dumps(digest) for digest in contracts)
    return '''#include "comparison-resources.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *const contracts[] = {
'''+declarations+'''
};
static struct { uint32_t generation, owner; uint64_t object; int live; }
  tokens[SPX_RESOURCE_CAPACITY];
static struct { uint32_t id; const char *contract; }
  frames[SPX_RESOURCE_FRAME_CAPACITY];
static uint32_t depth, next_frame;
static void event(const char *kind, uint32_t count, uint32_t token,
                  uint32_t generation, uint64_t object) {
  if (!depth) { fputs("resource instrumentation has no active frame\\n", stderr); exit(78); }
  fprintf(stderr, "SPX_RESOURCE {\\"contract_sha256\\":\\"%s\\",\\"frame\\":%" PRIu32
    ",\\"event\\":\\"%s\\",\\"count\\":%" PRIu32 ",\\"token\\":%" PRIu32
    ",\\"generation\\":%" PRIu32 ",\\"object\\":%" PRIu64 "}\\n",
    frames[depth-1].contract, frames[depth-1].id, kind, count, token, generation, object);
}
static void fault(const char *kind, spx_resource_token token) {
  event(kind, 0, token.slot, token.generation, 0); exit(78);
}
uint32_t spx_resource_frame_enter(const char *contract) {
  int known=0;
  for (size_t i=0; i<sizeof(contracts)/sizeof(contracts[0]); ++i)
    if (!strcmp(contract,contracts[i])) known=1;
  if (!known) { fputs("resource instrumentation contract is unbound\\n",stderr); exit(78); }
  if (depth==SPX_RESOURCE_FRAME_CAPACITY || next_frame==UINT32_MAX)
    fault("frame-capacity",(spx_resource_token){0,0});
  frames[depth].id=++next_frame; frames[depth].contract=contract; ++depth;
  event("begin",0,0,0,0); return next_frame;
}
spx_resource_token spx_resource_acquire(uint64_t object) {
  if (!depth) { fputs("resource acquisition has no active frame\\n",stderr); exit(78); }
  for (uint32_t i=0; i<SPX_RESOURCE_CAPACITY; ++i) {
    if (!tokens[i].live) {
      if (tokens[i].generation==UINT32_MAX) fault("generation",(spx_resource_token){i+1,UINT32_MAX});
      ++tokens[i].generation; tokens[i].live=1;
      tokens[i].owner=frames[depth-1].id; tokens[i].object=object;
      event("acquire",0,i+1,tokens[i].generation,object);
      return (spx_resource_token){i+1,tokens[i].generation};
    }
  }
  fault("capacity",(spx_resource_token){0,0});
  return (spx_resource_token){0,0};
}
uint32_t spx_resource_slot(spx_resource_token token) {
  if (!token.slot || token.slot>SPX_RESOURCE_CAPACITY ||
      !tokens[token.slot-1].live || tokens[token.slot-1].generation!=token.generation)
    fault("expired",token);
  return token.slot-1;
}
uint32_t spx_resource_borrow(spx_resource_token token) {
  uint32_t slot=spx_resource_slot(token);
  event("borrow",0,token.slot,token.generation,tokens[slot].object);
  return slot;
}
void spx_resource_consume(spx_resource_token token) {
  uint32_t slot=spx_resource_slot(token);
  event("consume",0,token.slot,token.generation,tokens[slot].object);
  tokens[slot].live=0;
}
void spx_resource_retain(spx_resource_token token) {
  uint32_t slot=spx_resource_slot(token);
  if (!depth || tokens[slot].owner!=frames[depth-1].id) fault("wrong-frame",token);
  event("retained",1,token.slot,token.generation,tokens[slot].object);
  tokens[slot].owner=0;
}
static void frame_finish(uint32_t frame, const char *outcome) {
  if (!depth || frames[depth-1].id!=frame) fault("wrong-frame",(spx_resource_token){0,0});
  uint32_t count=0;
  for (uint32_t i=0; i<SPX_RESOURCE_CAPACITY; ++i) {
    if (tokens[i].live && tokens[i].owner==frame) {
      ++count;
      event("untransferred",1,i+1,tokens[i].generation,tokens[i].object);
      /* Preserve the lost native reference; diagnostics must not repair it. */
      tokens[i].owner=0;
    }
  }
  event(outcome,count,0,0,0); --depth;
}
void spx_resource_frame_leave(uint32_t frame) { frame_finish(frame,"end"); }
uint32_t spx_resource_frame_checkpoint(void) { return depth ? frames[depth-1].id : 0; }
void spx_resource_frame_unwind(uint32_t checkpoint) {
  int known=checkpoint==0;
  for (uint32_t i=0;i<depth;++i) if(frames[i].id==checkpoint) known=1;
  if (!known) fault("wrong-frame",(spx_resource_token){0,0});
  while (spx_resource_frame_checkpoint()!=checkpoint)
    frame_finish(frames[depth-1].id,"unwind");
}
'''
