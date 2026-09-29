#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"
#include "case-unit.h"

int main(int argc, char **argv) {
  if (argc!=8 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
  uint32_t args[6];
  for (unsigned i=0;i<6;++i) {
    char *end; errno=0; unsigned long value=strtoul(argv[i+2],&end,10);
    if (errno || !*argv[i+2] || *end || value>UINT32_MAX) return 2;
    args[i]=(uint32_t)value;
  }
  if (args[1]>7 || args[2]>1 || args[3]>2 || args[4]>3 || args[5]>1) return 2;
  int source=!strcmp(argv[1],"source");
  dx_graphics *state=dx_setup(args[0],args[1],(int)args[2],args[3],args[4],args[5]);
  uint32_t results[4]={0}; unsigned count=0;
#if DX_CASE_UNIT == 0
  if (source) fixture_graphics_reset(state); else original_reset(state);
#elif DX_CASE_UNIT == 1
  /* The setter itself does not dereference or validate the handle. */
  if (source) fixture_graphics_bind(state,args[0]); else original_bind(state,args[0]);
#elif DX_CASE_UNIT == 2
  dx_seed_live_resources(state);
  if (source) results[count++]=fixture_graphics_blit(state,args[0]%255,19,37);
  else results[count++]=original_blit(state,args[0]%255,19,37);
#else
  results[count++]=source ? fixture_graphics_initialize(state) : original_initialize(state);
  results[count++]=state->current_surface;
  if (results[0]==1) {
    /* An explicit outside-scope loader supplies a live sprite object backed by
     * the newly created backbuffer. Both executions retain that same alias. */
    dx_load_sprite(state,args[0]%3,args[0]%255);
    if (source) {
      results[count++]=fixture_graphics_blit(state,args[0]%255,19,37);
      fixture_graphics_bind(state,state->backbuffer);
      results[count++]=fixture_graphics_blit(state,args[0]%255,71,13);
    } else {
      results[count++]=original_blit(state,args[0]%255,19,37);
      original_bind(state,state->backbuffer);
      results[count++]=original_blit(state,args[0]%255,71,13);
    }
  }
#endif
  if (source) dx_check_selected(DX_CASE_UNIT,count>0 && results[0]==1);
  dx_observe(state,results,count); return 0;
}
