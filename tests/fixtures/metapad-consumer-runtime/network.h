#ifndef SPX_CONSUMER_RUNTIME_NETWORK_H
#define SPX_CONSUMER_RUNTIME_NETWORK_H
#include "state-machine-runtime.h"
typedef struct {uint32_t fault,value;} network_result;
void network_require(int,const char *);
uint32_t network_word(spx_runtime *,uint32_t);
network_result network_run_save(spx_runtime *,void *,spx_machine_state *,uint32_t);
network_result network_run_replace(spx_runtime *,void *,spx_machine_state *,uint32_t);
spx_step_result spx_sub_00005c2a(spx_runtime *,spx_machine_state *,uint32_t);
spx_step_result spx_sub_0000b18e(spx_runtime *,spx_machine_state *,uint32_t);
#endif
