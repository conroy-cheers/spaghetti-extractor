/* Conditional growth-return -> clearing-call region of the real operation.
 * Connected mode starts at actual entry and checks the normal clear return and
 * persistent count publication at the real selected-slot barrier.
 * Allocation/liveness and successful growth are premises, not established here.
 * Array lengths remain symbolic; only the finite byte-effect history is bounded. */
#include "behavioral-c.h"
#include "portable-component-implementation.h"
#include "quote-objects.h"
#ifdef SPX_GROWTH_CONNECTED
static void check_growth_continuation(struct spx_opaque_quote_state_v5 *,
 struct spx_opaque_quote_table_v5 *,uint32_t,uint32_t,
 struct spx_opaque_quote_bytes_v5 *,uint32_t,struct spx_opaque_quote_options_v5 *);
#endif
#include "quote-slots.c"
#include "sparse-memory.h"

typedef struct spx_opaque_quote_table_v5 Slot;
typedef struct spx_opaque_quote_word_v5 Word;
/* Effects are meaningful only for the checked call domain. Retain every domain
 * assertion as a required obligation before using it in subsequent queries;
 * language-safety partitions disable assertions, but must not model effects of
 * an invalid service call as if that call had passed the separate check. */
#define CHECK_GROWTH_CALL(condition,label) do { \
 uint32_t call_domain_ok=(condition); \
 __CPROVER_assert(call_domain_ok,label); \
 __CPROVER_assume(call_domain_ok); \
} while(0)
static struct spx_mutable_world incoming,left,right;
static uint32_t old_address,new_address,old_count,new_count,index_value,stack_base,probe;
static uint32_t arguments[3],clear_calls,preallocated,old_buffer,published_table;
static uint8_t before_clear,post_growth;
static Slot old_slot,new_slot;
#ifdef SPX_GROWTH_CONNECTED
static uint32_t argument_word,size_word,options_word,errno_address,errno_target;
static uint32_t original_words[14],initialized[14],growth_arguments[5];
static uint32_t errno_calls,growth_calls,published_count;
static uint32_t continuation_witness;
static spx_machine_state entry_machine,final_machine;
#define PRIVATE_EXTENT 116U
#include "local-record-transport.h"
#else
#define PRIVATE_EXTENT 80U
#endif
#ifdef SPX_GROWTH_RECORD_SNAPSHOTS
#include "record-transport.h"
#define initial_slot spx_record_object_0[0]
#define source_state spx_record_projection_0
#else
static Slot initial_slot;
static struct spx_opaque_quote_state_v5 source_state;
static uint8_t buffer_identity;
#endif
spx_step_result spx_sub_00004eb3(spx_runtime *,spx_machine_state *,uint32_t);

static uint32_t disjoint(uint32_t a,uint64_t n,uint32_t b,uint64_t m){
 return !n || !m || (uint64_t)a+n<=b || (uint64_t)b+m<=a;
}
static uint32_t contains(uint32_t a,uint64_t n,uint32_t p){
 return p>=a && (uint64_t)p-a<n;
}
static uint32_t word(const struct spx_mutable_world *world,uint32_t address){
 uint32_t result=0U;
 for(uint32_t i=0U;i<4U;i++)result|=(uint32_t)spx_mutable_byte(world,address+i)<<(8U*i);
 return result;
}
static void admit(void){
 uint32_t arbitrary[7];
 old_address=arbitrary[0];new_address=arbitrary[1];old_count=arbitrary[2];new_count=arbitrary[3];
 index_value=arbitrary[4];stack_base=arbitrary[5];probe=arbitrary[6];
 __CPROVER_assume(old_address && new_address && old_count<=index_value && index_value<new_count);
 __CPROVER_assume((uint64_t)new_address+8ULL*new_count<=UINT64_C(4294967296));
 /* A checked consequence of the existing nonwrapping slot span, not a new
  * input restriction. Expose the exact original/C invalid-index threshold so
  * later safety queries need not rederive it through the complete history. */
 __CPROVER_assert(index_value<0x7fffffffU,"growth-memory-valid-index");
 __CPROVER_assume(index_value<0x7fffffffU);
 __CPROVER_assume((uint64_t)old_address+8ULL*old_count<=UINT64_C(4294967296));
 __CPROVER_assume(stack_base<=UINT64_C(4294967296)-PRIVATE_EXTENT);
 preallocated=old_address==0x420054U;
 __CPROVER_assume(!preallocated || old_count==1U);
 __CPROVER_assume(preallocated || disjoint(old_address,8ULL*old_count,0x420050U,16U));
 __CPROVER_assume(disjoint(new_address,8ULL*new_count,0x420050U,16U));
 __CPROVER_assume(new_address==old_address || disjoint(new_address,8ULL*new_count,old_address,8ULL*old_count));
 __CPROVER_assume(disjoint(stack_base,PRIVATE_EXTENT,0x420050U,16U));
 __CPROVER_assume(disjoint(stack_base,PRIVATE_EXTENT,old_address,8ULL*old_count));
 __CPROVER_assume(disjoint(stack_base,PRIVATE_EXTENT,new_address,8ULL*new_count));
 __CPROVER_assume(word(&incoming,0x42005cU)==old_count);
 spx_mutable_event(&incoming,0x420050U,4U,old_address,0U,0U);
 published_table=old_address;
#ifdef SPX_GROWTH_CONNECTED
 uint32_t inputs[5];argument_word=inputs[0];size_word=inputs[1];options_word=inputs[2];
 errno_address=inputs[3];errno_target=inputs[4];
 __CPROVER_assume(stack_base>=4U && errno_address && errno_address<=UINT32_MAX-3U && errno_target);
 __CPROVER_assume(disjoint(stack_base,PRIVATE_EXTENT,0x4321e4U,4U));
 __CPROVER_assume(disjoint(stack_base,PRIVATE_EXTENT,errno_address,4U));
 /* Entry import contents are part of incoming memory, including aliases with
  * the returned cell. The target is captured before growth may change it. */
 __CPROVER_assume(word(&incoming,0x4321e4U)==errno_target);
 published_count=old_count;
#endif
}
/* This is the required successful service contract, not a proof of xpalloc.
 * In-place extension retains old bytes. Relocation copies them before release.
 * New bytes are arbitrary; clearing them is the caller's responsibility. */
static void growth_effect(struct spx_mutable_world *world){
 if(!preallocated && new_address!=old_address)
  spx_mutable_copy(world,new_address,old_address,8ULL*old_count);
 uint64_t end=(uint64_t)new_address+8ULL*old_count;
 /* Other public bytes, including retired storage and allocator metadata, may
  * change. Preserve only the prefix and the table/count/initial-slot globals.
  * The native private frame has separate checked word storage in this region. */
 if(new_address>=0x420060U){
  spx_mutable_event(world,0U,0x420050U,0U,1U,0U);
  spx_mutable_event(world,0x420060U,(uint64_t)new_address-0x420060U,0U,1U,0U);
  spx_mutable_event(world,(uint32_t)end,UINT64_C(4294967296)-end,0U,1U,0U);
 }else{
  spx_mutable_event(world,0U,new_address,0U,1U,0U);
  spx_mutable_event(world,(uint32_t)end,UINT64_C(0x420050)-end,0U,1U,0U);
  spx_mutable_event(world,0x420060U,UINT64_C(4294967296)-0x420060U,0U,1U,0U);
 }
}
#ifdef SPX_GROWTH_CONNECTED
/* Keep physical coverage explicit without merging the selected array index.
 * Reads and writes use this same inventory; every read still checks that its
 * exact word was initialized by the actual prefix or the incoming options. */
#define PRIVATE_WORDS(APPLY) \
 APPLY(0,0U) APPLY(1,4U) APPLY(2,8U) APPLY(3,12U) APPLY(4,16U) \
 APPLY(5,76U) APPLY(6,40U) APPLY(7,44U) APPLY(8,48U) \
 APPLY(9,92U) APPLY(10,96U) APPLY(11,100U) APPLY(12,104U) APPLY(13,112U)
static void volatile_return(spx_machine_state *output,uint32_t eax){
 spx_machine_state arbitrary;output->eax=eax;output->ecx=arbitrary.ecx;output->edx=arbitrary.edx;
 output->cf=arbitrary.cf&1U;output->zf=arbitrary.zf&1U;output->of=arbitrary.of&1U;
 output->sf=arbitrary.sf&1U;output->pf=arbitrary.pf&1U;output->df=arbitrary.df&1U;
}
#endif
static uint32_t native_read(void *context,uint32_t address,uint32_t width,uint32_t *fault){
 (void)context;*fault=0U;
 __CPROVER_assert(width==4U,"growth-memory-read-width");
#ifdef SPX_GROWTH_CONNECTED
 if(address>=stack_base && (uint64_t)address+4U<=(uint64_t)stack_base+PRIVATE_EXTENT){
#define READ_PRIVATE_WORD(i,offset) \
  if(address==stack_base+offset){ \
   __CPROVER_assert(initialized[i],"growth-connected-stack-initialized"); \
   return original_words[i]; \
  }
  PRIVATE_WORDS(READ_PRIVATE_WORD)
#undef READ_PRIVATE_WORD
  __CPROVER_assert(0,"growth-connected-stack-coverage");__CPROVER_assume(0);return 0U;
 }
 if(address==0x420050U)return published_table;
 if(address==0x42005cU)return word(&left,address);
 if(address==0x4321e4U && !errno_calls)return word(&incoming,address);
 if(address==errno_address && errno_calls==1U && !growth_calls)return word(&incoming,address);
#else
 if(address==stack_base+76U)return new_count;
 if(address==stack_base || address==stack_base+4U || address==stack_base+8U)
  return arguments[(address-stack_base)/4U];
#endif
 __CPROVER_assert(address==0x42005cU || address==0x420054U || address==0x420058U,
  "growth-memory-read-coverage");
 /* Every event checks preservation of these twelve global bytes. */
 return word(&incoming,address);
}
static void native_write(void *context,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 (void)context;*fault=0U;
 __CPROVER_assert(width==4U,"growth-memory-write-width");
#ifdef SPX_GROWTH_CONNECTED
 if(address>=stack_base && (uint64_t)address+4U<=(uint64_t)stack_base+PRIVATE_EXTENT){
#define WRITE_PRIVATE_WORD(i,offset) \
  if(address==stack_base+offset){original_words[i]=value;initialized[i]=1U;return;}
  PRIVATE_WORDS(WRITE_PRIVATE_WORD)
#undef WRITE_PRIVATE_WORD
  __CPROVER_assert(0,"growth-connected-stack-coverage");__CPROVER_assume(0);return;
 }
 if(address==0x42005cU){
  __CPROVER_assert(clear_calls==1U,"growth-connected-count-store-order");published_count=value;
  spx_mutable_event(&left,address,width,value,0U,0U);return;
 }
#else
 if(address==stack_base || address==stack_base+4U || address==stack_base+8U){
  arguments[(address-stack_base)/4U]=value;return;
 }
#endif
 __CPROVER_assert(address==0x420050U || (preallocated && (address==new_address || address==new_address+4U)),
  "growth-memory-write-coverage");
 if(address==0x420050U)published_table=value;
 spx_mutable_event(&left,address,width,value,0U,0U);
}
static spx_call_status native_call(spx_runtime *runtime,const spx_call_event *event,
 const spx_machine_state *input,spx_machine_state *output){
 (void)runtime;*output=*input;
#ifdef SPX_GROWTH_CONNECTED
 CHECK_GROWTH_CALL(input->esp==stack_base,"growth-connected-call-frame");
 if(event->kind==SPX_CALL_INDIRECT){
  CHECK_GROWTH_CALL(!errno_calls && !growth_calls && !clear_calls &&
   event->source_rva==0x4ec6U && event->target_rva==errno_target,"growth-connected-errno-call");
  errno_calls++;volatile_return(output,errno_address);return SPX_CALL_OK;
 }
 if(event->kind==SPX_CALL_INTERNAL_DIRECT){
  CHECK_GROWTH_CALL(errno_calls==1U && !growth_calls && !clear_calls && event->target_rva==0x63acU &&
   event->source_rva==(preallocated?0x504cU:0x4f1bU),"growth-connected-growth-call");
  uint32_t fault;
  for(uint32_t i=0U;i<5U;i++)growth_arguments[i]=native_read(0,stack_base+4U*i,4U,&fault);
  CHECK_GROWTH_CALL(growth_arguments[0]==(preallocated?0U:old_address) &&
   growth_arguments[1]==stack_base+76U && growth_arguments[2]==index_value-old_count+1U &&
   growth_arguments[3]==2147483647U && growth_arguments[4]==8U,
   "growth-connected-native-grow-arguments");
  CHECK_GROWTH_CALL(native_read(0,growth_arguments[1],4U,&fault)==old_count,
   "growth-connected-native-count-input");
  growth_calls++;growth_effect(&left);post_growth=spx_mutable_byte(&left,probe);
  original_words[5]=new_count;volatile_return(output,new_address);return SPX_CALL_OK;
 }
 uint32_t fault;
 for(uint32_t i=0U;i<3U;i++)arguments[i]=native_read(0,stack_base+4U*i,4U,&fault);
#endif
 CHECK_GROWTH_CALL(!clear_calls && event->kind==SPX_CALL_EXTERNAL_IMPORT && event->source_rva==0x4f54U &&
  input->esp==stack_base,"growth-memory-clearing-cut");
 clear_calls++;
 CHECK_GROWTH_CALL(arguments[0]==new_address+8U*old_count && arguments[1]==0U &&
  arguments[2]==8ULL*(new_count-old_count),"growth-memory-native-clear-arguments");
 CHECK_GROWTH_CALL(published_table==new_address,
  "growth-memory-published-table-before-clear");
 before_clear=spx_mutable_byte(&left,probe);
 spx_mutable_fill(&left,arguments[0],arguments[2],arguments[1]);
#ifdef SPX_GROWTH_CONNECTED
 volatile_return(output,arguments[0]);return SPX_CALL_OK;
#else
 return SPX_CALL_NONLOCAL; /* Checker stop after modeling the normal call effect. */
#endif
}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *event,
 const spx_machine_state *input,spx_machine_state *output){
 /* Retained external imports use this path, while internal fallback calls use
  * the runtime callback. Both must pass the same exact site/argument checks. */
 return native_call(runtime,event,input,output);
}
static uint32_t errno_read(void *context,spx_ref_v5 ref,uint64_t offset,uint32_t width,uint64_t *result){
 (void)context;(void)ref;
 __CPROVER_assert(offset==0U && width==4U,"growth-memory-errno-read");
#ifdef SPX_GROWTH_CONNECTED
 *result=word(&incoming,errno_address);
#else
 *result=0U; /* Saved errno is outside this continuation relation. */
#endif
 return SPX_REF_OK;
}
static spx_view_v5 source_errno(void *context){
 (void)context;return (spx_view_v5){.extent=4U,.read=errno_read};
}
static Slot *returned_slot(void){return new_address==old_address?&old_slot:&new_slot;}
static Slot *source_grow(void *context,Slot *old,Word *count,uint32_t additional,uint32_t maximum){
 (void)context;
 __CPROVER_assert(old==(preallocated?0:&old_slot) && count->value==old_count &&
  additional==index_value-old_count+1U && maximum==2147483647U,"growth-memory-source-grow-arguments");
 growth_effect(&right);
#ifdef SPX_GROWTH_CONNECTED
 uint8_t bytes[4];spx_local_record_pack_quote_word(count,bytes);
 for(uint32_t j=0U;j<4U;j++){
  __CPROVER_assert(bytes[j]==(uint8_t)(old_count>>(8U*j)),"growth-connected-local-count-input");
  bytes[j]=(uint8_t)(original_words[5]>>(8U*j));
 }
 spx_local_record_unpack_quote_word(count,bytes);
#else
 count->value=new_count;
#endif
 return returned_slot();
}
static void source_clear(void *context,Slot *slots,uint32_t first,uint32_t count){
 (void)context;
 __CPROVER_assert(clear_calls==1U && slots==returned_slot() && first==old_count && count==new_count-old_count,
  "growth-memory-source-clear-arguments");
 __CPROVER_assert(source_state.table==slots && source_state.count==old_count,
  "growth-memory-source-published-table");
 spx_mutable_event(&right,0x420050U,4U,new_address,0U,0U);
 if(preallocated){
  __CPROVER_assert(slots->buffer==initial_slot.buffer,"growth-memory-copied-buffer-identity");
#ifdef SPX_GROWTH_RECORD_SNAPSHOTS
  __CPROVER_assert(slots->size==initial_slot.size,"growth-memory-copied-size");
  spx_mutable_copy(&right,new_address,0x420054U,8U);
#else
  spx_mutable_event(&right,new_address,4U,slots->size,0U,0U);
  spx_mutable_event(&right,new_address+4U,4U,old_buffer,0U,0U);
#endif
 }
#ifdef SPX_GROWTH_RECORD_SNAPSHOTS
 spx_record_frame();
#endif
 if(!contains(stack_base,PRIVATE_EXTENT,probe))
  __CPROVER_assert(spx_mutable_byte(&right,probe)==before_clear,"growth-memory-call-time-bytes");
 spx_mutable_fill(&right,new_address+8U*first,8ULL*count,0U);
 if(!contains(stack_base,PRIVATE_EXTENT,probe))
#ifdef SPX_GROWTH_CONNECTED
  /* Native count publication follows the clear's normal return. Compare that
   * memory only after the source performs its own count publication. */
  if(!contains(0x42005cU,4U,probe))
#endif
  __CPROVER_assert(spx_mutable_byte(&right,probe)==spx_mutable_byte(&left,probe),"growth-memory-post-clear-bytes");
#ifndef SPX_GROWTH_CONNECTED
 __CPROVER_assume(0); /* Full ordinary C stops at the same checking boundary. */
#endif
}
#ifdef SPX_GROWTH_CONNECTED
static void check_growth_continuation(struct spx_opaque_quote_state_v5 *state,
 Slot *slots,uint32_t index,uint32_t saved_errno,
 struct spx_opaque_quote_bytes_v5 *argument,uint32_t size,struct spx_opaque_quote_options_v5 *options){
 __CPROVER_assert(!continuation_witness,"growth-connected-continuation-witness");
 __CPROVER_assert(errno_calls==1U && growth_calls==1U && clear_calls==1U,
  "growth-connected-complete-call-trace");
 __CPROVER_assert(state==&source_state && slots==returned_slot() && state->table==slots &&
  state->count==published_count && published_count==new_count,
  "growth-connected-count-table-publication");
 __CPROVER_assert(index==index_value && saved_errno==original_words[8] &&
  size==original_words[7] && spx_record_encode_quote_bytes(argument)==original_words[6] &&
  spx_record_encode_quote_options(options)==final_machine.ebx,
  "growth-connected-source-continuation-inputs");
 __CPROVER_assert(final_machine.esp==stack_base && final_machine.esi==index &&
  final_machine.edi==new_address && final_machine.ebp==errno_target,
  "growth-connected-native-continuation-registers");
 __CPROVER_assert(original_words[9]==entry_machine.ebx && original_words[10]==entry_machine.esi &&
  original_words[11]==entry_machine.edi && original_words[12]==entry_machine.ebp &&
  original_words[13]==options_word,"growth-connected-saved-caller-frame");
 spx_mutable_event(&right,0x42005cU,4U,state->count,0U,0U);
 spx_record_frame();
 if(!contains(stack_base,PRIVATE_EXTENT,probe))
  __CPROVER_assert(spx_mutable_byte(&right,probe)==spx_mutable_byte(&left,probe),
   "growth-connected-continuation-memory");
 __CPROVER_assume(0); /* Proof-only boundary before selected-slot access. */
}
#endif
void check_static_domain(void){admit();__CPROVER_assume(preallocated);__CPROVER_assert(0,"growth-memory-static-domain");}
void check_moved_domain(void){admit();__CPROVER_assume(!preallocated && new_address!=old_address);__CPROVER_assert(0,"growth-memory-moved-domain");}
void check_inplace_domain(void){admit();__CPROVER_assume(new_address==old_address);__CPROVER_assert(0,"growth-memory-inplace-domain");}
void check_growth_memory(void){
 admit();left=incoming;right=incoming;
#ifndef SPX_GROWTH_CONNECTED
 growth_effect(&left);post_growth=spx_mutable_byte(&left,probe);
#endif
 spx_runtime runtime={0};runtime.read=native_read;runtime.write=native_write;runtime.external_call_fallback=native_call;
 spx_machine_state machine;machine.esp=stack_base;machine.eax=new_address;
 spx_step_result stop;
#ifdef SPX_GROWTH_CONNECTED
 original_words[13]=options_word;initialized[13]=1U;
 machine.esp=stack_base+108U;machine.eax=index_value;machine.edx=argument_word;machine.ecx=size_word;
 entry_machine=machine;
 stop=spx_sub_00004eb3(&runtime,&machine,0x4eb3U);final_machine=machine;
 __CPROVER_assert(stop.kind==SPX_FALLTHROUGH && stop.target_rva==0x4f62U && clear_calls==1U,
  "growth-connected-reaches-continuation");
 __CPROVER_assert(original_words[6]==argument_word && original_words[7]==size_word && machine.ebx==options_word &&
  original_words[8]==word(&incoming,errno_address),"growth-connected-native-preserved-inputs");
#else
 if(preallocated)stop=spx_sub_00004eb3(&runtime,&machine,0x505cU);
 else stop=spx_sub_00004eb3(&runtime,&machine,0x4f2cU);
 __CPROVER_assert(stop.kind==SPX_NONLOCAL && clear_calls==1U,"growth-memory-reaches-clear");
#endif
 uint8_t expected=post_growth;
 if(contains(new_address,8ULL*new_count,probe)){
  expected=0U;
  if(contains(new_address,8ULL*old_count,probe))expected=spx_mutable_byte(&incoming,old_address+(probe-new_address));
 }else if(contains(0x420050U,4U,probe))expected=(uint8_t)(new_address>>(8U*(probe-0x420050U)));
#ifdef SPX_GROWTH_CONNECTED
 else if(contains(0x42005cU,4U,probe))expected=(uint8_t)(new_count>>(8U*(probe-0x42005cU)));
#endif
 if(!contains(stack_base,PRIVATE_EXTENT,probe))
  __CPROVER_assert(spx_mutable_byte(&left,probe)==expected,"growth-memory-preserved-prefix-cleared-suffix-frame");
 old_buffer=word(&incoming,0x420058U);
#ifdef SPX_GROWTH_RECORD_SNAPSHOTS
 spx_growth_record_initialize();
 right.representation=&right;
 right.read_representation=spx_record_read;right.write_representation=spx_record_apply;
 right.snapshot_representation=spx_record_snapshot;
 right.read_representation_snapshot=spx_record_snapshot_read;
#else
 initial_slot.size=word(&incoming,0x420054U);
 initial_slot.buffer=old_buffer?(struct spx_opaque_quote_bytes_v5 *)&buffer_identity:0;
#endif
 source_state=(struct spx_opaque_quote_state_v5){.table=preallocated?&initial_slot:&old_slot,
  .count=old_count,.initial_table=&initial_slot};
 const spx_quote_slots_services_v5 services={.errno_cell=source_errno,.grow_slots=source_grow,.clear_slots=source_clear};
 spx_quote_slots_context_v5 context={.services=&services,.state={.slots=&source_state}};
 struct spx_opaque_quote_bytes_v5 *argument;struct spx_opaque_quote_options_v5 *options;uint32_t size;
#ifdef SPX_GROWTH_CONNECTED
 argument=spx_record_decode_quote_bytes(argument_word);options=spx_record_decode_quote_options(options_word);size=size_word;
#endif
 (void)quote_slots(&context,index_value,argument,size,options);
 __CPROVER_assert(0,"growth-memory-source-reaches-clear");
}
#ifdef SPX_GROWTH_CONNECTED
/* An expected counterexample establishes reachability through both actual
 * implementations. It is distinct from the simple input-domain witnesses. */
void check_growth_continuation_domain(void){
 continuation_witness=1U;check_growth_memory();
}
#endif
