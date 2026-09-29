#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "portable-component-implementation.h"
#include "compile.h"
#include "entries.h"
#include "native-entry.h"
#include "allocation-observer.h"
static unsigned source_calls;
void spx_observe_lifecycle_entry(const char *name) { (void)name; ++source_calls; }
/* Preserve a useful failure immediately instead of waiting in WineDbg. This
 * diagnostic exits unsuccessfully and never converts a target fault to a pass. */
static LONG WINAPI report_exception(EXCEPTION_POINTERS *error) {
  fprintf(stderr, "native-fault code=%08lx ip=%08lx eax=%08lx ecx=%08lx edx=%08lx image=%p\n",
      (unsigned long)error->ExceptionRecord->ExceptionCode,
      (unsigned long)error->ContextRecord->Eip, (unsigned long)error->ContextRecord->Eax,
      (unsigned long)error->ContextRecord->Ecx, (unsigned long)error->ContextRecord->Edx,
      (void *)GetModuleHandleA("libjq-1.dll"));
  fflush(stderr);
  ExitProcess(86);
  return EXCEPTION_EXECUTE_HANDLER;
}
static jv bytecode_snapshot(struct bytecode *code, struct bytecode *parent) {
  if(!code)return jv_null();
  jv words=jv_array(),children=jv_array();
  for(int i=0;i<code->codelen;++i)words=jv_array_append(words,jv_number(code->code[i]));
  for(int i=0;i<code->nsubfunctions;++i)children=jv_array_append(children,bytecode_snapshot(code->subfunctions[i],code));
  jv value=jv_object();
  value=jv_object_set(value,jv_string("code"),words);
  value=jv_object_set(value,jv_string("locals"),jv_number(code->nlocals));
  value=jv_object_set(value,jv_string("closures"),jv_number(code->nclosures));
  value=jv_object_set(value,jv_string("parent_ok"),jv_bool(code->parent==parent));
  value=jv_object_set(value,jv_string("globals_ok"),jv_bool(!parent||code->globals==parent->globals));
  value=jv_object_set(value,jv_string("constants"),jv_copy(code->constants));
  value=jv_object_set(value,jv_string("debug"),jv_copy(code->debuginfo));
  value=jv_object_set(value,jv_string("cfunctions"),jv_copy(code->globals->cfunc_names));
  return jv_object_set(value,jv_string("children"),children);
}
/* Native diagnostic only: pinned jq_state prefix, copied without type punning. */
static struct bytecode *compiled_code(jq_state *state) {
  struct { void (*handler)(void *); void *data; struct bytecode *code; } prefix;
  memcpy(&prefix,state,sizeof(prefix));return prefix.code;
}
struct callbacks { jv inputs,events; int next; };
static jv input_callback(jq_state *jq,void *data) {
  (void)jq;struct callbacks *state=data;
  state->events=jv_array_append(state->events,jv_string("input"));
  return jv_array_get(jv_copy(state->inputs),state->next++);
}
static void message_callback(void *data,jv message) {
  struct callbacks *state=data;
  state->events=jv_array_append(state->events,message);
}
static void emit(jv value) {
  allocation_observer_pause(1);
  printf("{\"kind\":%d,\"value\":",jv_get_kind(value));
  if(!jv_is_valid(value))value=jv_invalid_get_msg(value);
  if(!jv_is_valid(value)) { jv_free(value);value=jv_null(); }
  jv text=jv_dump_string(value,JV_PRINT_SORTED);
  fputs(jv_string_value(text),stdout);jv_free(text);putchar('}');
  allocation_observer_pause(0);
}
static unsigned digit(char c) {
  if(c>='0'&&c<='9')return c-'0';
  if(c>='a'&&c<='f')return c-'a'+10;
  abort();
}
static char *decode(const char *hex) {
  size_t n=strlen(hex)/2;char *text=malloc(n+1);if(!text||strlen(hex)%2)exit(2);
  for(size_t i=0;i<n;i++)text[i]=(char)((digit(hex[i*2])<<4)|digit(hex[i*2+1]));
  text[n]=0;return text;
}
int main(int argc,char **argv) {
  if(argc!=7)return 2;
  SetUnhandledExceptionFilter(report_exception);
  int selected=!strcmp(argv[1],"source"),limit=atoi(argv[5]);
  if(selected&&!install_entries())return 85;
  char *program=decode(argv[2]),*input_text=decode(argv[3]),*callback_text=decode(argv[4]);
  char *args_text=decode(argv[6]);
  static char *fixture_environment[]={"SPX_COMPILER_TEST=compiler-case","PATH=fixture-path",NULL}; _environ=fixture_environment;
  allocation_observer_begin();
  jq_state *states[2]={jq_init(),jq_init()};
  struct callbacks callback[2];
  jv inputs=jv_parse(input_text);
  if(!jv_is_valid(inputs))return 2;
  fputs("{\"contexts\":[",stdout);
  for(int index=0;index<2;index++) {
    jq_state *jq=states[index];if(!jq)return 84;
    callback[index]=(struct callbacks){jv_parse(callback_text),jv_array(),0};
    jq_set_input_cb(jq,input_callback,&callback[index]);
    jq_set_error_cb(jq,message_callback,&callback[index]);
    jq_set_debug_cb(jq,message_callback,&callback[index]);
    jq_set_stderr_cb(jq,message_callback,&callback[index]);
    jq_msg_cb msg_cb = NULL; void *msg_data = NULL;
    jq_input_cb input_cb = NULL; void *input_data = NULL;
    jq_get_error_cb(jq, &msg_cb, &msg_data);
    if (msg_cb != message_callback || msg_data != &callback[index]) return 84;
    jq_get_debug_cb(jq, &msg_cb, &msg_data);
    if (msg_cb != message_callback || msg_data != &callback[index]) return 84;
    jq_get_stderr_cb(jq, &msg_cb, &msg_data);
    if (msg_cb != message_callback || msg_data != &callback[index]) return 84;
    jq_get_input_cb(jq, &input_cb, &input_data);
    if (input_cb != input_callback || input_data != &callback[index]) return 84;
    jq_set_error_cb(jq, NULL, NULL);
    jq_get_error_cb(jq, &msg_cb, &msg_data);
    if (!msg_cb || !msg_data) return 84;
    jq_set_error_cb(jq, message_callback, &callback[index]);
    jq_set_nomem_handler(jq, NULL, NULL);
    jv attributes=jv_object();
    attributes=jv_object_set(attributes,jv_string("JQ_ORIGIN"),jv_string("library-origin"));
    attributes=jv_object_set(attributes,jv_string("PROGRAM_ORIGIN"),jv_string("program-origin"));
    jq_set_attrs(jq,attributes);
    jq_set_attr(jq,jv_string("context"),jv_number(index));
    int compiled=jq_compile_args(jq,program,jv_parse(args_text));
    printf("%s{\"compiled\":%s,\"bytecode\":",index?",":"",compiled?"true":"false");
    allocation_observer_pause(1);emit(bytecode_snapshot(compiled_code(jq),NULL));allocation_observer_pause(0);
    fputs(",\"runs\":[",stdout);
    if(compiled)for(int run=0;run<2;run++) {
      callback[index].next=0;
      jq_start(jq,jv_copy(inputs),0);
      printf("%s{\"values\":[",run?",":"");
      unsigned count=0;
      while(count<(unsigned)limit) {
        jv value=jq_next(jq);
        if(!jv_is_valid(value)) {
          printf("],\"error\":");
          emit(jv_invalid_get_msg(value));
          break;
        }
        if(count++)putchar(',');
        emit(value);
      }
      if(count==(unsigned)limit)fputs("],\"error\":null",stdout);
      printf(",\"halted\":%s,\"exit\":",jq_halted(jq)?"true":"false");
      emit(jq_get_exit_code(jq));fputs(",\"halt_message\":",stdout);emit(jq_get_error_message(jq));
      fputs(",\"input_after\":",stdout);emit(jv_copy(inputs));putchar('}');
    }
    fputs("],\"attributes\":[",stdout);
    emit(jq_get_attr(jq,jv_string("context")));putchar(',');
    emit(jq_get_jq_origin(jq));putchar(',');emit(jq_get_prog_origin(jq));putchar(',');emit(jq_get_lib_dirs(jq));
    fputs("],\"recompile\":[",stdout);
    int valid=jq_compile(jq,".,.");printf("%s,",valid?"true":"false");
    if(!valid)return 84;
    jq_start(jq,jv_number(index+40),0);emit(jq_next(jq));putchar(',');
    /* Recompile with a live fork and pending result, then recover after an error. */
    printf("%s,",jq_compile(jq,".[")?"true":"false");
    valid=jq_compile(jq,".,.");printf("%s,",valid?"true":"false");if(!valid)return 84;
    jq_start(jq,jv_number(index+50),0);emit(jq_next(jq));
    fputs("],\"formatted_errors\":[",stdout);
    emit(jq_format_error(jv_string("already formatted")));putchar(',');
    emit(jq_format_error(jv_invalid_with_msg(jv_string("an error"))));putchar(',');
    emit(jq_format_error(jv_invalid_with_msg(jv_array_append(jv_array(),jv_number(index)))));
    jq_report_error(jq,jv_string("explicit callback"));
    fputs("],\"callbacks\":",stdout);emit(jv_copy(callback[index].events));putchar('}');
  }
  for(int index=1;index>=0;index--) {
    jq_teardown(&states[index]);if(states[index])return 84;jq_teardown(&states[index]);jv_free(callback[index].inputs);jv_free(callback[index].events);
  }
  jv_free(inputs);
  fputs("],\"allocation_lifetime\":",stdout);allocation_observer_finish(stdout);puts("}");
  free(program);free(input_text);free(callback_text);free(args_text);
  fprintf(stderr,"authored-execution-lifecycle-calls=%u\n",source_calls);
  return selected&&(!source_calls||!entries_intact())?85:0;
}
