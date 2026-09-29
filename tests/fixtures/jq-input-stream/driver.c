#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "entries.h"
#include "native-entry.h"
#include "allocation-observer.h"
static void *entry(unsigned rva) { return (unsigned char *)GetModuleHandleA("libjq-1.dll")+rva; }
static spx_input *standard_input;
static void detach_stdin(void) { if(standard_input)(void)spx_input_detach(standard_input); }
spx_input *spx_runtime_stdin(void) {
 if(!standard_input) { standard_input=spx_input_attach(stdin,1,0);atexit(detach_stdin); }
 return standard_input;
}
void spx_input_callback_assertion(void) { _wassert(L"cb == jq_util_input_next_input_cb",L"src/util.c",351); }

jq_input_cb spx_input_callback_entry(void) { return (jq_input_cb)entry(0x45e3f); }
static jq_util_input_state * api_init(jq_util_msg_cb cb,void *data) { return ((jq_util_input_state * (*)(jq_util_msg_cb,void *))entry(0x45409))(cb,data); }
static void api_set_parser(jq_util_input_state *state,jv_parser *parser,int slurp) { ((void (*)(jq_util_input_state *,jv_parser *,int))entry(0x454b0))(state,parser,slurp); }
static void api_free(jq_util_input_state **owner) { ((void (*)(jq_util_input_state **))entry(0x45569))(owner); }
static void api_add_input(jq_util_input_state *state,const char *filename) { ((void (*)(jq_util_input_state *,const char *))entry(0x4561d))(state,filename); }
static int api_errors(jq_util_input_state *state) { return ((int (*)(jq_util_input_state *))entry(0x45666))(state); }
static jv api_get_position(jq_state *jq) { return ((jv (*)(jq_state *))entry(0x4566e))(jq); }
static jv api_get_current_filename(jq_state *jq) { return ((jv (*)(jq_state *))entry(0x4579e))(jq); }
static jv api_get_current_line(jq_state *jq) { return ((jv (*)(jq_state *))entry(0x45881))(jq); }
static jv api_next_input(jq_util_input_state *state) { return ((jv (*)(jq_util_input_state *))entry(0x45950))(state); }
static jv api_next_input_cb(jq_state *jq,void *data) { return ((jv (*)(jq_state *,void *))entry(0x45e3f))(jq,data); }

struct errors { jv messages; };
static void message(void *data,const char *name) {
 struct errors *errors=data;
 errors->messages=jv_array_append(errors->messages,jv_string_fmt("%s: %s",name,strerror(errno)));
}
static void file(const char *name,const char *contents) {
 FILE *f=fopen(name,"wb");if(!f)exit(82);
 if(fwrite(contents,1,strlen(contents),f)!=strlen(contents)||fclose(f))exit(82);
}
static void emit(jv value) {
 allocation_observer_pause(1);
 printf("{\"kind\":%d,\"value\":",jv_get_kind(value));
 if(!jv_is_valid(value))value=jv_invalid_get_msg(value);
 if(!jv_is_valid(value)){jv_free(value);value=jv_null();}
 jv text=jv_dump_string(value,JV_PRINT_SORTED);fputs(jv_string_value(text),stdout);jv_free(text);putchar('}');
 allocation_observer_pause(0);
}
int main(int argc,char **argv) {
 if(argc!=3)return 2;
 int selected=!strcmp(argv[1],"source");
 if(selected) {
 if(!install_init((void(*)(void))spx_entry_init))return 85;
 if(!install_set_parser((void(*)(void))spx_entry_set_parser))return 85;
 if(!install_free((void(*)(void))spx_entry_free))return 85;
 if(!install_add_input((void(*)(void))spx_entry_add_input))return 85;
 if(!install_errors((void(*)(void))spx_entry_errors))return 85;
 if(!install_get_position((void(*)(void))spx_entry_get_position))return 85;
 if(!install_get_current_filename((void(*)(void))spx_entry_get_current_filename))return 85;
 if(!install_get_current_line((void(*)(void))spx_entry_get_current_line))return 85;
 if(!install_next_input((void(*)(void))spx_entry_next_input))return 85;
 if(!install_next_input_cb((void(*)(void))spx_entry_next_input_cb))return 85;
 }
 int raw=!strncmp(argv[2],"raw",3),slurp=strstr(argv[2],"slurp")!=NULL;
 int early=strstr(argv[2],"early")!=NULL,missing=strstr(argv[2],"missing")!=NULL;
 file("First.txt",raw?"one\r\ntwo\nlast\r":"{\"x\":1}\r\n[2]\r\n");
 file("second.txt",strstr(argv[2],"bad")?"[broken]\n":raw?"three\r\nfour\x1aIGNORED":"3\r\n\x1aINVALID");
 if(strstr(argv[2],"stdin")) {
  file("stdin.txt","before\r\nnext\032after\n");
  if(!freopen("stdin.txt","r",stdin))return 82;
 }
 allocation_observer_begin();
 jq_state *jq[2]={jq_init(),jq_init()};
 struct errors errors[2]={{jv_array()},{jv_array()}};
 jq_util_input_state *input[2];
 for(int i=0;i<2;i++) {
  input[i]=api_init(message,&errors[i]);
  api_set_parser(input[i],raw?NULL:jv_parser_new(0),slurp);
  api_add_input(input[i],strstr(argv[2],"stdin")?"-":i?"FIRST.TXT":"First.txt");
  api_add_input(input[i],strstr(argv[2],"stdin")?"-":missing?"absent.txt":"second.txt");
  jq_set_input_cb(jq[i],spx_input_callback_entry(),input[i]);
 }
 fputs("{\"contexts\":[",stdout);
 for(int i=0;i<2;i++) {
  if(i)putchar(',');
  fputs("{\"before\":",stdout);emit(api_get_position(jq[i]));
  fputs(",\"values\":[",stdout);
  for(int n=0;n<32;n++) {
   jv v=(n&1)?api_next_input(input[i]):api_next_input_cb(jq[i],input[i]);
   int valid=jv_is_valid(v);if(n)putchar(',');
   fputs("{\"item\":",stdout);emit(v);
   fputs(",\"position\":",stdout);emit(api_get_position(jq[i]));
   fputs(",\"filename\":",stdout);emit(api_get_current_filename(jq[i]));
   fputs(",\"line\":",stdout);emit(api_get_current_line(jq[i]));putchar('}');
   if(!valid||early)break;
  }
  printf("],\"errors\":%d,\"messages\":",api_errors(input[i]));emit(jv_copy(errors[i].messages));
  api_free(&input[i]);printf(",\"owner_cleared\":%s}",input[i]?"false":"true");
 }
 for(int i=1;i>=0;i--){jq_teardown(&jq[i]);jv_free(errors[i].messages);}
 fputs("],\"allocation_lifetime\":",stdout);allocation_observer_finish(stdout);puts("}");
 if(selected&&!install_init_intact())return 85;
 if(selected&&!install_set_parser_intact())return 85;
 if(selected&&!install_free_intact())return 85;
 if(selected&&!install_add_input_intact())return 85;
 if(selected&&!install_errors_intact())return 85;
 if(selected&&!install_get_position_intact())return 85;
 if(selected&&!install_get_current_filename_intact())return 85;
 if(selected&&!install_get_current_line_intact())return 85;
 if(selected&&!install_next_input_intact())return 85;
 if(selected&&!install_next_input_cb_intact())return 85;
 return 0;
}
