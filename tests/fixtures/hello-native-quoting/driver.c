#include "native-runtime.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv) {
  if(argc==5 && (!strcmp(argv[1],"original") || !strcmp(argv[1],"source")) &&
      (!strcmp(argv[2],"terminal") || !strcmp(argv[2],"terminal-child")))
    return native_terminal_run(!strcmp(argv[1],"source"),!strcmp(argv[2],"terminal-child"),argv[3],argv[4]);
  if((argc!=4 && argc!=5) || (strcmp(argv[1],"original") && strcmp(argv[1],"source")))return 2;
  char *end;unsigned long style=strtoul(argv[2],&end,10);if(!*argv[2] || *end || style>9)return 2;
  unsigned long kind=strtoul(argv[3],&end,10);if(!*argv[3] || *end || kind>2)return 2;
  unsigned long mode=0;
  if(argc==5){mode=strtoul(argv[4],&end,10);if(!*argv[4] || *end || mode>2)return 2;}
  native_initialize(!strcmp(argv[1],"source"));
  native_environment((uint32_t)mode);
  native_reallocation_probe();
  native_checked_probe();
  const char short_text[]="a b\\\"'\n\t?";
  const char embedded[]={'a',0,'b','\n','\\','"','\'',(char)0xc3,(char)0xa9,0};
  char long_text[601];for(unsigned i=0;i<600;++i)long_text[i]=short_text[i%(sizeof(short_text)-1)];long_text[600]=0;
  const unsigned slots[]={0,3,15,19,3,0};
  printf("{\"invocations\":[");
  for(unsigned i=0;i<6;++i) {
    const char *argument=i>=4?long_text:kind?embedded:short_text;
    uint32_t size=i>=4?600:kind?9:(uint32_t)strlen(short_text);
    errno=37+(int)i;
    const char *result=native_consume(slots[i],(uint32_t)style,argument,size,(int)kind);
    if(i)putchar(',');
    native_observe(result);
  }
  native_cleanup();printf("],\"cleanup\":");native_observe(NULL);
  /* Reenter a real consumer after native cleanup to expose stale state. */
  errno=71;const char *reused=native_consume(0,(uint32_t)style,"again",5,(int)kind);
  printf(",\"after_cleanup\":");native_observe(reused);native_cleanup();putchar(',');native_finish();printf("}\n");
  return 0;
}
