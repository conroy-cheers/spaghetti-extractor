#ifndef HELLO_NATIVE_RUNTIME_H
#define HELLO_NATIVE_RUNTIME_H
#include <stdint.h>
void native_require(int, const char *);
void native_initialize(int);
void native_environment(uint32_t);
void native_reallocation_probe(void);
void native_checked_probe(void);
int native_terminal_run(int, int, const char *, const char *);
char *native_consume(uint32_t, uint32_t, const char *, uint32_t, int);
void native_cleanup(void);
void native_observe(const char *);
void native_finish(void);
#endif
