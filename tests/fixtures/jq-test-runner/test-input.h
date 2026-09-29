#ifndef SPX_JQ_TEST_INPUT_H
#define SPX_JQ_TEST_INPUT_H
#include "jv.h"
#ifdef _WIN32
#include "winpthread-pthread.h"
#else
#include <pthread.h>
#endif
struct spx_opaque_test_input_v5 { jv libraries; int verbose, argc; char **argv; };
int portable_jq_testsuite(jv, int, int, char **);
int spx_test_thread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int spx_test_thread_join(pthread_t, void **);
_Noreturn void spx_test_exit(int);
#endif
