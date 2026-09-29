/* Source-assisted from jq 1.8.1 jv.c and jv_dtoa_tsd.c; see COPYING. */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "context-inputs.h"
#include "context-services.h"
#include "jv_alloc.h"
#ifdef _WIN32
#include "winpthread-pthread.h"
#else
#include <pthread.h>
#endif

static pthread_once_t decimal_once=PTHREAD_ONCE_INIT;
static pthread_key_t decimal_key;
static pthread_once_t dtoa_once=PTHREAD_ONCE_INIT;
static pthread_key_t dtoa_key;
static pthread_once_t seed_once=PTHREAD_ONCE_INIT;
static uint32_t hash_seed;

void portable_decimal_finalize(void) {
    jv_mem_free(pthread_getspecific(decimal_key));
    pthread_setspecific(decimal_key,NULL);
}

void portable_decimal_initialize(void) {
    if (pthread_key_create(&decimal_key,jv_mem_free)!=0) {
        fprintf(stderr,"error: cannot create thread specific key");
        abort();
    }
    spx_context_atexit(portable_decimal_finalize);
}

decContext *portable_decimal_context(void) {
    pthread_once(&decimal_once,portable_decimal_initialize);
    decContext *context=pthread_getspecific(decimal_key);
    if (context) return context;
    context=spx_context_malloc(sizeof(*context));
    if (context) {
        decContextDefault(context,DEC_INIT_BASE);
        int32_t digits=INT32_MAX-(DECDPUN-1)-(context->emax-context->emin-1);
        context->digits=digits<DEC_MAX_DIGITS ? digits : DEC_MAX_DIGITS;
        context->traps=0;
        if (pthread_setspecific(decimal_key,context)!=0) {
            fprintf(stderr,"error: cannot store thread specific data");
            abort();
        }
    }
    return context;
}

static void dtoa_destroy(void *pointer) {
    if (pointer) {
        jvp_dtoa_context_free(pointer);
        jv_mem_free(pointer);
    }
}

void portable_dtoa_finalize(void) {
    dtoa_destroy(pthread_getspecific(dtoa_key));
    pthread_setspecific(dtoa_key,NULL);
}

void portable_dtoa_initialize(void) {
    if (pthread_key_create(&dtoa_key,dtoa_destroy)!=0) {
        fprintf(stderr,"error: cannot create thread specific key");
        abort();
    }
    spx_context_atexit(portable_dtoa_finalize);
}

struct dtoa_context *portable_dtoa_context(void) {
    pthread_once(&dtoa_once,portable_dtoa_initialize);
    struct dtoa_context *context=pthread_getspecific(dtoa_key);
    if (!context) {
        context=jv_mem_alloc(sizeof(*context));
        jvp_dtoa_context_init(context);
        if (pthread_setspecific(dtoa_key,context)!=0) {
            jv_mem_free(context);
            fprintf(stderr,"error: cannot set thread specific data");
            abort();
        }
    }
    return context;
}

static uint32_t fallback_seed(void) {
    uint32_t process=spx_seed_process_id();
    return process ^ spx_seed_time32();
}

static void initialize_seed(void) {
    unsigned char bytes[4];
    int descriptor=spx_seed_open("/dev/urandom",0);
    uint32_t seed;
    if (descriptor<0) {
        seed=fallback_seed();
    } else {
        if (spx_seed_read(descriptor,bytes,sizeof(bytes))!=4)
            seed=fallback_seed();
        else
            seed=(uint32_t)bytes[0] | ((uint32_t)bytes[1]<<8) |
                 ((uint32_t)bytes[2]<<16) | ((uint32_t)bytes[3]<<24);
        spx_seed_close(descriptor);
    }
    hash_seed=seed;
}

uint32_t portable_hash_seed(void) {
    pthread_once(&seed_once,initialize_seed);
    return hash_seed;
}
