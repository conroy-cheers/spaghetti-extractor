#ifndef HELLO_STANDALONE_SERVICES_H
#define HELLO_STANDALONE_SERVICES_H
#include <stdint.h>

/* One representation shared by the existing conversion component adapters. */
typedef struct {
    unsigned char implicit16[4], implicit32[4], implicit_string[4], conversion_state[4];
    uint32_t target_errno, allocated_bytes, allocations, releases;
    uint32_t fatal_entries, fatal_errno;
    uint32_t resets, decodes, conversions, converted, cursor_null, word_hash;
    uint16_t first_words[16];
    unsigned word_count;
    int argument_count;
    char **arguments;
    int exit_code;
    const char *program_name;
} HelloRuntime;
extern HelloRuntime hello_runtime;

int hello_application(int argc, char **argv);
void hello_start(int argc, char **argv);
void *hello_allocate(uint32_t size);
void hello_release(void *block);
void hello_reset(unsigned char state[4]);
uint32_t hello_decode16(uint16_t *output, const unsigned char *input,
                        uint32_t size, unsigned char state[4]);
uint32_t hello_convert(uint16_t *output, const unsigned char **input,
                       uint32_t limit, unsigned char state[4]);
_Noreturn void hello_allocation_failed(void);
_Noreturn void hello_invalid_state(void);
#endif
