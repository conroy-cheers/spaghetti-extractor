#ifndef HELLO_STRING_RUNTIME_H
#define HELLO_STRING_RUNTIME_H
#include <stdint.h>
void fixture_string_initialize(unsigned char *, int, unsigned);
void fixture_string_observe(void);
uint32_t fixture_string_calls(void);
#endif
