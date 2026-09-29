#ifndef HELLO_MULTIBYTE_RUNTIME_H
#define HELLO_MULTIBYTE_RUNTIME_H
#include <stdint.h>
/* Fixture-only ABI bridge and execution observation. */
uint32_t fixture_multibyte_decode32(unsigned char *, uint32_t *, const unsigned char *, uint32_t, uint32_t *);
uint32_t fixture_multibyte_decode16(unsigned char *, uint16_t *, const unsigned char *, uint32_t, uint32_t *);
void fixture_multibyte_install(unsigned char *image);
void fixture_multibyte_environment(unsigned char *image, unsigned mode);
void fixture_multibyte_finish(unsigned char *image, int source);
void fixture_multibyte_counts(uint32_t out[4]);
#endif
