#ifndef HELLO_ALLOCATION_OBJECTS_H
#define HELLO_ALLOCATION_OBJECTS_H
#include <stdint.h>
/* The count is a PE32 target value. Block identity and lifetime are transported
 * by explicit adapters; the algorithm never reconstructs a host pointer. */
struct spx_opaque_allocation_count_v5 { uint32_t value; };
struct spx_opaque_allocation_block_v5 { uint32_t address; };
#endif
