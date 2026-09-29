#ifndef DXBALL_SCORES_STATE_H
#define DXBALL_SCORES_STATE_H
#include <stdint.h>
#include <string.h>
/* The disk record is exactly 40 name bytes and one little-endian score.
 * Byte fields preserve padding, partial reads and non-native byte order. */
typedef struct { char name[40]; unsigned char value[4]; } score_entry;
_Static_assert(sizeof(score_entry) == 44, "score file record size");
typedef struct spx_opaque_scores_file_v5 scores_file;
typedef struct spx_opaque_scores_state_v5 { score_entry entries[15]; scores_file *file; } scores_state;
typedef struct spx_opaque_scores_name_v5 { const char *text; } scores_name;
typedef struct spx_opaque_scores_bytes_v5 { unsigned char *data; uint32_t size; } scores_bytes;
static inline uint32_t score_value(const score_entry *entry) {
    const unsigned char *p=entry->value;
    return p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static inline void score_set_value(score_entry *entry,uint32_t value) {
    for (unsigned i=0;i<4;++i) entry->value[i]=(unsigned char)(value>>(8*i));
}
#endif
