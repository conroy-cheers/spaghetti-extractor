#ifndef DXBALL_WARNING_HISTORY_H
#define DXBALL_WARNING_HISTORY_H
#include "warning-state.h"
/* Compatibility projections for the reviewed native gameplay-frame call sites.
 * These are values in the selected original environment, never host addresses. */
typedef struct {
    warning_input words;
    uint32_t incoming_ebp,incoming_esi;
} warning_frame_history;
static inline void warning_history_paddle(warning_frame_history *history,uint32_t sprite,uint32_t offset) {
    history->words=(warning_input){1,sprite,offset};
}
static inline void warning_history_frame_sprite(warning_frame_history *history) {
    history->words=(warning_input){0,history->incoming_esi,history->incoming_ebp};
}
static inline void warning_history_pickup_sprite(warning_frame_history *history) {
    history->words=(warning_input){history->incoming_esi,history->incoming_ebp,1};
}
/* Preserve bytes that a descriptor service does not write. The same descriptor
 * survives describe and every lock retry. Other descriptor fields retain their
 * existing service/view contract; these helpers cover the additional 12 bytes. */
static inline void warning_history_to_descriptor(const warning_frame_history *history,uint32_t descriptor[27]) {
    descriptor[20]=history->words.y;descriptor[21]=history->words.row;descriptor[22]=history->words.column;
}
static inline void warning_history_from_descriptor(warning_frame_history *history,const uint32_t descriptor[27]) {
    history->words=(warning_input){descriptor[20],descriptor[21],descriptor[22]};
}
#endif
