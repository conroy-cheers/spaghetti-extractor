#ifndef DXBALL_MUSIC_STATE_H
#define DXBALL_MUSIC_STATE_H
#include <stdint.h>
typedef struct spx_opaque_music_stream_v5 music_stream;
typedef struct spx_opaque_music_record_v5 { music_stream *stream; uint32_t playing; } music_record;
typedef struct spx_opaque_music_state_v5 { music_record *current; } music_state;
typedef struct spx_opaque_music_name_v5 { const char *text; } music_name;
#endif
