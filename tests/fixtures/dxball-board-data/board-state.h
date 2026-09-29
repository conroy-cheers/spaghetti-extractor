#ifndef DXBALL_BOARD_STATE_H
#define DXBALL_BOARD_STATE_H
#include <stdint.h>
typedef struct { unsigned char cells[20][20]; } board;
_Static_assert(sizeof(board)==400,"board file layout");
typedef struct spx_opaque_board_file_v5 board_file;
typedef struct spx_opaque_board_set_v5 {
    board current, saved[50];
    board_file *file;
} board_set;
typedef struct spx_opaque_board_name_v5 { const char *text; } board_name;
typedef struct spx_opaque_board_bytes_v5 { unsigned char *data; uint32_t size; } board_bytes;
#endif
