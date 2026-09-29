#ifndef DXBALL_PROGRAM_FILE_STORAGE_H
#define DXBALL_PROGRAM_FILE_STORAGE_H
#include <stdio.h>
#include "program-state.h"
#include "reader-state.h"

struct dxball_program_file { FILE *stream; struct dxball_program_file *next; };
struct dxball_program_bytes {
    reader_bytes reader;
    wave_bytes wave;
    unsigned live;
    struct dxball_program_bytes *next;
};
FILE *dxball_asset_open(const char *);
int dxball_file_opened(dxball_program *, struct dxball_program_file *, FILE *);
reader_bytes *dxball_program_file_read(dxball_program *, reader_name *, reader_bytes *, uint32_t);
void dxball_program_dispose_bytes(dxball_program *);
#endif
