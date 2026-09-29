#ifndef DXBALL_PROGRAM_MDS_STORAGE_H
#define DXBALL_PROGRAM_MDS_STORAGE_H
#include "mds-state.h"

struct dxball_program;
/* Resource records retain their own storage; MIDI callbacks borrow them until
 * the stream is closed. No native image address is needed to recover an owner. */
void dxball_mds_attach(mds_info *, struct dxball_program *);
struct dxball_program *dxball_mds_program(mds_info *);
void *dxball_mds_attachment(mds_info *);
void dxball_mds_set_attachment(mds_info *, void *, void (*)(void *));
#endif
