#ifndef SPX_WINE_TEST_H
#define SPX_WINE_TEST_H
/* Shared executable comparison environment. Application layouts and component
 * entry points belong to the caller. Controlled schedules are test inputs,
 * never claims about the behavior of an actual Windows or Wine implementation. */
#include <stddef.h>
#include <stdint.h>
#include "spx-observation.h"

typedef struct spx_wine_env spx_wine_env;
typedef struct spx_wine_object spx_wine_object;
enum spx_wine_mode { SPX_WINE_CONTROLLED, SPX_WINE_NATIVE };
enum spx_wine_kind { SPX_WINE_DS_DEVICE=1, SPX_WINE_DS_BUFFER=2,
    SPX_WINE_DD_DEVICE=3, SPX_WINE_DD_SURFACE=4 };
enum spx_wine_api {
    SPX_DS_CREATE, SPX_DS_COOPERATIVE, SPX_DS_CREATE_BUFFER,
    SPX_COM_RELEASE, SPX_COM_ADDREF, SPX_COM_QUERY,
    SPX_DS_FREQUENCY, SPX_DS_PAN, SPX_DS_VOLUME, SPX_DS_POSITION,
    SPX_DS_PLAY, SPX_DS_STATUS, SPX_DS_RESTORE, SPX_DS_STOP,
    SPX_DS_GET_FREQUENCY, SPX_DS_GET_PAN, SPX_DS_GET_VOLUME,
    SPX_DS_LOCK, SPX_DS_UNLOCK, SPX_USER_MESSAGE_A,
    SPX_FILE_OPEN_A, SPX_FILE_SIZE, SPX_FILE_READ, SPX_HANDLE_CLOSE,
    SPX_FILE_MAPPING_A, SPX_FILE_MAP, SPX_FILE_UNMAP,
    SPX_LOCAL_ALLOC, SPX_LOCAL_FREE, SPX_GLOBAL_ALLOC, SPX_GLOBAL_LOCK,
    SPX_GLOBAL_UNLOCK, SPX_GLOBAL_FREE, SPX_GLOBAL_HANDLE,
    SPX_MIDI_OPEN, SPX_MIDI_PROPERTY, SPX_MIDI_PREPARE, SPX_MIDI_OUT,
    SPX_MIDI_RESTART, SPX_MIDI_PAUSE, SPX_MIDI_RESET, SPX_MIDI_UNPREPARE,
    SPX_MIDI_CLOSE, SPX_MIDI_CALLBACK,
    SPX_DD_CREATE, SPX_DD_COOPERATIVE, SPX_DD_CREATE_SURFACE,
    SPX_DD_DESCRIBE, SPX_DD_LOCK, SPX_DD_UNLOCK, SPX_DD_BLT, SPX_WINE_API_COUNT
};
enum { SPX_RULE_RETURN=1, SPX_RULE_OBJECT=2, SPX_RULE_WORD=4,
       SPX_RULE_NO_WRITE=8, SPX_RULE_CALLBACK=16,
       SPX_RULE_BYTES=32, SPX_RULE_ERROR=64, SPX_RULE_LIMIT=128,
       SPX_RULE_DEFER_COMPLETIONS=256 };
/* MIDI open failure: explicitly publish a new, non-live output identity. */
#define SPX_WINE_FAILED_PUBLICATION UINT32_MAX
typedef struct {
    enum spx_wine_api api;
    uint32_t receiver, occurrence, flags, result, object, references, mask, value, callback;
    uint32_t last_error, limit, byte_count;
    const unsigned char *bytes; /* Copied when the rule is added. */
} spx_wine_rule;
typedef struct {
    uint32_t references, status, frequency, pan, volume, position, generation;
} spx_wine_object_state;
typedef struct {
    uint32_t size, flags, bytes, reserved;
    const void *format;
} spx_wine_buffer_spec;
typedef struct {
    void *first, *second;
    uint32_t first_bytes, second_bytes;
} spx_wine_locked;
typedef struct {
    enum spx_wine_api api;
    spx_wine_object *receiver;
    uint32_t arguments[8], argument_count;
    /* Object outputs are writable storage for a structure pointer. memcpy
     * preserves the representation without aliasing incompatible pointer types. */
    void *output;
    const void *input;
    uintptr_t window;
    const char *text, *caption;
    uintptr_t handle;
    void *buffer, *overlapped;
} spx_wine_call;
typedef struct {
    enum spx_wine_api api;
    uint32_t sequence, receiver, kind, occurrence, arguments[8], argument_count;
    uint32_t result, output_object, output_word, written_mask, callback;
    uint32_t references_before, references_after, generation, controlled;
    uint32_t output_before; /* Adapter transport only; not an unconditional observation. */
    uint32_t window, first_bytes, second_bytes;
    unsigned char *data;
    size_t data_bytes;
    char *text, *caption;
    uint32_t last_error, handle_live_before, handle_live_after, buffer_extent;
    uint32_t transferred, footprint_known, preserved, output_preserved, positions_known, handle_known;
    uint64_t file_position_before, file_position_after;
    unsigned char *byte_mask;
    uint32_t storage, storage_offset, storage_extent, locks_before, locks_after;
    uint32_t input_identity;
} spx_wine_event;
typedef struct {
    void *context;
    void (*before)(void *,const spx_wine_event *);
    void (*callback)(void *,uint32_t);
    void (*after)(void *,const spx_wine_event *);
} spx_wine_hooks;

spx_wine_env *spx_wine_create(enum spx_wine_mode);
void spx_wine_destroy(spx_wine_env *);
void spx_wine_set_hooks(spx_wine_env *,spx_wine_hooks);
/* Bind external inputs by boundary correspondence, not by first use in a trace. */
void spx_wine_bind_window(spx_wine_env *,uintptr_t,uint32_t);
void spx_wine_add_rule(spx_wine_env *,spx_wine_rule);
spx_wine_object *spx_wine_seed(spx_wine_env *,uint32_t,enum spx_wine_kind,spx_wine_object_state);
spx_wine_object *spx_wine_object_at(spx_wine_env *,uint32_t);
uint32_t spx_wine_object_id(const void *);
enum spx_wine_kind spx_wine_object_kind(const void *);
spx_wine_object_state spx_wine_state(const void *);
void spx_wine_controlled_state(spx_wine_object *,spx_wine_object_state);
uint32_t spx_wine_invoke(spx_wine_env *,spx_wine_call);
/* Candidate platform binding: on Win32 this invokes the same SDK-typed COM
 * entry points as machine callers. The environment has no candidate-side flag. */
uint32_t spx_wine_candidate_call(spx_wine_env *,spx_wine_call);
/* Legacy DDSURFACEDESC transport retains all 108 ABI bytes except lpSurface,
 * which is carried separately at host pointer width. words[9] must be zero.
 * Unselected descriptor fields retain caller history but are not API inputs. */
typedef struct { uint32_t words[27]; void *pixels; } spx_wine_surface_desc;
typedef struct { int32_t left,top,right,bottom; } spx_wine_rect;
typedef struct {
    const spx_wine_rect *destination;
    spx_wine_object *source;
    const spx_wine_rect *source_rect;
    uint32_t flags,effects_size,fill_color;
} spx_wine_blt;
int spx_wine_install_draw(spx_wine_env *,const char *module);
int spx_wine_uninstall_draw(spx_wine_env *);
/* Seed a controlled surface with exact full backing bytes, including padding.
 * Negative pitch puts row zero at the final physical row. No application layout
 * or candidate role is supplied. Descriptor includes pitch and pixel format. */
spx_wine_object *spx_wine_seed_surface(spx_wine_env *,uint32_t,
    const spx_wine_surface_desc *,const void *,uint32_t);
const unsigned char *spx_wine_surface_bytes(spx_wine_object *,uint32_t *size);
/* Bind a borrowed native interface by an explicit boundary input identity.
 * Its owner must keep it alive for the experiment. Acquisition/refcount methods
 * are outside this borrowed boundary; the environment neither owns nor releases it. */
spx_wine_object *spx_wine_bind_surface(spx_wine_env *,void *native,uint32_t input_identity);
void spx_wine_observe(spx_wine_env *,spx_observer *,const char *);
const char *spx_wine_api_name(enum spx_wine_api);
/* One selected environment per importing process; object calls retain their
 * owner. Install/restore via the existing checked PE32 import mechanism. */
int spx_wine_install(spx_wine_env *,const char *module,int sound,int messages);
int spx_wine_uninstall(spx_wine_env *);
void spx_wine_unavailable(const char *);

typedef struct {
    uint32_t size; /* Original PE32 SECURITY_ATTRIBUTES size, twelve bytes. */
    const void *descriptor;
    uint32_t inherit;
} spx_wine_file_security;

/* Synchronous file services share the same events, rules and hooks. The controlled
 * filesystem is explicit scenario input, with exact path spellings. Native mode
 * retains real HANDLE values; observers use separate lifetime identities. */
#define SPX_WINE_INVALID_HANDLE UINTPTR_MAX
enum { SPX_WINE_FILES_OPEN=1, SPX_WINE_FILES_SIZE=2, SPX_WINE_FILES_READ=4,
       SPX_WINE_FILES_CLOSE=8, SPX_WINE_FILES_ALL=15,
       SPX_WINE_FILES_NATIVE_UNBOUND_CLOSE=16 };
void spx_wine_seed_file(spx_wine_env *,const char *,const void *,uint32_t);
/* Bind incoming resources by explicit boundary identity, in ascending id order.
 * A controlled file path must name a seeded asset; NULL admits CloseHandle only.
 * The supplied position is a boundary premise for an existing native handle. */
void spx_wine_bind_handle(spx_wine_env *,uintptr_t,uint32_t,const char *,uint64_t);
int spx_wine_install_files(spx_wine_env *,const char *module,unsigned operations);
int spx_wine_uninstall_files(spx_wine_env *);
uintptr_t spx_wine_file_open(spx_wine_env *,const char *,uint32_t access,uint32_t share,
    const void *security,uint32_t disposition,uint32_t attributes,uintptr_t template_handle);
uint32_t spx_wine_file_size(spx_wine_env *,uintptr_t,void *high_word);
uint32_t spx_wine_file_read(spx_wine_env *,uintptr_t,void *,uint32_t,void *count,void *overlapped);
uint32_t spx_wine_file_close(spx_wine_env *,uintptr_t);
uint32_t spx_wine_file_last_error(spx_wine_env *);
uint32_t spx_wine_file_identity(spx_wine_env *,uintptr_t);

/* Read-only, unnamed mappings over observed files. Closing either handle does
 * not unmap a view. Mapping/view identities are independent of process addresses. */
enum { SPX_WINE_MAPPINGS_CREATE=1, SPX_WINE_MAPPINGS_MAP=2,
       SPX_WINE_MAPPINGS_UNMAP=4, SPX_WINE_MAPPINGS_ALL=7 };
int spx_wine_install_mappings(spx_wine_env *,const char *module,unsigned operations);
uintptr_t spx_wine_file_mapping(spx_wine_env *,uintptr_t,const void *security,
    uint32_t protection,uint32_t maximum_high,uint32_t maximum_low,const char *name);
void *spx_wine_file_map(spx_wine_env *,uintptr_t,uint32_t access,
    uint32_t offset_high,uint32_t offset_low,size_t size);
uint32_t spx_wine_file_unmap(spx_wine_env *,const void *);

/* Allocations preserve the Win32 handle/pointer distinction and lock counts.
 * Allocation bytes containing application pointers are observed through the
 * component's ordinary state correspondence, never as raw address equality. */
enum { SPX_WINE_MEMORY_LOCAL_ALLOC=1, SPX_WINE_MEMORY_LOCAL_FREE=2,
       SPX_WINE_MEMORY_GLOBAL_ALLOC=4, SPX_WINE_MEMORY_GLOBAL_LOCK=8,
       SPX_WINE_MEMORY_GLOBAL_UNLOCK=16, SPX_WINE_MEMORY_GLOBAL_FREE=32,
       SPX_WINE_MEMORY_GLOBAL_HANDLE=64, SPX_WINE_MEMORY_ALL=127 };
int spx_wine_install_memory(spx_wine_env *,const char *module,unsigned operations);
/* Explicit allocator history for controlled non-zero-initialized allocations.
 * SPX_RULE_BYTES may override individual allocations with exact initial bytes. */
void spx_wine_allocation_history(spx_wine_env *,unsigned char);
uintptr_t spx_wine_local_alloc(spx_wine_env *,uint32_t,size_t);
uintptr_t spx_wine_local_free(spx_wine_env *,uintptr_t);
uintptr_t spx_wine_global_alloc(spx_wine_env *,uint32_t,size_t);
void *spx_wine_global_lock(spx_wine_env *,uintptr_t);
uint32_t spx_wine_global_unlock(spx_wine_env *,uintptr_t);
uintptr_t spx_wine_global_free(spx_wine_env *,uintptr_t);
uintptr_t spx_wine_global_handle(spx_wine_env *,const void *);
typedef struct { uint32_t identity,offset,extent,live,locks; } spx_wine_storage;
spx_wine_storage spx_wine_memory_storage(spx_wine_env *,const void *);
void *spx_wine_memory_address(spx_wine_env *,uint32_t identity);
spx_wine_storage spx_wine_mapped_storage(spx_wine_env *,const void *);

/* MIDI buffers retain their identity until unprepared. A controlled completion
 * is an explicit finite scenario step; native mode forwards Wine callbacks on
 * their actual thread. Function callbacks require a boundary identity binding. */
#ifdef _WIN32
#include <windows.h>
#include <mmsystem.h>
typedef MIDIHDR spx_wine_midi_header;
#define SPX_WINE_CALLBACK __stdcall
#else
typedef struct spx_wine_midi_header {
    char *lpData;
    uint32_t dwBufferLength,dwBytesRecorded;
    uintptr_t dwUser;
    uint32_t dwFlags;
    struct spx_wine_midi_header *lpNext;
    uintptr_t reserved;
    uint32_t dwOffset;
    uintptr_t dwReserved[8];
} spx_wine_midi_header;
#define SPX_WINE_CALLBACK
#endif
typedef void (SPX_WINE_CALLBACK *spx_wine_midi_callback)(uintptr_t,uint32_t,uintptr_t,uintptr_t,uintptr_t);
enum { SPX_WINE_MIDI_OPEN=1, SPX_WINE_MIDI_PROPERTY=2, SPX_WINE_MIDI_PREPARE=4,
       SPX_WINE_MIDI_OUT=8, SPX_WINE_MIDI_RESTART=16, SPX_WINE_MIDI_PAUSE=32,
       SPX_WINE_MIDI_RESET=64, SPX_WINE_MIDI_UNPREPARE=128,
       SPX_WINE_MIDI_CLOSE=256, SPX_WINE_MIDI_ALL=511 };
int spx_wine_install_midi(spx_wine_env *,const char *module,unsigned operations);
void spx_wine_bind_midi_callback(spx_wine_env *,spx_wine_midi_callback,uintptr_t instance,uint32_t identity);
void spx_wine_bind_midi_user(spx_wine_env *,uintptr_t,uint32_t identity);
/* Allocation-backed user pointers retire with their allocation; recycled native
 * addresses then receive the new allocation's identity. Scalar bindings do not. */
void spx_wine_bind_midi_allocation_user(spx_wine_env *,uint32_t allocation_identity);
/* A translated header may live outside its original allocation. Bind its
 * logical 64-byte header extent to checked live allocation storage so disposal
 * preserves the same lifetime observation on hosts with wider pointers. */
void spx_wine_bind_midi_header_storage(spx_wine_env *,spx_wine_midi_header *,uint32_t allocation_identity,uint32_t offset);
/* Controlled experiments only: record disposal of still-retained storage.
 * Later API use or callback delivery through that retired header is rejected. */
void spx_wine_allow_retained_midi_disposal(spx_wine_env *);
uint32_t spx_wine_midi_open(spx_wine_env *,void *stream_out,uint32_t *device,uint32_t count,
    spx_wine_midi_callback,uintptr_t instance,uint32_t flags);
uint32_t spx_wine_midi_property(spx_wine_env *,uintptr_t,void *,uint32_t flags);
uint32_t spx_wine_midi_header_call(spx_wine_env *,enum spx_wine_api,uintptr_t,spx_wine_midi_header *,uint32_t abi_size);
uint32_t spx_wine_midi_stream_call(spx_wine_env *,enum spx_wine_api,uintptr_t);
uint32_t spx_wine_midi_header_identity(spx_wine_env *,const spx_wine_midi_header *);
void spx_wine_midi_complete(spx_wine_env *,uintptr_t stream,uint32_t header_identity);

static inline uint32_t spx_wine_method(spx_wine_env *e,enum spx_wine_api api,void *receiver,uint32_t value) {
    spx_wine_call c={0};c.api=api;c.receiver=receiver;c.arguments[0]=value;c.argument_count=1;
    return spx_wine_invoke(e,c);
}
#endif
