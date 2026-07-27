#ifndef BOCHS_CONFORMANCE_PROTOCOL_H
#define BOCHS_CONFORMANCE_PROTOCOL_H

#define BC_CONTROL_PORT 0xbef0
#define BC_SIGNAL_READY 0x434f4e46

#define BC_MAILBOX_ADDRESS 0x00005000
#define BC_HARNESS_STACK_TOP 0x00009000
#define BC_TEST_ADDRESS_MIN 0x00010000
#define BC_TEST_ADDRESS_MAX 0x00fffff0
#define BC_GUEST_RAM_END 0x01000000

#define BC_MAX_MEMORY_REGIONS 32
#define BC_MAX_MEMORY_BYTES 65536
#define BC_INSTRUCTION_SLOT_BYTES 15

#define BC_MAILBOX_RESUME_EIP 0
#define BC_MAILBOX_STATUS 4
#define BC_MAILBOX_EIP 8
#define BC_MAILBOX_EFLAGS 12
#define BC_MAILBOX_EAX 16
#define BC_MAILBOX_EBX 20
#define BC_MAILBOX_ECX 24
#define BC_MAILBOX_EDX 28
#define BC_MAILBOX_ESI 32
#define BC_MAILBOX_EDI 36
#define BC_MAILBOX_EBP 40
#define BC_MAILBOX_ESP 44
#define BC_MAILBOX_LENGTH 48
#define BC_MAILBOX_SIZE 64

#define BC_MAILBOX_EMPTY 0
#define BC_MAILBOX_EXECUTE 1
#define BC_MAILBOX_SKIP 2
#define BC_MAILBOX_END 3

#define BC_REQUIRE_MEMORY 0x00000001
#define BC_REQUIRE_FAULT 0x00000002
#define BC_REQUIRE_X87 0x00000004
#define BC_REQUIRE_SEGMENT_STATE 0x00000008
#define BC_REQUIRE_BRANCH 0x00000010
#define BC_REQUIRE_PROFILE 0x00000020
#define BC_REQUIRE_INSTRUCTION 0x00000040
#define BC_REQUIRE_MEMORY_BOUNDS 0x00000080
#define BC_REQUIRE_KNOWN_MASK 0x000000ff

#define BC_SAFE_EFLAGS_MASK 0x00000ed7

#ifndef __ASSEMBLER__

#include <stddef.h>

struct bc_mailbox {
  Bit32u resume_eip;
  Bit32u status;
  Bit32u eip;
  Bit32u eflags;
  Bit32u eax;
  Bit32u ebx;
  Bit32u ecx;
  Bit32u edx;
  Bit32u esi;
  Bit32u edi;
  Bit32u ebp;
  Bit32u esp;
  Bit8u length;
  Bit8u reserved[15];
};

typedef char bc_mailbox_size_must_match[
  sizeof(struct bc_mailbox) == BC_MAILBOX_SIZE ? 1 : -1];
typedef char bc_mailbox_status_offset_must_match[
  offsetof(struct bc_mailbox, status) == BC_MAILBOX_STATUS ? 1 : -1];
typedef char bc_mailbox_length_offset_must_match[
  offsetof(struct bc_mailbox, length) == BC_MAILBOX_LENGTH ? 1 : -1];

#endif

#endif
