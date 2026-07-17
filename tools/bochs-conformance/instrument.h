#ifndef BOCHS_CONFORMANCE_INSTRUMENT_H
#define BOCHS_CONFORMANCE_INSTRUMENT_H

#if BX_INSTRUMENTATION

class bxInstruction_c;

#define BX_INSTR_STORE_OPCODE_BYTES

void bx_instr_init_env(void);
void bx_instr_exit_env(void);
void bx_instr_initialize(unsigned cpu);
void bx_instr_exit(unsigned cpu);
void bx_instr_reset(unsigned cpu, unsigned type);
void bx_instr_hlt(unsigned cpu);
void bx_instr_mwait(unsigned cpu, bx_phy_address addr, unsigned len,
                    Bit32u flags);
void bx_instr_debug_promt(void);
void bx_instr_debug_cmd(const char *cmd);
void bx_instr_cnear_branch_taken(unsigned cpu, bx_address branch_eip,
                                 bx_address new_eip);
void bx_instr_cnear_branch_not_taken(unsigned cpu, bx_address branch_eip);
void bx_instr_ucnear_branch(unsigned cpu, unsigned what,
                            bx_address branch_eip, bx_address new_eip);
void bx_instr_far_branch(unsigned cpu, unsigned what, Bit16u prev_cs,
                         bx_address prev_eip, Bit16u new_cs,
                         bx_address new_eip);
void bx_instr_opcode(unsigned cpu, bxInstruction_c *i, const Bit8u *opcode,
                     unsigned len, bool is32, bool is64);
void bx_instr_interrupt(unsigned cpu, unsigned vector);
void bx_instr_exception(unsigned cpu, unsigned vector, unsigned error_code);
void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs,
                          bx_address eip);
void bx_instr_tlb_cntrl(unsigned cpu, unsigned what,
                        bx_phy_address new_cr3);
void bx_instr_cache_cntrl(unsigned cpu, unsigned what);
void bx_instr_prefetch_hint(unsigned cpu, unsigned what, unsigned seg,
                            bx_address offset);
void bx_instr_clflush(unsigned cpu, bx_address laddr, bx_phy_address paddr);
void bx_instr_before_execution(unsigned cpu, bxInstruction_c *i);
void bx_instr_after_execution(unsigned cpu, bxInstruction_c *i);
void bx_instr_repeat_iteration(unsigned cpu, bxInstruction_c *i);
void bx_instr_inp(Bit16u addr, unsigned len);
void bx_instr_inp2(Bit16u addr, unsigned len, unsigned val);
void bx_instr_outp(Bit16u addr, unsigned len, unsigned val);
void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_address phy,
                         unsigned len, unsigned memtype, unsigned rw);
void bx_instr_phy_access(unsigned cpu, bx_address phy, unsigned len,
                         unsigned memtype, unsigned rw);
void bx_instr_wrmsr(unsigned cpu, unsigned addr, Bit64u value);
void bx_instr_vmexit(unsigned cpu, Bit32u reason, Bit64u qualification);

#define BX_INSTR_INIT_ENV() bx_instr_init_env()
#define BX_INSTR_EXIT_ENV() bx_instr_exit_env()
#define BX_INSTR_INITIALIZE(cpu) bx_instr_initialize(cpu)
#define BX_INSTR_EXIT(cpu) bx_instr_exit(cpu)
#define BX_INSTR_RESET(cpu, type) bx_instr_reset(cpu, type)
#define BX_INSTR_HLT(cpu) bx_instr_hlt(cpu)
#define BX_INSTR_MWAIT(cpu, addr, len, flags) \
  bx_instr_mwait(cpu, addr, len, flags)
#define BX_INSTR_DEBUG_PROMPT() bx_instr_debug_promt()
#define BX_INSTR_DEBUG_CMD(cmd) bx_instr_debug_cmd(cmd)
#define BX_INSTR_CNEAR_BRANCH_TAKEN(cpu, old_eip, new_eip) \
  bx_instr_cnear_branch_taken(cpu, old_eip, new_eip)
#define BX_INSTR_CNEAR_BRANCH_NOT_TAKEN(cpu, old_eip) \
  bx_instr_cnear_branch_not_taken(cpu, old_eip)
#define BX_INSTR_UCNEAR_BRANCH(cpu, what, old_eip, new_eip) \
  bx_instr_ucnear_branch(cpu, what, old_eip, new_eip)
#define BX_INSTR_FAR_BRANCH(cpu, what, prev_cs, prev_eip, new_cs, new_eip) \
  bx_instr_far_branch(cpu, what, prev_cs, prev_eip, new_cs, new_eip)
#define BX_INSTR_OPCODE(cpu, i, opcode, len, is32, is64) \
  bx_instr_opcode(cpu, i, opcode, len, is32, is64)
#define BX_INSTR_EXCEPTION(cpu, vector, error_code) \
  bx_instr_exception(cpu, vector, error_code)
#define BX_INSTR_INTERRUPT(cpu, vector) bx_instr_interrupt(cpu, vector)
#define BX_INSTR_HWINTERRUPT(cpu, vector, cs, eip) \
  bx_instr_hwinterrupt(cpu, vector, cs, eip)
#define BX_INSTR_CLFLUSH(cpu, laddr, paddr) \
  bx_instr_clflush(cpu, laddr, paddr)
#define BX_INSTR_CACHE_CNTRL(cpu, what) bx_instr_cache_cntrl(cpu, what)
#define BX_INSTR_TLB_CNTRL(cpu, what, new_cr3) \
  bx_instr_tlb_cntrl(cpu, what, new_cr3)
#define BX_INSTR_PREFETCH_HINT(cpu, what, seg, offset) \
  bx_instr_prefetch_hint(cpu, what, seg, offset)
#define BX_INSTR_BEFORE_EXECUTION(cpu, i) bx_instr_before_execution(cpu, i)
#define BX_INSTR_AFTER_EXECUTION(cpu, i) bx_instr_after_execution(cpu, i)
#define BX_INSTR_REPEAT_ITERATION(cpu, i) bx_instr_repeat_iteration(cpu, i)
#define BX_INSTR_LIN_ACCESS(cpu, lin, phy, len, memtype, rw) \
  bx_instr_lin_access(cpu, lin, phy, len, memtype, rw)
#define BX_INSTR_PHY_ACCESS(cpu, phy, len, memtype, rw) \
  bx_instr_phy_access(cpu, phy, len, memtype, rw)
#define BX_INSTR_INP(addr, len) bx_instr_inp(addr, len)
#define BX_INSTR_INP2(addr, len, val) bx_instr_inp2(addr, len, val)
#define BX_INSTR_OUTP(addr, len, val) bx_instr_outp(addr, len, val)
#define BX_INSTR_WRMSR(cpu, addr, value) bx_instr_wrmsr(cpu, addr, value)
#define BX_INSTR_VMEXIT(cpu, reason, qualification) \
  bx_instr_vmexit(cpu, reason, qualification)

#else

#define BX_INSTR_INIT_ENV()
#define BX_INSTR_EXIT_ENV()
#define BX_INSTR_INITIALIZE(cpu)
#define BX_INSTR_EXIT(cpu)
#define BX_INSTR_RESET(cpu, type)
#define BX_INSTR_HLT(cpu)
#define BX_INSTR_MWAIT(cpu, addr, len, flags)
#define BX_INSTR_DEBUG_PROMPT()
#define BX_INSTR_DEBUG_CMD(cmd)
#define BX_INSTR_CNEAR_BRANCH_TAKEN(cpu, old_eip, new_eip)
#define BX_INSTR_CNEAR_BRANCH_NOT_TAKEN(cpu, old_eip)
#define BX_INSTR_UCNEAR_BRANCH(cpu, what, old_eip, new_eip)
#define BX_INSTR_FAR_BRANCH(cpu, what, prev_cs, prev_eip, new_cs, new_eip)
#define BX_INSTR_OPCODE(cpu, i, opcode, len, is32, is64)
#define BX_INSTR_EXCEPTION(cpu, vector, error_code)
#define BX_INSTR_INTERRUPT(cpu, vector)
#define BX_INSTR_HWINTERRUPT(cpu, vector, cs, eip)
#define BX_INSTR_CLFLUSH(cpu, laddr, paddr)
#define BX_INSTR_CACHE_CNTRL(cpu, what)
#define BX_INSTR_TLB_CNTRL(cpu, what, new_cr3)
#define BX_INSTR_PREFETCH_HINT(cpu, what, seg, offset)
#define BX_INSTR_BEFORE_EXECUTION(cpu, i)
#define BX_INSTR_AFTER_EXECUTION(cpu, i)
#define BX_INSTR_REPEAT_ITERATION(cpu, i)
#define BX_INSTR_LIN_ACCESS(cpu, lin, phy, len, memtype, rw)
#define BX_INSTR_PHY_ACCESS(cpu, phy, len, memtype, rw)
#define BX_INSTR_INP(addr, len)
#define BX_INSTR_INP2(addr, len, val)
#define BX_INSTR_OUTP(addr, len, val)
#define BX_INSTR_WRMSR(cpu, addr, value)
#define BX_INSTR_VMEXIT(cpu, reason, qualification)

#endif

#endif
