@ Modes and exceptions: the banked registers of every mode, SVC, UDF and
@ BKPT entry and return, an alignment Data Abort with its DFSR and DFAR,
@ SRS/RFE, MRS/MSR of the CPSR and SPSR, User mode and the way back to SVC,
@ LDM/STM of the User registers, and an SVC inside a Thumb IT block, whose
@ ITSTATE the return restores.
.include "common.inc"
vectors
reset:
  @ The flags are UNKNOWN at reset (B1.9.1): give them a value.
  msr APSR_nzcvq, #0
  li r10, OUT
  @ A stack and distinct banked registers in every mode.
  cps #0x1b
  li sp, STACK_UND
  mov lr, #0x1b
  cps #0x17
  li sp, STACK_ABT
  mov lr, #0x17
  cps #0x12
  li sp, STACK_IRQ
  mov lr, #0x12
  cps #0x11
  li sp, STACK_FIQ
  mov r8, #0x81
  mov r9, #0x91
  mov r10, #0xa1
  mov r11, #0xb1
  mov r12, #0xc1
  mov lr, #0x11
  cps #0x1f
  li sp, STACK_USR
  mov lr, #0x1f
  cps #0x13
  li sp, STACK_SVC
  li r10, OUT
  mov r8, #8
  mov r9, #9
  mov r11, #11
  mov r12, #12
  @ The banks, read back from each mode.
  mrs r0, cpsr
  out r0
  cps #0x11
  mov r0, r8
  mov r1, r12
  mov r2, lr
  cps #0x13
  out r0
  out r1
  out r2
  out r8
  out r12
  cps #0x1f
  mov r0, sp
  mov r1, lr
  cps #0x13
  out r0
  out r1
  @ SVC: the handler records the SPSR, LR and the immediate.
  li r0, 0x1234
  msr APSR_nzcvq, #0x90000000
  svc #0x42
  out r0
  outflags
  @ UDF.
  mov r0, #0
  udf #7
  out r0
  @ An alignment Data Abort, which the handler skips: LDM needs a word
  @ aligned address whatever SCTLR.A says (A3.2.1). (An unaligned LDR would
  @ reach Strongly-ordered memory with the MMU off, which is UNPREDICTABLE
  @ without the Virtualization Extensions, A3.2.2.)
  li r4, RAM + 0x10002
  mov r0, #0
  ldm r4, {r1, r2}
  out r0
  @ BKPT: a debug event taken as a Prefetch Abort.
  mov r0, #0
  bkpt #0x33
  out r0
  @ MSR to the SPSR and MRS of it.
  li r0, 0xf80f0010
  msr spsr_fsxc, r0
  mrs r1, spsr
  out r1
  @ SRS and RFE: return through the SVC stack.
  adr r0, 1f
  li r1, 0x60000013
  push {r0, r1}
  rfeia sp!
  b .
1:
  mrs r0, cpsr
  out r0
  @ User registers by LDM/STM ^ from SVC.
  li r6, RAM + 0x11000
  stmia r6, {r13, r14}^
  ldr r0, [r6]
  ldr r1, [r6, #4]
  out r0
  out r1
  li r0, 0x13579bdf
  li r1, 0x2468ace0
  stmia r6, {r0, r1}
  ldmia r6, {r13, r14}^
  cps #0x1f
  mov r0, sp
  mov r1, lr
  li sp, STACK_USR
  cps #0x13
  out r0
  out r1
  @ User mode: CPS is a NOP there, MRS gives the APSR, SVC gets out.
  mrs r0, cpsr
  bic r0, r0, #0x1f
  orr r0, r0, #0x10
  msr cpsr_c, r0
  cpsid aif
  mrs r0, cpsr
  out r0
  mov r0, #0x777
  svc #1
  mrs r0, cpsr
  out r0
  @ SVC inside a Thumb IT block, the rest of the block after the return.
  adr r12, thumb_it + 1
  blx r12
  finish

.thumb
.thumb_func
thumb_it:
  push {lr}
  movs r2, #0
  movs r3, #0
  cmp r2, #0
  itete eq
  svceq #5
  addne r2, #1
  addeq r3, #2
  addne r2, #4
  out r2
  out r3
  outflags
  pop {pc}

.arm
svc_handler:
  push {r1-r3, lr}
  mrs r1, spsr
  out r1
  out lr
  @ The immediate: Thumb SVC is a halfword, ARM a word.
  tst r1, #0x20
  ldrbne r2, [lr, #-2]
  ldreq r2, [lr, #-4]
  biceq r2, r2, #0xff000000
  out r2
  @ From User mode: back to SVC in the SPSR.
  and r3, r1, #0x1f
  cmp r3, #0x10
  biceq r1, r1, #0x1f
  orreq r1, r1, #0x13
  msreq spsr_c, r1
  add r0, r0, #1
  pop {r1-r3, lr}
  movs pc, lr

undef_handler:
  mrs r1, spsr
  out r1
  out lr
  mov r0, #0x99
  movs pc, lr

dabt_handler:
  mrc p15, 0, r1, c5, c0, 0
  out r1
  mrc p15, 0, r1, c6, c0, 0
  out r1
  out lr
  mrs r1, spsr
  out r1
  mov r0, #0xda
  subs pc, lr, #4

pabt_handler:
  mrc p15, 0, r1, c5, c0, 1
  out r1
  mrc p15, 0, r1, c6, c0, 2
  out r1
  out lr
  mov r0, #0xb0
  @ Return past the BKPT: LR is its address + 4.
  movs pc, lr

unexpected irq_handler
unexpected fiq_handler
.ltorg
