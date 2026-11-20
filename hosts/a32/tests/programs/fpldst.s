@ Extension register loads and stores: VLDR/VSTR of single and double
@ registers (offsets, PC-relative, conditional), VLDM/VSTM in both
@ directions with writeback, VPUSH/VPOP, and VLD1-VLD4/VST1-VST4 in every
@ form (multiple structures, one lane, all lanes) for each element size,
@ with the alignment qualifiers, writeback by the transfer size and by a
@ register, and the alignment faults they take; each register and the
@ memory written recorded.
.include "common.inc"
.include "fp.inc"
.equ BUF, RAM + 0x10000
.equ DST, RAM + 0x20000
vectors
reset:
  li sp, STACK_SVC
  cps #0x17
  li sp, STACK_ABT
  cps #0x13
  li r10, OUT
  fpon
  @ A source pattern: byte k of BUF is k * 0x9d + 0x31.
  li r4, BUF
  mov r0, #0x31
  mov r1, #0
1:
  strb r0, [r4, r1]
  add r0, r0, #0x9d
  add r1, r1, #1
  cmp r1, #256
  blo 1b

  @ VLDR/VSTR: single and double, positive and negative offsets.
  li r4, BUF + 0x40
  vldr s0, [r4]
  vldr s1, [r4, #-4]
  vldr s3, [r4, #1020]
  vldr d2, [r4, #8]
  vldr d17, [r4, #-1016]
  outd 0
  outd 1
  outd 2
  outd 17
  vldr d3, literal
  b 3f
.align 3
literal:
  .word 0x11223344, 0x55667788
3:
  vldr s7, literal
  vldrne d3, literal
  outd 3
  vmov r0, s7
  out r0
  li r5, DST
  vstr s1, [r5]
  vstr s0, [r5, #4]
  vstr d17, [r5, #8]
  vstr d3, [r5, #-8]
  ldm r5, {r0-r3}
  out r0
  out r1
  out r2
  out r3
  sub r6, r5, #8
  ldm r6, {r0, r1}
  out r0
  out r1
  @ A condition that fails: no access, so no fault on a misaligned address.
  li r6, BUF + 2
  cmp r6, r6
  vldrne d2, [r6]
  vstrne s0, [r6]
  outd 2
  @ VLDM/VSTM: increment after and decrement before, with writeback.
  li r4, BUF + 0x80
  vldmia r4!, {d4-d7}
  out r4
  vldmia r4, {s16-s21}
  vldmdb r4!, {d20-d23}
  out r4
  .irp n, 4,5,6,7,8,9,10,20,21,22,23
  outd \n
  .endr
  li r5, DST + 0x100
  vstmia r5!, {d20-d21}
  vstmdb r5!, {s16-s18}
  out r5
  vstmia r5, {d4-d7}
  li r6, DST + 0xf0
  ldm r6!, {r0-r3}
  out r0
  out r1
  out r2
  out r3
  ldm r6!, {r0-r3}
  out r0
  out r1
  out r2
  out r3
  @ VPUSH/VPOP.
  mov r7, sp
  vpush {d4-d6}
  vpush {s3-s5}
  sub r0, r7, sp
  out r0
  vpop {s24-s26}
  vpop {d24-d26}
  sub r0, r7, sp
  out r0
  .irp n, 12,13,24,25,26
  outd \n
  .endr
  @ An unaligned VLDR: an alignment fault whatever SCTLR.A says (MemA).
  li r4, BUF + 2
  mov r0, #0
  vldr s0, [r4]
  out r0
  mov r0, #0
  vldmia r4, {d0}
  out r0

  @ VLD1-VLD4 and VST1-VST4: each form loads from BUF, stores to DST.
  li r4, BUF
  li r5, DST + 0x200
  mov r8, #24
.macro ldst ld, st, regs, recs
  li r4, BUF + 0x10
  \ld \regs, [r4]
  .irp n, \recs
  outd \n
  .endr
  li r5, DST + 0x200
  \st \regs, [r5]
  ldm r5, {r0-r3}
  out r0
  out r1
  out r2
  out r3
.endm
.macro ldwb ld, regs, recs
  li r4, BUF + 0x20
  \ld \regs, [r4]!
  out r4
  li r4, BUF + 0x20
  \ld \regs, [r4], r8
  out r4
  .irp n, \recs
  outd \n
  .endr
.endm
  .irp e, 8,16,32,64
  ldst vld1.\e, vst1.\e, "{d0}", "0"
  ldst vld1.\e, vst1.\e, "{d0-d1}", "0,1"
  ldst vld1.\e, vst1.\e, "{d0-d2}", "0,1,2"
  ldst vld1.\e, vst1.\e, "{d0-d3}", "0,1,2,3"
  ldwb vld1.\e, "{d4-d7}", "4,5,6,7"
  .endr
  .irp e, 8,16,32
  ldst vld2.\e, vst2.\e, "{d0-d1}", "0,1"
  ldst vld2.\e, vst2.\e, "{d0,d2}", "0,2"
  ldst vld2.\e, vst2.\e, "{d0-d3}", "0,1,2,3"
  ldst vld3.\e, vst3.\e, "{d0-d2}", "0,1,2"
  ldst vld3.\e, vst3.\e, "{d0,d2,d4}", "0,2,4"
  ldst vld4.\e, vst4.\e, "{d0-d3}", "0,1,2,3"
  ldst vld4.\e, vst4.\e, "{d0,d2,d4,d6}", "0,2,4,6"
  ldwb vld2.\e, "{d8-d9}", "8,9"
  ldwb vld3.\e, "{d10-d12}", "10,11,12"
  ldwb vld4.\e, "{d16,d18,d20,d22}", "16,18,20,22"
  .endr
  @ One lane, and all lanes.
  .irp l, 0,1,3,7
  ldst vld1.8, vst1.8, "{d0[\l]}", "0"
  ldst vld2.8, vst2.8, "{d0[\l],d1[\l]}", "0,1"
  ldst vld3.8, vst3.8, "{d0[\l],d1[\l],d2[\l]}", "0,1,2"
  ldst vld4.8, vst4.8, "{d0[\l],d1[\l],d2[\l],d3[\l]}", "0,1,2,3"
  .endr
  .irp l, 0,3
  ldst vld1.16, vst1.16, "{d0[\l]}", "0"
  ldst vld2.16, vst2.16, "{d0[\l],d2[\l]}", "0,2"
  ldst vld3.16, vst3.16, "{d0[\l],d2[\l],d4[\l]}", "0,2,4"
  ldst vld4.16, vst4.16, "{d0[\l],d2[\l],d4[\l],d6[\l]}", "0,2,4,6"
  .endr
  .irp l, 0,1
  ldst vld1.32, vst1.32, "{d0[\l]}", "0"
  ldst vld2.32, vst2.32, "{d0[\l],d1[\l]}", "0,1"
  ldst vld3.32, vst3.32, "{d0[\l],d1[\l],d2[\l]}", "0,1,2"
  ldst vld4.32, vst4.32, "{d0[\l],d2[\l],d4[\l],d6[\l]}", "0,2,4,6"
  ldwb vld1.32, "{d24[\l]}", "24"
  .endr
  .irp e, 8,16,32
  li r4, BUF + 0x31
  .if \e == 16
  li r4, BUF + 0x32
  .endif
  .if \e == 32
  li r4, BUF + 0x34
  .endif
  vld1.\e {d0[]}, [r4]
  vld1.\e {d2[],d3[]}, [r4]
  vld2.\e {d4[],d5[]}, [r4]
  vld2.\e {d6[],d8[]}, [r4]
  vld3.\e {d10[],d11[],d12[]}, [r4]
  vld3.\e {d14[],d16[],d18[]}, [r4]!
  out r4
  vld4.\e {d20[],d21[],d22[],d23[]}, [r4], r8
  out r4
  vld4.\e {d24[],d26[],d28[],d30[]}, [r4]
  .irp n, 0,2,3,4,5,6,8,10,11,12,14,16,18,20,21,22,23,24,26,28,30
  outd \n
  .endr
  .endr
  @ The alignment qualifiers: aligned addresses load, misaligned ones
  @ take an alignment fault whatever SCTLR.A says.
  li r4, BUF + 0x40
  vld1.8 {d0-d1}, [r4:128]
  vld1.32 {d2-d5}, [r4:256]
  vld2.16 {d6-d7}, [r4:128]
  vld4.8 {d8-d11}, [r4:64]
  vld1.32 {d12[1]}, [r4:32]
  vld2.16 {d13[2],d14[2]}, [r4:32]
  vld4.8 {d15[3],d16[3],d17[3],d18[3]}, [r4:32]
  vld4.32 {d19[],d20[],d21[],d22[]}, [r4:128]
  .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
  outd \n
  .endr
  li r4, BUF + 0x48
  mov r0, #0
  vld1.8 {d0-d1}, [r4:128]
  out r0
  mov r0, #0
  vst1.8 {d0-d3}, [r4:256]
  out r0
  li r4, BUF + 0x42
  mov r0, #0
  vld1.32 {d12[1]}, [r4:32]
  out r0
  mov r0, #0
  vld1.16 {d0[]}, [r4:16]
  out r0
  @ (An unaligned element without a qualifier reaches Strongly-ordered
  @ memory with the MMU off, which is UNPREDICTABLE, A3.2.2.) With
  @ SCTLR.A set a 64-bit element must be 8-byte aligned; the base register
  @ is unchanged by the faulting access.
  mrc p15, 0, r1, c1, c0, 0
  orr r1, r1, #2
  mcr p15, 0, r1, c1, c0, 0
  isb
  li r4, BUF + 0x44
  mov r0, #0
  vld1.64 {d2}, [r4]!
  out r0
  out r4
  mov r0, #0
  vld1.32 {d2}, [r4]!
  out r0
  out r4
  bic r1, r1, #2
  mcr p15, 0, r1, c1, c0, 0
  isb
  @ The memory the stores wrote.
  li r6, DST
  mov r7, #0
2:
  ldr r0, [r6, r7]
  out r0
  add r7, r7, #4
  cmp r7, #0x240
  blo 2b
  finish

dabt_handler:
  mrc p15, 0, r1, c5, c0, 0
  out r1
  mrc p15, 0, r1, c6, c0, 0
  out r1
  out lr
  mov r0, #0x77
  subs pc, lr, #4

unexpected undef_handler
unexpected svc_handler
unexpected pabt_handler
unexpected irq_handler
unexpected fiq_handler

