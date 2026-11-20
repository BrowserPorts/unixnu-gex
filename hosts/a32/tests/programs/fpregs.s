@ The extension register file and the Floating-point system registers:
@ the CPACR and FPEXC enables (UNDEFINED until both allow an access),
@ VMRS/VMSR of FPSID, MVFR0/1, FPEXC and
@ the FPSCR (its read/write and RAZ/WI bits, APSR_nzcv), every VMOV
@ between the core and extension registers, the scalar forms, VDUP, and
@ the S/D/Q aliasing.
.include "common.inc"
.fpu neon-vfpv4
vectors
reset:
  msr APSR_nzcvq, #0
  cps #0x1b
  li sp, STACK_UND
  cps #0x13
  li sp, STACK_SVC
  li r10, OUT
  @ CPACR resets to 0: an extension register access is UNDEFINED.
  mov r0, #0
  vmov s0, r0
  out r0
  @ cp10 and cp11 full access; FPEXC.EN is still 0.
  li r1, 0x00f00000
  mcr p15, 0, r1, c1, c0, 2
  isb
  mrc p15, 0, r1, c1, c0, 2
  out r1
  mov r0, #0
  vmov s0, r0
  out r0
  @ FPSID, MVFR0/1 and FPEXC do not need FPEXC.EN (B9.3.21).
  vmrs r2, fpsid
  out r2
  vmrs r2, mvfr0
  out r2
  vmrs r2, mvfr1
  out r2
  vmrs r2, fpexc
  out r2
  mov r1, #0x40000000
  vmsr fpexc, r1
  vmrs r2, fpexc
  out r2
  @ The registers' reset values are UNKNOWN: give them one.
  mov r0, #0
  .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
  vmov d\n, r0, r0
  .endr
  @ The FPSCR: read/write bits, the RAZ/WI trap enables.
  li r0, 0xfff79f9f
  vmsr fpscr, r0
  vmrs r1, fpscr
  out r1
  vmrs APSR_nzcv, fpscr
  outflags
  li r0, 0x60000000
  vmsr fpscr, r0
  vmrs APSR_nzcv, fpscr
  outflags
  mov r0, #0
  vmsr fpscr, r0
  @ Core to single, single to core, two singles, a doubleword.
  li r0, 0x3f800000
  li r1, 0xc0000000
  vmov s0, r0
  vmov s1, r1
  vmov r2, r3, d0
  out r2
  out r3
  li r0, 0x01234567
  li r1, 0x89abcdef
  vmov d1, r0, r1
  vmov r2, s2
  out r2
  vmov r2, s3
  out r2
  vmov s5, s6, r1, r0
  vmov r2, r3, d2
  out r2
  out r3
  vmov r2, r3, s6, s7
  out r2
  out r3
  vmov d17, r1, r0
  vmov r2, r3, d17
  out r2
  out r3
  @ Scalars of every size, sign- and zero-extended.
  li r0, 0x80c1f2a3
  vmov d4, r0, r0
  li r1, 0x5a
  vmov.8 d4[3], r1
  li r1, 0x8765
  vmov.16 d4[1], r1
  li r1, 0xfeedface
  vmov.32 d4[1], r1
  vmov r2, r3, d4
  out r2
  out r3
  vmov.s8 r2, d4[3]
  out r2
  vmov.u8 r2, d4[2]
  out r2
  vmov.s8 r2, d4[1]
  out r2
  vmov.s16 r2, d4[1]
  out r2
  vmov.u16 r2, d4[3]
  out r2
  vmov.s16 r2, d4[2]
  out r2
  vmov.32 r2, d4[1]
  out r2
  vmov.8 d21[7], r1
  vmov.u8 r2, d21[7]
  out r2
  @ VDUP from a core register, D and Q.
  li r0, 0x89abcdef
  vdup.8 d5, r0
  vdup.16 q3, r0
  vdup.32 q4, r0
  vdup.16 d30, r0
  vmov r2, r3, d5
  out r2
  out r3
  vmov r2, r3, d7
  out r2
  out r3
  vmov r2, r3, d8
  out r2
  out r3
  vmov r2, r3, d30
  out r2
  out r3
  @ VMOV (register), Advanced SIMD.
  vmov q5, q3
  vmov d24, d5
  vmov r2, r3, d11
  out r2
  out r3
  vmov r2, r3, d24
  out r2
  out r3
  @ Conditional transfers.
  li r0, 0x11111111
  li r1, 0x22222222
  vmov s16, r0
  cmp r0, r0
  vmovne s16, r1
  vmoveq s17, r1
  vmovne r2, s17
  vmoveq r3, s16
  vmov r4, r5, d8
  out r3
  out r4
  out r5
  @ (CPACR.ASEDIS and CPACR.D32DIS are not compared: QEMU keeps the bits
  @ but does not act on them. The unit tests of gex-a32 cover them.)
  @ cp10/cp11 at PL1 only, then off.
  li r1, 0x00500000
  mcr p15, 0, r1, c1, c0, 2
  isb
  mov r0, #0
  vmov s0, r1
  out r0
  mov r1, #0
  mcr p15, 0, r1, c1, c0, 2
  isb
  mov r0, #0
  vmrs r2, fpexc
  out r0
  li r1, 0x00f00000
  mcr p15, 0, r1, c1, c0, 2
  isb
  @ FPEXC.EN = 0: the FPSCR is UNDEFINED, FPEXC is not.
  mov r1, #0
  vmsr fpexc, r1
  mov r0, #0
  vmrs r2, fpscr
  out r0
  mov r0, #0
  vmrs r2, fpexc
  out r0
  mov r1, #0x40000000
  vmsr fpexc, r1
  @ The whole register file.
  .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
  vmov r2, r3, d\n
  out r2
  out r3
  .endr
  finish

undef_handler:
  mrs r1, spsr
  out r1
  out lr
  mov r0, #0x99
  movs pc, lr

unexpected svc_handler
unexpected pabt_handler
unexpected dabt_handler
unexpected irq_handler
unexpected fiq_handler
