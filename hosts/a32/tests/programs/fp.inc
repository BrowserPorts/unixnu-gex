@ The frame of the Floating-point and Advanced SIMD test programs, after
@ common.inc: enable the extensions and give every register a value.
.fpu neon-vfpv4

@ CPACR cp10/cp11 full access, FPEXC.EN, D0-D31 and the FPSCR zero.
.macro fpon
  li r1, 0x00f00000
  mcr p15, 0, r1, c1, c0, 2
  isb
  mov r1, #0x40000000
  vmsr fpexc, r1
  mov r1, #0
  vmsr fpscr, r1
  .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
  vmov d\n, r1, r1
  .endr
.endm

@ Record D<n> (two words).
.macro outd n
  vmov r0, r1, d\n
  out r0
  out r1
.endm

@ Record the FPSCR.
.macro outfpscr
  vmrs r9, fpscr
  out r9
.endm
