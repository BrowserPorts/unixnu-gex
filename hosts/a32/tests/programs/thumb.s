@ Thumb-2: 16- and 32-bit encodings, the flag rules inside and outside IT
@ blocks, every IT pattern under every flag combination, CBZ/CBNZ, TBB/TBH,
@ PC-relative loads, and interworking both ways (BLX, BX, LDR PC, POP PC).
.include "common.inc"
vectors
reset:
  li sp, STACK_SVC
  li r10, OUT
  li r0, 0x80000001
  li r1, 0x7fffffff
  adr r12, thumb_main + 1
  blx r12                      @ ARM -> Thumb by register
  bl arm_after                 @ back in ARM
  finish

arm_after:
  li r2, 0xa5a5a5a5
  out r2
  bx lr

unexpected undef_handler
unexpected svc_handler
unexpected pabt_handler
unexpected dabt_handler
unexpected irq_handler
unexpected fiq_handler

@ An ARM function Thumb code calls.
arm_func:
  add r2, r0, r1, lsl #2
  out r2
  bx lr

.thumb
.thumb_func
thumb_main:
  push {r4-r7, lr}
  @ 16-bit data processing outside an IT block sets the flags.
  movs r2, #0
  adds r2, r0, r1
  out r2
  outflags
  subs r3, r0, #3
  out r3
  outflags
  lsls r4, r0, #1
  out r4
  outflags
  lsrs r4, r1, #31
  out r4
  outflags
  asrs r4, r0, #3
  out r4
  outflags
  movs r5, #7
  rors r4, r5
  out r4
  outflags
  muls r5, r0, r5
  out r5
  outflags
  mvns r5, r1
  out r5
  outflags
  negs r5, r0
  out r5
  outflags
  @ The same inside an IT block: no flags.
  mov.w r8, #0x40000000
  msr APSR_nzcvq, r8
  itttt eq
  addeq r2, r0, r1
  subeq r3, r0, #3
  lsleq r4, r0, #1
  mvneq r5, r1
  out r2
  out r3
  out r4
  out r5
  outflags
  @ 32-bit encodings.
  add.w r2, r0, r1, ror #7
  out r2
  adds.w r2, r0, #0x00ab00ab
  out r2
  outflags
  orn r2, r0, r1
  out r2
  bic.w r2, r1, #0x0f000000
  out r2
  addw r2, r0, #0xfff
  out r2
  subw r2, r1, #0xabc
  out r2
  mov.w r2, #0xff00ff00
  out r2
  movw r2, #0x1234
  movt r2, #0x5678
  out r2
  sbfx r2, r0, #2, #20
  out r2
  bfi r2, r1, #5, #11
  out r2
  smull r2, r3, r0, r1
  out r2
  out r3
  sdiv r2, r0, r1
  out r2
  udiv r2, r0, r1
  out r2
  qadd16 r2, r0, r1
  out r2
  uhsub8 r2, r0, r1
  out r2
  @ Every IT pattern under every flag value.
  movs r6, #0
1:
  lsls r7, r6, #28
  msr APSR_nzcvq, r7
  movs r2, #0
  movs r3, #0
  movs r4, #0
  movs r5, #0
  @ The flags were just set by MOVS: set them again.
  msr APSR_nzcvq, r7
  itete ge
  addge r2, #1
  addlt r3, #2
  addge r4, #4
  addlt r5, #8
  out r2
  out r3
  out r4
  out r5
  msr APSR_nzcvq, r7
  ittee hi
  addhi r2, #16
  addhi r3, #32
  addls r4, #64
  addls r5, #128
  out r2
  out r3
  out r4
  out r5
  msr APSR_nzcvq, r7
  itt vs
  addvs r2, r2, r3
  addvs r3, r2, r4
  out r2
  out r3
  msr APSR_nzcvq, r7
  ite mi
  movmi r2, #1
  movpl r2, #2
  out r2
  outflags
  adds r6, #1
  cmp r6, #16
  bne 1b
  @ CBZ/CBNZ.
  movs r2, #5
  movs r3, #0
2:
  adds r3, r3, r2
  subs r2, #1
  cbz r2, 3f
  b 2b
3:
  out r3
  movs r2, #0
  cbnz r2, 4f
  movs r3, #99
4:
  out r3
  @ TBB and TBH.
  movs r4, #0
5:
  tbb [pc, r4]
6:
  .byte (7f - 6b) / 2, (8f - 6b) / 2, (9f - 6b) / 2, 0
7:
  movs r2, #10
  b 10f
8:
  movs r2, #20
  b 10f
9:
  movs r2, #30
10:
  out r2
  adds r4, #1
  cmp r4, #3
  bne 5b
  movs r4, #1
  tbh [pc, r4, lsl #1]
11:
  .hword (12f - 11b) / 2, (13f - 11b) / 2
12:
  movs r2, #40
  b 14f
13:
  movs r2, #50
14:
  out r2
  @ A PC-relative load (Align(PC, 4)) and ADR.
  ldr r2, lit
  out r2
  adr r3, lit
  ldr r2, [r3]
  out r2
  @ Interworking: Thumb -> ARM -> Thumb.
  blx arm_func
  ldr r5, =arm_func
  blx r5
  @ A load of the PC with the Thumb bit set.
  adr r5, 15f + 1
  str r5, [sp, #-4]!
  ldr pc, [sp], #4
  nop
15:
  movs r2, #77
  out r2
  pop {r4-r7, pc}
.align 2
lit:
  .word 0xcafef00d
.ltorg
