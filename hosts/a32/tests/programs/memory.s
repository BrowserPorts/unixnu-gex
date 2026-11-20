@ Loads and stores in every addressing form: immediate, register and
@ scaled register offsets, pre- and post-indexing with writeback, the
@ byte, halfword, signed and doubleword forms, the unprivileged forms,
@ LDM/STM in all four modes, PUSH/POP, and the exclusives.
.include "common.inc"
vectors
reset:
  li sp, STACK_SVC
  li r10, OUT
  li r4, RAM + 0x8000
  li r0, 0x89abcdef
  li r1, 0x01234567
  @ A pattern to load from.
  str r0, [r4]
  str r1, [r4, #4]
  li r2, 0xfedcba98
  str r2, [r4, #8]
  li r2, 0x80ff7f01
  str r2, [r4, #12]
  @ Immediate, register and scaled offsets.
  ldr r2, [r4, #4]
  out r2
  mov r3, #8
  ldr r2, [r4, r3]
  out r2
  mov r3, #2
  ldr r2, [r4, r3, lsl #2]
  out r2
  add r5, r4, #16
  mov r3, #32
  ldr r2, [r5, -r3, lsr #2]
  out r2
  @ Pre-indexed with writeback, post-indexed.
  mov r5, r4
  ldr r2, [r5, #4]!
  out r2
  out r5
  ldr r2, [r5], #-4
  out r2
  out r5
  ldr r2, [r5], r3, lsr #3
  out r2
  out r5
  @ Bytes and halfwords, signed and not.
  ldrb r2, [r4, #12]
  out r2
  ldrsb r2, [r4, #12]
  out r2
  ldrsb r2, [r4, #14]
  out r2
  ldrh r2, [r4, #12]
  out r2
  ldrsh r2, [r4, #14]
  out r2
  ldrsh r2, [r4, #12]
  out r2
  mov r3, #13
  ldrb r2, [r4, r3]
  out r2
  mov r3, #2
  ldrh r2, [r4, -r3]!
  out r2
  out r4
  ldrsh r2, [r4], #2
  out r2
  out r4
  @ Stores.
  li r6, RAM + 0x9000
  li r2, 0x11223344
  strb r2, [r6]
  strb r2, [r6, #3]
  strh r2, [r6, #4]
  str r2, [r6, #8]!
  strh r0, [r6], #-6
  out r6
  li r6, RAM + 0x9000
  ldr r2, [r6]
  out r2
  ldr r2, [r6, #4]
  out r2
  ldr r2, [r6, #8]
  out r2
  @ Doublewords.
  ldrd r2, r3, [r4, #4]
  out r2
  out r3
  mov r7, #8
  ldrd r2, r3, [r4, -r7]!
  out r2
  out r3
  out r4
  li r6, RAM + 0x9100
  strd r0, r1, [r6], #8
  out r6
  ldrd r2, r3, [r6, #-8]
  out r2
  out r3
  @ Unprivileged forms (PL1 code, MMU off: allowed).
  li r6, RAM + 0x9200
  strt r0, [r6], #4
  ldrt r2, [r6], #-4
  out r2
  out r6
  ldrbt r2, [r6], #2
  out r2
  ldrsht r2, [r6], #2
  out r2
  @ LDM/STM in every mode, with and without writeback.
  li r6, RAM + 0x9300
  mov r0, #10
  mov r1, #11
  mov r2, #12
  mov r3, #13
  stmia r6!, {r0-r3}
  out r6
  stmib r6, {r0, r2}
  stmda r6!, {r1, r3}
  out r6
  stmdb r6, {r0-r2}
  li r6, RAM + 0x9300
  ldmia r6, {r0-r3}
  out r0
  out r1
  out r2
  out r3
  add r6, r6, #16
  ldmdb r6!, {r0, r3}
  out r0
  out r3
  out r6
  ldmib r6, {r1, r2}
  out r1
  out r2
  ldmda r6, {r0-r2}
  out r0
  out r1
  out r2
  @ PUSH and POP, a single register and several.
  li r0, 0x55
  li r1, 0x66
  push {r0}
  push {r0, r1, lr}
  pop {r2, r3, r12}
  pop {r5}
  out r2
  out r3
  out r5
  out sp
  @ Exclusives: a successful pair, one failed by CLREX, and the sizes.
  li r6, RAM + 0x9400
  li r0, 0x12345678
  str r0, [r6]
  ldrex r2, [r6]
  add r2, r2, #1
  strex r3, r2, [r6]
  out r3
  ldr r2, [r6]
  out r2
  ldrex r2, [r6]
  clrex
  strex r3, r2, [r6]
  out r3
  add r7, r6, #1
  ldrexb r2, [r7]
  out r2
  strexb r3, r1, [r7]
  out r3
  ldrexh r2, [r6]
  strexh r3, r0, [r6]
  out r3
  ldr r2, [r6]
  out r2
  ldrexd r2, r3, [r6]
  out r2
  out r3
  strexd r5, r0, r1, [r6]
  out r5
  ldrd r2, r3, [r6]
  out r2
  out r3
  @ A STREX with no LDREX before it fails.
  strex r3, r2, [r6]
  out r3
  finish
unexpected undef_handler
unexpected svc_handler
unexpected pabt_handler
unexpected dabt_handler
unexpected irq_handler
unexpected fiq_handler
.ltorg
