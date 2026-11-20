@ The frame every test program shares: the exception vectors at address 0,
@ RAM at 0x40000000 (results from OUT, stacks at the top), and the exit:
@ the result words hashed into r11 (r10 holding their count), then
@ semihosting SYS_EXIT.
.syntax unified
.equ RAM, 0x40000000
.equ OUT, 0x40000000
.equ STACK_SVC, 0x40100000
.equ STACK_UND, 0x400f0000
.equ STACK_ABT, 0x400e0000
.equ STACK_IRQ, 0x400d0000
.equ STACK_FIQ, 0x400c0000
.equ STACK_USR, 0x400b0000

@ Load a 32-bit constant without a literal pool.
.macro li r, v
  movw \r, #:lower16:\v
  movt \r, #:upper16:\v
.endm

@ Record register \r as the next result word.
.macro out r
  str \r, [r10], #4
.endm

@ Record the flags (CPSR<31:27> and GE) after an instruction.
.macro outflags
  mrs r9, apsr
  str r9, [r10], #4
.endm

.macro vectors
  .arm
  .text
  .global _start
_start:
  b reset
  b undef_handler
  b svc_handler
  b pabt_handler
  b dabt_handler
  b .
  b irq_handler
  b fiq_handler
.endm

@ A handler the program does not expect to run: it stops there.
.macro unexpected name
  .arm
\name:
  b \name
.endm

@ Fold the results into r11 and leave.
.macro finish
  mov r0, r10
  ldr r1, =OUT
  sub r10, r0, r1
  mov r10, r10, lsr #2
  ldr r11, =0x811c9dc5
1:
  cmp r1, r0
  beq 2f
  ldr r2, [r1], #4
  eor r11, r11, r2
  ldr r3, =0x01000193
  mul r11, r11, r3
  b 1b
2:
  mov r0, #0x18
  ldr r1, =0x20026
  svc 0x123456
.endm
