@ The VMSA's short-descriptor translation: sections, a supersection, small
@ pages, a read-only page whose permission fault the handler repairs (the
@ access is retried after TLB maintenance), a translation fault, a domain
@ fault, a manager domain, ATS1CPR and the PAR, unaligned accesses to
@ Normal memory, and SCTLR.A's alignment fault.
.include "common.inc"
.equ L1, 0x40020000
.equ L2, 0x40024000
vectors
reset:
  li sp, STACK_ABT
  cps #0x17
  li sp, STACK_ABT
  cps #0x13
  li sp, STACK_SVC
  li r10, OUT
  @ Clear the first-level table.
  li r0, L1
  mov r1, #0
  mov r2, #4096
1:
  str r1, [r0], #4
  subs r2, r2, #1
  bne 1b
  li r0, L1
  @ VA 0x000xxxxx: the code, a section.
  li r1, 0x00001c0e
  str r1, [r0]
  @ VA 0x400xxxxx-0x403xxxxx: RAM, sections (Normal, write-back).
  li r1, 0x40001c0e
  li r2, L1 + 0x400 * 4
  str r1, [r2]
  li r1, 0x40101c0e
  li r2, L1 + 0x401 * 4
  str r1, [r2]
  li r1, 0x40201c0e
  li r2, L1 + 0x402 * 4
  str r1, [r2]
  li r1, 0x40301c0e
  li r2, L1 + 0x403 * 4
  str r1, [r2]
  @ VA 0x800xxxxx: a page table.
  li r1, L2 + 1
  li r2, L1 + 0x800 * 4
  str r1, [r2]
  @ VA 0x810xxxxx: a section in domain 1 (no access).
  li r1, 0x40301c2e
  li r2, L1 + 0x810 * 4
  str r1, [r2]
  @ VA 0x820xxxxx: a section in domain 2 (manager), AP 000.
  li r1, 0x4040104e
  li r2, L1 + 0x820 * 4
  str r1, [r2]
  @ VA 0x90000000: a supersection of PA 0x40000000, in 16 entries.
  li r1, 0x40041c0e
  add r2, r0, #0x900 * 4
  mov r3, #16
2:
  str r1, [r2], #4
  subs r3, r3, #1
  bne 2b
  @ The second-level table: page 0 read/write, page 1 PL1 read-only,
  @ page 2 invalid.
  li r0, L2
  mov r1, #0
  mov r2, #256
3:
  str r1, [r0], #4
  subs r2, r2, #1
  bne 3b
  li r0, L2
  li r1, 0x4020007e
  str r1, [r0]
  li r1, 0x4020125e
  str r1, [r0, #4]
  @ Domains: 0 client, 1 no access, 2 manager.
  mov r0, #0x31
  mcr p15, 0, r0, c3, c0, 0
  mov r0, #0
  mcr p15, 0, r0, c2, c0, 2
  li r0, L1
  mcr p15, 0, r0, c2, c0, 0
  mcr p15, 0, r0, c8, c7, 0
  dsb
  mrc p15, 0, r0, c1, c0, 0
  orr r0, r0, #1
  mcr p15, 0, r0, c1, c0, 0
  isb
  mrc p15, 0, r0, c1, c0, 0
  out r0
  @ Through a page, read back through the section's identity map.
  li r4, 0x80000000
  li r1, 0xfeedface
  str r1, [r4, #0x10]
  li r5, 0x40200010
  ldr r2, [r5]
  out r2
  @ The read-only page: a read, then a write that faults and is retried.
  li r4, 0x80001000
  ldr r2, [r4]
  out r2
  li r1, 0x0badcafe
  str r1, [r4, #8]
  ldr r2, [r4, #8]
  out r2
  @ An invalid page: a translation fault, skipped.
  li r4, 0x80002000
  mov r0, #0
  ldr r2, [r4]
  out r0
  @ Domain 1: a domain fault.
  li r4, 0x81000000
  mov r0, #0
  ldr r2, [r4]
  out r0
  @ Domain 2 (manager): no permission check.
  li r4, 0x82000000
  li r1, 0x13572468
  str r1, [r4]
  ldr r2, [r4]
  out r2
  @ The supersection.
  li r4, 0x90200010
  ldr r2, [r4]
  out r2
  @ ATS1CPR and the PAR: the address and F. (Bits 10:1 are the region's
  @ attributes, which an implementation may report as it uses them, and NS,
  @ UNKNOWN outside Secure state: B4.1.112.)
  li r4, 0x80001234
  mcr p15, 0, r4, c7, c8, 0
  isb
  mrc p15, 0, r2, c7, c4, 0
  mov r3, r2, lsr #12
  out r3
  and r3, r2, #1
  out r3
  li r4, 0x80002000
  mcr p15, 0, r4, c7, c8, 0
  isb
  mrc p15, 0, r2, c7, c4, 0
  out r2
  @ Unaligned accesses to Normal memory are allowed with SCTLR.A clear.
  li r4, 0x40030001
  li r1, 0x11223344
  str r1, [r4]
  ldr r2, [r4]
  out r2
  ldrh r2, [r4, #1]
  out r2
  @ SCTLR.A: now an alignment fault.
  mrc p15, 0, r0, c1, c0, 0
  orr r0, r0, #2
  mcr p15, 0, r0, c1, c0, 0
  isb
  mov r0, #0
  ldr r2, [r4]
  out r0
  finish

dabt_handler:
  push {r1-r3}
  mrc p15, 0, r1, c5, c0, 0
  out r1
  mrc p15, 0, r2, c6, c0, 0
  out r2
  @ A permission fault on a page: make the page writable and retry.
  and r3, r1, #0xf
  tst r1, #0x400
  bne 1f
  cmp r3, #0xf
  bne 1f
  li r3, L2
  ldr r1, [r3, #4]
  bic r1, r1, #0x200
  orr r1, r1, #0x30
  str r1, [r3, #4]
  dsb
  mcr p15, 0, r2, c8, c7, 1
  dsb
  isb
  pop {r1-r3}
  subs pc, lr, #8
1:
  mov r0, #0xda
  pop {r1-r3}
  subs pc, lr, #4

unexpected undef_handler
unexpected svc_handler
unexpected pabt_handler
unexpected irq_handler
unexpected fiq_handler
.ltorg
