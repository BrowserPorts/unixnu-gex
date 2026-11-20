# The Advanced SIMD data-processing test programs: every instruction of a
# class, in each of its element types, over a table of operand sets; each
# destination and the FPSCR after it recorded.
# `python3 gen_neon.py int neon_int.s`, `python3 gen_neon.py perm neon_perm.s`,
# `python3 gen_neon.py fp neon_fp.s`.
import os
import sys

def rng(seed):
    s = seed
    while True:
        s ^= (s >> 12)
        s ^= (s << 25) & (2**64 - 1)
        s ^= (s >> 27)
        yield (s * 0x2545F4914F6CDD1D) & (2**64 - 1)

SU = ['s', 'u']

def int_ops():
    ops = []
    A = ops.append
    # Three registers of the same length (A7.4.1).
    for op in ['vhadd', 'vhsub', 'vrhadd', 'vcgt', 'vcge', 'vmax', 'vmin', 'vabd', 'vaba']:
        for t in SU:
            for e in [8, 16, 32]:
                A(f'{op}.{t}{e} q10, q8, q9')
    for op in ['vqadd', 'vqsub', 'vshl', 'vqshl', 'vrshl', 'vqrshl']:
        for t in SU:
            for e in [8, 16, 32, 64]:
                A(f'{op}.{t}{e} q10, q9, q8' if 'sh' in op else f'{op}.{t}{e} q10, q8, q9')
    for op in ['vand', 'vbic', 'vorr', 'vorn', 'veor', 'vbsl', 'vbit', 'vbif']:
        A(f'{op} q10, q8, q9')
        A(f'{op} d20, d16, d19')
    for e in [8, 16, 32]:
        A(f'vceq.i{e} q10, q8, q9')
        A(f'vtst.{e} q10, q8, q9')
        A(f'vmla.i{e} q10, q8, q9')
        A(f'vmls.i{e} q10, q8, q9')
        A(f'vmul.i{e} q10, q8, q9')
        A(f'vpadd.i{e} d20, d16, d19')
        for t in SU:
            A(f'vpmax.{t}{e} d20, d16, d19')
            A(f'vpmin.{t}{e} d20, d17, d18')
    A('vmul.p8 q10, q8, q9')
    for e in [8, 16, 32, 64]:
        A(f'vadd.i{e} q10, q8, q9')
        A(f'vsub.i{e} d20, d16, d19')
    for op in ['vqdmulh', 'vqrdmulh']:
        for e in [16, 32]:
            A(f'{op}.s{e} q10, q8, q9')
    # Three registers of different lengths (A7.4.2).
    for t in SU:
        for e in [8, 16, 32]:
            for op in ['vaddl', 'vsubl', 'vabal', 'vabdl', 'vmlal', 'vmlsl', 'vmull']:
                A(f'{op}.{t}{e} q10, d16, d19')
            for op in ['vaddw', 'vsubw']:
                A(f'{op}.{t}{e} q10, q8, d19')
    for e in [16, 32, 64]:
        for op in ['vaddhn', 'vraddhn', 'vsubhn', 'vrsubhn']:
            A(f'{op}.i{e} d20, q8, q9')
    A('vmull.p8 q10, d16, d19')
    for e in [16, 32]:
        for op in ['vqdmlal', 'vqdmlsl', 'vqdmull']:
            A(f'{op}.s{e} q10, d16, d19')
    # Two registers and a scalar (A7.4.3).
    for e, ix in [(16, [0, 3]), (32, [0, 1])]:
        for i in ix:
            for op in ['vmla', 'vmls', 'vmul']:
                A(f'{op}.i{e} q10, q8, d6[{i}]')
            for op in ['vqdmulh', 'vqrdmulh']:
                A(f'{op}.s{e} q10, q8, d6[{i}]')
            for op in ['vqdmlal', 'vqdmlsl', 'vqdmull']:
                A(f'{op}.s{e} q10, d17, d6[{i}]')
            for t in SU:
                for op in ['vmlal', 'vmlsl', 'vmull']:
                    A(f'{op}.{t}{e} q10, d16, d6[{i}]')
    # Two registers, miscellaneous (A7.4.5).
    for e in [8, 16, 32]:
        for t in SU:
            A(f'vpaddl.{t}{e} q10, q8')
            A(f'vpadal.{t}{e} q10, q9')
            A(f'vmovl.{t}{e} q10, d17')
        A(f'vcls.s{e} q10, q8')
        A(f'vclz.i{e} q10, q9')
        for op in ['vqabs', 'vqneg', 'vabs', 'vneg']:
            A(f'{op}.s{e} q10, q8')
        for op in ['vcge', 'vcgt', 'vcle', 'vclt']:
            A(f'{op}.s{e} q10, q8, #0')
        A(f'vceq.i{e} q10, q9, #0')
    A('vcnt.8 q10, q8')
    A('vmvn q10, q9')
    for e in [16, 32, 64]:
        A(f'vmovn.i{e} d20, q8')
        A(f'vqmovn.s{e} d20, q8')
        A(f'vqmovn.u{e} d20, q9')
        A(f'vqmovun.s{e} d20, q8')
    # Shifts by an immediate (A7.4.4).
    for e in [8, 16, 32, 64]:
        rs = sorted({1, e // 2, e - 1, e})
        ls = sorted({0, 1, e // 2, e - 1})
        for t in SU:
            for op in ['vshr', 'vsra', 'vrshr', 'vrsra']:
                for s in rs:
                    A(f'{op}.{t}{e} q10, q8, #{s}')
            for s in ls:
                A(f'vqshl.{t}{e} q10, q9, #{s}')
        for s in rs:
            A(f'vsri.{e} q10, q9, #{s}')
        for s in ls:
            A(f'vshl.i{e} q10, q8, #{s}')
            A(f'vsli.{e} q10, q9, #{s}')
            A(f'vqshlu.s{e} q10, q8, #{s}')
    for e in [16, 32, 64]:
        h = e // 2
        for s in sorted({1, h // 2, h}):
            A(f'vshrn.i{e} d20, q8, #{s}')
            A(f'vrshrn.i{e} d20, q9, #{s}')
            A(f'vqshrun.s{e} d20, q8, #{s}')
            A(f'vqrshrun.s{e} d20, q9, #{s}')
            for t in SU:
                A(f'vqshrn.{t}{e} d20, q8, #{s}')
                A(f'vqrshrn.{t}{e} d20, q9, #{s}')
    for e in [8, 16, 32]:
        for s in [1, e - 1]:
            for t in SU:
                A(f'vshll.{t}{e} q10, d17, #{s}')
        A(f'vshll.i{e} q10, d16, #{e}')
    # One register and a modified immediate (A7.4.6).
    for imm in ['vmov.i8 q10, #0xa5', 'vmov.i16 q10, #0x3c00', 'vmov.i32 q10, #0x00ab0000', 'vmov.i32 q10, #0x12ffff',
                'vmov.i64 q10, #0xff00ffff0000ff00', 'vmov.f32 q10, #-1.5', 'vmvn.i32 q10, #0x5aff', 'vmvn.i16 d20, #0x7f',
                'vorr.i16 q10, #0x4400', 'vorr.i32 d20, #0x99000000', 'vbic.i16 q10, #0x0081', 'vbic.i32 q10, #0x00ee0000']:
        A(imm)
    return ops

def perm_ops():
    ops = []
    A = ops.append
    for k in range(16):
        A(f'vext.8 q10, q8, q9, #{k}')
    for k in range(8):
        A(f'vext.8 d20, d16, d19, #{k}')
    A('vext.16 q10, q9, q8, #3')
    A('vext.32 d20, d17, d18, #1')
    for n in range(1, 5):
        regs = ', '.join(f'd{18 + j}' for j in range(n))
        A(f'vtbl.8 d20, {{{regs}}}, d16')
        A(f'vtbx.8 d20, {{{regs}}}, d16')
        A(f'vtbx.8 d21, {{{regs}}}, d17')
    for k in range(8):
        A(f'vdup.8 q10, d16[{k}]')
    for k in range(4):
        A(f'vdup.16 d20, d17[{k}]')
    for k in range(2):
        A(f'vdup.32 q10, d19[{k}]')
    for r in ['q10, q9', 'd20, d18']:
        A(f'vrev16.8 {r}')
        for e in [8, 16]:
            A(f'vrev32.{e} {r}')
        for e in [8, 16, 32]:
            A(f'vrev64.{e} {r}')
    # Both registers change: q12 (a copy of q9) is the second.
    A('vswp q10, q12')
    A('vswp d20, d25')
    for e in [8, 16, 32]:
        A(f'vtrn.{e} q10, q12')
        A(f'vtrn.{e} d20, d24')
        A(f'vuzp.{e} q10, q12')
        A(f'vzip.{e} q10, q12')
    for e in [8, 16]:
        A(f'vuzp.{e} d20, d24')
        A(f'vzip.{e} d20, d24')
    return ops

def fp_ops():
    ops = []
    A = ops.append
    for op in ['vadd', 'vsub', 'vmul', 'vabd', 'vmla', 'vmls', 'vfma', 'vfms', 'vceq', 'vcge', 'vcgt', 'vacge', 'vacgt',
               'vmax', 'vmin', 'vrecps', 'vrsqrts']:
        A(f'{op}.f32 q10, q8, q9')
    for op in ['vpadd', 'vpmax', 'vpmin']:
        A(f'{op}.f32 d20, d16, d19')
    for i in [0, 1]:
        for op in ['vmul', 'vmla', 'vmls']:
            A(f'{op}.f32 q10, q8, d6[{i}]')
    for op in ['vabs', 'vneg', 'vrecpe', 'vrsqrte']:
        A(f'{op}.f32 q10, q8')
        A(f'{op}.f32 d20, d19')
    for op in ['vrecpe', 'vrsqrte']:
        A(f'{op}.u32 q10, q9')
    for op in ['vceq', 'vcge', 'vcgt', 'vcle', 'vclt']:
        A(f'{op}.f32 q10, q8, #0')
    for t in ['s32', 'u32']:
        A(f'vcvt.{t}.f32 q10, q8')
        A(f'vcvt.f32.{t} q10, q9')
        for fb in [1, 16, 32]:
            A(f'vcvt.{t}.f32 q10, q8, #{fb}')
            A(f'vcvt.f32.{t} q10, q9, #{fb}')
    A('vcvt.f16.f32 d20, q8')
    A('vcvt.f32.f16 q10, d17')
    A('vcvt.f32.f16 q10, d19')
    return ops


CLASSES = {'int': (int_ops, 'integer and polynomial'), 'perm': (perm_ops, 'permute'), 'fp': (fp_ops, 'floating-point')}

kind, path = sys.argv[1], sys.argv[2]
ops_fn, what = CLASSES[kind]
ops = ops_fn()
g = rng(0x5eed + len(kind))
# Operand sets: n, m, the destination's first value, the scalar register.
sets = []
edges = [0x8000000000000000, 0x7fffffffffffffff, 0xffffffffffffffff, 0, 1, 0x8080808080808080, 0x7f7f7f7f7f7f7f7f,
         0x80007fff8000ffff, 0x7fffffff80000000, 0x0102fefd80817f7e]
for k in range(10):
    q = []
    for j in range(8):
        r = next(g)
        if (k + j) % 3 == 0:
            r = edges[(k * 3 + j) % len(edges)]
        q.append(r)
    sets.append(q)
# Floating-point operand sets: two single-precision values in each
# doubleword, from signed zeros, denormals, the normal limits, infinities,
# NaNs, integers, halves' limits and random values.
FLOATS = [0, 0x80000000, 0x3f800000, 0xbf800000, 0x3fc00000, 0x40200000, 0xc0200000, 0x3eaaaaab, 0x00000001,
          0x807fffff, 0x00800000, 0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000, 0x7fc00001, 0x7f800005,
          0xffc00007, 0x4f000000, 0xcf000000, 0x4f800000, 0x477fe000, 0x477ff000, 0x33800000, 0x387fc000,
          0x3f000001, 0x7e800000, 0x00400000, 0x40490fdb, 0xc61c4000, 0x4b7fffff, 0x3a83126f]
if kind == 'fp':
    sets = []
    for k in range(14):
        q = []
        for j in range(8):
            a, b = next(g), next(g)
            fa = FLOATS[a % len(FLOATS)] if a % 5 else a & 0xffffffff
            fb = FLOATS[b % len(FLOATS)] if b % 5 else b & 0xffffffff
            q.append(fb << 32 | fa)
        sets.append(q)
# Sets whose bytes are small signed shift counts for the shifts by register.
for k in range(3 if kind != 'fp' else 0):
    q = []
    for j in range(8):
        v = 0
        for b in range(8):
            sh = (next(g) % 20) - 10 if k < 2 else (next(g) % 140) - 70
            v |= (sh & 0xff) << (8 * b)
        q.append(v if j < 2 else next(g))
    sets.append(q)

out = []
P = out.append
P(f'@ Advanced SIMD {what} data processing: every instruction in each of')
P('@ its element types over a table of operand sets; each destination and')
P('@ the FPSCR (QC, the cumulative exception flags) after it recorded.')
P(f'@ Generated by gen_neon.py: `python3 gen_neon.py {kind} {os.path.basename(path)}`.')
P('.include "common.inc"')
P('.include "fp.inc"')
P('vectors')
P('reset:')
P('  li sp, STACK_SVC')
P('  li r10, OUT')
P('  fpon')
P('  mov r8, #0')
if kind == 'fp':
    P('  li r7, fpscrs')
    P('0:')
    P('  ldr r8, [r7], #4')
P('  li r4, sets')
P('  li r5, sets_end')
P('1:')
for d in ['d16', 'd17', 'd18', 'd19', 'd22', 'd23', 'd6', 'd7']:
    P('  ldm r4!, {r0, r1}')
    P(f'  vmov {d}, r0, r1')
for op in ops:
    P('  vmov q10, q11')
    if kind == 'perm':
        P('  vmov q12, q9')
    P('  vmsr fpscr, r8')
    P(f'  {op}')
    P('  vmrs r9, fpscr')
    P('  outd 20')
    P('  outd 21')
    if kind == 'perm':
        P('  outd 24')
        P('  outd 25')
    P('  out r9')
P('  cmp r4, r5')
P('  bhs 2f')
P('  b 1b')
P('2:')
if kind == 'fp':
    P('  li r0, fpscrs_end')
    P('  cmp r7, r0')
    P('  blo 0b')
P('  finish')
P('')
for h in ['undef_handler', 'svc_handler', 'pabt_handler', 'dabt_handler', 'irq_handler', 'fiq_handler']:
    P(f'unexpected {h}')
P('')
P('.align 2')
if kind == 'fp':
    # Advanced SIMD uses the standard FPSCR value, which keeps only AHP:
    # the class runs again under every other control set.
    P('fpscrs:')
    for v in [0, 0x07c00000]:
        P(f'  .word {v:#010x}')
    P('fpscrs_end:')
P('sets:')
for q in sets:
    for v in q:
        P(f'  .word {v & 0xffffffff:#010x}, {v >> 32:#010x}')
P('sets_end:')
open(path, 'w').write('\n'.join(out) + '\n')
