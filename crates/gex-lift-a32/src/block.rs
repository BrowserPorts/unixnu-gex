//! Assembling decoded AArch32 instructions into a GIR basic block.
//!
//! A block is keyed by `gex_abi::a32::key`: its first instruction's address,
//! the Thumb bit, and the ITSTATE that instruction executes in. ITSTATE
//! advances statically through the block (A2.5.2 `ITAdvance`); a block never
//! ends inside an IT block of its own accord, so only an exception return
//! into one (its SPSR's IT bits) enters a block with a nonzero ITSTATE.

use crate::{Flow, Lifter};
use gex_abi::a32 as abi;
use gex_ir::{pass, Block, Builder, Term};
use gex_isa_a32::*;

/// Bounds on how much a single block may cover.
#[derive(Copy, Clone, Debug)]
pub struct BlockLimits {
    /// Stop and fall through after this many instructions (once outside an
    /// IT block).
    pub max_insts: usize,
}

impl Default for BlockLimits {
    fn default() -> Self {
        BlockLimits { max_insts: 128 }
    }
}

/// Lift the block at `key`. `fetch(va)` gives the halfword of code at the
/// virtual address `va` as a fetch at the key's privilege level sees it,
/// or `None` where that fetch would abort: the block then ends with the
/// Prefetch Abort that executing it takes.
pub fn lift_block(fetch: &dyn Fn(u32) -> Option<u16>, key: u64, f: &Features, limits: BlockLimits) -> Block {
    let thumb = abi::key_thumb(key);
    let set = if thumb { InstrSet::Thumb } else { InstrSet::Arm };
    let start_addr = abi::key_addr(key);
    // The privilege the code runs at, every key of the block's carries.
    let user = key & abi::KEY_USER;
    let mut it = ItState(abi::key_it(key));
    let mut b = Builder::new(key);
    let mut addr = start_addr;
    let mut term = None;
    let mut n = 0usize;
    loop {
        let here = user | abi::key(addr, thumb, it.0);
        b.set_insn(here);
        // Fetch: one word (ARM) or one or two halfwords (Thumb).
        let fetched = match fetch(addr) {
            None => Err(addr),
            Some(h1) => {
                if !thumb || thumb_is_32(h1) {
                    match fetch(addr.wrapping_add(2)) {
                        None => Err(addr.wrapping_add(2)),
                        Some(h2) => Ok((h1, h2)),
                    }
                } else {
                    Ok((h1, 0))
                }
            }
        };
        let (h1, h2) = match fetched {
            Ok(h) => h,
            Err(at) => {
                // The fetch aborts: a Prefetch Abort when (and only when)
                // this instruction is executed.
                let mut l = Lifter::new(&mut b, set, addr, here, here, 0, 0);
                if let Flow::End(t) = l.exception(abi::exc::FETCH, at as u64) {
                    term = Some(t);
                }
                b.end_at(here.wrapping_add(2));
                break;
            }
        };
        let inst = if thumb {
            decode_thumb(h1, h2, it, f)
        } else {
            decode_arm((h2 as u32) << 16 | h1 as u32, f)
        };
        let next_it = match inst.op {
            Op::It { firstcond, mask } if inst.unpredictable.is_none() => ItState(firstcond << 4 | mask),
            _ => it.advance(),
        };
        let next_addr = addr.wrapping_add(inst.len as u32);
        let next = user | abi::key(next_addr, thumb, next_it.0);
        let flow = Lifter::new(&mut b, set, addr, here, next, inst.raw, inst.len).lift(&inst);
        b.end_at(key.wrapping_add(next_addr.wrapping_sub(start_addr) as u64));
        n += 1;
        match flow {
            Flow::End(t) => {
                term = Some(t);
                break;
            }
            Flow::Next => {}
        }
        addr = next_addr;
        it = next_it;
        if n >= limits.max_insts && !it.in_it() {
            break;
        }
    }
    let term = term.unwrap_or(Term::Goto { target: user | abi::key(addr, thumb, it.0) });
    let mut block = b.finish(term);
    pass::optimize(&mut block);
    block
}
