//! Vouchers (`osfmk/ipc/ipc_voucher.c`): immutable, deduplicated sets of
//! attribute values, one per well-known key, that messages carry and
//! threads adopt. Each key's values are kept by its attribute manager:
//! the bank (`osfmk/bank/bank.c`) and importance (`osfmk/ipc/
//! ipc_importance.c`) on iOS, whose kernel has no deprecated managers
//! (`CONFIG_VOUCHER_DEPRECATED` off) and no ATM manager.
//!
//! A voucher's table holds, for each key, an index into that key's value
//! table (`ipc_voucher_attr_control`), where values are deduplicated and
//! reference counted; index 0 is the manager's default value, and a
//! voucher with it for a key has nothing for that key.

use super::ipc::{ObjId, TaskKey};
use crate::syscalls::Kernel;
use std::collections::HashMap;

pub type VoucherId = u64;

/// `MACH_VOUCHER_ATTR_KEY_*`.
pub mod key {
    pub const ALL: u32 = !0;
    pub const NONE: u32 = 0;
    pub const ATM: u32 = 1;
    pub const IMPORTANCE: u32 = 2;
    pub const BANK: u32 = 3;
    pub const NUM_WELL_KNOWN: usize = 8;
}

/// `MACH_VOUCHER_ATTR_KEY_NUM`: the keys a voucher has values for, up to
/// the bank's.
const KEY_NUM: usize = key::BANK as usize;

/// `MACH_VOUCHER_ATTR_*` recipe commands.
pub mod cmd {
    pub const NOOP: u32 = 0;
    pub const COPY: u32 = 1;
    pub const REMOVE: u32 = 2;
    pub const SET_VALUE_HANDLE: u32 = 3;
    pub const AUTO_REDEEM: u32 = 4;
    pub const SEND_PREPROCESS: u32 = 5;
    pub const REDEEM: u32 = 10;
    pub const IMPORTANCE_SELF: u32 = 200;
    pub const BANK_NULL: u32 = 601;
    pub const BANK_CREATE: u32 = 610;
    pub const BANK_MODIFY_PERSONA: u32 = 611;
}

/// `IVAM_FLAGS_*`.
mod ivam_flags {
    pub const NONE: u32 = 0;
    pub const SUPPORT_SEND_PREPROCESS: u32 = 0x1;
    pub const SUPPORT_RECEIVE_POSTPROCESS: u32 = 0x2;
}

/// `MACH_VOUCHER_ATTR_VALUE_FLAGS_PERSIST`.
const VALUE_FLAGS_PERSIST: u32 = 1;
/// `MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE`.
pub const MAX_RAW_RECIPE_ARRAY_SIZE: u32 = 5120;
/// `sizeof(mach_voucher_attr_recipe_data_t)`: key, command, previous
/// voucher, content size.
pub const RECIPE_SIZE: usize = 16;
/// `MACH_VOUCHER_BANK_CONTENT_SIZE`.
const BANK_CONTENT_SIZE: u32 = 500;

/// `IV_UNUSED_VALINDEX`, `IV_UNUSED_KEYINDEX`, `IV_HASH_END`,
/// `IV_FREELIST_END`, `IVACE_REFS_MAX`, `IVAC_ENTRIES_MIN`, `_MAX`.
const IV_UNUSED_VALINDEX: u32 = 0;
const IV_UNUSED_KEYINDEX: u32 = !0;
const IV_HASH_END: u32 = u32::MAX;
const IV_FREELIST_END: u32 = 0;
const IVACE_REFS_MAX: u32 = (1 << 28) - 1;
const IVAC_ENTRIES_MIN: u32 = 512;
const IVAC_ENTRIES_MAX: u32 = 524_288;

/// `kern_return_t` values the voucher calls return.
pub mod vkr {
    pub const SUCCESS: u32 = 0;
    pub const INVALID_ARGUMENT: u32 = 4;
    pub const FAILURE: u32 = 5;
    pub const RESOURCE_SHORTAGE: u32 = 6;
    pub const NO_SPACE: u32 = 3;
    pub const NO_ACCESS: u32 = 8;
    pub const INVALID_CAPABILITY: u32 = 20;
    pub const INVALID_VALUE: u32 = 18;
    pub const INVALID_OBJECT: u32 = 29;
    pub const NOT_SUPPORTED: u32 = 46;
    pub const INVALID_TASK: u32 = 16;
}

/// The bank's handles, `BANK_DEFAULT_VALUE` (NULL) and
/// `BANK_DEFAULT_TASK_VALUE` (1), and its commands.
pub(crate) mod bank {
    pub const DEFAULT_VALUE: u64 = 0;
    pub const DEFAULT_TASK_VALUE: u64 = 1;
    /// `PERSONA_ID_NONE`.
    pub const PERSONA_ID_NONE: u32 = !0;
    /// `BANK_ORIGINATOR_PID`, `BANK_PERSONA_TOKEN`, `BANK_PERSONA_ID`,
    /// `BANK_PERSONA_ADOPT_ANY`, `BANK_ORIGINATOR_PROXIMATE_PID`.
    pub const ORIGINATOR_PID: u32 = 0x1;
    pub const PERSONA_TOKEN: u32 = 0x2;
    pub const PERSONA_ID: u32 = 0x3;
    pub const PERSONA_ADOPT_ANY: u32 = 0x4;
    pub const ORIGINATOR_PROXIMATE_PID: u32 = 0x5;
    /// `PROC_PERSONA_INFO_FLAG_ADOPTION_ALLOWED`.
    pub const FLAG_ADOPTION_ALLOWED: u32 = 0x1;
}

/// `MACH_VOUCHER_IMPORTANCE_ATTR_DROP_EXTERNAL`.
const IMPORTANCE_ATTR_DROP_EXTERNAL: u32 = 2;

/// `struct ivac_entry_s`.
#[derive(Clone, Copy, Debug)]
struct Ivace {
    value: u64,
    refs: u32,
    made: u32,
    persist: bool,
    free: bool,
    releasing: bool,
    /// The head of the hash chain of the bucket this entry indexes.
    index: u32,
    next: u32,
}

impl Ivace {
    /// `ivace_reset_data`.
    fn reset(next: u32) -> Ivace {
        Ivace { value: 0xDEAD_C0DE_DEAD_C0DE, refs: 0, made: 0, persist: false, free: true, releasing: false, index: IV_HASH_END, next }
    }
}

/// `struct ipc_voucher_attr_control`: one key's value table.
#[derive(Debug)]
struct Ivac {
    table: Vec<Ivace>,
    init_size: u32,
    freelist: u32,
}

impl Ivac {
    /// `ivac_init_well_known_voucher_attr_control` and the default value's
    /// registration (`ipc_register_well_known_mach_voucher_attr_manager`).
    fn new(default_value: u64) -> Ivac {
        let n = IVAC_ENTRIES_MIN;
        let mut table: Vec<Ivace> = (0..n).map(|i| Ivace::reset(i + 1)).collect();
        table[0].next = IV_HASH_END;
        table[0].free = false;
        table[n as usize - 1].next = IV_FREELIST_END;
        let mut ivac = Ivac { table, init_size: n, freelist: 1 };
        let d = &mut ivac.table[IV_UNUSED_VALINDEX as usize];
        d.value = default_value;
        d.refs = IVACE_REFS_MAX;
        d.made = IVACE_REFS_MAX;
        d.persist = true;
        let h = ivac.hash(default_value);
        assert_eq!(ivac.table[h as usize].index, IV_HASH_END);
        ivac.table[h as usize].index = IV_UNUSED_VALINDEX;
        ivac
    }

    /// `IV_HASH_VAL`.
    fn hash(&self, value: u64) -> u32 {
        ((value >> 3) % u64::from(self.init_size)) as u32
    }

    /// `ivac_grow_table`.
    fn grow(&mut self) {
        let old = self.table.len() as u32;
        assert!(old < IVAC_ENTRIES_MAX, "Cannot grow ipc space beyond IVAC_ENTRIES_MAX. Some process is leaking vouchers");
        let new = old * 2;
        self.table.extend((old..new).map(|i| Ivace::reset(i + 1)));
        self.table[new as usize - 1].next = self.freelist;
        self.freelist = old;
    }

    /// `ivace_lookup_values`.
    fn values(&self, index: u32) -> Vec<u64> {
        if index == IV_UNUSED_VALINDEX {
            return Vec::new();
        }
        let e = &self.table[index as usize];
        assert!(e.refs > 0);
        vec![e.value]
    }

    /// `ivace_reference_by_index`.
    fn reference_by_index(&mut self, index: u32) {
        if index == IV_UNUSED_VALINDEX {
            return;
        }
        let e = &mut self.table[index as usize];
        assert!(e.refs > 0 && !e.free);
        if !e.persist {
            e.refs += 1;
        }
    }

    /// `ivace_reference_by_value`.
    fn reference_by_value(&mut self, value: u64, flag: u32) -> u32 {
        loop {
            let h = self.hash(value);
            let mut index = self.table[h as usize].index;
            while index != IV_HASH_END {
                let e = &self.table[index as usize];
                assert!(!e.free);
                if e.value == value {
                    break;
                }
                assert_ne!(e.next, index);
                index = e.next;
            }
            if index != IV_HASH_END {
                let e = &mut self.table[index as usize];
                if !e.persist {
                    e.refs += 1;
                    e.made += 1;
                }
                return index;
            }
            let index = self.freelist;
            if index == IV_FREELIST_END {
                self.grow();
                continue;
            }
            let head = self.table[h as usize].index;
            let e = &mut self.table[index as usize];
            self.freelist = e.next;
            e.value = value;
            e.refs = 1;
            e.made = 1;
            e.free = false;
            e.persist = flag & VALUE_FLAGS_PERSIST != 0;
            e.next = head;
            self.table[h as usize].index = index;
            return index;
        }
    }

    /// The entry leaves its hash chain and goes back on the free list
    /// (`ivace_release`'s end).
    fn free_entry(&mut self, index: u32) {
        let value = self.table[index as usize].value;
        let h = self.hash(value);
        if self.table[h as usize].index == index {
            self.table[h as usize].index = self.table[index as usize].next;
        } else {
            let mut at = self.table[h as usize].index;
            assert_ne!(at, IV_HASH_END);
            while self.table[at as usize].next != index {
                at = self.table[at as usize].next;
                assert_ne!(at, IV_HASH_END);
            }
            self.table[at as usize].next = self.table[index as usize].next;
        }
        let freelist = self.freelist;
        let e = &mut self.table[index as usize];
        e.value = 0xDEAD_C0DE_DEAD_C0DE;
        e.releasing = false;
        e.free = true;
        e.made = 0;
        e.next = freelist;
        self.freelist = index;
    }
}

/// `struct ipc_voucher`.
#[derive(Debug)]
struct Voucher {
    table: [u32; KEY_NUM],
    refs: u32,
    port: Option<ObjId>,
}

/// `struct proc_persona_info`: the process a bank context stands for.
#[derive(Clone, Copy, Debug, Default)]
struct ProcPersonaInfo {
    unique_pid: u64,
    pid: i32,
    flags: u32,
    pidversion: u32,
    persona_id: u32,
    uid: u32,
    gid: u32,
    macho_uuid: [u8; 16],
}

impl ProcPersonaInfo {
    fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(PROC_PERSONA_INFO_SIZE as usize);
        b.extend_from_slice(&self.unique_pid.to_le_bytes());
        b.extend_from_slice(&self.pid.to_le_bytes());
        for w in [self.flags, self.pidversion, self.persona_id, self.uid, self.gid] {
            b.extend_from_slice(&w.to_le_bytes());
        }
        b.extend_from_slice(&self.macho_uuid);
        b
    }
}

/// `struct bank_persona`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BankPersona {
    id: u32,
    uid: u32,
}

/// A task's bank context (`struct bank_task`).
#[derive(Debug)]
struct BankTask {
    refs: u32,
    made: u32,
    voucher_ref: u32,
    info: ProcPersonaInfo,
    persona_uid: u32,
    hasentitlement: bool,
    thread_group: u64,
    /// `bt_accounts_to_pay`, `bt_accounts_to_charge`.
    to_pay: Vec<u64>,
    to_charge: Vec<u64>,
    /// `bt_ledger`: its task's ledger, until the task lets go of the
    /// context (`bank_destroy_bank_task_ledger`).
    ledger: Option<LedgerAt>,
    /// Its task's key: whose ledger it is.
    owner: TaskKey,
}

/// A bank context's ledger as the table reaches it: the ledger, where the
/// process holding the table is its task's own (natively every task's);
/// else, in the page, a task of another process, whose ledger is in that
/// process's memory: its task's key, a bill to which goes to that process
/// ([`super::ipc::Remote::Ledger`]).
#[derive(Clone, Debug)]
pub enum LedgerAt {
    Cell(std::sync::Arc<super::rusage::BankLedger>),
    Elsewhere(TaskKey),
}

impl LedgerAt {
    fn same(&self, o: &LedgerAt) -> bool {
        match (self, o) {
            (LedgerAt::Cell(a), LedgerAt::Cell(b)) => std::sync::Arc::ptr_eq(a, b),
            (LedgerAt::Elsewhere(a), LedgerAt::Elsewhere(b)) => a == b,
            _ => false,
        }
    }
}

/// `struct bank_account`: what a merchant task's work for a holder is
/// billed to: its bill (`ba_bill`), whose CPU time the merchant's threads
/// that adopt it credit (`bank_swap_thread_bank_ledger`, `thread_dispatch`)
/// and which goes to the holder's and merchant's ledgers as the account
/// goes. Its energy is 0 on this kernel: the only credit to the bank's
/// energy entry is `recount_current_thread_energy_nj`'s delta, which
/// T8011's kernel (no `RECOUNT_ENERGY`) never makes ([`super::rusage`]).
#[derive(Debug)]
struct BankAccount {
    refs: u32,
    made: u32,
    merchant: u64,
    holder: u64,
    secureoriginator: u64,
    proximateprocess: u64,
    thread_group: u64,
    so_persona: BankPersona,
    /// `ba_bill`'s cpu_time, in Mach time units.
    bill: u64,
    /// A thread's time could not be credited (the host has no per-thread
    /// clocks).
    bill_unkept: bool,
    /// The threads that have it as their bank ledger (`t_bankledger`).
    adopters: Vec<i32>,
}

#[derive(Debug)]
enum BankElem {
    Task(BankTask),
    Account(BankAccount),
}

/// A task's own voucher state: its bank context (`task->bank_context`),
/// and the credential's ids when it was to be made (`task_bank_init`, at
/// a fork or once an exec's image is in place). Its importance element is
/// the IPC table's, by task.
#[derive(Debug, Default)]
pub struct Vouchers {
    bank_context: Option<u64>,
    bank_ids: Option<(u32, u32)>,
}

/// The system's vouchers (`ivht`), each key's value table (`ivac`) and the
/// managers' elements, which every task shares with the IPC table.
#[derive(Debug, Default)]
pub struct VoucherTables {
    ivac: Vec<Option<Ivac>>,
    vouchers: HashMap<VoucherId, Voucher>,
    by_table: HashMap<[u32; KEY_NUM], VoucherId>,
    next: VoucherId,
    bank: HashMap<u64, BankElem>,
    pub(crate) imp: super::importance::ImpState,
    next_handle: u64,
}

impl Vouchers {
    /// A forked task's: its bank context to be made with these ids.
    pub fn forked(uid: u32, gid: u32) -> Vouchers {
        Vouchers { bank_ids: Some((uid, gid)), ..Vouchers::default() }
    }

    /// An exec's new task's: its bank context is yet to be made.
    pub fn for_exec(&self) -> Vouchers {
        assert!(self.bank_context.is_none());
        Vouchers::default()
    }
}

impl VoucherTables {
    /// A handle for a new element: distinct from the managers' defaults,
    /// aligned as an element's address is.
    fn alloc_handle(&mut self) -> u64 {
        self.next_handle = self.next_handle.max(0x1000) + 0x40;
        self.next_handle
    }
}

/// A recipe from user space or the kernel (`mach_voucher_attr_recipe_t`,
/// `ipc_voucher_attr_recipe_t`).
#[derive(Clone, Debug)]
pub struct Recipe {
    pub key: u32,
    pub command: u32,
    pub previous: Option<VoucherId>,
    pub content: Vec<u8>,
}

/// The managers that are registered: importance and the bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ivam {
    Importance,
    Bank,
}

impl Ivam {
    fn flags(self) -> u32 {
        match self {
            Ivam::Importance => ivam_flags::NONE,
            Ivam::Bank => ivam_flags::SUPPORT_SEND_PREPROCESS | ivam_flags::SUPPORT_RECEIVE_POSTPROCESS,
        }
    }
}

/// `iv_key_to_index`.
fn key_to_index(k: u32) -> u32 {
    if k == key::ALL || k as usize > KEY_NUM {
        return IV_UNUSED_KEYINDEX;
    }
    k.wrapping_sub(1)
}

/// `iv_index_to_key`.
fn index_to_key(i: u32) -> u32 {
    if (i as usize) < key::NUM_WELL_KNOWN { i + 1 } else { key::NONE }
}

impl Kernel {
    fn vt(&mut self) -> &mut VoucherTables {
        let v = &mut self.ipc().vouchers;
        if v.ivac.is_empty() {
            // bank_init and ipc_importance_init: the managers registered,
            // each with a default value of 0.
            v.ivac = (0..key::NUM_WELL_KNOWN).map(|_| None).collect();
            v.ivac[key_to_index(key::IMPORTANCE) as usize] = Some(Ivac::new(0));
            v.ivac[key_to_index(key::BANK) as usize] = Some(Ivac::new(bank::DEFAULT_VALUE));
        }
        v
    }

    /// `ivgt_lookup`: the key's manager, if one is registered.
    fn ivgt_lookup(&mut self, key_index: u32) -> Option<Ivam> {
        if key_index as usize >= key::NUM_WELL_KNOWN {
            return None;
        }
        match index_to_key(key_index) {
            key::IMPORTANCE => Some(Ivam::Importance),
            key::BANK => Some(Ivam::Bank),
            _ => None,
        }
    }

    fn ivac(&mut self, key_index: u32) -> &mut Ivac {
        self.vt().ivac[key_index as usize].as_mut().expect("a registered key")
    }

    fn voucher(&mut self, v: VoucherId) -> &mut Voucher {
        self.vt().vouchers.get_mut(&v).expect("a voucher")
    }

    /// `iv_lookup`.
    fn iv_lookup(&mut self, v: VoucherId, key_index: u32) -> u32 {
        if (key_index as usize) < KEY_NUM { self.voucher(v).table[key_index as usize] } else { IV_UNUSED_VALINDEX }
    }

    /// `iv_set`.
    fn iv_set(&mut self, v: VoucherId, key_index: u32, value_index: u32) {
        assert!((key_index as usize) < KEY_NUM, "key_index >= MACH_VOUCHER_ATTR_KEY_NUM");
        self.voucher(v).table[key_index as usize] = value_index;
    }

    /// `iv_alloc`.
    fn iv_alloc(&mut self) -> VoucherId {
        let vs = self.vt();
        vs.next += 1;
        let id = vs.next;
        vs.vouchers.insert(id, Voucher { table: [IV_UNUSED_VALINDEX; KEY_NUM], refs: 1, port: None });
        id
    }

    /// `ipc_voucher_reference`.
    pub(crate) fn ipc_voucher_reference(&mut self, v: VoucherId) {
        self.voucher(v).refs += 1;
    }

    /// `ipc_voucher_release`.
    pub(crate) fn ipc_voucher_release(&mut self, v: VoucherId) {
        let iv = self.voucher(v);
        iv.refs -= 1;
        if iv.refs == 0 {
            self.iv_dealloc(v, true);
        }
    }

    /// `iv_dealloc`.
    fn iv_dealloc(&mut self, v: VoucherId, unhash: bool) {
        if unhash {
            let t = self.voucher(v).table;
            self.vt().by_table.remove(&t);
        }
        if let Some(port) = self.voucher(v).port.take() {
            // ipc_kobject_dealloc_port: no send right is left.
            assert_eq!(self.ipc().port(port).srights, 0);
            let p = self.ipc().port_mut(port);
            p.active = false;
            p.kobject = None;
            self.ipc().release(port);
        }
        for i in 0..KEY_NUM as u32 {
            let vi = self.voucher(v).table[i as usize];
            self.ivace_release(i, vi);
            self.voucher(v).table[i as usize] = IV_UNUSED_VALINDEX;
        }
        self.vt().vouchers.remove(&v);
    }

    /// `iv_dedup`: the voucher already made with the same values, or this
    /// one, now known.
    fn iv_dedup(&mut self, v: VoucherId) -> VoucherId {
        let t = self.voucher(v).table;
        if let Some(&dupe) = self.vt().by_table.get(&t) {
            self.ipc_voucher_reference(dupe);
            self.iv_dealloc(v, false);
            return dupe;
        }
        self.vt().by_table.insert(t, v);
        v
    }

    /// `ivace_release`: a voucher lets go of a value; the last reference
    /// returns it to its manager.
    fn ivace_release(&mut self, key_index: u32, value_index: u32) {
        if value_index == IV_UNUSED_VALINDEX {
            return;
        }
        let ivam = self.ivgt_lookup(key_index).expect("a registered key");
        let ivac = self.ivac(key_index);
        let e = &mut ivac.table[value_index as usize];
        assert!(e.refs > 0);
        if e.persist {
            return;
        }
        e.refs -= 1;
        if e.refs > 0 || e.releasing {
            return;
        }
        e.releasing = true;
        let value = e.value;
        let k = index_to_key(key_index);
        loop {
            let made = self.ivac(key_index).table[value_index as usize].made;
            let kr = match ivam {
                Ivam::Bank => self.bank_release_value(value, made),
                Ivam::Importance => self.ipc_importance_release_value(value, made),
            };
            let _ = k;
            let ivac = self.ivac(key_index);
            let e = &mut ivac.table[value_index as usize];
            assert_eq!(e.value, value);
            if e.made != made {
                // More references were made while it was released: the
                // manager kept the value.
                if kr == vkr::SUCCESS {
                    e.made -= made;
                }
                if e.refs == 0 {
                    continue;
                }
                e.releasing = false;
                return;
            }
            if kr != vkr::SUCCESS {
                e.releasing = false;
                return;
            }
            break;
        }
        assert_eq!(self.ivac(key_index).table[value_index as usize].refs, 0);
        self.ivac(key_index).free_entry(value_index);
    }

    /// `ipc_replace_voucher_value`: the manager's value for `key` from the
    /// command and the previous voucher's value.
    fn ipc_replace_voucher_value(&mut self, v: VoucherId, k: u32, command: u32, prev: Option<VoucherId>, content: &[u8]) -> u32 {
        let key_index = key_to_index(k);
        let Some(ivam) = self.ivgt_lookup(key_index) else { return vkr::INVALID_ARGUMENT };
        let save_val_index = self.iv_lookup(v, key_index);
        let prev_val_index = match prev {
            Some(p) => self.iv_lookup(p, key_index),
            None => save_val_index,
        };
        let previous = self.ivac(key_index).values(prev_val_index);
        let r = match ivam {
            Ivam::Bank => self.bank_get_value(command, &previous, content),
            Ivam::Importance => self.ipc_importance_get_value(command, &previous, content),
        };
        let (new_value, new_flag) = match r {
            Ok(x) => x,
            Err(kr) => return kr,
        };
        let val_index = self.ivac(key_index).reference_by_value(new_value, new_flag);
        self.iv_set(v, key_index, val_index);
        self.ivace_release(key_index, save_val_index);
        vkr::SUCCESS
    }

    /// `ipc_directly_replace_voucher_value`.
    fn ipc_directly_replace_voucher_value(&mut self, v: VoucherId, k: u32, new_value: u64) -> u32 {
        let key_index = key_to_index(k);
        if self.ivgt_lookup(key_index).is_none() {
            return vkr::INVALID_ARGUMENT;
        }
        let save_val_index = self.iv_lookup(v, key_index);
        let val_index = self.ivac(key_index).reference_by_value(new_value, 0);
        self.iv_set(v, key_index, val_index);
        self.ivace_release(key_index, save_val_index);
        vkr::SUCCESS
    }

    /// `ipc_execute_voucher_recipe_command`.
    fn ipc_execute_voucher_recipe_command(&mut self, v: VoucherId, k: u32, command: u32, prev: Option<VoucherId>, content: &[u8], key_priv: bool) -> u32 {
        match command {
            cmd::COPY => {
                if !content.is_empty() {
                    return vkr::INVALID_ARGUMENT;
                }
                let Some(p) = prev else { return vkr::SUCCESS };
                let keys: Vec<u32> = if k == key::ALL {
                    (0..KEY_NUM as u32).collect()
                } else {
                    let ki = key_to_index(k);
                    if ki > KEY_NUM as u32 {
                        return vkr::INVALID_ARGUMENT;
                    }
                    vec![ki]
                };
                for j in keys {
                    let vi = self.iv_lookup(v, j);
                    self.ivace_release(j, vi);
                    let pi = self.iv_lookup(p, j);
                    if pi != IV_UNUSED_VALINDEX {
                        self.ivac(j).reference_by_index(pi);
                    }
                    self.iv_set(v, j, pi);
                }
            }
            cmd::REMOVE => {
                if !content.is_empty() {
                    return vkr::INVALID_ARGUMENT;
                }
                let keys: Vec<u32> = if k == key::ALL {
                    (0..KEY_NUM as u32).collect()
                } else {
                    let ki = key_to_index(k);
                    if ki > KEY_NUM as u32 {
                        return vkr::INVALID_ARGUMENT;
                    }
                    vec![ki]
                };
                let all = k == key::ALL;
                for j in keys {
                    let vi = self.iv_lookup(v, j);
                    if let Some(p) = prev {
                        if vi != self.iv_lookup(p, j) {
                            if all {
                                continue;
                            }
                            break;
                        }
                    }
                    self.ivace_release(j, vi);
                    self.iv_set(v, j, IV_UNUSED_VALINDEX);
                }
            }
            cmd::SET_VALUE_HANDLE => {
                if !key_priv {
                    return vkr::INVALID_CAPABILITY;
                }
                if content.len() != 8 {
                    return vkr::INVALID_ARGUMENT;
                }
                let new_value = u64::from_le_bytes(content.try_into().unwrap());
                let kr = self.ipc_directly_replace_voucher_value(v, k, new_value);
                if kr != vkr::SUCCESS {
                    return kr;
                }
            }
            cmd::REDEEM if k == key::ALL => {
                for j in 0..KEY_NUM as u32 {
                    let jk = index_to_key(j);
                    if jk == key::NONE {
                        continue;
                    }
                    let kr = self.ipc_replace_voucher_value(v, jk, command, prev, content);
                    if kr != vkr::SUCCESS {
                        return kr;
                    }
                }
            }
            _ => {
                let kr = self.ipc_replace_voucher_value(v, k, command, prev, content);
                if kr != vkr::SUCCESS {
                    return kr;
                }
            }
        }
        vkr::SUCCESS
    }

    /// `ipc_create_mach_voucher_internal`: a voucher from recipes, given
    /// a manager's privilege for its own key (`control`).
    pub(crate) fn ipc_create_mach_voucher(&mut self, control: Option<u32>, recipes: &[Recipe]) -> Result<Option<VoucherId>, u32> {
        if recipes.is_empty() {
            return Ok(None);
        }
        let v = self.iv_alloc();
        for r in recipes {
            let key_priv = control.is_some_and(|c| c == r.key);
            let kr = self.ipc_execute_voucher_recipe_command(v, r.key, r.command, r.previous, &r.content, key_priv);
            if kr != vkr::SUCCESS {
                self.iv_dealloc(v, false);
                return Err(kr);
            }
        }
        Ok(Some(self.iv_dedup(v)))
    }

    /// `host_create_mach_voucher` from a user's raw recipes. The recipes'
    /// previous vouchers are each referenced only while their command
    /// runs, as `ipc_create_mach_voucher_internal` converts them one by
    /// one; a bad recipe stops the rest.
    pub(crate) fn host_create_mach_voucher(&mut self, raw: &[u8]) -> Result<Option<VoucherId>, u32> {
        if raw.is_empty() {
            return Ok(None);
        }
        let v = self.iv_alloc();
        let mut used = 0usize;
        while used < raw.len() {
            if raw.len() - used < RECIPE_SIZE {
                self.iv_dealloc(v, false);
                return Err(vkr::INVALID_ARGUMENT);
            }
            let w = |o: usize| u32::from_le_bytes(raw[used + o..used + o + 4].try_into().unwrap());
            let (k, command, prev_name, size) = (w(0), w(4), w(8), w(12) as usize);
            if raw.len() - used - RECIPE_SIZE < size {
                self.iv_dealloc(v, false);
                return Err(vkr::INVALID_ARGUMENT);
            }
            let prev = self.convert_port_name_to_voucher(prev_name);
            if prev_name != 0 && prev.is_none() {
                self.iv_dealloc(v, false);
                return Err(vkr::INVALID_CAPABILITY);
            }
            let content = raw[used + RECIPE_SIZE..used + RECIPE_SIZE + size].to_vec();
            used += RECIPE_SIZE + size;
            let kr = self.ipc_execute_voucher_recipe_command(v, k, command, prev, &content, false);
            if let Some(p) = prev {
                self.ipc_voucher_release(p);
            }
            if kr != vkr::SUCCESS {
                self.iv_dealloc(v, false);
                return Err(kr);
            }
        }
        Ok(Some(self.iv_dedup(v)))
    }

    /// `convert_port_name_to_voucher`: a reference on the voucher a send
    /// right names.
    pub(crate) fn convert_port_name_to_voucher(&mut self, name: u32) -> Option<VoucherId> {
        if !super::ipc::name_valid(name) {
            return None;
        }
        let port = self.ipc().translate_send(name).ok()?;
        self.convert_port_to_voucher(port)
    }

    /// `convert_port_to_voucher`.
    pub(crate) fn convert_port_to_voucher(&mut self, port: ObjId) -> Option<VoucherId> {
        match self.ipc().port(port).kobject {
            Some(super::ipc::Kobject::Voucher(v)) => {
                self.ipc_voucher_reference(v);
                Some(v)
            }
            _ => None,
        }
    }

    /// `convert_voucher_to_port`: a send right for the voucher's port,
    /// made the first time; the voucher's reference goes to the port's
    /// send rights (released again when they are all gone).
    pub(crate) fn convert_voucher_to_port(&mut self, v: VoucherId) -> ObjId {
        // ipc_kobject_make_send_lazy_alloc_port: a send right made, with a
        // no-senders request armed; the caller's reference goes to the
        // request when this arms it, and is dropped when one was armed.
        let (port, armed) = match self.voucher(v).port {
            Some(p) => {
                let armed = !self.ipc().port(p).nsrequest_kobject;
                (p, armed)
            }
            None => {
                let p = self.ipc().kobject_port(super::ipc::Kobject::Voucher(v));
                self.voucher(v).port = Some(p);
                (p, true)
            }
        };
        self.ipc().make_send(port);
        if armed {
            self.ipc().port_mut(port).nsrequest_kobject = true;
        } else {
            self.ipc_voucher_release(v);
        }
        port
    }

    /// `ipc_voucher_no_senders`: the port's reference goes.
    pub(crate) fn ipc_voucher_no_senders(&mut self, v: VoucherId) {
        self.ipc_voucher_release(v);
    }

    /// `mach_voucher_extract_attr_recipe`: the recipe that would make the
    /// voucher's value for `k`, at most `size` bytes.
    pub(crate) fn mach_voucher_extract_attr_recipe(&mut self, v: VoucherId, k: u32, size: u32) -> Result<Vec<u8>, u32> {
        let key_index = key_to_index(k);
        let value_index = self.iv_lookup(v, key_index);
        if value_index == IV_UNUSED_VALINDEX {
            return Ok(Vec::new());
        }
        if (size as usize) < RECIPE_SIZE {
            return Err(vkr::NO_SPACE);
        }
        let Some(ivam) = self.ivgt_lookup(key_index) else { return Err(vkr::INVALID_ARGUMENT) };
        let vals = self.ivac(key_index).values(value_index);
        let room = size - RECIPE_SIZE as u32;
        let (command, content) = self.ivam_extract_content(ivam, &vals, room)?;
        let mut out = Vec::with_capacity(RECIPE_SIZE + content.len());
        for w in [k, command, 0, content.len() as u32] {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&content);
        Ok(out)
    }

    /// `mach_voucher_extract_attr_content`.
    pub(crate) fn mach_voucher_extract_attr_content(&mut self, v: VoucherId, k: u32, size: u32) -> Result<Vec<u8>, u32> {
        let key_index = key_to_index(k);
        let value_index = self.iv_lookup(v, key_index);
        if value_index == IV_UNUSED_VALINDEX {
            return Ok(Vec::new());
        }
        let Some(ivam) = self.ivgt_lookup(key_index) else { return Err(vkr::INVALID_ARGUMENT) };
        let vals = self.ivac(key_index).values(value_index);
        self.ivam_extract_content(ivam, &vals, size).map(|(_, c)| c)
    }

    /// `mach_voucher_attr_command`.
    pub(crate) fn mach_voucher_attr_command(&mut self, v: VoucherId, k: u32, command: u32, input: &[u8], out_size: u32) -> Result<Vec<u8>, u32> {
        let key_index = key_to_index(k);
        let Some(ivam) = self.ivgt_lookup(key_index) else { return Err(vkr::INVALID_ARGUMENT) };
        let value_index = self.iv_lookup(v, key_index);
        let vals = self.ivac(key_index).values(value_index);
        match ivam {
            Ivam::Bank => self.bank_command(&vals, command, out_size),
            Ivam::Importance => self.ipc_importance_command(&vals, command, input, out_size),
        }
    }

    fn ivam_extract_content(&mut self, ivam: Ivam, vals: &[u64], size: u32) -> Result<(u32, Vec<u8>), u32> {
        match ivam {
            Ivam::Bank => self.bank_extract_content(vals, size),
            Ivam::Importance => self.ipc_importance_extract_content(vals, size),
        }
    }

    /// `mach_voucher_extract_all_attr_recipes`: a recipe for each key the
    /// voucher has a value for, within `size` bytes.
    pub(crate) fn mach_voucher_extract_all_attr_recipes(&mut self, v: VoucherId, size: u32) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        for ki in 0..KEY_NUM as u32 {
            let vi = self.iv_lookup(v, ki);
            if vi == IV_UNUSED_VALINDEX {
                continue;
            }
            if (size as usize) - out.len() < RECIPE_SIZE {
                return Err(vkr::NO_SPACE);
            }
            let Some(ivam) = self.ivgt_lookup(ki) else { continue };
            let room = size - (out.len() + RECIPE_SIZE) as u32;
            let vals = self.ivac(ki).values(vi);
            let (command, content) = self.ivam_extract_content(ivam, &vals, room)?;
            for w in [index_to_key(ki), command, 0, content.len() as u32] {
                out.extend_from_slice(&w.to_le_bytes());
            }
            out.extend_from_slice(&content);
        }
        Ok(out)
    }

    /// Run `f` on voucher `v` with a reference held, as a MIG routine does
    /// on the voucher it converted its port to.
    pub(crate) fn with_voucher<T>(&mut self, v: VoucherId, f: impl FnOnce(&mut Kernel, VoucherId) -> T) -> T {
        self.ipc_voucher_reference(v);
        let r = f(self, v);
        self.ipc_voucher_release(v);
        r
    }

    /// `ipc_voucher_prepare_processing_recipe`: a copy of the voucher, then
    /// `command` for each of its keys whose manager takes it.
    fn ipc_voucher_prepare_processing_recipe(&mut self, v: VoucherId, command: u32, flags: u32) -> (Vec<Recipe>, bool) {
        let mut recipes = vec![Recipe { key: key::ALL, command: cmd::COPY, previous: Some(v), content: Vec::new() }];
        let mut need = false;
        for ki in 0..KEY_NUM as u32 {
            if self.iv_lookup(v, ki) == IV_UNUSED_VALINDEX {
                continue;
            }
            let Some(ivam) = self.ivgt_lookup(ki) else { continue };
            if ivam.flags() & flags == 0 {
                continue;
            }
            recipes.push(Recipe { key: index_to_key(ki), command, previous: Some(v), content: Vec::new() });
            need = true;
        }
        (recipes, need)
    }

    /// `ipc_voucher_send_preprocessing`: the voucher a message carries
    /// becomes what its managers make of it on the way out.
    pub(crate) fn ipc_voucher_send_preprocessing(&mut self, voucher_port: ObjId) -> ObjId {
        let Some(super::ipc::Kobject::Voucher(v)) = self.ipc().port(voucher_port).kobject else { unreachable!("a voucher port") };
        let (recipes, need) = self.ipc_voucher_prepare_processing_recipe(v, cmd::SEND_PREPROCESS, ivam_flags::SUPPORT_SEND_PREPROCESS);
        if !need {
            return voucher_port;
        }
        let nv = self.ipc_create_mach_voucher(None, &recipes).expect("send preprocessing makes a voucher").expect("a voucher");
        self.ipc().release_send(voucher_port);
        self.convert_voucher_to_port(nv)
    }

    /// `ipc_voucher_receive_postprocessing`: the voucher a received message
    /// carries is redeemed by its managers (MACH_RCV_VOUCHER only).
    pub(crate) fn ipc_voucher_receive_postprocessing(&mut self, voucher_port: ObjId) -> ObjId {
        let Some(super::ipc::Kobject::Voucher(v)) = self.ipc().port(voucher_port).kobject else { unreachable!("a voucher port") };
        let (recipes, need) = self.ipc_voucher_prepare_processing_recipe(v, cmd::AUTO_REDEEM, ivam_flags::SUPPORT_RECEIVE_POSTPROCESS);
        if !need {
            return voucher_port;
        }
        let nv = self.ipc_create_mach_voucher(None, &recipes).expect("receive postprocessing makes a voucher").expect("a voucher");
        self.ipc().release_send(voucher_port);
        self.convert_voucher_to_port(nv)
    }

    /// The importance value of the voucher a port names
    /// (`mach_voucher_attr_control_get_values`), if it has one.
    pub(crate) fn voucher_port_importance(&mut self, port: ObjId) -> Option<u64> {
        let Some(super::ipc::Kobject::Voucher(v)) = self.ipc().port(port).kobject else { return None };
        let ki = key_to_index(key::IMPORTANCE);
        let vi = self.iv_lookup(v, ki);
        self.ivac(ki).values(vi).first().copied()
    }

    /// `thread_set_voucher_name`: the calling thread adopts the voucher a
    /// send right names, or none.
    pub(crate) fn thread_set_voucher_name(&mut self, name: u32) -> u32 {
        const KERN_INVALID_RIGHT: u32 = 17;
        if name == super::ipc::PORT_DEAD {
            return KERN_INVALID_RIGHT;
        }
        let mut new = None;
        if super::ipc::name_valid(name) {
            new = self.convert_port_name_to_voucher(name);
            if new.is_none() {
                return vkr::INVALID_ARGUMENT;
            }
        }
        // bank_get_bank_ledger_thread_group_and_persona: the bank's ledger
        // (its thread group is not modeled; the persona is none), which
        // bank_swap_thread_bank_ledger makes the thread's.
        let ledger = self.bank_voucher_ledger(new);
        let tid = self.tid;
        let t = self.dtask.threads.map.entry(tid).or_default();
        let old = std::mem::replace(&mut t.voucher, new);
        t.voucher_name = name;
        self.bank_swap_thread_ledger(tid, ledger);
        if let Some(o) = old {
            self.ipc_voucher_release(o);
        }
        vkr::SUCCESS
    }

    /// `thread_set_voucher_name(MACH_PORT_NULL)` as thread `tid` runs
    /// it: the thread adopts no voucher.
    pub(crate) fn darwin_thread_clear_voucher(&mut self, tid: i32) {
        let Some(t) = self.dtask.threads.map.get_mut(&tid) else { return };
        let old = t.voucher.take();
        t.voucher_name = 0;
        self.bank_swap_thread_ledger(tid, None);
        if let Some(o) = old {
            self.ipc_voucher_release(o);
        }
    }

    /// Thread `tid` ends (`thread_terminate_self`'s
    /// `bank_swap_thread_bank_ledger(thread, NULL)`), then lets go of its
    /// voucher.
    pub(crate) fn darwin_thread_bank_end(&mut self, tid: i32) {
        self.bank_swap_thread_ledger(tid, None);
    }

    /// The task's threads let go of the vouchers they adopted, as they end
    /// with it (`thread_deallocate_complete`).
    pub(crate) fn darwin_threads_vouchers_release(&mut self) {
        let tids: Vec<i32> = self.dtask.threads.map.keys().copied().collect();
        for tid in tids {
            self.bank_swap_thread_ledger(tid, None);
        }
        let held: Vec<VoucherId> = self.dtask.threads.map.values_mut().filter_map(|t| t.voucher.take()).collect();
        for v in held {
            self.ipc_voucher_release(v);
        }
    }

    // -- the traps -----------------------------------------------------------------------

    /// `host_create_mach_voucher_trap(host, recipes, recipes_size,
    /// voucher)`.
    pub(crate) fn host_create_mach_voucher_trap(&mut self, m: &mut crate::GuestMem<'_>, host: u32, recipes: u64, size: i32, out: u64) -> u64 {
        use super::ipc::msg::mr;
        // port_name_to_host: a send right to the host or its privilege port.
        let is_host = super::ipc::name_valid(host)
            && self.ipc().translate_send(host).is_ok_and(|p| matches!(self.ipc().port(p).kobject, Some(super::ipc::Kobject::Host | super::ipc::Kobject::HostPriv)));
        if !is_host {
            return u64::from(mr::SEND_INVALID_DEST);
        }
        if size < 0 {
            return u64::from(vkr::INVALID_ARGUMENT);
        }
        if size as u32 > MAX_RAW_RECIPE_ARRAY_SIZE {
            return super::mach::kr2::MIG_ARRAY_TOO_LARGE;
        }
        let Ok(raw) = m.read(recipes, size as usize).map(<[u8]>::to_vec) else { return super::mach::kr2::MEMORY_ERROR };
        let v = match self.host_create_mach_voucher(&raw) {
            Ok(v) => v,
            Err(kr) => return u64::from(kr),
        };
        // convert_voucher_to_port, then the right copied out (a null
        // voucher is the null name).
        let name = match v {
            Some(v) => {
                let p = self.convert_voucher_to_port(v);
                self.darwin_copyout_send(p)
            }
            None => 0,
        };
        if m.write_u32(out, name).is_err() {
            return super::mach::kr2::MEMORY_ERROR;
        }
        0
    }

    /// `mach_voucher_extract_attr_recipe_trap(voucher, key, recipe,
    /// recipe_size)`.
    pub(crate) fn mach_voucher_extract_attr_recipe_trap(&mut self, m: &mut crate::GuestMem<'_>, name: u32, k: u32, recipe: u64, size_at: u64) -> u64 {
        use super::ipc::msg::mr;
        let Ok(sz) = m.read_u32(size_at) else { return super::mach::kr2::MEMORY_ERROR };
        if sz > MAX_RAW_RECIPE_ARRAY_SIZE {
            return super::mach::kr2::MIG_ARRAY_TOO_LARGE;
        }
        let Some(v) = self.convert_port_name_to_voucher(name) else { return u64::from(mr::SEND_INVALID_DEST) };
        let r = if m.read(recipe, sz as usize).is_err() {
            Err(super::mach::kr2::MEMORY_ERROR as u32)
        } else {
            self.mach_voucher_extract_attr_recipe(v, k, sz)
        };
        let kr = match r {
            Ok(out) => {
                if !out.is_empty() && m.write(recipe, &out).is_err() {
                    super::mach::kr2::MEMORY_ERROR
                } else if m.write_u32(size_at, out.len() as u32).is_err() {
                    super::mach::kr2::MEMORY_ERROR
                } else {
                    0
                }
            }
            Err(kr) => u64::from(kr),
        };
        self.ipc_voucher_release(v);
        kr
    }

    // -- the bank ------------------------------------------------------------------------

    /// The credential's ids are what the task's bank context will record
    /// (`task_bank_init`, at a fork and once an exec's image is in
    /// place); the rest of what it records does not change in a task.
    pub(crate) fn darwin_task_bank_init(&mut self) {
        assert!(self.dtask.vouchers.bank_context.is_none(), "Task bank init called with non null bank context");
        self.dtask.vouchers.bank_ids = Some((self.dtask.cred.uid, self.dtask.cred.gid()));
    }

    /// A spawn's child's `task_bank_init`, once its credentials and
    /// persona are its own: the ids its fork recorded give way.
    pub(crate) fn darwin_task_bank_reinit(&mut self) {
        self.dtask.vouchers.bank_ids = None;
        self.darwin_task_bank_init();
    }

    /// `get_bank_task_context(current_task(), FALSE)`: the task's bank
    /// context, made from what `task_bank_init` recorded.
    fn get_bank_task_context(&mut self) -> u64 {
        if let Some(h) = self.dtask.vouchers.bank_context {
            return h;
        }
        let bt = self.bank_task_alloc_init();
        let vt = self.vt();
        let h = vt.alloc_handle();
        vt.bank.insert(h, BankElem::Task(bt));
        self.dtask.vouchers.bank_context = Some(h);
        h
    }

    /// `bank_task_alloc_init`: the task's bank context, with one reference
    /// (the task's), its process's persona and whether that persona may be
    /// adopted (`bank_task_is_persona_adoption_allowed`: a system or
    /// system proxy persona's, on iOS).
    fn bank_task_alloc_init(&mut self) -> BankTask {
        let persona = self.dtask.persona.clone();
        let flags = if persona.as_ref().is_some_and(|p| p.adoption_allowed()) { bank::FLAG_ADOPTION_ALLOWED } else { 0 };
        let (uid, gid) = self.dtask.vouchers.bank_ids.unwrap_or((self.dtask.cred.uid, self.dtask.cred.gid()));
        let info = ProcPersonaInfo {
            unique_pid: self.dtask.uniqueid,
            pid: self.pid,
            flags,
            pidversion: self.dtask.pidversion as u32,
            persona_id: persona.as_ref().map_or(bank::PERSONA_ID_NONE, |p| p.id),
            uid,
            gid,
            macho_uuid: self.dtask.uuid,
        };
        let persona_uid = persona.as_ref().map_or(super::cred::UID_NONE, |p| p.get_uid());
        // get_bank_task_context: bt_ledger is the task's ledger.
        let ledger = Some(LedgerAt::Cell(std::sync::Arc::clone(&self.dtask.rusage.bank.lock().unwrap_or_else(|e| e.into_inner()))));
        let owner = self.ipc().task;
        BankTask { refs: 1, made: 0, voucher_ref: 0, info, persona_uid, hasentitlement: self.bank_task_is_propagate_entitled(), thread_group: super::coalition::thread_group(self.pid), to_pay: Vec::new(), to_charge: Vec::new(), ledger, owner }
    }

    /// `bank_task_is_propagate_entitled`: a platform binary propagates
    /// its persona unless entitled not to.
    fn bank_task_is_propagate_entitled(&mut self) -> bool {
        if self.darwin_task_entitled("com.apple.private.personas.no.propagate") {
            return false;
        }
        self.darwin_task_platform_binary()
    }

    fn bank_task(&mut self, h: u64) -> &mut BankTask {
        match self.vt().bank.get_mut(&h) {
            Some(BankElem::Task(t)) => t,
            _ => panic!("a bank task"),
        }
    }

    fn bank_account(&mut self, h: u64) -> &mut BankAccount {
        match self.vt().bank.get_mut(&h) {
            Some(BankElem::Account(a)) => a,
            _ => panic!("a bank account"),
        }
    }

    fn bank_is_task(&mut self, h: u64) -> bool {
        match self.vt().bank.get(&h) {
            Some(BankElem::Task(_)) => true,
            Some(BankElem::Account(_)) => false,
            None => panic!("Bogus bank type passed in get_value"),
        }
    }

    /// `bank_task_get_persona`.
    fn bank_task_get_persona(&mut self, h: u64) -> BankPersona {
        let t = self.bank_task(h);
        BankPersona { id: t.info.persona_id, uid: t.persona_uid }
    }

    /// `bank_task_can_adopt_persona`.
    fn bank_task_can_adopt_persona(&mut self, merchant: u64, p: BankPersona) -> bool {
        let t = self.bank_task(merchant);
        if t.info.persona_id == p.id {
            return true;
        }
        if t.info.flags & bank::FLAG_ADOPTION_ALLOWED == 0 {
            return false;
        }
        // A persona uid set, other than a system session persona's that
        // belongs to no user (UINT_MAX), must be the new one's.
        let own = t.persona_uid;
        own == super::cred::UID_NONE || own == u32::MAX || own == p.uid
    }

    /// `bank_task_made_reference`, and the voucher system's reference the
    /// first time (`bt_voucher_ref`).
    fn bank_task_made_reference_for_voucher(&mut self, h: u64) {
        let t = self.bank_task(h);
        t.made += 1;
        if t.voucher_ref == 0 {
            t.refs += 1;
            t.voucher_ref = 1;
        }
    }

    /// `bank_task_dealloc`: a reference goes; the last frees the context.
    fn bank_task_dealloc(&mut self, h: u64) {
        let t = self.bank_task(h);
        t.refs -= 1;
        if t.refs > 0 {
            return;
        }
        assert!(t.to_pay.is_empty() && t.to_charge.is_empty());
        self.vt().bank.remove(&h);
    }

    /// `bank_account_alloc_init`: the holder's account with the merchant,
    /// for this originator, proximate process, thread group and persona,
    /// with a made reference: the one it has, or a new one linking them.
    fn bank_account_alloc_init(&mut self, holder: u64, merchant: u64, so: u64, pp: u64, tg: u64, persona: BankPersona) -> u64 {
        let to_pay = self.bank_task(holder).to_pay.clone();
        for a in to_pay {
            let acc = self.bank_account(a);
            if acc.merchant != merchant || acc.secureoriginator != so || acc.proximateprocess != pp || acc.thread_group != tg || acc.so_persona.id != persona.id {
                continue;
            }
            acc.made += 1;
            return a;
        }
        let vt = self.vt();
        let h = vt.alloc_handle();
        vt.bank.insert(h, BankElem::Account(BankAccount { refs: 1, made: 1, merchant, holder, secureoriginator: so, proximateprocess: pp, thread_group: tg, so_persona: persona, bill: 0, bill_unkept: false, adopters: Vec::new() }));
        self.bank_task(holder).to_pay.push(h);
        self.bank_task(merchant).to_charge.push(h);
        for t in [holder, merchant, so, pp] {
            self.bank_task(t).refs += 1;
        }
        h
    }

    /// `bank_account_dealloc_with_sync`: the account goes if the voucher
    /// system's made references are all there are.
    fn bank_account_dealloc_with_sync(&mut self, h: u64, sync: u32) -> u32 {
        let acc = self.bank_account(h);
        if acc.made != sync {
            return vkr::FAILURE;
        }
        acc.made -= sync;
        acc.refs -= 1;
        assert!(acc.refs == 0, "Releasing a non zero ref bank account");
        let (holder, merchant, so, pp) = (acc.holder, acc.merchant, acc.secureoriginator, acc.proximateprocess);
        let (bill, unkept) = (acc.bill, acc.bill_unkept);
        // bank_rollup_chit_to_tasks: the bill to the holder's ledger and the
        // merchant's, unless they are the same ledger (or both gone).
        let (hl, ml) = (self.bank_task(holder).ledger.clone(), self.bank_task(merchant).ledger.clone());
        let same = match (&hl, &ml) {
            (Some(a), Some(b)) => a.same(b),
            (None, None) => true,
            _ => false,
        };
        if !same {
            use std::sync::atomic::Ordering::AcqRel;
            for (l, me) in [(hl, true), (ml, false)] {
                match l {
                    None => {}
                    Some(LedgerAt::Cell(l)) => {
                        if me { l.to_me.fetch_add(bill, AcqRel) } else { l.to_others.fetch_add(bill, AcqRel) };
                        l.unkept.fetch_or(unkept, AcqRel);
                    }
                    // Another process's task's ledger: the bill goes to it
                    // (none to a task that has ended).
                    Some(LedgerAt::Elsewhere(key)) => {
                        let (to_me, to_others) = if me { (bill, 0) } else { (0, bill) };
                        self.ipc().remote(key, super::ipc::Remote::Ledger { to_me, to_others, unkept });
                    }
                }
            }
        }
        self.bank_task(holder).to_pay.retain(|&a| a != h);
        self.bank_task(merchant).to_charge.retain(|&a| a != h);
        self.vt().bank.remove(&h);
        for t in [holder, merchant, so, pp] {
            self.bank_task_dealloc(t);
        }
        vkr::SUCCESS
    }

    /// `bank_task_destroy`: the task lets go of its bank context (its
    /// accounts keep it while they last).
    pub(crate) fn darwin_bank_task_destroy(&mut self) {
        if let Some(h) = self.dtask.vouchers.bank_context.take() {
            // bank_destroy_bank_task_ledger: no bill reaches the task's
            // ledger from now on.
            self.bank_task(h).ledger = None;
            self.bank_task_dealloc(h);
        }
    }

    /// `bank_get_bank_ledger_thread_group_and_persona`'s ledger for a
    /// thread adopting voucher `v`: the bill of the account in its bank
    /// value, unless the account's holder is its merchant. The task's bank
    /// context is made if it has none, as the call makes it.
    fn bank_voucher_ledger(&mut self, v: Option<VoucherId>) -> Option<u64> {
        let ctx = self.get_bank_task_context();
        let v = v?;
        let ki = key_to_index(key::BANK);
        let vi = self.iv_lookup(v, ki);
        let h = self.ivac(ki).values(vi).first().copied()?;
        if h == bank::DEFAULT_VALUE {
            return None;
        }
        let h = if h == bank::DEFAULT_TASK_VALUE { ctx } else { h };
        if self.bank_is_task(h) {
            return None;
        }
        let a = self.bank_account(h);
        (a.holder != a.merchant).then_some(h)
    }

    /// The CPU time thread `tid` used since its last credit, to the bill it
    /// has as its bank ledger (`thread_dispatch` as it goes off its CPU,
    /// `bank_swap_thread_bank_ledger`).
    pub(crate) fn darwin_bank_credit(&mut self, tid: i32) {
        let Some(t) = self.dtask.threads.map.get(&tid) else { return };
        let (ledger, deduct) = (t.bank_ledger, t.bank_deduct);
        if ledger.is_none() {
            return;
        }
        let now = self.thread_signals.get(tid).and_then(|s| s.cpu.times()).map(|(u, s)| u + s);
        if let Some(t) = self.dtask.threads.map.get_mut(&tid) {
            t.bank_deduct = now;
        }
        let Some(BankElem::Account(a)) = ledger.and_then(|h| self.vt().bank.get_mut(&h)) else { return };
        match (now, deduct) {
            (Some(n), Some(d)) => a.bill = a.bill.wrapping_add(super::rusage::mach_of_ns(n.saturating_sub(d))),
            _ => a.bill_unkept = true,
        }
    }

    /// `bank_swap_thread_bank_ledger(thread, new)`: thread `tid`'s time so
    /// far goes to the bill it had, and `new` is its bill from now on.
    fn bank_swap_thread_ledger(&mut self, tid: i32, new: Option<u64>) {
        let old = self.dtask.threads.map.get(&tid).and_then(|t| t.bank_ledger);
        if old.is_none() && new.is_none() {
            return;
        }
        self.darwin_bank_credit(tid);
        if old.is_none() {
            // The time from here on is the new bill's.
            let now = self.thread_signals.get(tid).and_then(|s| s.cpu.times()).map(|(u, s)| u + s);
            if let Some(t) = self.dtask.threads.map.get_mut(&tid) {
                t.bank_deduct = now;
            }
        }
        if let Some(BankElem::Account(a)) = old.and_then(|h| self.vt().bank.get_mut(&h)) {
            a.adopters.retain(|&t| t != tid);
        }
        if let Some(BankElem::Account(a)) = new.and_then(|h| self.vt().bank.get_mut(&h)) {
            a.adopters.push(tid);
        }
        if let Some(t) = self.dtask.threads.map.get_mut(&tid) {
            t.bank_ledger = new;
        }
    }

    /// `bank_billed_balance_safe` and `bank_serviced_balance_safe` of
    /// process `pid` (unique id `uniqueid`), whose record is `s`: with a
    /// bank context, its ledger's entries and the bills of its accounts to
    /// pay and to charge; without, its ledger's. A bill a thread has as its
    /// bank ledger while it runs has more than its last credit on a device
    /// (the quantum's end credits it), so it is not known then.
    pub(crate) fn darwin_bank_bills(&mut self, pid: i32, uniqueid: u64, s: &super::rusage::Shared) -> super::rusage::Bills {
        use super::rusage::Bills;
        let own = std::sync::Arc::clone(&s.bank.lock().unwrap_or_else(|e| e.into_inner()));
        let ctx = self.vt().bank.values().find_map(|e| match e {
            BankElem::Task(t) if t.info.pid == pid && t.info.unique_pid == uniqueid && matches!(&t.ledger, Some(LedgerAt::Cell(l)) if std::sync::Arc::ptr_eq(l, &own)) => Some((t.to_pay.clone(), t.to_charge.clone())),
            _ => None,
        });
        let Some((to_pay, to_charge)) = ctx else { return Bills::of_ledger(&own) };
        let mut b = Bills::of_ledger(&own);
        let bill = |k: &mut Kernel, h: u64| match k.vt().bank.get(&h) {
            Some(BankElem::Account(a)) => Some((a.bill, a.bill_unkept, a.adopters.clone())),
            _ => None,
        };
        for (accounts, billed) in [(to_pay, true), (to_charge, false)] {
            for h in accounts {
                let Some((v, unkept, adopters)) = bill(self, h) else { continue };
                let running = adopters.iter().any(|&t| !matches!(self.procs.sched.state(t), Some(super::sched::RunState::Wait | super::sched::RunState::Unint)));
                let total = if billed { &mut b.billed } else { &mut b.serviced };
                *total = if unkept || running { None } else { total.map(|t| t.wrapping_add(v)) };
            }
        }
        b
    }

    /// The bank element a value names, the default task value naming the
    /// current task's context.
    fn bank_element(&mut self, h: u64) -> u64 {
        if h == bank::DEFAULT_TASK_VALUE { self.get_bank_task_context() } else { h }
    }

    /// `bank_get_value`.
    fn bank_get_value(&mut self, command: u32, prev: &[u64], content: &[u8]) -> Result<(u64, u32), u32> {
        match command {
            // The default task value, which SEND_PREPROCESS makes a bank
            // context's.
            cmd::BANK_CREATE => Ok((bank::DEFAULT_TASK_VALUE, VALUE_FLAGS_PERSIST)),
            cmd::BANK_MODIFY_PERSONA => {
                for &h in prev {
                    if h == bank::DEFAULT_VALUE || h == bank::DEFAULT_TASK_VALUE {
                        continue;
                    }
                    if !self.darwin_task_entitled("com.apple.private.persona.modify") {
                        return Err(vkr::NO_ACCESS);
                    }
                    // struct persona_modify_info: persona_id, then (8-byte
                    // aligned) unique_pid.
                    if content.len() != 16 {
                        return Err(vkr::INVALID_ARGUMENT);
                    }
                    let id = u32::from_le_bytes(content[0..4].try_into().unwrap());
                    let unique_pid = u64::from_le_bytes(content[8..16].try_into().unwrap());
                    // bank_verify_persona_id.
                    let Some(p) = super::persona::lookup(id) else { return Err(vkr::INVALID_ARGUMENT) };
                    let persona = BankPersona { id, uid: p.get_uid() };
                    // Only a bank context's persona changes: its holder is
                    // to be trusted.
                    if !self.bank_is_task(h) {
                        return Err(vkr::INVALID_ARGUMENT);
                    }
                    let holder = h;
                    if unique_pid != self.bank_task(holder).info.unique_pid {
                        return Err(vkr::INVALID_CAPABILITY);
                    }
                    let tg = self.bank_task(holder).thread_group;
                    if !self.bank_task_can_adopt_persona(holder, persona) {
                        return Err(vkr::INVALID_ARGUMENT);
                    }
                    if self.bank_task(holder).info.persona_id == persona.id {
                        self.bank_task_made_reference_for_voucher(holder);
                        return Ok((holder, 0));
                    }
                    return Ok((self.bank_account_alloc_init(holder, holder, holder, holder, tg, persona), 0));
                }
                Ok((bank::DEFAULT_VALUE, 0))
            }
            cmd::AUTO_REDEEM => {
                for &h in prev {
                    // A default task value is not received from IPC.
                    if h == bank::DEFAULT_VALUE || h == bank::DEFAULT_TASK_VALUE {
                        continue;
                    }
                    let (holder, so, pp, tg, mut persona);
                    if self.bank_is_task(h) {
                        holder = h;
                        so = h;
                        pp = h;
                        tg = self.bank_task(h).thread_group;
                        persona = self.bank_task_get_persona(h);
                    } else {
                        let a = self.bank_account(h);
                        holder = a.holder;
                        so = a.secureoriginator;
                        pp = a.proximateprocess;
                        tg = a.thread_group;
                        persona = a.so_persona;
                    }
                    let merchant = self.get_bank_task_context();
                    let cur_tg = self.bank_task(merchant).thread_group;
                    // An app's voucher takes the app's own thread group.
                    let mut tg = tg;
                    if self.darwin_policy().is_app() {
                        tg = cur_tg;
                    }
                    if !self.bank_task_can_adopt_persona(merchant, persona) {
                        persona = self.bank_task_get_persona(merchant);
                    }
                    if holder == merchant && holder == so && holder == pp && tg == cur_tg && persona.id == self.bank_task(holder).info.persona_id {
                        return Ok((bank::DEFAULT_TASK_VALUE, VALUE_FLAGS_PERSIST));
                    }
                    return Ok((self.bank_account_alloc_init(holder, merchant, so, pp, tg, persona), 0));
                }
                Ok((bank::DEFAULT_VALUE, 0))
            }
            cmd::SEND_PREPROCESS => {
                for &h in prev {
                    if h == bank::DEFAULT_VALUE {
                        continue;
                    }
                    let e = self.bank_element(h);
                    let (holder, mut so, tg, mut persona);
                    if self.bank_is_task(e) {
                        holder = e;
                        so = e;
                        tg = self.bank_task(e).thread_group;
                        persona = self.bank_task_get_persona(e);
                    } else {
                        let a = self.bank_account(e);
                        holder = a.holder;
                        so = a.secureoriginator;
                        tg = a.thread_group;
                        persona = a.so_persona;
                    }
                    let merchant = self.get_bank_task_context();
                    let cur_tg = self.bank_task(merchant).thread_group;
                    // Without the entitlement to propagate it, the
                    // originator is the sender, with its persona.
                    if !self.bank_task(merchant).hasentitlement {
                        so = merchant;
                        persona = self.bank_task_get_persona(merchant);
                    }
                    let pp = merchant;
                    if holder == merchant && holder == so && holder == pp && tg == cur_tg && persona.id == self.bank_task(holder).info.persona_id {
                        self.bank_task_made_reference_for_voucher(holder);
                        return Ok((holder, 0));
                    }
                    return Ok((self.bank_account_alloc_init(holder, merchant, so, pp, tg, persona), 0));
                }
                Ok((bank::DEFAULT_VALUE, 0))
            }
            cmd::REDEEM => {
                // The value is to have been auto-redeemed: a reference on
                // that account, for its merchant only.
                for &h in prev {
                    if h == bank::DEFAULT_VALUE {
                        continue;
                    }
                    if h == bank::DEFAULT_TASK_VALUE {
                        return Ok((bank::DEFAULT_TASK_VALUE, VALUE_FLAGS_PERSIST));
                    }
                    let mine = self.get_bank_task_context();
                    if self.bank_is_task(h) {
                        return if h == mine { Ok((bank::DEFAULT_TASK_VALUE, VALUE_FLAGS_PERSIST)) } else { Err(vkr::INVALID_CAPABILITY) };
                    }
                    let a = self.bank_account(h);
                    if a.merchant != mine {
                        return Err(vkr::INVALID_CAPABILITY);
                    }
                    a.made += 1;
                    return Ok((h, 0));
                }
                Ok((bank::DEFAULT_VALUE, 0))
            }
            _ => Err(vkr::INVALID_ARGUMENT),
        }
    }

    /// `bank_release_value`.
    fn bank_release_value(&mut self, value: u64, sync: u32) -> u32 {
        assert!(value != bank::DEFAULT_VALUE && value != bank::DEFAULT_TASK_VALUE);
        if !self.bank_is_task(value) {
            return self.bank_account_dealloc_with_sync(value, sync);
        }
        let t = self.bank_task(value);
        if t.made != sync {
            return vkr::FAILURE;
        }
        t.made -= sync;
        assert_eq!(t.voucher_ref, 1);
        t.voucher_ref = 0;
        self.bank_task_dealloc(value);
        vkr::SUCCESS
    }

    /// `bank_extract_content`.
    fn bank_extract_content(&mut self, vals: &[u64], size: u32) -> Result<(u32, Vec<u8>), u32> {
        for &h in vals {
            if size == 0 {
                break;
            }
            if h == bank::DEFAULT_VALUE {
                continue;
            }
            let e = self.bank_element(h);
            if BANK_CONTENT_SIZE > size {
                return Err(vkr::NO_SPACE);
            }
            let s = if self.bank_is_task(e) {
                format!(" Bank Context for a pid {}\n", self.bank_task(e).info.pid)
            } else {
                let a = self.bank_account(e);
                let (holder, merchant, so, pp, sop) = (a.holder, a.merchant, a.secureoriginator, a.proximateprocess, a.so_persona.id);
                let pid = |k: &mut Kernel, t: u64| k.bank_task(t).info.pid;
                let (hp, mp, sp, ppp) = (pid(self, holder), pid(self, merchant), pid(self, so), pid(self, pp));
                let pp_persona = self.bank_task(pp).info.persona_id;
                format!(" Bank Account linking holder pid {hp} with merchant pid {mp}, originator PID/persona: {sp}, {sop} and proximate PID/persona: {ppp}, {pp_persona}\n")
            };
            // snprintf into MACH_VOUCHER_BANK_CONTENT_SIZE bytes.
            let mut b = s.into_bytes();
            b.truncate(BANK_CONTENT_SIZE as usize - 1);
            b.push(0);
            return Ok((cmd::BANK_NULL, b));
        }
        Ok((cmd::NOOP, Vec::new()))
    }

    /// `bank_command`.
    fn bank_command(&mut self, vals: &[u64], command: u32, out_size: u32) -> Result<Vec<u8>, u32> {
        let first = vals.iter().copied().find(|&h| h != bank::DEFAULT_VALUE);
        match command {
            bank::ORIGINATOR_PID => {
                if out_size < 4 {
                    return Err(vkr::NO_SPACE);
                }
                let Some(h) = first else { return Err(vkr::INVALID_VALUE) };
                let e = self.bank_element(h);
                let t = if self.bank_is_task(e) { e } else { self.bank_account(e).holder };
                Ok(self.bank_task(t).info.pid.to_le_bytes().to_vec())
            }
            bank::PERSONA_TOKEN => {
                if out_size < 2 * PROC_PERSONA_INFO_SIZE {
                    return Err(vkr::NO_SPACE);
                }
                let Some(h) = first else { return Err(vkr::INVALID_VALUE) };
                let e = self.bank_element(h);
                if self.bank_is_task(e) {
                    return Err(vkr::INVALID_OBJECT);
                }
                let (so, pp) = (self.bank_account(e).secureoriginator, self.bank_account(e).proximateprocess);
                let mut o = self.bank_task(so).info.bytes();
                o.extend_from_slice(&self.bank_task(pp).info.bytes());
                Ok(o)
            }
            bank::PERSONA_ID => {
                if out_size < 4 {
                    return Err(vkr::NO_SPACE);
                }
                let Some(h) = first else { return Err(vkr::INVALID_VALUE) };
                let e = self.bank_element(h);
                let id = if self.bank_is_task(e) { self.bank_task(e).info.persona_id } else { self.bank_account(e).so_persona.id };
                Ok(id.to_le_bytes().to_vec())
            }
            bank::PERSONA_ADOPT_ANY => {
                if out_size < 4 {
                    return Err(vkr::NO_SPACE);
                }
                let merchant = self.get_bank_task_context();
                let any = u32::from(self.bank_task(merchant).info.flags & bank::FLAG_ADOPTION_ALLOWED != 0);
                Ok(any.to_le_bytes().to_vec())
            }
            bank::ORIGINATOR_PROXIMATE_PID => {
                if out_size < 8 {
                    return Err(vkr::NO_SPACE);
                }
                let Some(h) = first else { return Err(vkr::INVALID_VALUE) };
                let e = self.bank_element(h);
                let (origin, proximate) = if self.bank_is_task(e) { (e, None) } else { (self.bank_account(e).holder, Some(self.bank_account(e).proximateprocess)) };
                let mut o = self.bank_task(origin).info.pid.to_le_bytes().to_vec();
                let ppid = match proximate {
                    Some(p) => self.bank_task(p).info.pid,
                    None => -1,
                };
                o.extend_from_slice(&ppid.to_le_bytes());
                Ok(o)
            }
            _ => Err(vkr::INVALID_ARGUMENT),
        }
    }

    /// `bank_get_bank_ledger_thread_group_and_persona`'s persona for a
    /// voucher: its bank account's originator persona, or else the current
    /// task's (`bank_get_voucher_bank_account`).
    pub(crate) fn darwin_bank_persona_id(&mut self, v: VoucherId) -> u32 {
        let ki = key_to_index(key::BANK);
        let vi = self.iv_lookup(v, ki);
        if let Some(&h) = self.ivac(ki).values(vi).first() {
            if h != bank::DEFAULT_VALUE {
                let e = self.bank_element(h);
                if !self.bank_is_task(e) {
                    return self.bank_account(e).so_persona.id;
                }
            }
        }
        let mine = self.get_bank_task_context();
        self.bank_task(mine).info.persona_id
    }

    // -- importance --------------------------------------------------------------------

    /// `ipc_importance_get_value`: a redeem is a made reference on the
    /// value; IMPORTANCE_SELF the current task's element.
    fn ipc_importance_get_value(&mut self, command: u32, prev: &[u64], content: &[u8]) -> Result<(u64, u32), u32> {
        if !content.is_empty() {
            return Err(vkr::INVALID_ARGUMENT);
        }
        match command {
            cmd::REDEEM => match prev.first() {
                Some(&h) => {
                    self.ipc().imp_redeem(h);
                    Ok((h, 0))
                }
                None => Ok((0, 0)),
            },
            cmd::IMPORTANCE_SELF => {
                let me = self.ipc().task;
                Ok((self.ipc().imp_for_task(me, true).unwrap_or(0), 0))
            }
            _ => Err(vkr::INVALID_ARGUMENT),
        }
    }

    /// `ipc_importance_release_value`.
    fn ipc_importance_release_value(&mut self, value: u64, sync: u32) -> u32 {
        self.ipc().imp_release_value(value, sync)
    }

    /// `ipc_importance_extract_content`: the first value's description (a
    /// release kernel's), truncated to the room given as scnprintf does,
    /// with its NUL.
    fn ipc_importance_extract_content(&mut self, vals: &[u64], size: u32) -> Result<(u32, Vec<u8>), u32> {
        if size < 1 {
            return Err(vkr::NO_SPACE);
        }
        let mut out = Vec::new();
        for &h in vals {
            if h == 0 {
                continue;
            }
            let s = self.ipc().imp_content(h);
            let room = (size as usize).saturating_sub(1);
            out.extend_from_slice(&s.as_bytes()[..s.len().min(room)]);
            out.push(0);
            break;
        }
        Ok((cmd::NOOP, out))
    }

    /// `ipc_importance_command`: DROP_EXTERNAL on an inherit, given a
    /// count of 4 bytes and room for one or none.
    fn ipc_importance_command(&mut self, vals: &[u64], command: u32, input: &[u8], out_size: u32) -> Result<Vec<u8>, u32> {
        if input.len() != 4 || (out_size != 0 && out_size != 4) {
            return Err(vkr::INVALID_ARGUMENT);
        }
        let refs = u32::from_le_bytes(input.try_into().unwrap());
        if command != IMPORTANCE_ATTR_DROP_EXTERNAL {
            return Err(vkr::NOT_SUPPORTED);
        }
        let n = self.ipc().imp_drop_external(vals, refs)?;
        Ok(if out_size != 0 { n.to_le_bytes().to_vec() } else { Vec::new() })
    }

    /// `ipc_importance_receive`: with MACH_RCV_VOUCHER, the importance the
    /// message carried goes into the voucher received (made for it when
    /// none was sent), as the receiver's inherit of it; without, it is
    /// taken as a legacy boost.
    pub(crate) fn ipc_importance_receive(&mut self, kmsg: &mut super::ipc::msg::Kmsg, options: u64) {
        if options & super::ipc::msg::opt::RCV_VOUCHER == 0 {
            self.ipc().importance_receive_legacy(kmsg);
            return;
        }
        let inherit = self.ipc().importance_inherit_from_kmsg(kmsg);
        let sent = kmsg.voucher;
        if sent.is_none() && inherit.is_none() {
            return;
        }
        let mut recipes = Vec::new();
        if let Some(port) = sent {
            let Some(super::ipc::Kobject::Voucher(v)) = self.ipc().port(port).kobject else { unreachable!("a voucher port") };
            recipes.push(Recipe { key: key::ALL, command: cmd::COPY, previous: Some(v), content: Vec::new() });
        }
        // The inherit's made reference goes to the voucher.
        recipes.push(Recipe { key: key::IMPORTANCE, command: cmd::SET_VALUE_HANDLE, previous: None, content: inherit.unwrap_or(0).to_le_bytes().to_vec() });
        let nv = self.ipc_create_mach_voucher(Some(key::IMPORTANCE), &recipes).expect("the importance voucher").expect("a voucher");
        kmsg.bits |= super::ipc::right::msgt::MOVE_SEND << 16;
        if let Some(port) = sent {
            self.ipc().release_send(port);
        }
        kmsg.voucher = Some(self.convert_voucher_to_port(nv));
    }
}

/// `sizeof(struct proc_persona_info)`.
const PROC_PERSONA_INFO_SIZE: u32 = 48;

// -- the tables as bytes ([`super::ipc::wire`]) -------------------------------------------

use super::ipc::wire::{sorted, Bad, Get, OwnTask, Put};

fn put_u64s(p: &mut Put, v: &[u64]) {
    p.len(v.len());
    for &x in v {
        p.u64(x);
    }
}

fn get_u64s(g: &mut Get<'_>) -> Result<Vec<u64>, Bad> {
    let n = g.len()?;
    (0..n).map(|_| g.u64()).collect()
}

fn put_key_table(p: &mut Put, t: &[u32; KEY_NUM]) {
    for &w in t {
        p.u32(w);
    }
}

fn get_key_table(g: &mut Get<'_>) -> Result<[u32; KEY_NUM], Bad> {
    let mut t = [0u32; KEY_NUM];
    for w in t.iter_mut() {
        *w = g.u32()?;
    }
    Ok(t)
}

impl VoucherTables {
    /// The tables as bytes: a bank context's ledger as its task's key.
    pub fn put(&self, p: &mut Put) {
        p.len(self.ivac.len());
        for c in &self.ivac {
            p.opt(c.as_ref(), |p, c: &Ivac| {
                p.len(c.table.len());
                for e in &c.table {
                    p.u64(e.value);
                    p.u32(e.refs);
                    p.u32(e.made);
                    p.bool(e.persist);
                    p.bool(e.free);
                    p.bool(e.releasing);
                    p.u32(e.index);
                    p.u32(e.next);
                }
                p.u32(c.init_size);
                p.u32(c.freelist);
            });
        }
        p.len(self.vouchers.len());
        for (&id, v) in sorted(&self.vouchers) {
            p.u64(id);
            put_key_table(p, &v.table);
            p.u32(v.refs);
            p.opt(v.port, Put::u64);
        }
        p.len(self.by_table.len());
        for (t, &id) in sorted(&self.by_table) {
            put_key_table(p, t);
            p.u64(id);
        }
        p.u64(self.next);
        p.len(self.bank.len());
        for (&h, e) in sorted(&self.bank) {
            p.u64(h);
            match e {
                BankElem::Task(t) => {
                    p.u8(0);
                    for w in [t.refs, t.made, t.voucher_ref] {
                        p.u32(w);
                    }
                    let i = &t.info;
                    p.u64(i.unique_pid);
                    p.i32(i.pid);
                    for w in [i.flags, i.pidversion, i.persona_id, i.uid, i.gid] {
                        p.u32(w);
                    }
                    p.bytes(&i.macho_uuid);
                    p.u32(t.persona_uid);
                    p.bool(t.hasentitlement);
                    p.u64(t.thread_group);
                    put_u64s(p, &t.to_pay);
                    put_u64s(p, &t.to_charge);
                    // The ledger as its task's key: a cell's is its owner's.
                    p.opt(t.ledger.as_ref(), |p, l: &LedgerAt| {
                        p.u64(match l {
                            LedgerAt::Cell(_) => t.owner,
                            LedgerAt::Elsewhere(k) => *k,
                        })
                    });
                    p.u64(t.owner);
                }
                BankElem::Account(a) => {
                    p.u8(1);
                    p.u32(a.refs);
                    p.u32(a.made);
                    for w in [a.merchant, a.holder, a.secureoriginator, a.proximateprocess, a.thread_group] {
                        p.u64(w);
                    }
                    p.u32(a.so_persona.id);
                    p.u32(a.so_persona.uid);
                    p.u64(a.bill);
                    p.bool(a.bill_unkept);
                    p.len(a.adopters.len());
                    for &t in &a.adopters {
                        p.i32(t);
                    }
                }
            }
        }
        self.imp.put(p);
        p.u64(self.next_handle);
    }

    /// The tables [`VoucherTables::put`] made: `own`'s task's bank context
    /// has its ledger's cell, every other task's its key.
    pub fn get(g: &mut Get<'_>, own: &OwnTask) -> Result<VoucherTables, Bad> {
        let n = g.len()?;
        let ivac = (0..n)
            .map(|_| {
                g.opt(|g| {
                    let m = g.len()?;
                    let table = (0..m).map(|_| Ok(Ivace { value: g.u64()?, refs: g.u32()?, made: g.u32()?, persist: g.bool()?, free: g.bool()?, releasing: g.bool()?, index: g.u32()?, next: g.u32()? })).collect::<Result<_, Bad>>()?;
                    Ok(Ivac { table, init_size: g.u32()?, freelist: g.u32()? })
                })
            })
            .collect::<Result<_, Bad>>()?;
        let n = g.len()?;
        let vouchers = (0..n).map(|_| Ok((g.u64()?, Voucher { table: get_key_table(g)?, refs: g.u32()?, port: g.opt(Get::u64)? }))).collect::<Result<_, Bad>>()?;
        let n = g.len()?;
        let by_table = (0..n).map(|_| Ok((get_key_table(g)?, g.u64()?))).collect::<Result<_, Bad>>()?;
        let next = g.u64()?;
        let n = g.len()?;
        let mut bank = HashMap::new();
        for _ in 0..n {
            let h = g.u64()?;
            let e = match g.u8()? {
                0 => {
                    let (refs, made, voucher_ref) = (g.u32()?, g.u32()?, g.u32()?);
                    let (unique_pid, pid) = (g.u64()?, g.i32()?);
                    let (flags, pidversion, persona_id, uid, gid) = (g.u32()?, g.u32()?, g.u32()?, g.u32()?, g.u32()?);
                    let uuid = g.bytes()?;
                    let macho_uuid: [u8; 16] = uuid.as_slice().try_into().map_err(|_| g.bad("a 16-byte UUID"))?;
                    let info = ProcPersonaInfo { unique_pid, pid, flags, pidversion, persona_id, uid, gid, macho_uuid };
                    let (persona_uid, hasentitlement, thread_group) = (g.u32()?, g.bool()?, g.u64()?);
                    let (to_pay, to_charge) = (get_u64s(g)?, get_u64s(g)?);
                    let ledger = g.opt(Get::u64)?.map(|k| match &own.ledger {
                        Some(l) if k == own.task => LedgerAt::Cell(std::sync::Arc::clone(l)),
                        _ => LedgerAt::Elsewhere(k),
                    });
                    BankElem::Task(BankTask { refs, made, voucher_ref, info, persona_uid, hasentitlement, thread_group, to_pay, to_charge, ledger, owner: g.u64()? })
                }
                1 => {
                    let (refs, made) = (g.u32()?, g.u32()?);
                    let (merchant, holder, secureoriginator, proximateprocess, thread_group) = (g.u64()?, g.u64()?, g.u64()?, g.u64()?, g.u64()?);
                    let so_persona = BankPersona { id: g.u32()?, uid: g.u32()? };
                    let (bill, bill_unkept) = (g.u64()?, g.bool()?);
                    let m = g.len()?;
                    let adopters = (0..m).map(|_| g.i32()).collect::<Result<_, Bad>>()?;
                    BankElem::Account(BankAccount { refs, made, merchant, holder, secureoriginator, proximateprocess, thread_group, so_persona, bill, bill_unkept, adopters })
                }
                _ => return Err(g.bad("a bank element's kind")),
            };
            bank.insert(h, e);
        }
        let imp = super::importance::ImpState::get(g, own)?;
        Ok(VoucherTables { ivac, vouchers, by_table, next, bank, imp, next_handle: g.u64()? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn tables(ledger: &Arc<super::super::rusage::BankLedger>) -> VoucherTables {
        let mut t = VoucherTables::default();
        t.ivac = vec![None, Some(Ivac { table: vec![Ivace::reset(1), Ivace { value: 9, refs: 2, made: 1, persist: true, free: false, releasing: false, index: 0, next: 0 }], init_size: 2, freelist: 0 })];
        t.vouchers.insert(3, Voucher { table: [1; KEY_NUM], refs: 1, port: Some(44) });
        t.by_table.insert([1; KEY_NUM], 3);
        t.next = 3;
        let info = ProcPersonaInfo { unique_pid: 77, pid: 105, flags: 1, pidversion: 2, persona_id: 501, uid: 501, gid: 20, macho_uuid: [7; 16] };
        t.bank.insert(0x1040, BankElem::Task(BankTask { refs: 1, made: 1, voucher_ref: 0, info, persona_uid: 501, hasentitlement: true, thread_group: 9, to_pay: vec![0x1080], to_charge: vec![], ledger: Some(LedgerAt::Cell(Arc::clone(ledger))), owner: 5 }));
        t.bank.insert(0x1080, BankElem::Account(BankAccount { refs: 1, made: 1, merchant: 0x1040, holder: 0x1040, secureoriginator: 0x1040, proximateprocess: 0x1040, thread_group: 9, so_persona: BankPersona { id: 501, uid: 501 }, bill: 1234, bill_unkept: true, adopters: vec![8, 9] }));
        t.next_handle = 0x1080;
        t
    }

    fn bytes(t: &VoucherTables) -> Vec<u8> {
        let mut p = Put::default();
        t.put(&mut p);
        p.0
    }

    #[test]
    fn a_bank_context_is_its_own_processs_ledger_and_a_key_elsewhere() {
        let ledger = Arc::new(super::super::rusage::BankLedger::default());
        let b = bytes(&tables(&ledger));
        let own = OwnTask { task: 5, policy: None, ledger: Some(Arc::clone(&ledger)), link: None };
        let mut g = Get::new(&b);
        let mine = VoucherTables::get(&mut g, &own).expect("it decodes");
        assert!(g.done());
        assert!(matches!(mine.bank.get(&0x1040), Some(BankElem::Task(BankTask { ledger: Some(LedgerAt::Cell(l)), .. })) if Arc::ptr_eq(l, &ledger)));
        assert_eq!(bytes(&mine), b);
        let other = OwnTask { task: 6, policy: None, ledger: Some(Arc::new(super::super::rusage::BankLedger::default())), link: None };
        let theirs = VoucherTables::get(&mut Get::new(&b), &other).expect("it decodes");
        assert!(matches!(theirs.bank.get(&0x1040), Some(BankElem::Task(BankTask { ledger: Some(LedgerAt::Elsewhere(5)), .. }))));
        assert_eq!(bytes(&theirs), b);
        for cut in [0, b.len() / 2, b.len() - 1] {
            assert!(VoucherTables::get(&mut Get::new(&b[..cut]), &other).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn ledgers_are_the_same_by_cell_or_by_key() {
        let l = Arc::new(super::super::rusage::BankLedger::default());
        assert!(LedgerAt::Cell(Arc::clone(&l)).same(&LedgerAt::Cell(Arc::clone(&l))));
        assert!(!LedgerAt::Cell(Arc::clone(&l)).same(&LedgerAt::Cell(Arc::new(super::super::rusage::BankLedger::default()))));
        assert!(LedgerAt::Elsewhere(4).same(&LedgerAt::Elsewhere(4)));
        assert!(!LedgerAt::Elsewhere(4).same(&LedgerAt::Elsewhere(5)));
        assert!(!LedgerAt::Elsewhere(4).same(&LedgerAt::Cell(l)));
    }
}
