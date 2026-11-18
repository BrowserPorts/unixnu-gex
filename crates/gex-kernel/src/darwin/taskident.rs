//! Task identity tokens (xnu-10063.141.1 `osfmk/kern/task_ident.c`):
//! IKOT_TASK_ID_TOKEN kernel objects naming a task without holding it, a
//! live one by its process's identity (`proc_ident`: pid, uniqueid,
//! pidversion), a corpse by its `task_uniqueid`. An EXCEPTION_IDENTITY_PROTECTED
//! handler gets one in `mach_exception_raise_identity_protected`, and
//! `task_identity_token_get_task_port` turns one back into a task port of a
//! flavor, as the conversion checks and the policies allow.
//!
//! Here a token's port is its task's kernel's object, served there, as
//! that kernel holds the task's ports; once the task ends its tokens' ports
//! are the system's ([`orphan`]), and a token finds no task.

use crate::syscalls::Kernel;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// `KERN_*` codes.
const KERN_INVALID_ARGUMENT: i32 = 4;
const KERN_DENIED: i32 = 53;
const KERN_NOT_FOUND: i32 = 56;

/// `TASK_FLAVOR_MAX`.
const TASK_FLAVOR_MAX: u32 = 3;

/// A token (`struct task_id_token`): the process identity it names (pid,
/// uniqueid, pidversion), or a corpse's `task_uniqueid`; its port once made.
#[derive(Clone, Copy, Debug)]
struct Token {
    ident: Option<(i32, u64, i32)>,
    task_uniqueid: u64,
    port: Option<super::ipc::ObjId>,
}

fn tokens() -> std::sync::MutexGuard<'static, HashMap<u64, Token>> {
    static T: std::sync::OnceLock<Mutex<HashMap<u64, Token>>> = std::sync::OnceLock::new();
    T.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

static NEXT: AtomicU64 = AtomicU64::new(1);

impl Kernel {
    /// `task_create_identity_token` of this task, and
    /// `convert_task_id_token_to_port` of it: a send right to the token's
    /// port, its no-senders notification armed (the token's one reference
    /// donated to it). A corpse's names its `task_uniqueid`; a live task
    /// with a process its process's identity; any other is refused.
    pub(crate) fn darwin_create_identity_token(&mut self) -> Result<super::ipc::ObjId, i32> {
        let token = if let Some(c) = self.dtask.corpse.as_ref() {
            Token { ident: None, task_uniqueid: c.task_uniqueid, port: None }
        } else if self.darwin_public(self.pid).is_some_and(|(_, zombie)| !zombie) {
            Token { ident: Some((self.pid, self.dtask.uniqueid, self.dtask.pidversion)), task_uniqueid: 0, port: None }
        } else {
            return Err(KERN_INVALID_ARGUMENT);
        };
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let ipc = self.ipc();
        let port = ipc.kobject_port(super::ipc::Kobject::TaskIdToken(id));
        ipc.make_send(port);
        ipc.port_mut(port).nsrequest_kobject = true;
        tokens().insert(id, Token { port: Some(port), ..token });
        Ok(port)
    }

    /// `task_identity_token_get_task_port(token, flavor)`, served in the
    /// kernel of the task the token names (or, once that task has ended,
    /// the caller's): a send right to that task's port of `flavor`.
    pub(crate) fn darwin_token_get_task_port(&mut self, id: u64, flavor: u32) -> super::kobject::Reply {
        use super::ipc::right::Carried;
        use super::kobject::{flavor as fl, Reply};
        let Some(token) = tokens().get(&id).copied() else { return Reply::err(KERN_INVALID_ARGUMENT) };
        if flavor > TASK_FLAVOR_MAX {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        // A corpse's control port holds the corpse: only that flavor.
        let corpse = token.task_uniqueid != 0;
        if corpse && flavor != u32::from(fl::CONTROL) {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        // task_identity_token_get_task_grp: find_corpse_task_by_uniqueid
        // or proc_find_ident; the token's task is this kernel's, if any.
        let key = self.ipc().task;
        let here = token.port.is_some_and(|p| self.ipc().port(p).owner == key && key != 0);
        let found = here
            && match token.ident {
                None => self.dtask.corpse.is_some() && super::corpse::find(key).is_some_and(|r| r.task_uniqueid == token.task_uniqueid),
                Some((pid, uniqueid, version)) => self.dtask.corpse.is_none() && pid == self.pid && uniqueid == self.dtask.uniqueid && version == self.dtask.pidversion && self.darwin_public(pid).is_some_and(|(_, zombie)| !zombie),
            };
        if !found {
            return Reply::err(KERN_NOT_FOUND);
        }
        let current = self.dtask.kcaller == 0 || self.dtask.kcaller == key;
        // convert_task_to_port_pinned: the caller's own control port is
        // its pinned self port.
        if flavor == u32::from(fl::CONTROL) && current {
            let p = self.darwin_task_self_port();
            self.ipc().make_send(p);
            return Reply::port(Carried::Port(p));
        }
        if flavor <= u32::from(fl::READ) && !self.darwin_conversion_eval(flavor as u8) {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        if !current {
            // mac_task_check_task_id_token_get_task: AMFI's hook (Sandbox
            // has none) with the caller's credential, no identity for a
            // corpse.
            let caller = self.dtask.kcaller;
            let ents = self.ipc().links.get(&caller).and_then(|l| l.codesign.as_ref()).map(|c| c.ents.clone()).unwrap_or_default();
            if super::amfi::task_id_token_get_task(&ents, corpse, flavor).is_err() {
                return Reply::err(KERN_DENIED);
            }
        }
        // convert_task_to_port_with_flavor.
        let p = match flavor as u8 {
            fl::CONTROL => {
                let p = self.darwin_task_port();
                self.ipc().make_send(p);
                p
            }
            fl::READ | fl::INSPECT => self.darwin_task_flavor_port(flavor as u8),
            _ => {
                let ipc = self.ipc();
                let me = ipc.task;
                let Some(p) = ipc.task_name_port(me) else { return Reply::err(KERN_NOT_FOUND) };
                ipc.make_send(p);
                p
            }
        };
        Reply::port(Carried::Port(p))
    }

    /// `task_conversion_eval(current_task(), this task, flavor)` for the
    /// control or read flavor: without Developer Mode a foreign task's
    /// control port only for a corpse; a platform binary's task only for a
    /// platform binary.
    pub(crate) fn darwin_conversion_eval(&mut self, flavor: u8) -> bool {
        let caller = self.dtask.kcaller;
        let key = self.ipc().task;
        if caller == 0 || caller == key {
            return true;
        }
        if !super::kobject::DEVELOPER_MODE && flavor == super::kobject::flavor::CONTROL && self.dtask.corpse.is_none() {
            return false;
        }
        self.darwin_read_conversion_ok()
    }

    /// `task_id_token_no_senders`: the token's last reference goes, and its
    /// port with it.
    pub(crate) fn darwin_task_id_token_no_senders(&mut self, port: super::ipc::ObjId, id: u64) {
        tokens().remove(&id);
        let ipc = self.ipc();
        ipc.port_mut(port).kobject = None;
        ipc.port_destroy(port);
        self.darwin_ipc_notify_drain();
    }

    /// This task has ended: its tokens' ports become the system's, so that
    /// a token of it, asked for its task, finds none.
    pub(crate) fn darwin_task_id_tokens_orphan(&mut self) {
        let key = self.ipc().task;
        let ports: Vec<super::ipc::ObjId> = tokens().values().filter_map(|t| t.port).collect();
        let ipc = self.ipc();
        for p in ports {
            if ipc.port(p).active && ipc.port(p).owner == key {
                ipc.port_mut(p).owner = 0;
            }
        }
    }
}
