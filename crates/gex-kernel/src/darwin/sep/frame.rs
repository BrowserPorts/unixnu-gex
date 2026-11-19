//! The mailbox message and the endpoint numbers and opcodes AppleSEPManager
//! uses (`drafts/sep/02-transport.md` and `03-boot-handshake.md`, read from
//! the kernelcache's AppleSEPManager).
//!
//! A message is one 64-bit little-endian word: byte 0 the endpoint, byte 1
//! the tag, byte 2 the opcode, byte 3 the parameter (a reply's status on the
//! control endpoint), bytes 4 to 7 a 32-bit datum. `_sendMessageGated`
//! (K 0xfffffff0063d1500) rebuilds the low 32 bits from the fields and
//! passes the high 32 through; `_doorbellAction` (K 0xfffffff0063cf9f8)
//! reads the endpoint from byte 0 and the opcode from byte 2.

/// One mailbox message.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message(pub u64);

impl Message {
    pub const fn new(endpoint: u8, tag: u8, opcode: u8, param: u8, data: u32) -> Message {
        Message((endpoint as u64) | (tag as u64) << 8 | (opcode as u64) << 16 | (param as u64) << 24 | (data as u64) << 32)
    }

    pub const fn endpoint(self) -> u8 {
        self.0 as u8
    }

    pub const fn tag(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub const fn opcode(self) -> u8 {
        (self.0 >> 16) as u8
    }

    pub const fn param(self) -> u8 {
        (self.0 >> 24) as u8
    }

    pub const fn data(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn with_endpoint(self, endpoint: u8) -> Message {
        Message(self.0 & !0xff | endpoint as u64)
    }

    pub const fn with_tag(self, tag: u8) -> Message {
        Message(self.0 & !0xff00 | (tag as u64) << 8)
    }
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Message({:#018x}: ep {:#x} tag {} op {:#x} param {:#x} data {:#x})", self.0, self.endpoint(), self.tag(), self.opcode(), self.param(), self.data())
    }
}

/// The endpoints with a fixed number. 1 to 0x1f are the sepOS's to
/// advertise (Discovery) and any other is invalid.
pub mod ep {
    /// `EP_CONTROL`, registered with the 4CC `cntl`.
    pub const CONTROL: u8 = 0;
    /// `_max_endpoints`: dynamic endpoints are below it.
    pub const MAX: u8 = 0x20;
    /// `EP_DISCOVERY`, and `EP_LOWEST_FIXED`.
    pub const DISCOVERY: u8 = 0xfd;
    /// `EP_L4INFO`.
    pub const L4INFO: u8 = 0xfe;
    /// `EP_BOOTSTRAP`: the SEP ROM.
    pub const BOOTSTRAP: u8 = 0xff;
}

/// Control endpoint (EP0) opcodes: the AP's requests, with their layouts in
/// 02-transport.md section 4.2, and the sepOS's unsolicited messages
/// (tag 0), section 4.1.
pub mod control {
    pub const PING: u8 = 0x00;
    pub const SET_OOL_IN_ADDRESS: u8 = 0x02;
    pub const SET_OOL_OUT_ADDRESS: u8 = 0x03;
    pub const SET_OOL_IN_SIZE: u8 = 0x04;
    pub const SET_OOL_OUT_SIZE: u8 = 0x05;
    pub const SLEEP: u8 = 0x0c;
    /// The AP's raw wake message (`0x0e0000`), which has no tag and no reply.
    pub const WAKE: u8 = 0x0e;
    pub const NAP: u8 = 0x12;
    pub const NAP_REQUEST: u8 = 0x13;
    pub const STATUS: u8 = 0x14;
    /// SEP to AP: the sepOS is alive (a thread call), and the same
    /// synchronously.
    pub const OS_ACTIVE_ASYNC: u8 = 0x0d;
    pub const OS_ACTIVE: u8 = 0x15;
    /// SEP to AP: "wake acknowledged"; the doorbell's fast path takes it
    /// with `OS_ACTIVE`.
    pub const WAKE_ACK: u8 = 0x0f;
    pub const SEP_INFO: u8 = 0x29;
}

/// Discovery (endpoint 0xfd) opcodes, SEP to AP.
pub mod discovery {
    pub const ADVERTISE_ENDPOINT: u8 = 0;
    pub const ADVERTISE_OOLS: u8 = 1;
}

/// The SEP ROM's protocol on `ep::BOOTSTRAP` (03-boot-handshake.md section 3).
pub mod rom {
    // AP to SEPROM.
    pub const STATUS: u8 = 0x02;
    pub const GENERATE_NONCE: u8 = 0x03;
    pub const NONCE_WORD: u8 = 0x04;
    pub const BOOT_TZ0: u8 = 0x05;
    pub const BOOT: u8 = 0x06;
    pub const LOAD_SEPART: u8 = 0x07;
    pub const RESUME: u8 = 0x08;
    pub const IBIC_KEY_REQUEST: u8 = 0x1e;
    pub const IBIC_KEY_WORD: u8 = 0x1f;
    pub const BOOT_TMM_MANIFEST: u8 = 0x24;
    pub const BOOT_PATCH: u8 = 0x25;
    // SEPROM to AP.
    pub const PING_RESPONSE: u8 = 0x65;
    pub const STATUS_REPLY: u8 = 0x66;
    pub const NONCE_GENERATED: u8 = 0x67;
    pub const NONCE_WORD_REPLY: u8 = 0x68;
    pub const TZ0_ACCEPTED: u8 = 0x69;
    pub const IMG4_ACCEPTED: u8 = 0x6a;
    pub const SEPART_ACCEPTED: u8 = 0x6b;
    pub const RESUMED: u8 = 0x6c;
    pub const IBIC_KEY: u8 = 0x82;
    pub const IBIC_KEY_WORD_REPLY: u8 = 0x83;
    pub const TMM_ACCEPTED: u8 = 0x88;
    pub const PATCHES_ACCEPTED: u8 = 0x89;
    /// A rejected request: opcode 0 or 0xc7, whose datum is the request's opcode.
    pub const REJECTED: u8 = 0xc7;
    pub const REJECTED_ALT: u8 = 0x00;
    pub const STATUS_UNSOLICITED: u8 = 0xd2;
    pub const LOG_WORD: u8 = 0xc9;
    pub const LOG_CHARS: u8 = 0xca;
    pub const PANIC: u8 = 0xff;

    /// The payload types a Boot, BootTz0 and BootPatch message carries in
    /// its parameter: `AppleSEPFirmwarePayloadType`.
    pub const PAYLOAD_SEPI: u8 = 0;
    pub const PAYLOAD_RSEP: u8 = 1;

    /// `BootStatus` values the booter's code compares or stores.
    pub mod status {
        pub const INITIAL: u16 = 0;
        /// The ROM's own answers to a status request before and after
        /// BootTz0 (the code requires exactly 1, then exactly 2).
        pub const BEFORE_TZ0: u16 = 1;
        pub const AFTER_TZ0: u16 = 2;
        pub const RESUMED: u16 = 3;
        pub const TZ0_ACCEPTED: u16 = 100;
        pub const IMG4_ACCEPTED: u16 = 101;
        pub const SEPART_ACCEPTED: u16 = 200;
        pub const TIMED_OUT: u16 = 201;
        pub const PANICKED: u16 = 202;
    }
}

/// An endpoint's four-character name as the sepOS advertises it (a 32-bit
/// number, the first character most significant) and the registry name the
/// manager publishes it under, "sep-endpoint," and the characters with
/// trailing spaces trimmed (`getPropertyForEpName`, K 0xfffffff0063b6040).
pub fn endpoint_name(name: u32) -> String {
    let bytes = name.to_be_bytes();
    let text: String = bytes.iter().map(|&b| b as char).collect();
    format!("sep-endpoint,{}", text.trim_end_matches(' '))
}

/// The number of a four-character name.
pub const fn fourcc(s: &[u8; 4]) -> u32 {
    (s[0] as u32) << 24 | (s[1] as u32) << 16 | (s[2] as u32) << 8 | s[3] as u32
}

/// The endpoint names the manager's kext has personalities for.
pub mod name {
    use super::fourcc;
    pub const CONTROL: u32 = fourcc(b"cntl");
    pub const ART_STORAGE: u32 = fourcc(b"arts");
    pub const ART_REQUESTS: u32 = fourcc(b"artr");
    pub const XART_SLAVE: u32 = fourcc(b"xars");
    pub const XART_MASTER: u32 = fourcc(b"xarm");
    pub const HILO: u32 = fourcc(b"hilo");
    pub const DEBUG: u32 = fourcc(b"debu");
    pub const PAIRING: u32 = fourcc(b"pair");
    pub const TESTING: u32 = fourcc(b"unit");
    pub const LOGGER: u32 = fourcc(b"log ");
    pub const KEYSTORE: u32 = fourcc(b"sks ");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_at_the_bytes_the_manager_reads() {
        let m = Message::new(0xff, 1, 0x06, 0, 0x1234);
        assert_eq!(m.0.to_le_bytes(), [0xff, 1, 6, 0, 0x34, 0x12, 0, 0]);
        assert_eq!((m.endpoint(), m.tag(), m.opcode(), m.param(), m.data()), (0xff, 1, 6, 0, 0x1234));
    }

    #[test]
    fn the_booters_words_are_the_ones_in_the_code() {
        // `bootSEP` builds `0x20100` for the status request, `0x50100 | type << 24` for BootTz0
        // (K 0xfffffff0063c7998, 0xfffffff0063c79f4) before `_sendMessageGated` writes the endpoint.
        assert_eq!(Message::new(0, 1, rom::STATUS, 0, 0).0, 0x0002_0100);
        assert_eq!(Message::new(0, 1, rom::BOOT_TZ0, rom::PAYLOAD_RSEP, 0).0, 0x0105_0100);
        assert_eq!(Message::new(0, 1, rom::BOOT, 0, 0x0123_4).0, 0x0000_1234_0006_0100);
    }

    #[test]
    fn the_endpoint_byte_is_replaced_and_the_rest_kept() {
        let m = Message::new(0, 3, 0x12, 4, 0xdead_beef).with_endpoint(0xfe);
        assert_eq!((m.endpoint(), m.tag(), m.opcode(), m.param(), m.data()), (0xfe, 3, 0x12, 4, 0xdead_beef));
        assert_eq!(m.with_tag(9).tag(), 9);
        assert_eq!(m.with_tag(9).endpoint(), 0xfe);
    }

    #[test]
    fn endpoint_names_publish_as_the_manager_does() {
        assert_eq!(endpoint_name(name::LOGGER), "sep-endpoint,log");
        assert_eq!(endpoint_name(name::XART_SLAVE), "sep-endpoint,xars");
        assert_eq!(endpoint_name(name::KEYSTORE), "sep-endpoint,sks");
        // The numeric values the kext builds with mov/movk.
        assert_eq!(name::CONTROL, 0x636e746c);
        assert_eq!(name::ART_STORAGE, 0x61727473);
        assert_eq!(name::XART_MASTER, 0x7861726d);
        assert_eq!(name::LOGGER, 0x6c6f6720);
    }
}
