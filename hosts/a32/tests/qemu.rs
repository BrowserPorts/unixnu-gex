//! End-to-end runs of ARMv7-A programs (`tests/programs/*.s`): each is
//! assembled with the host's clang, linked at address 0 with ld.lld, and
//! run twice to its semihosting SYS_EXIT: through gex (lifted, compiled by
//! the tier-1 emitter, run on wasmtime against the gex-a32 model) and on
//! QEMU's Cortex-A15 (`qemu-system-arm -M virt`, no Security or
//! Virtualization Extensions), the reference. The registers and the CPSR
//! at the exit must agree; each program folds every result it records into
//! R11, with their count in R10.
//!
//! The memory map is QEMU's virt board's as the programs use it: the image
//! at PA 0 (read-only, the flash) and RAM at PA 0x40000000.

use gex_a32::{Config, Core, ImpDef};
use gex_a32_host::{Exit, Machine, Region, HOST_BASE};
use gex_isa_a32::Features;
use std::path::{Path, PathBuf};
use std::process::Command;

const PROGRAMS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/programs");
const LLVM_OBJCOPY: &str = "/opt/homebrew/opt/llvm/bin/llvm-objcopy";

fn work() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("a32-programs");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(out.status.success(), "{cmd:?}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// Assemble and link `name`, giving the image's bytes.
fn build(name: &str) -> (PathBuf, Vec<u8>) {
    let w = work();
    let src = Path::new(PROGRAMS).join(format!("{name}.s"));
    let obj = w.join(format!("{name}.o"));
    let elf = w.join(format!("{name}.elf"));
    let bin = w.join(format!("{name}.bin"));
    run(Command::new("clang").args(["-target", "armv7a-none-eabi", "-mcpu=cortex-a15", "-I", PROGRAMS, "-c"]).arg(&src).arg("-o").arg(&obj));
    run(Command::new("ld.lld").args(["-Ttext=0", "--image-base=0", "--entry=_start", "-o"]).arg(&elf).arg(&obj));
    run(Command::new(LLVM_OBJCOPY).args(["-O", "binary", "--only-section=.text"]).arg(&elf).arg(&bin));
    let bytes = std::fs::read(&bin).unwrap();
    (bin, bytes)
}

/// The state at the exit: R0-R15 (R15 the SYS_EXIT call's address) and
/// the CPSR.
#[derive(Debug, PartialEq, Eq)]
struct Final {
    r: [u32; 16],
    cpsr: u32,
}

/// QEMU's state at its last semihosting call, from its `-d cpu` log with
/// one instruction per translation block.
fn qemu(name: &str, bin: &Path) -> Final {
    let log = work().join(format!("{name}.qemu.log"));
    let _ = std::fs::remove_file(&log);
    run(Command::new("qemu-system-arm")
        .args(["-M", "virt", "-cpu", "cortex-a15", "-nographic", "-semihosting", "-monitor", "none", "-serial", "none"])
        .args(["-accel", "tcg,one-insn-per-tb=on", "-d", "cpu,nochain,int", "-D"])
        .arg(&log)
        .arg("-bios")
        .arg(bin));
    let text = std::fs::read_to_string(&log).unwrap();
    let call = text.rfind("Taking exception 16 [Semihosting call]").expect("QEMU made no semihosting call");
    let start = text[..call].rfind("R00=").expect("no register dump before the call");
    let dump = &text[start..call];
    let mut r = [0u32; 16];
    for (i, reg) in r.iter_mut().enumerate() {
        let k = format!("R{i:02}=");
        let at = dump.find(&k).unwrap() + k.len();
        *reg = u32::from_str_radix(&dump[at..at + 8], 16).unwrap();
    }
    let at = dump.find("PSR=").unwrap() + 4;
    let cpsr = u32::from_str_radix(&dump[at..at + 8], 16).unwrap();
    Final { r, cpsr }
}

/// A Cortex-A15 as QEMU's virt board has it by default: the Security and
/// Virtualization Extensions off. The ID register values are QEMU's
/// `cortex-a15`'s.
fn a15() -> Config {
    let mut features = Features::ALL;
    features.security = false;
    features.virtualization = false;
    const MIDR: u32 = 0x412f_c0f1;
    // SCTLR's IMPLEMENTATION DEFINED bits: I, C, CP15BEN and Z read/write.
    const SCTLR_RW: u32 = 1 << 12 | 1 << 2 | 1 << 5 | 1 << 11;
    let imp = ImpDef {
        midr: Some(MIDR),
        ctr: Some(0x8444_c004),
        tcmtr: Some(0),
        tlbtr: Some(0),
        mpidr: Some(0x8000_0000),
        revidr: Some(MIDR),
        id_pfr: [Some(0x0000_1131), Some(0x0001_0001)],
        id_dfr0: Some(0x0201_0555),
        id_afr0: Some(0),
        id_mmfr: [Some(0x1020_1105), Some(0x2000_0000), Some(0x0124_0000), Some(0x0210_2211)],
        id_isar: [Some(0x0210_1110), Some(0x1311_2111), Some(0x2123_2041), Some(0x1111_2131), Some(0x1001_1142), Some(0)],
        clidr: Some(0x0a20_0023),
        aidr: Some(0),
        ccsidr: vec![(0, 0x701f_e00a), (1, 0x201f_e00a), (2, 0x711f_e07a)],
        actlr: Some((0, 0x0000_0041)),
        undef_cond_failed_traps: Some(false),
        reset_hivecs: Some(false),
        reset_te: Some(false),
        reset_ee: Some(false),
        reset_nmfi: Some(false),
        sctlr: Some((SCTLR_RW, 0)),
        reset_vector: Some(None),
        psr_j_raz_wi: Some(true),
        tre0_remap: Some(false),
        cpacr_asedis: Some(true),
        cpacr_d32dis: Some(true),
        joscr_rw: Some(false),
        fpsid: Some(0x4104_30f0),
        mvfr0: Some(0x1011_0222),
        mvfr1: Some(0x1111_1111),
        dbgdidr: Some(0x3515_f005),
        dbgdrar: Some(0),
        dbgdsar: Some(0),
        icimvau_translates: Some(false),
        bpimva_translates: Some(false),
        maint_access_flag_faults: Some(false),
        icmaint_fault_code: Some(false),
        par_bit8: Some(false),
        par_nc_shareability: Some(true),
        c15_allocated: Some(true),
        imp_regs: Vec::new(),
    };
    Config { features, imp }
}

fn gex(image: &[u8]) -> Final {
    let core = Core::new(a15()).expect("the Cortex-A15 configuration");
    let regions = vec![
        Region { pa: 0, size: 0x10_0000, host: HOST_BASE, writable: false },
        Region { pa: 0x4000_0000, size: 0x100_0000, host: HOST_BASE + 0x100_0000, writable: true },
    ];
    let mut m = Machine::new(core, regions).unwrap();
    m.load(0, image).unwrap();
    m.reset().unwrap();
    m.semihosting(true);
    let exit = m.run(1_000_000).unwrap();
    let Exit::Semihosting { code, pc } = exit else { panic!("the run ended with {exit:?}") };
    assert_eq!(code, 0x20026, "SYS_EXIT's reason");
    // The recorded results, for finding the first that differs.
    let n = gex_a32::Regs::r(m.regs(), 10) as usize;
    if let Ok(out) = m.read(0x4000_0000, 4 * n) {
        std::fs::write(work().join("last.gex.out"), out).unwrap();
    }
    m.with_core(|core, regs, _| {
        let mut r = [0u32; 16];
        for (i, reg) in r.iter_mut().enumerate().take(15) {
            *reg = gex_a32::Regs::r(regs, i as u8);
        }
        r[15] = gex_abi::a32::key_addr(pc);
        Final { r, cpsr: core.cpsr(regs) }
    })
}

fn same(name: &str) {
    let (bin, image) = build(name);
    let want = qemu(name, &bin);
    let got = gex(&image);
    assert_eq!(got, want, "{name}: gex (left) and QEMU (right) disagree");
}

#[test]
fn arm_data_processing_and_media() {
    same("a32_alu");
}

#[test]
fn thumb_it_blocks_and_interworking() {
    same("thumb");
}

#[test]
fn loads_stores_and_exclusives() {
    same("memory");
}

#[test]
fn modes_and_exceptions() {
    same("exceptions");
}

#[test]
fn short_descriptor_translation() {
    same("mmu");
}

#[test]
fn fp_registers_and_system_registers() {
    same("fpregs");
}

#[test]
fn vfp_arithmetic() {
    same("vfp");
}
