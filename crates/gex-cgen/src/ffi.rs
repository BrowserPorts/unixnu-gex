//! libffi's call thunks (gexcc-win's libffi, `gex.ffi_thunk`): a call
//! through a native function value whose wasm type is known only at run
//! time. `call_indirect` needs the type in the caller's module, so the host
//! makes one small module per signature: its one function, of type
//! `(fn: i64, av: i64, rv: i64) -> ()`, loads each argument through the
//! pointer array `av` (as libffi's `avalue`), calls `fn` through the
//! process's table with the signature's type, and stores the result at `rv`
//! in its own width. Its element segment puts it at `__table_base`, so the
//! install's slot is the function value the C side calls.
//!
//! A signature is its parameters' and result's wasm types, one letter each:
//! `i` i32, `I` i64, `f` f32, `d` f64, then `:` and the result (`v` none).
//! `IdI:i` is `(i64, f64, i64) -> i32`.

use crate::runtime::{ftab_type, memory_type, table_base_type};
use wasm_encoder::{
    CodeSection, ConstExpr, ElementSection, Elements, EntityType, Function, FunctionSection, GlobalType, ImportSection,
    Instruction as I, MemArg, Module, TypeSection, ValType,
};

/// Signatures longer than this many parameters are refused (C allows 127).
pub const MAX_PARAMS: usize = 256;

fn val(c: u8) -> Option<ValType> {
    Some(match c {
        b'i' => ValType::I32,
        b'I' => ValType::I64,
        b'f' => ValType::F32,
        b'd' => ValType::F64,
        _ => return None,
    })
}

/// `sig`'s parameter and result types, or why it is not one.
pub fn parse(sig: &str) -> Result<(Vec<ValType>, Option<ValType>), String> {
    let (p, r) = sig.split_once(':').ok_or_else(|| format!("ffi signature {sig:?}: no ':'"))?;
    if p.len() > MAX_PARAMS {
        return Err(format!("ffi signature {sig:?}: more than {MAX_PARAMS} parameters"));
    }
    let params = p.bytes().map(|c| val(c).ok_or_else(|| format!("ffi signature {sig:?}: {:?} is not a type", c as char))).collect::<Result<Vec<_>, _>>()?;
    let result = match r.as_bytes() {
        b"v" => None,
        [c] => Some(val(*c).ok_or_else(|| format!("ffi signature {sig:?}: result {:?} is not a type", *c as char))?),
        _ => return Err(format!("ffi signature {sig:?}: one result type")),
    };
    Ok((params, result))
}

/// The guest pointer on the stack (i64), as the memory's address type.
fn addr(f: &mut Function) {
    if !gex_abi::mem64() {
        f.instruction(&I::I32WrapI64);
    }
}

fn arg(offset: u64) -> MemArg {
    MemArg { offset, align: 0, memory_index: 0 }
}

/// The thunk module for `sig`.
pub fn thunk(sig: &str) -> Result<Vec<u8>, String> {
    let (params, result) = parse(sig)?;
    let mut types = TypeSection::new();
    types.ty().function(params.iter().copied(), result);
    types.ty().function([ValType::I64, ValType::I64, ValType::I64], []);
    let mut imports = ImportSection::new();
    imports.import("env", "memory", EntityType::Memory(memory_type()));
    imports.import("env", "__indirect_function_table", EntityType::Table(ftab_type()));
    imports.import("env", "__table_base", EntityType::Global(GlobalType { val_type: table_base_type(), mutable: false, shared: false }));
    let mut funcs = FunctionSection::new();
    funcs.function(1);
    let mut f = Function::new([]);
    // (the result's address under the call's operands, for its store)
    if result.is_some() {
        f.instruction(&I::LocalGet(2));
        addr(&mut f);
    }
    for (k, t) in params.iter().enumerate() {
        // av[k], then the value it points to
        f.instruction(&I::LocalGet(1));
        addr(&mut f);
        f.instruction(&I::I64Load(arg(8 * k as u64)));
        addr(&mut f);
        f.instruction(&match t {
            ValType::I32 => I::I32Load(arg(0)),
            ValType::I64 => I::I64Load(arg(0)),
            ValType::F32 => I::F32Load(arg(0)),
            _ => I::F64Load(arg(0)),
        });
    }
    f.instruction(&I::LocalGet(0));
    // (a table64 beside a memory64: the index as it is)
    if !gex_abi::mem64() {
        f.instruction(&I::I32WrapI64);
    }
    f.instruction(&I::CallIndirect { type_index: 0, table_index: 0 });
    // (an i32 or f32 result leaves the rest of libffi's 8-byte rvalue as
    // it was: the C side reads it at its own width)
    match result {
        Some(ValType::I32) => f.instruction(&I::I32Store(arg(0))),
        Some(ValType::I64) => f.instruction(&I::I64Store(arg(0))),
        Some(ValType::F32) => f.instruction(&I::F32Store(arg(0))),
        Some(_) => f.instruction(&I::F64Store(arg(0))),
        None => &mut f,
    };
    f.instruction(&I::End);
    let mut code = CodeSection::new();
    code.function(&f);
    let mut elems = ElementSection::new();
    elems.active(Some(0), &ConstExpr::global_get(0), Elements::Functions(std::borrow::Cow::Borrowed(&[0])));
    let mut m = Module::new();
    m.section(&types).section(&imports).section(&funcs).section(&elems).section(&code);
    Ok(m.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid() {
        for sig in [":v", "i:i", "IdI:i", "fff:f", "I:v", "iiiiiiiiiiiiIdfI:d"] {
            let w = thunk(sig).unwrap();
            wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all()).validate_all(&w).unwrap_or_else(|e| panic!("{sig}: {e}"));
        }
        assert!(thunk("x:i").is_err());
        assert!(thunk("i").is_err());
        assert!(thunk("i:ii").is_err());
    }
}
