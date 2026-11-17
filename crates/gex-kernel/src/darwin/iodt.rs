//! What the kernel derives from the device tree for its registry entries
//! (`IODeviceTreeSupport.cpp`, xnu-10063, checked against the kernelcache
//! of 21H461): the interrupt keys `IODeviceTreeAlloc` gives every entry
//! (`IODTMapInterruptsSharing`, its loop at 0xfffffff0077a9be8), and the
//! device memory `IODTResolveAddressing` (0xfffffff0077ac548) gives a nub
//! from its `reg`.

use super::iokit::{Node, Prop};

/// A property of an entry's device tree table.
fn prop<'a>(n: &'a Node, name: &str) -> Option<&'a [u8]> {
    n.props.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_slice())
}

/// The words of a property.
fn words(v: &[u8]) -> Vec<u32> {
    v.chunks_exact(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect()
}

/// `GetUInt32`: a property of exactly four bytes.
fn uint32(n: &Node, name: &str) -> Option<u32> {
    prop(n, name).filter(|v| v.len() == 4).map(|v| u32::from_le_bytes(v.try_into().unwrap()))
}

/// `FindPHandle`: the entry whose `AAPL,phandle` is `phandle`.
fn find_phandle(t: &[Node], phandle: u32) -> Option<u32> {
    t.iter().position(|n| n.class.is_empty() && prop(n, "AAPL,phandle").is_some_and(|v| v.len() >= 4 && u32::from_le_bytes(v[..4].try_into().unwrap()) == phandle)).map(|i| i as u32)
}

/// `IODTFindInterruptParent`: the entry's `interrupt-parent` (its
/// `index`th phandle, or its first when it has fewer), else its parent
/// unless it is a controller itself.
fn interrupt_parent(t: &[Node], i: u32, index: usize) -> Option<u32> {
    let n = &t[i as usize];
    if let Some(v) = prop(n, "interrupt-parent").filter(|v| v.len() >= 4) {
        let w = words(v);
        return find_phandle(t, w[if index < w.len() { index } else { 0 }]);
    }
    if prop(n, "interrupt-controller").is_none() {
        return n.parent;
    }
    None
}

/// `IODTGetICellCounts`: an interrupt parent's `#interrupt-cells` (1 when
/// it has none) and `#address-cells` (0 when it has none).
fn icell_counts(n: &Node) -> (usize, usize) {
    (uint32(n, "#interrupt-cells").unwrap_or(1) as usize, uint32(n, "#address-cells").unwrap_or(0) as usize)
}

/// `IODTMapOneInterrupt`: the controller and specifier of entry `i`'s
/// interrupt at `spec` (its `index`th), following any `interrupt-map` to
/// the first `interrupt-controller`; with the number of cells the entry's
/// interrupt takes. `Err` where the kernel would fail or never finish.
fn map_one(t: &[Node], i: u32, spec: &[u32], index: usize) -> Result<Option<(String, Vec<u32>, usize)>, String> {
    let n = &t[i as usize];
    let Some(mut parent) = interrupt_parent(t, i, index) else {
        return Err(format!("the interrupt parent of the device tree entry {} (none: the kernel would fault)", n.name));
    };
    let (mut icells, acells) = icell_counts(&t[parent as usize]);
    let original = icells;
    let reg = prop(n, "reg").map(words).unwrap_or_default();
    let mut addr: Vec<u32> = if acells > 0 && reg.len() >= acells { reg[..acells].to_vec() } else { Vec::new() };
    let mut acells = acells;
    let mut spec: Vec<u32> = spec.to_vec();
    for _ in 0..t.len() {
        let e = &t[parent as usize];
        if prop(e, "interrupt-controller").is_some() {
            let Some(phandle) = uint32(e, "AAPL,phandle") else { return Ok(None) };
            if spec.len() < icells {
                return Ok(None);
            }
            return Ok(Some((format!("IOInterruptController{phandle:08X}"), spec[..icells].to_vec(), original)));
        }
        let Some(map) = prop(e, "interrupt-map").map(words) else {
            return Err(format!("the interrupt of the device tree entry {} reaches {}, neither a controller nor a map (the kernel would not finish)", n.name, e.name));
        };
        let mask = prop(e, "interrupt-map-mask").map(words).filter(|m| m.len() >= acells + icells);
        let mut at = 0;
        let mut next = None;
        while at < map.len() {
            let cmp = (0..acells + icells).all(|k| {
                let cell = if k < acells { addr.get(k).copied().unwrap_or(0) } else { spec.get(k - acells).copied().unwrap_or(0) };
                let cell = mask.as_ref().map_or(cell, |m| cell & m[k]);
                map.get(at + k) == Some(&cell)
            });
            at += acells + icells;
            let Some(p) = map.get(at).and_then(|&ph| find_phandle(t, ph)) else { return Ok(None) };
            at += 1;
            let (picells, pacells) = icell_counts(&t[p as usize]);
            if cmp {
                addr = map.get(at..at + pacells).map(<[u32]>::to_vec).unwrap_or_default();
                spec = map.get(at + pacells..).map(<[u32]>::to_vec).unwrap_or_default();
                next = Some(p);
                break;
            }
            at += pacells + picells;
        }
        let Some(p) = next else { return Ok(None) };
        parent = p;
        let (ic, ac) = icell_counts(&t[parent as usize]);
        icells = ic;
        acells = ac;
    }
    Err(format!("the interrupt map below the device tree entry {}", n.name))
}

/// `IODTMapInterruptsSharing` of entry `i`: its interrupts' controllers'
/// names (symbols) and specifiers (data), when it has interrupts and each
/// maps; an entry's old-world `AAPL,interrupts` (or its parent's) maps
/// each word to the default controller, "IOPlatformInterruptController".
fn map_interrupts(t: &[Node], i: u32) -> Result<Option<(Vec<Prop>, Vec<Prop>)>, String> {
    let n = &t[i as usize];
    let mut local = prop(n, "AAPL,interrupts");
    let mut nw = local.is_none();
    if nw {
        local = prop(n, "interrupts");
        if local.is_none() {
            return Ok(None);
        }
        if let Some(p) = n.parent.and_then(|p| prop(&t[p as usize], "AAPL,interrupts")) {
            local = Some(p);
            nw = false;
        }
    }
    let bits = words(local.unwrap());
    let (mut controllers, mut specs) = (Vec::new(), Vec::new());
    let mut at = 0;
    let mut index = 0;
    let mut ok = true;
    loop {
        if nw {
            match map_one(t, i, &bits[at.min(bits.len())..], index)? {
                Some((c, s, skip)) => {
                    controllers.push(Prop::Sym(c));
                    specs.push(Prop::Data(s.iter().flat_map(|w| w.to_le_bytes()).collect()));
                    at += skip;
                }
                None => {
                    ok = false;
                    break;
                }
            }
        } else {
            controllers.push(Prop::Sym("IOPlatformInterruptController".to_string()));
            specs.push(Prop::Data(bits.get(index).copied().unwrap_or(0).to_le_bytes().to_vec()));
            at += 1;
        }
        index += 1;
        if at >= bits.len() {
            break;
        }
    }
    if !ok || at != bits.len() {
        return Ok(None);
    }
    Ok(Some((controllers, specs)))
}

/// `IODeviceTreeAlloc`'s adjustments of the tree, in its order over the
/// `IODeviceTree` plane: each entry's `IOInterruptControllers` and
/// `IOInterruptSpecifiers`, then "aot-power" (4 bytes, 1) on the entries
/// named sep, aop and disp0; and, when some entry has an
/// `interrupt-parent`, `IONWInterrupts` on the root, its key itself as its
/// value.
pub fn alloc(t: &mut [Node]) -> Result<(), String> {
    let mut nw = false;
    for i in 0..t.len() as u32 {
        if !t[i as usize].class.is_empty() {
            continue;
        }
        let mapped = map_interrupts(t, i)?;
        let n = &mut t[i as usize];
        if let Some((c, s)) = mapped {
            n.service_props.push(("IOInterruptControllers".to_string(), Prop::Array(c)));
            n.service_props.push(("IOInterruptSpecifiers".to_string(), Prop::Array(s)));
        }
        nw |= prop(n, "interrupt-parent").is_some();
        if matches!(n.name.as_str(), "sep" | "aop" | "disp0") {
            set(&mut n.service_props, "aot-power", Prop::Data(1u32.to_le_bytes().to_vec()));
        }
    }
    if nw {
        if let Some(root) = t.first_mut() {
            root.service_props.push(("IONWInterrupts".to_string(), Prop::Sym("IONWInterrupts".to_string())));
        }
    }
    Ok(())
}

/// `setProperty`: a key's value replaced where it is, else appended.
fn set(props: &mut Vec<(String, Prop)>, k: &str, v: Prop) {
    match props.iter_mut().find(|(o, _)| o == k) {
        Some(slot) => slot.1 = v,
        None => props.push((k.to_string(), v)),
    }
}

/// `IODTGetCellCounts`: an entry's `#size-cells` (1 when it has none) and
/// `#address-cells` (2 when it has none).
fn cell_counts(n: &Node) -> (usize, usize) {
    (uint32(n, "#size-cells").unwrap_or(1) as usize, uint32(n, "#address-cells").unwrap_or(2) as usize)
}

/// `CellsValue` on arm64: one cell, or the last two, the high word last.
fn cells_value(n: usize, c: &[u32]) -> u64 {
    match n {
        0 => 0,
        1 => u64::from(c[0]),
        _ => u64::from(c[n - 1]) << 32 | u64::from(c[n - 2]),
    }
}

/// `AddLengthToCells` on arm64.
fn add_length(n: usize, c: &mut [u32], offset: u64) {
    if n == 1 {
        c[0] = c[0].wrapping_add(offset as u32);
    } else {
        let sum = u64::from(c[n - 2]) + offset;
        c[n - 2] = sum as u32;
        if sum > u64::from(u32::MAX) {
            c[n - 1] = c[n - 1].wrapping_add((sum >> 32) as u32);
        }
    }
}

/// `DefaultCompare` on arm64: two cells as one 64-bit address, one as a
/// 32-bit unsigned difference.
fn compare(n: usize, l: &[u32], r: &[u32]) -> Result<i64, String> {
    match n {
        2 => Ok((u64::from(l[1]) << 32 | u64::from(l[0])).wrapping_sub(u64::from(r[1]) << 32 | u64::from(r[0])) as i64),
        1 => Ok(i64::from(l[0].wrapping_sub(r[0]))),
        _ => Err(format!("DefaultCompare of {n} cells (the kernel panics)")),
    }
}

/// `IODTResolveAddressCell` from entry `start` (whose children's cells
/// `cells_in` are): the physical address and length, through each
/// ancestor's `ranges`; none when a range does not hold it.
fn resolve_cell(t: &[Node], start: u32, cells_in: &[u32]) -> Result<Option<(u64, u64)>, String> {
    let mut reg = start;
    let (mut csize, mut caddr) = cell_counts(&t[reg as usize]);
    if caddr + csize > 8 {
        return Err("IODTResolveAddressCell: an invalid device tree (the kernel panics)".to_string());
    }
    let mut cell = [0u32; 8];
    cell[..caddr + csize].copy_from_slice(&cells_in[..caddr + csize]);
    let len_out = cells_value(csize, &cells_in[caddr..]);
    let mut offset: u64 = 0;
    loop {
        let n = &t[reg as usize];
        let Some(ranges) = prop(n, "ranges") else {
            return Ok(Some((cells_value(caddr, &cell).wrapping_add(offset), len_out)));
        };
        let Some(parent) = n.parent else { return Ok(None) };
        let (size, addr) = cell_counts(&t[parent as usize]);
        let mut ok = true;
        if !ranges.is_empty() {
            if addr != caddr {
                return Err(format!("the ranges of {} (a mixed comparison: the kernel panics)", n.name));
            }
            let r = words(ranges);
            let step = caddr + csize + addr;
            let mut found = None;
            ok = false;
            let mut at = 0;
            while at < r.len() {
                let range = r.get(at..at + step).ok_or_else(|| format!("the ranges of {} end early", n.name))?;
                let diff = compare(caddr, &cell, range)?;
                let mut end = [0u32; 8];
                end[..caddr].copy_from_slice(&range[..caddr]);
                add_length(caddr, &mut end, cells_value(csize, &range[caddr + addr..]));
                let diff2 = compare(caddr, &cell, &end)?;
                if diff < 0 || diff2 >= 0 {
                    at += step;
                    continue;
                }
                let len = cells_value(csize, &cell[caddr..]);
                ok = len == 0;
                if !ok {
                    let mut end = [0u32; 8];
                    end[..caddr].copy_from_slice(&cell[..caddr]);
                    add_length(caddr, &mut end, len.wrapping_sub(1));
                    let mut look = 0;
                    while look < r.len() {
                        let lr = &r[look..look + step];
                        let end_diff = compare(caddr, &end, lr)?;
                        if end_diff >= 0 {
                            let start = cells_value(addr, &range[caddr..]);
                            let lstart = cells_value(addr, &lr[caddr..]);
                            if (end_diff as u64).wrapping_sub(len).wrapping_add(1).wrapping_add(lstart) == (diff as u64).wrapping_add(start) {
                                ok = true;
                                break;
                            }
                        }
                        look += step;
                    }
                    if !ok {
                        at += step;
                        continue;
                    }
                }
                offset = offset.wrapping_add(diff as u64);
                found = Some(range.to_vec());
                break;
            }
            let Some(range) = found else { return Ok(None) };
            cell = [0u32; 8];
            cell[..addr].copy_from_slice(&range[caddr..caddr + addr]);
        }
        if !ok {
            return Ok(None);
        }
        reg = parent;
        csize = size;
        caddr = addr;
    }
}

/// `IODTResolveAddressing(entry, "reg", NULL)`: entry `i`'s device memory,
/// one physical range per `reg` tuple (`IODeviceMemory::withRange`), as
/// the nub's "IODeviceMemory" serializes: an array of each range's
/// `IOGeneralMemoryDescriptor::serialize` (0xfffffff0077ff248), an array of
/// one dictionary of its "address" and "length" (64-bit numbers). None
/// when the entry has no `reg`, no parent, or its parent no size cells.
pub fn device_memory(t: &[Node], i: u32) -> Result<Option<Prop>, String> {
    let n = &t[i as usize];
    let (Some(reg), Some(parent)) = (prop(n, "reg"), n.parent) else { return Ok(None) };
    let (size, addr) = cell_counts(&t[parent as usize]);
    if size == 0 {
        return Ok(None);
    }
    let w = words(reg);
    let cells = size + addr;
    let mut out = Vec::new();
    for k in 0..reg.len() / (4 * cells) {
        let mut c = w[k * cells..(k + 1) * cells].to_vec();
        c.resize(8, 0);
        if let Some((phys, len)) = resolve_cell(t, parent, &c)? {
            out.push(Prop::Array(vec![Prop::Dict(vec![("address".to_string(), Prop::Num(phys, 64)), ("length".to_string(), Prop::Num(len, 64))])]));
        }
    }
    Ok(Some(Prop::Array(out)))
}

#[cfg(test)]
mod tests {
    use super::super::iokit::{parse, Prop};

    fn node(b: &mut Vec<u8>, name: &str, props: &[(&str, &[u8])], children: u32) {
        let named: Vec<(&str, Vec<u8>)> = std::iter::once(("name", [name.as_bytes(), b"\0"].concat())).chain(props.iter().map(|&(k, v)| (k, v.to_vec()))).collect();
        b.extend_from_slice(&(named.len() as u32).to_le_bytes());
        b.extend_from_slice(&children.to_le_bytes());
        for (k, v) in named {
            let mut key = [0u8; 32];
            key[..k.len()].copy_from_slice(k.as_bytes());
            b.extend_from_slice(&key);
            b.extend_from_slice(&(v.len() as u32).to_le_bytes());
            b.extend_from_slice(&v);
            b.resize((b.len() + 3) & !3, 0);
        }
    }

    fn cells(w: &[u32]) -> Vec<u8> {
        w.iter().flat_map(|c| c.to_le_bytes()).collect()
    }

    #[test]
    fn interrupts_and_device_memory_resolve_through_the_tree() {
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("#address-cells", &cells(&[2])), ("#size-cells", &cells(&[2]))], 1);
        node(&mut b, "arm-io", &[("#address-cells", &cells(&[2])), ("#size-cells", &cells(&[2])), ("ranges", &cells(&[0, 0, 0, 2, 0x1000_0000, 0]))], 2);
        node(&mut b, "aic", &[("AAPL,phandle", &cells(&[0x1d])), ("interrupt-controller", b"\0"), ("#interrupt-cells", &cells(&[1]))], 0);
        node(&mut b, "disp0", &[("interrupt-parent", &cells(&[0x1d])), ("interrupts", &cells(&[0x10e, 0x111])), ("reg", &cells(&[0x10_0000, 0, 0x4000, 0]))], 0);
        let mut t = parse(&b).unwrap();
        super::alloc(&mut t).unwrap();
        let disp = 3;
        let p = |i: usize, k: &str| t[i].service_props.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let ctl = Prop::Sym("IOInterruptController0000001D".to_string());
        assert_eq!(p(disp, "IOInterruptControllers"), Some(Prop::Array(vec![ctl.clone(), ctl])));
        assert_eq!(p(disp, "IOInterruptSpecifiers"), Some(Prop::Array(vec![Prop::Data(cells(&[0x10e])), Prop::Data(cells(&[0x111]))])));
        assert_eq!(p(disp, "aot-power"), Some(Prop::Data(cells(&[1]))));
        assert_eq!(p(0, "IONWInterrupts"), Some(Prop::Sym("IONWInterrupts".to_string())));
        // The controller itself has no interrupts; arm-io none either.
        assert_eq!(p(2, "IOInterruptControllers"), None);
        let range = |a: u64, l: u64| Prop::Array(vec![Prop::Dict(vec![("address".to_string(), Prop::Num(a, 64)), ("length".to_string(), Prop::Num(l, 64))])]);
        assert_eq!(super::device_memory(&t, disp as u32), Ok(Some(Prop::Array(vec![range(0x2_0010_0000, 0x4000)]))));
        // An address outside every range does not resolve.
        t[disp].props.retain(|(k, _)| k != "reg");
        t[disp].props.push(("reg".to_string(), cells(&[0, 1, 0x4000, 0])));
        assert_eq!(super::device_memory(&t, disp as u32), Ok(Some(Prop::Array(vec![]))));
    }
}
