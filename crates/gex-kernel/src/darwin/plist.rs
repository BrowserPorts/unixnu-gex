//! XML property lists: read as a build manifest has them, and written as
//! CoreFoundation writes XML (`_CFGenerateXMLPropertyListToData` and
//! `_CFAppendXML0`, CF-1153.18 CFPropertyList.c), which
//! `-[NSDictionary writeToFile:atomically:]` does through
//! `CFPropertyListCreateData`.
//!
//! The values are the kinds a build manifest holds: dictionaries, arrays,
//! strings, data, integers and booleans. A real or a date is not read.

/// A property list value. A dictionary keeps its keys in the order read;
/// the writer sorts them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Dict(Vec<(String, Value)>),
    Array(Vec<Value>),
    String(String),
    Data(Vec<u8>),
    Integer(i128),
    Bool(bool),
}

impl Value {
    /// A dictionary's value for `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(d) => d.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Value::Data(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn err(&self, what: &str) -> String {
        format!("a property list: {what} at byte {}", self.at)
    }

    fn skip_space(&mut self) {
        while self.at < self.b.len() && self.b[self.at].is_ascii_whitespace() {
            self.at += 1;
        }
    }

    fn starts(&self, s: &str) -> bool {
        self.b[self.at..].starts_with(s.as_bytes())
    }

    /// Past `end`, which must come.
    fn past(&mut self, end: &str) -> Result<(), String> {
        let rest = &self.b[self.at..];
        let i = rest.windows(end.len()).position(|w| w == end.as_bytes()).ok_or_else(|| self.err(&format!("no {end}")))?;
        self.at += i + end.len();
        Ok(())
    }

    /// Whitespace, comments, the XML declaration and the document type.
    fn skip_misc(&mut self) -> Result<(), String> {
        loop {
            self.skip_space();
            if self.starts("<?") {
                self.past("?>")?;
            } else if self.starts("<!--") {
                self.past("-->")?;
            } else if self.starts("<!DOCTYPE") {
                self.past(">")?;
            } else {
                return Ok(());
            }
        }
    }

    /// The next tag: its name and whether it closes itself (`<true/>`),
    /// or a closing tag (`</dict>`) as `/dict`.
    fn tag(&mut self) -> Result<(String, bool), String> {
        self.skip_misc()?;
        if !self.starts("<") {
            return Err(self.err("text where a tag belongs"));
        }
        let start = self.at + 1;
        self.past(">")?;
        let inner = std::str::from_utf8(&self.b[start..self.at - 1]).map_err(|_| self.err("a tag that is not text"))?;
        let empty = inner.ends_with('/');
        let inner = inner.trim_end_matches('/');
        let name = inner.split_ascii_whitespace().next().unwrap_or("").to_string();
        Ok((name, empty))
    }

    /// The text up to the closing tag `</name>`, its references replaced.
    fn text(&mut self, name: &str) -> Result<String, String> {
        let start = self.at;
        let end = format!("</{name}>");
        self.past(&end)?;
        let raw = std::str::from_utf8(&self.b[start..self.at - end.len()]).map_err(|_| self.err("text that is not UTF-8"))?;
        unescape(raw).ok_or_else(|| self.err("a character reference"))
    }

    fn value(&mut self) -> Result<Value, String> {
        let (name, empty) = self.tag()?;
        Ok(match (name.as_str(), empty) {
            ("dict", true) => Value::Dict(Vec::new()),
            ("dict", false) => {
                let mut d = Vec::new();
                loop {
                    let (k, kempty) = self.tag()?;
                    match (k.as_str(), kempty) {
                        ("/dict", _) => break,
                        ("key", false) => {
                            let key = self.text("key")?;
                            d.push((key, self.value()?));
                        }
                        ("key", true) => d.push((String::new(), self.value()?)),
                        _ => return Err(self.err(&format!("<{k}> where a key belongs"))),
                    }
                }
                Value::Dict(d)
            }
            ("array", true) => Value::Array(Vec::new()),
            ("array", false) => {
                let mut a = Vec::new();
                loop {
                    let save = self.at;
                    let (t, _) = self.tag()?;
                    if t == "/array" {
                        break;
                    }
                    self.at = save;
                    a.push(self.value()?);
                }
                Value::Array(a)
            }
            ("string", true) => Value::String(String::new()),
            ("string", false) => Value::String(self.text("string")?),
            ("data", true) => Value::Data(Vec::new()),
            ("data", false) => {
                let t = self.text("data")?;
                Value::Data(base64_decode(&t).ok_or_else(|| self.err("data that is not base 64"))?)
            }
            ("integer", false) => {
                let t = self.text("integer")?;
                let t = t.trim();
                let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(h) => i128::from_str_radix(h, 16).ok(),
                    None => t.parse::<i128>().ok(),
                };
                let v = v.filter(|v| *v >= i64::MIN as i128 && *v <= u64::MAX as i128).ok_or_else(|| self.err("an integer"))?;
                Value::Integer(v)
            }
            ("true", true) => Value::Bool(true),
            ("false", true) => Value::Bool(false),
            (other, _) => return Err(self.err(&format!("a <{other}>, which is not read here"))),
        })
    }
}

fn unescape(s: &str) -> Option<String> {
    if !s.contains('&') {
        return Some(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let j = rest[i..].find(';')? + i;
        let name = &rest[i + 1..j];
        match name {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let n = if let Some(h) = name.strip_prefix("#x") {
                    u32::from_str_radix(h, 16).ok()?
                } else {
                    name.strip_prefix('#')?.parse().ok()?
                };
                out.push(char::from_u32(n)?);
            }
        }
        rest = &rest[j + 1..];
    }
    out.push_str(rest);
    Some(out)
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            break;
        }
        let v = BASE64.iter().position(|&x| x == c)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// An XML property list's value.
pub fn parse(b: &[u8]) -> Result<Value, String> {
    let mut r = Reader { b, at: 0 };
    let (name, _) = r.tag()?;
    if name != "plist" {
        return Err(r.err("no <plist>"));
    }
    let v = r.value()?;
    let (end, _) = r.tag()?;
    if end != "/plist" {
        return Err(r.err("no </plist>"));
    }
    Ok(v)
}

/// `_appendIndents`: a tab for each level.
fn indents(out: &mut Vec<u8>, n: usize) {
    out.extend(std::iter::repeat(b'\t').take(n));
}

/// `_appendEscapedString`: `<`, `>` and `&` as references.
fn escaped(out: &mut Vec<u8>, s: &str) {
    for c in s.bytes() {
        match c {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            _ => out.push(c),
        }
    }
}

/// `_XMLPlistAppendDataUsingBase64`: lines of at most 76 characters, the
/// indent (eight columns a tab, at most eight tabs) counted against them.
fn base64_lines(out: &mut Vec<u8>, data: &[u8], indent: usize) {
    const MAXLINELEN: usize = 76;
    let indent = indent.min(8);
    let mut buf = Vec::with_capacity(MAXLINELEN + 4);
    let flush = |out: &mut Vec<u8>, buf: &mut Vec<u8>| {
        buf.push(b'\n');
        indents(out, indent);
        out.extend_from_slice(buf);
        buf.clear();
    };
    for (i, &p) in data.iter().enumerate() {
        match i % 3 {
            0 => buf.push(BASE64[(p >> 2) as usize & 0x3f]),
            1 => buf.push(BASE64[((u32::from(data[i - 1]) << 8 | u32::from(p)) >> 4) as usize & 0x3f]),
            _ => {
                buf.push(BASE64[((u32::from(data[i - 1]) << 8 | u32::from(p)) >> 6) as usize & 0x3f]);
                buf.push(BASE64[p as usize & 0x3f]);
            }
        }
        if buf.len() >= MAXLINELEN.saturating_sub(8 * indent) {
            flush(out, &mut buf);
        }
    }
    match data.len() % 3 {
        1 => {
            buf.push(BASE64[(data[data.len() - 1] << 4) as usize & 0x30]);
            buf.extend_from_slice(b"==");
        }
        2 => {
            buf.push(BASE64[(data[data.len() - 1] << 2) as usize & 0x3c]);
            buf.push(b'=');
        }
        _ => {}
    }
    if !buf.is_empty() {
        flush(out, &mut buf);
    }
}

/// `_CFAppendXML0`.
fn append(out: &mut Vec<u8>, v: &Value, indentation: usize) {
    indents(out, indentation);
    match v {
        Value::String(s) => {
            out.extend_from_slice(b"<string>");
            escaped(out, s);
            out.extend_from_slice(b"</string>\n");
        }
        Value::Array(a) if a.is_empty() => out.extend_from_slice(b"<array/>\n"),
        Value::Array(a) => {
            out.extend_from_slice(b"<array>\n");
            for x in a {
                append(out, x, indentation + 1);
            }
            indents(out, indentation);
            out.extend_from_slice(b"</array>\n");
        }
        Value::Dict(d) if d.is_empty() => out.extend_from_slice(b"<dict/>\n"),
        Value::Dict(d) => {
            out.extend_from_slice(b"<dict>\n");
            // CFStringCompare with no options: UTF-16 code units, in order.
            let mut keys: Vec<&(String, Value)> = d.iter().collect();
            keys.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            for (k, x) in keys {
                indents(out, indentation + 1);
                out.extend_from_slice(b"<key>");
                escaped(out, k);
                out.extend_from_slice(b"</key>\n");
                append(out, x, indentation + 1);
            }
            indents(out, indentation);
            out.extend_from_slice(b"</dict>\n");
        }
        Value::Data(b) => {
            out.extend_from_slice(b"<data>\n");
            base64_lines(out, b, indentation);
            indents(out, indentation);
            out.extend_from_slice(b"</data>\n");
        }
        Value::Integer(n) => {
            out.extend_from_slice(format!("<integer>{n}</integer>\n").as_bytes());
        }
        Value::Bool(true) => out.extend_from_slice(b"<true/>\n"),
        Value::Bool(false) => out.extend_from_slice(b"<false/>\n"),
    }
}

/// `_CFGenerateXMLPropertyListToData`: the property list as XML.
pub fn to_xml(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n");
    append(&mut out, v, 0);
    out.extend_from_slice(b"</plist>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_reads() {
        let x = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>b</key>\n\t<array>\n\t\t<string>x &amp; y</string>\n\t\t<data>\n\t\tAAEC\n\t\t</data>\n\t\t<integer>12</integer>\n\t\t<true/>\n\t\t<dict/>\n\t</array>\n\t<key>A</key>\n\t<string/>\n</dict>\n</plist>\n";
        let v = parse(x).unwrap();
        assert_eq!(v.get("A"), Some(&Value::String(String::new())));
        let a = v.get("b").unwrap().as_array().unwrap();
        assert_eq!(a, &[Value::String("x & y".into()), Value::Data(vec![0, 1, 2]), Value::Integer(12), Value::Bool(true), Value::Dict(vec![])]);
        assert!(parse(b"<plist><real>1.5</real></plist>").is_err(), "a real is not read");
    }

    #[test]
    fn written_as_core_foundation_writes() {
        let v = Value::Dict(vec![
            ("b".into(), Value::Array(vec![Value::Data((0..60).collect()), Value::Integer(-3), Value::Bool(false), Value::Array(vec![])])),
            ("B".into(), Value::String("<&>".into())),
        ]);
        let want = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>B</key>\n\t<string>&lt;&amp;&gt;</string>\n\t<key>b</key>\n\t<array>\n\t\t<data>\n\t\tAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKiss\n\t\tLS4vMDEyMzQ1Njc4OTo7\n\t\t</data>\n\t\t<integer>-3</integer>\n\t\t<false/>\n\t\t<array/>\n\t</array>\n</dict>\n</plist>\n";
        assert_eq!(String::from_utf8(to_xml(&v)).unwrap(), want);
        assert_eq!(parse(want.as_bytes()).unwrap(), Value::Dict(vec![("B".into(), Value::String("<&>".into())), ("b".into(), v.get("b").unwrap().clone())]));
    }

    #[test]
    fn data_lines_break_as_core_foundation_breaks_them() {
        // At the top level a line holds 76 characters: 57 bytes.
        let mut out = Vec::new();
        base64_lines(&mut out, &[0xff; 58], 0);
        let s = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 76);
        assert_eq!(lines[1], "/w==");
        // Nine levels in: eight tabs, 12 characters a line.
        let mut out = Vec::new();
        base64_lines(&mut out, &[0; 9], 9);
        assert_eq!(String::from_utf8(out).unwrap(), "\t\t\t\t\t\t\t\tAAAAAAAAAAAA\n");
    }
}
