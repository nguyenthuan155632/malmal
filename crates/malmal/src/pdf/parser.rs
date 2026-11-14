//! PDF object syntax. Malicious files are routinely malformed on purpose, so
//! parsing either yields a value or fails cleanly; the caller decides how to
//! treat what could not be read.

const MAX_DEPTH: usize = 64;

/// Bytes of a name that fit in the value itself. Nearly every name does,
/// so a document of many small objects costs no allocation per name.
const INLINE: usize = 21;
/// Longest string whose contents are kept. The ones that are inspected
/// (addresses, appearance strings, file names) are far shorter.
const MAX_STRING: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
enum Text {
    Inline(u8, [u8; INLINE]),
    Heap(Box<[u8]>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Name {
    text: Text,
    obfuscated: bool,
}

impl Name {
    fn new(text: &[u8], obfuscated: bool) -> Self {
        let text = if text.len() <= INLINE {
            let mut bytes = [0; INLINE];
            bytes[..text.len()].copy_from_slice(text);
            Text::Inline(text.len() as u8, bytes)
        } else {
            Text::Heap(text.into())
        };
        Self { text, obfuscated }
    }

    /// Bytes after `#xx` escapes are decoded.
    pub fn text(&self) -> &[u8] {
        match &self.text {
            Text::Inline(length, bytes) => &bytes[..usize::from(*length)],
            Text::Heap(bytes) => bytes,
        }
    }

    /// A letter or digit was written as a `#xx` escape. No PDF writer does
    /// that; it is how keywords are hidden from naive scanners.
    pub fn obfuscated(&self) -> bool {
        self.obfuscated
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(f64),
    /// The decoded bytes, or `None` for a string longer than is kept.
    String(Option<Box<[u8]>>),
    Name(Name),
    Array(Box<[Value]>),
    Dict(Dict),
    /// Indirect reference by object number.
    Ref(u32),
}

/// Entries in file order. Duplicate keys are kept: which one a reader
/// honours differs between readers, so all of them are inspected.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Dict(pub Box<[(Name, Value)]>);

impl Dict {
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        self.0
            .iter()
            .find(|(name, _)| name.text() == key)
            .map(|(_, value)| value)
    }

    /// Every value stored under `key`.
    pub fn all<'d>(&'d self, key: &'d [u8]) -> impl Iterator<Item = &'d Value> {
        self.0
            .iter()
            .filter(move |(name, _)| name.text() == key)
            .map(|(_, value)| value)
    }
}

impl Value {
    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Self::Name(name) => Some(name.text()),
            _ => None,
        }
    }

    /// Contents of a string short enough to have been kept.
    pub fn as_string(&self) -> Option<&[u8]> {
        match self {
            Self::String(Some(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// Any number, as written.
    pub fn as_number(&self) -> Option<f64> {
        match *self {
            Self::Number(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Self::Dict(dict) => Some(dict),
            _ => None,
        }
    }

    /// Non-negative integer value.
    pub fn as_usize(&self) -> Option<usize> {
        match *self {
            // Whole, which below this it is if the integer it is cut to is
            // the same number.
            Self::Number(n) if (0.0..1e15).contains(&n) && (n as u64) as f64 == n => {
                Some(n as usize)
            }
            _ => None,
        }
    }
}

pub(crate) const fn is_whitespace(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

const fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// Whether each byte is neither whitespace nor a delimiter. Names and
/// operators are runs of these, and finding their ends is done a byte at a
/// time.
const REGULAR: [bool; 256] = {
    let mut regular = [false; 256];
    let mut byte = 0;
    while byte < 256 {
        regular[byte] = !is_whitespace(byte as u8) && !is_delimiter(byte as u8);
        byte += 1;
    }
    regular
};

pub(crate) fn is_regular(byte: u8) -> bool {
    REGULAR[byte as usize]
}

/// Items of one array or dictionary that are gathered where those of the
/// others are. One that grows past this gets a buffer of its own, which
/// becomes the array without a copy: an array of millions of items is then
/// in memory once and not twice.
const SHARED: usize = 64;

pub(crate) struct Parser<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    /// Values this parser may still allocate; parsing fails at zero so a
    /// file of millions of tiny tokens cannot exhaust memory.
    pub nodes_left: usize,
    /// The value is read and not built: see [`Parser::skip_value`].
    skipping: bool,
    /// The items of the arrays and dictionaries being read, innermost last,
    /// so that each is allocated once and at its size. Only while they are
    /// small: see [`SHARED`].
    items: Vec<Value>,
    entries: Vec<(Name, Value)>,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8], pos: usize, nodes_left: usize) -> Self {
        Self {
            data,
            pos,
            nodes_left,
            skipping: false,
            items: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    /// Skip whitespace and `%` comments.
    pub fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if is_whitespace(byte) {
                self.pos += 1;
            } else if byte == b'%' {
                while self.peek().is_some_and(|b| b != b'\n' && b != b'\r') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    /// Consume `keyword` if it is next and ends at a token boundary.
    pub fn eat_keyword(&mut self, keyword: &[u8]) -> bool {
        let rest = self.rest();
        let matched =
            rest.starts_with(keyword) && rest.get(keyword.len()).is_none_or(|&b| !is_regular(b));
        if matched {
            self.pos += keyword.len();
        }
        matched
    }

    pub fn parse_value(&mut self) -> Option<Value> {
        let value = self.value(0);
        // A value that failed part of the way left its items behind.
        self.items.clear();
        self.entries.clear();
        value
    }

    /// Read a value as [`Parser::parse_value`] does, to the same end and
    /// with the same count of values, without keeping any of it. Returns
    /// whether it is one.
    pub fn skip_value(&mut self) -> bool {
        self.skipping = true;
        let value = self.value(0);
        self.skipping = false;
        value.is_some()
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.nodes_left = self.nodes_left.checked_sub(1)?;
        self.skip_whitespace();
        match self.peek()? {
            b'<' if self.rest().starts_with(b"<<") => self.dict(depth),
            b'<' => self.hex_string(),
            b'(' => self.literal_string(),
            b'[' => {
                self.pos += 1;
                let first = self.items.len();
                let mut own: Option<Vec<Value>> = None;
                loop {
                    self.skip_whitespace();
                    if self.peek()? == b']' {
                        self.pos += 1;
                        return Some(Value::Array(match own {
                            Some(items) => items.into(),
                            None => self.items.drain(first..).collect(),
                        }));
                    }
                    let item = self.value(depth + 1)?;
                    match &mut own {
                        _ if self.skipping => {}
                        Some(items) => items.push(item),
                        None => {
                            self.items.push(item);
                            if self.items.len() - first > SHARED {
                                own = Some(self.items.split_off(first));
                            }
                        }
                    }
                }
            }
            b'/' => self.name().map(Value::Name),
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.number_or_reference(),
            _ if self.eat_keyword(b"true") => Some(Value::Bool(true)),
            _ if self.eat_keyword(b"false") => Some(Value::Bool(false)),
            _ if self.eat_keyword(b"null") => Some(Value::Null),
            _ => None,
        }
    }

    fn dict(&mut self, depth: usize) -> Option<Value> {
        self.pos += 2;
        let first = self.entries.len();
        let mut own: Option<Vec<(Name, Value)>> = None;
        loop {
            self.skip_whitespace();
            if self.rest().starts_with(b">>") {
                self.pos += 2;
                return Some(Value::Dict(Dict(match own {
                    Some(entries) => entries.into(),
                    None => self.entries.drain(first..).collect(),
                })));
            }
            if self.peek()? != b'/' {
                return None;
            }
            let key = self.name()?;
            let value = self.value(depth + 1)?;
            match &mut own {
                _ if self.skipping => {}
                Some(entries) => entries.push((key, value)),
                None => {
                    self.entries.push((key, value));
                    if self.entries.len() - first > SHARED {
                        own = Some(self.entries.split_off(first));
                    }
                }
            }
        }
    }

    /// A name token starting at the current `/`.
    pub fn name(&mut self) -> Option<Name> {
        self.pos += 1;
        let start = self.pos;
        let mut escaped = false;
        while let Some(byte) = self.peek().filter(|&byte| is_regular(byte)) {
            escaped |= byte == b'#';
            self.pos += 1;
        }
        let raw = &self.data[start..self.pos];
        let length = raw.len();
        if !escaped {
            return Some(Name::new(raw, false));
        }
        let mut text = Vec::with_capacity(length);
        let mut obfuscated = false;
        let mut at = 0;
        while let Some(&byte) = raw.get(at) {
            at += 1;
            let escaped = (byte == b'#')
                .then(|| raw.get(at..at + 2))
                .flatten()
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            match escaped {
                Some(decoded) => {
                    at += 2;
                    obfuscated |= decoded.is_ascii_alphanumeric();
                    text.push(decoded);
                }
                None => text.push(byte),
            }
        }
        Some(Name::new(&text, obfuscated))
    }

    fn hex_string(&mut self) -> Option<Value> {
        let length = memchr::memchr(b'>', self.rest())?;
        let digits = &self.rest()[1..length];
        self.pos += length + 1;
        if digits.len() > MAX_STRING * 2 || self.skipping {
            return Some(Value::String(None));
        }
        let mut nibbles = digits
            .iter()
            .filter_map(|&b| char::from(b).to_digit(16))
            .map(|digit| digit as u8);
        let mut bytes = Vec::with_capacity(digits.len() / 2);
        while let Some(high) = nibbles.next() {
            // An odd digit at the end stands for itself followed by zero.
            bytes.push(high << 4 | nibbles.next().unwrap_or(0));
        }
        Some(Value::String(Some(bytes.into())))
    }

    fn literal_string(&mut self) -> Option<Value> {
        let start = self.pos + 1;
        let mut depth = 0usize;
        let mut escapes = false;
        loop {
            let byte = self.peek()?;
            self.pos += 1;
            match byte {
                b'\\' => {
                    escapes = true;
                    self.pos += 1;
                }
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        let raw = &self.data[start..self.pos - 1];
        if raw.len() > MAX_STRING || self.skipping {
            return Some(Value::String(None));
        }
        let bytes = if escapes { unescape(raw) } else { raw.to_vec() };
        Some(Value::String(Some(bytes.into())))
    }

    fn number(&mut self) -> Option<f64> {
        let start = self.pos;
        let mut integer = 0u64;
        let mut digits_only = true;
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' => {
                    integer = integer
                        .wrapping_mul(10)
                        .wrapping_add(u64::from(byte - b'0'))
                }
                b'+' | b'-' | b'.' => digits_only = false,
                _ => break,
            }
            self.pos += 1;
        }
        // Most numbers are integers short enough to be exact.
        if digits_only && (1..=15).contains(&(self.pos - start)) {
            return Some(integer as f64);
        }
        std::str::from_utf8(&self.data[start..self.pos])
            .ok()?
            .parse()
            .ok()
    }

    /// A number, or `N G R` when two integers are followed by the keyword.
    fn number_or_reference(&mut self) -> Option<Value> {
        let number = self.number()?;
        let value = Value::Number(number);
        let after_number = self.pos;
        if let Some(object) = value.as_usize().and_then(|n| u32::try_from(n).ok()) {
            self.skip_whitespace();
            let generation =
                self.peek().is_some_and(|b| b.is_ascii_digit()) && self.number().is_some();
            self.skip_whitespace();
            if generation && self.eat_keyword(b"R") {
                return Some(Value::Ref(object));
            }
            self.pos = after_number;
        }
        Some(value)
    }

    /// A non-negative integer token, as used in object stream headers.
    pub fn integer(&mut self) -> Option<usize> {
        self.skip_whitespace();
        Value::Number(self.number()?).as_usize()
    }
}

/// Undo the backslash escapes of a literal string.
fn unescape(raw: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut at = 0;
    while let Some(&byte) = raw.get(at) {
        at += 1;
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let Some(&escaped) = raw.get(at) else { break };
        at += 1;
        match escaped {
            b'n' => bytes.push(b'\n'),
            b'r' => bytes.push(b'\r'),
            b't' => bytes.push(b'\t'),
            b'b' => bytes.push(8),
            b'f' => bytes.push(12),
            // A backslash before a line break continues the string.
            b'\r' => at += usize::from(raw.get(at) == Some(&b'\n')),
            b'\n' => {}
            b'0'..=b'7' => {
                let mut code = u32::from(escaped - b'0');
                for _ in 0..2 {
                    match raw.get(at) {
                        Some(&digit @ b'0'..=b'7') => {
                            code = code * 8 + u32::from(digit - b'0');
                            at += 1;
                        }
                        _ => break,
                    }
                }
                bytes.push(code as u8);
            }
            other => bytes.push(other),
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Option<Value> {
        Parser::new(text.as_bytes(), 0, 1000).parse_value()
    }

    fn string(text: &str) -> Vec<u8> {
        parse(text).unwrap().as_string().unwrap().to_vec()
    }

    fn name(text: &str) -> Value {
        Value::Name(Name::new(text.as_bytes(), false))
    }

    #[test]
    fn scalars() {
        assert_eq!(parse("null"), Some(Value::Null));
        assert_eq!(parse("0012"), Some(Value::Number(12.0)));
        assert_eq!(
            parse("123456789012345"),
            Some(Value::Number(123456789012345.0))
        );
        assert_eq!(
            parse("12345678901234567890"),
            Some(Value::Number(1.2345678901234567e19))
        );
        assert_eq!(parse("+.5"), Some(Value::Number(0.5)));
        assert_eq!(parse("1.2.3"), None);
        assert_eq!(parse("1-2"), None);
        assert_eq!(parse(" true "), Some(Value::Bool(true)));
        assert_eq!(parse("-12.5"), Some(Value::Number(-12.5)));
        assert_eq!(parse("% comment\n42"), Some(Value::Number(42.0)));
        assert_eq!(string("(a (nested) \\) string)"), b"a (nested) ) string");
        assert_eq!(string("(\\101\\n\\\\\\\nb\\7)"), b"A\n\\b\x07");
        assert_eq!(string("<48656C6C6F>"), b"Hello");
        assert_eq!(string("<4 8 7>"), b"Hp");
        let long = format!("({})", "x".repeat(MAX_STRING + 1));
        assert_eq!(parse(&long), Some(Value::String(None)));
        assert_eq!(parse("/Type"), Some(name("Type")));
        assert_eq!(parse("nullx"), None);
        assert_eq!(parse("(unterminated"), None);
    }

    #[test]
    fn references_need_the_keyword() {
        assert_eq!(parse("12 0 R"), Some(Value::Ref(12)));
        assert_eq!(parse("12 0 Rx"), Some(Value::Number(12.0)));
        assert_eq!(
            parse("[1 2 3 0 R]"),
            Some(Value::Array(
                vec![Value::Number(1.0), Value::Number(2.0), Value::Ref(3)].into()
            ))
        );
    }

    #[test]
    fn names_decode_hex_escapes() {
        let Some(Value::Name(plain)) = parse("/Arial#20Bold") else {
            panic!("not a name");
        };
        assert_eq!(plain.text(), b"Arial Bold");
        assert!(!plain.obfuscated());

        let Some(Value::Name(hidden)) = parse("/J#61vaScr#69pt") else {
            panic!("not a name");
        };
        assert_eq!(hidden.text(), b"JavaScript");
        assert!(hidden.obfuscated());

        let long = "/".to_string() + &"n".repeat(300);
        assert_eq!(parse(&long).unwrap().as_name().unwrap().len(), 300);
        assert!(std::mem::size_of::<Value>() <= 32);
    }

    #[test]
    fn dictionaries_keep_duplicates_and_nest() {
        let Some(Value::Dict(dict)) = parse("<</A 1/B<</C[/D(x)]>>/A 2>>") else {
            panic!("not a dict");
        };
        assert_eq!(dict.0.len(), 3);
        assert_eq!(dict.get(b"A"), Some(&Value::Number(1.0)));
        assert!(dict.get(b"B").and_then(Value::as_dict).is_some());
        assert_eq!(parse("<< /A 1 "), None);
        assert_eq!(parse("<< 1 2 >>"), None);
    }

    #[test]
    fn skipping_ends_where_parsing_does() {
        for text in [
            "<</A 1/B<</C[/D(x)]>>/A 2>> tail",
            "[1 2 3 0 R (a \\) b) <41> /N#41me null true] tail",
            "<< /A [1 2 >>",
            "[ (unterminated ]",
            "1.2.3",
            "<< /A 1 /B >>",
        ] {
            let mut parsing = Parser::new(text.as_bytes(), 0, 1000);
            let mut skipping = Parser::new(text.as_bytes(), 0, 1000);
            assert_eq!(parsing.parse_value().is_some(), skipping.skip_value());
            assert_eq!(parsing.pos, skipping.pos, "{text}");
            assert_eq!(parsing.nodes_left, skipping.nodes_left, "{text}");
        }
        // What a failure leaves behind is not part of the next value.
        let mut parser = Parser::new(b"[1 [2 (x] [3]", 0, 1000);
        assert_eq!(parser.parse_value(), None);
        parser.pos = 10;
        assert_eq!(
            parser.parse_value(),
            Some(Value::Array(vec![Value::Number(3.0)].into()))
        );
    }

    #[test]
    fn large_arrays_and_dictionaries_read_as_small_ones() {
        for count in [SHARED - 1, SHARED, SHARED + 1, SHARED + 2, 5 * SHARED] {
            let array = format!("[7 [{}] 8]", "1 ".repeat(count));
            let Some(Value::Array(outer)) = parse(&array) else {
                panic!("not an array");
            };
            assert_eq!(outer.len(), 3);
            assert_eq!(outer[1].as_array().map(<[Value]>::len), Some(count));
            assert_eq!(outer[2], Value::Number(8.0));

            let entries: String = (0..count).map(|n| format!("/K{n} {n} ")).collect();
            let dict = format!("<< /A 1 /B << {entries} >> /C 3 >>");
            let Some(Value::Dict(outer)) = parse(&dict) else {
                panic!("not a dictionary");
            };
            assert_eq!(outer.0.len(), 3);
            let inner = outer.get(b"B").and_then(Value::as_dict).unwrap();
            assert_eq!(inner.0.len(), count);
            let last = format!("K{}", count - 1);
            assert_eq!(
                inner.get(last.as_bytes()),
                Some(&Value::Number(count as f64 - 1.0))
            );
        }
    }

    #[test]
    fn limits_depth_and_node_count() {
        assert_eq!(parse(&"[".repeat(1000)), None);
        let mut parser = Parser::new(b"[1 2 3 4 5 6]", 0, 4);
        assert_eq!(parser.parse_value(), None);
    }
}
