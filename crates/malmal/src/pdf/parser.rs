//! PDF object syntax. Malicious files are routinely malformed on purpose, so
//! parsing either yields a value or fails cleanly; the caller decides how to
//! treat what could not be read.

const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Name {
    /// Bytes after `#xx` escapes are decoded.
    pub text: Vec<u8>,
    /// A letter or digit was written as a `#xx` escape. No PDF writer does
    /// that; it is how keywords are hidden from naive scanners.
    pub obfuscated: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(f64),
    /// String contents are never inspected, so they are not kept.
    String,
    Name(Name),
    Array(Vec<Value>),
    Dict(Dict),
    /// Indirect reference by object number.
    Ref(u32),
}

/// Entries in file order. Duplicate keys are kept: which one a reader
/// honours differs between readers, so all of them are inspected.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Dict(pub Vec<(Name, Value)>);

impl Dict {
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        self.0
            .iter()
            .find(|(name, _)| name.text == key)
            .map(|(_, value)| value)
    }
}

impl Value {
    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Self::Name(name) => Some(&name.text),
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
            Self::Number(n) if n >= 0.0 && n.fract() == 0.0 && n < 1e15 => Some(n as usize),
            _ => None,
        }
    }
}

pub(crate) fn is_whitespace(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

pub(crate) fn is_regular(byte: u8) -> bool {
    !is_whitespace(byte) && !is_delimiter(byte)
}

pub(crate) struct Parser<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    /// Values this parser may still allocate; parsing fails at zero so a
    /// file of millions of tiny tokens cannot exhaust memory.
    pub nodes_left: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8], pos: usize, nodes_left: usize) -> Self {
        Self {
            data,
            pos,
            nodes_left,
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
        self.value(0)
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.nodes_left = self.nodes_left.checked_sub(1)?;
        self.skip_whitespace();
        match self.peek()? {
            b'<' if self.rest().starts_with(b"<<") => self.dict(depth),
            b'<' => {
                self.pos += memchr::memchr(b'>', self.rest())? + 1;
                Some(Value::String)
            }
            b'(' => self.literal_string(),
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_whitespace();
                    if self.peek()? == b']' {
                        self.pos += 1;
                        return Some(Value::Array(items));
                    }
                    items.push(self.value(depth + 1)?);
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
        let mut entries = Vec::new();
        loop {
            self.skip_whitespace();
            if self.rest().starts_with(b">>") {
                self.pos += 2;
                return Some(Value::Dict(Dict(entries)));
            }
            if self.peek()? != b'/' {
                return None;
            }
            let key = self.name()?;
            let value = self.value(depth + 1)?;
            entries.push((key, value));
        }
    }

    /// A name token starting at the current `/`.
    pub fn name(&mut self) -> Option<Name> {
        self.pos += 1;
        let mut text = Vec::new();
        let mut obfuscated = false;
        while let Some(byte) = self.peek().filter(|&b| is_regular(b)) {
            self.pos += 1;
            let escaped = (byte == b'#')
                .then(|| self.data.get(self.pos..self.pos + 2))
                .flatten()
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            match escaped {
                Some(decoded) => {
                    self.pos += 2;
                    obfuscated |= decoded.is_ascii_alphanumeric();
                    text.push(decoded);
                }
                None => text.push(byte),
            }
        }
        Some(Name { text, obfuscated })
    }

    fn literal_string(&mut self) -> Option<Value> {
        let mut depth = 0usize;
        loop {
            let byte = self.peek()?;
            self.pos += 1;
            match byte {
                b'\\' => self.pos += 1,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(Value::String);
                    }
                }
                _ => {}
            }
        }
    }

    fn number(&mut self) -> Option<f64> {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| matches!(b, b'+' | b'-' | b'.' | b'0'..=b'9'))
        {
            self.pos += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Option<Value> {
        Parser::new(text.as_bytes(), 0, 1000).parse_value()
    }

    fn name(text: &str) -> Value {
        Value::Name(Name {
            text: text.as_bytes().to_vec(),
            obfuscated: false,
        })
    }

    #[test]
    fn scalars() {
        assert_eq!(parse("null"), Some(Value::Null));
        assert_eq!(parse(" true "), Some(Value::Bool(true)));
        assert_eq!(parse("-12.5"), Some(Value::Number(-12.5)));
        assert_eq!(parse("% comment\n42"), Some(Value::Number(42.0)));
        assert_eq!(parse("(a (nested) \\) string)"), Some(Value::String));
        assert_eq!(parse("<48656C6C6F>"), Some(Value::String));
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
            Some(Value::Array(vec![
                Value::Number(1.0),
                Value::Number(2.0),
                Value::Ref(3),
            ]))
        );
    }

    #[test]
    fn names_decode_hex_escapes() {
        let Some(Value::Name(plain)) = parse("/Arial#20Bold") else {
            panic!("not a name");
        };
        assert_eq!(plain.text, b"Arial Bold");
        assert!(!plain.obfuscated);

        let Some(Value::Name(hidden)) = parse("/J#61vaScr#69pt") else {
            panic!("not a name");
        };
        assert_eq!(hidden.text, b"JavaScript");
        assert!(hidden.obfuscated);
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
    fn limits_depth_and_node_count() {
        assert_eq!(parse(&"[".repeat(1000)), None);
        let mut parser = Parser::new(b"[1 2 3 4 5 6]", 0, 4);
        assert_eq!(parser.parse_value(), None);
    }
}
