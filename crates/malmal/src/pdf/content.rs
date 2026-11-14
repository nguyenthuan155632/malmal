//! The operators of a content stream, read a block at a time: the stream is
//! never held whole, and what is remembered between blocks is a few bytes.
//!
//! Two things in a content stream can only be told at its end. A string
//! whose parenthesis never closes is no string, and what follows it is read
//! as content; inline image data with no `EI` behind it is content too.
//! Where either is open at the end of a block, the bytes that follow are
//! read both ways, and the reading that did not come true is dropped.

use super::parser::{Parser, is_regular, is_whitespace};

/// Names one content stream is remembered to draw.
const MAX_DRAWN: usize = 4096;
/// Bytes kept of a token that crosses blocks. No operator that is looked
/// for is longer than two.
const MAX_TOKEN: usize = 8;
/// Bytes kept of a name, as written.
const MAX_NAME: usize = 4096;

/// The operand of a `Do` operator.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Drawn {
    Name(Vec<u8>),
    /// A name longer than is kept.
    Long,
}

impl Drawn {
    /// Whether this is the name `key`. A name too long to have been kept is
    /// taken for any key that may have been as long.
    pub fn is(&self, key: &[u8]) -> bool {
        match self {
            Self::Name(name) => name == key,
            // An escape is three bytes for one.
            Self::Long => key.len() > MAX_NAME / 3,
        }
    }
}

/// What a content stream turned out to hold.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Found {
    /// The `PS` operator, which hands its string operand to a PostScript
    /// interpreter.
    pub postscript: bool,
    /// What `Do` is called with, up to the first `PS`.
    pub drawn: Vec<Drawn>,
}

#[derive(Clone, Copy)]
enum State {
    Between,
    Comment,
    /// In a string: how deep in parentheses, and whether a backslash is
    /// waiting for the byte it escapes.
    String {
        depth: usize,
        escaped: bool,
    },
    /// After a `<`, which opens a hexadecimal string unless another follows.
    Less,
    Hex,
    Token,
    Name,
    /// In the data of an inline image, with this much seen of the `EI`
    /// after whitespace that ends it.
    Image(End),
}

#[derive(Clone, Copy, PartialEq)]
enum End {
    Nothing,
    Space,
    E,
    /// `EI`, which counts if no regular character follows.
    Both,
}

/// Call [`Operators::feed`] with the stream in order, in pieces of any
/// size, then [`Operators::finish`].
pub(super) struct Operators {
    state: State,
    /// A string ran to the end of the stream, so every later one does, and
    /// its parenthesis is stepped over.
    unclosed: bool,
    /// The data of an inline image ran to the end of the stream, so no
    /// later image is looked for the end of.
    unending: bool,
    /// The start of a token that a block ended in.
    token: [u8; MAX_TOKEN],
    token_len: usize,
    /// The last name read, as written and with its slash.
    name: Vec<u8>,
    name_long: bool,
    /// That name came before the next token: its operand, for the operators
    /// that take a name.
    named: bool,
    found: Found,
    /// How many more names may be remembered.
    room: usize,
    /// The reading that holds if the string or image now open never ends.
    other: Option<Box<Operators>>,
}

impl Operators {
    pub fn new() -> Self {
        Self {
            state: State::Between,
            unclosed: false,
            unending: false,
            token: [0; MAX_TOKEN],
            token_len: 0,
            name: Vec::new(),
            name_long: false,
            named: false,
            found: Found::default(),
            room: MAX_DRAWN,
            other: None,
        }
    }

    /// A reader for what follows, should it turn out to be content.
    fn fork(&self, unclosed: bool, unending: bool) -> Box<Self> {
        Box::new(Self {
            unclosed,
            unending,
            name: self.name.clone(),
            name_long: self.name_long,
            named: self.named,
            room: self.room - self.found.drawn.len(),
            ..Self::new()
        })
    }

    pub fn feed(&mut self, block: &[u8]) {
        let mut pos = 0;
        // Nothing after the operator is looked at.
        while pos < block.len() && !self.found.postscript {
            let rest = &block[pos..];
            pos += match self.state {
                State::Between => self.between(rest),
                State::Comment => {
                    let end = memchr::memchr2(b'\n', b'\r', rest);
                    self.leave(end, rest)
                }
                State::String { .. } => self.string(rest, false),
                // The first of two is stepped over; the second is looked
                // at as the first was.
                State::Less => {
                    self.state = match rest[0] {
                        b'<' => State::Between,
                        _ => State::Hex,
                    };
                    0
                }
                State::Hex => self.leave(memchr::memchr(b'>', rest), rest),
                State::Token => {
                    let length = regular(rest);
                    let kept = length.min(MAX_TOKEN.saturating_sub(self.token_len));
                    let start = self.token_len.min(MAX_TOKEN);
                    self.token[start..start + kept].copy_from_slice(&rest[..kept]);
                    self.token_len = self.token_len.saturating_add(length);
                    if length < rest.len() {
                        self.end_token();
                    }
                    length
                }
                State::Name => {
                    let length = regular(rest);
                    self.name_more(&rest[..length]);
                    if length < rest.len() {
                        self.named = true;
                        self.state = State::Between;
                    }
                    length
                }
                State::Image(_) => self.image(rest),
            };
        }
    }

    /// Back between tokens at `end`, if what was being skipped ends in
    /// `rest`. Returns how much of `rest` was read.
    fn leave(&mut self, end: Option<usize>, rest: &[u8]) -> usize {
        if end.is_some() {
            self.state = State::Between;
        }
        end.unwrap_or(rest.len())
    }

    fn name_more(&mut self, bytes: &[u8]) {
        let kept = bytes
            .len()
            .min((MAX_NAME + 1).saturating_sub(self.name.len()));
        self.name.extend_from_slice(&bytes[..kept]);
        self.name_long |= kept < bytes.len();
    }

    /// Read on between tokens, through the tokens, names and strings that
    /// end in `rest`, which most do. Returns how much of `rest` was read.
    fn between(&mut self, rest: &[u8]) -> usize {
        let mut pos = 0;
        while let Some(&byte) = rest.get(pos) {
            if is_regular(byte) {
                let length = regular(&rest[pos..]);
                if pos + length == rest.len() {
                    self.token_len = 0;
                    self.state = State::Token;
                    break;
                }
                self.operator(&rest[pos..pos + length]);
                pos += length;
                if self.found.postscript || !matches!(self.state, State::Between) {
                    break;
                }
                continue;
            }
            pos += 1;
            match byte {
                b'%' => self.state = State::Comment,
                b'(' if !self.unclosed => {
                    self.state = State::String {
                        depth: 1,
                        escaped: false,
                    };
                    pos += self.string(&rest[pos..], true);
                }
                b'<' => self.state = State::Less,
                b'/' => {
                    self.name.clear();
                    self.name.push(b'/');
                    self.name_long = false;
                    let length = regular(&rest[pos..]);
                    self.name_more(&rest[pos..pos + length]);
                    pos += length;
                    if pos == rest.len() {
                        self.state = State::Name;
                    } else {
                        self.named = true;
                    }
                }
                _ => {}
            }
            if !matches!(self.state, State::Between) {
                break;
            }
        }
        pos
    }

    /// Read on in a string. Returns how much of `rest` was read: to the
    /// parenthesis that closes the string, or all of it. `opening` says
    /// that the string opened just before `rest`.
    fn string(&mut self, rest: &[u8], opening: bool) -> usize {
        let State::String {
            mut depth,
            mut escaped,
        } = self.state
        else {
            return 0;
        };
        // A backslash at the end of the last block took the first byte.
        let mut pos = usize::from(escaped && !rest.is_empty());
        escaped &= rest.is_empty();
        while let Some(length) = memchr::memchr3(b'\\', b'(', b')', &rest[pos..]) {
            pos += length + 1;
            match rest[pos - 1] {
                b'\\' if pos == rest.len() => escaped = true,
                b'\\' => pos += 1,
                b'(' => depth += 1,
                _ => depth -= 1,
            }
            if depth == 0 {
                self.other = None;
                self.state = State::Between;
                return pos;
            }
        }
        self.state = State::String { depth, escaped };
        if opening {
            self.other = Some(self.fork(true, self.unending));
        }
        if let Some(other) = &mut self.other {
            other.feed(rest);
        }
        rest.len()
    }

    /// Read on in the data of an inline image. Returns how much of `rest`
    /// was read: up to the byte that follows `EI`, or all of it.
    fn image(&mut self, rest: &[u8]) -> usize {
        let State::Image(mut end) = self.state else {
            return 0;
        };
        for (index, &byte) in rest.iter().enumerate() {
            end = match (end, byte) {
                (End::Both, _) if !is_regular(byte) => {
                    self.end_image();
                    return index;
                }
                (End::Space, b'E') => End::E,
                (End::E, b'I') => End::Both,
                _ if is_whitespace(byte) => End::Space,
                _ => End::Nothing,
            };
        }
        self.state = State::Image(end);
        if let Some(other) = &mut self.other {
            other.feed(rest);
        }
        rest.len()
    }

    /// The image data is over; the `EI` behind it is a token like any other.
    fn end_image(&mut self) {
        self.other = None;
        self.token[..2].copy_from_slice(b"EI");
        self.token_len = 2;
        self.state = State::Token;
    }

    /// A token that began in an earlier block has ended.
    fn end_token(&mut self) {
        self.state = State::Between;
        let token = self.token;
        // What is kept of a longer one is longer than any operator.
        self.operator(&token[..self.token_len.min(MAX_TOKEN)]);
    }

    fn operator(&mut self, token: &[u8]) {
        let named = std::mem::take(&mut self.named);
        match token {
            b"PS" => self.found.postscript = true,
            b"Do" if named && self.found.drawn.len() < self.room => {
                let name = if self.name_long {
                    Drawn::Long
                } else {
                    let mut parser = Parser::new(&self.name, 0, usize::MAX);
                    Drawn::Name(
                        parser
                            .name()
                            .map_or(Vec::new(), |name| name.text().to_vec()),
                    )
                };
                self.found.drawn.push(name);
            }
            // Inline image data is binary up to the `EI` that closes it.
            b"ID" if !self.unending => {
                self.state = State::Image(End::Nothing);
                self.other = Some(self.fork(self.unclosed, true));
            }
            _ => {}
        }
    }

    /// The stream has ended.
    pub fn finish(mut self) -> Found {
        if self.found.postscript {
            return self.found;
        }
        match self.state {
            State::Token => self.end_token(),
            State::Image(End::Both) => {
                self.end_image();
                self.end_token();
            }
            _ => {}
        }
        // What was open never closed: the other reading was the right one.
        if let State::String { .. } | State::Image(_) = self.state
            && let Some(other) = self.other.take()
        {
            let rest = other.finish();
            self.found.postscript = rest.postscript;
            self.found.drawn.extend(rest.drawn);
        }
        self.found
    }
}

/// How many regular characters `bytes` starts with.
fn regular(bytes: &[u8]) -> usize {
    let end = bytes.iter().position(|&byte| !is_regular(byte));
    end.unwrap_or(bytes.len())
}

/// What `content`, a stream at hand in one piece, holds.
pub(super) fn scan(content: &[u8]) -> Found {
    let mut operators = Operators::new();
    operators.feed(content);
    operators.finish()
}

#[cfg(test)]
mod tests {
    use memchr::memmem;

    use super::*;

    /// The reader this one replaced, which had the stream in one piece. Call
    /// `visit` with every token of a content stream that stands outside
    /// strings, names and comments, and with the name that came before it,
    /// if one did. Stops and returns true once `visit` does.
    fn for_each_operator(
        content: &[u8],
        mut visit: impl FnMut(&[u8], Option<&[u8]>) -> bool,
    ) -> bool {
        let mut unclosed_string = false;
        let mut last_name: Option<Vec<u8>> = None;
        let mut pos = 0;
        while let Some(&byte) = content.get(pos) {
            match byte {
                b'%' => {
                    pos += memchr::memchr2(b'\n', b'\r', &content[pos..]).unwrap_or(content.len())
                }
                // Once a string runs to the end, so does every later one: step
                // over the parenthesis so that it cannot hide what follows.
                b'(' if unclosed_string => pos += 1,
                b'(' => {
                    let start = pos;
                    let mut depth = 0usize;
                    while let Some(&inner) = content.get(pos) {
                        pos += 1;
                        match inner {
                            b'\\' => pos += 1,
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            _ => {}
                        }
                        if depth == 0 {
                            break;
                        }
                    }
                    if depth > 0 {
                        unclosed_string = true;
                        pos = start + 1;
                    }
                }
                b'<' if content.get(pos + 1) != Some(&b'<') => {
                    pos += memchr::memchr(b'>', &content[pos..]).unwrap_or(content.len());
                }
                _ if is_regular(byte) => {
                    let length = content[pos..]
                        .iter()
                        .take_while(|&&b| is_regular(b))
                        .count();
                    let token = &content[pos..pos + length];
                    if visit(token, last_name.take().as_deref()) {
                        return true;
                    }
                    pos += length;
                    // Inline image data is binary up to the `EI` that closes it.
                    if token == b"ID" {
                        let end = memmem::find_iter(&content[pos..], b"EI").find(|&at| {
                            let before = content[pos + at - 1];
                            let after = content.get(pos + at + 2);
                            is_whitespace(before) && after.is_none_or(|&b| !is_regular(b))
                        });
                        pos += end.unwrap_or(0);
                    }
                }
                b'/' => {
                    let mut parser = Parser::new(content, pos, usize::MAX);
                    last_name = parser.name().map(|name| name.text().to_vec());
                    pos = parser.pos;
                }
                _ => pos += 1,
            }
        }
        false
    }

    /// What the callers made of the stream in one piece.
    fn in_one_piece(content: &[u8]) -> Found {
        let mut drawn = Vec::new();
        let postscript = for_each_operator(content, |token, name| {
            if token == b"Do"
                && let Some(name) = name
                && drawn.len() < MAX_DRAWN
            {
                drawn.push(Drawn::Name(name.to_vec()));
            }
            token == b"PS"
        });
        Found { postscript, drawn }
    }

    fn in_blocks(content: &[u8], size: usize) -> Found {
        let mut operators = Operators::new();
        for block in content.chunks(size) {
            operators.feed(block);
        }
        operators.finish()
    }

    fn drawn(content: &[u8]) -> Vec<Drawn> {
        scan(content).drawn
    }

    #[test]
    fn operators_and_their_names() {
        assert!(scan(b"BT (text) Tj ET\n(1 2 moveto) PS\n").postscript);
        assert!(scan(b"(x)PS").postscript);
        // The same letters as a string, a name, a comment or part of a word.
        assert!(!scan(b"(PS) Tj <5053> Tj /PS gs % PS\nPSx EPS BT ET").postscript);
        assert_eq!(
            drawn(b"q /A Do Q /B#20C (s) Do Do"),
            [Drawn::Name(b"A".to_vec()), Drawn::Name(b"B C".to_vec())]
        );
        assert_eq!(drawn(b"(/A Do) Tj"), []);
        // Neither inline image data nor a stray parenthesis hides anything.
        for hidden in [
            &b"BI /W 1 /H 1 ID (\x00 EI (x) PS"[..],
            b"BI /W 1 /H 1 ID \x00) EI (x) PS",
            b"( (x) PS",
            b"BI ID ( (x) PS",
            b"( BI ID (x) PS",
        ] {
            assert!(scan(hidden).postscript, "{hidden:?}");
        }
    }

    #[test]
    fn long_tokens_and_names_are_not_kept() {
        let mut content = b"PS".repeat(4096);
        content.extend_from_slice(b" /");
        content.extend(vec![b'n'; MAX_NAME + 1]);
        content.extend_from_slice(b" Do");
        assert_eq!(
            scan(&content),
            Found {
                postscript: false,
                drawn: vec![Drawn::Long],
            }
        );
        assert!(Drawn::Long.is(&vec![b'n'; MAX_NAME + 1]));
        assert!(!Drawn::Long.is(b"n"));
    }

    /// Streams made of the pieces that the reader treats differently, in a
    /// fixed order of orders.
    fn streams() -> impl Iterator<Item = Vec<u8>> {
        const PIECES: [&[u8]; 40] = [
            b"(", b")", b"\\", b"(a)", b"((b)c)", b"<", b"<<", b">", b">>", b"<41>", b"%", b"\n",
            b"\r", b" ", b"/", b"/A", b"/B#20C", b"/#", b"Do", b"PS", b"ID", b"EI", b"BI", b"E",
            b"I", b"D", b"P", b"S", b"o", b"q", b"\0", b"\t", b"[", b"]", b"{", b"12", b"/Do",
            b"/PS", b" EI ", b"x",
        ];
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut below = move |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % bound as u64) as usize
        };
        (0..20_000).map(move |_| {
            let mut stream = Vec::new();
            for _ in 0..below(24) {
                stream.extend_from_slice(PIECES[below(PIECES.len())]);
                if below(3) == 0 {
                    stream.push(b' ');
                }
            }
            stream
        })
    }

    #[test]
    fn blocks_of_any_size_read_as_one_piece() {
        for stream in streams() {
            let expected = in_one_piece(&stream);
            for size in [1, 2, 3, 5, 7, 16, usize::MAX] {
                assert_eq!(
                    in_blocks(&stream, size),
                    expected,
                    "{:?} in blocks of {size}",
                    String::from_utf8_lossy(&stream)
                );
            }
        }
    }
}
