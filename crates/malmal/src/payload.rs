//! Byte-pattern search for server-side and browser-side code hidden in files.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Php,
    /// HTML/JavaScript a browser would run.
    Script,
    /// ASP/JSP template tags.
    Template,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Content that may legitimately hold markup or ASCII-armoured data (PDF,
    /// PostScript, SVG): only the full PHP opening tag is matched.
    Mixed,
    /// Bytes that should hold no code at all, such as a raster image or its
    /// decoded metadata: every pattern is matched.
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHit {
    pub kind: PayloadKind,
    pub offset: usize,
}

/// What must follow a pattern for it to count. Keeps short patterns from
/// matching by chance in megabytes of compressed data.
#[derive(Clone, Copy)]
enum Tail {
    Any,
    /// PHP only treats `<?php` as a tag when whitespace follows.
    Whitespace,
    /// A complete tag must follow: source text that starts an expression,
    /// reaches a variable, call or string, and is closed by the given bytes
    /// or by the end of the file. The interpreter compiles the whole file
    /// before running any of it, so a tag left open into binary data never
    /// runs.
    Code(&'static [u8]),
    /// An ASP or JSP directive must follow: `<%@ page ... %>`.
    Directive,
}

/// Uncompressed pixels are often runs of printable bytes, so a text run
/// alone does not make a short tag.
const CODE_TAIL_WINDOW: usize = 4096;
/// No PHP, ASP or JSP expression starts with one of these.
const NOT_AN_EXPRESSION_START: &[u8] = b"<>?=;)]},:/*%^|";
/// Ends PHP compilation as a closing tag does.
const HALT_COMPILER: &[u8] = b"__halt_compiler";

impl Tail {
    fn accepts(self, rest: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Whitespace => rest.first().is_none_or(u8::is_ascii_whitespace),
            Self::Directive => {
                let text = leading_text(rest);
                let Some(length) = find(text, b"%>") else {
                    return false;
                };
                let directive = text[..length].trim_ascii_start();
                let word = directive
                    .iter()
                    .take_while(|b| b.is_ascii_alphabetic())
                    .count();
                word >= 4
                    && directive[word..]
                        .first()
                        .is_some_and(|&b| b.is_ascii_whitespace() || b == b'=')
                    && is_balanced(directive)
            }
            Self::Code(close) => {
                let text = leading_text(rest);
                let text_len = text.len();
                let closed = [close, HALT_COMPILER]
                    .iter()
                    .filter_map(|end| find(text, end))
                    .min();
                let code = match closed {
                    Some(length) => &text[..length],
                    None if text_len == rest.len() => text,
                    None => return false,
                };
                let starts_expression = code
                    .iter()
                    .find(|b| !b.is_ascii_whitespace())
                    .is_some_and(|b| !NOT_AN_EXPRESSION_START.contains(b));
                starts_expression && is_balanced(code) && reaches_something(code)
            }
        }
    }
}

/// The printable ASCII that `rest` starts with, up to a fixed window.
fn leading_text(rest: &[u8]) -> &[u8] {
    let window = &rest[..rest.len().min(CODE_TAIL_WINDOW)];
    let length = window
        .iter()
        .position(|b| !(b.is_ascii_graphic() || b.is_ascii_whitespace()))
        .unwrap_or(window.len());
    &window[..length]
}

/// Whether every bracket and quote in `code` is closed in order, as it is
/// in source text and almost never in pixels that happen to be printable.
fn is_balanced(code: &[u8]) -> bool {
    let mut open = Vec::new();
    let mut bytes = code.iter();
    while let Some(&byte) = bytes.next() {
        match byte {
            b'(' => open.push(b')'),
            b'[' => open.push(b']'),
            b'{' => open.push(b'}'),
            b')' | b']' | b'}' if open.pop() != Some(byte) => return false,
            b'\'' | b'"' | b'`' => loop {
                match bytes.next() {
                    Some(b'\\') => {
                        bytes.next();
                    }
                    Some(&end) if end == byte => break,
                    Some(_) => {}
                    None => return false,
                }
            },
            _ => {}
        }
    }
    open.is_empty()
}

/// Whether `code` calls something, runs a shell command or includes a file.
/// Printing a variable does none of these.
fn reaches_something(code: &[u8]) -> bool {
    let is_name_start = |b: u8| b.is_ascii_alphabetic() || b == b'_';
    let calls = code.iter().enumerate().any(|(index, &byte)| match byte {
        b'`' => true,
        b'(' => {
            let callee = code[..index].trim_ascii_end();
            let length = callee
                .iter()
                .rev()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'.')
                .count();
            let name = &callee[callee.len() - length..];
            match callee[..callee.len() - length].last() {
                // `$f(...)`, `$a[0](...)`, `f()(...)`
                Some(b'$') => length > 0,
                Some(b']' | b')' | b'}') if length == 0 => true,
                _ => length >= 2 && is_name_start(name[0]),
            }
        }
        _ => false,
    });
    let lower = code.to_ascii_lowercase();
    calls || find(&lower, b"include").is_some() || find(&lower, b"require").is_some()
}

struct Pattern {
    kind: PayloadKind,
    /// Lowercase; matched ASCII case-insensitively.
    bytes: &'static [u8],
    tail: Tail,
    binary_only: bool,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        kind: PayloadKind::Php,
        bytes: b"<?php",
        tail: Tail::Whitespace,
        binary_only: false,
    },
    Pattern {
        kind: PayloadKind::Php,
        bytes: b"<?=",
        tail: Tail::Code(b"?>"),
        binary_only: true,
    },
    Pattern {
        kind: PayloadKind::Script,
        bytes: b"<script",
        tail: Tail::Any,
        binary_only: true,
    },
    Pattern {
        kind: PayloadKind::Script,
        bytes: b"<iframe",
        tail: Tail::Any,
        binary_only: true,
    },
    Pattern {
        kind: PayloadKind::Script,
        bytes: b"javascript:",
        tail: Tail::Any,
        binary_only: true,
    },
    Pattern {
        kind: PayloadKind::Template,
        bytes: b"<%@",
        tail: Tail::Directive,
        binary_only: true,
    },
    Pattern {
        kind: PayloadKind::Template,
        bytes: b"<%=",
        tail: Tail::Code(b"%>"),
        binary_only: true,
    },
];

/// Earliest hit of each payload kind present in `data`, ordered by offset.
pub fn scan(data: &[u8], scope: Scope) -> Vec<PayloadHit> {
    let mut hits: Vec<PayloadHit> = Vec::new();
    // Every pattern starts with one of these bytes; anything else is skipped
    // at memchr speed.
    for offset in memchr::memchr3_iter(b'<', b'j', b'J', data) {
        let rest = &data[offset..];
        for pattern in PATTERNS {
            if pattern.binary_only && scope == Scope::Mixed {
                continue;
            }
            if hits.iter().any(|hit| hit.kind == pattern.kind) {
                continue;
            }
            let matches = rest
                .get(..pattern.bytes.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(pattern.bytes));
            if matches && pattern.tail.accepts(&rest[pattern.bytes.len()..]) {
                hits.push(PayloadHit {
                    kind: pattern.kind,
                    offset,
                });
            }
        }
    }
    hits
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(data: &[u8], scope: Scope) -> Vec<PayloadKind> {
        scan(data, scope).iter().map(|hit| hit.kind).collect()
    }

    #[test]
    fn finds_php_in_any_case() {
        let hits = scan(
            b"\xFF\xD8\xFF junk <?PhP system($_GET[0]); ?>",
            Scope::Mixed,
        );
        assert_eq!(
            hits,
            [PayloadHit {
                kind: PayloadKind::Php,
                offset: 9
            }]
        );
    }

    #[test]
    fn php_tag_needs_trailing_whitespace() {
        assert!(scan(b"<?phpx", Scope::Binary).is_empty());
        assert_eq!(kinds(b"<?php\n", Scope::Mixed), [PayloadKind::Php]);
        assert_eq!(kinds(b"<?php", Scope::Mixed), [PayloadKind::Php]);
    }

    #[test]
    fn short_patterns_only_match_in_binary_scope() {
        let data = b"xx <?= `id` ?> <%= eval(request(1)) %>";
        assert!(scan(data, Scope::Mixed).is_empty());
        assert_eq!(
            kinds(data, Scope::Binary),
            [PayloadKind::Php, PayloadKind::Template]
        );
    }

    #[test]
    fn short_patterns_need_a_code_tail() {
        assert!(scan(b"<?=\x00\x9c\x01binary", Scope::Binary).is_empty());
        assert!(scan(b"<%=abcdefghijk%>", Scope::Binary).is_empty());
        // Open into binary data, so it never compiles.
        assert!(scan(b"<?=eval($_GET[0]);\xFF", Scope::Binary).is_empty());
        assert_eq!(
            kinds(b"<?=eval($_GET[0]);", Scope::Binary),
            [PayloadKind::Php]
        );
        assert_eq!(
            kinds(b"<?=eval($_GET[0]);__halt_compiler();\xFF", Scope::Binary),
            [PayloadKind::Php]
        );
        // Seen in uncompressed PSD pixels.
        assert!(scan(b"<?=J84J7L4(?>G8I&F=0<1B5+FD$75>", Scope::Binary).is_empty());
        assert!(scan(b"<?=@BBA=<EC:@=<DCA?BGB@CDABE>78$A=;?;>", Scope::Binary).is_empty());
        for shell in [
            &b"<?=$_GET[0]($_GET[1])?>"[..],
            b"<?=$f('id')?>",
            b"<?=include$_GET[0]?>",
        ] {
            assert_eq!(kinds(shell, Scope::Binary), [PayloadKind::Php], "{shell:?}");
        }
        assert!(scan(b"<?=9416:5011/.)%'-./-.7@>626;?>", Scope::Binary).is_empty());
        assert_eq!(
            kinds(
                b"<%=Runtime.getRuntime().exec(request.getParameter(\"c\"))%>",
                Scope::Binary
            ),
            [PayloadKind::Template]
        );
        assert_eq!(
            kinds(
                b"<%@ page import=\"java.io.*\" %><% out.print(1); %>",
                Scope::Binary
            ),
            [PayloadKind::Template]
        );
        assert!(scan(b"<%@KX``XUZ[OCIYdfecdgmsst%>", Scope::Binary).is_empty());
        assert_eq!(
            kinds(b"<%@ Language=VBScript %>", Scope::Binary),
            [PayloadKind::Template]
        );
        // Seen in a JPEG quantization table and in PNG image data.
        assert!(scan(b"<?=<;<=>>==>>>>>>=>>>>>?>>>?>>\xFF", Scope::Binary).is_empty());
        assert!(scan(b"<?=??=?===?=??=\x89", Scope::Binary).is_empty());
        assert!(scan(b"<?=3;1956>><2<08\xD8", Scope::Binary).is_empty());
        assert_eq!(
            kinds(b"<?= system('id') ?>", Scope::Binary),
            [PayloadKind::Php]
        );
        assert_eq!(
            kinds(b"<?=`$_GET[0]`?>\xFF", Scope::Binary),
            [PayloadKind::Php]
        );
    }

    #[test]
    fn reports_earliest_offset_per_kind() {
        let hits = scan(b"JaVaScRiPt:alert(1) <script>", Scope::Binary);
        assert_eq!(
            hits,
            [PayloadHit {
                kind: PayloadKind::Script,
                offset: 0
            }]
        );
    }

    #[test]
    fn clean_data_has_no_hits() {
        assert!(scan(b"", Scope::Binary).is_empty());
        assert!(scan(b"just a caption < 3", Scope::Binary).is_empty());
    }
}
