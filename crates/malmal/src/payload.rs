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
    /// The next bytes must read as source text.
    Text,
}

const TEXT_TAIL_LEN: usize = 12;

impl Tail {
    fn accepts(self, rest: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Whitespace => rest.first().is_none_or(u8::is_ascii_whitespace),
            Self::Text => rest
                .iter()
                .take(TEXT_TAIL_LEN)
                .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()),
        }
    }
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
        tail: Tail::Text,
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
        tail: Tail::Text,
        binary_only: true,
    },
    Pattern {
        kind: PayloadKind::Template,
        bytes: b"<%=",
        tail: Tail::Text,
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
        let data = b"xx <?= `id` ?> <%= 1 %>";
        assert!(scan(data, Scope::Mixed).is_empty());
        assert_eq!(
            kinds(data, Scope::Binary),
            [PayloadKind::Php, PayloadKind::Template]
        );
    }

    #[test]
    fn short_patterns_need_a_text_tail() {
        assert!(scan(b"<?=\x00\x9c\x01binary", Scope::Binary).is_empty());
        assert!(scan(b"<%=abcdefghijk\xFF", Scope::Binary).is_empty());
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
