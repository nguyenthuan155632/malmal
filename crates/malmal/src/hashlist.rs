use std::collections::HashSet;
use std::fmt;

/// SHA-256 blocklist.
#[derive(Debug, Clone, Default)]
pub struct HashList(HashSet<[u8; 32]>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashListError {
    /// 1-based line of the entry that is not a SHA-256 hex digest.
    pub line: usize,
}

impl fmt::Display for HashListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: not a SHA-256 hex digest", self.line)
    }
}

impl std::error::Error for HashListError {}

impl HashList {
    /// One digest per line. Blank lines and `#` comments are skipped, and
    /// anything after the digest is ignored so `sha256sum` output loads as is.
    pub fn parse(text: &str) -> Result<Self, HashListError> {
        let mut list = Self::default();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let digest = line.split_whitespace().next().unwrap_or("");
            let hash = decode_hex(digest).ok_or(HashListError { line: index + 1 })?;
            list.0.insert(hash);
        }
        Ok(list)
    }

    pub fn insert(&mut self, hash: [u8; 32]) {
        self.0.insert(hash);
    }

    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.0.contains(hash)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn decode_hex(digest: &str) -> Option<[u8; 32]> {
    let bytes = digest.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, &[high, low]) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let high = (high as char).to_digit(16)?;
        let low = (low as char).to_digit(16)?;
        *byte = (high * 16 + low) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    #[test]
    fn parses_comments_blank_lines_and_sha256sum_output() {
        let text = format!(
            "# blocklist\n\n{DIGEST}  eicar.com\n{}\n",
            DIGEST.to_uppercase()
        );
        let list = HashList::parse(&text).unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains(&decode_hex(DIGEST).unwrap()));
        assert!(!list.contains(&[0; 32]));
    }

    #[test]
    fn rejects_malformed_entries_with_line_number() {
        let text = format!("{DIGEST}\nnot-a-hash\n");
        assert_eq!(
            HashList::parse(&text).unwrap_err(),
            HashListError { line: 2 }
        );
        assert!(HashList::parse(&DIGEST[..62]).is_err());
    }
}
