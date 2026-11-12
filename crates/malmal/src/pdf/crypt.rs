//! The standard security handler.
//!
//! A PDF "protected against copying" is encrypted with a key anyone can
//! derive: readers open it without asking. Such a file hides its object
//! streams and embedded files from a scanner that stops at `/Encrypt`, so
//! the key is derived here the way a reader does it, from the empty password
//! or from one the caller supplied. A file that none of them opens stays
//! unreadable and is reported as such.

use std::ops::Range;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use md5::{Digest, Md5};
use sha2::{Sha256, Sha384, Sha512};

use super::parser::{Parser, Value};

/// The padding string that stands in for a missing password.
const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];
const BLOCK: usize = 16;
/// Rounds of the revision 6 hash; it normally ends within a few past 64.
const MAX_HASH_ROUNDS: usize = 1024;
/// Longest password revisions 5 and 6 look at, in bytes of UTF-8.
const MAX_PASSWORD: usize = 127;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Identity,
    Rc4,
    /// AES-128 in CBC mode with a key derived per object.
    AesV2,
    /// AES-256 in CBC mode with the file key.
    AesV3,
}

/// What a stream is, as far as choosing its crypt filter goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamKind {
    Ordinary,
    EmbeddedFile,
    Metadata,
    /// Cross-reference streams are never encrypted.
    CrossReference,
}

#[derive(Debug)]
pub(crate) struct Decryptor {
    key: Vec<u8>,
    streams: Method,
    embedded_files: Method,
    encrypt_metadata: bool,
}

/// Top-level entries of the dictionary at `pos`, each with the byte range of
/// its value. The parser proper discards string contents; the key material
/// lives in strings, so they are read from here.
pub(crate) fn raw_entries(data: &[u8], pos: usize) -> Option<Vec<(Vec<u8>, Range<usize>)>> {
    let mut parser = Parser::new(data, pos, 4096);
    parser.skip_whitespace();
    if !parser.rest().starts_with(b"<<") {
        return None;
    }
    parser.pos += 2;
    let mut entries = Vec::new();
    loop {
        parser.skip_whitespace();
        if parser.rest().starts_with(b">>") {
            return Some(entries);
        }
        if parser.rest().first() != Some(&b'/') {
            return None;
        }
        let key = parser.name()?.text;
        parser.skip_whitespace();
        let start = parser.pos;
        parser.parse_value()?;
        entries.push((key, start..parser.pos));
    }
}

fn entry<'e>(entries: &'e [(Vec<u8>, Range<usize>)], key: &[u8]) -> Option<&'e Range<usize>> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, range)| range)
}

/// Contents of the literal or hexadecimal string that `raw` spells.
fn string(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    match raw.first()? {
        b'<' => {
            let mut digits = raw[1..]
                .iter()
                .take_while(|&&b| b != b'>')
                .filter_map(|&b| (b as char).to_digit(16));
            while let Some(high) = digits.next() {
                out.push((high << 4 | digits.next().unwrap_or(0)) as u8);
            }
        }
        b'(' => {
            let mut depth = 0usize;
            let mut bytes = raw.iter().copied().peekable();
            while let Some(byte) = bytes.next() {
                match byte {
                    b'(' => {
                        depth += 1;
                        if depth > 1 {
                            out.push(byte);
                        }
                    }
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        out.push(byte);
                    }
                    b'\\' => match bytes.next()? {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        first @ b'0'..=b'7' => {
                            let mut code = (first - b'0') as u32;
                            for _ in 0..2 {
                                match bytes.peek() {
                                    Some(&digit @ b'0'..=b'7') => {
                                        code = code * 8 + (digit - b'0') as u32;
                                        bytes.next();
                                    }
                                    _ => break,
                                }
                            }
                            out.push(code as u8);
                        }
                        // A backslash before a line end continues the line.
                        b'\r' => {
                            bytes.next_if_eq(&b'\n');
                        }
                        b'\n' => {}
                        other => out.push(other),
                    },
                    _ => out.push(byte),
                }
            }
        }
        _ => return None,
    }
    Some(out)
}

fn integer(raw: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(raw).ok()?.trim();
    text.parse::<f64>()
        .ok()
        .filter(|n| n.fract() == 0.0 && n.abs() < 1e15)
        .map(|n| n as i64)
}

fn name(raw: &[u8]) -> Option<Vec<u8>> {
    match Parser::new(raw, 0, 4).parse_value()? {
        Value::Name(name) => Some(name.text),
        _ => None,
    }
}

/// First element of the `/ID` array at `range`.
pub(crate) fn first_id(data: &[u8], range: &Range<usize>) -> Option<Vec<u8>> {
    let mut parser = Parser::new(&data[..range.end], range.start, 8);
    parser.skip_whitespace();
    if parser.rest().first() != Some(&b'[') {
        return None;
    }
    parser.pos += 1;
    parser.skip_whitespace();
    string(parser.rest())
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn rc4(key: &[u8], data: &mut [u8]) {
    let mut state: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(state[i as usize]);
        state.swap(i as usize, j as usize);
        *byte ^= state[state[i as usize].wrapping_add(state[j as usize]) as usize];
    }
}

enum Aes {
    Small(Box<Aes128>),
    Large(Box<Aes256>),
}

impl Aes {
    fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Aes128::new_from_slice(key)
                .ok()
                .map(|cipher| Self::Small(Box::new(cipher))),
            32 => Aes256::new_from_slice(key)
                .ok()
                .map(|cipher| Self::Large(Box::new(cipher))),
            _ => None,
        }
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Small(cipher) => cipher.decrypt_block(block),
            Self::Large(cipher) => cipher.decrypt_block(block),
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Small(cipher) => cipher.encrypt_block(block),
            Self::Large(cipher) => cipher.encrypt_block(block),
        }
    }
}

/// CBC decryption of whole blocks; a ragged tail is dropped, as readers do.
fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes::new(key)?;
    let mut out = data[..data.len() / BLOCK * BLOCK].to_vec();
    let mut previous = iv;
    let blocks = out.as_chunks_mut::<BLOCK>().0.iter_mut();
    for (block, ciphertext) in blocks.zip(data.as_chunks::<BLOCK>().0) {
        cipher.decrypt_block(block);
        for (byte, mask) in block.iter_mut().zip(previous) {
            *byte ^= mask;
        }
        previous = ciphertext;
    }
    Some(out)
}

fn cbc_encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Option<()> {
    let cipher = Aes::new(key)?;
    let mut previous = iv.to_vec();
    for block in data.as_chunks_mut::<BLOCK>().0 {
        for (byte, mask) in block.iter_mut().zip(&previous) {
            *byte ^= mask;
        }
        cipher.encrypt_block(block);
        previous.copy_from_slice(block);
    }
    Some(())
}

/// The password hash of revision 6 (ISO 32000-2, algorithm 2.B). `user` is
/// the first 48 bytes of `/U` when the owner password is being checked, and
/// empty otherwise.
fn hash_r6(password: &[u8], salt: &[u8], user: &[u8]) -> Option<[u8; 32]> {
    let mut key: Vec<u8> = Sha256::digest([password, salt, user].concat()).to_vec();
    let mut round = 0;
    loop {
        let mut block = [password, &key, user].concat().repeat(64);
        cbc_encrypt(&key[..16], &key[16..32], &mut block)?;
        let selector: u32 = block[..16].iter().map(|&b| b as u32).sum();
        key = match selector % 3 {
            0 => Sha256::digest(&block).to_vec(),
            1 => Sha384::digest(&block).to_vec(),
            _ => Sha512::digest(&block).to_vec(),
        };
        round += 1;
        let last = *block.last()? as usize;
        if round >= 64 && last + 32 <= round {
            return key[..32].try_into().ok();
        }
        if round > MAX_HASH_ROUNDS {
            return None;
        }
    }
}

/// `password` cut or padded to the 32 bytes revisions 2 to 4 work with.
fn padded(password: &[u8]) -> [u8; 32] {
    let mut out = PAD;
    let kept = password.len().min(32);
    out[..kept].copy_from_slice(&password[..kept]);
    out[kept..].copy_from_slice(&PAD[..32 - kept]);
    out
}

/// The RC4 key that wraps the user password in `/O` (revisions 2 to 4).
fn owner_key(password: &[u8], revision: i64, length: usize) -> Vec<u8> {
    let mut key = md5(&[&padded(password)]);
    if revision >= 3 {
        for _ in 0..50 {
            key = md5(&[&key[..length]]);
        }
    }
    key[..length].to_vec()
}

impl Decryptor {
    /// Derive the file key from the encryption dictionary at `encrypt`, the
    /// first `/ID` string and `password`, which is tried as the user password
    /// and then as the owner password. `None` when the handler is not the
    /// standard one, an entry is missing, or the password does not open it.
    pub(crate) fn open(data: &[u8], encrypt: usize, id: &[u8], password: &[u8]) -> Option<Self> {
        let entries = raw_entries(data, encrypt)?;
        let raw = |key: &[u8]| entry(&entries, key).map(|range| &data[range.clone()]);
        let int = |key: &[u8]| raw(key).and_then(integer);

        if name(raw(b"Filter")?)? != b"Standard" {
            return None;
        }
        let version = int(b"V").unwrap_or(0);
        let revision = int(b"R")?;
        let user = string(raw(b"U")?)?;
        let encrypt_metadata = raw(b"EncryptMetadata").is_none_or(|raw| raw != b"false");

        let (streams, embedded_files) = match version {
            1 | 2 => (Method::Rc4, Method::Rc4),
            4 | 5 => {
                let filters = entry(&entries, b"CF")
                    .and_then(|range| raw_entries(&data[..range.end], range.start))
                    .unwrap_or_default();
                let method = |key: &[u8]| -> Option<Method> {
                    let Some(filter) = raw(key).and_then(name) else {
                        return Some(Method::Identity);
                    };
                    if filter == b"Identity" {
                        return Some(Method::Identity);
                    }
                    let range = entry(&filters, &filter)?;
                    let filter = raw_entries(&data[..range.end], range.start)?;
                    let method = entry(&filter, b"CFM").and_then(|r| name(&data[r.clone()]));
                    Some(match method.as_deref() {
                        Some(b"V2") => Method::Rc4,
                        Some(b"AESV2") => Method::AesV2,
                        Some(b"AESV3") => Method::AesV3,
                        Some(b"None") | None => Method::Identity,
                        Some(_) => return None,
                    })
                };
                let streams = method(b"StmF")?;
                let embedded = match raw(b"EFF") {
                    Some(_) => method(b"EFF")?,
                    None => streams,
                };
                (streams, embedded)
            }
            _ => return None,
        };

        let key = match revision {
            2..=4 => {
                let owner = string(raw(b"O")?)?;
                let permissions = (int(b"P")? as u32).to_le_bytes();
                let length = match revision {
                    2 => 5,
                    _ => usize::try_from(int(b"Length").unwrap_or(40)).ok()? / 8,
                };
                if !(5..=16).contains(&length) || owner.len() < 32 || user.len() < 32 {
                    return None;
                }
                let no_metadata: &[u8] = if revision >= 4 && !encrypt_metadata {
                    &[0xFF; 4]
                } else {
                    &[]
                };
                // The file key for a user password, if `/U` agrees with it.
                let file_key = |password: &[u8; 32]| -> Option<Vec<u8>> {
                    let mut key = md5(&[password, &owner[..32], &permissions, id, no_metadata]);
                    if revision >= 3 {
                        for _ in 0..50 {
                            key = md5(&[&key[..length]]);
                        }
                    }
                    let key = key[..length].to_vec();
                    if revision == 2 {
                        let mut expected = PAD;
                        rc4(&key, &mut expected);
                        (expected[..] == user[..32]).then_some(key)
                    } else {
                        let mut expected = md5(&[&PAD, id]);
                        for round in 0..20u8 {
                            let round_key: Vec<u8> = key.iter().map(|byte| byte ^ round).collect();
                            rc4(&round_key, &mut expected);
                        }
                        (expected[..] == user[..16]).then_some(key)
                    }
                };
                file_key(&padded(password)).or_else(|| {
                    // `/O` is the user password, encrypted with the owner's.
                    let key = owner_key(password, revision, length);
                    let mut user_password: [u8; 32] = owner[..32].try_into().ok()?;
                    let rounds = if revision == 2 { 1 } else { 20u8 };
                    for round in (0..rounds).rev() {
                        let round_key: Vec<u8> = key.iter().map(|byte| byte ^ round).collect();
                        rc4(&round_key, &mut user_password);
                    }
                    file_key(&user_password)
                })?
            }
            5 | 6 => {
                let wrapped = string(raw(b"UE")?)?;
                if user.len() < 48 || wrapped.len() < 32 {
                    return None;
                }
                let password = &password[..password.len().min(MAX_PASSWORD)];
                let hash = |salt: &[u8], user: &[u8]| -> Option<[u8; 32]> {
                    if revision == 5 {
                        Some(Sha256::digest([password, salt, user].concat()).into())
                    } else {
                        hash_r6(password, salt, user)
                    }
                };
                if hash(&user[32..40], b"")?[..] == user[..32] {
                    cbc_decrypt(&hash(&user[40..48], b"")?, &[0; BLOCK], &wrapped[..32])?
                } else {
                    let owner = string(raw(b"O")?)?;
                    let wrapped = string(raw(b"OE")?)?;
                    if owner.len() < 48 || wrapped.len() < 32 {
                        return None;
                    }
                    let user = &user[..48];
                    if hash(&owner[32..40], user)?[..] != owner[..32] {
                        return None;
                    }
                    cbc_decrypt(&hash(&owner[40..48], user)?, &[0; BLOCK], &wrapped[..32])?
                }
            }
            _ => return None,
        };

        Some(Self {
            key,
            streams,
            embedded_files,
            encrypt_metadata,
        })
    }

    /// Plaintext of the stream data of object `number` `generation`.
    pub(crate) fn decrypt(
        &self,
        number: u32,
        generation: u16,
        kind: StreamKind,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let method = match kind {
            StreamKind::CrossReference => Method::Identity,
            StreamKind::Metadata if !self.encrypt_metadata => Method::Identity,
            StreamKind::EmbeddedFile => self.embedded_files,
            StreamKind::Ordinary | StreamKind::Metadata => self.streams,
        };
        let object_key = |salt: &[u8]| {
            let digest = md5(&[
                &self.key,
                &number.to_le_bytes()[..3],
                &generation.to_le_bytes(),
                salt,
            ]);
            digest[..(self.key.len() + 5).min(16)].to_vec()
        };
        match method {
            Method::Identity => Some(data.to_vec()),
            Method::Rc4 => {
                let mut out = data.to_vec();
                rc4(&object_key(b""), &mut out);
                Some(out)
            }
            Method::AesV2 => aes_stream(&object_key(b"sAlT"), data),
            Method::AesV3 => aes_stream(&self.key, data),
        }
    }
}

/// An AES stream is its initialization vector followed by padded blocks.
fn aes_stream(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    let (iv, blocks) = data.split_at_checked(BLOCK)?;
    let mut out = cbc_decrypt(key, iv, blocks)?;
    // Padding that is not PKCS#7 is left in place; filters ignore trailing bytes.
    if let Some(&pad) = out.last()
        && (1..=BLOCK).contains(&(pad as usize))
        && out.len() >= pad as usize
    {
        out.truncate(out.len() - pad as usize);
    }
    Some(out)
}

/// Builds encrypted documents for the tests here and in the parent module.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub(crate) const ID: &[u8] = b"0123456789abcdef";
    /// The owner password of every document built here.
    pub(crate) const OWNER_PASSWORD: &[u8] = b"owner";
    const IV: [u8; BLOCK] = [0x49; BLOCK];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn aes_encrypt(key: &[u8], plain: &[u8]) -> Vec<u8> {
        let pad = BLOCK - plain.len() % BLOCK;
        let mut blocks = plain.to_vec();
        blocks.resize(plain.len() + pad, pad as u8);
        cbc_encrypt(key, &IV, &mut blocks).unwrap();
        [&IV[..], &blocks].concat()
    }

    /// One way of encrypting a document with the user password `password`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Scheme {
        Rc4Short,
        Rc4Long,
        Aes128,
        Aes256,
        /// Revision 5, the Adobe extension that preceded revision 6.
        Aes256Extension,
    }

    pub(crate) struct Encrypted {
        pub scheme: Scheme,
        key: Vec<u8>,
        /// The `/Encrypt` dictionary.
        pub dict: String,
    }

    impl Encrypted {
        pub(crate) fn new(scheme: Scheme, password: &[u8]) -> Self {
            let permissions = (-44i32).to_le_bytes();
            match scheme {
                Scheme::Rc4Short | Scheme::Rc4Long | Scheme::Aes128 => {
                    let (revision, length) = match scheme {
                        Scheme::Rc4Short => (2, 5),
                        Scheme::Rc4Long => (3, 16),
                        _ => (4, 16),
                    };
                    let wrapping = owner_key(OWNER_PASSWORD, revision, length);
                    let mut owner = padded(password);
                    for round in 0..if revision == 2 { 1 } else { 20u8 } {
                        let round_key: Vec<u8> = wrapping.iter().map(|byte| byte ^ round).collect();
                        rc4(&round_key, &mut owner);
                    }
                    let mut key = md5(&[&padded(password), &owner, &permissions, ID]);
                    let user = if scheme == Scheme::Rc4Short {
                        let mut user = PAD;
                        rc4(&key[..length], &mut user);
                        user
                    } else {
                        for _ in 0..50 {
                            key = md5(&[&key[..length]]);
                        }
                        let mut user = [0; 32];
                        user[..16].copy_from_slice(&md5(&[&PAD, ID]));
                        for round in 0..20u8 {
                            let round_key: Vec<u8> = key.iter().map(|byte| byte ^ round).collect();
                            rc4(&round_key, &mut user[..16]);
                        }
                        user
                    };
                    let head = match scheme {
                        Scheme::Rc4Short => "/V 1 /R 2".to_string(),
                        Scheme::Rc4Long => "/V 2 /R 3 /Length 128".to_string(),
                        _ => "/V 4 /R 4 /Length 128 /StmF /StdCF /StrF /StdCF \
                              /CF << /StdCF << /CFM /AESV2 /AuthEvent /DocOpen /Length 16 >> >>"
                            .to_string(),
                    };
                    Self {
                        scheme,
                        key: key[..length].to_vec(),
                        dict: format!(
                            "<< /Filter /Standard {head} /P -44 /O <{}> /U <{}> >>",
                            hex(&owner),
                            hex(&user)
                        ),
                    }
                }
                Scheme::Aes256 | Scheme::Aes256Extension => {
                    let hash = |password: &[u8], salt: &[u8], user: &[u8]| -> [u8; 32] {
                        if scheme == Scheme::Aes256Extension {
                            Sha256::digest([password, salt, user].concat()).into()
                        } else {
                            hash_r6(password, salt, user).unwrap()
                        }
                    };
                    let (validation, key_salt) = (*b"validate", *b"key-salt");
                    let key = vec![0x6B; 32];
                    let mut wrapped = key.clone();
                    cbc_encrypt(&hash(password, &key_salt, b""), &[0; BLOCK], &mut wrapped)
                        .unwrap();
                    let user = [
                        &hash(password, &validation, b"")[..],
                        &validation,
                        &key_salt,
                    ]
                    .concat();
                    let mut owner_wrapped = key.clone();
                    let owner_hash = hash(OWNER_PASSWORD, &key_salt, &user);
                    cbc_encrypt(&owner_hash, &[0; BLOCK], &mut owner_wrapped).unwrap();
                    let owner = [
                        &hash(OWNER_PASSWORD, &validation, &user)[..],
                        &validation,
                        &key_salt,
                    ]
                    .concat();
                    let revision = if scheme == Scheme::Aes256 { 6 } else { 5 };
                    Self {
                        scheme,
                        key,
                        dict: format!(
                            "<< /Filter /Standard /V 5 /R {revision} /Length 256 /P -44 \
                             /StmF /StdCF /StrF /StdCF \
                             /CF << /StdCF << /CFM /AESV3 /AuthEvent /DocOpen /Length 32 >> >> \
                             /O <{}> /U <{}> /OE <{}> /UE <{}> /Perms <{}> >>",
                            hex(&owner),
                            hex(&user),
                            hex(&owner_wrapped),
                            hex(&wrapped),
                            hex(&[0; 16]),
                        ),
                    }
                }
            }
        }

        /// Stream data of object `number`, generation 0, as stored in the file.
        pub(crate) fn seal(&self, number: u32, plain: &[u8]) -> Vec<u8> {
            let object_key = |salt: &[u8]| {
                let digest = md5(&[&self.key, &number.to_le_bytes()[..3], &[0, 0], salt]);
                digest[..(self.key.len() + 5).min(16)].to_vec()
            };
            match self.scheme {
                Scheme::Rc4Short | Scheme::Rc4Long => {
                    let mut out = plain.to_vec();
                    rc4(&object_key(b""), &mut out);
                    out
                }
                Scheme::Aes128 => aes_encrypt(&object_key(b"sAlT"), plain),
                Scheme::Aes256 | Scheme::Aes256Extension => aes_encrypt(&self.key, plain),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Encrypted, ID, OWNER_PASSWORD, Scheme};
    use super::*;

    const SCHEMES: [Scheme; 5] = [
        Scheme::Rc4Short,
        Scheme::Rc4Long,
        Scheme::Aes128,
        Scheme::Aes256,
        Scheme::Aes256Extension,
    ];

    #[test]
    fn known_answers() {
        // RFC 6229 and RFC 1321 test vectors.
        let mut stream = [0; 8];
        rc4(&[1, 2, 3, 4, 5], &mut stream);
        assert_eq!(stream, [0xB2, 0x39, 0x63, 0x05, 0xF0, 0x3D, 0xC0, 0x27]);
        assert_eq!(
            md5(&[b"abc"]),
            [
                0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0, 0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1,
                0x7F, 0x72
            ]
        );
        // NIST SP 800-38A, CBC-AES128 first block.
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let iv: Vec<u8> = (0..16).collect();
        let cipher = [
            0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9,
            0x19, 0x7D,
        ];
        let plain = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        assert_eq!(cbc_decrypt(&key, &iv, &cipher).unwrap(), plain);
        let mut block = plain;
        cbc_encrypt(&key, &iv, &mut block).unwrap();
        assert_eq!(block, cipher);
    }

    #[test]
    fn strings_are_decoded() {
        assert_eq!(string(b"<48 65 6C6c 6F>").unwrap(), b"Hello");
        assert_eq!(string(b"<4>").unwrap(), [0x40]);
        assert_eq!(
            string(b"(a\\(b\\)\\\\ (nested) \\101\\7\\n\\\nz) trailing").unwrap(),
            b"a(b)\\ (nested) A\x07\nz"
        );
        assert_eq!(string(b"/Name"), None);
    }

    #[test]
    fn empty_password_opens_every_scheme() {
        for scheme in SCHEMES {
            let encrypted = Encrypted::new(scheme, b"");
            let decryptor = Decryptor::open(encrypted.dict.as_bytes(), 0, ID, b"")
                .unwrap_or_else(|| panic!("{scheme:?} did not open"));
            for plain in [&b""[..], b"short", &[0x10; 16], &[7; 100]] {
                let sealed = encrypted.seal(9, plain);
                assert_eq!(
                    decryptor
                        .decrypt(9, 0, StreamKind::Ordinary, &sealed)
                        .unwrap(),
                    plain,
                    "{scheme:?}"
                );
            }
            // Cross-reference streams are stored in the clear.
            assert_eq!(
                decryptor
                    .decrypt(9, 0, StreamKind::CrossReference, b"plain")
                    .unwrap(),
                b"plain"
            );
        }
    }

    #[test]
    fn a_real_password_opens_only_when_supplied() {
        for scheme in SCHEMES {
            let encrypted = Encrypted::new(scheme, b"secret");
            let dict = encrypted.dict.as_bytes();
            let sealed = encrypted.seal(9, b"plain text");
            for wrong in [&b""[..], b"Secret", b"secret "] {
                assert!(Decryptor::open(dict, 0, ID, wrong).is_none(), "{scheme:?}");
            }
            // The user's password and the owner's lead to the same key.
            for password in [&b"secret"[..], OWNER_PASSWORD] {
                let decryptor = Decryptor::open(dict, 0, ID, password)
                    .unwrap_or_else(|| panic!("{scheme:?} did not open"));
                assert_eq!(
                    decryptor
                        .decrypt(9, 0, StreamKind::Ordinary, &sealed)
                        .unwrap(),
                    b"plain text",
                    "{scheme:?}"
                );
            }
        }
    }

    #[test]
    fn other_handlers_and_damaged_dictionaries_do_not_open() {
        let dict = Encrypted::new(Scheme::Rc4Long, b"").dict;
        assert!(Decryptor::open(dict.as_bytes(), 0, b"another id", b"").is_none());
        let public_key = dict.replace("/Standard", "/Adobe.PubSec");
        assert!(Decryptor::open(public_key.as_bytes(), 0, ID, b"").is_none());
        let no_user = dict.replace("/U ", "/X ");
        assert!(Decryptor::open(no_user.as_bytes(), 0, ID, b"").is_none());
        assert!(Decryptor::open(b"<< /Filter /Standard", 0, ID, b"").is_none());
        assert!(Decryptor::open(b"", 0, ID, b"").is_none());
    }
}
