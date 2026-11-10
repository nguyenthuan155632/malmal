# Corpus

`crates/malmal/tests/corpus.rs` scans every file below this directory:

- `clean/` — files that must come back `Clean`. Add real exports from the
  tools your users have (phone photos, Illustrator, Word, Chrome's PDF
  printer); this is what keeps false positives measured.
- `malicious/` — files that must come back `Malicious`. The samples here are
  minimal hand-built ones: they carry the trigger a scanner must find and
  nothing that works as an exploit.

Add a file to the matching directory and the test covers it; no code changes
are needed.
