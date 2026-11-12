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

`expected.tsv` records the verdict and finding codes of every file here and in
`tests/prototypes/files`. The test fails when any of them moves, which is how
a change to an analyzer shows what it did to real files. After adding a file,
or when a change is intended, record the new state:

    MALMAL_RECORD=1 cargo test -p malmal --test corpus
