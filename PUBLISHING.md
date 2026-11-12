# Publishing to crates.io

The workspace publishes three crates. They depend on each other, so publish in
this order:

1. `malmal` — the scanner library
2. `malmal-ffi` — the C ABI (depends on `malmal`)
3. `malmal-cli` — the `malmal` / `malmald` binaries (depends on `malmal`)

## One-time setup

Create an account at <https://crates.io> (sign in with GitHub), then create an
API token under *Account Settings → API Tokens* and log in locally:

```bash
cargo login
```

Paste the token when prompted. The token is stored in `~/.cargo/credentials.toml`.

## Publish

Commit everything first (`cargo publish` refuses a dirty tree), then:

```bash
cargo publish -p malmal
```

Wait a few seconds for the crate to appear in the index, then:

```bash
cargo publish -p malmal-ffi
cargo publish -p malmal-cli
```

> Publishing is permanent. A version can be **yanked** (hidden from new
> resolution) but never deleted or overwritten. To ship a fix, bump the
> version and publish again.

## Releasing a new version

The version is written in three places that must agree: `version` in the
workspace `Cargo.toml`, and the `malmal = { ..., version = "..." }`
dependency in `crates/malmal-cli/Cargo.toml` and `crates/malmal-ffi/Cargo.toml`.
Add the release to `CHANGELOG.md`, commit, and publish the three crates in the
order above.

## After publishing

People can then install the CLI without cloning anything:

```bash
cargo install malmal-cli
```

This builds and installs the `malmal` and `malmald` binaries. Using the library
in another project:

```bash
cargo add malmal
```
