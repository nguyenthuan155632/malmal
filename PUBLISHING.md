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

## Releasing from a tag

`.github/workflows/release.yml` does all of the above when a tag is pushed:

```bash
git tag v0.2.0
```

```bash
git push origin v0.2.0
```

The tag must be `v` followed by the version in `Cargo.toml`. The workflow runs the tests,
builds static binaries for x86-64 and ARM64 Linux, attaches them to a GitHub release with
the changelog section as its notes, and pushes `ghcr.io/nguyenthuan155632/malmal` for both
architectures.

It also builds the Python wheels for x86-64 and ARM64 Linux and attaches them to the
release. They go to PyPI as well when the repository variable `PYPI_PUBLISH` is `true`
(*Settings → Secrets and variables → Actions → Variables*). No token is stored for that:
on PyPI, add a trusted publisher for the project `malmal` naming this repository, the
workflow `release.yml` and the environment `pypi` (*Publishing* in the account settings
for a project that does not exist yet, in the project's settings afterwards). The version
in `bindings/python/pyproject.toml` has to be the tag's as well.

It publishes the three crates as well if the repository has a secret named
`CARGO_REGISTRY_TOKEN` (*Settings → Secrets and variables → Actions*) holding a crates.io
API token; without the secret that job does nothing and the crates are published by hand as
described above. The container package is private until its visibility is changed under
the repository's *Packages*.

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
