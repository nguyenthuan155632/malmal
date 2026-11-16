---
name: release
description: Release a new version of malmal — bump the version everywhere, check, push to main, tag, publish the crates to crates.io, and confirm the release workflow put the wheels on PyPI and the gems on RubyGems. Use when asked to release, bump the version, or publish crates/PyPI/RubyGems.
---

# Release malmal

The full reference is `docs/releasing.md`. This is the path that works today.

## 1. Choose the version

Below 1.0: a breaking public API change raises the minor number (`0.4.x` → `0.5.0`),
anything else the patch number. Below, `X.Y.Z` stands for the new version and `OLD` for
the current one (`grep '^version' Cargo.toml`).

## 2. Write the version everywhere

```bash
sed -i 's/^version = "OLD"/version = "X.Y.Z"/' Cargo.toml bindings/python/pyproject.toml
sed -i 's/version = "OLD"/version = "X.Y.Z"/' crates/malmal-cli/Cargo.toml crates/malmal-ffi/Cargo.toml
sed -i 's/VERSION = "OLD"/VERSION = "X.Y.Z"/' bindings/ruby/malmal/lib/malmal/version.rb
cargo update -w
```

`malmal-rails` takes its version from `version.rb`; nothing else to change for it.

Also:

- `CHANGELOG.md`: rename `## Unreleased` to `## X.Y.Z`. The release notes are that
  section. If there is no Unreleased section, write one from `git log vOLD..HEAD` first.
- `examples/rails/Gemfile.lock`: the path gems `malmal-rails (OLD)`, `malmal (= OLD)` and
  `malmal (OLD)` become `X.Y.Z`. Do not touch other gems that happen to share the number.
- Version samples in docs: `bindings/python/README.md` (wheel file name) and
  `examples/rails/compose.yaml` (image tag). Leave `examples/rails/Gemfile`'s `~>`
  requirement alone for a patch release.
- Leave the `v0.4.0`-style examples in `docs/releasing.md`, `release.yml` and the
  comment in `malmal.h` as they are.

Then check nothing was missed:

```bash
git grep -n 'OLD' -- ':!CHANGELOG.md' ':!PLAN.md' ':!Cargo.lock'
```

## 3. Check locally

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo publish --dry-run --locked --workspace --allow-dirty
```

Use `--workspace` for the dry run: `-p malmal-ffi` alone fails because the new `malmal`
is not on crates.io yet.

## 4. Commit, push, tag

Only on `main`, with a clean tree apart from the version change:

```bash
git commit -am "Release X.Y.Z"
git push origin main
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The tag starts `.github/workflows/release.yml`.

## 5. Publish the crates

The repository has no `CARGO_REGISTRY_TOKEN` secret, so the workflow's `crates` job
does nothing and the crates are published from this machine with the token in
`~/.cargo/credentials.toml` (`cargo login` first if that file is missing; ask the user
for a token):

```bash
cargo publish --locked --workspace
```

This publishes `malmal`, then `malmal-ffi` and `malmal-cli`. Publishing is permanent:
a version can be yanked but never published again.

`malmal` depends on patched copies of other crates in `third_party/` (see its
README), published as `malmal-<crate>`. They are outside the workspace, so the
command above does not publish them. If one is not yet on crates.io at the version
its manifest gives, or its code changed since, publish it first, in this order
(each needs the one before it):

```bash
cargo search malmal-jxl --limit 5
cargo search malmal-filmcraft --limit 5
cargo publish --manifest-path third_party/jxl-jbr/Cargo.toml
cargo publish --manifest-path third_party/jxl-render/Cargo.toml
cargo publish --manifest-path third_party/jxl-oxide/Cargo.toml
cargo publish --manifest-path third_party/filmcraft-av1/Cargo.toml
```

A copy that changed needs a new version (for example `0.2.1-malmal.2`), here and
in the `version` of the dependency on it. Until these are on crates.io,
`cargo publish --dry-run --workspace` fails for `malmal`.

## 6. PyPI and RubyGems come from the workflow

The variables `PYPI_PUBLISH` and `RUBYGEMS_PUBLISH` are `true` and both registries use
trusted publishing, so no token is needed. Wait for the run (10–20 minutes) in the
background:

```bash
id=$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')
gh run watch $id --exit-status --interval 30 >/dev/null 2>&1
gh run view $id --json conclusion,jobs -q '.conclusion, (.jobs[] | "\(.name): \(.conclusion)")'
```

If only `rubygems` failed, push the gems attached to the release again:
`gh workflow run release.yml -f tag=vX.Y.Z`.

## 7. Confirm

```bash
curl -s -A release-check https://crates.io/api/v1/crates/malmal | jq -r .crate.max_version
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/malmal/X.Y.Z/json
curl -s https://rubygems.org/api/v1/versions/malmal.json | jq -r '.[0:6][] | "\(.number) \(.platform)"'
curl -s https://rubygems.org/api/v1/versions/malmal-rails/latest.json
```

PyPI's `/pypi/malmal/json` can still show the old version for a few minutes from its
cache; ask for the versioned URL, which answers 200 once the release is there.
