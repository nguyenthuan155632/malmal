# Releasing

A release is made by pushing a tag. [`.github/workflows/release.yml`](../.github/workflows/release.yml)
does the rest: it tests, builds the binaries, the Python wheels and the Ruby gems, creates
the GitHub release, pushes the container image, and publishes to crates.io, PyPI and
RubyGems where it has been given the means to.

## What a tag produces

Pushing `v<version>` runs these jobs:

| Job | What it does | Needs |
|---|---|---|
| `build` | Tests, then builds static (musl) binaries for x86-64 and ARM64, and packs `malmal-v<version>-<target>.tar.gz` with its `.sha256` | nothing |
| `wheels` | Builds manylinux wheels for x86-64 and ARM64, installs one and runs the Python tests | nothing |
| `gems` | Builds the `malmal` gem for each platform with its library, and tests the installed gem on x86-64 Linux (glibc, and musl in an Alpine container) and on ARM64 macOS | nothing |
| `ruby-gems` | Builds the `malmal` gem without a library (platform `ruby`) and `malmal-rails` | nothing |
| `github` | Creates the release, with the archives, wheels and gems attached and the changelog section as notes | nothing |
| `image` | Pushes `ghcr.io/<owner>/malmal:<version>` and `:latest` for both architectures | nothing |
| `crates` | Publishes `malmal`, `malmal-ffi` and `malmal-cli`, in that order | the `CARGO_REGISTRY_TOKEN` secret |
| `pypi` | Publishes the wheels | the `PYPI_PUBLISH` variable set to `true`, and a trusted publisher on PyPI |
| `rubygems` | Pushes the platform gems, then the `ruby` gem, then `malmal-rails` | the `RUBYGEMS_PUBLISH` variable set to `true`, and a trusted publisher for each gem on RubyGems |

Each archive holds `bin/malmal`, `bin/malmald`, `lib/libmalmal_ffi.a`,
`include/malmal.h`, the README, the changelog and both licenses. The released binaries
are built with the default features: no `yara`, no `cdr-pdf`.

Without the secret or the variables, `crates`, `pypi` and `rubygems` are skipped and the rest of the
release still happens.

## One-time setup

### crates.io

1. Sign in to [crates.io](https://crates.io) with GitHub and verify an email address.
2. Under Account Settings → API Tokens, create a token with the `publish-new` and
   `publish-update` scopes, limited to the crates `malmal`, `malmal-ffi` and `malmal-cli`.
   Before the first release the crates do not exist yet, so leave the crate limit off
   for that one and narrow it afterwards.
3. In the repository, under Settings → Secrets and variables → Actions → Secrets, add
   `CARGO_REGISTRY_TOKEN` with the token as its value.

The names are taken on first publish. Check that none of the three is already taken by
someone else before the first release.

### PyPI

The workflow publishes with PyPI's trusted publishing, so no token is stored.

1. Sign in to [pypi.org](https://pypi.org). Under Your projects → Publishing, add a
   pending publisher:
   - project name: `malmal`
   - owner: the GitHub owner of this repository; repository: `malmal`
   - workflow: `release.yml`
   - environment: `pypi`
2. In the repository, under Settings → Environments, create an environment named `pypi`.
3. Under Settings → Secrets and variables → Actions → Variables, add `PYPI_PUBLISH` with
   the value `true`.

### RubyGems

The workflow pushes with RubyGems' trusted publishing too, so no API key is stored.

1. Sign in to [rubygems.org](https://rubygems.org), with multi-factor authentication on
   (the gems require it). Under Settings → Trusted publishers (pending ones, before the
   first release), add one publisher for each of the gems `malmal` and `malmal-rails`:
   - repository owner: the GitHub owner of this repository; repository name: `malmal`
   - workflow filename: `release.yml`
   - environment: `rubygems`
2. In the repository, under Settings → Environments, create an environment named
   `rubygems`.
3. Under Settings → Secrets and variables → Actions → Variables, add `RUBYGEMS_PUBLISH`
   with the value `true`.

As with the crates, check that neither name is already taken before the first release.

### Container image

Nothing to set up: the workflow pushes with its own token. The first image is private on
ghcr.io. To make it public, open the package under the owner's Packages tab → Package
settings → Change visibility.

## Making a release

1. Merge everything the release should carry into `main`, with CI green. Do not tag a
   branch that has not been merged.

2. Choose the version. Where the release has changed the public API in a way that breaks
   callers, raise the minor number while below 1.0 (`0.2.0` to `0.3.0`); otherwise the
   patch number.

3. Write the version in every place that names it:
   - `version` under `[workspace.package]` in [`Cargo.toml`](../Cargo.toml);
   - the `version = "..."` of the `malmal` dependency in
     [`crates/malmal-ffi/Cargo.toml`](../crates/malmal-ffi/Cargo.toml) and
     [`crates/malmal-cli/Cargo.toml`](../crates/malmal-cli/Cargo.toml);
   - `version` in [`bindings/python/pyproject.toml`](../bindings/python/pyproject.toml);
   - `VERSION` in [`bindings/ruby/malmal/lib/malmal/version.rb`](../bindings/ruby/malmal/lib/malmal/version.rb)
     (`malmal-rails` takes its version, and depends on the `malmal` of the same one);
   - the heading `## <version>` in [`CHANGELOG.md`](../CHANGELOG.md), above the changes it
     brings. The release notes are that section, up to the next heading.

   Then bring the lock file up to date, since every build runs with `--locked`:

   ```bash
   cargo update -w
   ```

4. Check locally what the workflow will check:

   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --locked
   cargo build --release --locked --workspace --target x86_64-unknown-linux-musl
   ```

   And that the crates package and would publish, without publishing them:

   ```bash
   cargo publish --dry-run --locked --workspace
   ```

   `malmal-ffi` and `malmal-cli` depend on the `malmal` of the same version. Run on its
   own, `cargo publish -p malmal-ffi` looks for that version on crates.io, does not find it
   before it is published, and fails with `failed to select version for requirement
   malmal = ^<version>`. `--workspace` packs the three together and checks each against
   the others, in the order they depend on each other.

5. Commit the version change to `main` and push it:

   ```bash
   git commit -am "Release 0.3.0"
   git push origin main
   ```

6. Tag the commit and push the tag:

   ```bash
   git tag -a v0.3.0 -m "v0.3.0"
   git push origin v0.3.0
   ```

7. Follow the run under the Actions tab, or:

   ```bash
   gh run watch
   ```

   It takes some 10 to 20 minutes.

8. Check the result:
   - `gh release view v0.3.0` lists the two archives, their checksums and the wheels;
   - `cargo install malmal-cli` installs the new version;
   - `pip install malmal==0.3.0` installs it;
   - `gem install malmal-rails -v 0.3.0` installs both gems, the `malmal` one of the
     machine's platform;
   - `docker run --rm ghcr.io/<owner>/malmal:0.3.0 --help` runs.

## When something fails

The tag must equal the version in `Cargo.toml`, `pyproject.toml` and `version.rb`; the
first step of `build`, `wheels` and `gems` fails otherwise.

Before anything has been published, fix the cause on `main`, then move the tag to the
new commit:

```bash
gh release delete v0.3.0 --yes
git push --delete origin v0.3.0
git tag -fa v0.3.0 -m "v0.3.0"
git push origin v0.3.0
```

Once a crate or a wheel is out, that version cannot be published again: crates.io and PyPI
refuse a version they already have, even after it is yanked or deleted. Release the fix as
the next patch version instead. A crate that turns out broken can be yanked, which stops new
projects from picking it:

```bash
cargo yank --version 0.3.0 malmal-cli
```

If `crates` stopped partway, say after `malmal` was published but before `malmal-ffi`,
publish the rest by hand from the tagged commit, in order:

```bash
git checkout v0.3.0
cargo publish --locked -p malmal-ffi
cargo publish --locked -p malmal-cli
```

## Publishing by hand

The same steps without the workflow, for when it cannot be used.

**Crates**. `--workspace` publishes the library first and waits for it to be on
crates.io before the two crates that depend on it:

```bash
cargo login
cargo publish --locked --workspace
```

One at a time does the same, provided the library goes first:

```bash
cargo publish --locked -p malmal
cargo publish --locked -p malmal-ffi
cargo publish --locked -p malmal-cli
```

**Binaries**, for one target:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --workspace --target x86_64-unknown-linux-musl
```

They are in `target/x86_64-unknown-linux-musl/release/`. Pack them as the `Package` step
of the workflow does, then attach them to a release:

```bash
gh release create v0.3.0 malmal-v0.3.0-*.tar.gz* --title v0.3.0 --notes-file notes.md
```

**Wheels**, with `pip install cargo-zigbuild ziglang twine` and the targets
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`:

```bash
sh bindings/python/build_wheel.sh x86_64
sh bindings/python/build_wheel.sh aarch64
twine upload bindings/python/dist/*.whl
```

**Gems**, with the Rust targets, `pip install cargo-zigbuild ziglang` for the Linux ones,
and a Mac for the macOS ones. The platform gems go first, so that nobody installs the
`ruby` gem for want of one:

```bash
sh bindings/ruby/build_gem.sh x86_64-unknown-linux-gnu    # and each other target
sh bindings/ruby/build_gem.sh ruby                        # malmal without a library, and malmal-rails
for gem in bindings/ruby/pkg/malmal-[0-9]*-*.gem; do gem push "$gem"; done
gem push bindings/ruby/pkg/malmal-0.3.0.gem
gem push bindings/ruby/pkg/malmal-rails-0.3.0.gem
```
