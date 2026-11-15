#!/bin/sh
# Build the gems into bindings/ruby/pkg:
#
#   build_gem.sh <rust-target>   a malmal gem that carries libmalmal_ffi for it
#   build_gem.sh ruby            the malmal gem without a library, and malmal-rails
#
# The Rust targets and the gem platforms they make:
#
#   x86_64-unknown-linux-gnu     x86_64-linux-gnu    (glibc 2.17 or newer)
#   aarch64-unknown-linux-gnu    aarch64-linux-gnu
#   x86_64-unknown-linux-musl    x86_64-linux-musl   (Alpine)
#   aarch64-unknown-linux-musl   aarch64-linux-musl
#   aarch64-apple-darwin         arm64-darwin
#   x86_64-apple-darwin          x86_64-darwin
#
# Linux libraries are built with cargo-zigbuild (`pip install cargo-zigbuild
# ziglang`), which links against glibc 2.17 or against musl whatever the
# machine building them has; macOS ones with cargo on a Mac. Each needs the
# Rust target: `rustup target add <rust-target>`. With MALMAL_SKIP_CARGO=1 the
# library already built under target/ is packed as it is.
set -eu

target=${1:?usage: build_gem.sh <rust-target>|ruby}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$here/pkg"

# What an earlier build for another machine left behind must not be shipped.
rm -f "$here"/malmal/lib/malmal/libmalmal_ffi.*

build() {
  (cd "$here/$1" && gem build "$1.gemspec" --output "$here/pkg/$2")
}

if [ "$target" = ruby ]; then
  version=$(ruby -e 'require_relative ARGV[0]; print Malmal::VERSION' "$here/malmal/lib/malmal/version.rb")
  build malmal "malmal-$version.gem"
  build malmal-rails "malmal-rails-$version.gem"
  exit
fi

case $target in
  x86_64-unknown-linux-gnu) platform=x86_64-linux-gnu ;;
  aarch64-unknown-linux-gnu) platform=aarch64-linux-gnu ;;
  x86_64-unknown-linux-musl) platform=x86_64-linux-musl ;;
  aarch64-unknown-linux-musl) platform=aarch64-linux-musl ;;
  aarch64-apple-darwin) platform=arm64-darwin ;;
  x86_64-apple-darwin) platform=x86_64-darwin ;;
  *) echo "build_gem.sh: no gem platform for $target" >&2; exit 2 ;;
esac

manifest="--manifest-path $root/Cargo.toml"
cargo() {
  if [ "${MALMAL_SKIP_CARGO:-}" != 1 ]; then command cargo "$@"; fi
}
case $target in
  *-linux-gnu)
    cargo zigbuild --release --locked -p malmal-ffi --target "$target.2.17" $manifest
    library=libmalmal_ffi.so ;;
  *-linux-musl)
    # A shared library cannot be linked statically; it uses the system's musl.
    RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=-crt-static" \
      cargo zigbuild --release --locked -p malmal-ffi --target "$target" $manifest
    library=libmalmal_ffi.so ;;
  *-apple-darwin)
    cargo build --release --locked -p malmal-ffi --target "$target" $manifest
    library=libmalmal_ffi.dylib ;;
esac

cp "$root/target/$target/release/$library" "$here/malmal/lib/malmal/"
version=$(ruby -e 'require_relative ARGV[0]; print Malmal::VERSION' "$here/malmal/lib/malmal/version.rb")
(cd "$here/malmal" && MALMAL_GEM_PLATFORM=$platform gem build malmal.gemspec \
  --output "$here/pkg/malmal-$version-$platform.gem")
rm "$here/malmal/lib/malmal/$library"
