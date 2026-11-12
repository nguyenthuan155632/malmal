#!/bin/sh
# Build a wheel that carries the library, for Linux:
#
#   build_wheel.sh x86_64    (or aarch64)
#
# The library is linked against glibc 2.17, the oldest the manylinux2014
# tag promises, whatever the machine building it has. That takes
# cargo-zigbuild: `pip install cargo-zigbuild ziglang`, and the Rust target
# from `rustup target add <arch>-unknown-linux-gnu`.
set -eu

arch=${1:?usage: build_wheel.sh x86_64|aarch64}
target=$arch-unknown-linux-gnu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

cargo zigbuild --release --locked -p malmal-ffi --target "$target.2.17" \
  --manifest-path "$root/Cargo.toml"
# What an earlier build for another machine left behind must not be shipped.
rm -rf "$here/build" "$here"/malmal/*.so
cp "$root/target/$target/release/libmalmal_ffi.so" "$here/malmal/"
python3 -m pip wheel "$here" --no-deps --wheel-dir "$here/dist" \
  --config-settings=--build-option=--plat-name="manylinux2014_$arch"
rm "$here/malmal/libmalmal_ffi.so"
