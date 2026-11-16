#!/usr/bin/env python3
"""Check the patched copies in third_party/ against their upstream crates.

RustSec advisories name the upstream crates (`jxl-oxide`), not the copies
(`malmal-jxl-oxide`), so `cargo deny` on the workspace never reports them.
This writes a manifest in `target/forks/` that depends on each upstream crate
at the version that was copied, for `cargo deny check advisories` to read,
and fails if upstream has released a newer version: one may carry the fixes
(and the copy can go), or a fix the copy needs.

    python3 scripts/forks.py            # write the manifest, check for releases
    python3 scripts/forks.py --offline  # only write the manifest
"""

import json
import pathlib
import sys
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "target" / "forks"


def copies():
    """(upstream name, version copied) of each crate in third_party/."""
    for manifest in sorted((ROOT / "third_party").glob("*/Cargo.toml")):
        package = tomllib.loads(manifest.read_text())["package"]
        name = package["name"].removeprefix("malmal-")
        # A copy changed after it was published has a version of its own, and
        # names the release it came from.
        upstream = package.get("metadata", {}).get("malmal", {}).get("upstream")
        yield name, upstream or package["version"]


def newest(name):
    """The newest stable release of `name` on crates.io."""
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}",
        headers={"User-Agent": "malmal-forks-check"},
    )
    with urllib.request.urlopen(request, timeout=30) as answer:
        crate = json.load(answer)["crate"]
    return crate.get("max_stable_version") or crate["max_version"]


def key(version):
    return tuple(int(part) for part in version.split("."))


def main():
    found = list(copies())
    OUT.mkdir(parents=True, exist_ok=True)
    lines = [
        "[package]",
        'name = "malmal-forks-check"',
        'version = "0.0.0"',
        'edition = "2021"',
        "publish = false",
        "",
        "[workspace]",
        "",
        "[lib]",
        'path = "lib.rs"',
        "",
        "[dependencies]",
    ]
    lines += [f'{name} = {{ version = "={version}", default-features = false }}' for name, version in found]
    (OUT / "Cargo.toml").write_text("\n".join(lines) + "\n")
    (OUT / "lib.rs").write_text("")
    print(f"wrote {OUT / 'Cargo.toml'}")

    if "--offline" in sys.argv:
        return 0
    behind = []
    for name, version in found:
        latest = newest(name)
        state = "newer upstream" if key(latest) > key(version) else "up to date"
        print(f"{name}: copied {version}, upstream {latest} ({state})")
        if key(latest) > key(version):
            behind.append(f"{name} {latest}")
    if behind:
        print(
            "::warning::upstream released "
            + ", ".join(behind)
            + ": see third_party/README.md for whether a copy can go or needs the release's fixes"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
