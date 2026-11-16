# Third-party crates, patched

Copies of crates malmal depends on, with fixes that are not yet in a release
upstream. Each is published under the name `malmal-<crate>`, its version and
licence unchanged, and is used under its own name in the code (`package =` in
the manifest). Drop a copy once upstream releases its fixes.

Upkeep:

- `cargo audit` and RustSec advisories name the upstream crates, not these
  copies. The `Forks` workflow (weekly, and on changes here) checks the
  upstream crates at the versions copied for advisories, and fails once
  upstream releases a newer version: then see whether a copy can go, or bring
  the release's fixes over. `python3 scripts/forks.py` does the release check
  locally and writes the manifest the advisory check reads.
- A copy whose code changes after it is published needs a new version: raise
  the patch number (`0.2.1` to `0.2.2`; not `0.2.1-malmal.2`, which semver puts
  below `0.2.1`), write the release it came from in
  `[package.metadata.malmal] upstream`, and publish it before `malmal`.
- jxl-oxide: #508, #510 and #511 have pull requests upstream; #507 and #512 are
  issues with no pull request yet. filmcraft-av1 has no public repository, so
  its change stays here until its author adds a way to stop decoding.

## jxl-oxide 0.12.6, jxl-jbr 0.2.1 (published as 0.2.2), jxl-render 0.12.4

From <https://github.com/tirr-c/jxl-oxide> (MIT OR Apache-2.0, by Wonwoo Choi
and contributors). JPEG reconstruction (`jxl-jbr`) and rendering
(`jxl-render`):

- tirr-c/jxl-oxide#508: a scan of one subsampled component of a progressive
  JPEG is laid out by the sampling of the frame, not of the scan; it used to
  read past its grid and panic.
- tirr-c/jxl-oxide#507: a COM segment is written with one `0xFE`, not two.
- tirr-c/jxl-oxide#511: an empty DHT segment is written back empty.
- tirr-c/jxl-oxide#510: channels that share their sampling are not treated as
  subsampled (colour from luma), in reconstruction and rendering.
- tirr-c/jxl-oxide#512, and the same in DQT, APPn, COM, ICC and the data
  between markers: data that runs short is an error, not a panic.
- A scan whose component index, spectral selection or successive
  approximation is out of range is an error, not a panic (found by mutating
  the `jbrd` box, see `cdr::jxl` tests).

`jxl-oxide` itself is unchanged but for depending on the two above.

## filmcraft-av1 0.9.0

From the crate on crates.io (MIT OR Apache-2.0; it has no public repository
to send fixes to, and ships no licence files). The AV1 decoder of AVIF:

- `Decoder::set_cancel` takes a flag that, once set from another thread,
  stops the frame being decoded at its next superblock row (and before its
  post-filters) with `Error::Cancelled`. A rebuild past its deadline used to
  leave the decoder running to the end of the picture.
- The unused dependency on `filmcraft-bitstream` is dropped, and with it the
  tests and tools that are not in the crate.
