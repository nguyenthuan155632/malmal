# Third-party crates, patched

Copies of crates malmal depends on, with fixes that are not yet in a release
upstream. Each is published under the name `malmal-<crate>`, its version and
licence unchanged, and is used under its own name in the code (`package =` in
the manifest). Drop a copy once upstream releases its fixes.

## jxl-oxide 0.12.6, jxl-jbr 0.2.1, jxl-render 0.12.4

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
