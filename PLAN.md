# malmal — kế hoạch triển khai

Thư viện Rust quét file upload (ảnh, SVG, PDF, PostScript/EPS/AI) như một lớp phòng thủ.
Build ra static binary (`x86_64-unknown-linux-musl`), chạy trên Debian không cần cài thêm gì.

## Quyết định thiết kế

| Vấn đề | Quyết định | Lý do |
|---|---|---|
| Hình thức phân phối | Crate Rust là chính, kèm CLI; C ABI và daemon là tuỳ chọn ở M6 | Backend là Rust nên nhúng thẳng crate; CLI để kiểm thử và dùng trong script |
| Parser | Tự viết cho ảnh, PDF, PostScript | File độc hại thường sai chuẩn có chủ đích; parser "đúng chuẩn" như `lopdf` sẽ từ chối hoặc bỏ sót |
| Xử lý lỗi parse | Không bao giờ panic, không bao giờ coi lỗi parse là "sạch" | Lỗi parse sinh ra finding `*.malformed` |
| `unsafe` | `#![forbid(unsafe_code)]` ở mọi crate trừ `malmal-ffi` | Scanner không được trở thành lỗ hổng |
| Dependency | Chỉ crate thuần Rust, số lượng tối thiểu | Giữ static build đơn giản, giảm bề mặt supply chain |
| YARA | Feature `yara` (tắt mặc định), dùng `yara-x` | `yara-x` kéo theo `wasmtime`, làm binary to và build chậm |
| Kết quả khi vượt giới hạn | `Suspicious` + finding `limit.*` | Fail-closed: không quét hết thì không được báo sạch |

Dependency dự kiến: `miniz_oxide` (Flate), `weezl` (LZW), `quick-xml` (SVG/XMP), `sha2`,
`serde` + `serde_json`, `landlock` + `seccompiler` (sandbox), `yara-x` (tuỳ chọn).
CLI tự parse tham số, không dùng `clap`.

## Cấu trúc workspace

```
malmal/
├── Cargo.toml                 # workspace, profile release (lto, panic=abort ở CLI)
├── crates/
│   ├── malmal/                # thư viện lõi
│   │   └── src/
│   │       ├── lib.rs         # Scanner, ScanOptions, scan_bytes / scan_reader
│   │       ├── report.rs      # Verdict, Finding, Severity, Report
│   │       ├── limits.rs      # Limits, Budget (đếm byte giải nén, độ sâu, thời gian)
│   │       ├── detect.rs      # nhận diện loại file bằng magic bytes
│   │       ├── policy.rs      # Policy: ánh xạ mã finding -> hành động
│   │       ├── payload.rs     # bộ dò chuỗi dùng chung (php, script, header PE/ELF/ZIP)
│   │       ├── image/         # jpeg.rs png.rs gif.rs webp.rs bmp.rs tiff.rs meta.rs
│   │       ├── svg.rs
│   │       ├── pdf/           # lexer.rs object.rs xref.rs filters.rs analyze.rs
│   │       ├── ps/            # lexer.rs analyze.rs (PostScript, EPS, AI cũ)
│   │       ├── hashlist.rs    # blocklist SHA-256
│   │       └── yara.rs        # sau feature "yara"
│   ├── malmal-cli/            # binary `malmal`
│   ├── malmal-ffi/            # cdylib + staticlib, header malmal.h
│   └── malmal-daemon/         # binary `malmald`, Unix socket
├── fuzz/                      # cargo-fuzz, một target cho mỗi parser
├── tests/corpus/{clean,malicious}/
└── rules/                     # rule YARA mặc định
```

## API lõi

```rust
pub enum Verdict { Clean, Suspicious, Malicious }
pub enum Severity { Info, Low, Medium, High, Critical }

pub struct Finding {
    pub code: &'static str,     // vd "pdf.javascript"
    pub severity: Severity,
    pub message: String,
    pub offset: Option<u64>,
}

pub struct Report {
    pub verdict: Verdict,
    pub detected_type: FileType,
    pub declared_type: Option<FileType>,
    pub sha256: [u8; 32],
    pub findings: Vec<Finding>,
}

let scanner = Scanner::builder().limits(Limits::default()).policy(Policy::strict()).build();
let report = scanner.scan_bytes(&data, ScanHints { filename, content_type });
```

Verdict được tính từ finding qua `Policy`: finding `Critical`/`High` -> `Malicious`,
`Medium`/`Low` -> `Suspicious`, chỉ `Info` -> `Clean`. Policy cho phép ghi đè theo mã.

## Bảng mã finding

| Nhóm | Mã | Mức mặc định |
|---|---|---|
| Chung | `type.mismatch` (nội dung khác extension/Content-Type) | Medium |
| | `type.unknown`, `type.not_allowed` | Medium |
| | `type.executable` (PE/ELF/Mach-O/script có shebang) | Critical |
| | `name.dangerous_extension` (`shell.php.jpg`, `.htaccess`) | High |
| | `payload.php` (`<?php` ở mọi loại file; thêm `<?=` trong ảnh raster) | High |
| | `payload.script` (`<script`, `<iframe`, `javascript:` trong ảnh raster) | High |
| | `payload.template` (`<%=`, `<%@` trong ảnh raster) | High |
| | `limit.size`, `limit.decompression`, `limit.depth`, `limit.time`, `limit.complexity` | Medium |
| | `hash.blocklisted`, `yara.match` | Critical |
| Ảnh | `image.malformed` | Medium |
| | `image.trailing_data` (bỏ qua padding rỗng và khung MPF của JPEG) | Low |
| | `image.polyglot` (phần thừa là ZIP/PDF/PE/ELF/HTML; header PDF trong 1024 byte đầu; bản ghi ZIP kết thúc file) | High |
| | `image.metadata.payload` (code trong chunk PNG nén `zTXt`/`iTXt`/`iCCP`) | High |
| | `image.pixel_bomb` | Medium |
| SVG | `svg.script` (`<script>`, `<handler>`, stylesheet XSLT) | High |
| | `svg.event_handler` (thuộc tính `on*`, animation gán `on*`) | High |
| | `svg.javascript_uri` (trong `href`/`src`, animation, CSS) | High |
| | `svg.data_uri` | High nếu là HTML/XML/JS, Medium nếu loại khác không phải ảnh |
| | `svg.foreign_object`, `svg.external_ref` | Medium |
| | `svg.entity` (entity ngoài, parameter entity, entity lồng nhau, `ATTLIST`) | High |
| | `svg.malformed` (XML sai, encoding lạ, gốc không phải `<svg>`) | Medium |
| PDF | `pdf.javascript`, `pdf.launch` | High |
| | `pdf.open_action`, `pdf.additional_action` | Medium; High nếu trỏ tới JS/Launch; không báo nếu chỉ là nhảy trang |
| | `pdf.embedded_file` (file nhúng còn được quét đệ quy), `pdf.rich_media`, `pdf.xfa` | Medium |
| | `pdf.submit_form`, `pdf.remote_goto`, `pdf.uri` | Low (`uri` là Info) |
| | `pdf.obfuscated_name` (`#xx` trong tên khoá nhạy cảm) | High |
| | `pdf.encrypted`, `pdf.malformed`, `pdf.incremental_update` | Medium / Medium / Info |
| PostScript | `ps.file_access` (`file` ngoài `%stdin`/`%stdout`, `run`, `deletefile`, `renamefile`, `/OutputFile`) | High |
| | `ps.pipe` (`%pipe%` ở bất kỳ đâu, kể cả viết bằng escape hay hex) | Critical |
| | `ps.ghostscript_internal` (mọi toán tử bắt đầu bằng dấu chấm trừ nhóm vô hại; `superexec`, `getenv`...) | High |
| | `ps.exec_dynamic` (`cvx exec` trên code giải mã lúc chạy) | Medium |
| | `ps.malformed` (thiếu `%!`, header EPS nhị phân sai) | Medium |
| | `ps.wmf_preview` (EPS kèm preview WMF, không được phân tích) | Info |
| YARA | `yara.match`; `yara.error` khi rule không chạy xong | Critical; Medium |

## Các mốc

Mỗi mốc kết thúc khi: `cargo test` xanh, `cargo clippy -- -D warnings` sạch, và tiêu chí riêng đạt.

### M0 — Khung dự án
- `git init`, workspace với `malmal` và `malmal-cli` (crate FFI/daemon tạo ở M6), `rustup target add x86_64-unknown-linux-musl`.
- `report.rs`, `limits.rs`, `policy.rs` với test đơn vị.
- **Xong khi:** `cargo build --release --target x86_64-unknown-linux-musl` ra binary và `ldd` báo "not a dynamic executable".

### M1 — Core
- `detect.rs`: magic bytes cho JPEG, PNG, GIF, WebP, BMP, TIFF, SVG, PDF, PS/EPS, ZIP, PE, ELF, Mach-O, HTML, shebang.
  Tìm `%PDF-` trong 1024 byte đầu (đúng cách Acrobat đọc), không chỉ ở offset 0.
- So khớp với extension và `Content-Type` -> `type.mismatch`.
- `Budget`: mọi vòng lặp parse và mọi lần giải nén đều trừ vào budget.
- `payload.rs`: dò `<?php`, `<?=`, `<script`, `<%`, `eval(`, header file thực thi.
- `hashlist.rs`: nạp file text mỗi dòng một SHA-256.
- CLI tối thiểu: `malmal scan <file>... [--json] [--policy strict|default]`; exit code 0 sạch, 1 nghi ngờ, 2 độc hại, 3 lỗi.
- **Xong khi:** EICAR bị chặn qua hashlist; file `.jpg` chứa ELF cho `type.mismatch` + `type.executable`.

### M2 — Ảnh raster

> **Trạng thái: xong** (M0, M1 cũng đã xong). Khác với mô tả bên dưới: không có `meta.rs`.
> Metadata không nén (EXIF, XMP, ICC, comment) và phần dữ liệu thừa được phủ bằng một lần
> quét payload trên toàn bộ file ảnh, báo qua các mã `payload.*`; chỉ chunk PNG nén mới cần
> giải nén riêng. Pixel bomb mới chỉ kiểm tra tổng số pixel, chưa có tỉ lệ pixel/byte.
> Còn nợ: corpus ảnh thật cho TIFF, WebP, BMP và ảnh chụp từ điện thoại (M7).
- Mỗi định dạng một module duyệt cấu trúc tới đúng điểm kết thúc logic:
  JPEG (marker tới EOI), PNG (chunk + CRC tới IEND), GIF (block tới trailer `0x3B`),
  WebP (RIFF), BMP (kích thước trong header), TIFF (chuỗi IFD, phát hiện vòng lặp offset).
- Sau điểm kết thúc -> `image.trailing_data`, rồi chạy `payload.rs` và `detect.rs` trên phần thừa.
- `meta.rs`: tách EXIF, XMP, ICC, comment JPEG, `tEXt`/`zTXt`/`iTXt` PNG (giải nén có budget), quét payload.
- Pixel bomb: `rộng * cao` vượt ngưỡng, hoặc tỉ lệ pixel/byte bất thường.
- **Xong khi:** phát hiện đủ các mẫu tự tạo: webshell trong EXIF, JPEG+ZIP, GIF+JS (GIFAR), PNG có PHP trong `tEXt`; toàn bộ `corpus/clean` ảnh ra `Clean`.

### M3 — SVG

> **Trạng thái: xong.** Khác với mô tả bên dưới: DOCTYPE không bị báo ngay. Entity chuỗi đơn
> giản (kiểu Illustrator khai báo namespace) được giữ lại và mở rộng khi dùng, có trừ ngân
> sách; chỉ entity ngoài, parameter entity, entity chứa markup/tham chiếu và `ATTLIST` mới bị
> báo. SVG nhúng qua `data:image/svg+xml` được quét đệ quy. Link `<a href="https://...">`
> không bị coi là tham chiếu ngoài vì chỉ chạy khi người dùng bấm.
> Còn nợ: ảnh raster nhúng qua `data:` chưa được đưa qua bộ phân tích ảnh; dữ liệu thừa sau
> luồng gzip của SVGZ chưa được kiểm tra.
- `quick-xml` ở chế độ không mở rộng entity; gặp DOCTYPE/ENTITY là báo ngay.
- So tên phần tử và thuộc tính không phân biệt hoa thường, bỏ namespace prefix.
- Kiểm tra `<script>`, thuộc tính `on*`, `href`/`xlink:href` với `javascript:` và `data:` (giải mã entity, bỏ khoảng trắng và ký tự điều khiển trước khi so), `<foreignObject>`, `<use>`/`<image>` trỏ ra ngoài, `<style>` có `@import`/`url()` ngoài.
- SVGZ: giải nén có budget rồi quét.
- **Xong khi:** bắt được bộ payload XSS SVG chuẩn (kể cả biến thể làm rối `jav&#x09;ascript:`).

### M4 — PDF

> **Trạng thái: xong.** Khác với mô tả bên dưới: không có `xref.rs`. Bảng xref bị bỏ qua hoàn
> toàn; mọi `N G obj` trong file được parse tại chỗ (kể cả khi nằm trong dữ liệu stream), cộng
> với object stream đã giải nén. Object không parse được vẫn được dò tên từng token.
> Stream Flate hỏng hoặc cụt vẫn dùng phần giải nén được, như các trình đọc PDF.
> Còn nợ: PDF mã hoá với mật khẩu rỗng (trình đọc mở không hỏi) chỉ ra `pdf.encrypted`, không
> được giải mã; nội dung XFA không được phân tích; dữ liệu sau `%%EOF` cuối chưa được kiểm tra;
> predictor TIFF và các filter ảnh làm object stream bị báo `pdf.malformed`.
- `lexer.rs`: token PDF, chuẩn hoá tên (`#xx`), chuỗi literal và hex, chịu lỗi.
- `xref.rs`: đọc bảng xref và xref stream; **luôn** quét tuyến tính toàn file tìm `N G obj` song song, hợp nhất hai kết quả (file độc hại hay có xref sai hoặc object ẩn).
- `filters.rs`: Flate, ASCIIHex, ASCII85, LZW, RunLength, chuỗi filter lồng nhau, predictor PNG; tất cả có budget.
- Mở object stream (`/ObjStm`) và phân tích object bên trong.
- `analyze.rs`: sinh finding theo bảng; đi theo tham chiếu từ `/OpenAction` và `/AA` để nâng mức nếu tới JS/Launch.
- File nhúng (`/EmbeddedFile`): giải mã rồi **quét đệ quy** bằng chính scanner (có `limit.depth`).
- `/Encrypt` -> `pdf.encrypted`; không cố giải mã.
- **Xong khi:** bắt được mẫu của Didier Stevens (JS trong ObjStm, tên làm rối, Launch); PDF sạch trong corpus không bị báo `High`.

### M5 — PostScript / EPS / AI

> **Trạng thái: xong.** Một file `ps.rs` thay cho thư mục `ps/`. Ngoài tokenizer còn có một
> lượt dò byte thô cho `%pipe%` và các toán tử nội bộ đã biết, để thứ tokenizer đọc sai không
> giấu được chúng. Chuỗi được `cvx`/`cvn` thì được giải mã và phân tích như code; vùng
> `eexec` được giải mã rồi dò; vùng `%%BeginData` được đọc cả như dữ liệu lẫn như code.
> File khai là PostScript nhưng thiếu `%!` vẫn được phân tích.
> Còn nợ: dữ liệu AI private trong file `.ai` dạng PDF chưa được phân tích; tên toán tử ghép
> lúc chạy không thể thấy bằng phân tích tĩnh; chưa chạy PoC công khai của các lỗi Ghostscript.
- Định tuyến: `.ai` có `%PDF-` -> pipeline PDF (kèm quét phần AI private data); `%!PS` -> pipeline PS.
  EPS nhị phân (header `C5 D0 D3 C6`): tách phần PS và phần preview TIFF/WMF, quét từng phần.
- `lexer.rs`: token PostScript (tên, chuỗi `()` lồng nhau, hex `<>`, ASCII85 `<~ ~>`, procedure `{}`, comment DSC).
- `analyze.rs`: so tên operator với danh sách nguy hiểm; giải mã chuỗi hex/ASCII85 rồi quét lại (payload hay giấu sau `cvx exec`); phát hiện `%pipe%` trong mọi chuỗi.
- **Xong khi:** bắt được PoC công khai của các lỗi Ghostscript (`%pipe%`, `.libfile`, `.forceput`); file `.ai`/`.eps` xuất từ Illustrator trong corpus sạch không bị báo `High`.

### M6 — YARA và đóng gói

> **Trạng thái: xong, trừ YARA trên musl.** Rủi ro đã nêu thành sự thật: `yara-x` không build
> được cho musl (build script của `wasmtime` lỗi), nên bản có YARA chỉ có ở dạng liên kết
> động với glibc; các module `pe`/`elf` cũng phải tắt vì lỗi biên dịch. Khác với mô tả bên
> dưới: header `malmal.h` viết tay thay vì sinh bằng `cbindgen`; daemon nằm chung crate
> `malmal-cli` (binary `malmald`) thay vì crate riêng; seccomp là danh sách chặn chứ không
> phải danh sách cho phép; giới hạn bộ nhớ là `RLIMIT_AS` 4 GB, không có `RLIMIT_CPU`.
> Đã kiểm trên Debian 13 trần: CLI, daemon và ví dụ C đều chạy với `--require-sandbox`.
- `yara.rs` sau feature `yara`: nạp thư mục rule, mỗi match thành `yara.match`. Kiểm tra sớm việc `yara-x` build được với musl — đây là rủi ro kỹ thuật lớn nhất của dự án; nếu không được thì bản có YARA sẽ build glibc tĩnh một phần.
- `malmal-ffi`: `malmal_scanner_new`, `malmal_scan_bytes`, `malmal_report_json`, `malmal_free`; sinh `malmal.h` bằng `cbindgen`; bọc `catch_unwind`.
- `malmald`: Unix socket, giao thức đơn giản (độ dài + dữ liệu vào, JSON ra), pool worker, timeout mỗi request.
- Sandbox trong CLI và daemon: Landlock (chỉ đọc file đầu vào), seccomp (cấm `execve`, mạng), `RLIMIT_AS`/`RLIMIT_CPU`; tự giảm cấp khi kernel không hỗ trợ.
- **Xong khi:** binary musl chạy được trong container `debian:stable-slim` trần; ví dụ gọi FFI từ C chạy đúng.

### M7 — Kiểm thử và làm cứng (chạy song song từ M1)

> **Trạng thái: xong phần làm được trên máy này.** Mười fuzz target trong `fuzz/`; fuzz tìm ra
> một panic trong bộ phân tích PostScript (`<~>`), đã sửa và có test hồi quy. Corpus trong
> `tests/corpus` được quét bởi `cargo test`. CI ở `.github/workflows/ci.yml` chưa từng chạy.
> Còn nợ: property test riêng chưa viết (các test "không panic" duyệt mọi tiền tố và mọi byte
> hỏng thay cho nó); corpus sạch từ điện thoại, Word, LaTeX và corpus độc hại của bên thứ ba
> (Mitra, Didier Stevens) chưa có; fuzz mới chạy vài phút mỗi target.
- Fuzz target cho từng parser: `detect`, `jpeg`, `png`, `gif`, `webp`, `bmp`, `tiff`, `svg`, `pdf`, `ps`. Bất biến: không panic, không vượt budget, không treo.
- Property test: nối byte ngẫu nhiên vào cuối ảnh sạch luôn sinh `image.trailing_data`.
- Corpus sạch từ nguồn thật (ảnh máy ảnh/điện thoại, PDF từ Word/LaTeX/Chrome, AI/EPS từ Illustrator) để đo tỉ lệ báo nhầm; mục tiêu 0 finding `High` trên corpus sạch.
- Corpus độc hại: mẫu tự tạo cho mỗi mã finding + bộ polyglot của Ange Albertini (Mitra) + mẫu PDF của Didier Stevens.
- Benchmark: mục tiêu trên 100 MB/s với ảnh, PDF 10 MB dưới 200 ms.
- CI: test, clippy, `cargo deny`, build musl, fuzz ngắn 60 giây mỗi target.

## Thứ tự và phụ thuộc

```
M0 -> M1 -> M2 -> M3
              \-> M4 -> M5 -> M6
M7 chạy song song từ M1
```

M3 và M4 độc lập nhau. M5 cần M4 vì file AI hiện đại là PDF. M6 cần mọi analyzer xong để chốt API.

## Việc cần chuẩn bị trên máy

- `rustup target add x86_64-unknown-linux-musl`
- `cargo install cargo-fuzz cargo-deny cbindgen` (fuzz cần thêm toolchain nightly)
- Docker hoặc Podman để kiểm tra trên Debian trần (M6)

## Ngoài phạm vi (ghi lại để làm sau)

- Re-encode ảnh (CDR): lớp phòng thủ mạnh nhất với ảnh raster, nên là dự án tiếp theo.
- Office (DOCX/XLSX macro), archive (ZIP/RAR đệ quy), video.
- Giải mã PDF có mật khẩu.
