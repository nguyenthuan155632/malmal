# malmal

Thư viện Rust quét file upload trước khi backend xử lý chúng: ảnh raster, SVG, PDF,
PostScript/EPS và file Illustrator. Nó không cạnh tranh với antivirus về số lượng
signature; nó kiểm tra ba thứ antivirus thường bỏ qua:

1. **File có đúng là loại nó khai báo không** (nội dung so với extension và `Content-Type`).
2. **File có chứa nội dung chủ động không** (script, action, lệnh hệ thống, file nhúng).
3. **File có đúng cấu trúc không** (dữ liệu thừa, polyglot, bom giải nén, file cắt cụt).

Nguyên tắc xuyên suốt là fail-closed: file không phân tích hết được thì không bao giờ
được báo là sạch.

Đây là một lớp phòng thủ, không phải lớp duy nhất. Với ảnh raster, decode rồi encode lại
vẫn là cách chắc chắn nhất; malmal quyết định file nào được đi tới bước đó.

## Build

```bash
cargo build --release --workspace --target x86_64-unknown-linux-musl
```

Kết quả nằm trong `target/x86_64-unknown-linux-musl/release/`:

| File | Là gì |
|---|---|
| `malmal` | CLI, liên kết tĩnh hoàn toàn |
| `malmald` | Daemon trên Unix socket, liên kết tĩnh hoàn toàn |
| `libmalmal_ffi.a` | Thư viện tĩnh cho C, header ở `crates/malmal-ffi/include/malmal.h` |

Hai binary chạy được trên Debian trần, không cần cài thêm gói nào.

## Dùng từ Rust

```rust
use malmal::{Policy, ScanHints, Scanner, Verdict};

let scanner = Scanner::builder().policy(Policy::strict()).build();
let report = scanner.scan_bytes(&data, ScanHints {
    filename: Some("logo.svg"),
    content_type: Some("image/svg+xml"),
});
if report.verdict != Verdict::Clean {
    for finding in &report.findings {
        log::warn!("{} [{:?}] {}", finding.code, finding.severity, finding.message);
    }
    // từ chối upload
}
```

`Scanner` dùng chung được giữa các thread. `scan_reader` đọc từ `impl Read` và tự dừng ở
giới hạn kích thước.

- **`Policy`** quyết định verdict: `default` coi High trở lên là `Malicious`, `strict` coi
  Medium trở lên là `Malicious`. `with_override("svg.foreign_object", Severity::Info)`
  đổi mức của một mã; `with_allowed_types` thu hẹp loại file được nhận.
- **`Limits`** giới hạn kích thước file (64 MB), dữ liệu giải nén (256 MB), độ sâu file
  nhúng (4), thời gian (10 giây) và số pixel (2^28).
- **`HashList`** là blocklist SHA-256, đọc được thẳng output của `sha256sum`.

Bảng đầy đủ các mã finding nằm trong [PLAN.md](PLAN.md).

## CLI

```bash
malmal scan --json --policy strict upload.pdf
```

`-` đọc từ stdin. Exit code: 0 sạch, 1 nghi ngờ, 2 độc hại, 3 lỗi.

Trước khi mở file đầu tiên, tiến trình tự giam mình: Landlock chỉ cho đọc đúng các file
được truyền vào, seccomp chặn `execve`, socket và các syscall nguy hiểm khác, rlimit giới
hạn bộ nhớ. `--require-sandbox` biến việc không giam được thành lỗi; `--no-sandbox` tắt hẳn.

## Daemon

```bash
malmald --socket /run/malmal.sock --workers 8 --require-sandbox
```

Mỗi request là một dòng JSON rồi đúng `size` byte nội dung file:

```
{"size": 1234, "filename": "a.png", "content_type": "image/png"}\n<1234 byte>
```

Trả lời là một dòng JSON: `{"ok": true, "report": {...}}` hoặc
`{"ok": false, "error": "..."}`. Một kết nối gửi được nhiều request. Bất cứ thứ gì khác
`"ok": true` nghĩa là file chưa được quét.

## Dùng từ C

```c
malmal_scanner *scanner = malmal_scanner_new(0, NULL, 0);
char *report = NULL;
int verdict = malmal_scan(scanner, data, len, "a.png", "image/png", &report);
malmal_string_free(report);
malmal_scanner_free(scanner);
```

Ví dụ đầy đủ: `crates/malmal-ffi/examples/scan.c`.

## YARA (tuỳ chọn)

```bash
cargo build --release -p malmal-cli --features yara
malmal scan --yara rules/ upload.jpg
```

Tính năng này tắt mặc định vì nó kéo theo một runtime WebAssembly và đưa binary từ
0,8 MB lên 16 MB. Bản có YARA **không build được cho musl**; nó liên kết động với glibc,
nên hãy build trên chính bản Debian sẽ chạy nó. Các module `pe` và `elf` của YARA không
được bật.

## Kiểm thử

```bash
cargo test --workspace
```

```bash
cd fuzz && cargo +nightly fuzz run pdf corpus/pdf seeds/pdf
```

- `tests/corpus/clean` và `tests/corpus/malicious` được quét trong `cargo test`; thả file
  thật vào là có thêm ca kiểm thử.
- `fuzz/` có một target cho mỗi định dạng (`cargo fuzz list`).
- `cargo run --release --example throughput -- FILE...` đo thông lượng.

## Giới hạn đã biết

- **PostScript là ngôn ngữ lập trình đầy đủ**, nên phân tích tĩnh không thể trọn vẹn. Tên
  toán tử ghép lúc chạy sẽ không bị thấy; code giải mã lúc chạy bị báo `ps.exec_dynamic`
  chứ không được đọc. Hãy luôn chạy Ghostscript với `-dSAFER` và trong sandbox riêng.
- **PDF mã hoá không được giải mã**, kể cả loại mật khẩu rỗng; chúng ra `pdf.encrypted`.
- **Nội dung XFA và dữ liệu sau `%%EOF` của PDF chưa được phân tích.**
- **BigTIFF chưa hỗ trợ** và bị báo `image.malformed`.
- **File nhúng trong PDF không đi qua YARA.**
- Office, archive và video nằm ngoài phạm vi; chúng bị từ chối với `type.not_allowed`
  hoặc `type.unknown`.
