# Finding codes

Every finding in a report has a `code`, a `severity` and a `message`. The code is the stable
part: match on it, not on the message. A code keeps its meaning across releases; new codes
arrive in minor releases.

The default policy turns the worst severity into the verdict: **High** and **Critical** give
`malicious`, **Low** and **Medium** give `suspicious`, **Info** leaves the file `clean`.
`Policy::strict()` already treats Medium as `malicious`, and
`Policy::with_override(code, severity)` changes one code, and `--allow CODE` lowers it to Info
in the commands. `malmal::report::CODES` lists the codes below.

A code listed with two severities is reported at the higher one when the reason given applies.

## Any file type

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `type.executable` | Critical | The content is a PE, ELF or Mach-O binary, or a script starting with `#!`. Also reported for a file embedded in a PDF. | Reject. |
| `type.mismatch` | Medium | The content is not the type the extension or `Content-Type` claims. | Reject, or store under the detected type. |
| `type.unknown` | Medium | The content is none of the types the scanner knows. | Reject; the file was not analyzed. |
| `type.not_allowed` | Medium | The type was recognized and the policy does not accept it. | Reject, or add the type with `with_allowed_types`. |
| `name.dangerous_extension` | High | The file name has an extension a web server or operating system may execute, anywhere in it: `shell.php.jpg`, `.htaccess`. | Reject, and never store uploads under the client's file name. |
| `payload.php` | High | A PHP opening tag in the content. In images, a complete `<?= ... ?>` short tag too. | Reject. |
| `payload.script` | High | `<script`, `<iframe` or a `javascript:` URL inside a raster image. | Reject. |
| `payload.template` | High | A complete ASP or JSP tag (`<%= ... %>`, `<%@ ... %>`) inside a raster image. | Reject. |
| `hash.blocklisted` | Critical | The SHA-256 is on the blocklist the scanner was given. | Reject. |
| `yara.match` | Critical | A YARA rule matched the file, or a file embedded in a PDF. The message names the rule. | Reject. |
| `yara.error` | Medium | The YARA rules could not be evaluated to the end. | Treat as not scanned. |

## Limits

A scan that stopped at a limit has not cleared the file, so none of these is ever `clean`.

| Code | Severity | Meaning |
|---|---|---|
| `limit.size` | Medium | The file is larger than `Limits::max_file_size`; only the start was analyzed. |
| `limit.decompression` | Medium | Compressed data inside the file expands past `Limits::max_decompressed`: a decompression bomb, or a limit set too low. |
| `limit.depth` | Medium | Files are embedded in files deeper than `Limits::max_depth`. |
| `limit.time` | Medium | The scan took longer than `Limits::max_duration`. |
| `limit.complexity` | Medium | The structure costs far more to walk than the file's size justifies: more objects than one for every 16 bytes of a PDF (two million in any file), references that lead to more values than that, or streams that overlap so that reading them all is many times the file. |

## Raster images

JPEG, PNG, GIF, WebP, BMP, TIFF and BigTIFF, PSD and PSB, HEIC, AVIF, JPEG XL, ICO.

| Code | Severity | Meaning | What to do |
|---|---|---|---|
| `image.malformed` | Medium | The structure is broken or truncated, a dimension is zero, or a part points outside the file. | Reject; a decoder may misbehave on it. |
| `image.trailing_data` | Low | Bytes follow the end of the image. Zero padding is ignored. | Re-encode the image, which drops them, or reject. |
| `image.vendor_trailer` | Info | The bytes after the image are a complete Samsung metadata trailer or motion photo video. | Nothing; raise the severity with an override to refuse them. |
| `image.polyglot` | High | The file is also another format: the bytes after the image are a ZIP, PDF, executable or HTML file, a PDF header sits near the start, or a ZIP end record closes the file. | Reject. |
| `image.metadata.payload` | High | Code in a compressed PNG chunk (`zTXt`, `iTXt`, `iCCP`) or a Brotli-compressed JPEG XL metadata box. | Reject. |
| `image.pixel_bomb` | Medium | The image, or a layer of a PSD, declares more pixels than `Limits::max_pixels`. | Reject before a decoder allocates them. |

## SVG

| Code | Severity | Meaning |
|---|---|---|
| `svg.script` | High | A `<script>` or `<handler>` element, or an XSLT stylesheet. |
| `svg.event_handler` | High | An `on*` attribute, or an animation that sets one. |
| `svg.javascript_uri` | High | A `javascript:` URL in a link, an animation or CSS. |
| `svg.data_uri` | High / Medium | A `data:` URL. High when it holds HTML, XML or JavaScript; Medium for other non-image types. |
| `svg.foreign_object` | Medium | A `<foreignObject>`, which embeds HTML. |
| `svg.external_ref` | Medium | A reference to a resource outside the file, fetched when it is rendered. |
| `svg.entity` | High | DTD tricks: external, parameter or nested entities, `ATTLIST` defaults. |
| `svg.malformed` | Medium | Broken XML, an unusual encoding, or a root element that is not `<svg>`. |

Serve user-supplied SVG from a separate origin or with a `Content-Security-Policy` that
forbids scripts, whatever the verdict.

## PDF

Also applies to Illustrator files saved since version 9, which are PDFs.

| Code | Severity | Meaning |
|---|---|---|
| `pdf.javascript` | High | JavaScript in an action, a name tree or the scripts of an XFA form. A name tree of scripts that lists none, which Acrobat writes into many documents, is not reported; one that cannot be read is. |
| `pdf.launch` | High | An action that starts a program or opens a file. |
| `pdf.postscript` | High | PostScript handed to an interpreter: a PostScript XObject, a form XObject with a PostScript alternative, the `PS` operator in page content or in the default appearance string (`/DA`) of a form, or a calculator function (`/FunctionType 4`) that holds anything but the operators the format allows. |
| `pdf.open_action` | Medium / High | An action runs when the document opens. High when it leads to JavaScript or a launch; a plain jump to a page is not reported. |
| `pdf.additional_action` | Medium / High | An action runs on a page or document event. Same rule as `pdf.open_action`. |
| `pdf.obfuscated_name` | High | A keyword such as `/JavaScript` written with `#xx` escapes, which no PDF writer does. |
| `pdf.embedded_file` | Medium | The document carries attachments. Each one is scanned too, and what is found in it is reported with the prefix `embedded file:`. Not reported: an empty tree of attachments, the packets of an XFA form (which Adobe's programs store as streams of the same type; the form is `pdf.xfa`), and the rights over attachments that a signature grants (`/EF` as an array). |
| `pdf.rich_media` | Medium | Embedded Flash, video, sound or 3D content: `RichMedia`, `Movie`, `Sound` and `Screen` annotations, `3D`, `U3D` and `PRC` artwork. |
| `pdf.xfa` | Medium | An XFA form. Its packets are searched for scripts, which are reported as `pdf.javascript`. |
| `pdf.encrypted` | Info / Medium | The document is encrypted. Info when the empty password or one given with `pdf_passwords` opens it: the content was decrypted and inspected. Medium when no password at hand opens it, so its streams could not be inspected. |
| `pdf.polyglot` | High / Medium | The file is also another format: the bytes after the last `%%EOF` are a recognizable file, a ZIP end record closes the file, or a ZIP file header stands outside every stream. Medium for HTML or SVG markup (`<html`, `<script`, `<svg`) outside every stream. The same bytes in the data of a stream are data and are not reported. |
| `pdf.trailing_data` | Low | Bytes other than padding follow the last `%%EOF`. |
| `pdf.submit_form` | Low | A form action that sends or fetches data. |
| `pdf.remote_goto` | Low | An action that opens another document. |
| `pdf.uri` | Info | Links to external addresses. |
| `pdf.dangerous_uri` | High / Medium | A link that is not to a web page. High when it runs a script (`javascript:`, `vbscript:`, `data:`) or starts a protocol handler with a history of exploits (`ms-msdt:` and the other `ms-*:`, `search-ms:`, `mhtml:`, `jar:`, `shell:`). Medium when it opens a network share (`file://server/share`, `smb:`, `\\server\share`), which is sent the reader's Windows credentials, or a program or script on the reader's own machine (`file:///C:/…/x.exe`, `C:\…\x.bat`). A link to any other local file is what converting a saved web page leaves behind (`file:///C|/book/index.html`); it is as common in harmless documents as in the others and is reported as `pdf.uri` only. The address is read as a browser reads it: in either case, in UTF-16, with tabs and line breaks dropped. Also reported for the base address of the document (`/URI << /Base >>`). |
| `pdf.external_ref` | Medium | Content that is read from outside the file when it is rendered: a stream whose data is in another file (`/F`, `/FFilter`), a form that draws a page of another document (`/Ref`), a file specification that names a URL (`/FS /URL`), OPI comments. What is printed is then not what was scanned, and the renderer opens a path the file chose. |
| `pdf.xml_entity` | High / Medium | XML in the document (XMP metadata, an XFA packet) with a document type declaration. High when it declares entities: XXE and entity expansion in the XML parsers of readers and server tools. UTF-16 and UTF-32 text is read too. |
| `pdf.xml_external_ref` | Medium | XML in the document that makes its parser fetch something: XInclude, `<?xml-stylesheet?>`, an XFA web service connection. |
| `pdf.pixel_bomb` | Medium | An image declares more pixels than `Limits::max_pixels`: a few bytes that make a renderer allocate gigabytes. |
| `pdf.page_size` | Medium | A page box is longer than 28,800 points on a side (400 inches) after `/UserUnit`, twice what the format allows. Rasterizing it exhausts memory. |
| `pdf.draw_recursion` | Medium | A form XObject that draws itself, directly or through other forms, by its own resources or those of the page. Renderers follow the calls until they crash or hang. Only what content draws counts, not what a resource dictionary lists. |
| `pdf.conflicting_objects` | Medium | An object number is defined twice with different contents and no `%%EOF` between the two, so that no update explains it. Which one counts depends on the reader: the trick that shows a scanner one document and a reader another. Identical repeats and objects that stand in the data of a stream are not reported. |
| `pdf.risky_codec` | Info | An image compressed with JBIG2 or JPEG 2000, whose decoders have a long history of exploits (FORCEDENTRY). Raise the severity with an override to refuse them. |
| `pdf.print_only` | Info | An annotation or a layer that is printed and not shown on screen: what is approved on screen is not what comes out of the printer. Some real files carry such stamps. |
| `pdf.signature_modified` | Info | A signature's `/ByteRange` does not cover the whole file: bytes were added after signing, or left out of what was signed. Filling in a form or signing a second time does this too. Only the ranges are checked, not the signature. |
| `pdf.incremental_update` | Info | Several `%%EOF` markers: the file was saved incrementally or is linearized. |
| `pdf.malformed` | Medium | A missing header or `%%EOF`, data before the header, a second header, an object that could not be parsed, a stream that could not be decoded, decode parameters outside what the format allows (decoders size their buffers from them), or a name longer than 255 bytes. |

## PostScript, EPS and older Illustrator files

Static analysis of PostScript cannot be complete. Whatever the verdict, run Ghostscript with
`-dSAFER` and in a sandbox of its own.

| Code | Severity | Meaning |
|---|---|---|
| `ps.pipe` | Critical | `%pipe%`, which runs a shell command, however it is spelled. |
| `ps.file_access` | High | Reading, writing, deleting or renaming files: `file` on anything but standard input and output, `run`, `deletefile`, `renamefile`, `/OutputFile`. |
| `ps.device_access` | High | Selecting or reconfiguring the output device. |
| `ps.ghostscript_internal` | High | Ghostscript's internal operators and the keys that lift its file restrictions; the building blocks of its known sandbox escapes. |
| `ps.exec_dynamic` | Medium | Code that is decoded at run time and then executed, which static analysis cannot read. |
| `ps.unusual_filter` | Medium | Encoding filters that documents have no use for. |
| `ps.malformed` | Medium | No `%!` header, or a broken binary EPS header. |
| `ps.wmf_preview` | Info | An EPS with a WMF preview, which is not analyzed. |
