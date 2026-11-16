/* C interface to the malmal upload scanner. */
#ifndef MALMAL_H
#define MALMAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct malmal_scanner malmal_scanner;

enum {
  MALMAL_CLEAN = 0,
  MALMAL_SUSPICIOUS = 1,
  MALMAL_MALICIOUS = 2,
  /* Invalid arguments or an internal failure; treat the file as not scanned. */
  MALMAL_ERROR = 3,
  /* From malmal_sanitize only: the file is clean but there is no new file. */
  MALMAL_NOT_REBUILT = 4
};

/*
 * Create a scanner. `strict` selects the strict policy (medium findings are
 * malicious). `hashlist` is an optional SHA-256 blocklist, one hex digest
 * per line, of `hashlist_len` bytes; pass NULL for none.
 * Returns NULL if the blocklist does not parse.
 * A scanner may be used from several threads at once.
 */
malmal_scanner *malmal_scanner_new(int strict, const char *hashlist,
                                   size_t hashlist_len);

/*
 * As malmal_scanner_new, with passwords to try on encrypted PDFs, each as
 * user and as owner password: `pdf_passwords` is `pdf_passwords_len` bytes,
 * one password per line, or NULL for none. A document one of them opens is
 * decrypted and inspected like any other.
 */
malmal_scanner *malmal_scanner_new_with_passwords(int strict,
                                                  const char *hashlist,
                                                  size_t hashlist_len,
                                                  const char *pdf_passwords,
                                                  size_t pdf_passwords_len);

/*
 * As malmal_scanner_new_with_passwords, with finding codes that do not count
 * against a file: `allow` is a NUL-terminated list such as
 * "pdf.xfa,pdf.embedded_file" (commas or '|' between them), or NULL for
 * none. An allowed finding is still in the report, at "info". The codes are
 * listed in docs/findings.md; a code the scanner does not report, or a
 * limit.* code, is an error.
 * On an error, returns NULL and, if `error` is not NULL, stores in it a
 * NUL-terminated message, to be released with malmal_string_free; it is
 * set to NULL otherwise.
 */
malmal_scanner *malmal_scanner_new_with_allow(
    int strict, const char *hashlist, size_t hashlist_len,
    const char *pdf_passwords, size_t pdf_passwords_len, const char *allow,
    char **error);

/*
 * A scanner configured by a NUL-terminated JSON object, or NULL or "" for the
 * defaults. Every key is optional; an unknown key is an error:
 *   "policy"           "default", "strict" or "documents"
 *   "allow"            finding codes reported at "info", as for
 *                      malmal_scanner_new_with_allow: ["pdf.xfa"]
 *   "types"            the accepted file types: ["jpeg", "png", "pdf"];
 *                      every supported type when absent
 *   "hashlist"         a SHA-256 blocklist, one hex digest per line
 *   "pdf_passwords"    passwords to try on encrypted PDFs: ["secret"], or a
 *                      password's bytes for one that is not UTF-8: [233, 116]
 *   "max_size", "max_decompressed", "max_pixels", "max_depth"
 *                      the limits of one scan, as the commands' options
 *   "scan_timeout"     seconds one scan may take, checked between steps
 *   "max_memory"       bytes one scan may hold; 0 for no limit [512 MiB]
 *   "without_hash"     true to leave the SHA-256 out of the report
 *   "wait"             seconds after which malmal_scan stops waiting for a
 *                      scan and reports limit.time; the scan is left running
 *                      on a thread of its own (see malmal_scanner_overdue)
 * On an error, returns NULL and stores a message in `error` as
 * malmal_scanner_new_with_allow does.
 */
malmal_scanner *malmal_scanner_new_json(const char *options, char **error);

/*
 * The scans that "wait" stopped waiting for and that are still running. At
 * most 4 are left running; past that, every file is refused at once with
 * limit.time until one of them ends. Above 0, restart the program when it can
 * be. Always 0 for a scanner without "wait", or NULL.
 */
uint64_t malmal_scanner_overdue(const malmal_scanner *scanner);

/* The version of this library, such as "0.4.0"; not to be freed. */
const char *malmal_version(void);

/*
 * Stop a scan that holds more than `max` bytes beyond what its thread held
 * when it began, with the finding limit.memory; 0 for no limit. What is
 * counted is what this library allocates, on the thread that calls it. A
 * new scanner has a limit of 512 MiB, as the commands' --max-memory.
 * Not to be called while another thread uses the scanner.
 */
void malmal_scanner_set_max_memory(malmal_scanner *scanner, uint64_t max);

void malmal_scanner_free(malmal_scanner *scanner);

/*
 * Scan `len` bytes at `data`. `filename` and `content_type` are what the
 * uploader claimed, as NUL-terminated strings, or NULL.
 * Returns MALMAL_CLEAN, MALMAL_SUSPICIOUS, MALMAL_MALICIOUS or MALMAL_ERROR.
 * If `report_json` is not NULL it receives the full report as a
 * NUL-terminated JSON string (NULL on MALMAL_ERROR); release it with
 * malmal_string_free.
 */
int malmal_scan(const malmal_scanner *scanner, const uint8_t *data, size_t len,
                const char *filename, const char *content_type,
                char **report_json);

/*
 * Scan a file as malmal_scan does and, if it is clean and of a type that can
 * be, write it anew: an image from its pixels, an SVG from what draws in it,
 * a PDF as pictures of its pages. `jpeg_quality` is the quality of a rebuilt
 * JPEG, 1 to 100; anything else selects the default of 90.
 *
 * Returns MALMAL_CLEAN when there is a new file: `*image` and `*image_len`
 * receive it, to be stored in place of the upload and released with
 * malmal_bytes_free. Its type is not always that of the input.
 * Any other result leaves `*image` NULL, and the upload is not to be stored:
 * MALMAL_SUSPICIOUS or MALMAL_MALICIOUS if the scan of the upload, or of the
 * file made from it, did not come back clean,
 * MALMAL_NOT_REBUILT if the file is not of a type that can be rebuilt, is too
 * large or does not decode, and MALMAL_ERROR as for malmal_scan, or if
 * `image` or `image_len` is NULL.
 *
 * If `info_json` is not NULL it receives a NUL-terminated JSON object (NULL
 * on MALMAL_ERROR), to be released with malmal_string_free:
 *   {"report": {...}, "image": {"file_type": "png", "width": 1,
 *                               "height": 1, "frames": 1}}   new file;
 *       width and height are 0 for an SVG or a PDF, frames its pages
 *   {"report": {...}}                not clean; the report that was not
 *   {"error": "..."}                                          not rebuilt
 */
int malmal_sanitize(const malmal_scanner *scanner, const uint8_t *data,
                    size_t len, const char *filename, const char *content_type,
                    int jpeg_quality, uint8_t **image, size_t *image_len,
                    char **info_json);

/*
 * As malmal_sanitize, with the options of the rebuild as a NUL-terminated
 * JSON object, or NULL or "" for the defaults. Every key is optional; an
 * unknown key or a value out of range is MALMAL_ERROR, with
 * {"error": "..."} in `info_json`:
 *   "jpeg_quality"     1 to 100 [90]
 *   "types"            the types to rebuild: ["jpeg", "png"]; others are
 *                      MALMAL_NOT_REBUILT before any decoder runs
 *   "keep_cmyk"        true to keep the inks of a CMYK JPEG, TIFF or PSD,
 *                      with their colour profile, rather than as sRGB
 *   "keep_profile"     true to keep the colours of an image under an RGB
 *                      or grey profile other than sRGB (Display P3, Adobe
 *                      RGB) in it, with the profile written anew, rather
 *                      than as sRGB
 *   "pdf_dpi"          36 to 600 [150]
 *   "pdf_jpeg"         true to keep a page as JPEG where that is smaller
 *   "pdf_text"         false to leave out the text layer of a rebuilt PDF
 *   "pdf_vector_text"  false to keep all text of a rebuilt PDF in the picture
 * The rebuild does not go through "wait".
 */
int malmal_sanitize_json(const malmal_scanner *scanner, const uint8_t *data,
                         size_t len, const char *filename,
                         const char *content_type, const char *options,
                         uint8_t **image, size_t *image_len, char **info_json);

void malmal_string_free(char *string);

/* Release an image from malmal_sanitize; `len` is the length it came with. */
void malmal_bytes_free(uint8_t *bytes, size_t len);

#ifdef __cplusplus
}
#endif

#endif
