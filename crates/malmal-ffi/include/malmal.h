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
 * Scan a file as malmal_scan does and, if it is a clean raster image, write
 * it anew from its pixels, so that nothing but the picture is kept.
 * `jpeg_quality` is the quality of a rebuilt JPEG, 1 to 100; anything else
 * selects the default of 90.
 *
 * Returns MALMAL_CLEAN when there is a new file: `*image` and `*image_len`
 * receive it, to be stored in place of the upload and released with
 * malmal_bytes_free. Its type is not always that of the input.
 * Any other result leaves `*image` NULL, and the upload is not to be stored:
 * MALMAL_SUSPICIOUS or MALMAL_MALICIOUS if the scan did not come back clean,
 * MALMAL_NOT_REBUILT if the file is not an image that can be rebuilt, is too
 * large or does not decode, and MALMAL_ERROR as for malmal_scan, or if
 * `image` or `image_len` is NULL.
 *
 * If `info_json` is not NULL it receives a NUL-terminated JSON object (NULL
 * on MALMAL_ERROR), to be released with malmal_string_free:
 *   {"report": {...}, "image": {"file_type": "png", "width": 1,
 *                               "height": 1, "frames": 1}}   new file
 *   {"report": {...}}                                         not clean
 *   {"error": "..."}                                          not rebuilt
 */
int malmal_sanitize(const malmal_scanner *scanner, const uint8_t *data,
                    size_t len, const char *filename, const char *content_type,
                    int jpeg_quality, uint8_t **image, size_t *image_len,
                    char **info_json);

void malmal_string_free(char *string);

/* Release an image from malmal_sanitize; `len` is the length it came with. */
void malmal_bytes_free(uint8_t *bytes, size_t len);

#ifdef __cplusplus
}
#endif

#endif
