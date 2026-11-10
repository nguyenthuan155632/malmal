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
  MALMAL_ERROR = 3
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

void malmal_string_free(char *string);

#ifdef __cplusplus
}
#endif

#endif
