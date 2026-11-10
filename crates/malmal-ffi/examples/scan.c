/* Scan the files named on the command line through the C interface. */
#include <stdio.h>
#include <stdlib.h>

#include "malmal.h"

static uint8_t *read_file(const char *path, size_t *len) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  rewind(file);
  uint8_t *data = malloc(size > 0 ? (size_t)size : 1);
  *len = data ? fread(data, 1, (size_t)size, file) : 0;
  fclose(file);
  return data;
}

int main(int argc, char **argv) {
  malmal_scanner *scanner = malmal_scanner_new(0, NULL, 0);
  if (!scanner) return MALMAL_ERROR;

  int worst = MALMAL_CLEAN;
  for (int i = 1; i < argc; i++) {
    size_t len;
    uint8_t *data = read_file(argv[i], &len);
    if (!data) {
      perror(argv[i]);
      worst = MALMAL_ERROR;
      continue;
    }
    char *report = NULL;
    int verdict = malmal_scan(scanner, data, len, argv[i], NULL, &report);
    printf("%s: %d %s\n", argv[i], verdict, report ? report : "");
    if (verdict > worst) worst = verdict;
    malmal_string_free(report);
    free(data);
  }
  malmal_scanner_free(scanner);
  return worst;
}
