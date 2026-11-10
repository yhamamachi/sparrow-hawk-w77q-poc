#ifndef W77Q_COMMON_H
#define W77Q_COMMON_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qlib.h"

#define W77Q_SECTION_DEFAULT 4u
#define W77Q_BASE_DEFAULT    0x01000000u
#define W77Q_SIZE_DEFAULT    0x00100000u   /* 1 MiB: two 512 KiB halves (active/inactive) */

/* read whole file; returns malloc'd buffer padded with 0xFF to a multiple of 4 */
static inline uint8_t* w77q_load_file(const char* path, uint32_t* len)
{
    FILE* f = fopen(path, "rb");
    long n; uint8_t* b;
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    b = malloc((size_t)n + 4);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) { perror("read"); fclose(f); free(b); return NULL; }
    fclose(f);
    while (n & 3) b[n++] = 0xFF;
    *len = (uint32_t)n;
    return b;
}
#endif
