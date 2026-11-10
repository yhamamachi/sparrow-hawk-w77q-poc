/*
 * w77q_manifest: build-time helper. Computes the W77Q section digest/CRC of a firmware
 * image (padded with 0xFF to the size of one half of the rollback section) using the
 * QLIB utilities, and writes a small key=value manifest consumed by w77q_fwtool/SWUpdate.
 * Runs on any host (no flash access).
 *   w77q_manifest <fw.bin> <version> [section_size] > fw.manifest
 */
#include "w77q_common.h"
#include "qlib_utils_crc.h"
#include "qlib_utils_digest.h"

int main(int argc, char** argv)
{
    uint32_t len, secSize = W77Q_SIZE_DEFAULT, ver;
    uint64_t digest = 0; uint32_t crc = 0; DIGEST_EXT_T ext;
    uint8_t* fw;
    if (argc < 3) { fprintf(stderr, "usage: %s <fw.bin> <version> [section_size]\n", argv[0]); return 1; }
    ver = (uint32_t)strtoul(argv[2], NULL, 0);
    if (argc > 3) secSize = (uint32_t)strtoul(argv[3], NULL, 0);
    fw = w77q_load_file(argv[1], &len);
    if (!fw) return 1;
    if (len > secSize / 2) { fprintf(stderr, "firmware (%u) larger than half section (%u)\n", len, secSize / 2); return 1; }
    if (QLIB_UTILS_CalcCRCWithPadding((uint32_t*)fw, len, 0xFF, secSize / 2 - len, &crc) != QLIB_STATUS__OK ||
        QLIB_UTILS_CalcDigestWithPadding(fw, len, 0xFF, secSize / 2 - len, &digest, ext) != QLIB_STATUS__OK) {
        fprintf(stderr, "digest/crc calculation failed\n"); return 1;
    }
    printf("version=%u\nsize=%u\nsection_size=0x%x\ndigest=0x%016llx\ncrc=0x%08x\n", ver, len, secSize, (unsigned long long)digest, crc);
    return 0;
}
