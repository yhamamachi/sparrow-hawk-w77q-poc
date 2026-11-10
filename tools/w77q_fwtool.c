/*
 * w77q_fwtool: R-Car/Linux application on top of QLIB for secure firmware update of one
 * rollback-protected W77Q section (the Zephyr image for the Cortex-R52).
 *
 * All security decisions (session authentication, digest/CRC check, rollback check, swap)
 * are made by QLIB and the W77Q itself. This tool only orchestrates the documented QLIB
 * flow (same as samples/qlib_sample_fw_update.c) and derives keys from a key file.
 *
 *   w77q_fwtool provision <keyfile> [section base size]
 *   w77q_fwtool install   <keyfile> <fw.bin> <manifest> [section]
 *   w77q_fwtool status    [section]
 *   w77q_fwtool read      <out.bin> <len> [section]      (plain read of the active half)
 *
 * install exit codes: 0 accepted, 10 rejected by the flash, 1 other error.
 */
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "w77q_common.h"
#include "qlib_sample.h"
#include "qlib_sample_fw_update.h"

void* W77Q_OpenFlash(const char*);
void  W77Q_CloseFlash(void*);

#define STR(x) #x
#define NAME(x) [x] = #x
static const char* const g_names[] = { QLIB_STATUS(GENERATE_STRING) };
static const char* st(QLIB_STATUS_T s) { return (unsigned)s < sizeof g_names / sizeof *g_names ? g_names[s] : "?"; }
#define CK(x) do { QLIB_STATUS_T s_ = (x); if (s_ != QLIB_STATUS__OK) { fprintf(stderr, "ERROR %s -> %s (%d)\n", #x, st(s_), (int)s_); rc = 1; goto out; } } while (0)

/* key derivation (application policy, not a QLIB feature): HMAC-SHA256(secret, label|wid|section) */
static int load_secret(const char* path, uint8_t sec[32])
{
    char hex[128] = {0};
    FILE* f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    if (!fgets(hex, sizeof hex, f) || strlen(hex) < 64) { fprintf(stderr, "%s: need 64 hex chars\n", path); fclose(f); return -1; }
    fclose(f);
    for (int i = 0; i < 32; i++) { unsigned v; if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1; sec[i] = (uint8_t)v; }
    return 0;
}
static int derive(const uint8_t sec[32], const char* label, const QLIB_ID_T* id, uint32_t section, KEY_T key)
{
    uint8_t msg[96], out[32]; size_t ol = 0;
    int n = snprintf((char*)msg, 40, "w77q-poc|%s|", label);
    memcpy(msg + n, &id->sec.wid, sizeof id->sec.wid); n += sizeof id->sec.wid;
    memcpy(msg + n, &section, 4); n += 4;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, sec, 32, msg, (size_t)n, out, 32, &ol)) return -1;
    memcpy(key, out, sizeof(KEY_T));
    return 0;
}

static int session_init(void** h, QLIB_CONTEXT_T* c)
{
    QLIB_STATUS_T s;
    *h = W77Q_OpenFlash(NULL);
    if (!*h) return 1;
    if ((s = QLIB_InitLib(c)) != QLIB_STATUS__OK) goto e;
    QLIB_SetUserData(c, *h);
    if ((s = QLIB_Connect(c)) != QLIB_STATUS__OK) goto e;
    if ((s = QLIB_InitDevice(c, QLIB_BUS_FORMAT(QLIB_BUS_MODE_1_1_1, false))) != QLIB_STATUS__OK) { QLIB_Disconnect(c); goto e; }
    return 0;
e:  fprintf(stderr, "ERROR init -> %s\n", st(s)); return 1;
}

static int cmd_status(uint32_t sec)
{
    QLIB_CONTEXT_T c; void* h; int rc = 0; QLIB_SECTION_CONF_T sc = {0}; uint32_t base = 0, size = 0;
    QLIB_SECTION_RUNTIME_STATUS_T rt = {0}; QLIB_STATUS_T r;
    if (session_init(&h, &c)) return 1;
    CK(QLIB_GetDeviceSectionConfig(&c, sec, &base, &size, &sc));
    printf("section=%u base=0x%08x size=0x%08x version=%u rollback=%u plainRead=%u plainWrite=%u digest=%u crc=%u\n", sec, base, size,
           sc.version, sc.policy.rollbackProt, sc.policy.plainAccessReadEnable, sc.policy.plainAccessWriteEnable,
           sc.policy.digestIntegrity, sc.policy.checksumIntegrity);
    printf("section digest=0x%016llx crc=0x%08x\n", (unsigned long long)sc.digest, sc.crc);
    r = QLIB_GetSectionRuntimeStatus(&c, sec, &rt);
    if (r == QLIB_STATUS__OK)
        printf("runtime: rollbackEnabled=%d swapped=%d plainRead=%d plainWrite=%d integrityPass=%d\n", rt.rollbackEnabled, rt.swapped,
               rt.plainReadEnabled, rt.plainWriteEnabled, rt.integrityCheckPass);
out:
    QLIB_Disconnect(&c); W77Q_CloseFlash(h);
    return rc;
}

static int cmd_read(const char* path, uint32_t len, uint32_t sec)
{
    QLIB_CONTEXT_T c; void* h; int rc = 0; uint8_t* b = malloc(len); FILE* f;
    if (session_init(&h, &c)) return 1;
    for (uint32_t off = 0; off < len; off += 256) {
        uint32_t n = len - off < 256 ? len - off : 256;
        CK(QLIB_Read(&c, b + off, sec, off, n, false, false));
    }
    f = fopen(path, "wb"); fwrite(b, 1, len, f); fclose(f);
out:
    QLIB_Disconnect(&c); W77Q_CloseFlash(h); free(b);
    return rc;
}

static int cmd_provision(const char* keyfile, uint32_t sec, uint32_t base, uint32_t size)
{
    QLIB_CONTEXT_T c; void* h; int rc = 0; uint8_t secret[32];
    QLIB_ID_T id; QLIB_FLASH_CONFIG_T fc = {0}; QLIB_DIE_CONFIG_T dc = {0};
    static QLIB_SECTIONS_CONF_TABLE_T tbl[QLIB_MAX_DIES_SUPPORTED];
    QLIB_EXTENDED_SECTION_CONF_T* e; uint8_t die = 0; uint8_t nd;
    if (load_secret(keyfile, secret)) return 1;
    if (session_init(&h, &c)) return 1;
    nd = QLIB_GET_NUM_OF_DIES(&c);
    CK(QLIB_GetId(&c, &id));
    CK(QLIB_GetDeviceConfigMultiDie(&c, &fc, &dc, tbl, nd));
    CK(QLIB_GetActiveDie(&c, &die));
    e = &tbl[die].sectionConfigTable[sec];
    if (e->sectionConfig.policy.rollbackProt) { printf("section %u already provisioned (rollback protected), nothing to do\n", sec); goto out; }

    /* factory pre-provisioned master key (needed to install our own keys) + our device master key */
    CK(QLIB_SAMPLE_GetDeviceKey(&c, id.sec.wid, QLIB_KID__DEVICE_KEY_PRE_PROVISIONING, dc.preProvisionedMasterKey));
    if (derive(secret, "master", &id, 0, dc.deviceMasterKey)) { rc = 1; goto out; }

    e->baseAddr = base; e->size = size;
    e->sectionConfig.policy.plainAccessReadEnable = 1;  /* U-Boot reads the active half with plain reads */
    e->sectionConfig.policy.plainAccessWriteEnable = 0; /* only authenticated sessions may write         */
    e->sectionConfig.policy.authPlainAccess = 0;
    e->sectionConfig.policy.checksumIntegrity = 0;
    e->sectionConfig.policy.digestIntegrity = 0;
    e->sectionConfig.policy.digestIntegrityOnAccess = 0;
    e->sectionConfig.policy.rollbackProt = 1;
    e->sectionConfig.policy.slog = 0;
    e->sectionConfig.policy.writeProt = 0;
    e->resetPA = true;
    if (derive(secret, "full", &id, sec, e->fullAccessKey)) { rc = 1; goto out; }

    printf("provisioning section %u: base=0x%x size=0x%x rollback-protected\n", sec, base, size);
    CK(QLIB_ConfigDeviceMultiDie(&c, &fc, &dc, tbl, nd));
    CK(QLIB_SetActiveDie(&c, die));
    printf("provision OK\n");
out:
    QLIB_Disconnect(&c); W77Q_CloseFlash(h);
    return rc;
}

static int parse_manifest(const char* path, uint32_t* ver, uint32_t* size, uint64_t* digest, uint32_t* crc)
{
    char line[128]; FILE* f = fopen(path, "r"); int got = 0;
    if (!f) { perror(path); return -1; }
    while (fgets(line, sizeof line, f)) {
        unsigned long long v;
        if (sscanf(line, "version=%llu", &v) == 1) { *ver = (uint32_t)v; got |= 1; }
        else if (sscanf(line, "size=%llu", &v) == 1) { *size = (uint32_t)v; got |= 2; }
        else if (sscanf(line, "digest=%llx", &v) == 1) { *digest = v; got |= 4; }
        else if (sscanf(line, "crc=%llx", &v) == 1) { *crc = (uint32_t)v; got |= 8; }
    }
    fclose(f);
    return got == 15 ? 0 : -1;
}

static int cmd_install(const char* keyfile, const char* fwpath, const char* mpath, uint32_t sec)
{
    QLIB_CONTEXT_T c; void* h = NULL; int rc = 0; uint8_t secret[32]; QLIB_ID_T id; KEY_T key;
    uint32_t len = 0, mver = 0, msize = 0, mcrc = 0, base, ssize; uint64_t mdig = 0; uint8_t* fw = NULL;
    QLIB_SECTION_CONF_T cur = {0}; QLIB_STATUS_T r; bool keyLoaded = false;
    if (load_secret(keyfile, secret)) return 1;
    if (parse_manifest(mpath, &mver, &msize, &mdig, &mcrc)) { fprintf(stderr, "bad manifest %s\n", mpath); return 1; }
    fw = w77q_load_file(fwpath, &len);
    if (!fw) return 1;
    if (session_init(&h, &c)) return 1;
    CK(QLIB_GetId(&c, &id));
    CK(QLIB_GetDeviceSectionConfig(&c, sec, &base, &ssize, &cur));
    printf("current: version=%u; offered: version=%u size=%u (manifest size %u)\n", cur.version, mver, len, msize);
    if (derive(secret, "full", &id, sec, key)) { rc = 1; goto out; }
    CK(QLIB_LoadKey(&c, sec, key, true));
    keyLoaded = true;

    /* QLIB (sample helper): erase inactive half, secure write, QLIB_ConfigDeviceSection(digest, crc, version, swap) */
    r = QLIB_SAMPLE_SectionUpdate(&c, fw, len, sec, &mdig, &mcrc, &mver, true, QLIB_SECTION_CONF_ACTION__RELOAD);
    if (r != QLIB_STATUS__OK) {
        printf("RESULT: REJECTED (%s)\n", st(r));
        rc = 10; goto out;
    }
    CK(QLIB_GetDeviceSectionConfig(&c, sec, NULL, NULL, &cur));
    printf("RESULT: ACCEPTED (section version now %u)\n", cur.version);
out:
    if (keyLoaded) (void)QLIB_RemoveKey(&c, sec, true);
    if (h) { QLIB_Disconnect(&c); W77Q_CloseFlash(h); }
    free(fw);
    return rc;
}

int main(int argc, char** argv)
{
    uint32_t sec = W77Q_SECTION_DEFAULT;
    if (argc >= 2 && !strcmp(argv[1], "status")) return cmd_status(argc > 2 ? (uint32_t)strtoul(argv[2], 0, 0) : sec);
    if (argc >= 4 && !strcmp(argv[1], "read")) return cmd_read(argv[2], (uint32_t)strtoul(argv[3], 0, 0), argc > 4 ? (uint32_t)strtoul(argv[4], 0, 0) : sec);
    if (argc >= 3 && !strcmp(argv[1], "provision"))
        return cmd_provision(argv[2], argc > 3 ? (uint32_t)strtoul(argv[3], 0, 0) : sec, argc > 4 ? (uint32_t)strtoul(argv[4], 0, 0) : W77Q_BASE_DEFAULT,
                             argc > 5 ? (uint32_t)strtoul(argv[5], 0, 0) : W77Q_SIZE_DEFAULT);
    if (argc >= 5 && !strcmp(argv[1], "install")) return cmd_install(argv[2], argv[3], argv[4], argc > 5 ? (uint32_t)strtoul(argv[5], 0, 0) : sec);
    fprintf(stderr, "usage: %s provision <keyfile> [sec base size] | install <keyfile> <fw.bin> <manifest> [sec] | status [sec] | read <out> <len> [sec]\n", argv[0]);
    return 1;
}
