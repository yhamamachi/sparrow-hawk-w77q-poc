/* READ-ONLY probe: ids, hw version, feature bits, section table. Never writes to the flash. */
#include <stdio.h>
#include "qlib.h"
void* W77Q_OpenFlash(const char*);
void  W77Q_CloseFlash(void*);
#define CK(x) do { QLIB_STATUS_T s_ = (x); if (s_ != QLIB_STATUS__OK) { printf("FAIL %s -> %d\n", #x, (int)s_); return 1; } } while (0)
static void hex(const char* n, const uint8_t* p, int l) { printf("%s=", n); for (int i = 0; i < l; i++) printf("%02x", p[i]); puts(""); }
int main(void)
{
    QLIB_CONTEXT_T c; QLIB_HW_VER_T hw; QLIB_ID_T id; QLIB_SW_VERSION_T sv;
    QLIB_FLASH_CONFIG_T fc = {0}; QLIB_DIE_CONFIG_T dc = {0}; static QLIB_SECTIONS_CONF_TABLE_T tbl[QLIB_MAX_DIES_SUPPORTED];
    void* h = W77Q_OpenFlash(NULL);
    if (!h) return 1;
    CK(QLIB_GetVersion(&sv)); printf("qlib version 0x%08x target 0x%x\n", sv.qlibVersion, sv.qlibTarget);
    CK(QLIB_InitLib(&c)); QLIB_SetUserData(&c, h);
    CK(QLIB_Connect(&c));
    CK(QLIB_InitDevice(&c, QLIB_BUS_FORMAT(QLIB_BUS_MODE_1_1_1, false)));
    CK(QLIB_GetHWVersion(&c, &hw));
    printf("std mfr=%02x type=%02x cap=%02x dev=%02x | sec flash=%u secproto=%u rev=%u size=%02x hash=%u | dieType=0x%x flashSize=0x%x\n",
           hw.std.manufacturerID, hw.std.memoryType, hw.std.capacity, hw.std.deviceID, hw.sec.flashVersion, hw.sec.securityVersion,
           hw.sec.revision, hw.sec.flashSize, hw.sec.hashVersion, hw.info.dieType, hw.info.flashSize);
    CK(QLIB_GetId(&c, &id)); hex("suid", (uint8_t*)&id.sec.suid, 16);
    printf("features: LMS=%d AUTH_AC=%d RNG=%d VAULT=%d DIGEST_EXT=%d MULTIDIE=%d\n",
           QLIB_FeatureSupported(&c, W77Q_FEATURE_LMS), QLIB_FeatureSupported(&c, W77Q_FEATURE_AUTH_AC),
           QLIB_FeatureSupported(&c, W77Q_FEATURE_RNG), QLIB_FeatureSupported(&c, W77Q_FEATURE_VAULT),
           QLIB_FeatureSupported(&c, W77Q_FEATURE_DIGEST_EXT), QLIB_FeatureSupported(&c, W77Q_FEATURE_MULTI_DIE));
    CK(QLIB_GetDeviceConfigMultiDie(&c, &fc, &dc, tbl, QLIB_GET_NUM_OF_DIES(&c)));
    for (int s = 0; s < (int)QLIB_NUM_OF_SECTIONS; s++) {
        QLIB_EXTENDED_SECTION_CONF_T* e = &tbl[0].sectionConfigTable[s]; QLIB_POLICY_T p = e->sectionConfig.policy;
        printf("sec%d base=0x%08x size=0x%08x ver=%u rb=%u wp=%u plainR=%u plainW=%u auth=%u dig=%u crc=%u digOnAcc=%u resetPA=%d\n",
               s, e->baseAddr, e->size, e->sectionConfig.version, p.rollbackProt, p.writeProt, p.plainAccessReadEnable,
               p.plainAccessWriteEnable, p.authPlainAccess, p.digestIntegrity, p.checksumIntegrity, p.digestIntegrityOnAccess, e->resetPA);
    }
    {
        static const struct { const char* n; QLIB_KID_TYPE_T k; } kt[] = {
            {"pre-provisioned master", QLIB_KID__DEVICE_KEY_PRE_PROVISIONING}, {"device master", QLIB_KID__DEVICE_MASTER},
            {"device secret", QLIB_KID__DEVICE_SECRET}, {"section full-access", QLIB_KID__FULL_ACCESS_SECTION},
            {"section restricted", QLIB_KID__RESTRICTED_ACCESS_SECTION}, {"section LMS", QLIB_KID__SECTION_LMS} };
        for (unsigned i = 0; i < sizeof kt / sizeof *kt; i++) {
            printf("key provisioned: %-24s", kt[i].n);
            for (uint32_t s = 0; s < 9; s++) {
                bool b = false; QLIB_STATUS_T r = QLIB_IsKeyProvisioned(&c, kt[i].k, s, &b);
                printf(" %c", r == QLIB_STATUS__OK ? (b ? 'Y' : 'n') : '?');
                if (kt[i].k >= 0x8F) break;
            }
            puts("");
        }
        printf("devcfg: nonSecureFormatEn=%d devcfgLock=%d suid0=%08x\n", dc.nonSecureFormatEn, dc.devcfgLock, dc.suid[0]);
    }
    QLIB_Disconnect(&c); W77Q_CloseFlash(h);
    return 0;
}
