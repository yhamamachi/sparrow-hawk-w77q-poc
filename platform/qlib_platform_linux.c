/*
 * QLIB platform port for R-Car (Sparrow Hawk) Linux user space.
 *
 *  SPI    : /dev/w77q0 provided by kmod/w77q_raw (RPC-IF is spi-mem only, no spidev)
 *  SHA-256: OpenSSL EVP
 *  NONCE  : getrandom(2)
 *  RESET  : not possible from Linux user space -> no-op (use RELOAD post action)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <openssl/evp.h>
#include "qlib_platform.h"
#include "common_platform_sha256.h"
#include "../kmod/w77q_raw.h"

#ifdef W77Q_SPI_TRACE
#define TRACE(...) fprintf(stderr, __VA_ARGS__)
#else
#define TRACE(...) do {} while (0)
#endif

typedef struct { int fd; } w77q_handle_t;

void* W77Q_OpenFlash(const char* path)
{
    w77q_handle_t* h = malloc(sizeof(*h));
    if (!h) return NULL;
    h->fd = open(path ? path : "/dev/w77q0", O_RDWR);
    if (h->fd < 0) { perror("open /dev/w77q0 (is w77q_raw bound? see tools/w77q_bind.sh)"); free(h); return NULL; }
    return h;
}
void W77Q_CloseFlash(void* p)
{
    w77q_handle_t* h = p;
    if (h) { close(h->fd); free(h); }
}

void CORE_RESET(void)
{
    fprintf(stderr, "[platform] CORE_RESET requested: ignored on Linux user space\n");
}

static int do_xfer(int fd, uint8_t op, unsigned an, uint32_t addr, unsigned dummy,
                   int dir, void* buf, uint32_t len)
{
    struct w77q_xfer x = { .opcode = op, .addr_nbytes = an, .dir = dir,
                           .dummy_cycles = dummy, .addr = addr, .len = len,
                           .buf = (uint64_t)(uintptr_t)buf };
    return ioctl(fd, W77Q_IOC_XFER, &x);
}

/*
 * Map a QLIB transaction [cmd|addr|dataOut] [dummy] [dataIn] onto one spi-mem op:
 *   opcode = first byte; address phase = remaining cmd/addr bytes (<= 4);
 *   data phase = dataOut OR dataIn (spi-mem has a single data direction).
 */
int PLAT_SPI_WriteReadTransaction(const void* userData_pv, QLIB_BUS_MODE_T format, uint32_t flags_u32,
                                  const uint8_t* out, uint32_t cmdSize, uint32_t addrSize,
                                  uint32_t dataOutSize, uint32_t dummyCycles, uint8_t* in, uint32_t inSize)
{
    const w77q_handle_t* h = userData_pv;
    uint32_t hdr = cmdSize + addrSize;
    uint32_t addr = 0;
    unsigned an;
    int r;

    if (!h || cmdSize < 1) return -1;
    if (format != QLIB_BUS_MODE_1_1_1 || flags_u32 != 0) {
        fprintf(stderr, "[platform] unsupported SPI format %d flags 0x%x\n", format, flags_u32);
        return -1;
    }
    if (dataOutSize && inSize) {
        fprintf(stderr, "[platform] unsupported: dataOut and dataIn in one transaction\n");
        return -1;
    }
    an = hdr - 1;
    if (an > 4) {
        fprintf(stderr, "[platform] unsupported: cmd+addr %u bytes\n", hdr);
        return -1;
    }
    for (unsigned i = 0; i < an; i++) addr = (addr << 8) | out[1 + i];
    TRACE("SPI op=%02x an=%u addr=%08x out=%u dummy=%u in=%u\n", out[0], an, addr, dataOutSize, dummyCycles, inSize);
    if (inSize)
        r = do_xfer(h->fd, out[0], an, addr, dummyCycles, W77Q_DIR_IN, in, inSize);
    else
        r = do_xfer(h->fd, out[0], an, addr, dummyCycles, W77Q_DIR_OUT, (void*)(out + hdr), dataOutSize);
    if (r) { TRACE("SPI ioctl failed errno=%d\n", errno); return -1; }
    return 0;
}

/* ---- SHA-256 via OpenSSL ---- */
int PLAT_SHA256_Init(void** ctx)
{
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    if (!c || !EVP_DigestInit_ex(c, EVP_sha256(), NULL)) return -1;
    *ctx = c;
    return 0;
}
int PLAT_SHA256_Update(void* ctx, const void* d, uint32_t n) { return EVP_DigestUpdate(ctx, d, n) ? 0 : -1; }
int PLAT_SHA256_Finish(void* ctx, uint32_t* out)
{
    unsigned l = 32;
    int ok = EVP_DigestFinal_ex(ctx, (unsigned char*)out, &l);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}
int PLAT_HASH_Init(void** c, QLIB_HASH_OPT_T o) { (void)o; return PLAT_SHA256_Init(c); }
int PLAT_HASH_Update(void* c, const void* d, uint32_t n) { return PLAT_SHA256_Update(c, d, n); }
int PLAT_HASH_Finish(void* c, uint32_t* o) { return PLAT_SHA256_Finish(c, o); }

/* ---- nonce / random ---- */
static uint64_t rnd64(void)
{
    uint64_t v;
    if (getrandom(&v, sizeof v, 0) != sizeof v) { perror("getrandom"); exit(2); }
    return v;
}
uint64_t PLAT_GetNONCE(void) { return rnd64(); }
/* LMS module imports (used for signing with the sample HSM stub) */
uint64_t LMS_GetNonce(void)  { return rnd64(); }
uint64_t LMS_GetRandom(void) { return rnd64(); }
