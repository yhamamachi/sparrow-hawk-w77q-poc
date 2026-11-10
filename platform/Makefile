# Build QLIB platform port + tools against a checkout of winbond-secure-flash/qlib-bin.
#   make QLIB_DIR=/path/to/qlib-bin
QLIB_DIR ?= $(HOME)/qlib-bin
CC ?= gcc
CFLAGS = -O2 -Wall -DQLIB_MAX_DIES_SUPPORTED=4 -I$(QLIB_DIR)/inc -I$(QLIB_DIR)/inc/defs -I$(QLIB_DIR)/samples \
         -I$(QLIB_DIR)/crypto/lms/winbond_stubs -I../kmod -I../tools
LIBDIR = $(QLIB_DIR)/bin/build-$(shell uname -m)
LDFLAGS = -L$(LIBDIR) -Wl,-rpath,$(LIBDIR) -lqlib -lcrypto
PLAT = qlib_platform_linux.c
S = $(QLIB_DIR)/samples
OUT = ../build
all: $(OUT)/w77q_probe $(OUT)/w77q_manifest $(OUT)/w77q_fwtool
$(OUT):
	mkdir -p $(OUT)
$(OUT)/w77q_probe: ../tools/w77q_probe.c $(PLAT) | $(OUT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
$(OUT)/w77q_manifest: ../tools/w77q_manifest.c $(PLAT) $(S)/qlib_utils_crc.c $(S)/qlib_utils_digest.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
$(OUT)/w77q_fwtool: ../tools/w77q_fwtool.c $(PLAT) $(S)/qlib_sample_fw_update.c $(S)/qlib_sample_fw.c \
                    $(S)/qlib_utils_crc.c $(S)/qlib_utils_digest.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# The manifest tool also builds on the build PC (x86_64): it only calls the QLIB digest/CRC utilities,
# never the flash, but links the x86_64 libqlib from the same qlib-bin checkout.
