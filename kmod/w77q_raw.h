/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef W77Q_RAW_H
#define W77Q_RAW_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define W77Q_MAX_XFER 4096
#define W77Q_DIR_IN   0
#define W77Q_DIR_OUT  1
struct w77q_xfer {
	__u8  opcode;
	__u8  addr_nbytes;     /* 0..4 */
	__u8  dir;             /* W77Q_DIR_* */
	__u8  pad;
	__u32 dummy_cycles;    /* multiple of 8 */
	__u32 addr;
	__u32 len;
	__u64 buf;             /* user pointer */
};
#define W77Q_IOC_XFER _IOWR('W', 1, struct w77q_xfer)
#endif
