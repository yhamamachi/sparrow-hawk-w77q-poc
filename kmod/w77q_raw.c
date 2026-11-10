// SPDX-License-Identifier: GPL-2.0
/*
 * w77q_raw: expose raw spi-mem transactions of a SPI NOR-type flash
 * (Winbond W77Q on the R-Car RPC-IF) to user space as /dev/w77q0.
 *
 * Needed because the RPC-IF is a spi-mem-only controller (no spidev).
 * Bind with:  echo w77q-raw > /sys/bus/spi/devices/spi0.0/driver_override
 *             echo spi0.0 > /sys/bus/spi/drivers/spi-nor/unbind
 *             echo spi0.0 > /sys/bus/spi/drivers/w77q-raw/bind
 * (tools/w77q_bind.sh does this, and the reverse.)
 */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/spi/spi.h>
#include <linux/spi/spi-mem.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include "w77q_raw.h"

struct w77q_dev {
	struct spi_mem *mem;
	struct miscdevice misc;
	struct mutex lock;
};
static struct w77q_dev *g_dev;

static long w77q_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct w77q_xfer x;
	struct spi_mem_op op;
	u8 *buf = NULL;
	int ret;

	if (cmd != W77Q_IOC_XFER)
		return -ENOTTY;
	if (copy_from_user(&x, (void __user *)arg, sizeof(x)))
		return -EFAULT;
	if (x.addr_nbytes > 4 || x.len > W77Q_MAX_XFER || x.dummy_cycles % 8)
		return -EINVAL;

	if (x.len) {
		buf = kmalloc(x.len, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		if (x.dir == W77Q_DIR_OUT &&
		    copy_from_user(buf, (void __user *)(uintptr_t)x.buf, x.len)) {
			ret = -EFAULT;
			goto out;
		}
	}

	op = (struct spi_mem_op)SPI_MEM_OP(
		SPI_MEM_OP_CMD(x.opcode, 1),
		SPI_MEM_OP_ADDR(x.addr_nbytes, x.addr, 1),
		SPI_MEM_OP_DUMMY(x.dummy_cycles / 8, 1),
		SPI_MEM_OP_NO_DATA);
	if (x.len && x.dir == W77Q_DIR_IN) {
		op.data.dir = SPI_MEM_DATA_IN;
		op.data.nbytes = x.len;
		op.data.buf.in = buf;
		op.data.buswidth = 1;
	} else if (x.len) {
		op.data.dir = SPI_MEM_DATA_OUT;
		op.data.nbytes = x.len;
		op.data.buf.out = buf;
		op.data.buswidth = 1;
	}

	mutex_lock(&g_dev->lock);
	ret = spi_mem_exec_op(g_dev->mem, &op);
	mutex_unlock(&g_dev->lock);

	if (!ret && x.len && x.dir == W77Q_DIR_IN &&
	    copy_to_user((void __user *)(uintptr_t)x.buf, buf, x.len))
		ret = -EFAULT;
out:
	kfree(buf);
	return ret;
}

static const struct file_operations w77q_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = w77q_ioctl,
	.llseek = noop_llseek,
};

static int w77q_probe(struct spi_mem *mem)
{
	struct w77q_dev *d = devm_kzalloc(&mem->spi->dev, sizeof(*d), GFP_KERNEL);

	if (!d)
		return -ENOMEM;
	d->mem = mem;
	mutex_init(&d->lock);
	d->misc.minor = MISC_DYNAMIC_MINOR;
	d->misc.name = "w77q0";
	d->misc.fops = &w77q_fops;
	g_dev = d;
	spi_mem_set_drvdata(mem, d);
	return misc_register(&d->misc);
}

static int w77q_remove(struct spi_mem *mem)
{
	struct w77q_dev *d = spi_mem_get_drvdata(mem);

	misc_deregister(&d->misc);
	g_dev = NULL;
	return 0;
}

static struct spi_mem_driver w77q_driver = {
	.spidrv = { .driver = { .name = "w77q-raw" } },
	.probe = w77q_probe,
	.remove = w77q_remove,
};
module_spi_mem_driver(w77q_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Raw spi-mem access for Winbond W77Q (QLIB platform port)");
