/* Minimal Zephyr app for the W77Q secure update PoC: prints its version on the console UART. */
#include <zephyr/kernel.h>

int main(void)
{
	while (1) {
		printk("Zephyr Firmware Version %s\n", FW_VERSION_STR);
		k_sleep(K_SECONDS(5));
	}
	return 0;
}
