#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x225980c, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x5fda0227, __VMLINUX_SYMBOL_STR(vfs_stat) },
	{ 0xb5419b40, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x40305d96, __VMLINUX_SYMBOL_STR(unlock_rename) },
	{ 0xe7f23027, __VMLINUX_SYMBOL_STR(vfs_unlink) },
	{ 0x79548719, __VMLINUX_SYMBOL_STR(lock_rename) },
	{ 0x2bc95bd4, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x5152e605, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xba43d261, __VMLINUX_SYMBOL_STR(vfs_read) },
	{ 0xa48cfb6b, __VMLINUX_SYMBOL_STR(vfs_write) },
	{ 0x4c4fef19, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0x94867424, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0xfe90a9d0, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0x5c265cba, __VMLINUX_SYMBOL_STR(sg_init_one) },
	{ 0xb9267e31, __VMLINUX_SYMBOL_STR(crypto_destroy_tfm) },
	{ 0x2c95cf94, __VMLINUX_SYMBOL_STR(mem_map) },
	{ 0xd2a941d4, __VMLINUX_SYMBOL_STR(sg_init_table) },
	{ 0x2e60bace, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x1b684b49, __VMLINUX_SYMBOL_STR(crypto_alloc_base) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xaf963fcb, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x46991692, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x5e3b3ab4, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x56cb2648, __VMLINUX_SYMBOL_STR(sysptr) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "E599CDC87E0C9937815DEF1");
