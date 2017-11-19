#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

MODULE_LICENSE("Dual BSD/GPL");

struct load_info {
	Elf_Ehdr *hdr;
	unsigned long len;
	Elf_Shdr *sechdrs;
	char *secstrings, *strtab;
	unsigned long symoffs, stroffs;
	struct _ddebug *debug;
	unsigned int num_debug;
	bool sig_ok;

#ifdef CONFIG_KALLSYMS
	unsigned long mod_kallsyms_init_off;
#endif

	struct {
		unsigned int sym, str, mod, vers, info, pcpu;
	} index;
};

static int jload_module(struct load_info *info, const char __user *uargs, int flags)
{
	char *secstrings;
	Elf_Shdr *sechdrs, *shstr;

	printk(KERN_INFO "jload_module: hdr=0x%p, e_shoff=%lld, e_shstrndx=%d", info->hdr, info->hdr->e_shoff, info->hdr->e_shstrndx);

	sechdrs = (Elf_Shdr*)((char*)info->hdr + info->hdr->e_shoff);
	shstr = sechdrs + info->hdr->e_shstrndx;
	secstrings = (char *)info->hdr + shstr->sh_offset;

	printk(KERN_INFO "jload_module: secstrings=0x%p", secstrings);

	{
		char buf[shstr->sh_size];
		int i;
		for (i = 0; i < sizeof(buf) - 1; i++) {
                        buf[i] = (secstrings[i] == '\0') ? '$' : secstrings[i];
		}

		buf[i] = '\0';
		printk(KERN_INFO "jload_module: buf=%s", buf);
	}

	jprobe_return();
	return 0;
}

static struct jprobe jprobe_obj = {
	.entry = jload_module,
	.kp = {
		.symbol_name = "load_module"
	}
};

static int jpr_init(void)
{
	int ret;
	ret = register_jprobe(&jprobe_obj);

	if (ret < 0) {
		printk(KERN_INFO "jpr_init: register_jprobe failed: %d\n", ret);
		return -1;
	}

	printk(KERN_INFO "jpr_init: registered: %s\n", jprobe_obj.kp.symbol_name);
	return 0;
}

static void jpr_exit(void)
{
	unregister_jprobe(&jprobe_obj);
	printk(KERN_INFO "jpr_exit: unregistered jprobe\n");
}

module_init(jpr_init);
module_exit(jpr_exit);
