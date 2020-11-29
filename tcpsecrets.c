#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/siphash.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/net_namespace.h>
#include <net/secure_seq.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#error "Kernel 4.13.0+ is required."
#endif

#define PROC_ENTRY "tcp_secrets"

static void *cookie_v4_check_ptr;

static siphash_key_t (*syncookie_secret_ptr)[2] = NULL;
static siphash_key_t *net_secret_ptr = NULL;
static siphash_key_t *timestamp_secret_ptr = NULL;

static struct proc_dir_entry *proc_entry;

static void show_bytes(struct seq_file *m, const char *name,
		       const void *in, size_t size)
{
	size_t i;

	seq_printf(m, "%s ", name);
	for (i = 0; i < size; i++) {
		const u8 *bytes = (const u8 *)in;
		seq_printf(m, "%02x", (unsigned int)bytes[i]);
	}
	seq_printf(m, "\n");
}

static int tcp_secrets_show(struct seq_file *m, void *v)
{
	seq_printf(m, "time_sec %llu\n", ktime_get_real_seconds());
	seq_printf(m, "uptime_ms %u\n", tcp_time_stamp_raw());
	seq_printf(m, "jiffies %llu\n", get_jiffies_64());

	show_bytes(m, "cookie_secret",
		syncookie_secret_ptr, sizeof(*syncookie_secret_ptr));
	show_bytes(m, "net_secret",
		net_secret_ptr, sizeof(*net_secret_ptr));
	show_bytes(m, "timestamp_secret",
		timestamp_secret_ptr, sizeof(*timestamp_secret_ptr));

	return 0;
}

static int tcp_secrets_open(struct inode *inode, struct file *file)
{
	return single_open(file, tcp_secrets_show, NULL);
}

static const struct file_operations tcp_secrets_fops = {
	.open		= tcp_secrets_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int symbol_walk_callback(void *data, const char *name,
				struct module *mod, unsigned long addr)
{
	if (mod)
		return 0;

	if (strcmp(name, "cookie_v4_check") == 0) {
		cookie_v4_check_ptr = (void *)addr;
	}
	if (strcmp(name, "syncookie_secret") == 0) {
		syncookie_secret_ptr = (void *)addr;
	}
	if (strcmp(name, "net_secret") == 0) {
		net_secret_ptr = (void *)addr;
	}
	if (strcmp(name, "ts_secret") == 0) {
		timestamp_secret_ptr = (void *)addr;
	}
	return 0;
}

static struct sock *cookie_v4_check_wrapper(struct sock *sk,
					    struct sk_buff *skb)
{
	struct sock* (*old_func)(struct sock *sk, struct sk_buff *skb) =
		(void*)((unsigned long)cookie_v4_check_ptr + MCOUNT_INSN_SIZE);

	if (sock_net(sk)->ipv4.sysctl_tcp_syncookies == 2) {
		tcp_synq_overflow(sk);
	}
	return old_func(sk, skb);
}

static void notrace
tcpsecrets_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                      struct ftrace_ops *fops, struct pt_regs *regs)
{
	regs->ip = (unsigned long)cookie_v4_check_wrapper;
}

static struct ftrace_ops tcpsecrets_ftrace_ops __read_mostly = {
	.func = tcpsecrets_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

static void fix_cookie_v4_check(void)
{
	int ret;

	ret = ftrace_set_filter_ip(&tcpsecrets_ftrace_ops, (unsigned long)cookie_v4_check_ptr, 0, 0);
	if (ret)
		printk("can't set ftrace filter: err=%d\n", ret);

	ret = register_ftrace_function(&tcpsecrets_ftrace_ops);
	if (ret)
		printk("can't set ftrace function: err=%d\n", ret);
}

/* Force generation of secrets. */
static void init_secrets(void)
{
	struct iphdr ip = {};
	struct tcphdr tcp = {};
	struct in6_addr addr = {};
	u16 mss;

	/* syncookie_secret */
	__cookie_v4_init_sequence(&ip, &tcp, &mss);

	/* net_secret */
	secure_tcp_seq(0, 0, 0, 0);

	/* IPv4 version is not exported, but uses the same ts_secret.
	 * Addresses are passed as __be32*, but are used as IPv6.
	 */
	secure_tcpv6_ts_off(&init_net, (const __be32 *)&addr, (const __be32 *)&addr);
}

static int __init tcp_secrets_init(void)
{
	int rc = kallsyms_on_each_symbol(symbol_walk_callback, NULL);
	if (rc)
		return rc;

	if (cookie_v4_check_ptr) {
		fix_cookie_v4_check();
	} else {
		printk("tcp_secrets: can't find cookie_v4_check function!\n");
		return -1;
	}

	if (!syncookie_secret_ptr) {
		printk("tcp_secrets: can't find syncookie secret!\n");
		return -1;
	}
	if (!net_secret_ptr) {
		printk("tcp_secrets: can't find net secret!\n");
		return -1;
	}
	if (!timestamp_secret_ptr) {
		printk("tcp_secrets: can't find timestamp secret!\n");
		return -1;
	}

	proc_entry = proc_create(PROC_ENTRY, 0, NULL, &tcp_secrets_fops);
	if (proc_entry == NULL) {
		printk("tcp_secrets: can't create /proc/" PROC_ENTRY "!\n");
		return -1;
	}

	init_secrets();

	return 0;
}
module_init(tcp_secrets_init);

static void __exit tcp_secrets_exit(void)
{
	int ret;

	if (cookie_v4_check_ptr) {
		ret = unregister_ftrace_function(&tcpsecrets_ftrace_ops);
		if (ret)
			printk("can't unregister ftrace\n");

		ret = ftrace_set_filter_ip(&tcpsecrets_ftrace_ops,
				(unsigned long)cookie_v4_check_ptr, 1, 0);
		if (ret)
			printk("can't unregister filter\n");

        	cookie_v4_check_ptr = NULL;
	}

	syncookie_secret_ptr = NULL;
	net_secret_ptr = NULL;
	timestamp_secret_ptr = NULL;

	if (proc_entry) {
        	remove_proc_entry(PROC_ENTRY, 0);
		proc_entry = NULL;
	}
}
module_exit(tcp_secrets_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Polyakov <apolyakov@beget.ru>");
MODULE_AUTHOR("Dmitry Kozlyuk <kozlyuk@bifit.com>");
MODULE_DESCRIPTION("Provide access to TCP SYN cookie secrets via /proc/" PROC_ENTRY);
MODULE_VERSION("2.0");
