
#include "asm-generic/mman-common.h"
#include "asm/processor.h"
#include "linux/kstrtox.h"
#include "linux/mm.h"
#include "linux/mman.h"
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/init_syscalls.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include <kvm/vamp.h>

extern char modprobe_path[];

char zzzz[] = "Exploit me!                                                 ";

static spinlock_t total_lock;
static long total = 0;
//static atomic_t total = { .counter = 0 };
static long NLOOPS = 100000;
static const int READ_TASK_COUNT = 500;
static struct task_struct **reader_tasks;
static struct task_struct *writer_task;

atomic_t lock = { .counter = 0 };

static int rcu_reader(void *arg)
{
	long t;
	int cpu;


	for (long i = 0; i < NLOOPS; i++) {
		/*
		preempt_disable();
		asm("clflush %0" : "=m" (total):: "memory");
		WRITE_ONCE(total, READ_ONCE(total) + 1);
		asm("clflush %0" : "=m" (total):: "memory");
		preempt_enable();
		*/
		//asm("lock incl %0" : "=m" (total):: "memory");
		//total++;
		//spin_lock(&total_lock);
		//spin_unlock(&total_lock);
		
		int l = 0;
		while (!raw_atomic_try_cmpxchg(&lock, &l, 1)) {
			//schedule();
			asm("pause":::);
			l = 0;
		}

		WRITE_ONCE(total, READ_ONCE(total) + 1);

		atomic_set(&lock, 0);

	}

	t = total;
	cpu = 0; //this_cpu_read(cpu_number);


	pr_info("Hello from \e[46;30m READER \e[42m %ld \e[0m CPU=%3d TOTAL=%10ld", (long)arg, cpu, t);

	while (!kthread_should_stop()) {
		msleep_interruptible(100000);
	}

	return 0;
}

static int rcu_writer(void *arg)
{
	pr_info("Hello from \e[41;30m WRITER \e[42m %ld \e[0m", (long)arg);

	while (!kthread_should_stop()) {
		msleep_interruptible(100000);
	}

	return 0;
}

static void run(void)
{
	spin_lock_init(&total_lock);

	struct task_struct *tp;
	reader_tasks = kcalloc(READ_TASK_COUNT, sizeof(reader_tasks[0]), GFP_KERNEL);

	for (long i = 0; i < READ_TASK_COUNT; i++) {
		tp = kthread_create(&rcu_reader, (void *)i, "JMP reader thread %d", 0);
		sched_set_fifo(tp);
		reader_tasks[i] = tp;
		wake_up_process(tp);
	}

	tp = kthread_create(&rcu_writer, (void *)0, "JMP writer thread %d", 0);
	writer_task = tp;
	wake_up_process(tp);
	

	for (long i = 0; i < READ_TASK_COUNT; i++) {
		kthread_stop(reader_tasks[i]);
	}
	kthread_stop(writer_task);

	pr_info("TOTAL = \e[42m %ld \e[0m", (long)total);

}

static void list_directory_files(const char *path)
{
	struct file *f;

	f = filp_open("/init", 0, O_RDONLY);
	pr_info("/init = %p (%lx)", f, (uintptr_t)f);

	f = filp_open("/", 0, O_RDONLY);
	pr_info("/ = %p (%lx)", f, (uintptr_t)f);

	f = filp_open("/dev", 0, O_RDONLY);
	pr_info("/dev = %p", f);

	f = filp_open("/dev/console", 0, O_RDONLY);
	pr_info("/dev/console = %p", f);

	f = filp_open("/dev/ttyS0", 0, O_RDONLY);
	pr_info("/dev/ttyS0 = %p", f);

	f = filp_open("/dev/tty", 0, O_RDONLY);
	pr_info("/dev/tty = %p", f);

	f = filp_open("/dev/pty", 0, O_RDONLY);
	pr_info("/dev/pty = %p", f);
}

static int default_rootfs(void)
{
	int err;

	usermodehelper_enable();
	err = init_mkdir("/dev", 0755);
	if (err < 0)
		goto out;

	err = init_mknod("/dev/tty2", S_IFCHR | S_IRUSR | S_IWUSR,
			new_encode_dev(MKDEV(5, 1)));
	if (err < 0)
		goto out;

	err = init_mknod("/dev/tty3", S_IFCHR | S_IRUSR | S_IWUSR,
			new_encode_dev(MKDEV(5, 1)));
	if (err < 0)
		goto out;

	err = init_mknod("/dev/tty4", S_IFCHR | S_IRUSR | S_IWUSR,
			new_encode_dev(MKDEV(5, 1)));
	if (err < 0)
		goto out;

	err = init_mknod("/dev/console", S_IFCHR | S_IRUSR | S_IWUSR,
			new_encode_dev(MKDEV(5, 1)));
	if (err < 0)
		goto out;

	err = init_mkdir("/bin", 0700);
	if (err < 0)
		goto out;

	err = init_mkdir("/root", 0700);
	if (err < 0)
		goto out;

	return 0;

out:
	printk(KERN_WARNING "Failed to create a rootfs\n");
	return err;
}

#define PROCFS_NAME "jmp"

static struct proc_dir_entry *proc_file_entry;

// Function called when the /proc file is read
static ssize_t custom_proc_show(struct file *f, char __user *dest, size_t size, loff_t *offset) 
{
    //seq_printf(m, "Data in /proc/%s: %s\n", PROCFS_NAME, proc_buffer);
	unsigned long written = copy_to_user(dest, zzzz, min(size, strlen(zzzz)));
	pr_info("JMP says \e[41m %s \e[0m", zzzz);
	return written;
}

struct page *skb1 = 0, *pmd = 0, *pud = 0;
static ssize_t custom_proc_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos) 
{


	//pr_err("[*] skb1: %px (phys: %016llx), pmd: %px (phys: %016llx), pud: %px (phys: %016llx)\n", 
	//	skb1, page_to_phys(skb1), pmd, page_to_phys(pmd), pud, page_to_phys(pud));
	if (count == 1)
	{
		skb1 = alloc_page(GFP_KERNEL);
		__free_page(skb1);
		pr_err("\e[31m DOUBLE FREE 1st time\e[0m\n [*] skb1: %px (phys: %016llx)", skb1, page_to_phys(skb1));
	}
	else 
	if (count == 2) 
	{
		//pmd = alloc_page(GFP_KERNEL);
		__free_page(skb1);
		//pud = alloc_page(GFP_KERNEL);
		pr_err("\e[31m DOUBLE FREE 2nd time\e[0m\n [*] skb2: %px (phys: %016llx)", skb1, page_to_phys(skb1));
	} 
	else
	{
		char buf[4096];
		buf[0] = '!';
		buf[1] = 0;
		int l = (count > 4095) ? 4095 : count;
		unsigned long q = copy_from_user(buf, user_buffer, l);
		if (q);

		if (strncmp(buf, "cr3", 3) == 0) {
			unsigned long cr3 = read_cr3_pa();
			vamp_dump_cr3(cr3);

			return count;
		}


		pr_err("JMP Write:");
		pr_info("JMP [%s]", buf);

		unsigned long addr = 0;
		unsigned long v = 0;
		int res = kstrtoul(buf, 16, &addr);
		pr_info("JMP addr = %016lx VA=%016lx res=%d", addr, (unsigned long)__va(addr), res);

		v = *(unsigned long *)__va(addr); 
		*(unsigned long *)__va(addr) = 0x1122334455667788;
		pr_info("JMP prev = %016lx", v);

	}
	
	return count;
}

static const struct proc_ops custom_proc_fops = {
    .proc_read  = custom_proc_show,
    .proc_write = custom_proc_write,
    .proc_open  = NULL, // Use default open
    .proc_release = NULL, // Use default release
    .proc_lseek = NULL, // Use default lseek
};

static void register_file(void)
{
    proc_file_entry = proc_create(PROCFS_NAME, 0666, NULL, &custom_proc_fops);
    if (!proc_file_entry) {
        printk(KERN_ERR "Failed to create /proc/%s entry\n", PROCFS_NAME);
    }
    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
}

static void kref_juggling(void)
{
	struct page *skb1, *pmd, *pud;

	skb1 = alloc_page(GFP_KERNEL);
	__free_page(skb1);
	pmd = alloc_page(GFP_KERNEL);
	__free_page(skb1);
	pud = alloc_page(GFP_KERNEL);


	pr_err("[*] skb1: %px (phys: %016llx), pmd: %px (phys: %016llx), pud: %px (phys: %016llx)\n", 
		skb1, page_to_phys(skb1), pmd, page_to_phys(pmd), pud, page_to_phys(pud));
}


static int __init jmp_init(void)
{
	pr_info("John's Module Playground Sample Init");
	pr_info("\e[42m @@@@ CUT HERE @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ \e[0m");
	pr_info("Address of modprobe_path = %lx (phys: %lx)",
			(intptr_t)&modprobe_path,
			(intptr_t)__pa((struct page *)((intptr_t)(&modprobe_path) & 0xfffffffffffff000)));

	//default_rootfs();
	
	register_file();

	kref_juggling();

	//list_directory_files(NULL);

	//run();

	return 0;
}

module_init(jmp_init);

static void __exit jmp_exit(void)
{
	proc_remove(proc_file_entry);
	pr_info("John's Module Playground Sample Exit");
}
module_exit(jmp_exit);

MODULE_AUTHOR("John Johnson");
MODULE_DESCRIPTION("John's Module Playground");
MODULE_LICENSE("GPL");
