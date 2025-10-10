#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

extern void escape_to_root();

static const char sh_path[] = "/system/bin/sh";
static const char ksud_path[] = KSUD_PATH;
static const char su[] = SU_PATH;

static bool ksu_sucompat_non_kp __read_mostly = true;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static inline void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}
#else
static inline void __user *userspace_stack_buffer(const void *d, size_t len)
{
	if (!current->mm)
		return NULL;

	volatile unsigned long start_stack = current->mm->start_stack;
	unsigned int step = 32;
	char __user *p = NULL;
	
	do {
		p = (void __user *)(start_stack - step - len);
		if (ksu_access_ok(p, len) && !copy_to_user(p, d, len)) {
			/* pr_info("%s: start_stack: %lx p: %lx len: %zu\n",
				__func__, start_stack, (unsigned long)p, len ); */
			return p;
		}
		step = step + step;
	} while (step <= 2048);
	return NULL;
}
#endif

static inline char __user *sh_user_path(void)
{
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static inline char __user *ksud_user_path(void)
{
	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

// every little bit helps here
__attribute__((hot, no_stack_protector))
static __always_inline bool is_su_allowed(const void *ptr_to_check)
{
	DONT_GET_SMART();
	if (!ksu_sucompat_non_kp)
		return false;

	if (likely(!ksu_is_allow_uid(current_uid().val)))
		return false;

	if (unlikely(!ptr_to_check))
		return false;

	return true;
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
#ifndef CONFIG_KSU_SUSFS
	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS
	char path[sizeof(su) + 1] = {0};
#else
	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
#endif
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		pr_info("faccessat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && defined(CONFIG_KSU_SUSFS)
struct filename* susfs_ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags) {
	struct filename *name = getname_flags(*filename_user, getname_statx_lookup_flags(*flags), NULL);

	if (unlikely(IS_ERR(name) || name->name == NULL)) {
		return name;
	}

	if (likely(memcmp(name->name, su, sizeof(su)))) {
		return name;
	}

	const char sh[] = SH_PATH;
	pr_info("vfs_fstatat su->sh!\n");
	memcpy((void *)name->name, sh, sizeof(sh));
	return name;
}
#endif

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
#ifndef CONFIG_KSU_SUSFS
	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}
#endif

	if (unlikely(!filename_user)) {
		return 0;
	}

#ifdef CONFIG_KSU_SUSFS
	char path[sizeof(su) + 1] = {0};
#else
	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
#endif
// Remove this later!! we use syscall hook, so this will never happen!!!!!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) && 0
	// it becomes a `struct filename *` after 5.18
	if (flags) {
		struct filename *name = getname_flags(*filename_user, getname_statx_lookup_flags(*flags), NULL);
		if (unlikely(IS_ERR(name) || name->name == NULL)) {
			return PTR_ERR(name);
		}

		if (unlikely(!memcmp(name->name, su, sizeof(su)))) {
			const char sh[] = SH_PATH;
			pr_info("newfstatat su->sh!\n");
			memcpy((void *)name->name, sh, sizeof(sh));
		}
		putname(name);
	} else {
		ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

		if (unlikely(!memcmp(path, su, sizeof(su)))) {
			pr_info("newfstatat su->sh!\n");
			*filename_user = sh_user_path();
		}
	}
#else
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		pr_info("newfstatat su->sh!\n");
		*filename_user = sh_user_path();
	}
#endif

	return 0;
}

// getname_flags on fs/namei.c, this hooks ALL fs-related syscalls.
// NOT RECOMMENDED for daily use. mostly for debugging purposes.
int ksu_getname_flags_user(const char __user **filename_user, int flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	// sys_execve always calls getname, which sets flags = 0 on getname_flags
	// we can use it to deduce if caller is likely execve
	return ksu_sucompat_user_common(filename_user, "getname_flags", !!!flags);
}

static int ksu_sucompat_kernel_common(void *filename_ptr, const char *function_name, bool escalate)
{

	if (likely(memcmp(filename_ptr, SU_PATH, sizeof(SU_PATH))))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", function_name);
		memcpy(filename_ptr, KSUD_PATH, sizeof(KSUD_PATH));
		escape_to_root();
	} else {
		pr_info("%s su->sh\n", function_name);
		memcpy(filename_ptr, SH_PATH, sizeof(SH_PATH));
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
// for do_execveat_common / do_execve_common on >= 3.14
// take note: struct filename **filename
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

	if (unlikely(!filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (unlikely(!filename || !filename->name))
		return 0;

	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

#ifndef CONFIG_KSU_SUSFS
	if (!ksu_is_allow_uid(current_uid().val))
		return 0;
#endif

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_to_root();

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp, flags);
}
#else
// for do_execve_common on < 3.14
// take note: char **filename
int ksu_legacy_execve_sucompat(const char **filename_ptr,
				 void *__never_use_argv,
				 void *__never_use_envp)
{
	if (!is_su_allowed((const void *)filename_ptr))
		return 0;

	return ksu_sucompat_kernel_common((void *)*filename_ptr, "do_execve_common", true);
}
#endif

// vfs_statx for 5.18+
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
int ksu_handle_vfs_statx(void *__never_use_dfd, struct filename **filename_ptr,
			void *__never_use_flags, void **__never_use_stat,
			void *__never_use_request_mask)
{
	if (!is_su_allowed((const void *)filename_ptr))
		return 0;

	return ksu_sucompat_kernel_common((void *)(*filename_ptr)->name, "vfs_statx", false);
}
#endif

// getname_flags on fs/namei.c, this hooks ALL fs-related syscalls.
// put the hook right after usercopy
// NOT RECOMMENDED for daily use. mostly for debugging purposes.
int ksu_getname_flags_kernel(char **kname, int flags)
{
	if (!is_su_allowed((const void *)kname))
		return 0;

	return ksu_sucompat_kernel_common((void *)*kname, "getname_flags", !!!flags);
}

// dummified
int ksu_handle_devpts(struct inode *inode)
{
	return 0;
}

#ifdef CONFIG_KSU_SUSFS
int ksu_handle_devpts(struct inode *inode)
{
        if (!current->mm) {
                return 0;
        }

        uid_t uid = current_uid().val;
        if (uid % 100000 < 10000) {
                // not untrusted_app, ignore it
                return 0;
        }

        if (!ksu_is_allow_uid(uid))
                return 0;

        if (ksu_devpts_sid) {
                struct inode_security_struct *sec = selinux_inode(inode);
                if (sec) {
                        sec->sid = ksu_devpts_sid;
                }
        }

        return 0;
}
#endif

int __ksu_handle_devpts(struct inode *inode)
{
	DONT_GET_SMART();
	if (!ksu_sucompat_non_kp)
		return 0;

	if (!current->mm) {
		return 0;
	}

	uid_t uid = current_uid().val;
	if (uid % 100000 < 10000) {
		// not untrusted_app, ignore it
		return 0;
	}

	if (likely(!ksu_is_allow_uid(uid)))
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || defined(KSU_HAS_SELINUX_INODE)
	struct inode_security_struct *sec = selinux_inode(inode);
#else
	struct inode_security_struct *sec = (struct inode_security_struct *)inode->i_security;
#endif
	if (ksu_devpts_sid && sec)
		sec->sid = ksu_devpts_sid;

	return 0;
}

#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
extern void rp_sucompat_exit();
extern void rp_sucompat_init();
#endif

// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
	rp_sucompat_init();
#endif
	ksu_sucompat_non_kp = true;
	pr_info("ksu_sucompat_init: hooks enabled: exec, faccessat, stat, devpts\n");
}

void ksu_sucompat_exit()
{
#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
	rp_sucompat_exit();
#endif
	ksu_sucompat_non_kp = false;
	pr_info("ksu_sucompat_exit: hooks disabled: exec, faccessat, stat, devpts\n");
}

#ifdef CONFIG_KPROBES

static int faccessat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	// regs->di = dfd
	// regs->si = filename
	// regs->dx = mode
	// regs->r10 = flags (x86_64)
	// regs->r9 = flags (x86_64 compat)
	ksu_handle_faccessat((int *)&regs->di, (const char __user **)&regs->si, (int *)&regs->dx, (int *)&regs->r10);
	return 0;
}

static int stat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	// regs->di = dfd
	// regs->si = filename
	// regs->dx = statbuf
	// regs->r10 = flags (x86_64)
	// regs->r9 = flags (x86_64 compat)
	ksu_handle_stat((int *)&regs->di, (const char __user **)&regs->si, (int *)&regs->r10);
	return 0;
}

static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	// regs->di = filename
	// regs->si = argv
	// regs->dx = envp
	ksu_handle_execve_sucompat(NULL, (const char __user **)&regs->di, (void *)&regs->si, (void *)&regs->dx, NULL);
	return 0;
}

static int execveat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	// regs->di = dfd
	// regs->si = filename
	// regs->dx = argv
	// regs->r10 = envp (x86_64)
	// regs->r8 = flags (x86_64)
	// regs->r9 = flags (x86_64 compat)
	ksu_handle_execve_sucompat((int *)&regs->di, (const char __user **)&regs->si, (void *)&regs->dx, (void *)&regs->r10, (int *)&regs->r8);
	return 0;
}

static struct kprobe kp_faccessat = {
	.symbol_name = "do_faccessat",
	.pre_handler = faccessat_handler_pre,
};

static struct kprobe kp_stat = {
	.symbol_name = "do_newfstatat",
	.pre_handler = stat_handler_pre,
};

static struct kprobe kp_execve = {
	.symbol_name = "do_execve",
	.pre_handler = execve_handler_pre,
};

static struct kprobe kp_execveat = {
	.symbol_name = "do_execveat_common",
	.pre_handler = execveat_handler_pre,
};

void ksu_sucompat_kprobe_init(void)
{
	register_kprobe(&kp_faccessat);
	register_kprobe(&kp_stat);
	register_kprobe(&kp_execve);
	register_kprobe(&kp_execveat);
	pr_info("ksu_sucompat_kprobe_init: hooks registered\n");
}

void ksu_sucompat_kprobe_exit(void)
{
	unregister_kprobe(&kp_faccessat);
	unregister_kprobe(&kp_stat);
	unregister_kprobe(&kp_execve);
	unregister_kprobe(&kp_execveat);
	pr_info("ksu_sucompat_kprobe_exit: hooks unregistered\n");
}

#endif // CONFIG_KPROBES