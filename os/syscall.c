#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

#define STAT_DIR 0x040000
#define STAT_FILE 0x100000

struct Stat {
	uint64 dev;
	uint64 ino;
	uint32 mode;
	uint32 nlink;
	uint64 pad[7];
};

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
	struct proc *parent = curr_proc();
	char path[MAXPATH];
	struct inode *ip;
	struct proc *child;

	if (copyinstr(parent->pagetable, path, va, MAXPATH) < 0)
		return -1;
	if ((ip = namei(path)) == 0)
		return -1;
	if ((child = allocproc()) == 0) {
		iput(ip);
		return -1;
	}

	init_stdio(child);
	child->parent = parent;
	bin_loader(ip, child);
	iput(ip);

	char *argv[2];
	argv[0] = path;
	argv[1] = NULL;
	child->trapframe->a0 = push_argv(child, argv);
	add_task(child);
	return child->pid;
}

uint64 sys_set_priority(long long prio)
{
	// TODO: your job is to complete the sys call
	return -1;
}

uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

uint64 sys_mmap(uint64 start, uint64 len, int prot, int flags, int fd)
{
	(void)flags;
	(void)fd;

	struct proc *p = curr_proc();
	uint64 end;
	int perm = PTE_U;

	if (len == 0 || start % PGSIZE != 0)
		return -1;
	if (prot == 0 || (prot & ~0x7) != 0)
		return -1;
	if (start + len < start)
		return -1;
	end = PGROUNDUP(start + len);
	if (end <= start || end >= MAXVA)
		return -1;

	if (prot & 0x1)
		perm |= PTE_R;
	if (prot & 0x2)
		perm |= PTE_W | PTE_R;
	if (prot & 0x4)
		perm |= PTE_X;

	for (uint64 va = start; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return -1;
	}

	uint64 va;
	for (va = start; va < end; va += PGSIZE) {
		char *mem = kalloc();
		if (mem == 0)
			goto err;
		memset(mem, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) < 0) {
			kfree(mem);
			goto err;
		}
	}
	p->max_page = MAX(p->max_page, end / PAGE_SIZE);
	sfence_vma();
	return 0;

err:
	if (va > start)
		uvmunmap(p->pagetable, start, (va - start) / PGSIZE, 1);
	sfence_vma();
	return -1;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
	struct proc *p = curr_proc();
	uint64 end;

	if (len == 0 || start % PGSIZE != 0)
		return -1;
	if (start + len < start)
		return -1;
	end = PGROUNDUP(start + len);
	if (end <= start || end >= MAXVA)
		return -1;

	for (uint64 va = start; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return -1;
	}
	uvmunmap(p->pagetable, start, (end - start) / PGSIZE, 1);
	sfence_vma();
	return 0;
}

int sys_fstat(int fd, uint64 stat)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;

	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL || f->type != FD_INODE)
		return -1;

	ivalid(f->ip);
	struct Stat st;
	memset(&st, 0, sizeof(st));
	st.dev = 0;
	st.ino = f->ip->inum;
	st.nlink = f->ip->nlink;
	if (f->ip->type == T_DIR) {
		st.mode = STAT_DIR;
	} else if (f->ip->type == T_FILE) {
		st.mode = STAT_FILE;
	} else {
		return -1;
	}

	if (copyout(p->pagetable, stat, (char *)&st, sizeof(st)) < 0)
		return -1;
	return 0;
}

int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath,
	       uint64 flags)
{
	(void)olddirfd;
	(void)newdirfd;
	(void)flags;

	struct proc *p = curr_proc();
	char old[MAXPATH], new[MAXPATH];
	if (copyinstr(p->pagetable, old, oldpath, MAXPATH) < 0 ||
	    copyinstr(p->pagetable, new, newpath, MAXPATH) < 0)
		return -1;
	if (strncmp(old, new, MAXPATH) == 0)
		return -1;

	struct inode *dp = root_dir();
	struct inode *ip = dirlookup(dp, old, 0);
	if (ip == 0) {
		iput(dp);
		return -1;
	}

	ivalid(ip);
	if (ip->type != T_FILE || dirlink(dp, new, ip->inum) < 0) {
		iput(ip);
		iput(dp);
		return -1;
	}
	ip->nlink++;
	iupdate(ip);
	iput(ip);
	iput(dp);
	return 0;
}

int sys_unlinkat(int dirfd, uint64 name, uint64 flags)
{
	(void)dirfd;
	(void)flags;

	struct proc *p = curr_proc();
	char path[MAXPATH];
	uint off;
	struct dirent de;

	if (copyinstr(p->pagetable, path, name, MAXPATH) < 0)
		return -1;

	struct inode *dp = root_dir();
	struct inode *ip = dirlookup(dp, path, &off);
	if (ip == 0) {
		iput(dp);
		return -1;
	}

	memset(&de, 0, sizeof(de));
	if (writei(dp, 0, (uint64)&de, off, sizeof(de)) != sizeof(de)) {
		iput(ip);
		iput(dp);
		return -1;
	}

	ivalid(ip);
	if (ip->nlink < 1) {
		iput(ip);
		iput(dp);
		return -1;
	}
	ip->nlink--;
	iupdate(ip);
	iput(ip);
	iput(dp);
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_fstat:
	    ret = sys_fstat(args[0],args[1]);
		break;
	case SYS_linkat:
	    ret = sys_linkat(args[0],args[1],args[2],args[3],args[4]);
		break;
	case SYS_unlinkat:
	    ret = sys_unlinkat(args[0],args[1],args[2]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
