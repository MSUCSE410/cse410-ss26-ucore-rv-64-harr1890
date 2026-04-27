#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

static int valid_mmap_range(uint64 start, uint64 len)
{
	uint64 map_len;

	if (len == 0 || !PGALIGNED(start))
		return 0;
	map_len = PGROUNDUP(len);
	if (start >= TRAPFRAME)
		return 0;
	if (map_len > TRAPFRAME - start)
		return 0;
	return 1;
}

static int valid_munmap_range(uint64 start, uint64 len)
{
	if (len == 0 || !PGALIGNED(start) || !PGALIGNED(len))
		return 0;
	if (start >= TRAPFRAME)
		return 0;
	if (len > TRAPFRAME - start)
		return 0;
	return 1;
}

static int mapping_perm(int prot)
{
	int perm = PTE_U;

	if (prot & 0x1)
		perm |= PTE_R;
	if (prot & 0x2)
		perm |= PTE_W;
	if (prot & 0x4)
		perm |= PTE_X;
	return perm;
}

static int region_is_mapped(struct proc *p, uint64 start, uint64 len)
{
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return 0;
	}
	return 1;
}

static int region_is_free(struct proc *p, uint64 start, uint64 len)
{
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return 0;
	}
	return 1;
}

uint64 sys_write(int fd, uint64 va, uint len)
{
	uint written = 0;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];

	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;

	while (written < len) {
		uint chunk = MIN(len - written, MAX_STR_LEN);
		if (copyin(p->pagetable, str, va + written, chunk) < 0)
			return -1;
		for (uint i = 0; i < chunk; ++i) {
			console_putchar(str[i]);
		}
		written += chunk;
	}
	return len;
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];

	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN || len > MAX_STR_LEN)
		return -1;
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	if (copyout(p->pagetable, va, str, len) < 0)
		return -1;
	return len;
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
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	if (copyinstr(p->pagetable, name, va, sizeof(name)) < 0)
		return -1;
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = NULL;

	if (va != 0) {
		code = (int *)useraddr(p->pagetable, va);
		if (code == NULL)
			return -1;
	}
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];

	if (copyinstr(p->pagetable, name, va, sizeof(name)) < 0)
		return -1;
	return spawn(name);
}

uint64 sys_set_priority(long long prio)
{
	return setpriority(prio);
}

uint64 sys_mmap(uint64 start, uint64 len, int prot, int flag, int shmem_id)
{
	struct proc *p = curr_proc();
	uint64 map_len = PGROUNDUP(len);
	uint64 mapped = 0;
	int perm;

	if (!valid_mmap_range(start, len))
		return -1;
	if (prot <= 0 || (prot & ~0x7) != 0)
		return -1;
	if (flag != 0 || shmem_id != -1)
		return -1;
	if (!region_is_free(p, start, map_len))
		return -1;

	perm = mapping_perm(prot);
	for (uint64 va = start; va < start + map_len; va += PGSIZE) {
		void *page = kalloc();
		if (page == 0)
			goto fail;
		memset(page, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)page, perm) < 0) {
			kfree(page);
			goto fail;
		}
		mapped++;
	}

	if (p->max_page < (start + map_len) / PAGE_SIZE)
		p->max_page = (start + map_len) / PAGE_SIZE;
	return 0;

fail:
	if (mapped > 0)
		uvmunmap(p->pagetable, start, mapped, 1);
	return -1;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
	struct proc *p = curr_proc();

	if (!valid_munmap_range(start, len))
		return -1;
	if (!region_is_mapped(p, start, len))
		return -1;

	uvmunmap(p->pagetable, start, len / PGSIZE, 1);
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
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_setpriority:
		ret = sys_set_priority(args[0]);
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
