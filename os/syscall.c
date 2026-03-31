#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

static uint64 current_time_ms(void)
{
	return get_cycle() * 1000 / CPU_FREQ;
}

static int valid_mmap_range(uint64 start, uint64 len)
{
	if (len == 0 || !PGALIGNED(start))
		return 0;
	uint64 map_len = PGROUNDUP(len);
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
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;

	struct proc *p = curr_proc();
	char buf[MAX_STR_LEN];
	uint written = 0;

	while (written < len) {
		uint chunk = MIN(len - written, MAX_STR_LEN);
		if (copyin(p->pagetable, buf, va + written, chunk) < 0)
			return -1;
		for (uint i = 0; i < chunk; ++i) {
			console_putchar(buf[i]);
		}
		written += chunk;
	}
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

uint64 sys_getpid(void)
{
	return curr_proc()->pid;
}

uint64 sys_getppid(void)
{
	return 0;
}

uint64 sys_gettimeofday(uint64 va, int _tz)
{
	struct proc *p = curr_proc();
	TimeVal val;
	uint64 cycle = get_cycle();

	val.sec = cycle / CPU_FREQ;
	val.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	if (copyout(p->pagetable, va, (char *)&val, sizeof(val)) < 0)
		return -1;
	return 0;
}

/*
* LAB1: you may need to define sys_task_info here
*/
uint64 sys_task_info(uint64 va)
{
	struct proc *p = curr_proc();
	struct TaskInfo ti;

	memset(&ti, 0, sizeof(ti));
	ti.status = Running;
	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		ti.syscall_times[i] = p->syscall_counters[i];
	}
	ti.time = (int)(current_time_ms() - p->start_time);

	if (copyout(p->pagetable, va, (char *)&ti, sizeof(ti)) < 0)
		return -1;
	return 0;
}

uint64 sys_mmap(uint64 start, uint64 len, int prot, int flag, int shmem_id)
{
	struct proc *p = curr_proc();
	uint64 map_len = PGROUNDUP(len);
	uint64 mapped = 0;

	if (!valid_mmap_range(start, len))
		return -1;
	if (prot <= 0 || (prot & ~0x7) != 0)
		return -1;
	if (flag != 0 || shmem_id != -1)
		return -1;
	if (!region_is_free(p, start, map_len))
		return -1;

	int perm = mapping_perm(prot);
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

	uint64 end_page = PGROUNDUP(start + map_len - 1) / PAGE_SIZE;
	if (end_page > p->max_page)
		p->max_page = end_page;
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
	struct proc *p = curr_proc();
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7;
	int ret = -1;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		p->syscall_counters[id]++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:
		ret = sys_task_info(args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
