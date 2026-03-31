#include "vm.h"
#include "defs.h"
#include "riscv.h"

pagetable_t kernel_pagetable;

extern char e_text[];
extern char trampoline[];

static pagetable_t kvmmake(void)
{
	pagetable_t kpgtbl = (pagetable_t)kalloc();
	if (kpgtbl == 0)
		panic("kvmmake: kalloc failed");
	memset(kpgtbl, 0, PGSIZE);

	kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)e_text - KERNBASE,
	       PTE_R | PTE_X);
	kvmmap(kpgtbl, (uint64)e_text, (uint64)e_text, PHYSTOP - (uint64)e_text,
	       PTE_R | PTE_W);
	kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);
	return kpgtbl;
}

void kvm_init(void)
{
	kernel_pagetable = kvmmake();
	w_satp(MAKE_SATP(kernel_pagetable));
	sfence_vma();
	infof("enable paging at %p", r_satp());
}

static pte_t *walk(pagetable_t pagetable, uint64 va, int alloc)
{
	if (va >= MAXVA)
		panic("walk");

	for (int level = 2; level > 0; level--) {
		pte_t *pte = &pagetable[PX(level, va)];
		if (*pte & PTE_V) {
			pagetable = (pagetable_t)PTE2PA(*pte);
		} else {
			if (!alloc || (pagetable = (pde_t *)kalloc()) == 0)
				return 0;
			memset(pagetable, 0, PGSIZE);
			*pte = PA2PTE(pagetable) | PTE_V;
		}
	}
	return &pagetable[PX(0, va)];
}

uint64 walkaddr(pagetable_t pagetable, uint64 va)
{
	pte_t *pte;
	uint64 pa;

	if (va >= MAXVA)
		return 0;

	pte = walk(pagetable, va, 0);
	if (pte == 0)
		return 0;
	if ((*pte & PTE_V) == 0)
		return 0;
	if ((*pte & PTE_U) == 0)
		return 0;
	pa = PTE2PA(*pte);
	return pa;
}

uint64 useraddr(pagetable_t pagetable, uint64 va)
{
	uint64 page = walkaddr(pagetable, va);
	if (page == 0)
		return 0;
	return page | (va & 0xFFFULL);
}

void kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
	if (mappages(kpgtbl, va, sz, pa, perm) != 0)
		panic("kvmmap");
}

int mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
	uint64 a = PGROUNDDOWN(va);
	uint64 last = PGROUNDDOWN(va + size - 1);

	for (;;) {
		pte_t *pte = walk(pagetable, a, 1);
		if (pte == 0)
			return -1;
		if (*pte & PTE_V) {
			errorf("remap");
			return -1;
		}
		*pte = PA2PTE(pa) | perm | PTE_V;
		if (a == last)
			break;
		a += PGSIZE;
		pa += PGSIZE;
	}
	return 0;
}

void uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
	if ((va % PGSIZE) != 0)
		panic("uvmunmap: not aligned");

	for (uint64 a = va; a < va + npages * PGSIZE; a += PGSIZE) {
		pte_t *pte = walk(pagetable, a, 0);
		if (pte == 0)
			continue;
		if ((*pte & PTE_V) != 0) {
			if (PTE_FLAGS(*pte) == PTE_V)
				panic("uvmunmap: not a leaf");
			if (do_free) {
				uint64 pa = PTE2PA(*pte);
				kfree((void *)pa);
			}
		}
		*pte = 0;
	}
}

pagetable_t uvmcreate(void)
{
	pagetable_t pagetable = (pagetable_t)kalloc();
	if (pagetable == 0) {
		errorf("uvmcreate: kalloc error");
		return 0;
	}
	memset(pagetable, 0, PGSIZE);
	if (mappages(pagetable, TRAMPOLINE, PAGE_SIZE, (uint64)trampoline,
		     PTE_R | PTE_X) < 0) {
		kfree(pagetable);
		errorf("uvmcreate: mappages error");
		return 0;
	}
	return pagetable;
}

static void freewalk(pagetable_t pagetable)
{
	for (int i = 0; i < 512; i++) {
		pte_t pte = pagetable[i];
		if ((pte & PTE_V) && (pte & (PTE_R | PTE_W | PTE_X)) == 0) {
			uint64 child = PTE2PA(pte);
			freewalk((pagetable_t)child);
			pagetable[i] = 0;
		} else if (pte & PTE_V) {
			panic("freewalk: leaf");
		}
	}
	kfree((void *)pagetable);
}

void uvmfree(pagetable_t pagetable, uint64 max_page)
{
	if (max_page > 0)
		uvmunmap(pagetable, 0, max_page, 1);
	freewalk(pagetable);
}

int copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
	while (len > 0) {
		uint64 va0 = PGROUNDDOWN(dstva);
		uint64 pa0 = walkaddr(pagetable, va0);
		if (pa0 == 0)
			return -1;
		uint64 n = PGSIZE - (dstva - va0);
		if (n > len)
			n = len;
		memmove((void *)(pa0 + (dstva - va0)), src, n);

		len -= n;
		src += n;
		dstva = va0 + PGSIZE;
	}
	return 0;
}

int copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
	while (len > 0) {
		uint64 va0 = PGROUNDDOWN(srcva);
		uint64 pa0 = walkaddr(pagetable, va0);
		if (pa0 == 0)
			return -1;
		uint64 n = PGSIZE - (srcva - va0);
		if (n > len)
			n = len;
		memmove(dst, (void *)(pa0 + (srcva - va0)), n);

		len -= n;
		dst += n;
		srcva = va0 + PGSIZE;
	}
	return 0;
}

int copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
	int got_null = 0;
	int len = 0;

	while (got_null == 0 && max > 0) {
		uint64 va0 = PGROUNDDOWN(srcva);
		uint64 pa0 = walkaddr(pagetable, va0);
		if (pa0 == 0)
			return -1;
		uint64 n = PGSIZE - (srcva - va0);
		if (n > max)
			n = max;

		char *p = (char *)(pa0 + (srcva - va0));
		while (n > 0) {
			if (*p == '\0') {
				*dst = '\0';
				got_null = 1;
				break;
			}
			*dst = *p;
			--n;
			--max;
			p++;
			dst++;
			len++;
		}

		srcva = va0 + PGSIZE;
	}
	return len;
}
