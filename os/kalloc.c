#include "kalloc.h"
#include "defs.h"
#include "riscv.h"

extern char ekernel[];

struct linklist {
	struct linklist *next;
};

struct {
	struct linklist *freelist;
} kmem;

void freerange(void *pa_start, void *pa_end)
{
	char *p = (char *)PGROUNDUP((uint64)pa_start);
	for (; p + PGSIZE <= (char *)pa_end; p += PGSIZE)
		kfree(p);
}

void kinit(void)
{
	freerange(ekernel, (void *)PHYSTOP);
}

void kfree(void *pa)
{
	struct linklist *l;

	if (((uint64)pa % PGSIZE) != 0 || (char *)pa < ekernel ||
	    (uint64)pa >= PHYSTOP)
		panic("kfree");

	memset(pa, 1, PGSIZE);
	l = (struct linklist *)pa;
	l->next = kmem.freelist;
	kmem.freelist = l;
}

void *kalloc(void)
{
	struct linklist *l = kmem.freelist;
	if (l) {
		kmem.freelist = l->next;
		memset((char *)l, 5, PGSIZE);
	}
	return (void *)l;
}
