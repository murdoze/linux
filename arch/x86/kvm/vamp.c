#include "linux/stddef.h"
#include <kvm/vamp.h>

#include <linux/pagewalk.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <linux/ptdump.h>

static bool _enable_pr_cr3 = false;

void vamp_enable_pr_cr3(void)
{
	_enable_pr_cr3 = true;
}

void vamp_pr_cr3(unsigned long cr3)
{
	if (!_enable_pr_cr3)
		return;

	long int pml = cr3 & 0x7ffffffffffff000;
	pr_info("\e[41;m Write CR3 = %016lx (%016lx) \e[0m", cr3, pml);
	//dump_stack();
}

/* Page table dump */

/* Multipliers for offsets within the PTEs */
#define PTE_LEVEL_MULT (PAGE_SIZE)
#define PMD_LEVEL_MULT (PTRS_PER_PTE * PTE_LEVEL_MULT)
#define PUD_LEVEL_MULT (PTRS_PER_PMD * PMD_LEVEL_MULT)
#define P4D_LEVEL_MULT (PTRS_PER_PUD * PUD_LEVEL_MULT)
#define PGD_LEVEL_MULT (PTRS_PER_P4D * P4D_LEVEL_MULT)

struct pg_state {
	struct ptdump_state ptdump;
	int level;
	pgprotval_t current_prot;
	pgprotval_t effective_prot;
	pgprotval_t prot_levels[5];
	unsigned long start_address;
	const struct addr_marker *marker;
	unsigned long lines;
	bool to_dmesg;
	bool check_wx;
	unsigned long wx_pages;
	struct seq_file *seq;


	unsigned long prev_addr;
};

struct addr_marker {
	unsigned long start_address;
	const char *name;
	unsigned long max_lines;
};

static void note_page(struct ptdump_state *pt_st, unsigned long addr, int level,
		      u64 val)
{
	struct pg_state *st = container_of(pt_st, struct pg_state, ptdump);
	if (val == 0)
		return;

	if (addr - st->prev_addr == 0x1000 || addr - st->prev_addr == 0x200000)
	{
		st->prev_addr = addr;
		return;
	}

	st->prev_addr = addr;
	pr_info("%016lx\tlevel = %d\tval = %016llx\t", addr, level, val);
}

static void note_page_pte(struct ptdump_state *pt_st, unsigned long addr, pte_t pte)
{
	note_page(pt_st, addr, 4, pte_val(pte));
}

static void note_page_pmd(struct ptdump_state *pt_st, unsigned long addr, pmd_t pmd)
{
	note_page(pt_st, addr, 3, pmd_val(pmd));
}

static void note_page_pud(struct ptdump_state *pt_st, unsigned long addr, pud_t pud)
{
	note_page(pt_st, addr, 2, pud_val(pud));
}

static void note_page_p4d(struct ptdump_state *pt_st, unsigned long addr, p4d_t p4d)
{
	note_page(pt_st, addr, 1, p4d_val(p4d));
}

static void note_page_pgd(struct ptdump_state *pt_st, unsigned long addr, pgd_t pgd)
{
	note_page(pt_st, addr, 0, pgd_val(pgd));
}

static void note_page_flush(struct ptdump_state *pt_st)
{
	pte_t pte_zero = {0};

	note_page(pt_st, 0, -1, pte_val(pte_zero));
}

static void effective_prot(struct ptdump_state *pt_st, int level, u64 val)
{
	struct pg_state *st = container_of(pt_st, struct pg_state, ptdump);
	pgprotval_t prot = val & PTE_FLAGS_MASK;
	pgprotval_t effective;

	if (level > 0) {
		pgprotval_t higher_prot = st->prot_levels[level - 1];

		effective = (higher_prot & prot & (_PAGE_USER | _PAGE_RW)) |
			    ((higher_prot | prot) & _PAGE_NX);
	} else {
		effective = prot;
	}

	st->prot_levels[level] = effective;
}

static void effective_prot_pte(struct ptdump_state *st, pte_t pte)
{
	effective_prot(st, 4, pte_val(pte));
}

static void effective_prot_pmd(struct ptdump_state *st, pmd_t pmd)
{
	effective_prot(st, 3, pmd_val(pmd));
}

static void effective_prot_pud(struct ptdump_state *st, pud_t pud)
{
	effective_prot(st, 2, pud_val(pud));
}

static void effective_prot_p4d(struct ptdump_state *st, p4d_t p4d)
{
	effective_prot(st, 1, p4d_val(p4d));
}

static void effective_prot_pgd(struct ptdump_state *st, pgd_t pgd)
{
	effective_prot(st, 0, pgd_val(pgd));
}

static bool dumped = false;

void vamp_dump_pagetable(struct mm_struct *mm)
{
	if (dumped)
		return;
	dumped = true;

	const struct ptdump_range ptdump_ranges[] = {
#ifdef CONFIG_X86_64
	{0, PTRS_PER_PGD * PGD_LEVEL_MULT / 2},
	{GUARD_HOLE_END_ADDR, ~0UL},
#else
	{0, ~0UL},
#endif
	{0, 0}
};

	struct pg_state st = {
		.ptdump = {
			.note_page_pte = note_page_pte,
			.note_page_pmd = note_page_pmd,
			.note_page_pud = note_page_pud,
			.note_page_p4d = note_page_p4d,
			.note_page_pgd = note_page_pgd,
			.note_page_flush = note_page_flush,
			.effective_prot_pte = effective_prot_pte,
			.effective_prot_pmd = effective_prot_pmd,
			.effective_prot_pud = effective_prot_pud,
			.effective_prot_p4d = effective_prot_p4d,
			.effective_prot_pgd = effective_prot_pgd,
			.range		= ptdump_ranges
		},
		.level = -1,
		.to_dmesg	= true,
		.check_wx	= false,
		.seq		= NULL,

		.prev_addr	= 0,
	};

	pr_info("\e[41m = PAGE DUMP BEGIN,pgd = %016lx \e[0m", (uintptr_t)mm->pgd);
	ptdump_walk_pgd(&st.ptdump, mm, mm->pgd);
	pr_info("\e[41m = PAGE DUMP END   = \e[0m");

}

/* ********************************************************************************************* */
/*                                DUMP 4-LEVEL PAGETABLE STARING WITH CR3                        */
/* ********************************************************************************************* */


void vamp_dump_cr3(unsigned long cr3)
{
	if (dumped)
		return;
	dumped = true;

	pr_info("\e[41m = PAGE DUMP BEGIN = \e[0m");

	unsigned long pml4 = cr3 & 0x0ffffffffffff000;

	pr_info("CR3  = %016lx", cr3);
	pr_info("PML4\t\t%016lx\t%016lx", pml4, (unsigned long)__va(pml4));

	unsigned long *pml4p = (unsigned long *)__va(pml4);
	for (int i4 = 0; i4 < 512; i4++, pml4p++)
	{
		unsigned long pml4e = *pml4p;
		if ((pml4e & 1) == 0)
			continue;

		unsigned long pml4e_addr = pml4e & 0xfffffffffffff000;
		bool is_page = pml4e & (1 << 7);

		pr_info("PML4E\t#%3d\t%016lx\t\t%016lx\tVA=%016lx\t%s", 
				i4, 
				(unsigned long)pml4p, 
				pml4e, 
				(unsigned long)__va(pml4e_addr),
				is_page ? "Page" : "Page-Directory-Pointer Table");
	}

	pml4p = (unsigned long *)__va(pml4);
	for (int i4 = 0; i4 < 512; i4++, pml4p++)
	{
		unsigned long pml4e = *pml4p;
		if ((pml4e & 1) == 0)
			continue;

		unsigned long pml4e_addr = pml4e & 0xfffffffffffff000;
		bool is_pdpt = !(pml4e & (1 << 7));
		if (!is_pdpt)
			continue;

		pr_info("PDPT\t#%3d\t%016lx\t%016lx", i4, pml4e_addr, (unsigned long)__va(pml4e_addr));

		unsigned long *pdptp = __va(pml4e_addr);
		for (int i3 = 0; i3 < 512; i3++, pdptp++)
		{
			unsigned long pdpte = *pdptp;
			if ((pdpte & 1) == 0)
				continue;

			unsigned long pdpte_addr = pdpte & 0xfffffffffffff000;
			bool is_page = pdpte & (1 << 7);

			pr_info("PDPTE\t#%03d\t%016lx\t\t%016lx\tVA=%016lx\t%s", 
					i3, 
					(unsigned long)pdptp, 
					pdpte, 
					(unsigned long)__va(pdpte_addr),
					is_page ? "Page" : "Page directory");
		}
	}



	pr_info("\e[41m = PAGE DUMP END   = \e[0m");

	BUG();
}

