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

/* ********************************************************************************************* */
/*                                DUMP 4-LEVEL PAGETABLE STARING WITH CR3                        */
/* ********************************************************************************************* */

int dumped = 3;

void vamp_dump_cr3(unsigned long cr3)
{
	if (dumped == 0)
		return;
	dumped--;

	pr_info("\e[41m = PAGE DUMP BEGIN = \e[0m");

	unsigned long pml4 = cr3 & 0x0ffffffffffff000;

	pr_info("CR3  = %016lx", cr3);
	pr_info("PML4\t%016lx\t%016lx", pml4, (unsigned long)__va(pml4));

	pr_info("\n\n=========================== PD ====================================\n");
	unsigned long *pml4p = (unsigned long *)__va(pml4);
	for (int i4 = 0; i4 < 512; i4++, pml4p++)
	{
		unsigned long pml4e = *pml4p;
		if ((pml4e & 1) == 0)
			continue;

		unsigned long pml4e_addr = pml4e & 0x000ffffffffff000;
		bool is_pdpt = !(pml4e & (1 << 7));
		if (!is_pdpt)
			continue;
		bool is_page = pml4e & (1 << 7);

		pr_info("PDPT\t#%3d\t%016lx\t%016lx\tVA=%016lx\tPA=%016lx\t%s", 
				i4,
				(unsigned long)pml4e,
				pml4e_addr,
				(unsigned long)__va(pml4e_addr),
				(unsigned long)__pa(__va(pml4e_addr)),
				is_page ? "Page" : "Page-Directory-Pointer Table");

		unsigned long *pdptp = __va(pml4e_addr);
		for (int i3 = 0; i3 < 512; i3++, pdptp++)
		{
			unsigned long pdpte = *pdptp;
			if ((pdpte & 1) == 0)
				continue;

			unsigned long pdpte_addr = pdpte & 0x000ffffffffff000;
			bool is_page = pdpte & (1 << 7);

			pr_info("PDPTE\t#%03d\t%016lx\t%016lx\tVA=%016lx\tPA=%016lx\t%s", 
					i3, 
					(unsigned long)pdptp, 
					pdpte, 
					(unsigned long)__va(pdpte_addr),
					(unsigned long)__pa(__va(pdpte_addr)),
					is_page ? "Page" : "Page Directory");

			if (is_page)
				continue;

			unsigned long *pdp = __va(pdpte_addr);
			for (int i2 = 0; i2 < 512; i2++, pdp++)
			{
				unsigned long pde = *pdp;
				if ((pde & 1) == 0)
					continue;

				unsigned long pde_addr = pde & 0x000ffffffffff000;
				bool is_page = pde & (1 << 7);

				if (is_page)
					continue;

				pr_info("PDE\t#%03d\t%016lx\t%016lx\tVA=%016lx\tPA=%016lx\t%s", 
						i2, 
						(unsigned long)pdp, 
						pde, 
						(unsigned long)__va(pde_addr),
						(unsigned long)__pa(__va(pde_addr)),
						is_page ? "Page" : "Page Table");
			}

			
		}
	}




	pr_info("\e[41m = PAGE DUMP END   = \e[0m");

	// BUG();
}

