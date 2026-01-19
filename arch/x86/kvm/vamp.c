#include <kvm/vamp.h>

#include <linux/kvm_host.h>

#include <linux/xarray.h>
#include <linux/printk.h>

#define PGT_ADDR_MASK 0x000ffffffffff000
#define PGTE_PER_PAGE (PAGE_SIZE / sizeof(u64))

void kvm_init_guest_pgtable_protection(struct kvm *kvm)
{
	pr_info("Initialise guest page table protection");
}

static int update_pgtable_entry(struct xarray *xa_pgte, u64 val)
{
	int res;

	xa_lock(xa_pgte);
	res = xa_insert(xa_pgte, val, (void *)val, GFP_KERNEL);
	xa_unlock(xa_pgte);

	
	if (res == -ENOMEM)
		return res;

	if (res == 0) {
		pr_info("\e[42m New PGTE GPA=%016llx \e[0m", val);
	}

	return 0;
}

static u64 cr3_to_pfn(u64 cr3)
{
	return (cr3 & CR3_ADDR_MASK) >> PAGE_SHIFT;
}

static int kvm_update_guest_cr3(struct xarray *xa_cr3_pfn, unsigned long cr3)
{
	int res;

	u64 cr3_pfn = cr3_to_pfn(cr3);

	xa_lock(xa_cr3_pfn);
	res = xa_insert(xa_cr3_pfn, cr3_pfn, (void *)cr3_pfn, GFP_KERNEL);
	xa_unlock(xa_cr3_pfn);

	if (res == -ENOMEM)
		return res;

	if (res == 0) {
		pr_info("\e[45m New CR3, PFN=%016llx \e[0m", cr3_pfn);
	}

	return 0;
}

static int guest_dumped1 = 3000;

static int kvm_update_guest_pgtes(struct kvm *kvm, unsigned long cr3)
{

	if (guest_dumped1 == 0)
		return 0;
	guest_dumped1--;

	int res = 0;

	unsigned long pages = __get_free_pages(GFP_KERNEL, 2);
	if (!pages)
		return -ENOMEM;
	u64 *pt_pages = (u64 *)pages;
	u64 *l4_pgte_page = pt_pages;
	u64 *l3_pgte_page = pt_pages + PAGE_SIZE;
	u64 *l2_pgte_page = pt_pages + PAGE_SIZE + PAGE_SIZE;

	u64 gpa_pml4 = cr3 & CR3_ADDR_MASK;

	res = kvm_read_guest(kvm, gpa_pml4, l4_pgte_page, PAGE_SIZE);
	if (res)
		goto out;

	for (int i4 = 0; i4 < PGTE_PER_PAGE; i4++)
	{
		u64 g_pml4e = l4_pgte_page[i4];
		if ((g_pml4e & 1) == 0)
			continue;

		unsigned long gpa_pml4e = g_pml4e & PGT_ADDR_MASK;

		res = update_pgtable_entry(&kvm->arch.guest_pgtable_protection.pages, gpa_pml4e);
		if (res)
			goto out;

		u64 gpa_pdpt = gpa_pml4e;
		res = kvm_read_guest(kvm, gpa_pdpt, l3_pgte_page, PAGE_SIZE);
		if (res)
			goto out;

		for (int i3 = 0; i3 < PGTE_PER_PAGE; i3++)
		{
			u64 g_pdpte = l3_pgte_page[i3];
			if ((g_pdpte & 1) == 0)
				continue;

			bool is_page = g_pdpte & (1 << 7);
			if (is_page)
				continue;

			u64 gpa_pdpte = g_pdpte & PGT_ADDR_MASK;

			res = update_pgtable_entry(&kvm->arch.guest_pgtable_protection.pages, gpa_pdpte);
			if (res)
				goto out;

			u64 gpa_pd = gpa_pdpte;
			res = kvm_read_guest(kvm, gpa_pd, l2_pgte_page, PAGE_SIZE);
			if (res)
				goto out;

			for (int i2 = 0; i2 < PGTE_PER_PAGE; i2++)
			{
				u64 g_pde = l2_pgte_page[i2];
				if ((g_pde & 1) == 0)
					continue;

				bool is_page = g_pde & (1 << 7);
				if (is_page)
					continue;

				u64 gpa_pde = g_pde & PGT_ADDR_MASK;

				res = update_pgtable_entry(&kvm->arch.guest_pgtable_protection.pages, gpa_pde);
				if (res)
					goto out;
			}
		}
	}

out:
	free_pages(pages, 2);

	return res;
}

int kvm_update_guest_pgtable_protection(struct kvm *kvm, unsigned long cr3)
{
	int res;

	res = kvm_update_guest_cr3(&kvm->arch.guest_pgtable_protection.cr3_pfn, cr3);
	if (res == -ENOMEM)
		return res;

	if (res == 0) {
		res = kvm_update_guest_pgtes(kvm, cr3);
	}

	return res;
}

/* ********************************************************************************************* */
/*                                     PRINT CR3                                                 */
/* ********************************************************************************************* */

static int pr_cr3_count = 3;

void vamp_pr_cr3(unsigned long cr3)
{
	if (pr_cr3_count == 0)
		return;
	pr_cr3_count--;

	long int pml = cr3 & 0x7ffffffffffff000;
	pr_info("\e[41m Write CR3 = %016lx (%016lx) \e[0m", cr3, pml);
	//dump_stack();
}

/* ********************************************************************************************* */
/*                                DUMP 4-LEVEL PAGETABLE STARING WITH CR3                        */
/* ********************************************************************************************* */

static int dumped = 3;

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

		pr_info("PML4E\t#%3d\t%016lx\t%016lx\tVA=%016lx\tPA=%016lx\t%s", 
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

/* ********************************************************************************************* */
/*                             DUMP GUEST 4-LEVEL PAGETABLE STARING WITH CR3                     */
/* ********************************************************************************************* */

static int guest_dumped = 3000;

void vamp_kvm_dump_guest_cr3(struct kvm *kvm, unsigned long cr3)
{
	if (guest_dumped == 0)
		return;
	guest_dumped--;

	pr_info("\e[44m = GUEST PAGE DUMP BEGIN = (%d) \e[0m", guest_dumped);


	u64 gpa_pml4 = cr3 & 0x0ffffffffffff000;
	gfn_t gfn_pml4 = gpa_pml4 >> PAGE_SHIFT;
	u64 g_pml4_page[512];
	int res = kvm_read_guest(kvm, gpa_pml4, g_pml4_page, sizeof(g_pml4_page));
	if (res) {
		pr_err("\e[41m Error reading guest PML4 at %016llx \e[0m", gpa_pml4);
		return;
	}

	hva_t hva_pml4 = gfn_to_hva(kvm, gfn_pml4);
	

	pr_info("CR3  = %016lx", cr3);
	pr_info("PML4\tGFN=\t%016llx\tHVA=%016lx\terror=%d", gfn_pml4, hva_pml4, kvm_is_error_hva(hva_pml4));

	for (int i4 = 0; i4 < 512; i4++)
	{
		u64 g_pml4e = g_pml4_page[i4];
		if ((g_pml4e & 1) == 0)
			continue;

		unsigned long gpa_pml4e = g_pml4e & 0x000ffffffffff000;
		
		pr_info("PML4E\t#%3d\t%016llx\tGPA=%016lx\t%s", 
				i4,
				g_pml4e,
				gpa_pml4e,
				"Page-Directory-Pointer Table");
		
		u64 gpa_pdpt = gpa_pml4e;
		u64 g_pdpt_page[512];
		int res = kvm_read_guest(kvm, gpa_pdpt, g_pdpt_page, sizeof(g_pdpt_page));
		if (res) {
			pr_err("\e[41m Error reading guest PDPT at %016llx \e[0m", gpa_pdpt);
			return;
		}

		for (int i3 = 0; i3 < 512; i3++)
		{
			u64 g_pdpte = g_pdpt_page[i3];
			if ((g_pdpte & 1) == 0)
				continue;

			bool is_page = g_pdpte & (1 << 7);
			if (is_page)
				continue;

			u64 gpa_pdpte = g_pdpte & 0x000ffffffffff000;

			pr_info("PDPTE\t#%3d\t%016llx\tGPA=%016llx\t%s", 
					i3,
					g_pdpte,
					gpa_pdpte,
					is_page ? "Page" : "Page Directory");

			u64 gpa_pd = gpa_pdpte;
			u64 g_pd_page[512];
			int res = kvm_read_guest(kvm, gpa_pd, g_pd_page, sizeof(g_pd_page));
			if (res) {
				pr_err("\e[41m Error reading guest PD at %016llx \e[0m", gpa_pdpt);
				return;
			}

			if (!is_page)
			for (int i2 = 0; i2 < 512; i2++)
			{
				u64 g_pde = g_pd_page[i2];
				if ((g_pde & 1) == 0)
					continue;

				bool is_page = g_pde & (1 << 7);
				if (is_page)
					continue;

				u64 gpa_pde = g_pde & 0x000ffffffffff000;

				pr_info("PDE\t#%3d\t%016llx\tGPA=%016llx\t%s", 
						i2,
						g_pde,
						gpa_pde,
						is_page ? "Page" : "Page Table");

			}
		}
	}

	pr_info("\e[44m = GUEST PAGE DUMP END = \e[0m");
}

