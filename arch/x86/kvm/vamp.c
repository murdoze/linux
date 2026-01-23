#include "linux/gfp_types.h"
#include "linux/rcupdate.h"
#include "linux/stddef.h"
#include "mmu/spte.h"
#include "vdso/page.h"
#include <kvm/vamp.h>

#include <linux/kvm_host.h>

#include <linux/xarray.h>
#include <linux/printk.h>

#include <mmu/mmu_internal.h>
#include <mmu/tdp_mmu.h>
#include <mmu/tdp_iter.h>

#include "mmu.h"

#define PGT_ADDR_MASK 0x000ffffffffff000
#define PGTE_PER_PAGE (PAGE_SIZE / sizeof(u64))

static inline gfn_t tdp_mmu_max_gfn_exclusive(void)
{
	/*
	 * Bound TDP MMU walks at host.MAXPHYADDR.  KVM disallows memslots with
	 * a gpa range that would exceed the max gfn, and KVM does not create
	 * MMIO SPTEs for "impossible" gfns, instead sending such accesses down
	 * the slow emulation path every time.
	 */
	return kvm_mmu_max_gfn() + 1;
}

int kvm_protect_guest_pagetable(struct kvm_vcpu *vcpu, hpa_t root_hpa)
{
	//if (!vcpu->kvm->arch.guest_pgtable_protection.dirty)
	//	return 0;

	int ret = 0; 

	struct kvm_mmu_page *root = root_to_sp(root_hpa);

	struct tdp_iter iter;
	u64 new_spte;

	struct xarray *xa_pgte = &vcpu->kvm->arch.guest_pgtable_protection.pages;
	unsigned long pte_gfn;
	void *spte;

	//pr_info("\e[54m *********************************************************************************************** \e[0m");

	xa_lock(xa_pgte);

	rcu_read_lock();

	xa_for_each(xa_pgte, pte_gfn, spte) {
		// if ((uintptr_t)spte == FROZEN_SPTE) {
			for_each_tdp_pte(iter, vcpu->kvm, root, pte_gfn, pte_gfn + 1) {
				if (iter.level == PG_LEVEL_4K) {
					if (iter.gfn != pte_gfn) {
						pr_err("\e[41m Found wrong GFN, level=%d searched=%016lx found=%016llx \e[0m", iter.level, pte_gfn, iter.gfn);
						goto out;
					}
					if ((iter.old_spte & PT_WRITABLE_MASK) == 0)
						continue;

					new_spte = iter.old_spte & ~(PT_WRITABLE_MASK);

					ret = kvm_tdp_mmu_set_spte_atomic(vcpu->kvm, &iter, new_spte);

					kvm_flush_remote_tlbs_gfn(vcpu->kvm, iter.gfn, iter.level);

					//pr_info("\e[42m TDP PTE found, root=%016llx level=%d gfn=%016llx old_spte=%016llx new_spte=%016llx ret=%d\e[0m",
					//	root_hpa, iter.level, iter.gfn, iter.old_spte, new_spte, ret);

					if (ret)
						goto out;

					//void *xa_ret = xa_store(xa_pgte, pte_gfn, (void *)new_spte, GFP_KERNEL);
					//if (xa_ret != (void *)FROZEN_SPTE)
					//	goto out;
				}
			}

			//pr_info("\e[45m PTE gfn=%016lx \e[0m", pte_gfn);
		//}
	}

out:
	rcu_read_unlock();

	xa_unlock(xa_pgte);

	return ret;
}


bool kvm_is_protected_pgtable_entry(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	bool ret;

	struct xarray *xa_pgte = &vcpu->kvm->arch.guest_pgtable_protection.pages;
	gfn_t gfn = gpa_to_gfn(gpa);

	xa_lock(xa_pgte);
	ret = xa_load(xa_pgte, gfn) != NULL;
	xa_unlock(xa_pgte);

	return ret;
}

static int update_pgtable_entry(struct kvm_vcpu *vcpu, gpa_t pte_gpa)
{
	int res;

	struct xarray *xa_pgte = &vcpu->kvm->arch.guest_pgtable_protection.pages;
	gfn_t pte_gfn = gpa_to_gfn(pte_gpa);

	xa_lock(xa_pgte);
	res = xa_insert(xa_pgte, pte_gfn, (void *)FROZEN_SPTE, GFP_KERNEL);
	vcpu->kvm->arch.guest_pgtable_protection.dirty = true;
	xa_unlock(xa_pgte);
	
	if (res == -ENOMEM)
		return res;

	if (res == 0) {
		pr_info("\e[42m New PGTE GPA=%016llx \e[0m", pte_gpa);
	}

	return res;
}

static u64 cr3_to_pfn(u64 cr3)
{
	return (cr3 & CR3_ADDR_MASK) >> PAGE_SHIFT;
}

static int kvm_update_guest_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	int res;

	struct xarray *xa_cr3_pfn = &vcpu->kvm->arch.guest_pgtable_protection.cr3_pfn;

	u64 cr3_pfn = cr3_to_pfn(cr3);

	xa_lock(xa_cr3_pfn);
	res = xa_insert(xa_cr3_pfn, cr3_pfn, (void *)cr3_pfn, GFP_KERNEL);
	xa_unlock(xa_cr3_pfn);

	if (res == -ENOMEM)
		return res;

	if (res == 0) {
		pr_info("\e[45m New CR3, GFN=%016llx \e[0m", cr3_pfn);
	}

	return 0;
}

static int kvm_update_guest_pgtes(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	int res = 0;

	unsigned long pages = __get_free_pages(GFP_KERNEL, 2);
	if (!pages)
		return -ENOMEM;
	u64 *pt_pages = (u64 *)pages;
	u64 *l4_pgte_page = pt_pages;
	u64 *l3_pgte_page = pt_pages + PAGE_SIZE;
	u64 *l2_pgte_page = pt_pages + PAGE_SIZE + PAGE_SIZE;

	u64 gpa_pml4 = cr3 & CR3_ADDR_MASK;

	res = kvm_read_guest(vcpu->kvm, gpa_pml4, l4_pgte_page, PAGE_SIZE);
	if (res)
		goto out;

	for (int i4 = 0; i4 < PGTE_PER_PAGE; i4++)
	{
		u64 g_pml4e = l4_pgte_page[i4];
		if ((g_pml4e & 1) == 0)
			continue;

		unsigned long gpa_pml4e = g_pml4e & PGT_ADDR_MASK;

		res = update_pgtable_entry(vcpu, gpa_pml4e);
		if (res)
			goto out;

		u64 gpa_pdpt = gpa_pml4e;
		res = kvm_read_guest(vcpu->kvm, gpa_pdpt, l3_pgte_page, PAGE_SIZE);
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

			res = update_pgtable_entry(vcpu, gpa_pdpte);
			if (res)
				goto out;

			u64 gpa_pd = gpa_pdpte;
			res = kvm_read_guest(vcpu->kvm, gpa_pd, l2_pgte_page, PAGE_SIZE);
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

				res = update_pgtable_entry(vcpu, gpa_pde);
				if (res)
					goto out;
			}
		}
	}

out:
	free_pages(pages, 2);

	return res;
}

int kvm_update_guest_pgtable_protection(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	int res;

	res = kvm_update_guest_cr3(vcpu, cr3);
	if (res == -ENOMEM)
		return res;

	if (res == 0) {
		res = kvm_update_guest_pgtes(vcpu, cr3);
	}

	return res;
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
