#include "linux/stddef.h"
#include "vdso/page.h"
#include <kvm/vamp.h>

#include <linux/kvm_host.h>

#include <linux/xarray.h>
#include <linux/printk.h>

#include <mmu/mmu_internal.h>
#include <mmu/tdp_mmu.h>
#include <mmu/tdp_iter.h>

#define PGT_ADDR_MASK 0x000ffffffffff000
#define PGTE_PER_PAGE (PAGE_SIZE / sizeof(u64))

static int protect_guest_pagetable_entry(struct kvm_vcpu *vcpu, gpa_t gpte)
{
	struct kvm_page_fault _fault = {
		.addr = gpte,
		.error_code = PFERR_WRITE_MASK | PFERR_USER_MASK,
		.exec = false,
		.write = false,
		.present = false,
		.rsvd = false,
		.user = false,
		.prefetch = false,
		.is_tdp = true,
		.nx_huge_page_workaround_enabled = is_nx_huge_page_enabled(vcpu->kvm),

		.max_level = KVM_MAX_HUGEPAGE_LEVEL,
		.req_level = PG_LEVEL_4K,
		.goal_level = PG_LEVEL_4K,
		.is_private = false,

		.pfn = gpte >> PAGE_SHIFT,
	};
	if (vcpu->arch.mmu->root_role.direct) {
		/*
		 * Things like memslots don't understand the concept of a shared
		 * bit. Strip it so that the GFN can be used like normal, and the
		 * fault.addr can be used when the shared bit is needed.
		 */
		_fault.gfn = gpa_to_gfn(_fault.addr) & ~kvm_gfn_direct_bits(vcpu->kvm);
		_fault.slot = kvm_vcpu_gfn_to_memslot(vcpu, _fault.gfn);
	}
	struct kvm_page_fault *fault = &_fault;

	/* res = kvm_tdp_mmu_map(vcpu, &fault); */

	int ret; 

	ret = RET_PF_RETRY;

	struct kvm_mmu_page *root = tdp_mmu_get_root_for_fault(vcpu, fault);
	struct kvm *kvm = vcpu->kvm;
	struct tdp_iter iter;
	struct kvm_mmu_page *sp;
	u64 new_spte;

	rcu_read_lock();

	for_each_tdp_pte(iter, kvm, root, fault->gfn, fault->gfn + 1) {
		if (iter.level == fault->goal_level)
			goto map_target_level;

		if (is_shadow_present_pte(iter.old_spte) &&
		    !is_large_pte(iter.old_spte))
			continue;
	}
	pr_err("\e[43m TDP PTE not found \e[0m");
	goto out;	

map_target_level:

	new_spte = iter.old_spte;

	new_spte = new_spte & (~PT_WRITABLE_MASK);

	ret = kvm_tdp_mmu_set_spte_atomic(vcpu->kvm, &iter, new_spte);
	kvm_flush_remote_tlbs_gfn(vcpu->kvm, iter.gfn, iter.level);

	pr_info("\e[42m TDP PTE found, level=%d gfn=%016llx old_spte=%016llx new_spte=%016llx ret=%d\e[0m",
			iter.level, iter.gfn, iter.old_spte, new_spte, ret);
out:	
	rcu_read_unlock();

	return ret;
}

static int update_pgtable_entry(struct kvm_vcpu *vcpu, gpa_t gpte)
{
	int res;

	struct xarray *xa_pgte = &vcpu->kvm->arch.guest_pgtable_protection.pages;

	xa_lock(xa_pgte);
	res = xa_insert(xa_pgte, gpte, (void *)gpte, GFP_KERNEL);
	xa_unlock(xa_pgte);

	
	if (res == -ENOMEM)
		return res;

	if (res == 0) {
		pr_info("\e[42m New PGTE GPA=%016llx, protecting... \e[0m", gpte);

		res = protect_guest_pagetable_entry(vcpu, gpte);
		if (res != 0) {
			pr_err("\e[41m Protecting failed, error = %d \e[0m", res);
		}
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

