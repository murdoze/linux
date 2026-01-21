#include <kvm/vamp.h>

#include <linux/kvm_host.h>

#include <linux/xarray.h>
#include <linux/printk.h>

#define PGT_ADDR_MASK 0x000ffffffffff000
#define PGTE_PER_PAGE (PAGE_SIZE / sizeof(u64))

static int protect_guest_pagetable_entry(struct kvm_vcpu *vcpu, gpa_t gpte)
{
	/* int kvm_tdp_mmu_map(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault) */

	return 0;
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

		protect_guest_pagetable_entry(vcpu, gpte);
	}

	return 0;
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

