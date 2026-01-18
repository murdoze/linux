#ifndef ARCH_X86_KVM_X86_VAMP_H
#define ARCH_X86_KVM_X86_VAMP_H

#include <linux/mm_types.h>

void vamp_enable_pr_cr3(void);

void vamp_pr_cr3(unsigned long cr3);

void vamp_dump_pagetable(struct mm_struct *mm);
void vamp_dump_cr3(unsigned long cr3);

#endif

