#ifndef ARCH_X86_KVM_X86_VAMP_H
#define ARCH_X86_KVM_X86_VAMP_H

#include <linux/kvm_host.h>

#ifdef CONFIG_KVM_PROTECT_PGTABLE
void kvm_init_guest_pgtable_protection(struct kvm *kvm);
int kvm_update_guest_pgtable_protection(struct kvm *kvm, unsigned long cr3);
#else
#define kvm_init_guest_pgtable_protection(kvm) do {} while (0)
#define kvm_update_guest_pgtable_protection(kvm, cr3) (0)
#endif

void vamp_pr_cr3(unsigned long cr3);

void vamp_dump_cr3(unsigned long cr3);

void vamp_kvm_dump_guest_cr3(struct kvm *kvm, unsigned long cr3);

#endif

