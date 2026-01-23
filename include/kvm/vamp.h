#ifndef ARCH_X86_KVM_X86_VAMP_H
#define ARCH_X86_KVM_X86_VAMP_H

#include <linux/kvm_host.h>

#ifdef CONFIG_KVM_PROTECT_PGTABLE
int kvm_update_guest_pgtable_protection(struct kvm_vcpu *vcpu, unsigned long cr3);
int kvm_protect_guest_pagetable(struct kvm_vcpu *vcpu, hpa_t root_hpa);
bool kvm_is_protected_pgtable_entry(struct kvm_vcpu *vcpu, gpa_t gpa);

void vamp_dump_cr3(unsigned long cr3);
#else
#define kvm_update_guest_pgtable_protection(vcpu, cr3) (0)
#define kvm_protect_guest_pagetable(vcpu) (0)
#define kvm_is_protected_pgtable_entry(cpu, gpa) (0)

#define vamp_dump_cr3(cr3) do {} while(0);
#endif

#endif

