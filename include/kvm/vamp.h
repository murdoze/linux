#ifndef ARCH_X86_KVM_X86_VAMP_H
#define ARCH_X86_KVM_X86_VAMP_H

#include <linux/kvm_host.h>

#ifdef CONFIG_KVM_PROTECT_PGTABLE
int kvm_update_guest_pgtable_protection(struct kvm_vcpu *vcpu, unsigned long cr3);
#else
#define kvm_update_guest_pgtable_protection(vcpu, cr3) (0)
#endif

#endif

