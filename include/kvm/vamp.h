#ifndef ARCH_X86_KVM_X86_VAMP_H
#define ARCH_X86_KVM_X86_VAMP_H

#include <linux/kvm_host.h>

void vamp_pr_cr3(unsigned long cr3);

void vamp_dump_cr3(unsigned long cr3);

void vamp_kvm_dump_guest_cr3(struct kvm *kvm, unsigned long cr3);

#endif

