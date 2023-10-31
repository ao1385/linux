// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Microsoft Hyper-V VSM emulation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "mmu/mmu_internal.h"
#include "hyperv.h"
#include "trace.h"

#include <linux/kvm_host.h>

#define KVM_HV_VTL_ATTRS                                          \
	(KVM_MEMORY_ATTRIBUTE_READ | KVM_MEMORY_ATTRIBUTE_WRITE | \
	 KVM_MEMORY_ATTRIBUTE_EXECUTE | KVM_MEMORY_ATTRIBUTE_NO_ACCESS)

struct kvm_hv_vtl_dev {
	int vtl;
	struct xarray mem_attrs;
};

static struct xarray *kvm_hv_vsm_get_memprots(struct kvm_vcpu *vcpu);

static void kvm_hv_inject_gpa_intercept(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	struct kvm_vcpu *target_vcpu =
		kvm_hv_get_vtl_vcpu(vcpu, get_active_vtl(vcpu) + 1);
	struct kvm_vcpu_hv_intercept_info *intercept =
		&target_vcpu->arch.hyperv->intercept_info;

	WARN_ON_ONCE(!to_kvm_hv(vcpu->kvm)->hv_enable_vsm);

	intercept->type = HVMSG_GPA_INTERCEPT;
	intercept->gpa = fault->addr;
	intercept->access =
		(fault->user ? HV_INTERCEPT_ACCESS_READ : 0) |
		(fault->write ? HV_INTERCEPT_ACCESS_WRITE : 0) |
		(fault->exec ? HV_INTERCEPT_ACCESS_EXECUTE : 0);
	intercept->vcpu = vcpu;

	kvm_make_request(KVM_REQ_HV_INJECT_INTERCEPT, target_vcpu);
	kvm_vcpu_kick(target_vcpu);
}


bool kvm_hv_vsm_access_valid(struct kvm_page_fault *fault, unsigned long attrs)
{
	if (attrs == KVM_MEMORY_ATTRIBUTE_NO_ACCESS)
		return false;

	if (fault->write && !(attrs & KVM_MEMORY_ATTRIBUTE_WRITE))
		return false;

	if (fault->exec && !(attrs & KVM_MEMORY_ATTRIBUTE_EXECUTE))
		return false;

	return true;
}

static unsigned long kvm_hv_vsm_get_memory_attributes(struct kvm_vcpu *vcpu,
						      gfn_t gfn)
{
	struct xarray *prots = kvm_hv_vsm_get_memprots(vcpu);

	if (!prots)
		return 0;

	return xa_to_value(xa_load(prots, gfn));
}

int kvm_hv_faultin_pfn(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault)
{
	unsigned long attrs;

	attrs = kvm_hv_vsm_get_memory_attributes(vcpu, fault->gfn);
	if (!attrs)
		return RET_PF_CONTINUE;

	trace_kvm_hv_faultin_pfn(vcpu->vcpu_id, fault->gfn, fault->write,
				 fault->exec, fault->user, attrs);

	if (kvm_hv_vsm_access_valid(fault, attrs)) {
		fault->map_executable = attrs & KVM_MEMORY_ATTRIBUTE_EXECUTE;
		fault->map_writable = attrs & KVM_MEMORY_ATTRIBUTE_WRITE;
		return RET_PF_CONTINUE;
	}

	kvm_hv_inject_gpa_intercept(vcpu, fault);
	kvm_prepare_memory_fault_exit(vcpu, fault->addr, PAGE_SIZE,
				      fault->write, fault->exec, fault->user,
				      fault->is_private);
	return RET_PF_USER;
}

static int kvm_hv_vtl_get_attr(struct kvm_device *dev,
			       struct kvm_device_attr *attr)
{
	struct kvm_hv_vtl_dev *vtl_dev = dev->private;

	switch (attr->group) {
	case KVM_DEV_HV_VTL_GROUP:
	switch (attr->attr){
	case KVM_DEV_HV_VTL_GROUP_VTLNUM:
		return put_user(vtl_dev->vtl, (u32 __user *)attr->addr);
	}
	}

	return -EINVAL;
}

static void kvm_hv_vtl_release(struct kvm_device *dev)
{
	struct kvm_hv_vtl_dev *vtl_dev = dev->private;

	xa_destroy(&vtl_dev->mem_attrs);
	kfree(vtl_dev);
	kfree(dev); /* alloc by kvm_ioctl_create_device, free by .release */
}

static long kvm_hv_vtl_ioctl(struct kvm_device *dev, unsigned int ioctl,
			     unsigned long arg)
{
	switch (ioctl) {
	case KVM_SET_MEMORY_ATTRIBUTES: {
		struct kvm_hv_vtl_dev *vtl_dev = dev->private;
		struct kvm_memory_attributes attrs;
		int r;

		if (copy_from_user(&attrs, (void __user *)arg, sizeof(attrs)))
			return -EFAULT;

		r = kvm_ioctl_set_mem_attributes(dev->kvm, &vtl_dev->mem_attrs,
						 KVM_HV_VTL_ATTRS, &attrs);
		if (r)
			return r;
		break;
	}
	default:
		return -ENOTTY;
	}

	return 0;
}

static int kvm_hv_vtl_create(struct kvm_device *dev, u32 type);

static struct kvm_device_ops kvm_hv_vtl_ops = {
	.name = "kvm-hv-vtl",
	.create = kvm_hv_vtl_create,
	.release = kvm_hv_vtl_release,
	.ioctl = kvm_hv_vtl_ioctl,
	.get_attr = kvm_hv_vtl_get_attr,
};

static struct xarray *kvm_hv_vsm_get_memprots(struct kvm_vcpu *vcpu)
{
	struct kvm_hv_vtl_dev *vtl_dev;
	struct kvm_device *tmp;

	list_for_each_entry(tmp, &vcpu->kvm->devices, vm_node)
		if (tmp->ops == &kvm_hv_vtl_ops) {
			vtl_dev = tmp->private;
			if (vtl_dev->vtl == get_active_vtl(vcpu))
				return &vtl_dev->mem_attrs;
		}

	return NULL;
}

static int kvm_hv_vtl_create(struct kvm_device *dev, u32 type)
{
	struct kvm_hv_vtl_dev *vtl_dev;
	struct kvm_device *tmp;
	int vtl = 0;

	vtl_dev = kzalloc(sizeof(*vtl_dev), GFP_KERNEL_ACCOUNT);
	if (!vtl_dev)
		return -ENOMEM;

	/* Device creation is protected by kvm->lock */
	list_for_each_entry(tmp, &dev->kvm->devices, vm_node)
		if (tmp->ops == &kvm_hv_vtl_ops)
			vtl++;

	vtl_dev->vtl = vtl;
	xa_init(&vtl_dev->mem_attrs);
	dev->private = vtl_dev;

	return 0;
}

int kvm_hv_vtl_dev_register(void)
{
	return kvm_register_device_ops(&kvm_hv_vtl_ops, KVM_DEV_TYPE_HV_VSM_VTL);
}

void kvm_hv_vtl_dev_unregister(void)
{
	kvm_unregister_device_ops(KVM_DEV_TYPE_HV_VSM_VTL);
}
