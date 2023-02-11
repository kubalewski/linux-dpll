// SPDX-License-Identifier: GPL-2.0
/*
 *  dpll_core.c - Generic DPLL Management class support.
 *
 *  Copyright (c) 2021 Meta Platforms, Inc. and affiliates
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "dpll_core.h"

DEFINE_MUTEX(dpll_device_xa_lock);
DEFINE_MUTEX(dpll_pin_xa_lock);

DEFINE_XARRAY_FLAGS(dpll_device_xa, XA_FLAGS_ALLOC);
DEFINE_XARRAY_FLAGS(dpll_pin_xa, XA_FLAGS_ALLOC);

#define ASSERT_DPLL_REGISTERED(d)                                          \
	WARN_ON_ONCE(!xa_get_mark(&dpll_device_xa, (d)->id, DPLL_REGISTERED))
#define ASSERT_DPLL_NOT_REGISTERED(d)                                      \
	WARN_ON_ONCE(xa_get_mark(&dpll_device_xa, (d)->id, DPLL_REGISTERED))

static struct class dpll_class = {
	.name = "dpll",
};

/**
 * dpll_device_get_by_id - find dpll device by it's id
 * @id: id of searched dpll
 *
 * Return: dpll_device struct if found, NULL otherwise.
 */
struct dpll_device *dpll_device_get_by_id(int id)
{
	struct dpll_device *dpll = NULL;

	if (xa_get_mark(&dpll_device_xa, id, DPLL_REGISTERED))
		dpll = xa_load(&dpll_device_xa, id);

	return dpll;
}

/**
 * dpll_device_get_by_name - find dpll device by it's id
 * @bus_name: bus name of searched dpll
 * @dev_name: dev name of searched dpll
 *
 * Return: dpll_device struct if found, NULL otherwise.
 */
struct dpll_device *
dpll_device_get_by_name(const char *bus_name, const char *device_name)
{
	struct dpll_device *dpll, *ret = NULL;
	unsigned long index;

	mutex_lock(&dpll_device_xa_lock);
	xa_for_each_marked(&dpll_device_xa, index, dpll, DPLL_REGISTERED) {
		if (!strcmp(dev_bus_name(&dpll->dev), bus_name) &&
		    !strcmp(dev_name(&dpll->dev), device_name)) {
			ret = dpll;
			break;
		}
	}
	mutex_unlock(&dpll_device_xa_lock);

	return ret;
}

struct dpll_device
*dpll_device_alloc(const u64 clock_id, u32 dev_driver_id, struct module *module)
{
	struct dpll_device *dpll;
	int ret;

	dpll = kzalloc(sizeof(*dpll), GFP_KERNEL);
	if (!dpll)
		return ERR_PTR(-ENOMEM);
	mutex_init(&dpll->lock);
	dpll->dev.class = &dpll_class;
	dpll->dev_driver_id = dev_driver_id;
	dpll->clock_id = clock_id;
	ret = xa_alloc(&dpll_device_xa, &dpll->id, dpll,
		       xa_limit_16b, GFP_KERNEL);
	if (ret) {
		kfree(dpll);
		mutex_unlock(&dpll_device_xa_lock);
		return ERR_PTR(ret);
	}
	xa_init_flags(&dpll->pins, XA_FLAGS_ALLOC);
	mutex_unlock(&dpll_device_xa_lock);

	return dpll;
}

static int dpll_pin_ref_dpll_add(struct dpll_pin *pin, struct dpll_device *dpll,
				 struct dpll_pin_ops *ops, void *priv)
{
	struct dpll_pin_ref *ref, *pos;
	unsigned long index;
	u32 idx;
	int ret;

	ref = kzalloc(sizeof(struct dpll_pin_ref), GFP_KERNEL);
	if (!ref)
		return -ENOMEM;
	ref->dpll = dpll;
	ref->ops = ops;
	ref->priv = priv;
	if (!xa_empty(&pin->dpll_refs)) {
		xa_for_each(&pin->dpll_refs, index, pos) {
			if (pos->dpll == ref->dpll)
				return -EEXIST;
		}
	}

	ret = xa_alloc(&pin->dpll_refs, &idx, ref, xa_limit_16b, GFP_KERNEL);
	if (!ret)
		refcount_inc(&dpll->refcount);

	return ret;
}

static void
dpll_pin_ref_dpll_del(struct dpll_pin *pin, struct dpll_device *dpll)
{
	struct dpll_pin_ref *pos;
	unsigned long index;

	xa_for_each(&pin->dpll_refs, index, pos) {
		if (pos->dpll == dpll) {
			if (pos == xa_erase(&pin->dpll_refs, index)) {
				refcount_dec(&dpll->refcount);
				kfree(pos);
				break;
			}
		}
	}
}

struct dpll_device
*dpll_device_get(u64 clock_id, u32 dev_driver_id, struct module *module)
{
	struct dpll_device *dpll, *ret = NULL;
	unsigned long index;

	mutex_lock(&dpll_device_xa_lock);
	xa_for_each(&dpll_device_xa, index, dpll) {
		if (dpll->clock_id == clock_id &&
		    dpll->dev_driver_id == dev_driver_id &&
		    dpll->module == module) {
			ret = dpll;
			break;
		}
	}
	if (!ret)
		ret = dpll_device_alloc(clock_id, dev_driver_id, module);
	mutex_unlock(&dpll_device_xa_lock);
	if (!IS_ERR_OR_NULL(ret))
		refcount_inc(&ret->refcount);

	return ret;
}
EXPORT_SYMBOL_GPL(dpll_device_get);

void dpll_device_free(struct dpll_device *dpll)
{
	WARN_ON_ONCE(!xa_empty(&dpll->pins));
	xa_destroy(&dpll->pins);
	mutex_destroy(&dpll->lock);
	kfree(dpll);
}

void dpll_device_put(struct dpll_device *dpll)
{
	if (!dpll)
		return;

	if (refcount_dec_and_test(&dpll->refcount) == 0)
		dpll_device_free(dpll);

}
EXPORT_SYMBOL_GPL(dpll_device_put);

void dpll_device_register(struct dpll_device *dpll, enum dpll_type type,
			  void *priv, struct device *owner)
{
	mutex_lock(&dpll->lock);
	ASSERT_DPLL_NOT_REGISTERED(dpll);
	dpll->dev.bus = owner->bus;
	dpll->parent = owner;
	dpll->type = type;
	dev_set_name(&dpll->dev, "%s_%d", dev_name(owner),
		     dpll->dev_driver_id);
	dpll->priv = priv;
	xa_set_mark(&dpll_device_xa, dpll->id, DPLL_REGISTERED);
	mutex_unlock(&dpll->lock);
	dpll_notify_device_create(dpll);
}
EXPORT_SYMBOL_GPL(dpll_device_register);

/**
 * dpll_device_deregister - deregister dpll device
 * @dpll: registered dpll pointer
 *
 * Note: It does not free the memory
 */
void dpll_device_deregister(struct dpll_device *dpll)
{
	ASSERT_DPLL_REGISTERED(dpll);

	mutex_lock(&dpll_device_xa_lock);
	xa_erase(&dpll_device_xa, dpll->id);
	mutex_unlock(&dpll_device_xa_lock);
	dpll_notify_device_delete(dpll);
}
EXPORT_SYMBOL_GPL(dpll_device_deregister);

void dpll_pin_put(struct dpll_pin *pin)
{
	if (refcount_dec_and_test(&pin->refcount) == 0) {
		xa_destroy(&pin->dpll_refs);
		xa_destroy(&pin->pin_refs);
		mutex_destroy(&pin->lock);
		kfree(pin->prop.description);
		kfree(pin->rclk_dev_name);
		kfree(pin);
	}
}
EXPORT_SYMBOL_GPL(dpll_pin_put);

struct dpll_pin
*dpll_pin_alloc(u64 clock_id, u8 device_drv_id,	struct module *module,
		const struct dpll_pin_properties *prop)
{
	struct dpll_pin *pin;
	int ret;

	pin = kzalloc(sizeof(*pin), GFP_KERNEL);
	if (!pin)
		return ERR_PTR(-ENOMEM);
	mutex_init(&pin->lock);
	pin->dev_driver_id = device_drv_id;
	pin->clock_id = clock_id;
	pin->module = module;
	refcount_set(&pin->refcount, 0);
	if (WARN_ON(pin->prop.description))
		return ERR_PTR(-EINVAL);
	pin->prop.description = kstrdup(pin->prop.description, GFP_KERNEL);
	if (!pin->prop.description)
		return ERR_PTR(-ENOMEM);
	if (WARN_ON(pin->prop.type <= DPLL_PIN_TYPE_UNSPEC ||
		    pin->prop.type > DPLL_PIN_TYPE_MAX))
		return ERR_PTR(-EINVAL);
	pin->prop.type = pin->prop.type;
	pin->prop.caps_supported = pin->prop.caps_supported;
	pin->prop.freq_supported = pin->prop.freq_supported;
	pin->prop.any_freq_min = pin->prop.any_freq_min;
	pin->prop.any_freq_max = pin->prop.any_freq_max;
	xa_init_flags(&pin->pin_refs, XA_FLAGS_ALLOC);
	xa_init_flags(&pin->dpll_refs, XA_FLAGS_ALLOC);
	ret = xa_alloc(&dpll_pin_xa, &pin->idx, pin,
		       xa_limit_16b, GFP_KERNEL);
	if (ret) {
		dpll_pin_put(pin);
		return ERR_PTR(ret);
	}

	return pin;
}

struct dpll_pin
*dpll_pin_get(u64 clock_id, u32 device_drv_id, struct module *module,
	      const struct dpll_pin_properties *prop)
{
	struct dpll_pin *pos, *ret = NULL;
	unsigned long index;

	mutex_lock(&dpll_pin_xa_lock);
	xa_for_each(&dpll_pin_xa, index, pos) {
		if (pos->clock_id == clock_id &&
		    pos->dev_driver_id == device_drv_id &&
		    pos->module == module) {
			ret = pos;
			break;
		}
	}
	if (!ret)
		ret = dpll_pin_alloc(clock_id, device_drv_id, module, prop);
	mutex_unlock(&dpll_pin_xa_lock);
	if (!IS_ERR_OR_NULL(ret))
		refcount_inc(&ret->refcount);

	return ret;
}
EXPORT_SYMBOL_GPL(dpll_pin_get);

static int dpll_xa_pin_add(struct xarray *pins, struct dpll_pin *pin)
{
	struct dpll_pin *pos;
	unsigned long index;
	u32 idx;

	xa_for_each(pins, index, pos) {
		if (WARN_ON(pos == pin ||
			    !strcmp(pos->prop.description,
				    pin->prop.description)) ||
			    pos->dev_driver_id == pin->dev_driver_id)
			return -EEXIST;
	}

	return xa_alloc(pins, &idx, pin, xa_limit_16b, GFP_KERNEL);
}

static int dpll_xa_pin_del(struct xarray *xa_pins, struct dpll_pin *pin)
{
	struct dpll_pin *pos;
	unsigned long index;

	xa_for_each(xa_pins, index, pos) {
		if (pos == pin) {
			WARN_ON_ONCE(pos != xa_erase(xa_pins, index));
			return 0;
		}
	}

	return -ENXIO;
}

int
dpll_pin_on_dpll_register(struct dpll_device *dpll, struct dpll_pin *pin,
			  struct dpll_pin_ops *ops, void *priv,
			  struct device *rclk_device)
{
	int ret;

	if (WARN_ON(!dpll))
		return -ENODEV;
	if (WARN_ON(!pin))
		return -EINVAL;
	if (rclk_device) {
		pin->rclk_dev_name = kstrdup(dev_name(rclk_device), GFP_KERNEL);
		if (!pin->rclk_dev_name)
			return -ENOMEM;
	}
	mutex_lock(&dpll->lock);
	ret = dpll_pin_ref_dpll_add(pin, dpll, ops, priv);
	if (ret)
		goto rclk_free;
	ret = dpll_xa_pin_add(&dpll->pins, pin);
	if (ret) {
		dpll_pin_ref_dpll_del(pin, dpll);
		goto rclk_free;
	} else {
		refcount_inc(&pin->refcount);
		xa_set_mark(&dpll_pin_xa, pin->idx, DPLL_PIN_REGISTERED);
		dpll_pin_notify(dpll, pin, DPLL_A_PIN_IDX);
	}
	mutex_unlock(&dpll->lock);

	return ret;
rclk_free:
	kfree(pin->rclk_dev_name);
	mutex_lock(&dpll->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(dpll_pin_on_dpll_register);

static int dpll_pin_ref_pin_add(struct dpll_pin *pin, struct dpll_pin *parent,
				struct dpll_pin_ops *ops, void *priv)
{
	struct dpll_pin_ref *ref, *pos;
	unsigned long index;
	u32 idx;
	int ret;

	ref = kzalloc(sizeof(struct dpll_pin_ref), GFP_KERNEL);
	if (!ref)
		return -ENOMEM;
	ref->pin = parent;
	ref->ops = ops;
	ref->priv = priv;
	if (!xa_empty(&pin->pin_refs)) {
		xa_for_each(&pin->pin_refs, index, pos) {
			if (pos->pin == ref->pin)
				return -EEXIST;
		}
	}

	ret = xa_alloc(&pin->pin_refs, &idx, ref, xa_limit_16b, GFP_KERNEL);
	if (!ret)
		refcount_inc(&pin->refcount);

	return ret;
}

int
dpll_pin_on_pin_register(struct dpll_pin *parent, struct dpll_pin *pin,
			 struct dpll_pin_ops *ops, void *priv,
			 struct device *rclk_device)
{
	int ret;

	if (WARN_ON(!pin || !parent))
		return -EINVAL;
	if (WARN_ON(parent->prop.type != DPLL_PIN_TYPE_MUX))
		return -EPERM;

	mutex_lock(&pin->lock);
	ret = dpll_pin_ref_pin_add(pin, parent, ops, priv);
	mutex_unlock(&pin->lock);
	if (!ret) {
		struct dpll_pin_ref *ref;
		unsigned long index;

		xa_for_each(&parent->dpll_refs, index, ref) {
			dpll_pin_parent_notify(ref->dpll, pin, parent,
					       DPLL_A_PIN_IDX);
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(dpll_pin_on_pin_register);

struct dpll_pin *dpll_pin_get_by_idx_from_xa(struct xarray *xa_pins, u32 idx)
{
	struct dpll_pin *pos;
	unsigned long index;

	xa_for_each_marked(xa_pins, index, pos, DPLL_PIN_REGISTERED) {
		if (pos->idx == idx)
			return pos;
	}

	return NULL;
}

/**
 * dpll_pin_get_by_idx - find a pin by its index
 * @dpll: dpll device pointer
 * @idx: index of pin
 *
 * Allows multiple driver instances using one physical DPLL to find
 * and share pin already registered with existing dpll device.
 *
 * Return: pointer if pin was found, NULL otherwise.
 */
struct dpll_pin *dpll_pin_get_by_idx(struct dpll_device *dpll, u32 idx)
{
	return dpll_pin_get_by_idx_from_xa(&dpll->pins, idx);
}

int dpll_pin_deregister(struct dpll_device *dpll, struct dpll_pin *pin)
{
	int ret = 0;

	if (xa_empty(&dpll->pins))
		return -ENOENT;

	mutex_lock(&dpll->lock);
	ret = dpll_xa_pin_del(&dpll->pins, pin);
	if (!ret)
		dpll_pin_ref_dpll_del(pin, dpll);
	mutex_unlock(&dpll->lock);
	if (!ret)
		dpll_pin_notify(dpll, pin, DPLL_A_PIN_IDX);

	return ret;
}
EXPORT_SYMBOL_GPL(dpll_pin_deregister);

struct dpll_pin_ref
*dpll_pin_find_dpll_ref(const struct dpll_device *dpll,
			const struct dpll_pin *pin)
{
	struct dpll_pin_ref *ref;
	unsigned long index;

	xa_for_each((struct xarray *)&pin->dpll_refs, index, ref) {
		if (ref->dpll != dpll)
			continue;
		else
			return ref;
	}

	return NULL;
}

struct dpll_pin_ref
*dpll_pin_find_pin_ref(const struct dpll_pin *parent,
		       const struct dpll_pin *pin)
{
	struct dpll_pin_ref *ref;
	unsigned long index;

	xa_for_each((struct xarray *)&pin->pin_refs, index, ref) {
		if (ref->pin != parent)
			continue;
		else
			return ref;
	}

	return NULL;
}

void *dpll_priv(const struct dpll_device *dpll)
{
	return dpll->priv;
}
EXPORT_SYMBOL_GPL(dpll_priv);

void *dpll_pin_priv(const struct dpll_device *dpll, const struct dpll_pin *pin)
{
	struct dpll_pin_ref *ref = dpll_pin_find_dpll_ref(dpll, pin);

	if (!ref)
		return NULL;

	return ref->priv;
}
EXPORT_SYMBOL_GPL(dpll_pin_priv);

static int __init dpll_init(void)
{
	int ret;

	ret = dpll_netlink_init();
	if (ret)
		goto error;

	ret = class_register(&dpll_class);
	if (ret)
		goto unregister_netlink;

	return 0;

unregister_netlink:
	dpll_netlink_finish();
error:
	mutex_destroy(&dpll_device_xa_lock);
	return ret;
}
subsys_initcall(dpll_init);
