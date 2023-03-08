/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (c) 2021 Meta Platforms, Inc. and affiliates
 */

#ifndef __DPLL_CORE_H__
#define __DPLL_CORE_H__

#include <linux/dpll.h>
#include <linux/refcount.h>
#include "dpll_netlink.h"

#define DPLL_REGISTERED		XA_MARK_1

/**
 * struct dpll_device - structure for a DPLL device
 * @id:			unique id number for each device
 * @dev_driver_id:	id given by dev driver
 * @dev:		struct device for this dpll device
 * @parent:		parent device
 * @module:		module of creator
 * @ops:		operations this &dpll_device supports
 * @lock:		mutex to serialize operations
 * @type:		type of a dpll
 * @priv:		pointer to private information of owner
 * @pins:		list of pointers to pins registered with this dpll
 * @clock_id:		unique identifier (clock_id) of a dpll
 * @mode_supported_mask: mask of supported modes
 * @refcount:		refcount
 **/
struct dpll_device {
	u32 id;
	u32 dev_driver_id;
	struct device dev;
	struct device *parent;
	struct module *module;
	struct dpll_device_ops *ops;
	enum dpll_type type;
	void *priv;
	struct xarray pin_refs;
	u64 clock_id;
	unsigned long mode_supported_mask;
	refcount_t refcount;
};

/**
 * struct dpll_pin - structure for a dpll pin
 * @idx:		unique idx given by alloc on global pin's XA
 * @dev_driver_id:	id given by dev driver
 * @clock_id:		clock_id of creator
 * @module:		module of creator
 * @dpll_refs:		hold referencees to dplls that pin is registered with
 * @pin_refs:		hold references to pins that pin is registered with
 * @prop:		properties given by registerer
 * @rclk_dev_name:	holds name of device when pin can recover clock from it
 * @refcount:		refcount
 **/
struct dpll_pin {
	u32 idx;
	u32 dev_driver_id;
	u64 clock_id;
	struct module *module;
	struct xarray dpll_refs;
	struct xarray parent_refs;
	struct dpll_pin_properties prop;
	char *rclk_dev_name;
	refcount_t refcount;
};

/**
 * struct dpll_pin_ref - structure for referencing either dpll or pins
 * @dpll:		pointer to a dpll
 * @pin:		pointer to a pin
 * @ops:		ops for a dpll pin
 * @priv:		pointer to private information of owner
 **/
struct dpll_pin_ref {
	union {
		struct dpll_device *dpll;
		struct dpll_pin *pin;
	};
	struct dpll_pin_ops *ops;
	void *priv;
	refcount_t refcount;
};

struct dpll_device *dpll_device_get_by_id(int id);
struct dpll_device *dpll_device_get_by_name(const char *bus_name,
					    const char *dev_name);
void dpll_device_unregister(struct dpll_device *dpll);
struct dpll_pin *dpll_pin_get_by_idx(struct dpll_device *dpll, u32 idx);
struct dpll_pin_ref *
dpll_xa_ref_pin_find(struct xarray *xa_refs, const struct dpll_pin *pin);
struct dpll_pin_ref *
dpll_xa_ref_dpll_find(struct xarray *xa_refs, const struct dpll_device *dpll);
extern struct xarray dpll_device_xa;
extern struct xarray dpll_pin_xa;
extern struct mutex dpll_device_xa_lock;
extern struct mutex dpll_pin_xa_lock;
#endif
