// SPDX-License-Identifier: GPL-2.0
/*
 * Generic netlink for DPLL management framework
 *
 * Copyright (c) 2021 Meta Platforms, Inc. and affiliates
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>
#include "dpll_core.h"
#include "dpll_nl.h"
#include <uapi/linux/dpll.h>

static int
dpll_msg_add_dev_handle(struct sk_buff *msg, const struct dpll_device *dpll)
{
	if (nla_put_u32(msg, DPLL_A_ID, dpll->id))
		return -EMSGSIZE;
	if (nla_put_string(msg, DPLL_A_BUS_NAME, dev_bus_name(&dpll->dev)))
		return -EMSGSIZE;
	if (nla_put_string(msg, DPLL_A_DEV_NAME, dev_name(&dpll->dev)))
		return -EMSGSIZE;

	return 0;
}

static int
dpll_msg_add_mode(struct sk_buff *msg, const struct dpll_device *dpll,
		  struct netlink_ext_ack *extack)
{
	enum dpll_mode mode;

	if (WARN_ON(!dpll->ops->mode_get))
		return -EOPNOTSUPP;
	if (dpll->ops->mode_get(dpll, &mode, extack))
		return -EFAULT;
	if (nla_put_u8(msg, DPLL_A_MODE, mode))
		return -EMSGSIZE;

	return 0;
}

static int
dpll_msg_add_source_pin_idx(struct sk_buff *msg, struct dpll_device *dpll,
			    struct netlink_ext_ack *extack)
{
	u32 source_pin_idx;

	if (WARN_ON(!dpll->ops->source_pin_idx_get))
		return -EOPNOTSUPP;
	if (dpll->ops->source_pin_idx_get(dpll, &source_pin_idx, extack))
		return -EFAULT;
	if (nla_put_u32(msg, DPLL_A_SOURCE_PIN_IDX, source_pin_idx))
		return -EMSGSIZE;

	return 0;
}

static int
dpll_msg_add_lock_status(struct sk_buff *msg, struct dpll_device *dpll,
			 struct netlink_ext_ack *extack)
{
	enum dpll_lock_status status;

	if (WARN_ON(!dpll->ops->lock_status_get))
		return -EOPNOTSUPP;
	if (dpll->ops->lock_status_get(dpll, &status, extack))
		return -EFAULT;
	if (nla_put_u8(msg, DPLL_A_LOCK_STATUS, status))
		return -EMSGSIZE;

	return 0;
}

static int
dpll_msg_add_temp(struct sk_buff *msg, struct dpll_device *dpll,
		  struct netlink_ext_ack *extack)
{
	s32 temp;

	if (!dpll->ops->temp_get)
		return -EOPNOTSUPP;
	if (dpll->ops->temp_get(dpll, &temp, extack))
		return -EFAULT;
	if (nla_put_s32(msg, DPLL_A_TEMP, temp))
		return -EMSGSIZE;

	return 0;
}

static int
dpll_msg_add_pin_prio(struct sk_buff *msg, const struct dpll_device *dpll,
		      const struct dpll_pin *pin, struct dpll_pin_ops *ops,
		      struct netlink_ext_ack *extack)
{
	u32 prio;

	if (!ops->prio_get)
		return -EOPNOTSUPP;
	if (ops->prio_get(pin, dpll, &prio, extack))
		return -EFAULT;
	if (nla_put_u8(msg, DPLL_A_PIN_PRIO, prio))
		return -EMSGSIZE;

	return 0;
}

static u32 dpll_pin_freq_value[] = {
	[DPLL_PIN_FREQ_SUPP_1_HZ] = DPLL_PIN_FREQ_1_HZ,
	[DPLL_PIN_FREQ_SUPP_10_MHZ] = DPLL_PIN_FREQ_10_MHZ,
};

static int
dpll_msg_add_pin_freq(struct sk_buff *msg, const struct dpll_pin *pin,
		      struct netlink_ext_ack *extack, bool dump_any_freq)
{
	enum dpll_pin_freq_supp fs;
	struct dpll_pin_ref *ref;
	unsigned long i;
	u32 freq;

	xa_for_each((struct xarray *)&pin->dpll_refs, i, ref) {
		if (ref && ref->ops && ref->dpll)
			break;
	}

	if (!ref->ops->frequency_get)
		return -EOPNOTSUPP;
	if (ref->ops->frequency_get(pin, ref->dpll, &freq, extack))
		return -EFAULT;
	if (nla_put_u32(msg, DPLL_A_PIN_FREQUENCY, freq))
		return -EMSGSIZE;
	if (!dump_any_freq)
		return 0;

	for (fs = DPLL_PIN_FREQ_SUPP_UNSPEC; fs < DPLL_PIN_FREQ_SUPP_MAX; fs++)
		if (test_bit(fs, &pin->prop.freq_supported))
			if (nla_put_u32(msg, DPLL_A_PIN_FREQUENCY_SUPPORTED,
			    dpll_pin_freq_value[fs]))
				return -EMSGSIZE;
	if (pin->prop.any_freq_min && pin->prop.any_freq_max) {
		if (nla_put_u32(msg, DPLL_A_PIN_ANY_FREQUENCY_MIN,
				pin->prop.any_freq_min))
			return -EMSGSIZE;
		if (nla_put_u32(msg, DPLL_A_PIN_ANY_FREQUENCY_MAX,
				pin->prop.any_freq_max))
			return -EMSGSIZE;
	}

	return 0;
}

static int
dpll_msg_add_pin_parents(struct sk_buff *msg, struct dpll_pin *pin,
			 struct netlink_ext_ack *extack)
{
	struct dpll_pin_ref *ref = NULL;
	enum dpll_pin_state state;
	struct nlattr *nest;
	unsigned long index;
	int ret;

	xa_for_each(&pin->pin_refs, index, ref) {
		if (WARN_ON(!ref->ops->state_on_pin_get))
			return -EFAULT;
		ret = ref->ops->state_on_pin_get(pin, ref->pin, &state,
						 extack);
		if (ret)
			return -EFAULT;
		nest = nla_nest_start(msg, DPLL_A_PIN_PARENT);
		if (!nest)
			return -EMSGSIZE;
		if (nla_put_u32(msg, DPLL_A_PIN_IDX, ref->pin->dev_driver_id)) {
			ret = -EMSGSIZE;
			goto nest_cancel;
		}
		if (nla_put_u8(msg, DPLL_A_PIN_STATE, state)) {
			ret = -EMSGSIZE;
			goto nest_cancel;
		}
		nla_nest_end(msg, nest);
	}

	return 0;

nest_cancel:
	nla_nest_cancel(msg, nest);
	return ret;
}

static int
dpll_msg_add_pin_dplls(struct sk_buff *msg, struct dpll_pin *pin,
		       struct netlink_ext_ack *extack)
{
	enum dpll_pin_state state;
	struct dpll_pin_ref *ref;
	struct nlattr *attr;
	unsigned long index;
	int ret;

	xa_for_each(&pin->dpll_refs, index, ref) {
		struct dpll_device *dpll = ref->dpll;
		struct dpll_pin_ops *ops = ref->ops;

		if (WARN_ON(!ref->ops->state_on_dpll_get))
			return -EFAULT;
		ret = ops->state_on_dpll_get(pin, dpll, &state, extack);
		if (ret)
			return -EFAULT;
		attr = nla_nest_start(msg, DPLL_A_DPLL);
		if (!attr)
			return -EMSGSIZE;
		ret = dpll_msg_add_dev_handle(msg, dpll);
		if (ret)
			goto nest_cancel;
		if (nla_put_u8(msg, DPLL_A_PIN_STATE, state)) {
			ret = -EMSGSIZE;
			goto nest_cancel;
		}
		ret = dpll_msg_add_pin_prio(msg, dpll, pin, ops, extack);
		if (ret && ret != -EOPNOTSUPP)
			goto nest_cancel;
		nla_nest_end(msg, attr);
	}

	return 0;

nest_cancel:
	nla_nest_end(msg, attr);
	return ret;
}

static int
__dpll_cmd_pin_dump_one(struct sk_buff *msg, struct dpll_pin *pin,
			struct netlink_ext_ack *extack)
{
	int ret;

	if (nla_put_u32(msg, DPLL_A_PIN_IDX, pin->dev_driver_id))
		return -EMSGSIZE;
	if (nla_put_string(msg, DPLL_A_PIN_DESCRIPTION, pin->prop.description))
		return -EMSGSIZE;
	if (nla_put_s32(msg, DPLL_A_PIN_TYPE, pin->prop.type))
		return -EMSGSIZE;
	ret = dpll_msg_add_pin_freq(msg, pin, extack, true);
	if (ret)
		return ret;
	if (!xa_empty(&pin->pin_refs)) {
		ret = dpll_msg_add_pin_parents(msg, pin, extack);
		if (ret)
			return ret;
	}
	if (!xa_empty(&pin->dpll_refs)) {
		ret = dpll_msg_add_pin_dplls(msg, pin, extack);
		if (ret)
			return ret;
	}
	if (pin->rclk_dev_name)
		if (nla_put_string(msg, DPLL_A_PIN_RCLK_DEVICE,
				   pin->rclk_dev_name))
			return -EMSGSIZE;

	return 0;
}

static int
dpll_device_dump_one(struct dpll_device *dpll, struct sk_buff *msg,
		     struct netlink_ext_ack *extack)
{
	enum dpll_mode mode;
	int ret;

	ret = dpll_msg_add_dev_handle(msg, dpll);
		return ret;
	ret = dpll_msg_add_source_pin_idx(msg, dpll, extack);
	if (ret)
		return ret;
	ret = dpll_msg_add_temp(msg, dpll, extack);
	if (ret && ret != -EOPNOTSUPP)
		return ret;
	ret = dpll_msg_add_lock_status(msg, dpll, extack);
	if (ret)
		return ret;
	ret = dpll_msg_add_mode(msg, dpll, extack);
	if (ret)
		return ret;
	for (mode = DPLL_MODE_UNSPEC + 1; mode <= DPLL_MODE_MAX; mode++)
		if (test_bit(mode, &dpll->mode_supported_mask))
			if (nla_put_s32(msg, DPLL_A_MODE_SUPPORTED, mode))
				return -EMSGSIZE;
	if (nla_put_64bit(msg, DPLL_A_CLOCK_ID, sizeof(dpll->clock_id),
			  &dpll->clock_id, 0))
		return -EMSGSIZE;
	if (nla_put_s32(msg, DPLL_A_TYPE, dpll->type))
		return -EMSGSIZE;

	return 0;
}

static bool dpll_pin_is_freq_supported(struct dpll_pin *pin, u32 freq)
{
	enum dpll_pin_freq_supp fs;

	if (freq >= pin->prop.any_freq_min && freq <= pin->prop.any_freq_max)
		return true;
	for (fs = DPLL_PIN_FREQ_SUPP_UNSPEC; fs < DPLL_PIN_FREQ_SUPP_MAX; fs++)
		if (test_bit(fs, &pin->prop.freq_supported))
			if (freq == dpll_pin_freq_value[fs])
				return true;
	return false;
}

static int
dpll_pin_freq_set(struct dpll_pin *pin, struct nlattr *a,
		  struct netlink_ext_ack *extack)
{
	u32 freq = nla_get_u32(a);
	struct dpll_pin_ref *ref;
	unsigned long i;
	int ret;

	if (!dpll_pin_is_freq_supported(pin, freq))
		return -EINVAL;

	xa_for_each(&pin->dpll_refs, i, ref) {
		ret = ref->ops->frequency_set(pin, ref->dpll, freq, extack);
		if (ret)
			return -EFAULT;
		dpll_pin_notify(ref->dpll, pin, DPLL_A_PIN_FREQUENCY);
	}

	return 0;
}

static int
dpll_pin_parent_state_set(struct dpll_device *dpll, struct dpll_pin *pin,
			  struct nlattr *nested, struct netlink_ext_ack *extack)
{
	enum dpll_pin_state state;
	struct dpll_pin_ref *ref;
	struct dpll_pin *parent;
	struct nlattr *a;
	unsigned long i;
	u32 parent_idx;
	int ret, rem;

	if (!test_bit(DPLL_PIN_CAPS_STATE_CAN_CHANGE, &pin->prop.capabilities))
		return -EOPNOTSUPP;
	nla_for_each_nested(a, nested, rem) {
		switch (nla_type(a)) {
		case DPLL_A_PIN_STATE:
			state = nla_get_u8(a);
			break;
		case DPLL_A_PIN_PARENT_IDX:
			parent_idx = nla_get_u32(a);
			break;
		default:
			break;
		}
	}
	xa_for_each(&pin->pin_refs, i, parent) {
		if (parent->dev_driver_id == parent_idx)
			break;
	}
	if (!parent)
		return -EINVAL;
	ref = dpll_pin_find_pin_ref(parent, pin);
	if (!ref)
		return -EINVAL;
	ret = ref->ops->state_on_pin_set(pin, parent, state, extack);
	if (ret)
		return -EFAULT;
	dpll_pin_parent_notify(dpll, pin, parent, DPLL_A_PIN_STATE);

	return 0;
}

static int
dpll_pin_dpll_set(struct dpll_pin *pin, struct nlattr *nested,
		  struct netlink_ext_ack *extack)
{
	struct nlattr *a, *dev_attr = NULL, *bus_attr = NULL;
	bool state_change = false, prio_change = false;
	enum dpll_pin_state state;
	struct dpll_pin_ref *ref;
	unsigned long i;
	int rem;
	u8 prio;

	nla_for_each_nested(a, nested, rem) {
		switch (nla_type(a)) {
		case DPLL_A_DEV_NAME:
			dev_attr = a;
			break;
		case DPLL_A_BUS_NAME:
			bus_attr = a;
			break;
		case DPLL_A_PIN_STATE:
			state = nla_get_u8(a);
			state_change = true;
			break;
		case DPLL_A_PIN_PRIO:
			prio = nla_get_u8(a);
			prio_change = true;
			break;
		default:
			break;
		}
	}
	xa_for_each(&pin->dpll_refs, i, ref) {
		if (!nla_strcmp(bus_attr, dev_bus_name(&ref->dpll->dev)) &&
		    !nla_strcmp(dev_attr, dev_name(&ref->dpll->dev)))
			break;
	}
	if (!ref)
		return -EINVAL;

	if (state_change) {
		if (!test_bit(DPLL_PIN_CAPS_STATE_CAN_CHANGE,
			      &pin->prop.capabilities))
			return -EOPNOTSUPP;
		if (!ref->ops || !ref->ops->state_on_dpll_set)
			return -EOPNOTSUPP;
		if (ref->ops->state_on_dpll_set(pin, ref->dpll, state, extack))
			return -EINVAL;
		dpll_pin_notify(ref->dpll, pin, DPLL_A_PIN_STATE);
	}

	if (prio_change) {
		if (!test_bit(DPLL_PIN_CAPS_PRIORITY_CAN_CHANGE,
			      &pin->prop.capabilities))
			return -EOPNOTSUPP;
		if (!ref->ops || !ref->ops->prio_set)
			return -EOPNOTSUPP;
		if (ref->ops->prio_set(pin, ref->dpll, state, extack))
			return -EINVAL;
		dpll_pin_notify(ref->dpll, pin, DPLL_A_PIN_PRIO);
	}

	return 0;
}

static int
dpll_pin_direction_set(struct dpll_pin *pin, struct nlattr *a,
		       struct netlink_ext_ack *extack)
{
	enum dpll_pin_direction direction = nla_get_u8(a);
	struct dpll_pin_ref *ref;
	unsigned long i;

	if (!test_bit(DPLL_PIN_CAPS_DIRECTION_CAN_CHANGE,
		      &pin->prop.capabilities))
		return -EINVAL;

	xa_for_each(&pin->dpll_refs, i, ref) {
		if (ref->ops->direction_set(pin, ref->dpll, direction, extack))
			return -EFAULT;
		dpll_pin_notify(ref->dpll, pin, DPLL_A_PIN_DIRECTION);
	}

	return 0;
}

static int
dpll_pin_set_from_nlattr(struct dpll_device *dpll,
			 struct dpll_pin *pin, struct genl_info *info)
{
	int rem, ret = -EINVAL;
	struct nlattr *a;

	nla_for_each_attr(a, genlmsg_data(info->genlhdr),
			  genlmsg_len(info->genlhdr), rem) {
		switch (nla_type(a)) {
		case DPLL_A_PIN_FREQUENCY:
			ret = dpll_pin_freq_set(pin, a, info->extack);
			if (ret)
				return ret;
			break;
		case DPLL_A_PIN_PARENT:
			ret = dpll_pin_parent_state_set(dpll, pin, a,
							info->extack);
			if (ret)
				return ret;
			break;
		case DPLL_A_DPLL:
			ret = dpll_pin_dpll_set(pin, a, info->extack);
			if (ret)
				return ret;
			break;
		case DPLL_A_PIN_DIRECTION:
			ret = dpll_pin_direction_set(pin, a, info->extack);
			if (ret)
				return ret;
			break;
		default:
			break;
		}
	}

	return ret;
}

int dpll_nl_pin_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct dpll_device *dpll = info->user_ptr[0];
	struct dpll_pin *pin = info->user_ptr[1];

	return dpll_pin_set_from_nlattr(dpll, pin, info);
}

int dpll_nl_pin_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct dpll_pin *pin = info->user_ptr[1];
	struct nlattr *hdr, *nest;
	struct sk_buff *msg;
	int ret;

	if (!pin)
		return -ENODEV;
	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	hdr = genlmsg_put_reply(msg, info, &dpll_nl_family, 0,
				DPLL_CMD_DEVICE_GET);
	if (!hdr)
		return -EMSGSIZE;
	nest = nla_nest_start(msg, DPLL_A_PIN);
	if (!nest)
		return -EMSGSIZE;
	ret = __dpll_cmd_pin_dump_one(msg, pin, info->extack);
	if (ret) {
		nlmsg_free(msg);
		return ret;
	}
	nla_nest_end(msg, nest);
	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);
}

int dpll_nl_pin_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *hdr, *nest;
	struct dpll_pin *pin;
	unsigned long i;
	int ret;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &dpll_nl_family, 0, DPLL_CMD_DEVICE_GET);
	if (!hdr)
		return -EMSGSIZE;

	xa_for_each_marked(&dpll_pin_xa, i, pin, DPLL_PIN_REGISTERED) {
		nest = nla_nest_start(skb, DPLL_A_PIN);
		if (!nest) {
			ret = -EMSGSIZE;
			break;
		}
		ret = __dpll_cmd_pin_dump_one(skb, pin, cb->extack);
		if (ret) {
			nla_nest_cancel(skb, nest);
			break;
		}
		nla_nest_end(skb, nest);
	}

	if (ret)
		genlmsg_cancel(skb, hdr);
	else
		genlmsg_end(skb, hdr);

	return ret;
}

static int
dpll_set_from_nlattr(struct dpll_device *dpll, struct genl_info *info)
{
	struct nlattr *attr;
	int rem, ret = 0;

	nla_for_each_attr(attr, genlmsg_data(info->genlhdr),
			  genlmsg_len(info->genlhdr), rem) {
		switch (nla_type(attr)) {
		case DPLL_A_MODE:
			enum dpll_mode mode = nla_get_u8(attr);

			if (!dpll->ops || !dpll->ops->mode_set)
				return -EOPNOTSUPP;
			ret = dpll->ops->mode_set(dpll, mode, info->extack);
			if (ret)
				return ret;
			break;
		default:
			break;
		}
	}

	return ret;
}

int dpll_nl_device_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct dpll_device *dpll = info->user_ptr[0];

	return dpll_set_from_nlattr(dpll, info);
}

int dpll_nl_device_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *hdr, *nest;
	struct dpll_device *dpll;
	unsigned long i;
	int ret;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &dpll_nl_family, 0, DPLL_CMD_DEVICE_GET);
	if (!hdr)
		return -EMSGSIZE;

	mutex_lock(&dpll_device_xa_lock);
	xa_for_each(&dpll_device_xa, i, dpll) {
		nest = nla_nest_start(skb, DPLL_A_DPLL);
		mutex_lock(&dpll->lock);
		ret = dpll_device_dump_one(dpll, skb, cb->extack);
		mutex_unlock(&dpll->lock);
		if (ret) {
			nla_nest_cancel(skb, nest);
			break;
		}
		nla_nest_end(skb, nest);
	}
	mutex_unlock(&dpll_device_xa_lock);
	if (ret)
		genlmsg_cancel(skb, hdr);
	else
		genlmsg_end(skb, hdr);

	return ret;
}

int dpll_nl_device_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct dpll_device *dpll = info->user_ptr[0];
	struct nlattr *hdr, *nest;
	struct sk_buff *msg;
	int ret;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	hdr = genlmsg_put_reply(msg, info, &dpll_nl_family, 0,
				DPLL_CMD_DEVICE_GET);
	if (!hdr)
		return -EMSGSIZE;

	nest = nla_nest_start(msg, DPLL_A_DPLL);
	mutex_lock(&dpll->lock);
	ret = dpll_device_dump_one(dpll, msg, info->extack);
	mutex_unlock(&dpll->lock);
	if (ret) {
		nlmsg_free(msg);
		return ret;
	}
	nla_nest_end(msg, nest);
	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);
}

int dpll_pin_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		      struct genl_info *info)
{
	int ret = dpll_pre_doit(ops, skb, info);
	struct dpll_device *dpll;
	struct dpll_pin *pin;

	if (ret)
		return ret;
	dpll = info->user_ptr[0];
	if (!info->attrs[DPLL_A_PIN_IDX])
		return -EINVAL;
	pin = dpll_pin_get_by_idx(dpll,
				  nla_get_u32(info->attrs[DPLL_A_PIN_IDX]));
	if (!pin)
		return -EINVAL;
	info->user_ptr[1] = pin;

	return 0;
}

int dpll_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		  struct genl_info *info)
{
	struct dpll_device *dpll_id = NULL, *dpll_name = NULL;

	if (!info->attrs[DPLL_A_ID] &&
	    !(info->attrs[DPLL_A_BUS_NAME] && info->attrs[DPLL_A_DEV_NAME]))
		return -EINVAL;

	if (info->attrs[DPLL_A_ID]) {
		u32 id = nla_get_u32(info->attrs[DPLL_A_ID]);

		dpll_id = dpll_device_get_by_id(id);
		if (!dpll_id)
			return -ENODEV;
		info->user_ptr[0] = dpll_id;
	}
	if (info->attrs[DPLL_A_BUS_NAME] &&
	    info->attrs[DPLL_A_DEV_NAME]) {
		const char *bus_name = nla_data(info->attrs[DPLL_A_BUS_NAME]);
		const char *dev_name = nla_data(info->attrs[DPLL_A_DEV_NAME]);

		dpll_name = dpll_device_get_by_name(bus_name, dev_name);
		if (!dpll_name)
			return -ENODEV;

		if (dpll_id && dpll_name != dpll_id)
			return -EINVAL;
		info->user_ptr[0] = dpll_name;
	}

	return 0;
}

static int
dpll_event_device_change(struct sk_buff *msg, struct dpll_device *dpll,
			 struct dpll_pin *pin, struct dpll_pin *parent,
			 enum dplla attr)
{
	int ret = dpll_msg_add_dev_handle(msg, dpll);
	struct dpll_pin_ref *ref = NULL;

	if (ret)
		return ret;
	if (pin && nla_put_u32(msg, DPLL_A_PIN_IDX, pin->dev_driver_id))
		return -EMSGSIZE;

	switch (attr) {
	case DPLL_A_MODE:
		ret = dpll_msg_add_mode(msg, dpll, NULL);
		break;
	case DPLL_A_SOURCE_PIN_IDX:
		ret = dpll_msg_add_source_pin_idx(msg, dpll, NULL);
		break;
	case DPLL_A_LOCK_STATUS:
		ret = dpll_msg_add_lock_status(msg, dpll, NULL);
		break;
	case DPLL_A_TEMP:
		ret = dpll_msg_add_temp(msg, dpll, NULL);
		break;
	case DPLL_A_PIN_FREQUENCY:
		ret = dpll_msg_add_pin_freq(msg, pin, NULL, false);
		break;
	case DPLL_A_PIN_PRIO:
		ref = dpll_pin_find_dpll_ref(dpll, pin);
		if (!ref)
			return -EFAULT;
		ret = dpll_msg_add_pin_prio(msg, dpll, pin, ref->ops, NULL);
		break;
	case DPLL_A_PIN_STATE:
		enum dpll_pin_state state;

		if (parent) {
			ref = dpll_pin_find_pin_ref(parent, pin);
			if (!ref || !ref->ops || !ref->ops->state_on_pin_get)
				return -EOPNOTSUPP;
			ret = ref->ops->state_on_pin_get(pin, parent, &state,
							 NULL);
			if (ret)
				return ret;
			if (nla_put_u32(msg, DPLL_A_PIN_PARENT_IDX,
					parent->dev_driver_id))
				return -EMSGSIZE;
		} else {
			ref = dpll_pin_find_dpll_ref(dpll, pin);
			if (!ref || !ref->ops || !ref->ops->state_on_dpll_get)
				return -EOPNOTSUPP;
			ret = ref->ops->state_on_dpll_get(pin, dpll, &state,
							  NULL);
			if (ret)
				return ret;
		}
		if (nla_put_u8(msg, DPLL_A_PIN_STATE, state))
			return -EMSGSIZE;
		break;
	default:
		break;
	}

	return ret;
}

static int
dpll_send_event_create(enum dpll_event event, struct dpll_device *dpll)
{
	struct sk_buff *msg;
	int ret = -EMSGSIZE;
	void *hdr;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &dpll_nl_family, 0, event);
	if (!hdr)
		goto out_free_msg;

	ret = dpll_msg_add_dev_handle(msg, dpll);
	if (ret)
		goto out_cancel_msg;
	genlmsg_end(msg, hdr);
	genlmsg_multicast(&dpll_nl_family, msg, 0, 0, GFP_KERNEL);

	return 0;

out_cancel_msg:
	genlmsg_cancel(msg, hdr);
out_free_msg:
	nlmsg_free(msg);

	return ret;
}

static int
dpll_send_event_change(struct dpll_device *dpll, struct dpll_pin *pin,
		       struct dpll_pin *parent, enum dplla attr)
{
	struct sk_buff *msg;
	int ret = -EMSGSIZE;
	void *hdr;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &dpll_nl_family, 0, DPLL_EVENT_DEVICE_CHANGE);
	if (!hdr)
		goto out_free_msg;

	ret = dpll_event_device_change(msg, dpll, pin, parent, attr);
	if (ret)
		goto out_cancel_msg;
	genlmsg_end(msg, hdr);
	genlmsg_multicast(&dpll_nl_family, msg, 0, 0, GFP_KERNEL);

	return 0;

out_cancel_msg:
	genlmsg_cancel(msg, hdr);
out_free_msg:
	nlmsg_free(msg);

	return ret;
}

int dpll_notify_device_create(struct dpll_device *dpll)
{
	return dpll_send_event_create(DPLL_EVENT_DEVICE_CREATE, dpll);
}

int dpll_notify_device_delete(struct dpll_device *dpll)
{
	return dpll_send_event_create(DPLL_EVENT_DEVICE_DELETE, dpll);
}

int dpll_device_notify(struct dpll_device *dpll, enum dplla attr)
{
	return dpll_send_event_change(dpll, NULL, NULL, attr);
}
EXPORT_SYMBOL_GPL(dpll_device_notify);

int dpll_pin_notify(struct dpll_device *dpll, struct dpll_pin *pin,
		    enum dplla attr)
{
	return dpll_send_event_change(dpll, pin, NULL, attr);
}

int dpll_pin_parent_notify(struct dpll_device *dpll, struct dpll_pin *pin,
			   struct dpll_pin *parent, enum dplla attr)
{
	return dpll_send_event_change(dpll, pin, parent, attr);
}

int __init dpll_netlink_init(void)
{
	return genl_register_family(&dpll_nl_family);
}

void dpll_netlink_finish(void)
{
	genl_unregister_family(&dpll_nl_family);
}

void __exit dpll_netlink_fini(void)
{
	dpll_netlink_finish();
}
