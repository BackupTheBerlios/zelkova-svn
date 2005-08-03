/*
 *----------------------------------------------------------------------------
 *
 * Zelkova - A Firewall and Intrusion Prevention System on Linux Kernel
 *
 * Copyright (C) 2005 Dongsu Park <advance@dongsu.pe.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *
 * $Id$
 *----------------------------------------------------------------------------
 */

/** @file main.c
 * Core modules of Zelkova
 */

#ifndef __KERNEL__
# define __KERNEL__
#endif

#ifndef MODULE
# define MODULE
#endif

/*#include <linux/config.h>*/
#include <asm/poll.h>				/* POLLIN, POLLRDNORM */
#include <linux/types.h>			/* size_t */
/*#include <linux/sched.h>*/
#include <linux/kernel.h>			/* printk() */
/*#include <linux/init.h>*/
/*#include <asm/uaccess.h>*/
#include <linux/module.h>
#include <linux/slab.h>				/* kmalloc() */
#include <linux/fs.h>				/*  */
#include <linux/errno.h>			/* error codes */
#include <linux/proc_fs.h>			/*  */
#include <linux/netfilter.h>		/* nf_hook_ops */
#include <linux/netfilter_ipv4.h>	/* NF_* */

#include "zelkova.h"
#include "zkuio.h"
#include "zkpktinfo.h"				/* zkpktinfo_t */


/*
 * Static Functions & Variables
 */
static int __init zelkova_init_module(void);
static void __exit zelkova_cleanup_module(void);

static ssize_t		zelkova_read(struct file *file, char *buf, size_t nbytes, loff_t *ppos);
static unsigned int	zelkova_poll(struct file *, struct poll_table_struct *);
static int			zelkova_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
static int			zelkova_open(struct inode *, struct file *);
static int			zelkova_release(struct inode *, struct file *);

static unsigned int zkfv_input_check (unsigned int hook,
		struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *));

static unsigned int zkfv_forward_check (unsigned int hook,
		struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *));

static unsigned int zkfv_output_check (unsigned int hook,
		struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *));

/**
 * @var   zelkova_fops
 * @brief A file_operations interface into zelkova device driver
 *
 * Here we register 5 fops handlers such as read, poll, ioctl, open, release.
 */
static struct file_operations zelkova_fops = {
	.owner		= THIS_MODULE,
	.read		= zelkova_read,
	.poll		= zelkova_poll,
	.ioctl		= zelkova_ioctl,
	.open		= zelkova_open,
	.release	= zelkova_release,
};


/**
 * @var   zkfv_ops
 * @brief An array of nf_hook_ops which includes basic zelkova packet handlers
 *
 * Zelkova is attached into existing netfilter framework, so that at least
 * three packet handlers should be hooked at each three points, that is,
 * input, forward, and output.
 */
static struct nf_hook_ops zkfv_ops[] = {
	/* TODO: Check differences between hooknums and make a document */
	{
		{ NULL, NULL },
		.hook		= zkfv_input_check,
		.pf			= PF_INET,
		.hooknum	= NF_IP_LOCAL_IN,
		.priority	= NF_IP_PRI_FILTER,
	},
	{
		{ NULL, NULL },
		.hook		= zkfv_forward_check,
		.pf			= PF_INET,
		.hooknum	= NF_IP_FORWARD,
		.priority	= NF_IP_PRI_FILTER,
	},
	{
		{ NULL, NULL },
		.hook		= zkfv_output_check,
		.pf			= PF_INET,
		.hooknum	= NF_IP_LOCAL_OUT,
		.priority	= NF_IP_PRI_FILTER,
	},
};

/**
 * @var   zelkova_run
 * @brief A global flag which indicates whether zelkova is running.
 *
 * 1 if running, 0 if not running.
 */
static int	zelkova_run = 0;

int zelkova_major =		ZELKOVA_MAJOR;	/**< Major number of zelkova device file */
int zelkova_nr_devs =	ZELKOVA_NR_DEVS;	/**< Number of total devices */

MODULE_PARM(zelkova_major, "i");
MODULE_PARM(zelkova_nr_devs, "i");
MODULE_PARM_DESC(zelkova_major, "Major number of zelkova device file");
MODULE_PARM_DESC(zelkova_nr_devs, "Total number of zelkova device files");
MODULE_AUTHOR("Dongsu Park");
MODULE_DESCRIPTION("High-Traffic-Processible Firewall & IPS software");
MODULE_LICENSE("GPL");

void		*spdroot;		/* FIS-tree root */

void zelkova_attach(void);
void zelkova_detach(void);

/*
 * Extern Functions & Variables
 */
extern int	zelkova_ioctl_filter(uint cmd, void *data, int mode);


/**
 *---------------------------------------------------------------------------
 *
 * @fn     int zelkova_init_module(void)
 * @brief  Initializes the zelkova module
 * @param  NONE
 * @return >=0 if normal, <0 if abnormal.
 * @date   19 Jul, 2005
 * @see    zelkova_cleanup_module()
 *
 *  Attaches into kernel interceptor, and initializes character devices.
 *
 *---------------------------------------------------------------------------
 */

static int __init zelkova_init_module(void)
{
	int		ret;
	int		result;

	zelkova_attach();

	/* Register an input hook */
	ret = nf_register_hook(&zkfv_ops[0]);
	if (ret < 0) {
		ZKDEBUG("Error: nf_register_hook(&zkfv_ops[0]) failed.\n");
		goto cleanup_table;
	}

	/* Register a forward hook */
	ret = nf_register_hook(&zkfv_ops[1]);
	if (ret < 0) {
		ZKDEBUG("Error: nf_register_hook(&zkfv_ops[1]) failed.\n");
		goto cleanup_hook0;
	}

	/* Register an output hook */
	ret = nf_register_hook(&zkfv_ops[2]);
	if (ret < 0) {
		ZKDEBUG("Error: nf_register_hook(&zkfv_ops[2]) failed.\n");
		goto cleanup_hook1;
	}

	/* Register to the character device with major number zelkova_major. */
	result = register_chrdev(zelkova_major, ZELKOVA_MODNAME, &zelkova_fops);
	if (result < 0) {
		ZKDEBUG("Error: unable to get a major number %d\n", zelkova_major);
		return result;
	}
    if (zelkova_major == 0) {
		zelkova_major = result; /* dynamic */
	}

	/* Increase the zelkova counter value */
	zelkova_run++;

	ZKDEBUG("The module %s has been attached.\n", ZELKOVA_MODNAME);

	return ret;

cleanup_hook1:
	nf_unregister_hook(&zkfv_ops[1]);
cleanup_hook0:
	nf_unregister_hook(&zkfv_ops[0]);
cleanup_table:

	return -1;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zelkova_cleanup_module(void)
 * @brief  Unload the zelkova module from kernel
 * @param  NONE
 * @return NONE
 * @date   19 Jul, 2005
 * @see    zelkova_init_module()
 *
 *  Detach swip from kernel, and unload the zelkova module from kernel.
 *
 *---------------------------------------------------------------------------
 */

static void __exit zelkova_cleanup_module(void)
{
	unsigned int i;

	zelkova_run = 0;

	unregister_chrdev(zelkova_major, ZELKOVA_MODNAME);

	for (i = 0; i < sizeof(zkfv_ops) / sizeof(struct nf_hook_ops); i++) {
		nf_unregister_hook(&zkfv_ops[i]);
	}

	zelkova_detach();
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn void zelkova_attach(void)
 * @brief Initializes variables in the zelkova module
 * @param NONE
 * @return NONE
 * @date 19 Jul, 2005
 * @see zelkova_detach()
 *
 *  Initializes variables in the zelkova module
 *
 *---------------------------------------------------------------------------
 */

void zelkova_attach(void)
{
#if 0
	init_timer(&timer);

	timer.expires	= jiffies + SWEEP_TIMERTIME;
	timer.data		= 0;
	timer.function	= &slowtimer;

	add_timer(&timer);
#endif
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     void zelkova_detach(void)
 * @brief  Cleans variables in the zelkova module
 * @param  NONE
 * @return NONE
 * @date   21 Jul, 2005
 * @see    zelkova_attach()
 *
 *  Cleans variables in the zelkova module
 *
 *---------------------------------------------------------------------------
 */

void zelkova_detach(void)
{
#if 0
	del_timer(&timer);
#endif
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static ssize_t zelkova_read(struct file *file, char *buf, size_t nbytes, loff_t *ppos)
 * @brief  Get log informations from the zelkova device
 * @param  struct file *file
 * @param  char *buf
 * @param  size_t nbytes
 * @param  loff_t *ppos
 * @return Return data size read, 0 if read none
 * @date   21 Jul, 2005
 * @see    zelkova_poll(), zelkova_ioctl(), zelkova_open(), zelkova_release()
 *
 *  Get log informations from the zelkova device
 *
 *---------------------------------------------------------------------------
 */

static ssize_t zelkova_read(struct file *file, char *buf, size_t nbytes, loff_t *ppos)
{
	struct inode	*inode = file->f_dentry->d_inode;
	int				unit = minor(inode->i_rdev);
	struct uio		uio;

	if (nbytes == 0) {
		return 0;
	}

	uio.uio_resid	= nbytes;
	uio.uio_buff	= buf;

	switch (unit) {
		case DEV_ACCT:
			/* TODO: return zelkovalog_read(unit, &uio); */
		default:
			return 0;
	}

	return 0;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static unsigned int zelkova_poll(struct file *file, struct poll_table_struct *wait)
 * @brief  processes select operations on the character device
 * @param  struct file *file
 * @param  struct poll_table_struct *wait
 * @return Return poll flag value, 0 if none
 * @date   21 Jul, 2005
 * @see    zelkova_read(), zelkova_ioctl(), zelkova_open(), zelkova_release()
 *
 *  Processes select operations on the character device
 *
 *---------------------------------------------------------------------------
 */

static unsigned int zelkova_poll(struct file *file, struct poll_table_struct *wait)
{
	struct inode	*inode = file->f_dentry->d_inode;

	/* file->private_data is pointing struct private structure */

	switch (minor(inode->i_rdev)) {
	case DEV_ACCT:
		/* TODO: poll_wait() */

		return (POLLIN | POLLRDNORM);

		break;
	default:
		break;
	}

	return 0;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static int zelkova_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
 * @brief  Process data exchange operations
 * @param  struct inode *inode
 * @param  struct file *file
 * @param  unsigned int cmd
 * @param  unsigned long arg
 * @return 0 if normal, <0 if abnormal.
 * @date   21 Jul, 2005
 * @see    zelkova_read(), zelkova_poll(), zelkova_open(), zelkova_release()
 *
 *  Process data exchange operations between kernel module and
 *  another applications.
 *
 *---------------------------------------------------------------------------
 */

static int zelkova_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	static int	nioctl = 0;
/*    int			unit = minor(inode->i_rdev);*/
	int			mode = file->f_mode;

	if (!zelkova_run) {
		return -ENXIO;
	}

	nioctl++;

	ZKDEBUG("ioctl: [%d] '%c'/0x%02x unit=%d mode=0x%x\n",
			nioctl, (char)_IOC_TYPE(cmd), (uint32_t)_IOC_NR(cmd), unit, mode);

	/* NOTE: ioctl() and NF_IP_LOCAL_OUT is processed by system calls.
	 * Therefore bottom half interrupts have to be controlled in this point
	 * in order to avoid reentrant problems triggered by bottom half interrupt
	 * handlers.
	 */

	switch(_IOC_TYPE(cmd)) {
	case FILTER_IOCTL:	/* Filter rules */
		return zelkova_ioctl_filter(cmd, (void *)arg, mode);
	default:
		return -EINVAL;
	}

	return 0;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static int zelkova_open(struct inode *inode, struct file *file)
 * @brief  Open the zelkova device
 * @param  struct inode *inode
 * @param  struct file *file
 * @return 0 if normal, <0 if abnormal.
 * @date   21 Jul, 2005
 * @see    zelkova_read(), zelkova_poll(), zelkova_ioctl(), zelkova_release()
 *
 *  Open the zelkova device
 *
 *---------------------------------------------------------------------------
 */

static int zelkova_open(struct inode *inode, struct file *file)
{
	if (minor(inode->i_rdev) > DEV_MAX) {
		return -ENXIO;
	}

	MOD_INC_USE_COUNT;

	return 0;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static int zelkova_release(struct inode *inode, struct file *file)
 * @brief  Close the zelkova device
 * @param  struct inode *inode
 * @param  struct file *file
 * @return 0 if normal, <0 if abnormal.
 * @date   21 Jul, 2005
 * @see    zelkova_read(), zelkova_poll(), zelkova_ioctl(), zelkova_open()
 *
 *  Close the zelkova device
 *
 *---------------------------------------------------------------------------
 */

static int zelkova_release(struct inode *inode, struct file *file)
{
	if (minor(inode->i_rdev) > DEV_MAX) {
		return -ENXIO;
	}

	MOD_DEC_USE_COUNT;

	return 0;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static unsigned int zkfv_input_check(unsigned int hook, struct sk_buff **pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
 * @brief  Check packets on the netfilter input hook
 * @param  unsigned int hook
 * @param  struct sk_buff **pskb
 * @param  const struct net_device *in
 * @param  const struct net_device *out
 * @param  int (*okfn)(struct sk_buff *)
 * @return NF_ACCEPT, NF_DROP, or etc.
 * @date   23 Jul, 2005
 * @see    zkfv_forward_check(), zkfv_output_check()
 *
 *  Check packets on the netfilter input hook
 *
 *---------------------------------------------------------------------------
 */

static unsigned int zkfv_input_check (unsigned int hook,
		struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return NF_ACCEPT;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static unsigned int zkfv_forward_check(unsigned int hook, struct sk_buff **pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
 * @brief  Check packets on the netfilter forward hook
 * @param  unsigned int hook
 * @param  struct sk_buff **pskb
 * @param  const struct net_device *in
 * @param  const struct net_device *out
 * @param  int (*okfn)(struct sk_buff *)
 * @return NF_ACCEPT, NF_DROP, or etc.
 * @date   23 Jul, 2005
 * @see    zkfv_input_check(), zkfv_output_check()
 *
 *  Check packets on the netfilter forward hook
 *
 *---------------------------------------------------------------------------
 */

static unsigned int zkfv_forward_check (unsigned int hook,
		struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return NF_ACCEPT;
}


/**
 *---------------------------------------------------------------------------
 *
 * @fn     static unsigned int zkfv_output_check(unsigned int hook, struct sk_buff **pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
 * @brief  Check packets on the netfilter output hook
 * @param  unsigned int hook
 * @param  struct sk_buff **pskb
 * @param  const struct net_device *in
 * @param  const struct net_device *out
 * @param  int (*okfn)(struct sk_buff *)
 * @return NF_ACCEPT, NF_DROP, or etc.
 * @date   23 Jul, 2005
 * @see    zkfv_input_check(), zkfv_forward_check()
 *
 *  Check packets on the netfilter output hook
 *
 *---------------------------------------------------------------------------
 */

static unsigned int zkfv_output_check (unsigned int hook,
		struct sk_buff **pskb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return NF_ACCEPT;
}

module_init(zelkova_init_module);
module_exit(zelkova_cleanup_module);
