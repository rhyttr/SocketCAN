/*
* drivers/net/can/softing/softing_cs.c
*
* Copyright (C) 2008
*
* - Kurt Van Dijck, EIA Electronics
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the version 2 of the GNU General Public License
* as published by the Free Software Foundation
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/major.h>
#include <linux/io.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ciscode.h>
#include <pcmcia/ds.h>
#include <pcmcia/cisreg.h>

#include <asm/system.h>

#include "softing.h"

struct softing_cs {
	struct io_req_t  io ;
	struct irq_req_t irq;
	window_handle_t  win;
	config_req_t	  conf;
	struct softing	 softing;
};
#define softing2cs(x) container_of((x), struct softing_cs, softing)

struct lookup {
	int i;
	const char *a;
};

static const char __devinit *lookup_mask(const struct lookup *lp, int *i)
{
	for (; lp->a; ++lp) {
		if (lp->i & *i) {
			*i &= ~lp->i;
			return lp->a;
		}
	}
	return 0;
}

static int card_reset_via_pcmcia(struct softing *sdev, int v)
{
	struct pcmcia_device *pcmcia = to_pcmcia_dev(sdev->dev);
	conf_reg_t reg;
	reg.Function = 0; /* socket */
	reg.Action	 = CS_WRITE;
	reg.Offset	 = 2;
	reg.Value	 = v ? 0 : 0x20;
	return pcmcia_access_configuration_register(pcmcia, &reg);
}

static int card_reset_via_dpram(struct softing *sdev, int v)
{
	if (v) {
		spin_lock_bh(&sdev->spin);
		sdev->dpram.virt[0xe00] &= ~1;
		spin_unlock_bh(&sdev->spin);
		card_reset_via_pcmcia(sdev, v);
	} else {
		card_reset_via_pcmcia(sdev, v);
		spin_lock_bh(&sdev->spin);
		sdev->dpram.virt[0xe00] |=  1;
		spin_unlock_bh(&sdev->spin);
	}
	return 0;
}

static int card_enable_irq_via_pcmcia(struct softing *sdev, int v)
{
	int ret;
	struct pcmcia_device *pcmcia = to_pcmcia_dev(sdev->dev);
	conf_reg_t reg;
	memset(&reg, 0, sizeof(reg));
	reg.Function = 0; /* socket */
	reg.Action	 = CS_WRITE;
	reg.Offset	 = 0;
	reg.Value	 = v ? 0x60 : 0;
	ret = pcmcia_access_configuration_register(pcmcia, &reg);
	if (ret)
		mod_alert("failed %u", ret);
	return ret;
}

/* TODO: in 2.6.26, __devinitconst works*/
static const __devinitdata struct lookup pcmcia_io_attr[] = {
	{ IO_DATA_PATH_WIDTH_AUTO	, "[auto]"	, },
	{ IO_DATA_PATH_WIDTH_8		, "8bit"	, },
	{ IO_DATA_PATH_WIDTH_16		, "16bit"	, },
	{ 0, 0, },
};

static const __devinitdata struct lookup pcmcia_mem_attr[] = {
	{ WIN_ADDR_SPACE_IO	, "IO"		, },
	{ WIN_MEMORY_TYPE_AM	, "typeAM"	, },
	{ WIN_ENABLE		, "enable"	, },
	{ WIN_DATA_WIDTH_8	, "8bit"	, },
	{ WIN_DATA_WIDTH_16	, "16bit"	, },
	{ WIN_DATA_WIDTH_32	, "32bit"	, },
	{ WIN_PAGED		, "paged"	, },
	{ WIN_SHARED		, "shared"	, },
	{ WIN_FIRST_SHARED	, "first_shared", },
	{ WIN_USE_WAIT		, "wait"	, },
	{ WIN_STRICT_ALIGN	, "strict_align", },
	{ WIN_MAP_BELOW_1MB	, "below_1MB"	, },
	{ WIN_PREFETCH		, "prefetch"	, },
	{ WIN_CACHEABLE		, "cacheable"	, },
	{ 0, 0, },
};

static int __devinit
dev_config(struct pcmcia_device *pcmcia, struct softing_cs *csdev)
{
	struct softing *sdev = &csdev->softing;
	cistpl_cftable_entry_t *cf;
	int ret;
	int last_ret = 0;
	int last_fn  = 0;
	struct {
		tuple_t tuple;
		unsigned char buff[64];
		cisparse_t parse;
	} cfg;
	config_info_t config;
	cistpl_cftable_entry_t def_cf = { 0, };
	win_req_t req;
	memreq_t map;

	mod_info("%s", pcmcia->devname);

	cfg.tuple.Attributes		= 0;
	cfg.tuple.TupleData		= (cisdata_t *)cfg.buff;
	cfg.tuple.TupleDataMax	= sizeof(cfg.buff);
	cfg.tuple.TupleOffset	= 0;
	/* Get configuration register information */
	cfg.tuple.DesiredTuple	= CISTPL_CONFIG;
	if (pcmcia_get_first_tuple(pcmcia, &cfg.tuple))
		goto cs_failed;
	if (pcmcia_get_tuple_data(pcmcia, &cfg.tuple))
		goto cs_failed;
	if (pcmcia_parse_tuple(pcmcia, &cfg.tuple, &cfg.parse))
		goto cs_failed;
	csdev->conf.ConfigBase = cfg.parse.config.base;
	csdev->conf.Present	  = cfg.parse.config.rmask[0];

	/* get current Vcc */
	ret = pcmcia_get_configuration_info(pcmcia, &config);
	if (ret)
		goto cs_failed;

	cf = &cfg.parse.cftable_entry;
	cfg.tuple.DesiredTuple	= CISTPL_CFTABLE_ENTRY;

	if (pcmcia_get_first_tuple(pcmcia, &cfg.tuple))
		goto cs_failed;
	do {
		if (pcmcia_get_tuple_data(pcmcia, &cfg.tuple)
			|| pcmcia_parse_tuple(pcmcia, &cfg.tuple, &cfg.parse))
			goto do_next;
		if (cf->flags & CISTPL_CFTABLE_DEFAULT)
			def_cf = *cf;
		if (!cf->index)
			goto do_next;
		csdev->conf.ConfigIndex = cf->index;
		/* power settings (Vcc & Vpp) */
		if (cf->vcc.present & (1 << CISTPL_POWER_VNOM)) {
			if (config.Vcc !=
				cf->vcc.param[CISTPL_POWER_VNOM]/10000) {
				mod_alert("%s: cf->Vcc mismatch\n", __FILE__);
				goto do_next;
			}
		} else if (def_cf.vcc.present & (1 << CISTPL_POWER_VNOM)) {
			if (config.Vcc !=
				def_cf.vcc.param[CISTPL_POWER_VNOM]/10000) {
				mod_alert("%s: cf->Vcc mismatch\n", __FILE__);
				goto do_next;
			}
		}
		if (cf->vpp1.present & (1 << CISTPL_POWER_VNOM))
			config.Vpp1
				= config.Vpp2
				= cf->vpp1.param[CISTPL_POWER_VNOM] / 10000;

		else if (def_cf.vpp1.present & (1 << CISTPL_POWER_VNOM))
			config.Vpp1
				= config.Vpp2
				= def_cf.vpp1.param[CISTPL_POWER_VNOM] / 10000;

		/* interrupt ? */
		if (cf->irq.IRQInfo1 || def_cf.irq.IRQInfo1)
			csdev->conf.Attributes |= CONF_ENABLE_IRQ;
		/* IO window */
		csdev->io.NumPorts1
			= csdev->io.NumPorts2
			= 0;
		if ((cf->io.nwin > 0) || (def_cf.io.nwin > 0)) {
			cistpl_io_t *io = (cf->io.nwin) ? &cf->io : &def_cf.io;
			csdev->io.Attributes1 = IO_DATA_PATH_WIDTH_AUTO;
			if (!(io->flags & CISTPL_IO_8BIT))
				csdev->io.Attributes1 = IO_DATA_PATH_WIDTH_16;
			if (!(io->flags & CISTPL_IO_16BIT))
				csdev->io.Attributes1 = IO_DATA_PATH_WIDTH_8;
			csdev->io.IOAddrLines
				= io->flags & CISTPL_IO_LINES_MASK;
			csdev->io.BasePort1 = io->win[0].base;
			csdev->io.NumPorts1 = io->win[0].len ;
			if (io->nwin > 1) {
				csdev->io.Attributes2 = csdev->io.Attributes1;
				csdev->io.BasePort2	 = io->win[1].base;
				csdev->io.NumPorts2	 = io->win[1].base;
			}
			/* reserve IO, but don't enable it. */
			ret = pcmcia_request_io(pcmcia, &csdev->io);
			if (ret) {
				mod_alert("pcmcia_request_io() mismatch\n");
				goto do_next;
			}
		}
		/* Memory window */
		if ((cf->mem.nwin > 0) || (def_cf.mem.nwin > 0)) {
			cistpl_mem_t *mem
				= (cf->mem.nwin) ? &cf->mem : &def_cf.mem;
			req.Attributes = ((sdev->desc->generation >= 2)
					? WIN_DATA_WIDTH_16 : WIN_DATA_WIDTH_8)
				| WIN_MEMORY_TYPE_CM
				| WIN_ENABLE;
			req.Base = mem->win[0].host_addr;
			req.Size = mem->win[0].len;
			if (req.Size < 0x1000)
				req.Size = 0x1000;
			req.AccessSpeed = 0;
			ret = pcmcia_request_window(&pcmcia, &req, &csdev->win);
			if (ret) {
				mod_alert("pcmcia_request_window() mismatch\n");
				goto do_next;
			}
			if (sdev->desc->generation < 2) {
				csdev->win->ctl.flags
					= MAP_ACTIVE | MAP_USE_WAIT;
				csdev->win->ctl.speed = 3;
			}
			map.Page = 0;
			map.CardOffset = mem->win[0].card_addr;
			if (pcmcia_map_mem_page(csdev->win, &map)) {
				mod_alert("pcmcia_map_mem_page() mismatch\n");
				goto do_next_win;
			}
		} else {
			mod_info("no memory window in tuple %u", cf->index);
			goto do_next;
		}
		break;
do_next_win:
		pcmcia_release_window(csdev->win);
do_next:
		pcmcia_disable_device(pcmcia);
		if (pcmcia_get_next_tuple(pcmcia, &cfg.tuple))
			goto cs_failed;
	} while (1);

	if (csdev->conf.Attributes & CONF_ENABLE_IRQ) {
		/*csdev->irq.Handler  = dev_interrupt_nshared;
		csdev->irq.Instance = card;
		csdev->irq.Attributes |= IRQ_HANDLE_PRESENT;
		*/
		if (pcmcia_request_irq(pcmcia, &csdev->irq))
			goto cs_failed;
	}

	if (pcmcia_request_configuration(pcmcia, &csdev->conf))
		goto cs_failed;

	/* Finally, report what we've done */
	printk(KERN_INFO "[%s] %s: index 0x%02x",
			THIS_MODULE->name,
			pcmcia->devname,
			csdev->conf.ConfigIndex);
	printk(", Vcc %d.%01d", config.Vcc/10, config.Vcc%10);
	if (config.Vpp1)
		printk(", Vpp %d.%d", config.Vpp1/10, config.Vpp1%10);
	if (csdev->conf.Attributes & CONF_ENABLE_IRQ) {
		printk(", irq %d", csdev->irq.AssignedIRQ);
		sdev->irq.nr = csdev->irq.AssignedIRQ;
	}
	if (csdev->io.NumPorts1) {
		int tmp;
		const char *p;
		printk(", io 0x%04x-0x%04x"
				, pcmcia->io.BasePort1
				, csdev->io.BasePort1+csdev->io.NumPorts1-1);
		tmp = csdev->io.Attributes1;
		if (tmp) {
			do {
				p = lookup_mask(pcmcia_io_attr, &tmp);
				if (p)
					printk(" %s", p);
			} while (p);
		}
	}
	if (csdev->io.NumPorts2) {
		int tmp;
		const char *p;
		printk(" & 0x%04x-0x%04x"
			, csdev->io.BasePort2
			, csdev->io.BasePort2+csdev->io.NumPorts2-1);
		tmp = csdev->io.Attributes2;
		if (tmp)
			do {
				p = lookup_mask(pcmcia_io_attr, &tmp);
				if (p)
					printk(" %s", p);
			} while (p);
	}
	if (csdev->win) {
		int tmp;
		const char *p;
		sdev->dpram.phys = req.Base;
		sdev->dpram.size = req.Size;
		printk(", mem 0x%08lx-0x%08lx"
				, sdev->dpram.phys
				, sdev->dpram.phys + sdev->dpram.size-1);
		tmp = req.Attributes;
		if (tmp)
			do {
				p = lookup_mask(pcmcia_mem_attr, &tmp);
				if (p)
					printk(" %s", p);
			} while (p);
	}
	printk("\n");
	return 0;

cs_failed:
	cs_error(pcmcia, last_fn, last_ret);
	pcmcia_release_window(csdev->win);
	pcmcia_disable_device(pcmcia);
	return EINVAL;
}

static void driver_remove(struct pcmcia_device *pcmcia)
{
	struct softing *card = (struct softing *)pcmcia->priv;
	struct softing_cs *cs = softing2cs(card);
	mod_trace("%s,device'%s'", card->id.name, pcmcia->devname);
	rm_softing(card);
	/* release pcmcia stuff */
	pcmcia_release_window(cs->win);
	pcmcia_disable_device(pcmcia);
	/* free bits */
	kfree(cs);
}

static int __devinit driver_probe(struct pcmcia_device *pcmcia)
{
	struct softing_cs *cs;
	struct softing		*card;
	int ret = 0;

	mod_trace("on %s", pcmcia->devname);

	/* Create new softing device */
	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs) {
		ret = ENOMEM;
		goto no_mem;
	}
	card = &cs->softing;
	pcmcia->priv = card;
	card->id.manf = pcmcia->manf_id;
	card->id.prod = pcmcia->card_id;
	card->desc = softing_lookup_desc(card->id.manf, card->id.prod);
	card->dev = &pcmcia->dev;
	if (card->desc->generation >= 2) {
		card->fn.reset = card_reset_via_dpram;
	} else {
		card->fn.reset = card_reset_via_pcmcia;
		card->fn.enable_irq = card_enable_irq_via_pcmcia;
	}

	card->nbus = 2;
	card->irq.shared = (card->desc->generation >= 2);
	/* presets */
	cs->irq.Attributes
		= card->irq.shared
		? IRQ_TYPE_DYNAMIC_SHARING : IRQ_TYPE_EXCLUSIVE;
	cs->irq.IRQInfo1	 = IRQ_LEVEL_ID;
	cs->irq.Handler	 = 0;
	cs->conf.Attributes = 0;
	cs->conf.IntType	  = INT_MEMORY_AND_IO;

	ret = dev_config(pcmcia, cs);
	if (ret)
		goto config_failed;

	if (card->dpram.size != 0x1000) {
		mod_alert("dpram size 0x%lx mismatch\n", card->dpram.size);
		goto wrong_dpram;
	}

	if (!mk_softing(card))
		return 0;
	/* else */
wrong_dpram:
	pcmcia_release_window(cs->win);
config_failed:
	kfree(cs);
no_mem:
	pcmcia_disable_device(pcmcia);
	return ret ? ret : EINVAL;
}

static struct pcmcia_device_id driver_ids[] = {
	/* softing */
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0001),
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0002),
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0004),
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0005),
	/* vector , manufacturer? */
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0081),
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0084),
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0085),
	/* EDIC */
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0102),
	PCMCIA_DEVICE_MANF_CARD(0x0168, 0x0105),
	PCMCIA_DEVICE_NULL,
};

MODULE_DEVICE_TABLE(pcmcia, driver_ids);

static struct pcmcia_driver softing_cs_driver = {
	.owner		= THIS_MODULE,
	.drv			= {
	.name		= "softing_cs",
	},
	.probe		= driver_probe,
	.remove		= driver_remove,
	.id_table	= driver_ids,
};

static int __init mod_start(void)
{
	mod_trace("");
	return pcmcia_register_driver(&softing_cs_driver);
}

static void __exit mod_stop(void)
{
	mod_trace("");
	pcmcia_unregister_driver(&softing_cs_driver);
}

module_init(mod_start);
module_exit(mod_stop);

MODULE_DESCRIPTION("softing CANcard driver"
		", links PCMCIA card to softing driver");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("softing CANcard2");

