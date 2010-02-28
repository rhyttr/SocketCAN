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
#include <linux/version.h>
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
	struct softing	 softing;
	win_req_t win;
};
#define softing2cs(x) container_of((x), struct softing_cs, softing)

/* card descriptions */
static const struct softing_desc carddescs[] = {
{
	.name = "CANcard",
	.manf = 0x0168, .prod = 0x001,
	.generation = 1,
	.freq = 16, .max_brp = 32, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cancard.bin",},
}, {
	.name = "CANcard-NEC",
	.manf = 0x0168, .prod = 0x002,
	.generation = 1,
	.freq = 16, .max_brp = 32, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cancard.bin",},
}, {
	.name = "CANcard-SJA",
	.manf = 0x0168, .prod = 0x004,
	.generation = 1,
	.freq = 20, .max_brp = 32, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cansja.bin",},
}, {
	.name = "CANcard-2",
	.manf = 0x0168, .prod = 0x005,
	.generation = 2,
	.freq = 24, .max_brp = 64, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard2.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard2.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cancrd2.bin",},
}, {
	.name = "Vector-CANcard",
	.manf = 0x0168, .prod = 0x081,
	.generation = 1,
	.freq = 16, .max_brp = 64, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cancard.bin",},
}, {
	.name = "Vector-CANcard-SJA",
	.manf = 0x0168, .prod = 0x084,
	.generation = 1,
	.freq = 20, .max_brp = 32, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cansja.bin",},
}, {
	.name = "Vector-CANcard-2",
	.manf = 0x0168, .prod = 0x085,
	.generation = 2,
	.freq = 24, .max_brp = 64, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard2.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard2.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cancrd2.bin",},
}, {
	.name = "EDICcard-NEC",
	.manf = 0x0168, .prod = 0x102,
	.generation = 1,
	.freq = 16, .max_brp = 64, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cancard.bin",},
}, {
	.name = "EDICcard-2",
	.manf = 0x0168, .prod = 0x105,
	.generation = 2,
	.freq = 24, .max_brp = 64, .max_sjw = 4,
	.dpram_size = 0x0800,
	.boot = {0x0000, 0x000000, fw_dir "bcard2.bin",},
	.load = {0x0120, 0x00f600, fw_dir "ldcard2.bin",},
	.app = {0x0010, 0x0d0000, fw_dir "cancrd2.bin",},
	},
{0, 0,},
};

MODULE_FIRMWARE(fw_dir "bcard.bin");
MODULE_FIRMWARE(fw_dir "ldcard.bin");
MODULE_FIRMWARE(fw_dir "cancard.bin");
MODULE_FIRMWARE(fw_dir "cansja.bin");

MODULE_FIRMWARE(fw_dir "bcard2.bin");
MODULE_FIRMWARE(fw_dir "ldcard2.bin");
MODULE_FIRMWARE(fw_dir "cancrd2.bin");

static const struct softing_desc *softing_cs_lookup_desc
					(unsigned int manf, unsigned int prod)
{
	const struct softing_desc *lp = carddescs;
	for (; lp->name; ++lp) {
		if ((lp->manf == manf) && (lp->prod == prod))
			return lp;
	}
	return 0;
}


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
		dev_alert(&pcmcia->dev, "failed %u\n", ret);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
/* backported */
struct pcmcia_cfg_mem {
	tuple_t tuple;
	cisparse_t parse;
	u8 buf[256];
	cistpl_cftable_entry_t dflt;
};
static int pcmcia_loop_config(struct pcmcia_device *p_dev,
		       int	(*conf_check)	(struct pcmcia_device *p_dev,
						 cistpl_cftable_entry_t *cfg,
						 cistpl_cftable_entry_t *dflt,
						 unsigned int vcc,
						 void *priv_data),
		       void *priv_data)
{
	struct pcmcia_cfg_mem *cfg_mem;

	tuple_t *tuple;
	int ret = -ENODEV;
	unsigned int vcc;

	cfg_mem = kzalloc(sizeof(*cfg_mem), GFP_KERNEL);
	if (cfg_mem == NULL)
		return -ENOMEM;

	/* get the current Vcc setting */
	vcc = p_dev->socket->socket.Vcc;

	tuple = &cfg_mem->tuple;
	tuple->TupleData = cfg_mem->buf;
	tuple->TupleDataMax = sizeof(cfg_mem->buf)-1;
	tuple->TupleOffset = 0;
	tuple->DesiredTuple = CISTPL_CFTABLE_ENTRY;
	tuple->Attributes = 0;

	ret = pcmcia_get_first_tuple(p_dev, tuple);
	while (!ret) {
		cistpl_cftable_entry_t *cfg = &cfg_mem->parse.cftable_entry;

		if (pcmcia_get_tuple_data(p_dev, tuple))
			goto next_entry;

		if (pcmcia_parse_tuple(p_dev, tuple, &cfg_mem->parse))
			goto next_entry;

		/* default values */
		p_dev->conf.ConfigIndex = cfg->index;
		if (cfg->flags & CISTPL_CFTABLE_DEFAULT)
			cfg_mem->dflt = *cfg;

		ret = conf_check(p_dev, cfg, &cfg_mem->dflt, vcc, priv_data);
		if (!ret)
			break;

next_entry:
		ret = pcmcia_get_next_tuple(p_dev, tuple);
	}
	kfree(cfg_mem);
	return ret;
}
#endif

static int dev_conf_check(struct pcmcia_device *pdev,
	cistpl_cftable_entry_t *cf, cistpl_cftable_entry_t *def_cf,
	unsigned int vcc, void *priv_data)
{
	struct softing_cs *csdev = priv_data;
	struct softing *sdev = &csdev->softing;
	int ret;

	if (!cf->index)
		goto do_next;
	/* power settings (Vcc & Vpp) */
	if (cf->vcc.present & (1 << CISTPL_POWER_VNOM)) {
		if (vcc != cf->vcc.param[CISTPL_POWER_VNOM]/10000) {
			dev_alert(&pdev->dev, "cf->Vcc mismatch\n");
			goto do_next;
		}
	} else if (def_cf->vcc.present & (1 << CISTPL_POWER_VNOM)) {
		if (vcc != def_cf->vcc.param[CISTPL_POWER_VNOM]/10000) {
			dev_alert(&pdev->dev, "cf->Vcc mismatch\n");
			goto do_next;
		}
	}
	if (cf->vpp1.present & (1 << CISTPL_POWER_VNOM))
		pdev->conf.Vpp
			= cf->vpp1.param[CISTPL_POWER_VNOM] / 10000;

	else if (def_cf->vpp1.present & (1 << CISTPL_POWER_VNOM))
		pdev->conf.Vpp
			= def_cf->vpp1.param[CISTPL_POWER_VNOM] / 10000;

	/* interrupt ? */
	if (cf->irq.IRQInfo1 || def_cf->irq.IRQInfo1)
		pdev->conf.Attributes |= CONF_ENABLE_IRQ;

	/* IO window */
	pdev->io.NumPorts1
		= pdev->io.NumPorts2
		= 0;
	/* Memory window */
	if ((cf->mem.nwin > 0) || (def_cf->mem.nwin > 0)) {
		memreq_t map;
		cistpl_mem_t *mem
			= (cf->mem.nwin) ? &cf->mem : &def_cf->mem;
		/* softing specific: choose 8 or 16bit access */
		csdev->win.Attributes = ((sdev->desc->generation >= 2)
				? WIN_DATA_WIDTH_16 : WIN_DATA_WIDTH_8)
			| WIN_MEMORY_TYPE_CM
			| WIN_ENABLE;
		csdev->win.Base = mem->win[0].host_addr;
		csdev->win.Size = mem->win[0].len;
		csdev->win.AccessSpeed = 0;
		/* softing specific: choose slower access for old cards */
		if (sdev->desc->generation < 2) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
			pdev->win->ctl.flags
				= MAP_ACTIVE | MAP_USE_WAIT;
			pdev->win->ctl.speed = 3;
#else
			csdev->win.Attributes |= WIN_USE_WAIT;
			csdev->win.AccessSpeed = 3;
#endif
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		ret = pcmcia_request_window(&pdev, &csdev->win, &pdev->win);
#else
		ret = pcmcia_request_window(pdev, &csdev->win, &pdev->win);
#endif
		if (ret) {
			dev_alert(&pdev->dev,
				"pcmcia_request_window() mismatch\n");
			goto do_next;
		}
		map.Page = 0;
		map.CardOffset = mem->win[0].card_addr;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		if (pcmcia_map_mem_page(pdev->win, &map)) {
#else
		if (pcmcia_map_mem_page(pdev, pdev->win, &map)) {
#endif
			dev_alert(&pdev->dev,
				"pcmcia_map_mem_page() mismatch\n");
			goto do_next_win;
		}
	} else {
		dev_info(&pdev->dev, "no memory window in tuple %u\n",
			cf->index);
		goto do_next;
	}
	return 0;
do_next_win:
do_next:
	pcmcia_disable_device(pdev);
	return -ENODEV;
}

static void driver_remove(struct pcmcia_device *pcmcia)
{
	struct softing *card = (struct softing *)pcmcia->priv;
	struct softing_cs *cs = softing2cs(card);
	dev_dbg(&pcmcia->dev, "%s, device '%s'\n"
		, card->id.name, pcmcia->devname);
	rm_softing(card);
	/* release pcmcia stuff */
	pcmcia_disable_device(pcmcia);
	/* free bits */
	kfree(cs);
}

static int __devinit driver_probe(struct pcmcia_device *pcmcia)
{
	struct softing_cs *cs;
	struct softing *card;
	char *str;
	char line[1024]; /* possible memory corruption */

	dev_dbg(&pcmcia->dev, "on %s\n", pcmcia->devname);

	/* Create new softing device */
	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		goto no_mem;
	/* setup links */
	card = &cs->softing;
	pcmcia->priv = card;
	card->dev = &pcmcia->dev;
	/* properties */
	card->id.manf = pcmcia->manf_id;
	card->id.prod = pcmcia->card_id;
	card->desc = softing_cs_lookup_desc(card->id.manf, card->id.prod);
	if (!card->desc) {
		dev_alert(&pcmcia->dev, "unknown card\n");
		goto description_failed;
	}
	if (card->desc->generation >= 2) {
		card->fn.reset = card_reset_via_dpram;
	} else {
		card->fn.reset = card_reset_via_pcmcia;
		card->fn.enable_irq = card_enable_irq_via_pcmcia;
	}

	card->nbus = 2;
	/* pcmcia presets */
	pcmcia->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	pcmcia->irq.IRQInfo1 = IRQ_LEVEL_ID;
#endif
	pcmcia->irq.Handler	= 0;
	pcmcia->conf.Attributes = 0;
	pcmcia->conf.IntType = INT_MEMORY_AND_IO;

	if (pcmcia_loop_config(pcmcia, dev_conf_check, cs))
		goto config_failed;

	if (pcmcia_request_irq(pcmcia, &pcmcia->irq))
		goto config_failed;

	if (pcmcia_request_configuration(pcmcia, &pcmcia->conf))
		goto config_failed;

	card->dpram.phys = cs->win.Base;
	card->dpram.size = cs->win.Size;

	if (card->dpram.size != 0x1000) {
		dev_alert(&pcmcia->dev, "dpram size 0x%lx mismatch\n",
			card->dpram.size);
		goto wrong_dpram;
	}

	/* Finally, report what we've done */
	str = line;
	str += sprintf(str, "config index %u", pcmcia->conf.ConfigIndex);
	if (pcmcia->conf.Vpp)
		str += sprintf(str, ", Vpp %d.%d",
			pcmcia->conf.Vpp/10, pcmcia->conf.Vpp%10);
	if (pcmcia->conf.Attributes & CONF_ENABLE_IRQ) {
		str += sprintf(str, ", irq %d", pcmcia->irq.AssignedIRQ);
		card->irq.nr = pcmcia->irq.AssignedIRQ;
	}

	if (pcmcia->win) {
		int tmp;
		const char *p;
		str += sprintf(str, ", mem 0x%08lx-0x%08lx"
			, card->dpram.phys
			, card->dpram.phys + card->dpram.size-1);
		tmp = cs->win.Attributes;
		while (tmp) {
			p = lookup_mask(pcmcia_mem_attr, &tmp);
			if (!p)
				continue;
			str += sprintf(str, " %s", p);
		}
	}
	dev_info(&pcmcia->dev, "%s\n", line);

	if (mk_softing(card))
		goto softing_failed;
	return 0;

softing_failed:
wrong_dpram:
config_failed:
description_failed:
	kfree(cs);
no_mem:
	pcmcia_disable_device(pcmcia);
	return -ENODEV;
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
	return pcmcia_register_driver(&softing_cs_driver);
}

static void __exit mod_stop(void)
{
	pcmcia_unregister_driver(&softing_cs_driver);
}

module_init(mod_start);
module_exit(mod_stop);

MODULE_DESCRIPTION("softing CANcard driver"
		", links PCMCIA card to softing driver");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("softing CANcard2");

