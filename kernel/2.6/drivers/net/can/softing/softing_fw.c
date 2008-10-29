/*
* drivers/net/can/softing/softing_fw.c
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
#include <linux/init.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/io.h>

#include "softing.h"

#define fw_dir "softing-4.6/"

const struct can_bittiming_const softing_btr_const = {
	.tseg1_min = 1,
	.tseg1_max = 16,
	.tseg2_min = 1,
	.tseg2_max = 8,
	.sjw_max = 4, /* overruled */
	.brp_min = 1,
	.brp_max = 32, /* overruled */
	.brp_inc = 1,
};

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

/* never tested, but taken from original softing */
{	.name = "CAN-AC2-104",
	.manf = 0x0000, .prod = 0x009,
	.generation = 1,
	.freq = 25, .max_brp = 64, .max_sjw = 4,
	.dpram_size = 0x1000,
	.boot = {0x0000, 0x000000, fw_dir "boot104.bin",},
	.load = {0x0800, 0x035000, fw_dir "ld104.bin",},
	.app = {0x0010, 0x120000, fw_dir "canpc104.bin",},
	},
{0, 0,},
};

const struct softing_desc *softing_lookup_desc
					(unsigned int manf, unsigned int prod)
{
	const struct softing_desc *lp = carddescs;
	for (; lp->name; ++lp) {
		if ((lp->manf == manf) && (lp->prod == prod))
			return lp;
	}
	return 0;
}
EXPORT_SYMBOL(softing_lookup_desc);

int softing_fct_cmd(struct softing *card, int cmd, int vector, const char *msg)
{
	int ret;
	unsigned long stamp;
	if (vector == RES_OK)
		vector = RES_NONE;
	card->dpram.fct->param[0] = cmd;
	card->dpram.fct->host_access = vector;
	/* be sure to flush this to the card */
	wmb();
	stamp = jiffies;
	/*wait for card */
	do {
		ret = card->dpram.fct->host_access;
		/* don't have any cached variables */
		rmb();
		if (ret == RES_OK) {
			/*don't read return-value now */
			ret = card->dpram.fct->returned;
			if (ret)
				mod_alert("%s returned %u", msg, ret);
			return 0;
		}
		if ((jiffies - stamp) >= 1 * HZ)
			break;
		if (in_interrupt())
			/* go as fast as possible */
			continue;
		/* process context => relax */
		schedule();
	} while (!signal_pending(current));

	if (ret == RES_NONE) {
		mod_alert("%s, no response from card on %u/0x%02x"
			, msg, cmd, vector);
		return 1;
	} else {
		mod_alert("%s, bad response from card on %u/0x%02x, 0x%04x"
			, msg, cmd, vector, ret);
		/*make sure to return something not 0 */
		return ret ? ret : 1;
	}
}

int softing_bootloader_command(struct softing *card
		, int command, const char *msg)
{
	int ret;
	unsigned long stamp;
	card->dpram.receipt[0] = RES_NONE;
	card->dpram.command[0] = command;
	/* be sure to flush this to the card */
	wmb();
	stamp = jiffies;
	/*wait for card */
	do {
		ret = card->dpram.receipt[0];
		/* don't have any cached variables */
		rmb();
		if (ret == RES_OK)
			return 0;
		if ((jiffies - stamp) >= (3 * HZ))
			break;
		schedule();
	} while (!signal_pending(current));

	switch (ret) {
	case RES_NONE:
		mod_alert("%s: no response from card", msg);
		break;
	case RES_NOK:
		mod_alert("%s: response from card nok", msg);
		break;
	case RES_UNKNOWN:
		mod_alert("%s: command 0x%04x unknown", msg, command);
		break;
	default:
		mod_alert("%s: bad response from card (%u)]", msg, ret);
		break;
	}
	return ret ? ret : 1;
}

struct fw_hdr {
	u16 type;
	u32 addr;
	u16 len;
	u16 checksum;
	const unsigned char *base;
} __attribute__ ((packed));

static int fw_parse(const unsigned char **pmem, struct fw_hdr *hdr)
{
	u16 tmp;
	const unsigned char *mem;
	const unsigned char *end;
	mem = *pmem;
	hdr->type = (mem[0] << 0) | (mem[1] << 8);
	hdr->addr = (mem[2] << 0) | (mem[3] << 8)
		 | (mem[4] << 16) | (mem[5] << 24);
	hdr->len = (mem[6] << 0) | (mem[7] << 8);
	hdr->base = &mem[8];
	hdr->checksum =
		 (hdr->base[hdr->len] << 0) | (hdr->base[hdr->len + 1] << 8);
	for (tmp = 0, mem = *pmem, end = &hdr->base[hdr->len]; mem < end; ++mem)
		tmp += *mem;
	if (tmp != hdr->checksum)
		return EINVAL;
	*pmem += 10 + hdr->len;
	return 0;
}

int softing_load_fw(const char *file, struct softing *card,
			unsigned char *virt, unsigned int size, int offset)
{
	const struct firmware *fw;
	const unsigned char *mem;
	const unsigned char *end;
	int ret;
	u32 start_addr;
	struct fw_hdr rec;
	int ok = 0;
	unsigned char buf[256];

	ret = request_firmware(&fw, file, card->dev);
	if (ret) {
		mod_alert("request_firmware(%s) got %i", file, ret);
		return ret;
	}
	mod_trace("%s, firmware(%s) got %u bytes, offset %c0x%04x"
			, card->id.name, file, (unsigned int)fw->size,
		  (offset >= 0) ? '+' : '-', abs(offset));
	/* parse the firmware */
	mem = fw->data;
	end = &mem[fw->size];
	/* look for header record */
	if (fw_parse(&mem, &rec))
		goto fw_end;
	if (rec.type != 0xffff) {
		mod_alert("firware starts with type 0x%04x", rec.type);
		goto fw_end;
	}
	if (strncmp("Structured Binary Format, Softing GmbH"
			, rec.base, rec.len)) {
		mod_info("firware string '%.*s'", rec.len, rec.base);
		goto fw_end;
	}
	ok |= 1;
	/* ok, we had a header */
	while (mem < end) {
		if (fw_parse(&mem, &rec))
			break;
		if (rec.type == 3) {
			/*start address */
			start_addr = rec.addr;
			ok |= 2;
			continue;
		} else if (rec.type == 1) {
			/*eof */
			ok |= 4;
			goto fw_end;
		} else if (rec.type != 0) {
			mod_alert("unknown record type 0x%04x", rec.type);
			break;
		}

		if ((rec.addr + rec.len + offset) > size) {
			mod_alert("firmware out of range (0x%08x / 0x%08x)"
			, (rec.addr + rec.len + offset), size);
			goto fw_end;
		}
		memcpy_toio(&virt[rec.addr + offset],
				 rec.base, rec.len);
		/* be sure to flush caches from IO space */
		mb();
		if (rec.len > sizeof(buf)) {
			mod_info("record is big (%u bytes), not verifying"
				, rec.len);
			continue;
		}
		/* verify record data */
		memcpy_fromio(buf, &virt[rec.addr + offset], rec.len);
		if (!memcmp(buf, rec.base, rec.len))
			/* is ok */
			continue;
		mod_alert("0x%08x:0x%03x at 0x%p failed", rec.addr, rec.len
			, &virt[rec.addr + offset]);
		goto fw_end;
	}
fw_end:
	release_firmware(fw);
	if (0x5 == (ok & 0x5)) {
		/*got eof & start */
		return 0;
	}
	mod_alert("failed");
	return EINVAL;
}

int softing_load_app_fw(const char *file, struct softing *card)
{
	const struct firmware *fw;
	const unsigned char *mem;
	const unsigned char *end;
	int ret;
	struct fw_hdr rec;
	int ok = 0;
	u32 start_addr = 0;
	u16 rx_sum;
	unsigned int sum;
	const unsigned char *mem_lp;
	const unsigned char *mem_end;
	struct cpy {
		u32 src;
		u32 dst;
		u16 len;
		u8 do_cs;
	} __attribute__((packed)) *pcpy =
		 (struct cpy *)&card->dpram.command[1];

	ret = request_firmware(&fw, file, card->dev);
	if (ret) {
		mod_alert("request_firmware(%s) got %i", file, ret);
		return ret;
	}
	mod_trace("%s, firmware(%s) got %lu bytes", card->id.name, file,
		  (unsigned long)fw->size);
	/* parse the firmware */
	mem = fw->data;
	end = &mem[fw->size];
	/* look for header record */
	if (fw_parse(&mem, &rec))
		goto fw_end;
	if (rec.type != 0xffff) {
		mod_alert("firware starts with type 0x%04x", rec.type);
		goto fw_end;
	}
	if (strncmp("Structured Binary Format, Softing GmbH"
		, rec.base, rec.len)) {
		mod_info("firware string '%.*s'", rec.len, rec.base);
		goto fw_end;
	}
	ok |= 1;
	/* ok, we had a header */
	while (mem < end) {
		if (fw_parse(&mem, &rec))
			break;

		if (rec.type == 3) {
			/*start address */
			start_addr = rec.addr;
			ok |= 2;
			continue;
		} else if (rec.type == 1) {
			/*eof */
			ok |= 4;
			goto fw_end;
		} else if (rec.type != 0) {
			mod_alert("unknown record type 0x%04x", rec.type);
			break;
		}
		/* regualar data */
		for (sum = 0, mem_lp = rec.base, mem_end = &mem_lp[rec.len];
			mem_lp < mem_end; ++mem_lp)
			sum += *mem_lp;

		memcpy_toio(&card->dpram. virt[card->desc->app.offs],
				 rec.base, rec.len);
		pcpy->src = card->desc->app.offs + card->desc->app.addr;
		pcpy->dst = rec.addr;
		pcpy->len = rec.len;
		pcpy->do_cs = 1;
		if (softing_bootloader_command(card, 1, "loading app."))
			goto fw_end;
		/*verify checksum */
		rx_sum = card->dpram.receipt[1];
		if (rx_sum != (sum & 0xffff)) {
			mod_alert("SRAM seems to be damaged"
				", wanted 0x%04x, got 0x%04x", sum, rx_sum);
			goto fw_end;
		}
	}
fw_end:
	release_firmware(fw);
	if (ok == 7) {
		/*got start, start_addr, & eof */
		struct cmd {
			u32 start;
			u8 autorestart;
		} *pcmd = (struct cmd *)&card->dpram.command[1];
		pcmd->start = start_addr;
		pcmd->autorestart = 1;
		if (!softing_bootloader_command(card, 3, "start app.")) {
			mod_trace("%s: card app. run at 0x%06x"
				, card->id.name, start_addr);
			return 0;
		}
	}
	mod_alert("failed");
	return EINVAL;
}

int softing_reset_chip(struct softing *card)
{
	mod_trace("%s", card->id.name);
	do {
		/*reset chip */
		card->dpram.info->reset_rcv_fifo = 0;
		card->dpram.info->reset = 1;
		if (!softing_fct_cmd(card, 0, 0, "reset_chip"))
			break;
		if (signal_pending(current))
			goto failed;
		/*sync */
		if (softing_fct_cmd(card, 99, 0x55, "sync-a"))
			goto failed;
		if (softing_fct_cmd(card, 99, 0xaa, "sync-a"))
			goto failed;
	} while (1);
	card->tx.pending = 0;
	return 0;
failed:
	return -EIO;
}

int softing_reinit(struct softing *card, int bus0, int bus1)
{
	int ret;
	int restarted_bus = -1;
	mod_trace("%s", card->id.name);
	if (!card->fw.up)
		return -EIO;
	if (bus0 < 0) {
		bus0 = (card->bus[0]->netdev->flags & IFF_UP) ? 1 : 0;
		if (bus0)
			restarted_bus = 0;
	} else if (bus1 < 0) {
		bus1 = (card->bus[1]->netdev->flags & IFF_UP) ? 1 : 0;
		if (bus1)
			restarted_bus = 1;
	}
	/* collect info */
	if (card->bus[0]) {
		card->bus[0]->can.state = CAN_STATE_STOPPED;
		softing_flush_echo_skb(card->bus[0]);
	}
	if (card->bus[1]) {
		card->bus[1]->can.state = CAN_STATE_STOPPED;
		softing_flush_echo_skb(card->bus[1]);
	}

	/* start acting */
	if (!bus0 && !bus1) {
		softing_card_irq(card, 0);
		softing_reset_chip(card);
		if (card->bus[0])
			netif_carrier_off(card->bus[0]->netdev);
		if (card->bus[1])
			netif_carrier_off(card->bus[1]->netdev);
		return 0;
	}
	ret = softing_reset_chip(card);
	if (ret) {
		softing_card_irq(card, 0);
		return ret;
	}
	if (bus0) {
		/*init chip */
		card->dpram.fct->param[1] = card->bus[0]->can.bittiming.brp;
		card->dpram.fct->param[2] = card->bus[0]->can.bittiming.sjw;
		card->dpram.fct->param[3] =
			 card->bus[0]->can.bittiming.phase_seg1 +
			 card->bus[0]->can.bittiming.prop_seg;
		card->dpram.fct->param[4] =
			 card->bus[0]->can.bittiming.phase_seg2;
		card->dpram.fct->param[5] = (card->bus[0]->can.ctrlmode &
					     CAN_CTRLMODE_3_SAMPLES)?1:0;
		if (softing_fct_cmd(card, 1, 0, "initialize_chip[0]"))
			goto failed;
		/*set mode */
		card->dpram.fct->param[1] = 0;
		card->dpram.fct->param[2] = 0;
		if (softing_fct_cmd(card, 3, 0, "set_mode[0]"))
			goto failed;
		/*set filter */
		card->dpram.fct->param[1] = 0x0000;/*card->bus[0].s.msg; */
		card->dpram.fct->param[2] = 0x07ff;/*card->bus[0].s.msk; */
		card->dpram.fct->param[3] = 0x0000;/*card->bus[0].l.msg; */
		card->dpram.fct->param[4] = 0xffff;/*card->bus[0].l.msk; */
		card->dpram.fct->param[5] = 0x0000;/*card->bus[0].l.msg >> 16;*/
		card->dpram.fct->param[6] = 0x1fff;/*card->bus[0].l.msk >> 16;*/
		if (softing_fct_cmd(card, 7, 0, "set_filter[0]"))
			goto failed;
		/*set output control */
		card->dpram.fct->param[1] = card->bus[0]->output;
		if (softing_fct_cmd(card, 5, 0, "set_output[0]"))
			goto failed;
	}
	if (bus1) {
		/*init chip2 */
		card->dpram.fct->param[1] = card->bus[1]->can.bittiming.brp;
		card->dpram.fct->param[2] = card->bus[1]->can.bittiming.sjw;
		card->dpram.fct->param[3] =
			 card->bus[1]->can.bittiming.phase_seg1 +
			 card->bus[1]->can.bittiming.prop_seg;
		card->dpram.fct->param[4] =
			 card->bus[1]->can.bittiming.phase_seg2;
		card->dpram.fct->param[5] = (card->bus[1]->can.ctrlmode &
					     CAN_CTRLMODE_3_SAMPLES)?1:0;
		if (softing_fct_cmd(card, 2, 0, "initialize_chip[1]"))
			goto failed;
		/*set mode2 */
		card->dpram.fct->param[1] = 0;
		card->dpram.fct->param[2] = 0;
		if (softing_fct_cmd(card, 4, 0, "set_mode[1]"))
			goto failed;
		/*set filter2 */
		card->dpram.fct->param[1] = 0x0000;/*card->bus[1].s.msg; */
		card->dpram.fct->param[2] = 0x07ff;/*card->bus[1].s.msk; */
		card->dpram.fct->param[3] = 0x0000;/*card->bus[1].l.msg; */
		card->dpram.fct->param[4] = 0xffff;/*card->bus[1].l.msk; */
		card->dpram.fct->param[5] = 0x0000;/*card->bus[1].l.msg >> 16;*/
		card->dpram.fct->param[6] = 0x1fff;/*card->bus[1].l.msk >> 16;*/
		if (softing_fct_cmd(card, 8, 0, "set_filter[1]"))
			goto failed;
		/*set output control2 */
		card->dpram.fct->param[1] = card->bus[1]->output;
		if (softing_fct_cmd(card, 6, 0, "set_output[1]"))
			goto failed;
	}
	/*set interrupt */
	/*enable_error_frame */
	if (softing_fct_cmd(card, 51, 0, "enable_error_frame"))
		goto failed;
	/*initialize interface */
	card->dpram.fct->param[1] = 1;
	card->dpram.fct->param[2] = 1;
	card->dpram.fct->param[3] = 1;
	card->dpram.fct->param[4] = 1;
	card->dpram.fct->param[5] = 1;
	card->dpram.fct->param[6] = 1;
	card->dpram.fct->param[7] = 1;
	card->dpram.fct->param[8] = 1;
	card->dpram.fct->param[9] = 1;
	card->dpram.fct->param[10] = 1;
	if (softing_fct_cmd(card, 17, 0, "initialize_interface"))
		goto failed;
	/*enable_fifo */
	if (softing_fct_cmd(card, 36, 0, "enable_fifo"))
		goto failed;
	/*enable fifo tx ack */
	if (softing_fct_cmd(card, 13, 0, "fifo_tx_ack[0]"))
		goto failed;
	/*enable fifo tx ack2 */
	if (softing_fct_cmd(card, 14, 0, "fifo_tx_ack[1]"))
		goto failed;
	/*enable timestamps */
	/*is default, no code found */
	/*start_chip */
	if (softing_fct_cmd(card, 11, 0, "start_chip"))
		goto failed;
	card->dpram.info->bus_state = 0;
	card->dpram.info->bus_state2 = 0;
	mod_info("ok for %s, %s/%s\n", card->bus[0]->netdev->name,
		 card->bus[1]->netdev->name, card->id.name);
	if (card->desc->generation < 2) {
		card->dpram.irq->to_host = 0;
		/* flush the DPRAM caches */
		wmb();
	}
	/*run once */
	/*the bottom halve will start flushing the tx-queue too */
	tasklet_schedule(&card->irq.bh);

	ret = softing_card_irq(card, 1);
	if (ret)
		goto failed;

	/*TODO: generate RESTARTED messages */

	if (card->bus[0] && bus0) {
		card->bus[0]->can.state = CAN_STATE_ACTIVE;
		netif_carrier_on(card->bus[0]->netdev);
	}
	if (card->bus[1] && bus1) {
		card->bus[1]->can.state = CAN_STATE_ACTIVE;
		netif_carrier_on(card->bus[1]->netdev);
	}
	return 0;
failed:
	softing_card_irq(card, 0);
	softing_reset_chip(card);
	if (card->bus[0])
		netif_carrier_off(card->bus[0]->netdev);
	if (card->bus[1])
		netif_carrier_off(card->bus[1]->netdev);
	return -EIO;
}


int softing_default_output(struct softing *card, struct softing_priv *priv)
{
	switch (priv->chip) {
	case 1000:
		if (card->desc->generation < 2)
			return 0xfb;
		return 0xfa;
	case 5:
		return 0x60;
	default:
		return 0x40;
	}
}

u32 softing_time2usec(struct softing *card, u32 raw)
{
	/*TODO : don't loose higher order bits in computation */
	switch (card->desc->freq) {
	case 20:
		return raw * 4 / 5;
	case 24:
		return raw * 2 / 3;
	case 25:
		return raw * 16 / 25;
	case 0:
	case 16:
	default:
		return raw;
	}
}


