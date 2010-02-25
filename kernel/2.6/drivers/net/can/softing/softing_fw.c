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
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <asm/div64.h>

#include "softing.h"

static const struct softing_desc carddescs[] = {
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

MODULE_FIRMWARE(fw_dir "boot104.bin");
MODULE_FIRMWARE(fw_dir "ld104.bin");
MODULE_FIRMWARE(fw_dir "canpc104.bin");

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
				dev_alert(card->dev,
					"%s returned %u\n", msg, ret);
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
		dev_alert(card->dev,
			"%s, no response from card on %u/0x%02x\n",
			msg, cmd, vector);
		return 1;
	} else {
		dev_alert(card->dev,
			"%s, bad response from card on %u/0x%02x, 0x%04x\n",
			msg, cmd, vector, ret);
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
		dev_alert(card->dev, "%s: no response from card\n", msg);
		break;
	case RES_NOK:
		dev_alert(card->dev, "%s: response from card nok\n", msg);
		break;
	case RES_UNKNOWN:
		dev_alert(card->dev, "%s: command 0x%04x unknown\n",
			msg, command);
		break;
	default:
		dev_alert(card->dev, "%s: bad response from card (%u)]\n",
			msg, ret);
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
	unsigned char buf[1024];

	ret = request_firmware(&fw, file, card->dev);
	if (ret) {
		dev_alert(card->dev, "request_firmware(%s) got %i\n",
			file, ret);
		return ret;
	}
	dev_dbg(card->dev, "%s, firmware(%s) got %u bytes"
		", offset %c0x%04x\n",
		card->id.name, file, (unsigned int)fw->size,
		(offset >= 0) ? '+' : '-', (unsigned int)abs(offset));
	/* parse the firmware */
	mem = fw->data;
	end = &mem[fw->size];
	/* look for header record */
	if (fw_parse(&mem, &rec))
		goto fw_end;
	if (rec.type != 0xffff) {
		dev_alert(card->dev, "firware starts with type 0x%04x\n",
			rec.type);
		goto fw_end;
	}
	if (strncmp("Structured Binary Format, Softing GmbH"
			, rec.base, rec.len)) {
		dev_info(card->dev, "firware string '%.*s'\n",
			rec.len, rec.base);
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
			dev_alert(card->dev, "unknown record type 0x%04x\n",
				rec.type);
			break;
		}

		if ((rec.addr + rec.len + offset) > size) {
			dev_alert(card->dev,
				"firmware out of range (0x%08x / 0x%08x)\n",
				(rec.addr + rec.len + offset), size);
			goto fw_end;
		}
		memcpy_toio(&virt[rec.addr + offset],
				 rec.base, rec.len);
		/* be sure to flush caches from IO space */
		mb();
		if (rec.len > sizeof(buf)) {
			dev_info(card->dev,
				"record is big (%u bytes), not verifying\n",
				rec.len);
			continue;
		}
		/* verify record data */
		memcpy_fromio(buf, &virt[rec.addr + offset], rec.len);
		if (!memcmp(buf, rec.base, rec.len))
			/* is ok */
			continue;
		dev_alert(card->dev, "0x%08x:0x%03x at 0x%p failed\n",
			rec.addr, rec.len, &virt[rec.addr + offset]);
		goto fw_end;
	}
fw_end:
	release_firmware(fw);
	if (0x5 == (ok & 0x5)) {
		/*got eof & start */
		return 0;
	}
	dev_info(card->dev, "firmware %s failed\n", file);
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
	struct cmd {
		u32 start;
		u8 autorestart;
	} __attribute__((packed)) *pcmdstart =
		(struct cmd *)&card->dpram.command[1];

	ret = request_firmware(&fw, file, card->dev);
	if (ret) {
		dev_alert(card->dev, "request_firmware(%s) got %i\n",
			file, ret);
		return ret;
	}
	dev_dbg(card->dev, "%s, firmware(%s) got %lu bytes\n",
		card->id.name, file, (unsigned long)fw->size);
	/* parse the firmware */
	mem = fw->data;
	end = &mem[fw->size];
	/* look for header record */
	if (fw_parse(&mem, &rec))
		goto fw_end;
	if (rec.type != 0xffff) {
		dev_alert(card->dev, "firware starts with type 0x%04x\n",
			rec.type);
		goto fw_end;
	}
	if (strncmp("Structured Binary Format, Softing GmbH"
		, rec.base, rec.len)) {
		dev_alert(card->dev, "firware string '%.*s' fault\n",
			rec.len, rec.base);
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
			dev_alert(card->dev, "unknown record type 0x%04x\n",
				rec.type);
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
			dev_alert(card->dev, "SRAM seems to be damaged"
				", wanted 0x%04x, got 0x%04x\n", sum, rx_sum);
			goto fw_end;
		}
	}
fw_end:
	release_firmware(fw);
	if (ok != 7)
		goto fw_failed;
	/*got start, start_addr, & eof */
	pcmdstart->start = start_addr;
	pcmdstart->autorestart = 1;
	if (softing_bootloader_command(card, 3, "start app."))
		goto fw_failed;
	dev_info(card->dev, "firmware %s up\n", file);
	return 0;
fw_failed:
	dev_info(card->dev, "firmware %s failed\n", file);
	return EINVAL;
}

int softing_reset_chip(struct softing *card)
{
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

static void softing_initialize_timestamp(struct softing *card)
{
	uint64_t ovf;

	card->ts_ref = ktime_get();

	/* 16MHz is the reference */
	ovf = 0x100000000ULL * 16;
	do_div(ovf, card->desc->freq ?: 16);

	card->ts_overflow = ktime_add_us(ktime_set(0, 0), ovf);
}

ktime_t softing_raw2ktime(struct softing *card, u32 raw)
{
	uint64_t rawl;
	ktime_t now, real_offset;
	ktime_t target;
	ktime_t tmp;

	now = ktime_get();
	real_offset = ktime_sub(ktime_get_real(), now);

	/* find nsec from card */
	rawl = raw * 16;
	do_div(rawl, card->desc->freq ?: 16);
	target = ktime_add_us(card->ts_ref, rawl);
	/* test for overflows */
	tmp = ktime_add(target, card->ts_overflow);
	while (unlikely(ktime_to_ns(tmp) > ktime_to_ns(now))) {
		card->ts_ref = ktime_add(card->ts_ref, card->ts_overflow);
		target = tmp;
		tmp = ktime_add(target, card->ts_overflow);
	}
	return ktime_add(target, real_offset);
}

int softing_cycle(struct softing *card, struct softing_priv *bus, int up)
{
	int ret;
	struct softing_priv *pbus;
	int mask_start;
	int j;
	struct can_frame msg;

	if (!card->fw.up)
		return -EIO;

	ret = mutex_lock_interruptible(&card->fw.lock);
	if (ret)
		return ret;
	if (card->fw.failed)
		goto failed_already;

	mask_start = 0;
	/* bring netdevs down */
	for (j = 0; j < card->nbus; ++j) {
		pbus = card->bus[j];
		if (!pbus)
			continue;

		if (bus != pbus)
			netif_stop_queue(pbus->netdev);

		if ((bus != pbus) && netif_running(pbus->netdev))
			mask_start |= (1 << j);
		if (netif_running(pbus->netdev)) {
			pbus->tx.pending = 0;
			pbus->tx.echo_put = 0;
			pbus->tx.echo_get = 0;
			/* this bus' may just have called open_candev()
			 * which is rather stupid to call close_candev()
			 * already
			 * but we may come here from busoff recovery too
			 * in which case the echo_skb _needs_ flushing too.
			 * just be sure to call open_candev() again
			 */
			close_candev(pbus->netdev);
		}
		pbus->can.state = CAN_STATE_STOPPED;
	}
	card->tx.pending = 0;
	if (bus && up)
		/* prepare to start this bus as well */
		mask_start |= (1 << bus->index);

	softing_card_irq(card, 0);
	ret = softing_reset_chip(card);
	if (ret)
		goto failed;
	if (!mask_start)
		/* no busses to be brought up */
		goto card_done;

	/* from here, we must jump to failed: */

	if (mask_start & 1) {
		pbus = card->bus[0];
		/*init chip 1 */
		card->dpram.fct->param[1] = pbus->can.bittiming.brp;
		card->dpram.fct->param[2] = pbus->can.bittiming.sjw;
		card->dpram.fct->param[3] =
			pbus->can.bittiming.phase_seg1 +
			pbus->can.bittiming.prop_seg;
		card->dpram.fct->param[4] =
			pbus->can.bittiming.phase_seg2;
		card->dpram.fct->param[5] = (pbus->can.ctrlmode &
			CAN_CTRLMODE_3_SAMPLES) ? 1 : 0;
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
		card->dpram.fct->param[1] = pbus->output;
		if (softing_fct_cmd(card, 5, 0, "set_output[0]"))
			goto failed;
	}
	if (mask_start & 2) {
		pbus = card->bus[1];
		/*init chip2 */
		card->dpram.fct->param[1] = pbus->can.bittiming.brp;
		card->dpram.fct->param[2] = pbus->can.bittiming.sjw;
		card->dpram.fct->param[3] =
			pbus->can.bittiming.phase_seg1 +
			pbus->can.bittiming.prop_seg;
		card->dpram.fct->param[4] =
			pbus->can.bittiming.phase_seg2;
		card->dpram.fct->param[5] = (pbus->can.ctrlmode &
			CAN_CTRLMODE_3_SAMPLES) ? 1 : 0;
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
		card->dpram.fct->param[1] = pbus->output;
		if (softing_fct_cmd(card, 6, 0, "set_output[1]"))
			goto failed;
	}
	/*enable_error_frame */
	/*
	if (softing_fct_cmd(card, 51, 0, "enable_error_frame"))
		goto failed;
	*/
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
	dev_info(card->dev, "ok for %s, %s/%s\n",
		card->bus[0]->netdev->name, card->bus[1]->netdev->name,
		card->id.name);
	if (card->desc->generation < 2) {
		card->dpram.irq->to_host = 0;
		/* flush the DPRAM caches */
		wmb();
	}

	softing_initialize_timestamp(card);

	/*
	 * do socketcan notifications/status changes
	 * from here, no errors should occur, or the failed: part
	 * must be reviewed
	 */
	memset(&msg, 0, sizeof(msg));
	msg.can_id = CAN_ERR_FLAG | CAN_ERR_RESTARTED;
	msg.can_dlc = CAN_ERR_DLC;
	for (j = 0; j < card->nbus; ++j) {
		pbus = card->bus[j];
		if (!pbus)
			continue;
		if (!(mask_start & (1 << j)))
			continue;
		pbus->can.state = CAN_STATE_ERROR_ACTIVE;
		open_candev(pbus->netdev);
		if (bus != pbus) {
			/* notify other busses on the restart */
			softing_rx(pbus->netdev, &msg, ktime_set(0, 0));
			++pbus->can.can_stats.restarts;
		}
		netif_wake_queue(pbus->netdev);
	}

	/* enable interrupts */
	ret = softing_card_irq(card, 1);
	if (ret)
		goto failed;
card_done:
	mutex_unlock(&card->fw.lock);
	return 0;
failed:
	dev_alert(card->dev, "firmware failed, going idle\n");
	softing_card_irq(card, 0);
	softing_reset_chip(card);
	card->fw.failed = 1;
	mutex_unlock(&card->fw.lock);
	/* bring all other interfaces down */
	for (j = 0; j < card->nbus; ++j) {
		pbus = card->bus[j];
		if (!pbus)
			continue;
		dev_close(pbus->netdev);
	}
	return -EIO;

failed_already:
	mutex_unlock(&card->fw.lock);
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

