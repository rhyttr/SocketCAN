#ifndef _CAN_SJA1000_PLATFORM_H_
#define _CAN_SJA1000_PLATFORM_H_

struct sja1000_platform_data {
	u32 clock;	/* CAN bus oscillator frequency in Hz */

	u8 ocr;		/* output control register */
	u8 cdr;		/* clock divider register */
};

#endif	/* !_CAN_SJA1000_PLATFORM_H_ */
