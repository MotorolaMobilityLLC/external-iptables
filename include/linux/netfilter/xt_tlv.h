#ifndef _LINUX_NETFILTER_XT_TLV_H
#define _LINUX_NETFILTER_XT_TLV_H

#include <linux/types.h>

#define MAX_MATCH_DATA 128

struct xt_tlv_info {
	uint32_t token;
	/*  whether sending notification to userspace */
	uint32_t notify;
	/*  it's the all key data length of the red packet */
	uint16_t data_len;
	/*  the number of the entry */
	uint16_t entries;
	/*  the data of the entries */
	uint8_t entries_data[MAX_MATCH_DATA];
};

#endif /* _LINUX_NETFILTER_XT_TLV_H */
