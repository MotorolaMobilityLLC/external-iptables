#ifndef _XT_NFLOG_TARGET
#define _XT_NFLOG_TARGET

#include <linux/types.h>

#define XT_NFLOG_DEFAULT_GROUP		0x1
#define XT_NFLOG_DEFAULT_THRESHOLD	0

#define NF_LOG_ALL                  0x00 //copy network plus trasnport plus app data
#define NF_LOG_NETWORK_ONLY         0x01 //only copy network data
#define NF_LOG_NETWORK_TRANSPORT    0x02 //copy network plus transport
#define NF_LOG_TRANSPORT_ONLY       0x03 //only copy transport data
#define NF_LOG_TRANSPORT_APP        0x04 //copy transport plus app data
#define NF_LOG_APP_ONLY             0x05 //only copy app data
#define NF_LOG_DEFAULT_LAYER        NF_LOG_ALL

#define XT_NFLOG_MASK			0x1

/* This flag indicates that 'len' field in xt_nflog_info is set*/
#define XT_NFLOG_F_COPY_LEN		0x1

struct xt_nflog_info {
	/* 'len' will be used iff you set XT_NFLOG_F_COPY_LEN in flags */
	__u32	len;
	__u16	group;
	__u16	threshold;
	__u16	flags;
	__u16	pad;
	char		prefix[64];
};

struct xt_nflog_info_v1 {
	/* 'len' will be used iff you set XT_NFLOG_F_COPY_LEN in flags */
	__u32	len;
	__u16	group;
	__u16	threshold;
	__u16	flags;
	__u16	pad;
	char		prefix[64];
	__u16   layer;
};

#endif /* _XT_NFLOG_TARGET */
