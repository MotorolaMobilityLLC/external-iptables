#ifndef _XT_RATEEST_TARGET_H
#define _XT_RATEEST_TARGET_H

struct xt_rateest_target_info {
	char			name[IFNAMSIZ];
	signed char		interval;
	unsigned char		ewma_log;
	struct xt_rateest	*est __attribute__((aligned(8)));
};

#endif /* _XT_RATEEST_TARGET_H */
