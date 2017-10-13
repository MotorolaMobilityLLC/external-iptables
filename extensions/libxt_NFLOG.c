#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <xtables.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_NFLOG.h>

enum {
	O_GROUP = 0,
	O_LAYER,
	O_PREFIX,
	O_RANGE,
	O_SIZE,
	O_THRESHOLD,
	F_RANGE = 1 << O_RANGE,
	F_SIZE = 1 << O_SIZE,
};

#define s struct xt_nflog_info
static const struct xt_option_entry NFLOG_opts[] = {
	{.name = "nflog-group", .id = O_GROUP, .type = XTTYPE_UINT16,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, group)},
	{.name = "nflog-prefix", .id = O_PREFIX, .type = XTTYPE_STRING,
	 .min = 1, .flags = XTOPT_PUT, XTOPT_POINTER(s, prefix)},
	{.name = "nflog-range", .id = O_RANGE, .type = XTTYPE_UINT32,
	 .excl = F_SIZE, .flags = XTOPT_PUT, XTOPT_POINTER(s, len)},
	{.name = "nflog-size", .id = O_SIZE, .type = XTTYPE_UINT32,
	 .excl = F_RANGE, .flags = XTOPT_PUT, XTOPT_POINTER(s, len)},
	{.name = "nflog-threshold", .id = O_THRESHOLD, .type = XTTYPE_UINT16,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, threshold)},
	XTOPT_TABLEEND,
};
#undef s

#define s struct xt_nflog_info_v1
static const struct xt_option_entry NFLOG_opts_v1[] = {
	{.name = "nflog-group", .id = O_GROUP, .type = XTTYPE_UINT16,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, group)},
	{.name = "nflog-prefix", .id = O_PREFIX, .type = XTTYPE_STRING,
	 .min = 1, .flags = XTOPT_PUT, XTOPT_POINTER(s, prefix)},
	{.name = "nflog-range", .id = O_RANGE, .type = XTTYPE_UINT32,
	 .excl = F_SIZE, .flags = XTOPT_PUT, XTOPT_POINTER(s, len)},
	{.name = "nflog-size", .id = O_SIZE, .type = XTTYPE_UINT32,
	 .excl = F_RANGE, .flags = XTOPT_PUT, XTOPT_POINTER(s, len)},
	{.name = "nflog-threshold", .id = O_THRESHOLD, .type = XTTYPE_UINT16,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, threshold)},
	{.name = "nflog-layer", .id = O_LAYER, .type = XTTYPE_UINT16,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, layer)},
	XTOPT_TABLEEND,
};
#undef s

static void NFLOG_help(void)
{
	printf("NFLOG target options:\n"
	       " --nflog-group NUM		NETLINK group used for logging\n"
	       " --nflog-range NUM		This option has no effect, use --nflog-size\n"
	       " --nflog-size NUM		Number of bytes to copy\n"
	       " --nflog-threshold NUM		Message threshold of in-kernel queue\n"
	       " --nflog-prefix STRING		Prefix string for log messages\n");
}

static void NFLOG_help_v1(void)
{
	printf("NFLOG target options:\n"
	       " --nflog-group NUM		NETLINK group used for logging\n"
	       " --nflog-range NUM		This option has no effect, use --nflog-size\n"
	       " --nflog-size NUM		Number of bytes to copy\n"
	       " --nflog-threshold NUM		Message threshold of in-kernel queue\n"
	       " --nflog-prefix STRING		Prefix string for log messages\n"
	       " --nflog-layer NUM		Layer index for getting payload\n"
	       " 0: all\n"
	       " 1: ip header only\n"
	       " 2: ip header and transport header\n"
	       " 3: transport header only\n"
	       " 4: transport header and application data\n"
	       " 5: application data only\n");
}

static void NFLOG_init(struct xt_entry_target *t)
{
	struct xt_nflog_info *info = (struct xt_nflog_info *)t->data;

	info->threshold	= XT_NFLOG_DEFAULT_THRESHOLD;
}

static void NFLOG_init_v1(struct xt_entry_target *t)
{
	struct xt_nflog_info_v1 *info = (struct xt_nflog_info_v1 *)t->data;

	info->threshold	= XT_NFLOG_DEFAULT_THRESHOLD;
	info->layer	= NF_LOG_DEFAULT_LAYER;
}

static void NFLOG_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_PREFIX:
		if (strchr(cb->arg, '\n') != NULL)
			xtables_error(PARAMETER_PROBLEM,
				   "Newlines not allowed in --log-prefix");
		break;
	}
}

static void NFLOG_check(struct xt_fcheck_call *cb)
{
	struct xt_nflog_info *info = cb->data;

	if (cb->xflags & F_RANGE)
		fprintf(stderr, "warn: --nflog-range has never worked and is no"
			" longer supported, please use --nflog-size insted\n");

	if (cb->xflags & F_SIZE)
		info->flags |= XT_NFLOG_F_COPY_LEN;
}

static void NFLOG_check_v1(struct xt_fcheck_call *cb)
{
	struct xt_nflog_info_v1 *info = cb->data;

	if (cb->xflags & F_RANGE)
		fprintf(stderr, "warn: --nflog-range has never worked and is no"
			" longer supported, please use --nflog-size insted\n");

	if (cb->xflags & F_SIZE)
		info->flags |= XT_NFLOG_F_COPY_LEN;

	if (info->layer < 0 || info->layer > 5)
		fprintf(stderr, "warn: --nflog-layer param value out of range, "
				" 0 - 5 supported\n");
}

static void nflog_print(const struct xt_nflog_info *info, char *prefix)
{
	if (info->prefix[0] != '\0') {
		printf(" %snflog-prefix ", prefix);
		xtables_save_string(info->prefix);
	}
	if (info->group)
		printf(" %snflog-group %u", prefix, info->group);
	if (info->flags & XT_NFLOG_F_COPY_LEN)
		printf(" %snflog-size %u", prefix, info->len);
	else if (info->len)
		printf(" %snflog-range %u", prefix, info->len);
	if (info->threshold != XT_NFLOG_DEFAULT_THRESHOLD)
		printf(" %snflog-threshold %u", prefix, info->threshold);
}

static void nflog_print_v1(const struct xt_nflog_info_v1 *info, char *prefix)
{
	if (info->prefix[0] != '\0') {
		printf(" %snflog-prefix ", prefix);
		xtables_save_string(info->prefix);
	}
	if (info->group)
		printf(" %snflog-group %u", prefix, info->group);
	if (info->flags & XT_NFLOG_F_COPY_LEN)
		printf(" %snflog-size %u", prefix, info->len);
	else if (info->len)
		printf(" %snflog-range %u", prefix, info->len);
	if (info->threshold != XT_NFLOG_DEFAULT_THRESHOLD)
		printf(" %snflog-threshold %u", prefix, info->threshold);
	if (info->layer != NF_LOG_DEFAULT_LAYER)
		printf(" %snflog-layer %u", prefix, info->layer);
}

static void NFLOG_print(const void *ip, const struct xt_entry_target *target,
			int numeric)
{
	const struct xt_nflog_info *info = (struct xt_nflog_info *)target->data;

	nflog_print(info, "");
}

static void NFLOG_print_v1(const void *ip, const struct xt_entry_target *target,
			int numeric)
{
	const struct xt_nflog_info_v1 *info = (struct xt_nflog_info_v1 *)target->data;

	nflog_print_v1(info, "");
}

static void NFLOG_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_nflog_info *info = (struct xt_nflog_info *)target->data;

	nflog_print(info, "--");
}

static void NFLOG_save_v1(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_nflog_info_v1 *info = (struct xt_nflog_info_v1 *)target->data;

	nflog_print_v1(info, "--");
}

static void nflog_print_xlate(const struct xt_nflog_info *info,
			      struct xt_xlate *xl, bool escape_quotes)
{
	xt_xlate_add(xl, "log ");
	if (info->prefix[0] != '\0') {
		if (escape_quotes)
			xt_xlate_add(xl, "prefix \\\"%s\\\" ", info->prefix);
		else
			xt_xlate_add(xl, "prefix \"%s\" ", info->prefix);

	}
	if (info->flags & XT_NFLOG_F_COPY_LEN)
		xt_xlate_add(xl, "snaplen %u ", info->len);
	if (info->threshold != XT_NFLOG_DEFAULT_THRESHOLD)
		xt_xlate_add(xl, "queue-threshold %u ", info->threshold);
	xt_xlate_add(xl, "group %u ", info->group);
}

static void nflog_print_xlate_v1(const struct xt_nflog_info_v1 *info,
			      struct xt_xlate *xl, bool escape_quotes)
{
	xt_xlate_add(xl, "log ");
	if (info->prefix[0] != '\0') {
		if (escape_quotes)
			xt_xlate_add(xl, "prefix \\\"%s\\\" ", info->prefix);
		else
			xt_xlate_add(xl, "prefix \"%s\" ", info->prefix);

	}
	if (info->flags & XT_NFLOG_F_COPY_LEN)
		xt_xlate_add(xl, "snaplen %u ", info->len);
	if (info->threshold != XT_NFLOG_DEFAULT_THRESHOLD)
		xt_xlate_add(xl, "queue-threshold %u ", info->threshold);
	if (info->layer != NF_LOG_DEFAULT_LAYER)
		xt_xlate_add(xl, "nflog-layer %u ", info->layer);
	xt_xlate_add(xl, "group %u ", info->group);
}

static int NFLOG_xlate(struct xt_xlate *xl,
		       const struct xt_xlate_tg_params *params)
{
	const struct xt_nflog_info *info =
		(struct xt_nflog_info *)params->target->data;

	nflog_print_xlate(info, xl, params->escape_quotes);

	return 1;
}

static int NFLOG_xlate_v1(struct xt_xlate *xl,
		       const struct xt_xlate_tg_params *params)
{
	const struct xt_nflog_info_v1 *info =
		(struct xt_nflog_info_v1 *)params->target->data;

	nflog_print_xlate_v1(info, xl, params->escape_quotes);

	return 1;
}

static struct xtables_target nflog_targets[] = {
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "NFLOG",
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_nflog_info)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_nflog_info)),
		.help		= NFLOG_help,
		.init		= NFLOG_init,
		.x6_fcheck	= NFLOG_check,
		.x6_parse	= NFLOG_parse,
		.print		= NFLOG_print,
		.save		= NFLOG_save,
		.x6_options	= NFLOG_opts,
		.xlate		= NFLOG_xlate,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "NFLOG",
		.version	= XTABLES_VERSION,
		.revision	= 1,
		.size		= XT_ALIGN(sizeof(struct xt_nflog_info_v1)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_nflog_info_v1)),
		.help		= NFLOG_help_v1,
		.init		= NFLOG_init_v1,
		.x6_fcheck	= NFLOG_check_v1,
		.x6_parse	= NFLOG_parse,
		.print		= NFLOG_print_v1,
		.save		= NFLOG_save_v1,
		.x6_options	= NFLOG_opts_v1,
		.xlate		= NFLOG_xlate_v1,
	}
};

void _init(void)
{
	xtables_register_targets(nflog_targets, ARRAY_SIZE(nflog_targets));
}
