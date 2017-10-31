#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_tlv.h>

#define ENTRY_HEADER_SIZE 3

enum {
	RANGE_TAG = 0,
	DATA_TAG
};

enum {
	O_TOKEN = 0,
	O_NOTIFY,
	O_TLV_DATA
};

union xt_tlv_entry {
	struct __entry_hdr {
		uint32_t tag;
		uint32_t len;
		uint32_t offset;
	} entry_hdr_st;
	uint32_t entry_hdr[ENTRY_HEADER_SIZE];
};

static void tlv_init(struct xt_entry_match *match)
{
	struct xt_tlv_info *info = (struct xt_tlv_info *)match->data;
	info->token = 0xffffffff;
	info->notify = 0;
}

static void tlv_mt_help(void)
{
	printf( "tlv match options:\n"
		"  --token the token of the data parsed\n"
		"  --notify send notify or NFLOG message\n"
		"  --tlv-data the tlv data should be matched\n");
}

static const struct xt_option_entry tlv_mt_opts[] = {
	{.name = "token", .id = O_TOKEN, .type = XTTYPE_UINT32,
		.flags = XTOPT_PUT, XTOPT_POINTER(struct xt_tlv_info, token)},
	{.name = "notify", .id = O_NOTIFY, .type = XTTYPE_UINT32,
		.flags = XTOPT_PUT, XTOPT_POINTER(struct xt_tlv_info, notify)},
	{.name = "tlv-data", .id = O_TLV_DATA, .type = XTTYPE_STRING,
		.flags = XTOPT_MAND},
	XTOPT_TABLEEND,
};

static void char2hex(const uint8_t *src, uint8_t *dst, int len) {
	int i = 0;
	uint8_t byte = 0;

	for (i = 0; i < len; i += 2) {
		if (src[i] >= '0' && src[i] <= '9') {
			byte = src[i] - '0';
		} else if (src[i] >= 'a' && src[i] <= 'f') {
			byte = src[i] - 'a' + 0x0a;
		} else if (src[i] >= 'A' && src[i] <= 'F') {

			byte = src[i] - 'A' + 0x0a;
		} else {
			continue;
		}
		*dst = (byte << 4) & 0xf0;

		if (src[i + 1] >= '0' && src[i + 1] <= '9') {
			byte = src[i + 1] - '0';
		} else if (src[i + 1] >= 'a' && src[i + 1] <= 'f') {
			byte = src[i + 1] - 'a' + 0x0a;
		} else if (src[i + 1] >= 'A' && src[i + 1] <= 'F') {
			byte = src[i + 1] - 'A' + 0x0a;
		} else {
			continue;
		}
		*dst++ |= byte & 0x0f;
	}
}

/*  parse the given string and construct one or more xt_tlv_entry(s).
 *  then pass the header and body of xt_tlv_entry to kernel with
 *  info->entries_data.
 *  1. parse the tlv header: the tag type, length, and offset;
 *  2. parse the tlv body:
 *       RANGE_TAG: the min and max value of the field matched;
 *       DATA_TAG:  Hex format, must be the same with the field
 *                  concerned, including byte-order.
 *
 * Example:
 * The below string is the data rule we set, it have 2 types of data:
 *
 *  "0,4,0,0x41d,0x48d,1,16,4,001000010000007a0000000000000001"
 *
 *  (1) RANGE_TAG
 *      0       4       0       0x41d       0x48d
 *  range tag  len    offset     min         max
 *
 *  (2) DATA_TAG
 *      1       16      4       001000010000007a0000000000000001
 *  data tag   len    offset    data
 *
 *  The data as below will be matched:
 *  0000045d 00100001 0000007a 00000000 00000001
 *  or
 *  0000047d 00100001 0000007a 00000000 00000001
 */
static void parse_match_data(struct xt_tlv_info *info,
			     const char *match_data_str) {
	char *buf, *cp, *next;
	uint16_t i,j;
	uint16_t offset = 0;
	uint32_t match_data;
	union xt_tlv_entry entry;
	int match_data_len = strlen(match_data_str);
	int bytes_left = 0;

	buf = strdup(match_data_str);
	if (!buf)
		xtables_error(OTHER_PROBLEM, "strdup failed");

	info->entries = 0;
	for (cp = buf, i = 0; cp && i < match_data_len;) {
		// parse the entry tag, length and offset
		for (j = 0; j < ENTRY_HEADER_SIZE; j++) {
			next = strchr(cp, ',');
			if (next) {
				*next++='\0';
				i += next - cp;
			} else {
				goto error_exit;
			}
			if (!xtables_strtoui(cp, NULL,
					     entry.entry_hdr + j,
					     0, UINT32_MAX - 1)) {
				goto error_exit;
			}
			cp = next;
		}

		if (offset + sizeof(entry) > MAX_MATCH_DATA)
			goto error_exit;

		memcpy(info->entries_data + offset,
		       (void*)&entry, sizeof(entry));
		offset += sizeof(entry);
		info->data_len += entry.entry_hdr_st.len;
		info->entries++;

		switch (entry.entry_hdr_st.tag) {
		case RANGE_TAG:
			// parse the ranges value of the range tag
			for (j = 0; j < 2; j++) {
				next = strchr(cp, ',');
				if (next) {
					*next++='\0';
					i += next - cp;
				} else {
					bytes_left = match_data_len - i;
					if(strlen(cp) != bytes_left) {
						goto error_exit;
					}
					i += bytes_left;
				}

				if (!xtables_strtoui(cp, NULL,
						     &match_data,
						     0, UINT32_MAX - 1)) {
					goto error_exit;
				}

				cp = next;
				if (offset + sizeof(match_data) > MAX_MATCH_DATA)
					goto error_exit;

				memcpy(info->entries_data + offset,
				       (void*)&match_data, sizeof(match_data));
				offset += sizeof(match_data);
			}
			break;
		case DATA_TAG:
			// parse the data of the data tag
			next = strchr(cp, ',');
			if (next) {
				*next++='\0';
				i += next - cp;
			} else {
				bytes_left = match_data_len - i;
				if (bytes_left != (entry.entry_hdr_st.len << 1)) {
					goto error_exit;
				}
				i += bytes_left;
			}
			if (offset + entry.entry_hdr_st.len > MAX_MATCH_DATA) {
				xtables_param_act(XTF_BAD_VALUE, "tlv", "--tlv-data, len:", offset + entry.entry_hdr_st.len);
				goto error_exit;
			}
			char2hex((const uint8_t *)cp,
				 info->entries_data + offset,
				 entry.entry_hdr_st.len << 1);
			offset += entry.entry_hdr_st.len;
			break;
		default:
			break;
		}
	}
	free(buf);
	return;
error_exit:
	free(buf);
	xtables_param_act(XTF_BAD_VALUE, "tlv", "--tlv-data", cp);
}

static void tlv_mt_parse(struct xt_option_call *cb)
{
	struct xt_tlv_info *info = cb->data;
	xtables_option_parse(cb);

	switch (cb->entry->id) {
		case O_TLV_DATA:
			if (cb->arg != NULL) {
				parse_match_data(info, cb->arg);
			}
			break;
	}
}

static void tlv_mt_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM,
			      "tlv match: '--token', '--notify' and '--tlv-data' are required\n");
}

static void tlv_mt_print(const void *ip, const struct xt_entry_match *match,
		int numeric)
{
	const struct xt_tlv_info *info = (const void*)match->data;
	printf(" --token:%d", info->token);
	printf(" --notify:%d", info->notify);
	printf(" --tlv-data len:%d entries:%d\n",
			info->data_len, info->entries);
}

static void tlv_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tlv_info *info = (const void*)match->data;
	printf(" --token:%d", info->token);
	printf(" --notify:%d", info->notify);
	printf(" --tlv-data len:%d entries:%d\n",
			info->data_len, info->entries);
}

static struct xtables_match tlv_mt_reg[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = "tlv",
		.revision      = 1,
		.family        = NFPROTO_IPV4,
		.size          = XT_ALIGN(sizeof(struct xt_tlv_info)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_tlv_info)),
		.init          = tlv_init,
		.help          = tlv_mt_help,
		.x6_parse      = tlv_mt_parse,
		.x6_fcheck     = tlv_mt_check,
		.print         = tlv_mt_print,
		.save          = tlv_mt_save,
		.x6_options    = tlv_mt_opts,
	},
	{
		.version       = XTABLES_VERSION,
		.name          = "tlv",
		.revision      = 1,
		.family        = NFPROTO_IPV6,
		.size          = XT_ALIGN(sizeof(struct xt_tlv_info)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_tlv_info)),
		.init          = tlv_init,
		.help          = tlv_mt_help,
		.x6_parse      = tlv_mt_parse,
		.x6_fcheck     = tlv_mt_check,
		.print         = tlv_mt_print,
		.save          = tlv_mt_save,
		.x6_options    = tlv_mt_opts,
	},
};

void _init(void)
{
	xtables_register_matches(tlv_mt_reg, ARRAY_SIZE(tlv_mt_reg));
}
