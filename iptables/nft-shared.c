/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Tomasz Bursztyka <tomasz.bursztyka@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <errno.h>

#include <xtables.h>

#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>

#include "nft-shared.h"
#include "xshared.h"

extern struct nft_family_ops nft_family_ops_ipv4;
extern struct nft_family_ops nft_family_ops_ipv6;

void add_meta(struct nft_rule *r, uint32_t key)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("meta");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_META_KEY, key);
	nft_rule_expr_set_u32(expr, NFT_EXPR_META_DREG, NFT_REG_1);

	nft_rule_add_expr(r, expr);
}

void add_payload(struct nft_rule *r, int offset, int len)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("payload");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_BASE,
			      NFT_PAYLOAD_NETWORK_HEADER);
	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_DREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_OFFSET, offset);
	nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_LEN, len);

	nft_rule_add_expr(r, expr);
}

/* bitwise operation is = sreg & mask ^ xor */
void add_bitwise_u16(struct nft_rule *r, int mask, int xor)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("bitwise");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_SREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_DREG, NFT_REG_1);
	nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_LEN, sizeof(uint16_t));
	nft_rule_expr_set(expr, NFT_EXPR_BITWISE_MASK, &mask, sizeof(uint16_t));
	nft_rule_expr_set(expr, NFT_EXPR_BITWISE_XOR, &xor, sizeof(uint16_t));

	nft_rule_add_expr(r, expr);
}

void add_cmp_ptr(struct nft_rule *r, uint32_t op, void *data, size_t len)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("cmp");
	if (expr == NULL)
		return;

	nft_rule_expr_set_u8(expr, NFT_EXPR_CMP_SREG, NFT_REG_1);
	nft_rule_expr_set_u8(expr, NFT_EXPR_CMP_OP, op);
	nft_rule_expr_set(expr, NFT_EXPR_CMP_DATA, data, len);

	nft_rule_add_expr(r, expr);
}

void add_cmp_u8(struct nft_rule *r, uint8_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

void add_cmp_u16(struct nft_rule *r, uint16_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

void add_cmp_u32(struct nft_rule *r, uint32_t val, uint32_t op)
{
	add_cmp_ptr(r, op, &val, sizeof(val));
}

void add_iniface(struct nft_rule *r, char *iface, int invflags)
{
	int iface_len;
	uint32_t op;

	iface_len = strlen(iface);

	if (invflags & IPT_INV_VIA_IN)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	if (iface[iface_len - 1] == '+') {
		add_meta(r, NFT_META_IIFNAME);
		add_cmp_ptr(r, op, iface, iface_len - 1);
	} else {
		add_meta(r, NFT_META_IIF);
		add_cmp_u32(r, if_nametoindex(iface), op);
	}
}

void add_outiface(struct nft_rule *r, char *iface, int invflags)
{
	int iface_len;
	uint32_t op;

	iface_len = strlen(iface);

	if (invflags & IPT_INV_VIA_OUT)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	if (iface[iface_len - 1] == '+') {
		add_meta(r, NFT_META_OIFNAME);
		add_cmp_ptr(r, op, iface, iface_len - 1);
	} else {
		add_meta(r, NFT_META_OIF);
		add_cmp_u32(r, if_nametoindex(iface), op);
	}
}

void add_addr(struct nft_rule *r, int offset,
	      void *data, size_t len, int invflags)
{
	uint32_t op;

	add_payload(r, offset, len);

	if (invflags & IPT_INV_SRCIP || invflags & IPT_INV_DSTIP)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	add_cmp_ptr(r, op, data, len);
}

void add_proto(struct nft_rule *r, int offset, size_t len,
	       uint8_t proto, int invflags)
{
	uint32_t op;

	add_payload(r, offset, len);

	if (invflags & XT_INV_PROTO)
		op = NFT_CMP_NEQ;
	else
		op = NFT_CMP_EQ;

	add_cmp_u8(r, proto, op);
}

bool is_same_interfaces(const char *a_iniface, const char *a_outiface,
			unsigned const char *a_iniface_mask,
			unsigned const char *a_outiface_mask,
			const char *b_iniface, const char *b_outiface,
			unsigned const char *b_iniface_mask,
			unsigned const char *b_outiface_mask)
{
	int i;

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a_iniface_mask[i] != b_iniface_mask[i]) {
			DEBUGP("different iniface mask %x, %x (%d)\n",
			a_iniface_mask[i] & 0xff, b_iniface_mask[i] & 0xff, i);
			return false;
		}
		if ((a_iniface[i] & a_iniface_mask[i])
		    != (b_iniface[i] & b_iniface_mask[i])) {
			DEBUGP("different iniface\n");
			return false;
		}
		if (a_outiface_mask[i] != b_outiface_mask[i]) {
			DEBUGP("different outiface mask\n");
			return false;
		}
		if ((a_outiface[i] & a_outiface_mask[i])
		    != (b_outiface[i] & b_outiface_mask[i])) {
			DEBUGP("different outiface\n");
			return false;
		}
	}

	return true;
}

void parse_meta(struct nft_rule_expr *e, uint8_t key, char *iniface,
		unsigned char *iniface_mask, char *outiface,
		unsigned char *outiface_mask, uint8_t *invflags)
{
	uint32_t value;
	const void *ifname;
	size_t len;

	switch(key) {
	case NFT_META_IIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_IN;

		if_indextoname(value, iniface);

		memset(iniface_mask, 0xff, strlen(iniface)+1);
		break;
	case NFT_META_OIF:
		value = nft_rule_expr_get_u32(e, NFT_EXPR_CMP_DATA);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		if_indextoname(value, outiface);

		memset(outiface_mask, 0xff, strlen(outiface)+1);
		break;
	case NFT_META_IIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_IN;

		memcpy(iniface, ifname, len);
		iniface[len] = '\0';

		/* If zero, then this is an interface mask */
		if (if_nametoindex(iniface) == 0) {
			iniface[len] = '+';
			iniface[len+1] = '\0';
		}

		memset(iniface_mask, 0xff, len);
		break;
	case NFT_META_OIFNAME:
		ifname = nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len);
		if (nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP) == NFT_CMP_NEQ)
			*invflags |= IPT_INV_VIA_OUT;

		memcpy(outiface, ifname, len);
		outiface[len] = '\0';

		/* If zero, then this is an interface mask */
		if (if_nametoindex(outiface) == 0) {
			outiface[len] = '+';
			outiface[len+1] = '\0';
		}

		memset(outiface_mask, 0xff, len);
		break;
	default:
		DEBUGP("unknown meta key %d\n", key);
		break;
	}
}

static void
nft_parse_target(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		 struct iptables_command_state *cs)
{
	size_t tg_len;
	const char *targname = nft_rule_expr_get_str(e, NFT_EXPR_TG_NAME);
	const void *targinfo = nft_rule_expr_get(e, NFT_EXPR_TG_INFO, &tg_len);
	struct xtables_target *target;
	struct xt_entry_target *t;

	target = xtables_find_target(targname, XTF_TRY_LOAD);
	if (target == NULL)
		return;

	t = calloc(1, sizeof(struct xt_entry_target) + tg_len);
	if (t == NULL) {
		fprintf(stderr, "OOM");
		exit(EXIT_FAILURE);
	}
	memcpy(&t->data, targinfo, tg_len);
	t->u.target_size = tg_len + XT_ALIGN(sizeof(struct xt_entry_target));
	t->u.user.revision = nft_rule_expr_get_u32(e, NFT_EXPR_TG_REV);
	strcpy(t->u.user.name, target->name);

	target->t = t;
	cs->target = target;
}

static void
nft_parse_match(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		struct iptables_command_state *cs)
{
	size_t mt_len;
	const char *mt_name = nft_rule_expr_get_str(e, NFT_EXPR_MT_NAME);
	const void *mt_info = nft_rule_expr_get(e, NFT_EXPR_MT_INFO, &mt_len);
	struct xtables_match *match;
	struct xt_entry_match *m;

	match = xtables_find_match(mt_name, XTF_TRY_LOAD, &cs->matches);
	if (match == NULL)
		return;

	m = calloc(1, sizeof(struct xt_entry_match) + mt_len);
	if (m == NULL) {
		fprintf(stderr, "OOM");
		exit(EXIT_FAILURE);
	}

	memcpy(&m->data, mt_info, mt_len);
	m->u.match_size = mt_len + XT_ALIGN(sizeof(struct xt_entry_match));
	m->u.user.revision = nft_rule_expr_get_u32(e, NFT_EXPR_TG_REV);
	strcpy(m->u.user.name, match->name);

	match->m = m;
}

void print_proto(uint16_t proto, int invert)
{
	const struct protoent *pent = getprotobynumber(proto);

	if (invert)
		printf("! ");

	if (pent) {
		printf("-p %s ", pent->p_name);
		return;
	}

	printf("-p %u ", proto);
}

void get_cmp_data(struct nft_rule_expr_iter *iter,
		  void *data, size_t dlen, bool *inv)
{
	struct nft_rule_expr *e;
	const char *name;
	size_t len;
	uint8_t op;

	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	if (strcmp(name, "cmp") != 0) {
		DEBUGP("skipping no cmp after meta\n");
		return;
	}

	memcpy(data, nft_rule_expr_get(e, NFT_EXPR_CMP_DATA, &len), dlen);
	op = nft_rule_expr_get_u8(e, NFT_EXPR_CMP_OP);
	if (op == NFT_CMP_NEQ)
		*inv = true;
	else
		*inv = false;
}

static void
nft_parse_meta(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
	       int family, struct iptables_command_state *cs)
{
	uint8_t key = nft_rule_expr_get_u8(e, NFT_EXPR_META_KEY);
	struct nft_family_ops *ops = nft_family_ops_lookup(family);
	const char *name;

	e = nft_rule_expr_iter_next(iter);
	if (e == NULL)
		return;

	name = nft_rule_expr_get_str(e, NFT_RULE_EXPR_ATTR_NAME);
	if (strcmp(name, "cmp") != 0) {
		DEBUGP("skipping no cmp after meta\n");
		return;
	}

	ops->parse_meta(e, key, cs);
}

static void
nft_parse_payload(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  int family, struct iptables_command_state *cs)
{
	struct nft_family_ops *ops = nft_family_ops_lookup(family);
	uint32_t offset;

	offset = nft_rule_expr_get_u32(e, NFT_EXPR_PAYLOAD_OFFSET);

	ops->parse_payload(iter, cs, offset);
}

static void
nft_parse_counter(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		  struct xt_counters *counters)
{
	counters->pcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_PACKETS);
	counters->bcnt = nft_rule_expr_get_u64(e, NFT_EXPR_CTR_BYTES);
}

static void
nft_parse_immediate(struct nft_rule_expr *e, struct nft_rule_expr_iter *iter,
		    int family, struct iptables_command_state *cs)
{
	int verdict = nft_rule_expr_get_u32(e, NFT_EXPR_IMM_VERDICT);
	const char *chain = nft_rule_expr_get_str(e, NFT_EXPR_IMM_CHAIN);
	struct nft_family_ops *ops;

	/* Standard target? */
	switch(verdict) {
	case NF_ACCEPT:
		cs->jumpto = "ACCEPT";
		return;
	case NF_DROP:
		cs->jumpto = "DROP";
		return;
	case NFT_RETURN:
		cs->jumpto = "RETURN";
		return;
	case NFT_GOTO:
		ops = nft_family_ops_lookup(family);
		ops->parse_immediate(cs);
	case NFT_JUMP:
		cs->jumpto = chain;
		return;
	}
}

void nft_rule_to_iptables_command_state(struct nft_rule *r,
					struct iptables_command_state *cs)
{
	struct nft_rule_expr_iter *iter;
	struct nft_rule_expr *expr;
	int family = nft_rule_attr_get_u8(r, NFT_RULE_ATTR_FAMILY);

	iter = nft_rule_expr_iter_create(r);
	if (iter == NULL)
		return;

	expr = nft_rule_expr_iter_next(iter);
	while (expr != NULL) {
		const char *name =
			nft_rule_expr_get_str(expr, NFT_RULE_EXPR_ATTR_NAME);

		if (strcmp(name, "counter") == 0)
			nft_parse_counter(expr, iter, &cs->counters);
		else if (strcmp(name, "payload") == 0)
			nft_parse_payload(expr, iter, family, cs);
		else if (strcmp(name, "meta") == 0)
			nft_parse_meta(expr, iter, family, cs);
		else if (strcmp(name, "immediate") == 0)
			nft_parse_immediate(expr, iter, family, cs);
		else if (strcmp(name, "match") == 0)
			nft_parse_match(expr, iter, cs);
		else if (strcmp(name, "target") == 0)
			nft_parse_target(expr, iter, cs);

		expr = nft_rule_expr_iter_next(iter);
	}

	nft_rule_expr_iter_destroy(iter);

	if (cs->target != NULL)
		cs->jumpto = cs->target->name;
	else if (cs->jumpto != NULL)
		cs->target = xtables_find_target(cs->jumpto, XTF_TRY_LOAD);
	else
		cs->jumpto = "";
}

void print_num(uint64_t number, unsigned int format)
{
	if (format & FMT_KILOMEGAGIGA) {
		if (number > 99999) {
			number = (number + 500) / 1000;
			if (number > 9999) {
				number = (number + 500) / 1000;
				if (number > 9999) {
					number = (number + 500) / 1000;
					if (number > 9999) {
						number = (number + 500) / 1000;
						printf(FMT("%4lluT ","%lluT "), (unsigned long long)number);
					}
					else printf(FMT("%4lluG ","%lluG "), (unsigned long long)number);
				}
				else printf(FMT("%4lluM ","%lluM "), (unsigned long long)number);
			} else
				printf(FMT("%4lluK ","%lluK "), (unsigned long long)number);
		} else
			printf(FMT("%5llu ","%llu "), (unsigned long long)number);
	} else
		printf(FMT("%8llu ","%llu "), (unsigned long long)number);
}

void print_firewall_details(const struct iptables_command_state *cs,
			    const char *targname, uint8_t flags,
			    uint8_t invflags, uint8_t proto,
			    const char *iniface, const char *outiface,
			    unsigned int num, unsigned int format)
{
	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(cs->counters.pcnt, format);
		print_num(cs->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname ? targname : "");

	fputc(invflags & XT_INV_PROTO ? '!' : ' ', stdout);
	{
		const char *pname =
			proto_to_name(proto, format&FMT_NUMERIC);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(invflags & IPT_INV_FRAG ? '!' : '-', stdout);
		fputc(flags & IPT_F_FRAG ? 'f' : '-', stdout);
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];
		if (invflags & IPT_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (iniface[0] != '\0') {
			strcat(iface, iniface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (invflags & IPT_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (outiface[0] != '\0') {
			strcat(iface, outiface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}
}

static void
print_iface(char letter, const char *iface, const unsigned char *mask, int inv)
{
	unsigned int i;

	if (mask[0] == 0)
		return;

	printf("%s-%c ", inv ? "! " : "", letter);

	for (i = 0; i < IFNAMSIZ; i++) {
		if (mask[i] != 0) {
			if (iface[i] != '\0')
				printf("%c", iface[i]);
			} else {
				if (iface[i-1] != '\0')
					printf("+");
				break;
		}
	}

	printf(" ");
}

void save_firewall_details(const struct iptables_command_state *cs,
			   uint8_t invflags, uint16_t proto,
			   const char *iniface,
			   unsigned const char *iniface_mask,
			   const char *outiface,
			   unsigned const char *outiface_mask,
			   unsigned int format)
{
	if (!(format & FMT_NOCOUNTS)) {
		printf("-c ");
		print_num(cs->counters.pcnt, format);
		print_num(cs->counters.bcnt, format);
	}

	if (iniface != NULL) {
		print_iface('i', iniface, iniface_mask,
			    invflags & IPT_INV_VIA_IN);
	}
	if (outiface != NULL) {
		print_iface('o', outiface, outiface_mask,
			    invflags & IPT_INV_VIA_OUT);
	}

	if (proto > 0) {
		const struct protoent *pent = getprotobynumber(proto);

		if (invflags & XT_INV_PROTO)
			printf("! ");

		if (pent)
			printf("-p %s ", pent->p_name);
		else
			printf("-p %u ", proto);
	}
}

void print_matches_and_target(struct iptables_command_state *cs,
			      unsigned int format)
{
	struct xtables_rule_match *matchp;

	for (matchp = cs->matches; matchp; matchp = matchp->next) {
		if (matchp->match->print != NULL) {
			matchp->match->print(NULL, matchp->match->m,
					     format & FMT_NUMERIC);
		}
	}

	if (cs->target != NULL) {
		if (cs->target->print != NULL) {
			cs->target->print(NULL, cs->target->t,
					  format & FMT_NUMERIC);
		}
	}
}

struct nft_family_ops *nft_family_ops_lookup(int family)
{
	switch (family) {
	case AF_INET:
		return &nft_family_ops_ipv4;
	case AF_INET6:
		return &nft_family_ops_ipv6;
	default:
		break;
	}

	return NULL;
}

