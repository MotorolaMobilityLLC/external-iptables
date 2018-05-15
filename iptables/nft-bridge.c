/*
 * (C) 2014 by Giuseppe Longo <giuseppelng@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <inttypes.h>

#include <xtables.h>
#include <libiptc/libxtc.h>
#include <linux/netfilter/nf_tables.h>
#include <ebtables/ethernetdb.h>

#include "nft-shared.h"
#include "nft-bridge.h"
#include "nft.h"

void ebt_cs_clean(struct iptables_command_state *cs)
{
	struct ebt_match *m, *nm;

	xtables_rule_matches_free(&cs->matches);

	for (m = cs->match_list; m;) {
		nm = m->next;
		if (!m->ismatch)
			free(m->u.watcher->t);
		free(m);
		m = nm;
	}
}

/* 0: default, print only 2 digits if necessary
 * 2: always print 2 digits, a printed mac address
 * then always has the same length
 */
int ebt_printstyle_mac;

static void ebt_print_mac(const unsigned char *mac)
{
	if (ebt_printstyle_mac == 2) {
		int j;
		for (j = 0; j < ETH_ALEN; j++)
			printf("%02x%s", mac[j],
				(j==ETH_ALEN-1) ? "" : ":");
	} else
		printf("%s", ether_ntoa((struct ether_addr *) mac));
}

static bool mac_all_ones(const unsigned char *mac)
{
	static const char hlpmsk[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	return memcmp(mac, hlpmsk, sizeof(hlpmsk)) == 0;
}

/* Put the mac address into 6 (ETH_ALEN) bytes returns 0 on success. */
static void ebt_print_mac_and_mask(const unsigned char *mac, const unsigned char *mask)
{

	if (!memcmp(mac, eb_mac_type_unicast, 6) &&
	    !memcmp(mask, eb_msk_type_unicast, 6))
		printf("Unicast");
	else if (!memcmp(mac, eb_mac_type_multicast, 6) &&
	         !memcmp(mask, eb_msk_type_multicast, 6))
		printf("Multicast");
	else if (!memcmp(mac, eb_mac_type_broadcast, 6) &&
	         !memcmp(mask, eb_msk_type_broadcast, 6))
		printf("Broadcast");
	else if (!memcmp(mac, eb_mac_type_bridge_group, 6) &&
	         !memcmp(mask, eb_msk_type_bridge_group, 6))
		printf("BGA");
	else {
		ebt_print_mac(mac);
		if (!mac_all_ones(mask)) {
			printf("/");
			ebt_print_mac(mask);
		}
	}
}

static void add_logical_iniface(struct nftnl_rule *r, char *iface, uint32_t op)
{
	int iface_len;

	iface_len = strlen(iface);

	add_meta(r, NFT_META_BRI_IIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

static void add_logical_outiface(struct nftnl_rule *r, char *iface, uint32_t op)
{
	int iface_len;

	iface_len = strlen(iface);

	add_meta(r, NFT_META_BRI_OIFNAME);
	if (iface[iface_len - 1] == '+')
		add_cmp_ptr(r, op, iface, iface_len - 1);
	else
		add_cmp_ptr(r, op, iface, iface_len + 1);
}

/* TODO: Use generic add_action() once we convert this to use
 * iptables_command_state.
 */
static int _add_action(struct nftnl_rule *r, struct iptables_command_state *cs)
{
	int ret = 0;

	if (cs->jumpto == NULL || strcmp(cs->jumpto, "CONTINUE") == 0)
		return 0;

	/* If no target at all, add nothing (default to continue) */
	if (cs->target != NULL) {
		/* Standard target? */
		if (strcmp(cs->jumpto, XTC_LABEL_ACCEPT) == 0)
			ret = add_verdict(r, NF_ACCEPT);
		else if (strcmp(cs->jumpto, XTC_LABEL_DROP) == 0)
			ret = add_verdict(r, NF_DROP);
		else if (strcmp(cs->jumpto, XTC_LABEL_RETURN) == 0)
			ret = add_verdict(r, NFT_RETURN);
		else
			ret = add_target(r, cs->target->t);
	} else if (strlen(cs->jumpto) > 0) {
		/* Not standard, then it's a jump to chain */
		ret = add_jumpto(r, cs->jumpto, NFT_JUMP);
	}

	return ret;
}

static int nft_bridge_add(struct nftnl_rule *r, void *data)
{
	struct iptables_command_state *cs = data;
	struct ebt_match *iter;
	struct ebt_entry *fw = &cs->eb;
	uint32_t op;

	if (fw->in[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_IIN);
		add_iniface(r, fw->in, op);
	}

	if (fw->out[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_IOUT);
		add_outiface(r, fw->out, op);
	}

	if (fw->logical_in[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_ILOGICALIN);
		add_logical_iniface(r, fw->logical_in, op);
	}

	if (fw->logical_out[0] != '\0') {
		op = nft_invflags2cmp(fw->invflags, EBT_ILOGICALOUT);
		add_logical_outiface(r, fw->logical_out, op);
	}

	if (fw->bitmask & EBT_ISOURCE) {
		op = nft_invflags2cmp(fw->invflags, EBT_ISOURCE);
		add_payload(r, offsetof(struct ethhdr, h_source), 6,
			    NFT_PAYLOAD_LL_HEADER);
		if (!mac_all_ones(fw->sourcemsk))
			add_bitwise(r, fw->sourcemsk, 6);
		add_cmp_ptr(r, op, fw->sourcemac, 6);
	}

	if (fw->bitmask & EBT_IDEST) {
		op = nft_invflags2cmp(fw->invflags, EBT_IDEST);
		add_payload(r, offsetof(struct ethhdr, h_dest), 6,
			    NFT_PAYLOAD_LL_HEADER);
		if (!mac_all_ones(fw->destmsk))
			add_bitwise(r, fw->destmsk, 6);
		add_cmp_ptr(r, op, fw->destmac, 6);
	}

	if ((fw->bitmask & EBT_NOPROTO) == 0) {
		op = nft_invflags2cmp(fw->invflags, EBT_IPROTO);
		add_payload(r, offsetof(struct ethhdr, h_proto), 2,
			    NFT_PAYLOAD_LL_HEADER);
		add_cmp_u16(r, fw->ethproto, op);
	}

	add_compat(r, fw->ethproto, fw->invflags);

	for (iter = cs->match_list; iter; iter = iter->next) {
		if (iter->ismatch) {
			if (add_match(r, iter->u.match->m))
				break;
		} else {
			if (add_target(r, iter->u.watcher->t))
				break;
		}
	}

	if (add_counters(r, cs->counters.pcnt, cs->counters.bcnt) < 0)
		return -1;

	return _add_action(r, cs);
}

static void nft_bridge_parse_meta(struct nft_xt_ctx *ctx,
				  struct nftnl_expr *e, void *data)
{
	struct iptables_command_state *cs = data;
	struct ebt_entry *fw = &cs->eb;
	uint8_t invflags = 0;
	char iifname[IFNAMSIZ], oifname[IFNAMSIZ];

	memset(iifname, 0, sizeof(iifname));
	memset(oifname, 0, sizeof(oifname));

	parse_meta(e, ctx->meta.key, iifname, NULL, oifname, NULL, &invflags);

	switch (ctx->meta.key) {
	case NFT_META_BRI_IIFNAME:
		if (invflags & IPT_INV_VIA_IN)
			cs->eb.invflags |= EBT_ILOGICALIN;
		snprintf(fw->logical_in, sizeof(fw->logical_in), "%s", iifname);
		break;
	case NFT_META_IIFNAME:
		if (invflags & IPT_INV_VIA_IN)
			cs->eb.invflags |= EBT_IIN;
		snprintf(fw->in, sizeof(fw->in), "%s", iifname);
		break;
	case NFT_META_BRI_OIFNAME:
		if (invflags & IPT_INV_VIA_OUT)
			cs->eb.invflags |= EBT_ILOGICALOUT;
		snprintf(fw->logical_out, sizeof(fw->logical_out), "%s", oifname);
		break;
	case NFT_META_OIFNAME:
		if (invflags & IPT_INV_VIA_OUT)
			cs->eb.invflags |= EBT_IOUT;
		snprintf(fw->out, sizeof(fw->out), "%s", oifname);
		break;
	default:
		break;
	}
}

static void nft_bridge_parse_payload(struct nft_xt_ctx *ctx,
				     struct nftnl_expr *e, void *data)
{
	struct iptables_command_state *cs = data;
	struct ebt_entry *fw = &cs->eb;
	unsigned char addr[ETH_ALEN];
	unsigned short int ethproto;
	bool inv;
	int i;

	switch (ctx->payload.offset) {
	case offsetof(struct ethhdr, h_dest):
		get_cmp_data(e, addr, sizeof(addr), &inv);
		for (i = 0; i < ETH_ALEN; i++)
			fw->destmac[i] = addr[i];
		if (inv)
			fw->invflags |= EBT_IDEST;

		if (ctx->flags & NFT_XT_CTX_BITWISE) {
                        memcpy(fw->destmsk, ctx->bitwise.mask, ETH_ALEN);
                        ctx->flags &= ~NFT_XT_CTX_BITWISE;
                } else {
                        memset(&fw->destmsk, 0xff, ETH_ALEN);
                }
		fw->bitmask |= EBT_IDEST;
		break;
	case offsetof(struct ethhdr, h_source):
		get_cmp_data(e, addr, sizeof(addr), &inv);
		for (i = 0; i < ETH_ALEN; i++)
			fw->sourcemac[i] = addr[i];
		if (inv)
			fw->invflags |= EBT_ISOURCE;
		if (ctx->flags & NFT_XT_CTX_BITWISE) {
                        memcpy(fw->sourcemsk, ctx->bitwise.mask, ETH_ALEN);
                        ctx->flags &= ~NFT_XT_CTX_BITWISE;
                } else {
                        memset(&fw->sourcemsk, 0xff, ETH_ALEN);
                }
		fw->bitmask |= EBT_ISOURCE;
		break;
	case offsetof(struct ethhdr, h_proto):
		get_cmp_data(e, &ethproto, sizeof(ethproto), &inv);
		fw->ethproto = ethproto;
		if (inv)
			fw->invflags |= EBT_IPROTO;
		fw->bitmask &= ~EBT_NOPROTO;
		break;
	}
}

static void nft_bridge_parse_immediate(const char *jumpto, bool nft_goto,
				       void *data)
{
	struct iptables_command_state *cs = data;

	cs->jumpto = jumpto;
}

static void parse_watcher(void *object, struct ebt_match **match_list,
			  bool ismatch)
{
	struct ebt_match *m;

	m = calloc(1, sizeof(struct ebt_match));
	if (m == NULL)
		xtables_error(OTHER_PROBLEM, "Can't allocate memory");

	if (ismatch)
		m->u.match = object;
	else
		m->u.watcher = object;

	m->ismatch = ismatch;
	if (*match_list == NULL)
		*match_list = m;
	else
		(*match_list)->next = m;
}

static void nft_bridge_parse_match(struct xtables_match *m, void *data)
{
	struct iptables_command_state *cs = data;

	parse_watcher(m, &cs->match_list, true);
}

static void nft_bridge_parse_target(struct xtables_target *t, void *data)
{
	struct iptables_command_state *cs = data;

	/* harcoded names :-( */
	if (strcmp(t->name, "log") == 0 ||
	    strcmp(t->name, "nflog") == 0) {
		parse_watcher(t, &cs->match_list, false);
		return;
	}

	cs->target = t;
}

static void nft_rule_to_ebtables_command_state(struct nftnl_rule *r,
					       struct iptables_command_state *cs)
{
	cs->eb.bitmask = EBT_NOPROTO;
	nft_rule_to_iptables_command_state(r, cs);
}

static void print_iface(const char *option, const char *name, bool invert)
{
	if (*name)
		printf("%s%s %s ", invert ? "! " : "", option, name);
}

static void nft_bridge_print_table_header(const char *tablename)
{
	printf("Bridge table: %s\n\n", tablename);
}

static void nft_bridge_print_header(unsigned int format, const char *chain,
				    const char *pol,
				    const struct xt_counters *counters,
				    bool basechain, uint32_t refs)
{
	printf("Bridge chain: %s, entries: %u, policy: %s\n",
	       chain, refs, basechain ? pol : "RETURN");
}

static void print_matches_and_watchers(const struct iptables_command_state *cs,
				       unsigned int format)
{
	struct xtables_target *watcherp;
	struct xtables_match *matchp;
	struct ebt_match *m;

	for (m = cs->match_list; m; m = m->next) {
		if (m->ismatch) {
			matchp = m->u.match;
			if (matchp->print != NULL) {
				matchp->print(&cs->eb, matchp->m,
					      format & FMT_NUMERIC);
			}
		} else {
			watcherp = m->u.watcher;
			if (watcherp->print != NULL) {
				watcherp->print(&cs->eb, watcherp->t,
						format & FMT_NUMERIC);
			}
		}
	}
}

static void print_mac(char option, const unsigned char *mac,
		      const unsigned char *mask,
		      bool invert)
{
	printf("-%c ", option);
	if (invert)
		printf("! ");
	ebt_print_mac_and_mask(mac, mask);
	printf(" ");
}


static void print_protocol(uint16_t ethproto, bool invert, unsigned int bitmask)
{
	struct ethertypeent *ent;

	/* Dont print anything about the protocol if no protocol was
	 * specified, obviously this means any protocol will do. */
	if (bitmask & EBT_NOPROTO)
		return;

	printf("-p ");
	if (invert)
		printf("! ");

	if (bitmask & EBT_802_3) {
		printf("length ");
		return;
	}

	ent = getethertypebynumber(ntohs(ethproto));
	if (!ent)
		printf("0x%x ", ntohs(ethproto));
	else
		printf("%s ", ent->e_name);
}

static void nft_bridge_print_firewall(struct nftnl_rule *r, unsigned int num,
				      unsigned int format)
{
	struct iptables_command_state cs = {};

	nft_rule_to_ebtables_command_state(r, &cs);

	if (format & FMT_LINENUMBERS)
		printf("%d ", num);

	print_protocol(cs.eb.ethproto, cs.eb.invflags & EBT_IPROTO, cs.eb.bitmask);
	if (cs.eb.bitmask & EBT_ISOURCE)
		print_mac('s', cs.eb.sourcemac, cs.eb.sourcemsk,
		          cs.eb.invflags & EBT_ISOURCE);
	if (cs.eb.bitmask & EBT_IDEST)
		print_mac('d', cs.eb.destmac, cs.eb.destmsk,
		          cs.eb.invflags & EBT_IDEST);

	print_iface("-i", cs.eb.in, cs.eb.invflags & EBT_IIN);
	print_iface("--logical-in", cs.eb.logical_in, cs.eb.invflags & EBT_ILOGICALIN);
	print_iface("-o", cs.eb.out, cs.eb.invflags & EBT_IOUT);
	print_iface("--logical-out", cs.eb.logical_out, cs.eb.invflags & EBT_ILOGICALOUT);

	print_matches_and_watchers(&cs, format);

	printf("-j ");

	if (cs.jumpto != NULL) {
		if (strcmp(cs.jumpto, "") != 0)
			printf("%s", cs.jumpto);
		else
			printf("CONTINUE");
	}
	else if (cs.target != NULL && cs.target->print != NULL)
		cs.target->print(&cs.fw, cs.target->t, format & FMT_NUMERIC);

	if (!(format & FMT_NOCOUNTS))
		printf(" , pcnt = %"PRIu64" -- bcnt = %"PRIu64"",
		       (uint64_t)cs.counters.pcnt, (uint64_t)cs.counters.bcnt);

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);

	ebt_cs_clean(&cs);
}

static bool nft_bridge_is_same(const void *data_a, const void *data_b)
{
	const struct ebt_entry *a = data_a;
	const struct ebt_entry *b = data_b;
	int i;

	if (a->ethproto != b->ethproto ||
	    /* FIXME: a->flags != b->flags || */
	    a->invflags != b->invflags) {
		DEBUGP("different proto/flags/invflags\n");
		return false;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		if (a->sourcemac[i] != b->sourcemac[i]) {
			DEBUGP("different source mac %x, %x (%d)\n",
			a->sourcemac[i] & 0xff, b->sourcemac[i] & 0xff, i);
			return false;
		}

		if (a->destmac[i] != b->destmac[i]) {
			DEBUGP("different destination mac %x, %x (%d)\n",
			a->destmac[i] & 0xff, b->destmac[i] & 0xff, i);
			return false;
		}
	}

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a->logical_in[i] != b->logical_in[i]) {
			DEBUGP("different logical iniface %x, %x (%d)\n",
			a->logical_in[i] & 0xff, b->logical_in[i] & 0xff, i);
			return false;
		}

		if (a->logical_out[i] != b->logical_out[i]) {
			DEBUGP("different logical outiface %x, %x (%d)\n",
			a->logical_out[i] & 0xff, b->logical_out[i] & 0xff, i);
			return false;
		}
	}

	return strcmp(a->in, b->in) == 0 && strcmp(a->out, b->out) == 0;
}

static bool nft_bridge_rule_find(struct nft_family_ops *ops, struct nftnl_rule *r,
				 void *data)
{
	struct iptables_command_state *cs = data;
	struct iptables_command_state this = {};

	nft_rule_to_ebtables_command_state(r, &this);

	DEBUGP("comparing with... ");

	if (!nft_bridge_is_same(cs, &this))
		return false;

	if (!compare_matches(cs->matches, this.matches)) {
		DEBUGP("Different matches\n");
		return false;
	}

	if (!compare_targets(cs->target, this.target)) {
		DEBUGP("Different target\n");
		return false;
	}

	if (cs->jumpto != NULL && strcmp(cs->jumpto, this.jumpto) != 0) {
		DEBUGP("Different verdict\n");
		return false;
	}

	return true;
}

static int xlate_ebmatches(const struct iptables_command_state *cs, struct xt_xlate *xl)
{
	int ret = 1, numeric = cs->options & OPT_NUMERIC;
	struct ebt_match *m;

	for (m = cs->match_list; m; m = m->next) {
		if (m->ismatch) {
			struct xtables_match *matchp = m->u.match;
			struct xt_xlate_mt_params mt_params = {
				.ip		= (const void *)&cs->eb,
				.numeric	= numeric,
				.escape_quotes	= false,
				.match		= matchp->m,
			};

			if (!matchp->xlate)
				return 0;

			ret = matchp->xlate(xl, &mt_params);
		} else {
			struct xtables_target *watcherp = m->u.watcher;
			struct xt_xlate_tg_params wt_params = {
				.ip		= (const void *)&cs->eb,
				.numeric	= numeric,
				.escape_quotes	= false,
				.target		= watcherp->t,
			};

			if (!watcherp->xlate)
				return 0;

			ret = watcherp->xlate(xl, &wt_params);
		}

		if (!ret)
			break;
	}

	return ret;
}

static int xlate_ebaction(const struct iptables_command_state *cs, struct xt_xlate *xl)
{
	int ret = 1, numeric = cs->options & OPT_NUMERIC;

	/* If no target at all, add nothing (default to continue) */
	if (cs->target != NULL) {
		/* Standard target? */
		if (strcmp(cs->jumpto, XTC_LABEL_ACCEPT) == 0)
			xt_xlate_add(xl, " accept");
		else if (strcmp(cs->jumpto, XTC_LABEL_DROP) == 0)
			xt_xlate_add(xl, " drop");
		else if (strcmp(cs->jumpto, XTC_LABEL_RETURN) == 0)
			xt_xlate_add(xl, " return");
		else if (cs->target->xlate) {
			xt_xlate_add(xl, " ");
			struct xt_xlate_tg_params params = {
				.ip		= (const void *)&cs->eb,
				.target		= cs->target->t,
				.numeric	= numeric,
			};
			ret = cs->target->xlate(xl, &params);
		}
		else
			return 0;
	} else if (cs->jumpto == NULL) {
	} else if (strlen(cs->jumpto) > 0)
		xt_xlate_add(xl, " jump %s", cs->jumpto);

	return ret;
}

static void xlate_mac(struct xt_xlate *xl, const unsigned char *mac)
{
	int i;

	xt_xlate_add(xl, "%02x", mac[0]);

	for (i=1; i < ETH_ALEN; i++)
		xt_xlate_add(xl, ":%02x", mac[i]);
}

static void nft_bridge_xlate_mac(struct xt_xlate *xl, const char *type, bool invert,
				 const unsigned char *mac, const unsigned char *mask)
{
	char one_msk[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	xt_xlate_add(xl, "ether %s %s", type, invert ? "!= " : "");

	xlate_mac(xl, mac);

	if (memcmp(mask, one_msk, ETH_ALEN)) {
		int i;
		xt_xlate_add(xl, " and ");

		xlate_mac(xl, mask);

		xt_xlate_add(xl, " == %02x", mac[0] & mask[0]);
		for (i=1; i < ETH_ALEN; i++)
			xt_xlate_add(xl, ":%02x", mac[i] & mask[i]);
	}

	xt_xlate_add(xl, " ");
}

static int nft_bridge_xlate(const void *data, struct xt_xlate *xl)
{
	const struct iptables_command_state *cs = data;
	int ret;

	xlate_ifname(xl, "iifname", cs->eb.in,
		     cs->eb.invflags & EBT_IIN);
	xlate_ifname(xl, "meta ibrname", cs->eb.logical_in,
		     cs->eb.invflags & EBT_ILOGICALIN);
	xlate_ifname(xl, "oifname", cs->eb.out,
		     cs->eb.invflags & EBT_IOUT);
	xlate_ifname(xl, "meta obrname", cs->eb.logical_out,
		     cs->eb.invflags & EBT_ILOGICALOUT);

	if ((cs->eb.bitmask & EBT_NOPROTO) == 0) {
		const char *implicit = NULL;

		switch (ntohs(cs->eb.ethproto)) {
		case ETH_P_IP:
			implicit = "ip";
			break;
		case ETH_P_IPV6:
			implicit = "ip6";
			break;
		case ETH_P_8021Q:
			implicit = "vlan";
			break;
		default:
			break;
		}

		if (!implicit || !xlate_find_match(cs, implicit))
			xt_xlate_add(xl, "ether type %s0x%x ",
				     cs->eb.invflags & EBT_IPROTO ? "!= " : "",
				     ntohs(cs->eb.ethproto));
	}

	if (cs->eb.bitmask & EBT_802_3)
		return 0;

	if (cs->eb.bitmask & EBT_ISOURCE)
		nft_bridge_xlate_mac(xl, "saddr", cs->eb.invflags & EBT_ISOURCE,
				     cs->eb.sourcemac, cs->eb.sourcemsk);
	if (cs->eb.bitmask & EBT_IDEST)
		nft_bridge_xlate_mac(xl, "daddr", cs->eb.invflags & EBT_IDEST,
				     cs->eb.destmac, cs->eb.destmsk);
	ret = xlate_ebmatches(cs, xl);
	if (ret == 0)
		return ret;

	/* Always add counters per rule, as in ebtables */
	xt_xlate_add(xl, "counter");
	ret = xlate_ebaction(cs, xl);

	return ret;
}

struct nft_family_ops nft_family_ops_bridge = {
	.add			= nft_bridge_add,
	.is_same		= nft_bridge_is_same,
	.print_payload		= NULL,
	.parse_meta		= nft_bridge_parse_meta,
	.parse_payload		= nft_bridge_parse_payload,
	.parse_immediate	= nft_bridge_parse_immediate,
	.parse_match		= nft_bridge_parse_match,
	.parse_target		= nft_bridge_parse_target,
	.print_table_header	= nft_bridge_print_table_header,
	.print_header		= nft_bridge_print_header,
	.print_firewall		= nft_bridge_print_firewall,
	.save_firewall		= NULL,
	.save_counters		= NULL,
	.post_parse		= NULL,
	.rule_find		= nft_bridge_rule_find,
	.xlate			= nft_bridge_xlate,
};
