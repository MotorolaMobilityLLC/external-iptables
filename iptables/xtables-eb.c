/*
 * ebtables.c, v2.0 July 2002
 *
 * Author: Bart De Schuymer
 *
 *  This code was stongly inspired on the iptables code which is
 *  Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <xtables.h>

#include <linux/netfilter_bridge.h>
#include <linux/netfilter/nf_tables.h>
#include <ebtables/ethernetdb.h>
#include "xshared.h"
#include "nft.h"
#include "nft-bridge.h"

extern struct xtables_globals xtables_globals;
#define prog_name xtables_globals.program_name
#define prog_vers xtables_globals.program_version

/*
 * From include/ebtables_u.h
 */
#define EXEC_STYLE_PRG    0
#define EXEC_STYLE_DAEMON 1

/*
 * From useful_functions.c
 */

/* 0: default
 * 1: the inverse '!' of the option has already been specified */
int ebt_invert = 0;

unsigned char eb_mac_type_unicast[ETH_ALEN] =   {0,0,0,0,0,0};
unsigned char eb_msk_type_unicast[ETH_ALEN] =   {1,0,0,0,0,0};
unsigned char eb_mac_type_multicast[ETH_ALEN] = {1,0,0,0,0,0};
unsigned char eb_msk_type_multicast[ETH_ALEN] = {1,0,0,0,0,0};
unsigned char eb_mac_type_broadcast[ETH_ALEN] = {255,255,255,255,255,255};
unsigned char eb_msk_type_broadcast[ETH_ALEN] = {255,255,255,255,255,255};
unsigned char eb_mac_type_bridge_group[ETH_ALEN] = {0x01,0x80,0xc2,0,0,0};
unsigned char eb_msk_type_bridge_group[ETH_ALEN] = {255,255,255,255,255,255};

int ebt_get_mac_and_mask(const char *from, unsigned char *to,
  unsigned char *mask)
{
	char *p;
	int i;
	struct ether_addr *addr = NULL;

	if (strcasecmp(from, "Unicast") == 0) {
		memcpy(to, eb_mac_type_unicast, ETH_ALEN);
		memcpy(mask, eb_msk_type_unicast, ETH_ALEN);
		return 0;
	}
	if (strcasecmp(from, "Multicast") == 0) {
		memcpy(to, eb_mac_type_multicast, ETH_ALEN);
		memcpy(mask, eb_msk_type_multicast, ETH_ALEN);
		return 0;
	}
	if (strcasecmp(from, "Broadcast") == 0) {
		memcpy(to, eb_mac_type_broadcast, ETH_ALEN);
		memcpy(mask, eb_msk_type_broadcast, ETH_ALEN);
		return 0;
	}
	if (strcasecmp(from, "BGA") == 0) {
		memcpy(to, eb_mac_type_bridge_group, ETH_ALEN);
		memcpy(mask, eb_msk_type_bridge_group, ETH_ALEN);
		return 0;
	}
	if ( (p = strrchr(from, '/')) != NULL) {
		*p = '\0';
		if (!(addr = ether_aton(p + 1)))
			return -1;
		memcpy(mask, addr, ETH_ALEN);
	} else
		memset(mask, 0xff, ETH_ALEN);
	if (!(addr = ether_aton(from)))
		return -1;
	memcpy(to, addr, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++)
		to[i] &= mask[i];
	return 0;
}

/* This is a replacement for the ebt_check_option2() macro.
 *
 * Make sure the same option wasn't specified twice. This is used in the parse
 * functions of the extensions and ebtables.c.
 */
static void ebt_check_option2(unsigned int *flags, unsigned int mask)
{
	if (*flags & mask)
		xtables_error(PARAMETER_PROBLEM,
			      "Multiple use of same option not allowed");
	*flags |= mask;
}

static int ebt_check_inverse2(const char option[], int argc, char **argv)
{
	if (!option)
		return ebt_invert;
	if (strcmp(option, "!") == 0) {
		if (ebt_invert == 1)
			xtables_error(PARAMETER_PROBLEM,
				      "Double use of '!' not allowed");
		if (optind >= argc)
			optarg = NULL;
		else
			optarg = argv[optind];
		optind++;
		ebt_invert = 1;
		return 1;
	}
	return ebt_invert;
}

/*
 * From libebtc.c
 */

/* The four target names, from libebtc.c */
const char* ebt_standard_targets[NUM_STANDARD_TARGETS] =
{
	"ACCEPT",
	"DROP",
	"CONTINUE",
	"RETURN",
};

/* Prints all registered extensions */
static void ebt_list_extensions(const struct xtables_target *t,
				const struct xtables_rule_match *m)
{
	printf("%s v%s\n", prog_name, prog_vers);
	printf("Loaded userspace extensions:\n");
	/*printf("\nLoaded tables:\n");
        while (tbl) {
		printf("%s\n", tbl->name);
                tbl = tbl->next;
	}*/
	printf("\nLoaded targets:\n");
        for (t = xtables_targets; t; t = t->next) {
		printf("%s\n", t->name);
	}
	printf("\nLoaded matches:\n");
        for (; m != NULL; m = m->next)
		printf("%s\n", m->match->name);
	/*printf("\nLoaded watchers:\n");
        while (w) {
		printf("%s\n", w->name);
                w = w->next;
	}*/
}

/*
 * Glue code to use libxtables
 */
static int parse_rule_number(const char *rule)
{
	unsigned int rule_nr;

	if (!xtables_strtoui(rule, NULL, &rule_nr, 1, INT_MAX))
		xtables_error(PARAMETER_PROBLEM,
			      "Invalid rule number `%s'", rule);

	return rule_nr;
}

static const char *
parse_target(const char *targetname)
{
	const char *ptr;

	if (strlen(targetname) < 1)
		xtables_error(PARAMETER_PROBLEM,
			      "Invalid target name (too short)");

	if (strlen(targetname)+1 > EBT_CHAIN_MAXNAMELEN)
		xtables_error(PARAMETER_PROBLEM,
			      "Invalid target '%s' (%d chars max)",
			      targetname, EBT_CHAIN_MAXNAMELEN);

	for (ptr = targetname; *ptr; ptr++)
		if (isspace(*ptr))
			xtables_error(PARAMETER_PROBLEM,
				      "Invalid target name `%s'", targetname);
	return targetname;
}

static int
append_entry(struct nft_handle *h,
	     const char *chain,
	     const char *table,
	     struct ebtables_command_state *cs,
	     int rule_nr,
	     bool verbose, bool append)
{
	int ret = 1;

	if (append)
		ret = nft_rule_append(h, chain, table, cs, 0, verbose);
	else
		ret = nft_rule_insert(h, chain, table, cs, rule_nr, verbose);

	return ret;
}

static int
delete_entry(struct nft_handle *h,
	     const char *chain,
	     const char *table,
	     struct ebtables_command_state *cs,
	     int rule_nr,
	     int rule_nr_end,
	     bool verbose)
{
	int ret = 1;

	if (rule_nr == -1)
		ret = nft_rule_delete(h, chain, table, cs, verbose);
	else {
		do {
			ret = nft_rule_delete_num(h, chain, table,
						  rule_nr, verbose);
			rule_nr++;
		} while (rule_nr < rule_nr_end);
	}

	return ret;
}

static int get_current_chain(const char *chain)
{
	if (strcmp(chain, "PREROUTING") == 0)
		return NF_BR_PRE_ROUTING;
	else if (strcmp(chain, "INPUT") == 0)
		return NF_BR_LOCAL_IN;
	else if (strcmp(chain, "FORWARD") == 0)
		return NF_BR_FORWARD;
	else if (strcmp(chain, "OUTPUT") == 0)
		return NF_BR_LOCAL_OUT;
	else if (strcmp(chain, "POSTROUTING") == 0)
		return NF_BR_POST_ROUTING;

	return -1;
}

/*
 * The original ebtables parser
 */

/* Checks whether a command has already been specified */
#define OPT_COMMANDS (flags & OPT_COMMAND || flags & OPT_ZERO)

#define OPT_COMMAND	0x01
#define OPT_TABLE	0x02
#define OPT_IN		0x04
#define OPT_OUT		0x08
#define OPT_JUMP	0x10
#define OPT_PROTOCOL	0x20
#define OPT_SOURCE	0x40
#define OPT_DEST	0x80
#define OPT_ZERO	0x100
#define OPT_LOGICALIN	0x200
#define OPT_LOGICALOUT	0x400
#define OPT_KERNELDATA	0x800 /* This value is also defined in ebtablesd.c */
#define OPT_COUNT	0x1000 /* This value is also defined in libebtc.c */
#define OPT_CNT_INCR	0x2000 /* This value is also defined in libebtc.c */
#define OPT_CNT_DECR	0x4000 /* This value is also defined in libebtc.c */

/* Default command line options. Do not mess around with the already
 * assigned numbers unless you know what you are doing */
static struct option ebt_original_options[] =
{
	{ "append"         , required_argument, 0, 'A' },
	{ "insert"         , required_argument, 0, 'I' },
	{ "delete"         , required_argument, 0, 'D' },
	{ "list"           , optional_argument, 0, 'L' },
	{ "Lc"             , no_argument      , 0, 4   },
	{ "Ln"             , no_argument      , 0, 5   },
	{ "Lx"             , no_argument      , 0, 6   },
	{ "Lmac2"          , no_argument      , 0, 12  },
	{ "zero"           , optional_argument, 0, 'Z' },
	{ "flush"          , optional_argument, 0, 'F' },
	{ "policy"         , required_argument, 0, 'P' },
	{ "in-interface"   , required_argument, 0, 'i' },
	{ "in-if"          , required_argument, 0, 'i' },
	{ "logical-in"     , required_argument, 0, 2   },
	{ "logical-out"    , required_argument, 0, 3   },
	{ "out-interface"  , required_argument, 0, 'o' },
	{ "out-if"         , required_argument, 0, 'o' },
	{ "version"        , no_argument      , 0, 'V' },
	{ "help"           , no_argument      , 0, 'h' },
	{ "jump"           , required_argument, 0, 'j' },
	{ "set-counters"   , required_argument, 0, 'c' },
	{ "change-counters", required_argument, 0, 'C' },
	{ "proto"          , required_argument, 0, 'p' },
	{ "protocol"       , required_argument, 0, 'p' },
	{ "db"             , required_argument, 0, 'b' },
	{ "source"         , required_argument, 0, 's' },
	{ "src"            , required_argument, 0, 's' },
	{ "destination"    , required_argument, 0, 'd' },
	{ "dst"            , required_argument, 0, 'd' },
	{ "table"          , required_argument, 0, 't' },
	{ "modprobe"       , required_argument, 0, 'M' },
	{ "new-chain"      , required_argument, 0, 'N' },
	{ "rename-chain"   , required_argument, 0, 'E' },
	{ "delete-chain"   , optional_argument, 0, 'X' },
	{ "atomic-init"    , no_argument      , 0, 7   },
	{ "atomic-commit"  , no_argument      , 0, 8   },
	{ "atomic-file"    , required_argument, 0, 9   },
	{ "atomic-save"    , no_argument      , 0, 10  },
	{ "init-table"     , no_argument      , 0, 11  },
	{ "concurrent"     , no_argument      , 0, 13  },
	{ 0 }
};

static struct option *ebt_options = ebt_original_options;

/*
 * More glue code.
 */
static struct xtables_target *command_jump(struct ebtables_command_state *cs,
					   const char *jumpto)
{
	struct xtables_target *target;
	size_t size;

	/* XTF_TRY_LOAD (may be chain name) */
	target = xtables_find_target(jumpto, XTF_TRY_LOAD);

	if (!target)
		return NULL;

	size = XT_ALIGN(sizeof(struct xt_entry_target))
		+ target->size;

	target->t = xtables_calloc(1, size);
	target->t->u.target_size = size;
	strncpy(target->t->u.user.name, jumpto, sizeof(target->t->u.user.name));
	target->t->u.user.name[sizeof(target->t->u.user.name)-1] = '\0';
	target->t->u.user.revision = target->revision;

	xs_init_target(target);

	if (target->x6_options != NULL)
		ebt_options = xtables_options_xfrm(xtables_globals.orig_opts,
					    ebt_options, target->x6_options,
					    &target->option_offset);
	else
		ebt_options = xtables_merge_options(xtables_globals.orig_opts,
					     ebt_options, target->extra_opts,
					     &target->option_offset);

	return target;
}

static void print_help(const struct xtables_target *t,
		       const struct xtables_rule_match *m, const char *table)
{
	printf("%s %s\n", prog_name, prog_vers);
	printf(
"Usage:\n"
"ebtables -[ADI] chain rule-specification [options]\n"
"ebtables -P chain target\n"
"ebtables -[LFZ] [chain]\n"
"ebtables -[NX] [chain]\n"
"ebtables -E old-chain-name new-chain-name\n\n"
"Commands:\n"
"--append -A chain             : append to chain\n"
"--delete -D chain             : delete matching rule from chain\n"
"--delete -D chain rulenum     : delete rule at position rulenum from chain\n"
"--change-counters -C chain\n"
"          [rulenum] pcnt bcnt : change counters of existing rule\n"
"--insert -I chain rulenum     : insert rule at position rulenum in chain\n"
"--list   -L [chain]           : list the rules in a chain or in all chains\n"
"--flush  -F [chain]           : delete all rules in chain or in all chains\n"
"--init-table                  : replace the kernel table with the initial table\n"
"--zero   -Z [chain]           : put counters on zero in chain or in all chains\n"
"--policy -P chain target      : change policy on chain to target\n"
"--new-chain -N chain          : create a user defined chain\n"
"--rename-chain -E old new     : rename a chain\n"
"--delete-chain -X [chain]     : delete a user defined chain\n"
"--atomic-commit               : update the kernel w/t table contained in <FILE>\n"
"--atomic-init                 : put the initial kernel table into <FILE>\n"
"--atomic-save                 : put the current kernel table into <FILE>\n"
"--atomic-file file            : set <FILE> to file\n\n"
"Options:\n"
"--proto  -p [!] proto         : protocol hexadecimal, by name or LENGTH\n"
"--src    -s [!] address[/mask]: source mac address\n"
"--dst    -d [!] address[/mask]: destination mac address\n"
"--in-if  -i [!] name[+]       : network input interface name\n"
"--out-if -o [!] name[+]       : network output interface name\n"
"--logical-in  [!] name[+]     : logical bridge input interface name\n"
"--logical-out [!] name[+]     : logical bridge output interface name\n"
"--set-counters -c chain\n"
"          pcnt bcnt           : set the counters of the to be added rule\n"
"--modprobe -M program         : try to insert modules using this program\n"
"--concurrent                  : use a file lock to support concurrent scripts\n"
"--version -V                  : print package version\n\n"
"Environment variable:\n"
/*ATOMIC_ENV_VARIABLE "          : if set <FILE> (see above) will equal its value"*/
"\n\n");
	for (; m != NULL; m = m->next) {
		printf("\n");
		m->match->help();
	}
	if (t != NULL) {
		printf("\n");
		t->help();
	}

//	if (table->help)
//		table->help(ebt_hooknames);
}

/* Execute command L */
static int list_rules(struct nft_handle *h, const char *chain, const char *table,
		      int rule_nr, int verbose, int numeric, int expanded,
		      int linenumbers)
{
	unsigned int format;

	format = FMT_OPTIONS;
	if (!verbose)
		format |= FMT_NOCOUNTS;
	else
		format |= FMT_VIA;

	if (numeric)
		format |= FMT_NUMERIC;

	if (!expanded)
		format |= FMT_KILOMEGAGIGA;

	if (linenumbers)
		format |= FMT_LINENUMBERS;

	return nft_rule_list(h, chain, table, rule_nr, format);
}

static int parse_rule_range(const char *argv, int *rule_nr, int *rule_nr_end)
{
	char *colon = strchr(argv, ':'), *buffer;

	if (colon) {
		*colon = '\0';
		if (*(colon + 1) == '\0')
			*rule_nr_end = -1; /* Until the last rule */
		else {
			*rule_nr_end = strtol(colon + 1, &buffer, 10);
			if (*buffer != '\0' || *rule_nr_end == 0)
				return -1;
		}
	}
	if (colon == argv)
		*rule_nr = 1; /* Beginning with the first rule */
	else {
		*rule_nr = strtol(argv, &buffer, 10);
		if (*buffer != '\0' || *rule_nr == 0)
			return -1;
	}
	if (!colon)
		*rule_nr_end = *rule_nr;
	return 0;
}

/* Incrementing or decrementing rules in daemon mode is not supported as the
 * involved code overload is not worth it (too annoying to take the increased
 * counters in the kernel into account). */
static int parse_change_counters_rule(int argc, char **argv, int *rule_nr, int *rule_nr_end, int exec_style, struct ebtables_command_state *cs)
{
	char *buffer;
	int ret = 0;

	if (optind + 1 >= argc || (argv[optind][0] == '-' && (argv[optind][1] < '0' || argv[optind][1] > '9')) ||
	    (argv[optind + 1][0] == '-' && (argv[optind + 1][1] < '0'  && argv[optind + 1][1] > '9')))
		xtables_error(PARAMETER_PROBLEM,
			      "The command -C needs at least 2 arguments");
	if (optind + 2 < argc && (argv[optind + 2][0] != '-' || (argv[optind + 2][1] >= '0' && argv[optind + 2][1] <= '9'))) {
		if (optind + 3 != argc)
			xtables_error(PARAMETER_PROBLEM,
				      "No extra options allowed with -C start_nr[:end_nr] pcnt bcnt");
		if (parse_rule_range(argv[optind], rule_nr, rule_nr_end))
			xtables_error(PARAMETER_PROBLEM,
				      "Something is wrong with the rule number specification '%s'", argv[optind]);
		optind++;
	}

	if (argv[optind][0] == '+') {
		if (exec_style == EXEC_STYLE_DAEMON)
daemon_incr:
			xtables_error(PARAMETER_PROBLEM,
				      "Incrementing rule counters (%s) not allowed in daemon mode", argv[optind]);
		ret += 1;
		cs->counters.pcnt = strtoull(argv[optind] + 1, &buffer, 10);
	} else if (argv[optind][0] == '-') {
		if (exec_style == EXEC_STYLE_DAEMON)
daemon_decr:
			xtables_error(PARAMETER_PROBLEM,
				      "Decrementing rule counters (%s) not allowed in daemon mode", argv[optind]);
		ret += 2;
		cs->counters.pcnt = strtoull(argv[optind] + 1, &buffer, 10);
	} else
		cs->counters.pcnt = strtoull(argv[optind], &buffer, 10);

	if (*buffer != '\0')
		goto invalid;
	optind++;
	if (argv[optind][0] == '+') {
		if (exec_style == EXEC_STYLE_DAEMON)
			goto daemon_incr;
		ret += 3;
		cs->counters.bcnt = strtoull(argv[optind] + 1, &buffer, 10);
	} else if (argv[optind][0] == '-') {
		if (exec_style == EXEC_STYLE_DAEMON)
			goto daemon_decr;
		ret += 6;
		cs->counters.bcnt = strtoull(argv[optind] + 1, &buffer, 10);
	} else
		cs->counters.bcnt = strtoull(argv[optind], &buffer, 10);

	if (*buffer != '\0')
		goto invalid;
	optind++;
	return ret;
invalid:
	xtables_error(PARAMETER_PROBLEM,"Packet counter '%s' invalid", argv[optind]);
}

static int parse_iface(char *iface, char *option)
{
	char *c;

	if ((c = strchr(iface, '+'))) {
		if (*(c + 1) != '\0') {
			xtables_error(PARAMETER_PROBLEM,
				      "Spurious characters after '+' wildcard for '%s'", option);
			return -1;
		} else
			*c = IF_WILDCARD;
	}
	return 0;
}

/* We use exec_style instead of #ifdef's because ebtables.so is a shared object. */
int do_commandeb(struct nft_handle *h, int argc, char *argv[], char **table)
{
	char *buffer;
	int c, i;
	int zerochain = -1; /* Needed for the -Z option (we can have -Z <this> -L <that>) */
	int chcounter = 0; /* Needed for -C */
	int rule_nr = 0;
	int rule_nr_end = 0;
	int ret = 0;
	unsigned int flags = 0;
	struct xtables_target *t;
	struct ebtables_command_state cs;
	char command = 'h';
	const char *chain = NULL;
	const char *policy = NULL;
	int exec_style = EXEC_STYLE_PRG;
	int selected_chain = -1;

	memset(&cs, 0, sizeof(cs));

	if (nft_init(h, xtables_bridge) < 0)
		xtables_error(OTHER_PROBLEM,
			      "Could not initialize nftables layer.");

	h->ops = nft_family_ops_lookup(h->family);
	if (h->ops == NULL)
		xtables_error(PARAMETER_PROBLEM, "Unknown family");

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}

	/* Getopt saves the day */
	while ((c = getopt_long(argc, argv,
	   "-A:D:C:I:N:E:X::L::Z::F::P:Vhi:o:j:c:p:s:d:t:M:", ebt_options, NULL)) != -1) {
		switch (c) {

		case 'A': /* Add a rule */
		case 'D': /* Delete a rule */
		case 'C': /* Change counters */
		case 'P': /* Define policy */
		case 'I': /* Insert a rule */
		case 'N': /* Make a user defined chain */
		case 'E': /* Rename chain */
		case 'X': /* Delete chain */
			/* We allow -N chainname -P policy */
			/* XXX: Not in ebtables-compat */
			if (command == 'N' && c == 'P') {
				command = c;
				optind--; /* No table specified */
				goto handle_P;
			}
			if (OPT_COMMANDS)
				xtables_error(PARAMETER_PROBLEM,
					      "Multiple commands are not allowed");

			command = c;
			chain = optarg;
			selected_chain = get_current_chain(chain);
			flags |= OPT_COMMAND;
			/*if (!(replace->flags & OPT_KERNELDATA))
				ebt_get_kernel_table(replace, 0);*/
			/*if (optarg && (optarg[0] == '-' || !strcmp(optarg, "!")))
				ebt_print_error2("No chain name specified");*/
			if (c == 'N') {
				ret = nft_chain_user_add(h, chain, *table);
				break;
			} else if (c == 'X') {
				ret = nft_chain_user_del(h, chain, *table);
				break;
			}

			if (c == 'E') {
				if (optind >= argc)
					xtables_error(PARAMETER_PROBLEM, "No new chain name specified");
				else if (optind < argc - 1)
					xtables_error(PARAMETER_PROBLEM, "No extra options allowed with -E");
				else if (strlen(argv[optind]) >= NFT_CHAIN_MAXNAMELEN)
					xtables_error(PARAMETER_PROBLEM, "Chain name length can't exceed %d"" characters", NFT_CHAIN_MAXNAMELEN - 1);
				else if (strchr(argv[optind], ' ') != NULL)
					xtables_error(PARAMETER_PROBLEM, "Use of ' ' not allowed in chain names");

				ret = nft_chain_user_rename(h, chain, *table,
							    argv[optind]);
				if (ret != 0 && errno == ENOENT)
					xtables_error(PARAMETER_PROBLEM, "Chain '%s' doesn't exists", chain);

				optind++;
				break;
			} else if (c == 'D' && optind < argc && (argv[optind][0] != '-' || (argv[optind][1] >= '0' && argv[optind][1] <= '9'))) {
				if (optind != argc - 1)
					xtables_error(PARAMETER_PROBLEM,
							 "No extra options allowed with -D start_nr[:end_nr]");
				if (parse_rule_range(argv[optind], &rule_nr, &rule_nr_end))
					xtables_error(PARAMETER_PROBLEM,
							 "Problem with the specified rule number(s) '%s'", argv[optind]);
				optind++;
			} else if (c == 'C') {
				if ((chcounter = parse_change_counters_rule(argc, argv, &rule_nr, &rule_nr_end, exec_style, &cs)) == -1)
					return -1;
			} else if (c == 'I') {
				if (optind >= argc || (argv[optind][0] == '-' && (argv[optind][1] < '0' || argv[optind][1] > '9')))
					rule_nr = 1;
				else {
					rule_nr = parse_rule_number(argv[optind]);
					optind++;
				}
			} else if (c == 'P') {
handle_P:
				if (optind >= argc)
					xtables_error(PARAMETER_PROBLEM,
						      "No policy specified");
				for (i = 0; i < NUM_STANDARD_TARGETS; i++)
					if (!strcmp(argv[optind], ebt_standard_targets[i])) {
						policy = argv[optind];
						if (-i-1 == EBT_CONTINUE)
							xtables_error(PARAMETER_PROBLEM,
								      "Wrong policy '%s'",
								      argv[optind]);
						break;
					}
				if (i == NUM_STANDARD_TARGETS)
					xtables_error(PARAMETER_PROBLEM,
						      "Unknown policy '%s'", argv[optind]);
				optind++;
			}
			break;
		case 'L': /* List */
		case 'F': /* Flush */
		case 'Z': /* Zero counters */
			if (c == 'Z') {
				if ((flags & OPT_ZERO) || (flags & OPT_COMMAND && command != 'L'))
print_zero:
					xtables_error(PARAMETER_PROBLEM,
						      "Command -Z only allowed together with command -L");
				flags |= OPT_ZERO;
			} else {
				if (flags & OPT_COMMAND)
					xtables_error(PARAMETER_PROBLEM,
						      "Multiple commands are not allowed");
				command = c;
				flags |= OPT_COMMAND;
				if (flags & OPT_ZERO && c != 'L')
					goto print_zero;
			}

#ifdef SILENT_DAEMON
			if (c== 'L' && exec_style == EXEC_STYLE_DAEMON)
				xtables_error(PARAMETER_PROBLEM,
					      "-L not supported in daemon mode");
#endif

			/*if (!(replace->flags & OPT_KERNELDATA))
				ebt_get_kernel_table(replace, 0);
			i = -1;
			if (optind < argc && argv[optind][0] != '-') {
				if ((i = ebt_get_chainnr(replace, argv[optind])) == -1)
					ebt_print_error2("Chain '%s' doesn't exist", argv[optind]);
				optind++;
			}
			if (i != -1) {
				if (c == 'Z')
					zerochain = i;
				else
					replace->selected_chain = i;
			}*/
			break;
		case 'V': /* Version */
			if (OPT_COMMANDS)
				xtables_error(PARAMETER_PROBLEM,
					      "Multiple commands are not allowed");
			command = 'V';
			if (exec_style == EXEC_STYLE_DAEMON)
				xtables_error(PARAMETER_PROBLEM,
					      "%s %s\n", prog_name, prog_vers);
			printf("%s %s\n", prog_name, prog_vers);
			exit(0);
		case 'h': /* Help */
#ifdef SILENT_DAEMON
			if (exec_style == EXEC_STYLE_DAEMON)
				xtables_error(PARAMETER_PROBLEM,
					      "-h not supported in daemon mode");
#endif
			if (OPT_COMMANDS)
				xtables_error(PARAMETER_PROBLEM,
					      "Multiple commands are not allowed");
			command = 'h';

			/* All other arguments should be extension names */
			while (optind < argc) {
				/*struct ebt_u_match *m;
				struct ebt_u_watcher *w;*/

				if (!strcasecmp("list_extensions", argv[optind])) {
					ebt_list_extensions(xtables_targets, cs.matches);
					exit(0);
				}
				/*if ((m = ebt_find_match(argv[optind])))
					ebt_add_match(new_entry, m);
				else if ((w = ebt_find_watcher(argv[optind])))
					ebt_add_watcher(new_entry, w);
				else {*/
					if (!(t = xtables_find_target(argv[optind], XTF_TRY_LOAD)))
						xtables_error(PARAMETER_PROBLEM,"Extension '%s' not found", argv[optind]);
					if (flags & OPT_JUMP)
						xtables_error(PARAMETER_PROBLEM,"Sorry, you can only see help for one target extension at a time");
					flags |= OPT_JUMP;
					cs.target = t;
				//}
				optind++;
			}
			break;
		case 't': /* Table */
			if (OPT_COMMANDS)
				xtables_error(PARAMETER_PROBLEM,
					      "Please put the -t option first");
			ebt_check_option2(&flags, OPT_TABLE);
			if (strlen(optarg) > EBT_TABLE_MAXNAMELEN - 1)
				xtables_error(PARAMETER_PROBLEM,
					      "Table name length cannot exceed %d characters",
					      EBT_TABLE_MAXNAMELEN - 1);
			*table = optarg;
			break;
		case 'i': /* Input interface */
		case 2  : /* Logical input interface */
		case 'o': /* Output interface */
		case 3  : /* Logical output interface */
		case 'j': /* Target */
		case 'p': /* Net family protocol */
		case 's': /* Source mac */
		case 'd': /* Destination mac */
		case 'c': /* Set counters */
			if (!OPT_COMMANDS)
				xtables_error(PARAMETER_PROBLEM,
					      "No command specified");
			if (command != 'A' && command != 'D' && command != 'I' && command != 'C')
				xtables_error(PARAMETER_PROBLEM,
					      "Command and option do not match");
			if (c == 'i') {
				ebt_check_option2(&flags, OPT_IN);
				if (selected_chain > 2 && selected_chain < NF_BR_BROUTING)
					xtables_error(PARAMETER_PROBLEM,
						      "Use -i only in INPUT, FORWARD, PREROUTING and BROUTING chains");
				if (ebt_check_inverse2(optarg, argc, argv))
					cs.fw.invflags |= EBT_IIN;

				if (strlen(optarg) >= IFNAMSIZ)
big_iface_length:
					xtables_error(PARAMETER_PROBLEM,
						      "Interface name length cannot exceed %d characters",
						      IFNAMSIZ - 1);
				xtables_parse_interface(optarg, cs.fw.in, cs.fw.in_mask);
				break;
			} else if (c == 2) {
				ebt_check_option2(&flags, OPT_LOGICALIN);
				if (selected_chain > 2 && selected_chain < NF_BR_BROUTING)
					xtables_error(PARAMETER_PROBLEM,
						      "Use --logical-in only in INPUT, FORWARD, PREROUTING and BROUTING chains");
				if (ebt_check_inverse2(optarg, argc, argv))
					cs.fw.invflags |= EBT_ILOGICALIN;

				if (strlen(optarg) >= IFNAMSIZ)
					goto big_iface_length;
				strcpy(cs.fw.logical_in, optarg);
				if (parse_iface(cs.fw.logical_in, "--logical-in"))
					return -1;
				break;
			} else if (c == 'o') {
				ebt_check_option2(&flags, OPT_OUT);
				if (selected_chain < 2 || selected_chain == NF_BR_BROUTING)
					xtables_error(PARAMETER_PROBLEM,
						      "Use -o only in OUTPUT, FORWARD and POSTROUTING chains");
				if (ebt_check_inverse2(optarg, argc, argv))
					cs.fw.invflags |= EBT_IOUT;

				if (strlen(optarg) >= IFNAMSIZ)
					goto big_iface_length;

				xtables_parse_interface(optarg, cs.fw.out, cs.fw.out_mask);
				break;
			} else if (c == 3) {
				ebt_check_option2(&flags, OPT_LOGICALOUT);
				if (selected_chain < 2 || selected_chain == NF_BR_BROUTING)
					xtables_error(PARAMETER_PROBLEM,
						      "Use --logical-out only in OUTPUT, FORWARD and POSTROUTING chains");
				if (ebt_check_inverse2(optarg, argc, argv))
					cs.fw.invflags |= EBT_ILOGICALOUT;

				if (strlen(optarg) >= IFNAMSIZ)
					goto big_iface_length;
				strcpy(cs.fw.logical_out, optarg);
				if (parse_iface(cs.fw.logical_out, "--logical-out"))
					return -1;
				break;
			} else if (c == 'j') {
				ebt_check_option2(&flags, OPT_JUMP);
				cs.jumpto = parse_target(optarg);
				cs.target = command_jump(&cs, cs.jumpto);
				break;
			} else if (c == 's') {
				ebt_check_option2(&flags, OPT_SOURCE);
				if (ebt_check_inverse2(optarg, argc, argv))
					cs.fw.invflags |= EBT_ISOURCE;

				if (ebt_get_mac_and_mask(optarg, cs.fw.sourcemac, cs.fw.sourcemsk))
					xtables_error(PARAMETER_PROBLEM, "Problem with specified source mac '%s'", optarg);
				cs.fw.bitmask |= EBT_SOURCEMAC;
				break;
			} else if (c == 'd') {
				ebt_check_option2(&flags, OPT_DEST);
				if (ebt_check_inverse2(optarg, argc, argv))
					cs.fw.invflags |= EBT_IDEST;

				if (ebt_get_mac_and_mask(optarg, cs.fw.destmac, cs.fw.destmsk))
					xtables_error(PARAMETER_PROBLEM, "Problem with specified destination mac '%s'", optarg);
				cs.fw.bitmask |= EBT_DESTMAC;
				break;
			} else if (c == 'c') {
				ebt_check_option2(&flags, OPT_COUNT);
				if (ebt_check_inverse2(optarg, argc, argv))
					xtables_error(PARAMETER_PROBLEM,
						      "Unexpected '!' after -c");
				if (optind >= argc || optarg[0] == '-' || argv[optind][0] == '-')
					xtables_error(PARAMETER_PROBLEM,
						      "Option -c needs 2 arguments");

				cs.counters.pcnt = strtoull(optarg, &buffer, 10);
				if (*buffer != '\0')
					xtables_error(PARAMETER_PROBLEM,
						      "Packet counter '%s' invalid",
						      optarg);
				cs.counters.bcnt = strtoull(argv[optind], &buffer, 10);
				if (*buffer != '\0')
					xtables_error(PARAMETER_PROBLEM,
						      "Packet counter '%s' invalid",
						      argv[optind]);
				optind++;
				break;
			}
			ebt_check_option2(&flags, OPT_PROTOCOL);
			if (ebt_check_inverse2(optarg, argc, argv))
				cs.fw.invflags |= EBT_IPROTO;

			cs.fw.bitmask &= ~((unsigned int)EBT_NOPROTO);
			i = strtol(optarg, &buffer, 16);
			if (*buffer == '\0' && (i < 0 || i > 0xFFFF))
				xtables_error(PARAMETER_PROBLEM,
					      "Problem with the specified protocol");
			if (*buffer != '\0') {
				struct ethertypeent *ent;

				if (!strcasecmp(optarg, "LENGTH")) {
					cs.fw.bitmask |= EBT_802_3;
					break;
				}
				ent = getethertypebyname(optarg);
				if (!ent)
					xtables_error(PARAMETER_PROBLEM,
						      "Problem with the specified Ethernet protocol '%s', perhaps "_PATH_ETHERTYPES " is missing", optarg);
				cs.fw.ethproto = ent->e_ethertype;
			} else
				cs.fw.ethproto = i;

			if (cs.fw.ethproto < 0x0600)
				xtables_error(PARAMETER_PROBLEM,
					      "Sorry, protocols have values above or equal to 0x0600");
			break;
		case 4  : /* Lc */
#ifdef SILENT_DAEMON
			if (exec_style == EXEC_STYLE_DAEMON)
				xtables_error(PARAMETER_PROBLEM,
					      "--Lc is not supported in daemon mode");
#endif
			ebt_check_option2(&flags, LIST_C);
			if (command != 'L')
				xtables_error(PARAMETER_PROBLEM,
					      "Use --Lc with -L");
			flags |= LIST_C;
			break;
		case 5  : /* Ln */
#ifdef SILENT_DAEMON
			if (exec_style == EXEC_STYLE_DAEMON)
				xtables_error(PARAMETER_PROBLEM,
					      "--Ln is not supported in daemon mode");
#endif
			ebt_check_option2(&flags, LIST_N);
			if (command != 'L')
				xtables_error(PARAMETER_PROBLEM,
					      "Use --Ln with -L");
			if (flags & LIST_X)
				xtables_error(PARAMETER_PROBLEM,
					      "--Lx is not compatible with --Ln");
			flags |= LIST_N;
			break;
		case 6  : /* Lx */
#ifdef SILENT_DAEMON
			if (exec_style == EXEC_STYLE_DAEMON)
				xtables_error(PARAMETER_PROBLEM,
					      "--Lx is not supported in daemon mode");
#endif
			ebt_check_option2(&flags, LIST_X);
			if (command != 'L')
				xtables_error(PARAMETER_PROBLEM,
					      "Use --Lx with -L");
			if (flags & LIST_N)
				xtables_error(PARAMETER_PROBLEM,
					      "--Lx is not compatible with --Ln");
			flags |= LIST_X;
			break;
		case 12 : /* Lmac2 */
#ifdef SILENT_DAEMON
			if (exec_style == EXEC_STYLE_DAEMON)
				xtables_error(PARAMETER_PROBLEM,
					      "--Lmac2 is not supported in daemon mode");
#endif
			ebt_check_option2(&flags, LIST_MAC2);
			if (command != 'L')
				xtables_error(PARAMETER_PROBLEM,
					       "Use --Lmac2 with -L");
			flags |= LIST_MAC2;
			break;
		case 8 : /* atomic-commit */
/*			if (exec_style == EXEC_STYLE_DAEMON)
				ebt_print_error2("--atomic-commit is not supported in daemon mode");
			replace->command = c;
			if (OPT_COMMANDS)
				ebt_print_error2("Multiple commands are not allowed");
			replace->flags |= OPT_COMMAND;
			if (!replace->filename)
				ebt_print_error2("No atomic file specified");*/
			/* Get the information from the file */
			/*ebt_get_table(replace, 0);*/
			/* We don't want the kernel giving us its counters,
			 * they would overwrite the counters extracted from
			 * the file */
			/*replace->num_counters = 0;*/
			/* Make sure the table will be written to the kernel */
			/*free(replace->filename);
			replace->filename = NULL;
			break;*/
		/*case 7 :*/ /* atomic-init */
		/*case 10:*/ /* atomic-save */
		/*case 11:*/ /* init-table */
		/*	if (exec_style == EXEC_STYLE_DAEMON) {
				if (c == 7) {
					ebt_print_error2("--atomic-init is not supported in daemon mode");
				} else if (c == 10)
					ebt_print_error2("--atomic-save is not supported in daemon mode");
				ebt_print_error2("--init-table is not supported in daemon mode");
			}
			replace->command = c;
			if (OPT_COMMANDS)
				ebt_print_error2("Multiple commands are not allowed");
			if (c != 11 && !replace->filename)
				ebt_print_error2("No atomic file specified");
			replace->flags |= OPT_COMMAND;
			{
				char *tmp = replace->filename;*/

				/* Get the kernel table */
				/*replace->filename = NULL;
				ebt_get_kernel_table(replace, c == 10 ? 0 : 1);
				replace->filename = tmp;
			}
			break;
		case 9 :*/ /* atomic */
			/*if (exec_style == EXEC_STYLE_DAEMON)
				ebt_print_error2("--atomic is not supported in daemon mode");
			if (OPT_COMMANDS)
				ebt_print_error2("--atomic has to come before the command");*/
			/* A possible memory leak here, but this is not
			 * executed in daemon mode */
			/*replace->filename = (char *)malloc(strlen(optarg) + 1);
			strcpy(replace->filename, optarg);
			break;
		case 13 : *//* concurrent */
			/*signal(SIGINT, sighandler);
			signal(SIGTERM, sighandler);
			use_lockfd = 1;
			break;*/
		case 1 :
			if (!strcmp(optarg, "!"))
				ebt_check_inverse2(optarg, argc, argv);
			else
				xtables_error(PARAMETER_PROBLEM,
					      "Bad argument : '%s'", optarg);
			/* ebt_ebt_check_inverse2() did optind++ */
			optind--;
			continue;
		default:
			/* Is it a target option? */
			/*t = (struct ebt_u_target *)new_entry->t;
			if ((t->parse(c - t->option_offset, argv, argc, new_entry, &t->flags, &t->t))) {
				if (ebt_errormsg[0] != '\0')
					return -1;
				goto check_extension;
			}*/

			/* Is it a match_option? */
			/*for (m = ebt_matches; m; m = m->next)
				if (m->parse(c - m->option_offset, argv, argc, new_entry, &m->flags, &m->m))
					break;

			if (m != NULL) {
				if (ebt_errormsg[0] != '\0')
					return -1;
				if (m->used == 0) {
					ebt_add_match(new_entry, m);
					m->used = 1;
				}
				goto check_extension;
			}*/

			/* Is it a watcher option? */
			/*for (w = ebt_watchers; w; w = w->next)
				if (w->parse(c - w->option_offset, argv, argc, new_entry, &w->flags, &w->w))
					break;

			if (w == NULL && c == '?')
				ebt_print_error2("Unknown argument: '%s'", argv[optind - 1], (char)optopt, (char)c);
			else if (w == NULL) {
				if (!strcmp(t->name, "standard"))
					ebt_print_error2("Unknown argument: don't forget the -t option");
				else
					ebt_print_error2("Target-specific option does not correspond with specified target");
			}
			if (ebt_errormsg[0] != '\0')
				return -1;
			if (w->used == 0) {
				ebt_add_watcher(new_entry, w);
				w->used = 1;
			}
check_extension: */
			if (command != 'A' && command != 'I' &&
			    command != 'D' && command != 'C')
				xtables_error(PARAMETER_PROBLEM,
					      "Extensions only for -A, -I, -D and -C");
		}
		ebt_invert = 0;
	}

	/* Just in case we didn't catch an error */
	/*if (ebt_errormsg[0] != '\0')
		return -1;

	if (!(table = ebt_find_table(replace->name)))
		ebt_print_error2("Bad table name");*/

	if (command == 'h' && !(flags & OPT_ZERO)) {
		print_help(cs.target, cs.matches, *table);
		if (exec_style == EXEC_STYLE_PRG)
			exit(0);
	}

	/* Do the final checks */
	/*if (replace->command == 'A' || replace->command == 'I' ||
	   replace->command == 'D' || replace->command == 'C') {*/
		/* This will put the hook_mask right for the chains */
		/*ebt_check_for_loops(replace);
		if (ebt_errormsg[0] != '\0')
			return -1;
		entries = ebt_to_chain(replace);
		m_l = new_entry->m_list;
		w_l = new_entry->w_list;
		t = (struct ebt_u_target *)new_entry->t;
		while (m_l) {
			m = (struct ebt_u_match *)(m_l->m);
			m->final_check(new_entry, m->m, replace->name,
			   entries->hook_mask, 0);
			if (ebt_errormsg[0] != '\0')
				return -1;
			m_l = m_l->next;
		}
		while (w_l) {
			w = (struct ebt_u_watcher *)(w_l->w);
			w->final_check(new_entry, w->w, replace->name,
			   entries->hook_mask, 0);
			if (ebt_errormsg[0] != '\0')
				return -1;
			w_l = w_l->next;
		}
		t->final_check(new_entry, t->t, replace->name,
		   entries->hook_mask, 0);
		if (ebt_errormsg[0] != '\0')
			return -1;
	}*/
	/* So, the extensions can work with the host endian.
	 * The kernel does not have to do this of course */
	cs.fw.ethproto = htons(cs.fw.ethproto);

	if (command == 'P') {
		if (selected_chain < 0) {
			xtables_error(PARAMETER_PROBLEM,
				      "Policy %s not allowed for user defined chains",
				      policy);
		}
		if (strcmp(policy, "RETURN") == 0) {
			xtables_error(PARAMETER_PROBLEM,
				      "Policy RETURN only allowed for user defined chains");
		}
		ret = nft_chain_set(h, *table, chain, policy, NULL);
		if (ret < 0)
			xtables_error(PARAMETER_PROBLEM, "Wrong policy");
	} else if (command == 'L') {
		ret = list_rules(h, chain, *table, rule_nr,
				 flags&OPT_VERBOSE,
				 flags&OPT_NUMERIC,
				 /*flags&OPT_EXPANDED*/0,
				 flags&LIST_N);
		if (!(flags & OPT_ZERO) && exec_style == EXEC_STYLE_PRG)
			exit(0);
	}
	if (flags & OPT_ZERO) {
		selected_chain = zerochain;
		ret = nft_chain_zero_counters(h, chain, *table);
	} else if (command == 'F') {
		ret = nft_rule_flush(h, chain, *table);
	} else if (command == 'A') {
		ret = append_entry(h, chain, *table, &cs, 0,
				   flags&OPT_VERBOSE, true);
	} else if (command == 'I') {
		ret = append_entry(h, chain, *table, &cs, rule_nr - 1,
				   flags&OPT_VERBOSE, false);
	} else if (command == 'D') {
		ret = delete_entry(h, chain, *table, &cs, rule_nr - 1,
				   rule_nr_end, flags&OPT_VERBOSE);
	} /*else if (replace->command == 'C') {
		ebt_change_counters(replace, new_entry, rule_nr, rule_nr_end, &(new_entry->cnt_surplus), chcounter);
		if (ebt_errormsg[0] != '\0')
			return -1;
	}*/
	/* Commands -N, -E, -X, --atomic-commit, --atomic-commit, --atomic-save,
	 * --init-table fall through */

	/*if (ebt_errormsg[0] != '\0')
		return -1;
	if (table->check)
		table->check(replace);

	if (exec_style == EXEC_STYLE_PRG) {*//* Implies ebt_errormsg[0] == '\0' */
		/*ebt_deliver_table(replace);

		if (replace->nentries)
			ebt_deliver_counters(replace);*/
	return ret;
}
