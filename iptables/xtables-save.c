/* Code to save the xtables state, in human readable-form. */
/* (C) 1999 by Paul 'Rusty' Russell <rusty@rustcorp.com.au> and
 * (C) 2000-2002 by Harald Welte <laforge@gnumonks.org>
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This code is distributed under the terms of GNU GPL v2
 *
 */
#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include "libiptc/libiptc.h"
#include "iptables.h"
#include "xtables-multi.h"
#include "nft.h"

#include <libnftnl/chain.h>

#ifndef NO_SHARED_LIBS
#include <dlfcn.h>
#endif

static bool show_counters = false;

static const struct option options[] = {
	{.name = "counters", .has_arg = false, .val = 'c'},
	{.name = "dump",     .has_arg = false, .val = 'd'},
	{.name = "table",    .has_arg = true,  .val = 't'},
	{.name = "modprobe", .has_arg = true,  .val = 'M'},
	{.name = "file",     .has_arg = true,  .val = 'f'},
	{.name = "ipv4",     .has_arg = false, .val = '4'},
	{.name = "ipv6",     .has_arg = false, .val = '6'},
	{NULL},
};

static int
do_output(struct nft_handle *h, const char *tablename, bool counters)
{
	struct nftnl_chain_list *chain_list;

	if (!tablename)
		return nft_for_each_table(h, do_output, counters) ? 1 : 0;

	if (!nft_table_find(h, tablename)) {
		printf("Table `%s' does not exist\n", tablename);
		return 1;
	}

	if (!nft_is_table_compatible(h, tablename)) {
		printf("# Table `%s' is incompatible, use 'nft' tool.\n", tablename);
		return 0;
	}

	chain_list = nft_chain_dump(h);

	time_t now = time(NULL);

	printf("# Generated by xtables-save v%s on %s",
	       IPTABLES_VERSION, ctime(&now));
	printf("*%s\n", tablename);

	/* Dump out chain names first,
	 * thereby preventing dependency conflicts */
	nft_chain_save(h, chain_list, tablename);
	nft_rule_save(h, tablename, counters);

	now = time(NULL);
	printf("COMMIT\n");
	printf("# Completed on %s", ctime(&now));
	return 0;
}

/* Format:
 * :Chain name POLICY packets bytes
 * rule
 */
static int
xtables_save_main(int family, const char *progname, int argc, char *argv[])
{
	struct builtin_table *tables;
	const char *tablename = NULL;
	bool dump = false;
	struct nft_handle h = {
		.family	= family,
	};
	FILE *file = NULL;
	int ret, c;

	xtables_globals.program_name = progname;
	c = xtables_init_all(&xtables_globals, family);
	if (c < 0) {
		fprintf(stderr, "%s/%s Failed to initialize xtables\n",
				xtables_globals.program_name,
				xtables_globals.program_version);
		exit(1);
	}

	while ((c = getopt_long(argc, argv, "bcdt:M:f:46", options, NULL)) != -1) {
		switch (c) {
		case 'b':
			fprintf(stderr, "-b/--binary option is not implemented\n");
			break;
		case 'c':
			show_counters = true;
			break;

		case 't':
			/* Select specific table. */
			tablename = optarg;
			break;
		case 'M':
			xtables_modprobe_program = optarg;
			break;
		case 'f':
			file = fopen(optarg, "w");
			if (file == NULL) {
				fprintf(stderr, "Failed to open file, error: %s\n",
					strerror(errno));
				exit(1);
			}
			ret = dup2(fileno(file), STDOUT_FILENO);
			if (ret == -1) {
				fprintf(stderr, "Failed to redirect stdout, error: %s\n",
					strerror(errno));
				exit(1);
			}
			fclose(file);
			break;
		case 'd':
			dump = true;
			break;
		case '4':
			h.family = AF_INET;
			break;
		case '6':
			h.family = AF_INET6;
			xtables_set_nfproto(AF_INET6);
			break;
		default:
			fprintf(stderr,
				"Look at manual page `xtables-save.8' for more information.\n");
			exit(1);
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Unknown arguments found on commandline\n");
		exit(1);
	}

	switch (family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6: /* fallthough, same table */
#if defined(ALL_INCLUSIVE) || defined(NO_SHARED_LIBS)
		init_extensions();
		init_extensions4();
#endif
		tables = xtables_ipv4;
		break;
	case NFPROTO_ARP:
		tables = xtables_arp;
		break;
	case NFPROTO_BRIDGE:
		tables = xtables_bridge;
		break;
	default:
		fprintf(stderr, "Unknown family %d\n", family);
		return 1;
	}

	if (nft_init(&h, tables) < 0) {
		fprintf(stderr, "%s/%s Failed to initialize nft: %s\n",
				xtables_globals.program_name,
				xtables_globals.program_version,
				strerror(errno));
		exit(EXIT_FAILURE);
	}


	ret = nft_is_ruleset_compatible(&h);
	if (ret) {
		printf("ERROR: You're using nft features that cannot be mapped to iptables, please keep using nft.\n");
		exit(EXIT_FAILURE);
	}

	if (dump) {
		do_output(&h, tablename, show_counters);
		exit(0);
	}

	return do_output(&h, tablename, show_counters);
}

int xtables_ip4_save_main(int argc, char *argv[])
{
	return xtables_save_main(NFPROTO_IPV4, "iptables-save", argc, argv);
}

int xtables_ip6_save_main(int argc, char *argv[])
{
	return xtables_save_main(NFPROTO_IPV6, "ip6tables-save", argc, argv);
}
