/* Shared library add-on to ip6tables to add MAC address checking support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#if defined(__GLIBC__) && __GLIBC__ == 2
#include <net/ethernet.h>
#else
#include <linux/if_ether.h>
#endif
#include <ip6tables.h>

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"AGR v%s options:\n"
" This module hasn't got any option\n"
" This module checks for aggregated IPv6 addresses\n"
"\n", NETFILTER_VERSION);
}

static struct option opts[] = {
	{0}
};

/* Initialize the match. */
static void
init(struct ip6t_entry_match *m, unsigned int *nfcache)
{
	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ip6t_entry *entry,
      unsigned int *nfcache,
      struct ip6t_entry_match **match)
{
	return 0;
}

/* Final check */
static void final_check(unsigned int flags)
{
}

/* Prints out the matchinfo. */
static void
print(const struct ip6t_ip6 *ip,
      const struct ip6t_entry_match *match,
      int numeric)
{
	printf("AGR ");
}

/* Saves the union ip6t_matchinfo in parsable form to stdout. */
static void save(const struct ip6t_ip6 *ip, const struct ip6t_entry_match *match)
{
	/* printf("--agr "); */
}

static
struct ip6tables_match agr
= { NULL,
    "agr",
    NETFILTER_VERSION,
    IP6T_ALIGN(sizeof(int)),
    IP6T_ALIGN(sizeof(int)),
    &help,
    &init,
    &parse,
    &final_check,
    &print,
    &save,
    opts
};

void _init(void)
{
	register_match6(&agr);
}
