/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <errno.h>
#include <netdb.h>	/* getprotobynumber */
#include <time.h>
#include <stdarg.h>
#include <inttypes.h>
#include <assert.h>

#include <xtables.h>
#include <libiptc/libxtc.h>
#include <libiptc/xtcshared.h>

#include <stdlib.h>
#include <string.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <netinet/ip6.h>

#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>

#include <linux/netfilter/xt_limit.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <libnftnl/udata.h>
#include <libnftnl/batch.h>

#include <netinet/in.h>	/* inet_ntoa */
#include <arpa/inet.h>

#include "nft.h"
#include "xshared.h" /* proto_to_name */
#include "nft-shared.h"
#include "xtables-config-parser.h"

static void *nft_fn;

int mnl_talk(struct nft_handle *h, struct nlmsghdr *nlh,
	     int (*cb)(const struct nlmsghdr *nlh, void *data),
	     void *data)
{
	int ret;
	char buf[16536];

	if (mnl_socket_sendto(h->nl, nlh, nlh->nlmsg_len) < 0)
		return -1;

	ret = mnl_socket_recvfrom(h->nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, h->seq, h->portid, cb, data);
		if (ret <= 0)
			break;

		ret = mnl_socket_recvfrom(h->nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		return -1;
	}

	return 0;
}

#define NFT_NLMSG_MAXSIZE (UINT16_MAX + getpagesize())

/* selected batch page is 256 Kbytes long to load ruleset of
 * half a million rules without hitting -EMSGSIZE due to large
 * iovec.
 */
#define BATCH_PAGE_SIZE getpagesize() * 32

static struct nftnl_batch *mnl_batch_init(void)
{
	struct nftnl_batch *batch;

	batch = nftnl_batch_alloc(BATCH_PAGE_SIZE, NFT_NLMSG_MAXSIZE);
	if (batch == NULL)
		return NULL;

	return batch;
}

static void mnl_nft_batch_continue(struct nftnl_batch *batch)
{
	assert(nftnl_batch_update(batch) >= 0);
}

static uint32_t mnl_batch_begin(struct nftnl_batch *batch, uint32_t seqnum)
{
	nftnl_batch_begin(nftnl_batch_buffer(batch), seqnum);
	mnl_nft_batch_continue(batch);

	return seqnum;
}

static void mnl_batch_end(struct nftnl_batch *batch, uint32_t seqnum)
{
	nftnl_batch_end(nftnl_batch_buffer(batch), seqnum);
	mnl_nft_batch_continue(batch);
}

static void mnl_batch_reset(struct nftnl_batch *batch)
{
	nftnl_batch_free(batch);
}

struct mnl_err {
	struct list_head	head;
	int			err;
	uint32_t		seqnum;
};

static void mnl_err_list_node_add(struct list_head *err_list, int error,
				  int seqnum)
{
	struct mnl_err *err = malloc(sizeof(struct mnl_err));

	err->seqnum = seqnum;
	err->err = error;
	list_add_tail(&err->head, err_list);
}

static void mnl_err_list_free(struct mnl_err *err)
{
	list_del(&err->head);
	free(err);
}

static int nlbuffsiz;

static void mnl_set_sndbuffer(const struct mnl_socket *nl,
			      struct nftnl_batch *batch)
{
	int newbuffsiz;

	if (nftnl_batch_iovec_len(batch) * BATCH_PAGE_SIZE <= nlbuffsiz)
		return;

	newbuffsiz = nftnl_batch_iovec_len(batch) * BATCH_PAGE_SIZE;

	/* Rise sender buffer length to avoid hitting -EMSGSIZE */
	if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_SNDBUFFORCE,
		       &newbuffsiz, sizeof(socklen_t)) < 0)
		return;

	nlbuffsiz = newbuffsiz;
}

static ssize_t mnl_nft_socket_sendmsg(const struct mnl_socket *nf_sock,
				      struct nftnl_batch *batch)
{
	static const struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK
	};
	uint32_t iov_len = nftnl_batch_iovec_len(batch);
	struct iovec iov[iov_len];
	struct msghdr msg = {
		.msg_name	= (struct sockaddr *) &snl,
		.msg_namelen	= sizeof(snl),
		.msg_iov	= iov,
		.msg_iovlen	= iov_len,
	};

	mnl_set_sndbuffer(nf_sock, batch);
	nftnl_batch_iovec(batch, iov, iov_len);

	return sendmsg(mnl_socket_get_fd(nf_sock), &msg, 0);
}

static int mnl_batch_talk(const struct mnl_socket *nf_sock,
			  struct nftnl_batch *batch, struct list_head *err_list)
{
	const struct mnl_socket *nl = nf_sock;
	int ret, fd = mnl_socket_get_fd(nl), portid = mnl_socket_get_portid(nl);
	char rcv_buf[MNL_SOCKET_BUFFER_SIZE];
	fd_set readfds;
	struct timeval tv = {
		.tv_sec		= 0,
		.tv_usec	= 0
	};
	int err = 0;

	ret = mnl_nft_socket_sendmsg(nf_sock, batch);
	if (ret == -1)
		return -1;

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	/* receive and digest all the acknowledgments from the kernel. */
	ret = select(fd+1, &readfds, NULL, NULL, &tv);
	if (ret == -1)
		return -1;

	while (ret > 0 && FD_ISSET(fd, &readfds)) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)rcv_buf;

		ret = mnl_socket_recvfrom(nl, rcv_buf, sizeof(rcv_buf));
		if (ret == -1)
			return -1;

		ret = mnl_cb_run(rcv_buf, ret, 0, portid, NULL, NULL);
		/* Continue on error, make sure we get all acknowledgments */
		if (ret == -1) {
			mnl_err_list_node_add(err_list, errno, nlh->nlmsg_seq);
			err = -1;
		}

		ret = select(fd+1, &readfds, NULL, NULL, &tv);
		if (ret == -1)
			return -1;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
	}
	return err;
}

enum obj_update_type {
	NFT_COMPAT_TABLE_ADD,
	NFT_COMPAT_TABLE_FLUSH,
	NFT_COMPAT_CHAIN_ADD,
	NFT_COMPAT_CHAIN_USER_ADD,
	NFT_COMPAT_CHAIN_USER_DEL,
	NFT_COMPAT_CHAIN_USER_FLUSH,
	NFT_COMPAT_CHAIN_UPDATE,
	NFT_COMPAT_CHAIN_RENAME,
	NFT_COMPAT_CHAIN_ZERO,
	NFT_COMPAT_RULE_APPEND,
	NFT_COMPAT_RULE_INSERT,
	NFT_COMPAT_RULE_REPLACE,
	NFT_COMPAT_RULE_DELETE,
	NFT_COMPAT_RULE_FLUSH,
};

enum obj_action {
	NFT_COMPAT_COMMIT,
	NFT_COMPAT_ABORT,
};

struct obj_update {
	struct list_head	head;
	enum obj_update_type	type;
	unsigned int		seq;
	union {
		struct nftnl_table	*table;
		struct nftnl_chain	*chain;
		struct nftnl_rule	*rule;
		void			*ptr;
	};
	struct {
		unsigned int		lineno;
	} error;
};

static int mnl_append_error(const struct nft_handle *h,
			    const struct obj_update *o,
			    const struct mnl_err *err,
			    char *buf, unsigned int len)
{
	static const char *type_name[] = {
		[NFT_COMPAT_TABLE_ADD] = "TABLE_ADD",
		[NFT_COMPAT_TABLE_FLUSH] = "TABLE_FLUSH",
		[NFT_COMPAT_CHAIN_ADD] = "CHAIN_ADD",
		[NFT_COMPAT_CHAIN_USER_ADD] = "CHAIN_USER_ADD",
		[NFT_COMPAT_CHAIN_USER_DEL] = "CHAIN_USER_DEL",
		[NFT_COMPAT_CHAIN_USER_FLUSH] = "CHAIN_USER_FLUSH",
		[NFT_COMPAT_CHAIN_UPDATE] = "CHAIN_UPDATE",
		[NFT_COMPAT_CHAIN_RENAME] = "CHAIN_RENAME",
		[NFT_COMPAT_RULE_APPEND] = "RULE_APPEND",
		[NFT_COMPAT_RULE_INSERT] = "RULE_INSERT",
		[NFT_COMPAT_RULE_REPLACE] = "RULE_REPLACE",
		[NFT_COMPAT_RULE_DELETE] = "RULE_DELETE",
		[NFT_COMPAT_RULE_FLUSH] = "RULE_FLUSH",
	};
	char errmsg[256];
	char tcr[128];

	if (o->error.lineno)
		snprintf(errmsg, sizeof(errmsg), "\nline %u: %s failed (%s)",
			 o->error.lineno, type_name[o->type], strerror(err->err));
	else
		snprintf(errmsg, sizeof(errmsg), " %s failed (%s)",
			 type_name[o->type], strerror(err->err));

	switch (o->type) {
	case NFT_COMPAT_TABLE_ADD:
	case NFT_COMPAT_TABLE_FLUSH:
		snprintf(tcr, sizeof(tcr), "table %s",
			 nftnl_table_get_str(o->table, NFTNL_TABLE_NAME));
		break;
	case NFT_COMPAT_CHAIN_ADD:
	case NFT_COMPAT_CHAIN_ZERO:
	case NFT_COMPAT_CHAIN_USER_ADD:
	case NFT_COMPAT_CHAIN_USER_DEL:
	case NFT_COMPAT_CHAIN_USER_FLUSH:
	case NFT_COMPAT_CHAIN_UPDATE:
	case NFT_COMPAT_CHAIN_RENAME:
		snprintf(tcr, sizeof(tcr), "chain %s",
			 nftnl_chain_get_str(o->chain, NFTNL_CHAIN_NAME));
		break;
	case NFT_COMPAT_RULE_APPEND:
	case NFT_COMPAT_RULE_INSERT:
	case NFT_COMPAT_RULE_REPLACE:
	case NFT_COMPAT_RULE_DELETE:
	case NFT_COMPAT_RULE_FLUSH:
		snprintf(tcr, sizeof(tcr), "rule in chain %s",
			 nftnl_rule_get_str(o->rule, NFTNL_RULE_CHAIN));
#if 0
		{
			nft_rule_print_save(o->rule, NFT_RULE_APPEND, FMT_NOCOUNTS);
		}
#endif
		break;
	}

	return snprintf(buf, len, "%s: %s", errmsg, tcr);
}

static int batch_add(struct nft_handle *h, enum obj_update_type type, void *ptr)
{
	struct obj_update *obj;

	obj = calloc(1, sizeof(struct obj_update));
	if (obj == NULL)
		return -1;

	obj->ptr = ptr;
	obj->error.lineno = h->error.lineno;
	obj->type = type;
	list_add_tail(&obj->head, &h->obj_list);
	h->obj_list_num++;

	return 0;
}

static int batch_table_add(struct nft_handle *h, enum obj_update_type type,
			   struct nftnl_table *t)
{
	return batch_add(h, type, t);
}

static int batch_chain_add(struct nft_handle *h, enum obj_update_type type,
			   struct nftnl_chain *c)
{
	return batch_add(h, type, c);
}

static int batch_rule_add(struct nft_handle *h, enum obj_update_type type,
			  struct nftnl_rule *r)
{
	return batch_add(h, type, r);
}

struct builtin_table xtables_ipv4[TABLES_MAX] = {
	[RAW] = {
		.name	= "raw",
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[MANGLE] = {
		.name	= "mangle",
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "route",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_LOCAL_OUT,
			},
			{
				.name	= "POSTROUTING",
				.type	= "filter",
				.prio	= -150,	/* NF_IP_PRI_MANGLE */
				.hook	= NF_INET_POST_ROUTING,
			},
		},
	},
	[FILTER] = {
		.name	= "filter",
		.chains = {
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= 0,	/* NF_IP_PRI_FILTER */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[SECURITY] = {
		.name	= "security",
		.chains = {
			{
				.name	= "INPUT",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "FORWARD",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_FORWARD,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= 150,	/* NF_IP_PRI_SECURITY */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
	[NAT] = {
		.name	= "nat",
		.chains = {
			{
				.name	= "PREROUTING",
				.type	= "nat",
				.prio	= -100, /* NF_IP_PRI_NAT_DST */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "INPUT",
				.type	= "nat",
				.prio	= 100, /* NF_IP_PRI_NAT_SRC */
				.hook	= NF_INET_LOCAL_IN,
			},
			{
				.name	= "POSTROUTING",
				.type	= "nat",
				.prio	= 100, /* NF_IP_PRI_NAT_SRC */
				.hook	= NF_INET_POST_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.type	= "nat",
				.prio	= -100, /* NF_IP_PRI_NAT_DST */
				.hook	= NF_INET_LOCAL_OUT,
			},
		},
	},
};

#include <linux/netfilter_arp.h>

struct builtin_table xtables_arp[TABLES_MAX] = {
	[FILTER] = {
	.name   = "filter",
	.chains = {
			{
				.name   = "INPUT",
				.type   = "filter",
				.prio   = NF_IP_PRI_FILTER,
				.hook   = NF_ARP_IN,
			},
			{
				.name   = "OUTPUT",
				.type   = "filter",
				.prio   = NF_IP_PRI_FILTER,
				.hook   = NF_ARP_OUT,
			},
		},
	},
};

#include <linux/netfilter_bridge.h>

struct builtin_table xtables_bridge[TABLES_MAX] = {
	[FILTER] = {
		.name = "filter",
		.chains = {
			{
				.name   = "INPUT",
				.type   = "filter",
				.prio   = NF_BR_PRI_FILTER_BRIDGED,
				.hook   = NF_BR_LOCAL_IN,
			},
			{
				.name   = "FORWARD",
				.type   = "filter",
				.prio   = NF_BR_PRI_FILTER_BRIDGED,
				.hook   = NF_BR_FORWARD,
			},
			{
				.name   = "OUTPUT",
				.type   = "filter",
				.prio   = NF_BR_PRI_FILTER_BRIDGED,
				.hook   = NF_BR_LOCAL_OUT,
			},
		},
	},
	[NAT] = {
		.name = "nat",
		.chains = {
			{
				.name   = "PREROUTING",
				.type   = "filter",
				.prio   = NF_BR_PRI_NAT_DST_BRIDGED,
				.hook   = NF_BR_PRE_ROUTING,
			},
			{
				.name   = "OUTPUT",
				.type   = "filter",
				.prio   = NF_BR_PRI_NAT_DST_OTHER,
				.hook   = NF_BR_LOCAL_OUT,
			},
			{
				.name   = "POSTROUTING",
				.type   = "filter",
				.prio   = NF_BR_PRI_NAT_SRC,
				.hook   = NF_BR_POST_ROUTING,
			},
		},
	},
};

static int nft_table_builtin_add(struct nft_handle *h,
				 struct builtin_table *_t)
{
	struct nftnl_table *t;
	int ret;

	if (_t->initialized)
		return 0;

	t = nftnl_table_alloc();
	if (t == NULL)
		return -1;

	nftnl_table_set(t, NFTNL_TABLE_NAME, (char *)_t->name);

	ret = batch_table_add(h, NFT_COMPAT_TABLE_ADD, t);

	return ret;
}

static struct nftnl_chain *
nft_chain_builtin_alloc(struct builtin_table *table,
			struct builtin_chain *chain, int policy)
{
	struct nftnl_chain *c;

	c = nftnl_chain_alloc();
	if (c == NULL)
		return NULL;

	nftnl_chain_set(c, NFTNL_CHAIN_TABLE, (char *)table->name);
	nftnl_chain_set(c, NFTNL_CHAIN_NAME, (char *)chain->name);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, chain->hook);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, chain->prio);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_POLICY, policy);
	nftnl_chain_set(c, NFTNL_CHAIN_TYPE, (char *)chain->type);

	return c;
}

static void nft_chain_builtin_add(struct nft_handle *h,
				  struct builtin_table *table,
				  struct builtin_chain *chain)
{
	struct nftnl_chain *c;

	c = nft_chain_builtin_alloc(table, chain, NF_ACCEPT);
	if (c == NULL)
		return;

	batch_chain_add(h, NFT_COMPAT_CHAIN_ADD, c);
}

/* find if built-in table already exists */
struct builtin_table *
nft_table_builtin_find(struct nft_handle *h, const char *table)
{
	int i;
	bool found = false;

	for (i=0; i<TABLES_MAX; i++) {
		if (h->tables[i].name == NULL)
			continue;

		if (strcmp(h->tables[i].name, table) != 0)
			continue;

		found = true;
		break;
	}

	return found ? &h->tables[i] : NULL;
}

/* find if built-in chain already exists */
struct builtin_chain *
nft_chain_builtin_find(struct builtin_table *t, const char *chain)
{
	int i;
	bool found = false;

	for (i=0; i<NF_IP_NUMHOOKS && t->chains[i].name != NULL; i++) {
		if (strcmp(t->chains[i].name, chain) != 0)
			continue;

		found = true;
		break;
	}
	return found ? &t->chains[i] : NULL;
}

static void nft_chain_builtin_init(struct nft_handle *h,
				   struct builtin_table *table)
{
	int i;
	struct nftnl_chain_list *list = nft_chain_dump(h);
	struct nftnl_chain *c;

	/* Initialize built-in chains if they don't exist yet */
	for (i=0; i < NF_INET_NUMHOOKS && table->chains[i].name != NULL; i++) {

		c = nft_chain_list_find(list, table->name,
					table->chains[i].name);
		if (c != NULL)
			continue;

		nft_chain_builtin_add(h, table, &table->chains[i]);
	}
}

static int nft_xt_builtin_init(struct nft_handle *h, const char *table)
{
	struct builtin_table *t;

	t = nft_table_builtin_find(h, table);
	if (t == NULL)
		return -1;

	if (t->initialized)
		return 0;

	if (nft_table_builtin_add(h, t) < 0)
		return -1;

	nft_chain_builtin_init(h, t);

	t->initialized = true;

	return 0;
}

static bool nft_chain_builtin(struct nftnl_chain *c)
{
	/* Check if this chain has hook number, in that case is built-in.
	 * Should we better export the flags to user-space via nf_tables?
	 */
	return nftnl_chain_get(c, NFTNL_CHAIN_HOOKNUM) != NULL;
}

static int nft_restart(struct nft_handle *h)
{
	mnl_socket_close(h->nl);

	h->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (h->nl == NULL)
		return -1;

	if (mnl_socket_bind(h->nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return -1;

	h->portid = mnl_socket_get_portid(h->nl);

	return 0;
}

int nft_init(struct nft_handle *h, struct builtin_table *t)
{
	h->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (h->nl == NULL)
		return -1;

	if (mnl_socket_bind(h->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		mnl_socket_close(h->nl);
		return -1;
	}

	h->portid = mnl_socket_get_portid(h->nl);
	h->tables = t;

	INIT_LIST_HEAD(&h->obj_list);
	INIT_LIST_HEAD(&h->err_list);

	return 0;
}

static int __flush_rule_cache(struct nftnl_rule *r, void *data)
{
	const char *tablename = data;

	if (!strcmp(nftnl_rule_get_str(r, NFTNL_RULE_TABLE), tablename)) {
		nftnl_rule_list_del(r);
		nftnl_rule_free(r);
	}

	return 0;
}

static void flush_rule_cache(struct nft_handle *h, const char *tablename)
{
	if (!h->rule_cache)
		return;

	if (tablename) {
		nftnl_rule_list_foreach(h->rule_cache, __flush_rule_cache,
					(void *)tablename);
	} else {
		nftnl_rule_list_free(h->rule_cache);
		h->rule_cache = NULL;
	}
}

static int __flush_chain_cache(struct nftnl_chain *c, void *data)
{
	const char *tablename = data;

	if (!strcmp(nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE), tablename)) {
		nftnl_chain_list_del(c);
		nftnl_chain_free(c);
	}

	return 0;
}

static void flush_chain_cache(struct nft_handle *h, const char *tablename)
{
	if (!h->chain_cache)
		return;

	if (tablename) {
		nftnl_chain_list_foreach(h->chain_cache, __flush_chain_cache,
					 (void *)tablename);
	} else {
		nftnl_chain_list_free(h->chain_cache);
		h->chain_cache = NULL;
	}
}

void nft_fini(struct nft_handle *h)
{
	flush_chain_cache(h, NULL);
	flush_rule_cache(h, NULL);
	mnl_socket_close(h->nl);
}

static void nft_chain_print_debug(struct nftnl_chain *c, struct nlmsghdr *nlh)
{
#ifdef NLDEBUG
	char tmp[1024];

	nftnl_chain_snprintf(tmp, sizeof(tmp), c, 0, 0);
	printf("DEBUG: chain: %s\n", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif
}

static struct nftnl_chain *nft_chain_new(struct nft_handle *h,
				       const char *table, const char *chain,
				       int policy,
				       const struct xt_counters *counters)
{
	struct nftnl_chain *c;
	struct builtin_table *_t;
	struct builtin_chain *_c;

	_t = nft_table_builtin_find(h, table);
	/* if this built-in table does not exists, create it */
	if (_t != NULL)
		nft_table_builtin_add(h, _t);

	_c = nft_chain_builtin_find(_t, chain);
	if (_c != NULL) {
		/* This is a built-in chain */
		c = nft_chain_builtin_alloc(_t, _c, policy);
		if (c == NULL)
			return NULL;
	} else {
		errno = ENOENT;
		return NULL;
	}

	if (counters) {
		nftnl_chain_set_u64(c, NFTNL_CHAIN_BYTES,
					counters->bcnt);
		nftnl_chain_set_u64(c, NFTNL_CHAIN_PACKETS,
					counters->pcnt);
	}

	return c;
}

int nft_chain_set(struct nft_handle *h, const char *table,
		  const char *chain, const char *policy,
		  const struct xt_counters *counters)
{
	struct nftnl_chain *c = NULL;
	int ret;

	nft_fn = nft_chain_set;

	if (strcmp(policy, "DROP") == 0)
		c = nft_chain_new(h, table, chain, NF_DROP, counters);
	else if (strcmp(policy, "ACCEPT") == 0)
		c = nft_chain_new(h, table, chain, NF_ACCEPT, counters);

	if (c == NULL)
		return 0;

	ret = batch_chain_add(h, NFT_COMPAT_CHAIN_UPDATE, c);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static int __add_match(struct nftnl_expr *e, struct xt_entry_match *m)
{
	void *info;

	nftnl_expr_set(e, NFTNL_EXPR_MT_NAME, m->u.user.name, strlen(m->u.user.name));
	nftnl_expr_set_u32(e, NFTNL_EXPR_MT_REV, m->u.user.revision);

	info = calloc(1, m->u.match_size);
	if (info == NULL)
		return -ENOMEM;

	memcpy(info, m->data, m->u.match_size - sizeof(*m));
	nftnl_expr_set(e, NFTNL_EXPR_MT_INFO, info, m->u.match_size - sizeof(*m));

	return 0;
}

static int add_nft_limit(struct nftnl_rule *r, struct xt_entry_match *m)
{
	struct xt_rateinfo *rinfo = (void *)m->data;
	static const uint32_t mult[] = {
		XT_LIMIT_SCALE*24*60*60,	/* day */
		XT_LIMIT_SCALE*60*60,		/* hour */
		XT_LIMIT_SCALE*60,		/* min */
		XT_LIMIT_SCALE,			/* sec */
	};
	struct nftnl_expr *expr;
	int i;

	expr = nftnl_expr_alloc("limit");
	if (!expr)
		return -ENOMEM;

	for (i = 1; i < ARRAY_SIZE(mult); i++) {
		if (rinfo->avg > mult[i] ||
		    mult[i] / rinfo->avg < mult[i] % rinfo->avg)
			break;
	}

	nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_TYPE, NFT_LIMIT_PKTS);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_FLAGS, 0);

	nftnl_expr_set_u64(expr, NFTNL_EXPR_LIMIT_RATE,
			   mult[i - 1] / rinfo->avg);
        nftnl_expr_set_u64(expr, NFTNL_EXPR_LIMIT_UNIT,
			   mult[i - 1] / XT_LIMIT_SCALE);

	nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_BURST, rinfo->burst);

	nftnl_rule_add_expr(r, expr);
	return 0;
}

int add_match(struct nftnl_rule *r, struct xt_entry_match *m)
{
	struct nftnl_expr *expr;
	int ret;

	if (!strcmp(m->u.user.name, "limit"))
		return add_nft_limit(r, m);

	expr = nftnl_expr_alloc("match");
	if (expr == NULL)
		return -ENOMEM;

	ret = __add_match(expr, m);
	nftnl_rule_add_expr(r, expr);

	return ret;
}

static int __add_target(struct nftnl_expr *e, struct xt_entry_target *t)
{
	void *info;

	nftnl_expr_set(e, NFTNL_EXPR_TG_NAME, t->u.user.name,
			  strlen(t->u.user.name));
	nftnl_expr_set_u32(e, NFTNL_EXPR_TG_REV, t->u.user.revision);

	info = calloc(1, t->u.target_size);
	if (info == NULL)
		return -ENOMEM;

	memcpy(info, t->data, t->u.target_size - sizeof(*t));
	nftnl_expr_set(e, NFTNL_EXPR_TG_INFO, info, t->u.target_size - sizeof(*t));

	return 0;
}

static int add_meta_nftrace(struct nftnl_rule *r)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG32_01);
	nftnl_expr_set_u8(expr, NFTNL_EXPR_IMM_DATA, 1);
	nftnl_rule_add_expr(r, expr);

	expr = nftnl_expr_alloc("meta");
	if (expr == NULL)
		return -ENOMEM;
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_NFTRACE);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_META_SREG, NFT_REG32_01);

	nftnl_rule_add_expr(r, expr);
	return 0;
}

int add_target(struct nftnl_rule *r, struct xt_entry_target *t)
{
	struct nftnl_expr *expr;
	int ret;

	if (strcmp(t->u.user.name, "TRACE") == 0)
		return add_meta_nftrace(r);

	expr = nftnl_expr_alloc("target");
	if (expr == NULL)
		return -ENOMEM;

	ret = __add_target(expr, t);
	nftnl_rule_add_expr(r, expr);

	return ret;
}

int add_jumpto(struct nftnl_rule *r, const char *name, int verdict)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, verdict);
	nftnl_expr_set_str(expr, NFTNL_EXPR_IMM_CHAIN, (char *)name);
	nftnl_rule_add_expr(r, expr);

	return 0;
}

int add_verdict(struct nftnl_rule *r, int verdict)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("immediate");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, verdict);
	nftnl_rule_add_expr(r, expr);

	return 0;
}

int add_action(struct nftnl_rule *r, struct iptables_command_state *cs,
	       bool goto_set)
{
       int ret = 0;

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
	       /* Not standard, then it's a go / jump to chain */
	       if (goto_set)
		       ret = add_jumpto(r, cs->jumpto, NFT_GOTO);
	       else
		       ret = add_jumpto(r, cs->jumpto, NFT_JUMP);
       }
       return ret;
}

static void nft_rule_print_debug(struct nftnl_rule *r, struct nlmsghdr *nlh)
{
#ifdef NLDEBUG
	char tmp[1024];

	nftnl_rule_snprintf(tmp, sizeof(tmp), r, 0, 0);
	printf("DEBUG: rule: %s\n", tmp);
	mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, sizeof(struct nfgenmsg));
#endif
}

int add_counters(struct nftnl_rule *r, uint64_t packets, uint64_t bytes)
{
	struct nftnl_expr *expr;

	expr = nftnl_expr_alloc("counter");
	if (expr == NULL)
		return -ENOMEM;

	nftnl_expr_set_u64(expr, NFTNL_EXPR_CTR_PACKETS, packets);
	nftnl_expr_set_u64(expr, NFTNL_EXPR_CTR_BYTES, bytes);

	nftnl_rule_add_expr(r, expr);

	return 0;
}

enum udata_type {
	UDATA_TYPE_COMMENT,
	__UDATA_TYPE_MAX,
};
#define UDATA_TYPE_MAX (__UDATA_TYPE_MAX - 1)

int add_comment(struct nftnl_rule *r, const char *comment)
{
	struct nftnl_udata_buf *udata;
	uint32_t len;

	if (nftnl_rule_get_data(r, NFTNL_RULE_USERDATA, &len))
		return -EALREADY;

	udata = nftnl_udata_buf_alloc(NFT_USERDATA_MAXLEN);
	if (!udata)
		return -ENOMEM;

	if (strnlen(comment, 255) == 255)
		return -ENOSPC;

	if (!nftnl_udata_put_strz(udata, UDATA_TYPE_COMMENT, comment))
		return -ENOMEM;

	nftnl_rule_set_data(r, NFTNL_RULE_USERDATA,
			    nftnl_udata_buf_data(udata),
			    nftnl_udata_buf_len(udata));

	nftnl_udata_buf_free(udata);

	return 0;
}

static int parse_udata_cb(const struct nftnl_udata *attr, void *data)
{
	unsigned char *value = nftnl_udata_get(attr);
	uint8_t type = nftnl_udata_type(attr);
	uint8_t len = nftnl_udata_len(attr);
	const struct nftnl_udata **tb = data;

	switch (type) {
	case UDATA_TYPE_COMMENT:
		if (value[len - 1] != '\0')
			return -1;
		break;
	default:
		return 0;
	}
	tb[type] = attr;
	return 0;
}

char *get_comment(const void *data, uint32_t data_len)
{
	const struct nftnl_udata *tb[UDATA_TYPE_MAX + 1] = {};

	if (nftnl_udata_parse(data, data_len, parse_udata_cb, tb) < 0)
		return NULL;

	if (!tb[UDATA_TYPE_COMMENT])
		return NULL;

	return nftnl_udata_get(tb[UDATA_TYPE_COMMENT]);
}

void add_compat(struct nftnl_rule *r, uint32_t proto, bool inv)
{
	nftnl_rule_set_u32(r, NFTNL_RULE_COMPAT_PROTO, proto);
	nftnl_rule_set_u32(r, NFTNL_RULE_COMPAT_FLAGS,
			      inv ? NFT_RULE_COMPAT_F_INV : 0);
}

static struct nftnl_rule *
nft_rule_new(struct nft_handle *h, const char *chain, const char *table,
	     void *data)
{
	struct nftnl_rule *r;

	r = nftnl_rule_alloc();
	if (r == NULL)
		return NULL;

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, h->family);
	nftnl_rule_set(r, NFTNL_RULE_TABLE, (char *)table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, (char *)chain);

	if (h->ops->add(r, data) < 0)
		goto err;

	return r;
err:
	nftnl_rule_free(r);
	return NULL;
}

static struct nftnl_rule_list *nft_rule_list_get(struct nft_handle *h);

int
nft_rule_append(struct nft_handle *h, const char *chain, const char *table,
		void *data, uint64_t handle, bool verbose)
{
	struct nftnl_rule *r;
	int type;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	nft_fn = nft_rule_append;

	r = nft_rule_new(h, chain, table, data);
	if (r == NULL)
		return 0;

	if (handle > 0) {
		nftnl_rule_set(r, NFTNL_RULE_HANDLE, &handle);
		type = NFT_COMPAT_RULE_REPLACE;
	} else
		type = NFT_COMPAT_RULE_APPEND;

	if (batch_rule_add(h, type, r) < 0) {
		nftnl_rule_free(r);
		return 0;
	}

	if (verbose)
		h->ops->print_rule(r, 0, FMT_PRINT_RULE);

	if (!nft_rule_list_get(h))
		return 0;

	nftnl_rule_list_add_tail(r, h->rule_cache);

	return 1;
}

void
nft_rule_print_save(const struct nftnl_rule *r, enum nft_rule_print type,
		    unsigned int format)
{
	const char *chain = nftnl_rule_get_str(r, NFTNL_RULE_CHAIN);
	int family = nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY);
	struct iptables_command_state cs = {};
	struct nft_family_ops *ops;

	ops = nft_family_ops_lookup(family);
	ops->rule_to_cs(r, &cs);

	if (!(format & (FMT_NOCOUNTS | FMT_C_COUNTS)) && ops->save_counters)
		ops->save_counters(&cs);

	/* print chain name */
	switch(type) {
	case NFT_RULE_APPEND:
		printf("-A %s ", chain);
		break;
	case NFT_RULE_DEL:
		printf("-D %s ", chain);
		break;
	}

	if (ops->save_rule)
		ops->save_rule(&cs, format);

	if (ops->clear_cs)
		ops->clear_cs(&cs);
}

static int nftnl_chain_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_chain *c;
	struct nftnl_chain_list *list = data;

	c = nftnl_chain_alloc();
	if (c == NULL)
		goto err;

	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		goto out;

	nftnl_chain_list_add_tail(c, list);

	return MNL_CB_OK;
out:
	nftnl_chain_free(c);
err:
	return MNL_CB_OK;
}

static struct nftnl_chain_list *nftnl_chain_list_get(struct nft_handle *h)
{
	char buf[16536];
	struct nlmsghdr *nlh;
	struct nftnl_chain_list *list;
	int ret;

	if (h->chain_cache)
		return h->chain_cache;
retry:
	list = nftnl_chain_list_alloc();
	if (list == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, h->family,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nftnl_chain_list_cb, list);
	if (ret < 0 && errno == EINTR) {
		assert(nft_restart(h) >= 0);
		nftnl_chain_list_free(list);
		goto retry;
	}

	h->chain_cache = list;

	return list;
}

struct nftnl_chain_list *nft_chain_dump(struct nft_handle *h)
{
	return nftnl_chain_list_get(h);
}

static const char *policy_name[NF_ACCEPT+1] = {
	[NF_DROP] = "DROP",
	[NF_ACCEPT] = "ACCEPT",
};

int nft_chain_save(struct nft_handle *h, struct nftnl_chain_list *list,
		   const char *table)
{
	struct nftnl_chain_list_iter *iter;
	struct nft_family_ops *ops;
	struct nftnl_chain *c;

	ops = nft_family_ops_lookup(h->family);

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		return 0;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
		const char *policy = NULL;

		if (strcmp(table, chain_table) != 0)
			goto next;

		if (nft_chain_builtin(c)) {
			uint32_t pol = NF_ACCEPT;

			if (nftnl_chain_get(c, NFTNL_CHAIN_POLICY))
				pol = nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY);
			policy = policy_name[pol];
		}

		if (ops->save_chain)
			ops->save_chain(c, policy);
next:
		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);

	return 1;
}

static int nftnl_rule_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_rule *r;
	struct nftnl_rule_list *list = data;

	r = nftnl_rule_alloc();
	if (r == NULL)
		goto err;

	if (nftnl_rule_nlmsg_parse(nlh, r) < 0)
		goto out;

	nftnl_rule_list_add_tail(r, list);

	return MNL_CB_OK;
out:
	nftnl_rule_free(r);
	nftnl_rule_list_free(list);
err:
	return MNL_CB_OK;
}

static struct nftnl_rule_list *nft_rule_list_get(struct nft_handle *h)
{
	char buf[16536];
	struct nlmsghdr *nlh;
	struct nftnl_rule_list *list;
	int ret;

	if (h->rule_cache)
		return h->rule_cache;

retry:
	list = nftnl_rule_list_alloc();
	if (list == NULL)
		return 0;

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, h->family,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nftnl_rule_list_cb, list);
	if (ret < 0) {
		if (errno == EINTR) {
			assert(nft_restart(h) >= 0);
			nftnl_rule_list_free(list);
			goto retry;
		}

		nftnl_rule_list_free(list);
		return NULL;
	}

	h->rule_cache = list;
	return list;
}

int nft_rule_save(struct nft_handle *h, const char *table, unsigned int format)
{
	struct nftnl_rule_list *list;
	struct nftnl_rule_list_iter *iter;
	struct nftnl_rule *r;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	iter = nftnl_rule_list_iter_create(list);
	if (iter == NULL)
		return 0;

	r = nftnl_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nftnl_rule_get_str(r, NFTNL_RULE_TABLE);

		if (strcmp(table, rule_table) != 0)
			goto next;

		nft_rule_print_save(r, NFT_RULE_APPEND, format);

next:
		r = nftnl_rule_list_iter_next(iter);
	}

	nftnl_rule_list_iter_destroy(iter);

	/* the core expects 1 for success and 0 for error */
	return 1;
}

static void
__nft_rule_flush(struct nft_handle *h, const char *table, const char *chain)
{
	struct nftnl_rule *r;

	r = nftnl_rule_alloc();
	if (r == NULL)
		return;

	nftnl_rule_set(r, NFTNL_RULE_TABLE, (char *)table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, (char *)chain);

	if (batch_rule_add(h, NFT_COMPAT_RULE_FLUSH, r) < 0)
		nftnl_rule_free(r);
}

struct chain_user_flush_data {
	struct nft_handle	*handle;
	const char		*table;
	const char		*chain;
};

static int __nft_chain_user_flush(struct nftnl_chain *c, void *data)
{
	const char *table_name = nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
	const char *chain_name = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	struct chain_user_flush_data *d = data;
	struct nft_handle *h = d->handle;
	const char *table = d->table;
	const char *chain = d->chain;
	int ret;

	if (strcmp(table, table_name) != 0)
		return 0;

	if (strcmp(chain, chain_name) != 0)
		return 0;

	if (!nftnl_chain_is_set(c, NFTNL_CHAIN_HOOKNUM)) {
		ret = batch_chain_add(h, NFT_COMPAT_CHAIN_USER_FLUSH, c);
		if (ret < 0)
			return ret;

		nftnl_chain_list_del(c);
	}

	return 0;
}

int nft_chain_user_flush(struct nft_handle *h, struct nftnl_chain_list *list,
			 const char *table, const char *chain)
{
	struct chain_user_flush_data d = {
		.handle = h,
		.table	= table,
		.chain  = chain,
	};

	nft_fn = nft_chain_user_flush;

	nftnl_chain_list_foreach(list, __nft_chain_user_flush, &d);

	return 1;
}

int nft_rule_flush(struct nft_handle *h, const char *chain, const char *table,
		   bool verbose)
{
	int ret = 0;
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;

	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	nft_fn = nft_rule_flush;

	list = nftnl_chain_list_get(h);
	if (list == NULL) {
		ret = 1;
		goto err;
	}

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL) {
		ret = 1;
		goto err;
	}

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *table_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
		const char *chain_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);

		if (strcmp(table, table_name) != 0)
			goto next;

		if (chain != NULL && strcmp(chain, chain_name) != 0)
			goto next;

		if (verbose)
			fprintf(stdout, "Flushing chain `%s'\n", chain_name);

		__nft_rule_flush(h, table_name, chain_name);

		if (chain != NULL)
			break;
next:
		c = nftnl_chain_list_iter_next(iter);
	}
	nftnl_chain_list_iter_destroy(iter);
	flush_rule_cache(h, table);
err:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

int nft_chain_user_add(struct nft_handle *h, const char *chain, const char *table)
{
	struct nftnl_chain *c;
	int ret;

	nft_fn = nft_chain_user_add;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	c = nftnl_chain_alloc();
	if (c == NULL)
		return 0;

	nftnl_chain_set(c, NFTNL_CHAIN_TABLE, (char *)table);
	nftnl_chain_set(c, NFTNL_CHAIN_NAME, (char *)chain);

	ret = batch_chain_add(h, NFT_COMPAT_CHAIN_USER_ADD, c);

	nft_chain_dump(h);

	nftnl_chain_list_add(c, h->chain_cache);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

/* From linux/netlink.h */
#ifndef NLM_F_NONREC
#define NLM_F_NONREC	0x100	/* Do not delete recursively    */
#endif

int nft_chain_user_del(struct nft_handle *h, const char *chain,
		       const char *table, bool verbose)
{
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;
	int ret = 0;
	int deleted_ctr = 0;

	nft_fn = nft_chain_user_del;

	list = nftnl_chain_list_get(h);
	if (list == NULL)
		goto err;

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		goto err;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *table_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
		const char *chain_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);

		/* don't delete built-in chain */
		if (nft_chain_builtin(c))
			goto next;

		if (strcmp(table, table_name) != 0)
			goto next;

		if (chain != NULL && strcmp(chain, chain_name) != 0)
			goto next;

		if (verbose)
			fprintf(stdout, "Deleting chain `%s'\n", chain);

		ret = batch_chain_add(h, NFT_COMPAT_CHAIN_USER_DEL, c);

		if (ret < 0)
			break;

		deleted_ctr++;
		nftnl_chain_list_del(c);

		if (chain != NULL)
			break;
next:
		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);
err:

	/* chain not found */
	if (chain != NULL && deleted_ctr == 0) {
		ret = -1;
		errno = ENOENT;
	}

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

struct nftnl_chain *
nft_chain_list_find(struct nftnl_chain_list *list,
		    const char *table, const char *chain)
{
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		return NULL;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *table_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
		const char *chain_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);

		if (strcmp(table, table_name) != 0)
			goto next;

		if (strcmp(chain, chain_name) != 0)
			goto next;

		nftnl_chain_list_iter_destroy(iter);
		return c;
next:
		c = nftnl_chain_list_iter_next(iter);
	}
	nftnl_chain_list_iter_destroy(iter);
	return NULL;
}

static struct nftnl_chain *
nft_chain_find(struct nft_handle *h, const char *table, const char *chain)
{
	struct nftnl_chain_list *list;

	list = nftnl_chain_list_get(h);
	if (list == NULL)
		return NULL;

	return nft_chain_list_find(list, table, chain);
}

int nft_chain_user_rename(struct nft_handle *h,const char *chain,
			  const char *table, const char *newname)
{
	struct nftnl_chain *c;
	uint64_t handle;
	int ret;

	nft_fn = nft_chain_user_add;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	/* Config load changed errno. Ensure genuine info for our callers. */
	errno = 0;

	/* Find the old chain to be renamed */
	c = nft_chain_find(h, table, chain);
	if (c == NULL) {
		errno = ENOENT;
		return -1;
	}
	handle = nftnl_chain_get_u64(c, NFTNL_CHAIN_HANDLE);

	/* Now prepare the new name for the chain */
	c = nftnl_chain_alloc();
	if (c == NULL)
		return -1;

	nftnl_chain_set(c, NFTNL_CHAIN_TABLE, (char *)table);
	nftnl_chain_set(c, NFTNL_CHAIN_NAME, (char *)newname);
	nftnl_chain_set_u64(c, NFTNL_CHAIN_HANDLE, handle);

	ret = batch_chain_add(h, NFT_COMPAT_CHAIN_RENAME, c);

	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

static int nftnl_table_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_table *t;
	struct nftnl_table_list *list = data;

	t = nftnl_table_alloc();
	if (t == NULL)
		goto err;

	if (nftnl_table_nlmsg_parse(nlh, t) < 0)
		goto out;

	nftnl_table_list_add_tail(t, list);

	return MNL_CB_OK;
out:
	nftnl_table_free(t);
err:
	return MNL_CB_OK;
}

static struct nftnl_table_list *nftnl_table_list_get(struct nft_handle *h)
{
	char buf[16536];
	struct nlmsghdr *nlh;
	struct nftnl_table_list *list;
	int ret;

retry:
	list = nftnl_table_list_alloc();
	if (list == NULL)
		return 0;

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, h->family,
					NLM_F_DUMP, h->seq);

	ret = mnl_talk(h, nlh, nftnl_table_list_cb, list);
	if (ret < 0 && errno == EINTR) {
		assert(nft_restart(h) >= 0);
		nftnl_table_list_free(list);
		goto retry;
	}

	return list;
}

bool nft_table_find(struct nft_handle *h, const char *tablename)
{
	struct nftnl_table_list *list;
	struct nftnl_table_list_iter *iter;
	struct nftnl_table *t;
	bool ret = false;

	list = nftnl_table_list_get(h);
	if (list == NULL)
		goto err;

	iter = nftnl_table_list_iter_create(list);
	if (iter == NULL)
		goto err;

	t = nftnl_table_list_iter_next(iter);
	while (t != NULL) {
		const char *this_tablename =
			nftnl_table_get(t, NFTNL_TABLE_NAME);

		if (strcmp(tablename, this_tablename) == 0)
			return true;

		t = nftnl_table_list_iter_next(iter);
	}

	nftnl_table_list_free(list);

err:
	return ret;
}

int nft_for_each_table(struct nft_handle *h,
		       int (*func)(struct nft_handle *h, const char *tablename, bool counters),
		       bool counters)
{
	struct nftnl_table_list *list;
	struct nftnl_table_list_iter *iter;
	struct nftnl_table *t;

	list = nftnl_table_list_get(h);
	if (list == NULL)
		return -1;

	iter = nftnl_table_list_iter_create(list);
	if (iter == NULL)
		return -1;

	t = nftnl_table_list_iter_next(iter);
	while (t != NULL) {
		const char *tablename =
			nftnl_table_get(t, NFTNL_TABLE_NAME);

		func(h, tablename, counters);

		t = nftnl_table_list_iter_next(iter);
	}

	nftnl_table_list_free(list);
	return 0;
}

static int __nft_table_flush(struct nft_handle *h, const char *table)
{
	struct builtin_table *_t;
	struct nftnl_table *t;

	t = nftnl_table_alloc();
	if (t == NULL)
		return -1;

	nftnl_table_set_str(t, NFTNL_TABLE_NAME, table);

	batch_table_add(h, NFT_COMPAT_TABLE_FLUSH, t);

	_t = nft_table_builtin_find(h, table);
	assert(t);
	_t->initialized = false;

	flush_chain_cache(h, table);
	flush_rule_cache(h, table);

	return 0;
}

int nft_table_flush(struct nft_handle *h, const char *table)
{
	struct nftnl_table_list_iter *iter;
	struct nftnl_table_list *list;
	struct nftnl_table *t;
	int ret = 0;

	nft_fn = nft_table_flush;

	list = nftnl_table_list_get(h);
	if (list == NULL) {
		ret = -1;
		goto err_out;
	}

	iter = nftnl_table_list_iter_create(list);
	if (iter == NULL) {
		ret = -1;
		goto err_table_list;
	}

	t = nftnl_table_list_iter_next(iter);
	while (t != NULL) {
		const char *table_name =
			nftnl_table_get_str(t, NFTNL_TABLE_NAME);

		if (strcmp(table_name, table) != 0)
			goto next;

		ret = __nft_table_flush(h, table);
		if (ret < 0)
			goto err_table_iter;
next:
		t = nftnl_table_list_iter_next(iter);
	}

	if (!h->rule_cache) {
		h->rule_cache = nftnl_rule_list_alloc();
		if (h->rule_cache == NULL)
			return -1;
	}

err_table_iter:
	nftnl_table_list_iter_destroy(iter);
err_table_list:
	nftnl_table_list_free(list);
err_out:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

void nft_table_new(struct nft_handle *h, const char *table)
{
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);
}

static int __nft_rule_del(struct nft_handle *h, struct nftnl_rule_list *list,
			  struct nftnl_rule *r)
{
	int ret;

	nftnl_rule_list_del(r);

	ret = batch_rule_add(h, NFT_COMPAT_RULE_DELETE, r);
	if (ret < 0) {
		nftnl_rule_free(r);
		return -1;
	}
	return 1;
}

static struct nftnl_rule *
nft_rule_find(struct nft_handle *h, struct nftnl_rule_list *list,
	      const char *chain, const char *table, void *data, int rulenum)
{
	struct nftnl_rule *r;
	struct nftnl_rule_list_iter *iter;
	int rule_ctr = 0;
	bool found = false;

	iter = nftnl_rule_list_iter_create(list);
	if (iter == NULL)
		return 0;

	r = nftnl_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nftnl_rule_get_str(r, NFTNL_RULE_TABLE);
		const char *rule_chain =
			nftnl_rule_get_str(r, NFTNL_RULE_CHAIN);

		if (strcmp(table, rule_table) != 0 ||
		    strcmp(chain, rule_chain) != 0) {
			DEBUGP("different chain / table\n");
			goto next;
		}

		if (rulenum >= 0) {
			/* Delete by rule number case */
			if (rule_ctr == rulenum) {
			    found = true;
			    break;
			}
		} else {
			found = h->ops->rule_find(h->ops, r, data);
			if (found)
				break;
		}
		rule_ctr++;
next:
		r = nftnl_rule_list_iter_next(iter);
	}

	nftnl_rule_list_iter_destroy(iter);

	return found ? r : NULL;
}

int nft_rule_check(struct nft_handle *h, const char *chain,
		   const char *table, void *data, bool verbose)
{
	struct nftnl_rule_list *list;
	struct nftnl_rule *r;

	nft_fn = nft_rule_check;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, data, -1);
	if (r == NULL) {
		errno = ENOENT;
		return 0;
	}
	if (verbose)
		h->ops->print_rule(r, 0, FMT_PRINT_RULE);

	return 1;
}

int nft_rule_delete(struct nft_handle *h, const char *chain,
		    const char *table, void *data, bool verbose)
{
	int ret = 0;
	struct nftnl_rule *r;
	struct nftnl_rule_list *list;

	nft_fn = nft_rule_delete;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, data, -1);
	if (r != NULL) {
		ret =__nft_rule_del(h, list, r);
		if (ret < 0)
			errno = ENOMEM;
		if (verbose)
			h->ops->print_rule(r, 0, FMT_PRINT_RULE);
	} else
		errno = ENOENT;

	return ret;
}

static struct nftnl_rule *
nft_rule_add(struct nft_handle *h, const char *chain,
	     const char *table, struct iptables_command_state *cs,
	     uint64_t handle, bool verbose)
{
	struct nftnl_rule *r;

	r = nft_rule_new(h, chain, table, cs);
	if (r == NULL)
		return NULL;

	if (handle > 0)
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle);

	if (batch_rule_add(h, NFT_COMPAT_RULE_INSERT, r) < 0) {
		nftnl_rule_free(r);
		return NULL;
	}

	if (verbose)
		h->ops->print_rule(r, 0, FMT_PRINT_RULE);

	return r;
}

int nft_rule_insert(struct nft_handle *h, const char *chain,
		    const char *table, void *data, int rulenum, bool verbose)
{
	struct nftnl_rule *r, *new_rule;
	struct nftnl_rule_list *list;
	uint64_t handle = 0;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0)
		nft_xt_builtin_init(h, table);

	nft_fn = nft_rule_insert;

	if (rulenum > 0) {
		list = nft_rule_list_get(h);
		if (list == NULL)
			goto err;

		r = nft_rule_find(h, list, chain, table, data, rulenum);
		if (r == NULL) {
			/* special case: iptables allows to insert into
			 * rule_count + 1 position.
			 */
			r = nft_rule_find(h, list, chain, table, data,
					  rulenum - 1);
			if (r != NULL)
				return nft_rule_append(h, chain, table, data,
						       0, verbose);

			errno = ENOENT;
			goto err;
		}

		handle = nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE);
		DEBUGP("adding after rule handle %"PRIu64"\n", handle);
	} else {
		nft_rule_list_get(h);
	}

	new_rule = nft_rule_add(h, chain, table, data, handle, verbose);
	if (!new_rule)
		goto err;

	if (handle)
		nftnl_rule_list_insert_at(new_rule, r);
	else
		nftnl_rule_list_add(new_rule, h->rule_cache);

	return 1;
err:
	return 0;
}

int nft_rule_delete_num(struct nft_handle *h, const char *chain,
			const char *table, int rulenum, bool verbose)
{
	int ret = 0;
	struct nftnl_rule *r;
	struct nftnl_rule_list *list;

	nft_fn = nft_rule_delete_num;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, NULL, rulenum);
	if (r != NULL) {
		ret = 1;

		DEBUGP("deleting rule by number %d\n", rulenum);
		ret = __nft_rule_del(h, list, r);
		if (ret < 0)
			errno = ENOMEM;
	} else
		errno = ENOENT;

	return ret;
}

int nft_rule_replace(struct nft_handle *h, const char *chain,
		     const char *table, void *data, int rulenum, bool verbose)
{
	int ret = 0;
	struct nftnl_rule *r;
	struct nftnl_rule_list *list;

	nft_fn = nft_rule_replace;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, data, rulenum);
	if (r != NULL) {
		DEBUGP("replacing rule with handle=%llu\n",
			(unsigned long long)
			nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE));

		nftnl_rule_list_del(r);

		ret = nft_rule_append(h, chain, table, data,
				      nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE),
				      verbose);
	} else
		errno = ENOENT;

	return ret;
}

static int
__nft_rule_list(struct nft_handle *h, const char *chain, const char *table,
		int rulenum, unsigned int format,
		void (*cb)(struct nftnl_rule *r, unsigned int num,
			   unsigned int format))
{
	struct nftnl_rule_list *list;
	struct nftnl_rule_list_iter *iter;
	struct nftnl_rule *r;
	int rule_ctr = 0, ret = 0;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	iter = nftnl_rule_list_iter_create(list);
	if (iter == NULL)
		goto err;

	r = nftnl_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nftnl_rule_get_str(r, NFTNL_RULE_TABLE);
		const char *rule_chain =
			nftnl_rule_get_str(r, NFTNL_RULE_CHAIN);

		if (strcmp(table, rule_table) != 0 ||
		    strcmp(chain, rule_chain) != 0)
			goto next;

		rule_ctr++;

		if (rulenum > 0 && rule_ctr != rulenum) {
			/* List by rule number case */
			goto next;
		}

		cb(r, rule_ctr, format);
		if (rulenum > 0 && rule_ctr == rulenum) {
			ret = 1;
			break;
		}

next:
		r = nftnl_rule_list_iter_next(iter);
	}

	nftnl_rule_list_iter_destroy(iter);
err:
	if (ret == 0)
		errno = ENOENT;

	return ret;
}

static int nft_rule_count(struct nft_handle *h,
			  const char *chain, const char *table)
{
	struct nftnl_rule_list_iter *iter;
	struct nftnl_rule_list *list;
	struct nftnl_rule *r;
	int rule_ctr = 0;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	iter = nftnl_rule_list_iter_create(list);
	if (iter == NULL)
		return 0;

	r = nftnl_rule_list_iter_next(iter);
	while (r != NULL) {
		const char *rule_table =
			nftnl_rule_get_str(r, NFTNL_RULE_TABLE);
		const char *rule_chain =
			nftnl_rule_get_str(r, NFTNL_RULE_CHAIN);

		if (strcmp(table, rule_table) != 0 ||
		    strcmp(chain, rule_chain) != 0)
			goto next;

		rule_ctr++;
next:
		r = nftnl_rule_list_iter_next(iter);
	}

	nftnl_rule_list_iter_destroy(iter);
	return rule_ctr;
}

int nft_rule_list(struct nft_handle *h, const char *chain, const char *table,
		  int rulenum, unsigned int format)
{
	const struct nft_family_ops *ops;
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;
	bool found = false;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0) {
		nft_xt_builtin_init(h, table);
		/* Force table and chain creation, otherwise first iptables -L
		 * lists no table/chains.
		 */
		if (!list_empty(&h->obj_list)) {
			nft_commit(h);
			flush_chain_cache(h, NULL);
		}
	}

	ops = nft_family_ops_lookup(h->family);

	if (!nft_is_table_compatible(h, table)) {
		xtables_error(OTHER_PROBLEM, "table `%s' is incompatible, use 'nft' tool.\n", table);
		return 0;
	}

	if (chain && rulenum) {
		__nft_rule_list(h, chain, table,
				rulenum, format, ops->print_rule);
		return 1;
	}

	list = nft_chain_dump(h);

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		goto err;

	if (ops->print_table_header)
		ops->print_table_header(table);

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
		const char *chain_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
		uint32_t policy =
			nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY);
		uint32_t refs =
			nftnl_chain_get_u32(c, NFTNL_CHAIN_USE);
		struct xt_counters ctrs = {
			.pcnt = nftnl_chain_get_u64(c, NFTNL_CHAIN_PACKETS),
			.bcnt = nftnl_chain_get_u64(c, NFTNL_CHAIN_BYTES),
		};
		bool basechain = false;

		if (nftnl_chain_get(c, NFTNL_CHAIN_HOOKNUM))
			basechain = true;

		if (strcmp(table, chain_table) != 0)
			goto next;
		if (chain && strcmp(chain, chain_name) != 0)
			goto next;

		refs -= nft_rule_count(h, chain_name, table);

		if (found)
			printf("\n");

		ops->print_header(format, chain_name, policy_name[policy],
				  &ctrs, basechain, refs);

		__nft_rule_list(h, chain_name, table,
				rulenum, format, ops->print_rule);

		found = true;

		/* we printed the chain we wanted, stop processing. */
		if (chain)
			break;

next:
		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);
err:
	if (chain && !found)
		return 0;

	return 1;
}

static void
list_save(struct nftnl_rule *r, unsigned int num, unsigned int format)
{
	nft_rule_print_save(r, NFT_RULE_APPEND, format);
}

static int
nftnl_rule_list_chain_save(struct nft_handle *h, const char *chain,
			 const char *table, struct nftnl_chain_list *list,
			 int counters)
{
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		return 0;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
		const char *chain_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
		uint32_t policy =
			nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY);

		if (strcmp(table, chain_table) != 0 ||
		    (chain && strcmp(chain, chain_name) != 0))
			goto next;

		/* this is a base chain */
		if (nft_chain_builtin(c)) {
			printf("-P %s %s", chain_name, policy_name[policy]);

			if (counters) {
				printf(" -c %"PRIu64" %"PRIu64"\n",
					nftnl_chain_get_u64(c, NFTNL_CHAIN_PACKETS),
					nftnl_chain_get_u64(c, NFTNL_CHAIN_BYTES));
			} else
				printf("\n");
		} else {
			printf("-N %s\n", chain_name);
		}
next:
		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);

	return 1;
}

int nft_rule_list_save(struct nft_handle *h, const char *chain,
		       const char *table, int rulenum, int counters)
{
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	unsigned int format = 0;
	struct nftnl_chain *c;
	int ret = 1;

	/* If built-in chains don't exist for this table, create them */
	if (nft_xtables_config_load(h, XTABLES_CONFIG_DEFAULT, 0) < 0) {
		nft_xt_builtin_init(h, table);
		/* Force table and chain creation, otherwise first iptables -L
		 * lists no table/chains.
		 */
		if (!list_empty(&h->obj_list)) {
			nft_commit(h);
			flush_chain_cache(h, NULL);
		}
	}

	if (!nft_is_table_compatible(h, table)) {
		xtables_error(OTHER_PROBLEM, "table `%s' is incompatible, use 'nft' tool.\n", table);
		return 0;
	}

	list = nft_chain_dump(h);

	/* Dump policies and custom chains first */
	if (!rulenum)
		nftnl_rule_list_chain_save(h, chain, table, list, counters);

	/* Now dump out rules in this table */
	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		goto err;

	if (counters < 0)
		format = FMT_C_COUNTS;
	else if (counters == 0)
		format = FMT_NOCOUNTS;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_table =
			nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
		const char *chain_name =
			nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);

		if (strcmp(table, chain_table) != 0)
			goto next;
		if (chain && strcmp(chain, chain_name) != 0)
			goto next;

		ret = __nft_rule_list(h, chain_name, table, rulenum,
				      format, list_save);

		/* we printed the chain we wanted, stop processing. */
		if (chain)
			break;
next:
		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);
err:
	return ret;
}

int nft_rule_zero_counters(struct nft_handle *h, const char *chain,
			   const char *table, int rulenum)
{
	struct iptables_command_state cs = {};
	struct nftnl_rule_list *list;
	struct nftnl_rule *r;
	int ret = 0;

	nft_fn = nft_rule_delete;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return 0;

	r = nft_rule_find(h, list, chain, table, NULL, rulenum);
	if (r == NULL) {
		errno = ENOENT;
		ret = 1;
		goto error;
	}

	nft_rule_to_iptables_command_state(r, &cs);

	cs.counters.pcnt = cs.counters.bcnt = 0;

	ret =  nft_rule_append(h, chain, table, &cs,
			       nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE),
			       false);

error:
	return ret;
}

static void nft_compat_table_batch_add(struct nft_handle *h, uint16_t type,
				       uint16_t flags, uint32_t seq,
				       struct nftnl_table *table)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_table_nlmsg_build_hdr(nftnl_batch_buffer(h->batch),
					type, h->family, flags, seq);
	nftnl_table_nlmsg_build_payload(nlh, table);
}

static void nft_compat_chain_batch_add(struct nft_handle *h, uint16_t type,
				       uint16_t flags, uint32_t seq,
				       struct nftnl_chain *chain)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_chain_nlmsg_build_hdr(nftnl_batch_buffer(h->batch),
					type, h->family, flags, seq);
	nftnl_chain_nlmsg_build_payload(nlh, chain);
	nft_chain_print_debug(chain, nlh);
}

static void nft_compat_rule_batch_add(struct nft_handle *h, uint16_t type,
				      uint16_t flags, uint32_t seq,
				      struct nftnl_rule *rule)
{
	struct nlmsghdr *nlh;

	nlh = nftnl_rule_nlmsg_build_hdr(nftnl_batch_buffer(h->batch),
				       type, h->family, flags, seq);
	nftnl_rule_nlmsg_build_payload(nlh, rule);
	nft_rule_print_debug(rule, nlh);
}

static void batch_obj_del(struct nft_handle *h, struct obj_update *o)
{
	switch (o->type) {
	case NFT_COMPAT_TABLE_ADD:
	case NFT_COMPAT_TABLE_FLUSH:
		nftnl_table_free(o->table);
		break;
	case NFT_COMPAT_CHAIN_ZERO:
	case NFT_COMPAT_CHAIN_USER_ADD:
		break;
	case NFT_COMPAT_CHAIN_ADD:
	case NFT_COMPAT_CHAIN_USER_DEL:
	case NFT_COMPAT_CHAIN_USER_FLUSH:
	case NFT_COMPAT_CHAIN_UPDATE:
	case NFT_COMPAT_CHAIN_RENAME:
		nftnl_chain_free(o->chain);
		break;
	case NFT_COMPAT_RULE_APPEND:
	case NFT_COMPAT_RULE_INSERT:
	case NFT_COMPAT_RULE_REPLACE:
	case NFT_COMPAT_RULE_DELETE:
		break;
	case NFT_COMPAT_RULE_FLUSH:
		nftnl_rule_free(o->rule);
		break;
	}
	h->obj_list_num--;
	list_del(&o->head);
	free(o);
}

static int nft_action(struct nft_handle *h, int action)
{
	struct obj_update *n, *tmp;
	struct mnl_err *err, *ne;
	unsigned int buflen, i, len;
	bool show_errors = true;
	char errmsg[1024];
	uint32_t seq = 1;
	int ret = 0;

	h->batch = mnl_batch_init();

	mnl_batch_begin(h->batch, seq++);

	list_for_each_entry(n, &h->obj_list, head) {
		n->seq = seq++;
		switch (n->type) {
		case NFT_COMPAT_TABLE_ADD:
			nft_compat_table_batch_add(h, NFT_MSG_NEWTABLE,
						   NLM_F_CREATE, n->seq,
						   n->table);
			break;
		case NFT_COMPAT_TABLE_FLUSH:
			nft_compat_table_batch_add(h, NFT_MSG_DELTABLE,
						   0,
						   n->seq, n->table);
			break;
		case NFT_COMPAT_CHAIN_ADD:
		case NFT_COMPAT_CHAIN_ZERO:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN,
						   NLM_F_CREATE, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_USER_ADD:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN,
						   NLM_F_EXCL, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_USER_DEL:
			nft_compat_chain_batch_add(h, NFT_MSG_DELCHAIN,
						   NLM_F_NONREC, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_USER_FLUSH:
			nft_compat_chain_batch_add(h, NFT_MSG_DELCHAIN,
						   0, n->seq,
						   n->chain);
			break;
		case NFT_COMPAT_CHAIN_UPDATE:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN,
						   h->restore ?
						     NLM_F_CREATE : 0,
						   n->seq, n->chain);
			break;
		case NFT_COMPAT_CHAIN_RENAME:
			nft_compat_chain_batch_add(h, NFT_MSG_NEWCHAIN, 0,
						   n->seq, n->chain);
			break;
		case NFT_COMPAT_RULE_APPEND:
			nft_compat_rule_batch_add(h, NFT_MSG_NEWRULE,
						  NLM_F_CREATE | NLM_F_APPEND,
						  n->seq, n->rule);
			break;
		case NFT_COMPAT_RULE_INSERT:
			nft_compat_rule_batch_add(h, NFT_MSG_NEWRULE,
						  NLM_F_CREATE, n->seq,
						  n->rule);
			break;
		case NFT_COMPAT_RULE_REPLACE:
			nft_compat_rule_batch_add(h, NFT_MSG_NEWRULE,
						  NLM_F_CREATE | NLM_F_REPLACE,
						  n->seq, n->rule);
			break;
		case NFT_COMPAT_RULE_DELETE:
		case NFT_COMPAT_RULE_FLUSH:
			nft_compat_rule_batch_add(h, NFT_MSG_DELRULE, 0,
						  n->seq, n->rule);
			break;
		}

		mnl_nft_batch_continue(h->batch);
	}

	switch (action) {
	case NFT_COMPAT_COMMIT:
		mnl_batch_end(h->batch, seq++);
		break;
	case NFT_COMPAT_ABORT:
		break;
	}

	ret = mnl_batch_talk(h->nl, h->batch, &h->err_list);

	i = 0;
	buflen = sizeof(errmsg);

	list_for_each_entry_safe(n, tmp, &h->obj_list, head) {
		list_for_each_entry_safe(err, ne, &h->err_list, head) {
			if (err->seqnum > n->seq)
				break;

			if (err->seqnum == n->seq && show_errors) {
				if (n->error.lineno == 0)
					show_errors = false;
				len = mnl_append_error(h, n, err, errmsg + i, buflen);
				if (len > 0 && len <= buflen) {
					buflen -= len;
					i += len;
				}
			}
			mnl_err_list_free(err);
		}
		batch_obj_del(h, n);
	}

	mnl_batch_reset(h->batch);

	if (i)
		xtables_error(RESOURCE_PROBLEM, "%s", errmsg);

	return ret == 0 ? 1 : 0;
}

int nft_commit(struct nft_handle *h)
{
	return nft_action(h, NFT_COMPAT_COMMIT);
}

int nft_abort(struct nft_handle *h)
{
	return nft_action(h, NFT_COMPAT_ABORT);
}

int nft_compatible_revision(const char *name, uint8_t rev, int opt)
{
	struct mnl_socket *nl;
	char buf[16536];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, type = 0;
	uint32_t pf = AF_INET;
	int ret = 0;

	switch (opt) {
	case IPT_SO_GET_REVISION_MATCH:
		break;
	case IP6T_SO_GET_REVISION_MATCH:
		pf = AF_INET6;
		break;
	case IPT_SO_GET_REVISION_TARGET:
		type = 1;
		break;
	case IP6T_SO_GET_REVISION_TARGET:
		type = 1;
		pf = AF_INET6;
		break;
	default:
		/* No revision support (arp, ebtables), assume latest version ok */
		return 1;
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFT_COMPAT << 8) | NFNL_MSG_COMPAT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = pf;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	mnl_attr_put_strz(nlh, NFTA_COMPAT_NAME, name);
	mnl_attr_put_u32(nlh, NFTA_COMPAT_REV, htonl(rev));
	mnl_attr_put_u32(nlh, NFTA_COMPAT_TYPE, htonl(type));

	DEBUGP("requesting `%s' rev=%d type=%d via nft_compat\n",
		name, rev, type);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL)
		return 0;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		goto err;

	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		goto err;

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1)
		goto err;

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1)
		goto err;

err:
	mnl_socket_close(nl);

	return ret < 0 ? 0 : 1;
}

/* Translates errno numbers into more human-readable form than strerror. */
const char *nft_strerror(int err)
{
	unsigned int i;
	static struct table_struct {
		void *fn;
		int err;
		const char *message;
	} table[] =
	  {
	    { nft_chain_user_del, ENOTEMPTY, "Chain is not empty" },
	    { nft_chain_user_del, EINVAL, "Can't delete built-in chain" },
	    { nft_chain_user_del, EBUSY, "Directory not empty" },
	    { nft_chain_user_del, EMLINK,
	      "Can't delete chain with references left" },
	    { nft_chain_user_add, EEXIST, "Chain already exists" },
	    { nft_rule_insert, ENOENT, "Index of insertion too big" },
	    { nft_rule_check, ENOENT, "Bad rule (does a matching rule exist in that chain?)" },
	    { nft_rule_replace, ENOENT, "Index of replacement too big" },
	    { nft_rule_delete_num, ENOENT, "Index of deletion too big" },
/*	    { TC_READ_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_ZERO_COUNTER, E2BIG, "Index of counter too big" }, */
	    /* ENOENT for DELETE probably means no matching rule */
	    { nft_rule_delete, ENOENT,
	      "Bad rule (does a matching rule exist in that chain?)" },
	    { nft_chain_set, ENOENT, "Bad built-in chain name" },
	    { nft_chain_set, EINVAL, "Bad policy name" },
	    { NULL, ELOOP, "Loop found in table" },
	    { NULL, EPERM, "Permission denied (you must be root)" },
	    { NULL, 0, "Incompatible with this kernel" },
	    { NULL, ENOPROTOOPT, "iptables who? (do you need to insmod?)" },
	    { NULL, ENOSYS, "Will be implemented real soon.  I promise ;)" },
	    { NULL, ENOMEM, "Memory allocation problem" },
	    { NULL, ENOENT, "No chain/target/match by that name" },
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == nft_fn)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}

static void xtables_config_perror(uint32_t flags, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);

	if (flags & NFT_LOAD_VERBOSE)
		vfprintf(stderr, fmt, args);

	va_end(args);
}

static int __nft_xtables_config_load(struct nft_handle *h, const char *filename,
				     uint32_t flags)
{
	struct nftnl_table_list *table_list = NULL;
	struct nftnl_chain_list *chain_list = NULL;
	struct nftnl_table_list_iter *titer = NULL;
	struct nftnl_chain_list_iter *citer = NULL;
	struct nftnl_table *table;
	struct nftnl_chain *chain;
	uint32_t table_family, chain_family;
	bool found = false;

	table_list = nftnl_table_list_alloc();
	chain_list = nftnl_chain_list_alloc();

	if (xtables_config_parse(filename, table_list, chain_list) < 0) {
		if (errno == ENOENT) {
			xtables_config_perror(flags,
				"configuration file `%s' does not exists\n",
				filename);
		} else {
			xtables_config_perror(flags,
				"Fatal error parsing config file: %s\n",
				 strerror(errno));
		}
		goto err;
	}

	/* Stage 1) create tables */
	titer = nftnl_table_list_iter_create(table_list);
	while ((table = nftnl_table_list_iter_next(titer)) != NULL) {
		table_family = nftnl_table_get_u32(table,
						      NFTNL_TABLE_FAMILY);
		if (h->family != table_family)
			continue;

		found = true;

		if (batch_table_add(h, NFT_COMPAT_TABLE_ADD, table) < 0) {
			if (errno == EEXIST) {
				xtables_config_perror(flags,
					"table `%s' already exists, skipping\n",
					(char *)nftnl_table_get(table, NFTNL_TABLE_NAME));
			} else {
				xtables_config_perror(flags,
					"table `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nftnl_table_get(table, NFTNL_TABLE_NAME),
					strerror(errno));
				goto err;
			}
			continue;
		}
		xtables_config_perror(flags, "table `%s' has been created\n",
			(char *)nftnl_table_get(table, NFTNL_TABLE_NAME));
	}
	nftnl_table_list_iter_destroy(titer);
	nftnl_table_list_free(table_list);

	if (!found)
		goto err;

	/* Stage 2) create chains */
	citer = nftnl_chain_list_iter_create(chain_list);
	while ((chain = nftnl_chain_list_iter_next(citer)) != NULL) {
		chain_family = nftnl_chain_get_u32(chain,
						      NFTNL_CHAIN_TABLE);
		if (h->family != chain_family)
			continue;

		if (batch_chain_add(h, NFT_COMPAT_CHAIN_ADD, chain) < 0) {
			if (errno == EEXIST) {
				xtables_config_perror(flags,
					"chain `%s' already exists in table `%s', skipping\n",
					(char *)nftnl_chain_get(chain, NFTNL_CHAIN_NAME),
					(char *)nftnl_chain_get(chain, NFTNL_CHAIN_TABLE));
			} else {
				xtables_config_perror(flags,
					"chain `%s' cannot be create, reason `%s'. Exitting\n",
					(char *)nftnl_chain_get(chain, NFTNL_CHAIN_NAME),
					strerror(errno));
				goto err;
			}
			continue;
		}

		xtables_config_perror(flags,
			"chain `%s' in table `%s' has been created\n",
			(char *)nftnl_chain_get(chain, NFTNL_CHAIN_NAME),
			(char *)nftnl_chain_get(chain, NFTNL_CHAIN_TABLE));
	}
	nftnl_chain_list_iter_destroy(citer);
	nftnl_chain_list_free(chain_list);

	h->config_done = 1;

	return 0;

err:
	nftnl_table_list_free(table_list);
	nftnl_chain_list_free(chain_list);

	if (titer != NULL)
		nftnl_table_list_iter_destroy(titer);
	if (citer != NULL)
		nftnl_chain_list_iter_destroy(citer);

	h->config_done = -1;

	return -1;
}

int nft_xtables_config_load(struct nft_handle *h, const char *filename,
			    uint32_t flags)
{
	if (!h->config_done)
		return __nft_xtables_config_load(h, filename, flags);

	return h->config_done;
}

int nft_chain_zero_counters(struct nft_handle *h, const char *chain,
			    const char *table, bool verbose)
{
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *c;
	int ret = 0;

	list = nftnl_chain_list_get(h);
	if (list == NULL)
		goto err;

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		goto err;

	c = nftnl_chain_list_iter_next(iter);
	while (c != NULL) {
		const char *chain_name =
			nftnl_chain_get(c, NFTNL_CHAIN_NAME);
		const char *chain_table =
			nftnl_chain_get(c, NFTNL_CHAIN_TABLE);

		if (strcmp(table, chain_table) != 0)
			goto next;

		if (chain != NULL && strcmp(chain, chain_name) != 0)
			goto next;

		if (verbose)
			fprintf(stdout, "Zeroing chain `%s'\n", chain_name);

		nftnl_chain_set_u64(c, NFTNL_CHAIN_PACKETS, 0);
		nftnl_chain_set_u64(c, NFTNL_CHAIN_BYTES, 0);

		nftnl_chain_unset(c, NFTNL_CHAIN_HANDLE);

		ret = batch_chain_add(h, NFT_COMPAT_CHAIN_ZERO, c);

		if (chain != NULL)
			break;
next:
		c = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);

err:
	/* the core expects 1 for success and 0 for error */
	return ret == 0 ? 1 : 0;
}

uint32_t nft_invflags2cmp(uint32_t invflags, uint32_t flag)
{
	if (invflags & flag)
		return NFT_CMP_NEQ;

	return NFT_CMP_EQ;
}

#define NFT_COMPAT_EXPR_MAX     8

static const char *supported_exprs[NFT_COMPAT_EXPR_MAX] = {
	"match",
	"target",
	"payload",
	"meta",
	"cmp",
	"bitwise",
	"counter",
	"immediate"
};


static int nft_is_expr_compatible(const struct nftnl_expr *expr)
{
	const char *name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
	int i;

	for (i = 0; i < NFT_COMPAT_EXPR_MAX; i++) {
		if (strcmp(supported_exprs[i], name) == 0)
			return 0;
	}

	if (!strcmp(name, "limit") &&
	    nftnl_expr_get_u32(expr, NFTNL_EXPR_LIMIT_TYPE) == NFT_LIMIT_PKTS &&
	    nftnl_expr_get_u32(expr, NFTNL_EXPR_LIMIT_FLAGS) == 0)
		return 0;

	return 1;
}

static bool nft_is_rule_compatible(struct nftnl_rule *rule)
{
	struct nftnl_expr_iter *iter;
	struct nftnl_expr *expr;
	bool compatible = false;

	iter = nftnl_expr_iter_create(rule);
	if (iter == NULL)
		return false;

	expr = nftnl_expr_iter_next(iter);
	while (expr != NULL) {
		if (nft_is_expr_compatible(expr) == 0) {
			expr = nftnl_expr_iter_next(iter);
			continue;
		}

		compatible = true;
		break;
	}

	nftnl_expr_iter_destroy(iter);
	return compatible;
}

static int nft_is_chain_compatible(const struct nft_handle *h,
				   const struct nftnl_chain *chain)
{
	const char *table, *name, *type, *cur_table;
	struct builtin_chain *chains;
	int i, j, prio;
	enum nf_inet_hooks hook;

	table = nftnl_chain_get(chain, NFTNL_CHAIN_TABLE);
	name = nftnl_chain_get(chain, NFTNL_CHAIN_NAME);
	type = nftnl_chain_get(chain, NFTNL_CHAIN_TYPE);
	prio = nftnl_chain_get_u32(chain, NFTNL_CHAIN_PRIO);
	hook = nftnl_chain_get_u32(chain, NFTNL_CHAIN_HOOKNUM);

	for (i = 0; i < TABLES_MAX; i++) {
		cur_table = h->tables[i].name;
		chains = h->tables[i].chains;

		if (!cur_table || strcmp(table, cur_table) != 0)
			continue;

		for (j = 0; j < NF_INET_NUMHOOKS && chains[j].name; j++) {
			if (strcmp(name, chains[j].name) != 0)
				continue;

			if (strcmp(type, chains[j].type) == 0 &&
			    prio == chains[j].prio &&
			    hook == chains[j].hook)
				return 0;
			break;
		}
	}

	return 1;
}

static int nft_are_chains_compatible(struct nft_handle *h, const char *tablename)
{
	struct nftnl_chain_list *list;
	struct nftnl_chain_list_iter *iter;
	struct nftnl_chain *chain;
	int ret = 0;

	list = nftnl_chain_list_get(h);
	if (list == NULL)
		return -1;

	iter = nftnl_chain_list_iter_create(list);
	if (iter == NULL)
		return -1;

	chain = nftnl_chain_list_iter_next(iter);
	while (chain != NULL) {
		const char *chain_table;

		chain_table = nftnl_chain_get_str(chain, NFTNL_CHAIN_TABLE);

		if (strcmp(chain_table, tablename) ||
		    !nft_chain_builtin(chain))
			goto next;

		ret = nft_is_chain_compatible(h, chain);
		if (ret != 0)
			break;
next:
		chain = nftnl_chain_list_iter_next(iter);
	}

	nftnl_chain_list_iter_destroy(iter);

	return ret;
}

bool nft_is_table_compatible(struct nft_handle *h, const char *tablename)
{
	struct nftnl_rule_list *list;
	struct nftnl_rule_list_iter *iter;
	struct nftnl_rule *rule;
	int ret = 0, i;

	for (i = 0; i < TABLES_MAX; i++) {
		if (!h->tables[i].name)
			continue;
		if (strcmp(h->tables[i].name, tablename) == 0)
			break;
	}

	if (i == TABLES_MAX)
		return false;

	ret = nft_are_chains_compatible(h, tablename);
	if (ret != 0)
		return false;

	list = nft_rule_list_get(h);
	if (list == NULL)
		return true;

	iter = nftnl_rule_list_iter_create(list);
	if (iter == NULL)
		return true;

	rule = nftnl_rule_list_iter_next(iter);
	while (rule != NULL) {
		ret = nft_is_rule_compatible(rule);
		if (ret != 0)
			break;
		rule = nftnl_rule_list_iter_next(iter);
	}

	nftnl_rule_list_iter_destroy(iter);
	return ret == 0;
}
