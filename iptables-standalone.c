/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 * Based on the ipchains code by Paul Russell and Michael Neuling
 *
 * (C) 2000-2002 by the netfilter coreteam <coreteam@netfilter.org>:
 * 		    Paul 'Rusty' Russell <rusty@rustcorp.com.au>
 * 		    Marc Boucher <marc+nf@mbsi.ca>
 * 		    James Morris <jmorris@intercode.com.au>
 * 		    Harald Welte <laforge@gnumonks.org>
 * 		    Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 *	iptables -- IP firewall administration for kernels with
 *	firewall table (aimed for the 2.3 kernels)
 *
 *	See the accompanying manual page iptables(8) for information
 *	about proper usage of this program.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <iptables.h>
#include "iptables-multi.h"

#ifdef IPTABLES_MULTI
int
iptables_main(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	int ret;
	char *table = "filter";
	struct iptc_handle *handle = NULL;

	program_name = "iptables";
	program_version = XTABLES_VERSION;

	lib_dir = getenv("XTABLES_LIBDIR");
	if (lib_dir == NULL) {
		lib_dir = getenv("IPTABLES_LIB_DIR");
		if (lib_dir != NULL)
			fprintf(stderr, "IPTABLES_LIB_DIR is deprecated, "
			        "use XTABLES_LIBDIR.\n");
	}
	if (lib_dir == NULL)
		lib_dir = XTABLES_LIBDIR;

#ifdef NO_SHARED_LIBS
	init_extensions();
#endif

	ret = do_command(argc, argv, &table, &handle);
	if (ret) {
		ret = iptc_commit(handle);
		iptc_free(handle);
	}

	if (!ret) {
		fprintf(stderr, "iptables: %s. "
				"Run `dmesg' for more information.\n",
			iptc_strerror(errno));
		if (errno == EAGAIN) {
			exit(RESOURCE_PROBLEM);
		}
	}

	exit(!ret);
}
