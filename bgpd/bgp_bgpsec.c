/*
 * BGP RPKI
 * Copyright (C) 2013 Michael Mester (m.mester@fu-berlin.de), for FU Berlin
 * Copyright (C) 2014-2017 Andreas Reuter (andreas.reuter@fu-berlin.de), for FU
 * Berlin
 * Copyright (C) 2016-2017 Colin Sames (colin.sames@haw-hamburg.de), for HAW
 * Hamburg
 * Copyright (C) 2017-2018 Marcel Röthke (marcel.roethke@haw-hamburg.de),
 * for HAW Hamburg
 *
 * This file is part of FRRouting.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define LIBSSH_LEGACY_0_4

#include <zebra.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include "prefix.h"
#include "log.h"
#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "thread.h"
#include "filter.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgp_advertise.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "lib/network.h"
#include "lib/thread.h"
#ifndef VTYSH_EXTRACT_PL
#include "rtrlib/rtrlib.h"
#include "rtrlib/rtr_mgr.h"
#include "rtrlib/transport/tcp/tcp_transport.h"
#if defined(FOUND_SSH)
#include "rtrlib/transport/ssh/ssh_transport.h"
#endif
#endif
#include "hook.h"
#include "libfrr.h"
#include "version.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_bgpsec_clippy.c"
#endif

static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr);

static int put_bgpsec_cap(struct stream *s, struct peer *peer);

static int gen_bgpsec_sig(struct peer *peer, struct attr *attr,
			  struct bgp *bgp, struct prefix *p,
			  uint8_t **signature);

static int attr_bgpsec_path(struct bgp_attr_parser_args *args);

static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	uint8_t version_dir = 0;
	uint16_t afi = 0;

	version_dir = stream_getc(s);
	afi = stream_getw(s);

	if (hdr->length != CAPABILITY_CODE_BGPSEC_LEN) {
		flog_err(EC_BGP_CAPABILITY_INVALID_LENGTH,
			 "BGPSEC: received invalid capability header length %d",
			 hdr->length);
		return 1;
	}

	/* check, if the receive capability is set for IPv4/6
	 */
	if ((version_dir | (BGPSEC_DIR_RECEIVE << 3)) == 0) {
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_RCV);

		//TODO: The flags are set by the user via the vty for a certain peer.
		/*if (afi == BGPSEC_AFI_IPV4) {*/
			/*SET_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV4);*/
		/*} else if (afi == BGPSEC_AFI_IPV6) {*/
			/*SET_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV6);*/
		/*} else {*/
			//TODO: gives strange error code output in test.
			flog_err(EC_BGP_CAPABILITY_INVALID_DATA,
				 "BGPSEC: received invalid AFI %d in capability",
				 afi);
			return 1;
		/*}*/

		if (bgp_debug_neighbor_events(peer)) {
			zlog_debug("%s BGPSEC: Receive Capability received for AFI %d",
				   peer->host, afi);
		}
	}

	/* check, if the send capability is set set for IPv4/6
	 */
	if (version_dir & (BGPSEC_DIR_SEND << 3)) {
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_RCV);

		//TODO: The flags are set by the user via the vty for a certain peer.
		/*if (afi == BGPSEC_AFI_IPV4) {*/
			/*SET_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV4);*/
		/*} else if (afi == BGPSEC_AFI_IPV6) {*/
			/*SET_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV6);*/
		/*} else {*/
			//TODO: gives strange error code output in test.
			flog_err(EC_BGP_CAPABILITY_INVALID_DATA,
				 "BGPSEC: received invalid AFI %d in capability",
				 afi);
			return 1;
		/*}*/

		if (bgp_debug_neighbor_events(peer)) {
			zlog_debug("%s BGPSEC: Send Capability received for AFI %u",
				   peer->host, afi);
		}
	}

	return 0;
}

static int put_bgpsec_cap(struct stream *s, struct peer *peer)
{
	uint8_t bgpsec_version_dir = 0;
	uint16_t bgpsec_afi = 0;

	/* BGPsec IPv4 send capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV4)) {
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		bgpsec_version_dir = ((BGPSEC_VERSION << 4) | (BGPSEC_DIR_SEND << 3));
		bgpsec_afi = BGPSEC_AFI_IPV4;
		stream_putc(s, bgpsec_version_dir);
		stream_putw(s, bgpsec_afi);
		if (bgp_debug_neighbor_events(peer)) {
			zlog_debug(
				"%s BGPSEC: sending Send Capability for AFI IPv4",
				peer->host);
		}
	}

	/* BGPsec IPv4 receive capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV4)) {
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		bgpsec_version_dir = ((BGPSEC_VERSION << 4) | (BGPSEC_DIR_RECEIVE << 3));
		bgpsec_afi = BGPSEC_AFI_IPV4;
		stream_putc(s, bgpsec_version_dir);
		stream_putw(s, bgpsec_afi);
		if (bgp_debug_neighbor_events(peer)) {
			zlog_debug(
				"%s BGPSEC: sending Receive Capability for AFI IPv4",
				peer->host);
		}
	}

	//TODO: check if ipv6 capable
	/* BGPsec IPv6 send capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV6)) {
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		bgpsec_version_dir = ((BGPSEC_VERSION << 4) | (BGPSEC_DIR_SEND << 3));
		bgpsec_afi = BGPSEC_AFI_IPV6;
		stream_putc(s, bgpsec_version_dir);
		stream_putw(s, bgpsec_afi);
		if (bgp_debug_neighbor_events(peer)) {
			zlog_debug(
				"%s BGPSEC: sending Send Capability for AFI IPv6",
				peer->host);
		}
	}

	/* BGPsec IPv6 receive capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV6)) {
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		bgpsec_version_dir = ((BGPSEC_VERSION << 4) | (BGPSEC_DIR_RECEIVE << 3));
		bgpsec_afi = BGPSEC_AFI_IPV6;
		stream_putc(s, bgpsec_version_dir);
		stream_putw(s, bgpsec_afi);
		if (bgp_debug_neighbor_events(peer)) {
			zlog_debug(
				"%s BGPSEC: sending Receive Capability for AFI IPv6",
				peer->host);
		}
	}
	return 0;
}

static int gen_bgpsec_sig(struct peer *peer, struct attr *attr,
			  struct bgp *bgp, struct prefix *p,
			  uint8_t **signature)
{
	struct rtr_bgpsec *bgpsec = NULL;
	//TODO: write allocator function for this struct.
	struct rtr_bgpsec_nlri *pfx = NULL;

	struct rtr_signature_seg *ss = NULL;
	struct rtr_secure_path_seg *my_sps = NULL;
	struct rtr_signature_seg *new_ss = NULL;

	uint8_t flags = 0;
	uint8_t pcount = 0;
	uint16_t afi = 0;

	int bgpsec_origin = 0;
	int retval = 0;

	/* Check, if the peer can receive bgpsec updates, and we
	 * can also send bgpsec updates */
	if (CHECK_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_RCV)
	    && (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV4)
		|| CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV6)))
	{
		//TODO: only eBGP is covered right now.
		if (peer->sort == BGP_PEER_EBGP) {
			/* Set the confed flag if required */
			if (peer->sort == BGP_PEER_CONFED) {
				flags = 0x80;
			}
			/* Set the pCount to the appropriate value */
			//TODO: AS migration and pCounts > 1 are
			// currently ignored.
			if (peer->sort != BGP_PEER_CONFED) {
				pcount = 0;
			}

			/* Begin the signing process */

			/* This is the secure path segment of the local AS */
			my_sps = rtr_mgr_bgpsec_new_secure_path_seg(pcount,
								    flags,
								    ntohl(bgp->as));

			/* If the BGPsec_PATH has not been used before,
			 * then this is an origin UPDATE. */
			if (attr->bgpsecpath == NULL) {
				bgpsec_origin = 1;
				/* If this in indeed an origin UPDATE, allocate
				 * memory for the bgpsec_aspath structure */
				attr->bgpsecpath = XMALLOC(MTYPE_ATTR,
								sizeof(struct bgpsec_aspath));
			}

			//TODO: only the first signature block is
			// used right now.

			/* Assign all necessary values to the data struct */

			/* Use RTRlib struct to store the prefix, AFI and length.
			 * Store a IPv4/6 address according to the AFI. */
			pfx = XMALLOC(MTYPE_ATTR, sizeof(struct rtr_bgpsec_nlri));
			pfx->prefix_len = p->prefixlen;
			afi = family2afi(pfx->family);
			switch (afi) {
			case AFI_IP:
				pfx->prefix.ver = LRTR_IPV4;
				pfx->prefix.u.addr4.addr = p->u.prefix4.s_addr;
				break;
			case AFI_IP6:
				pfx->prefix.ver = LRTR_IPV6;
				pfx->prefix.u.addr6.addr = p->u.prefix6.s6_addr32;
				break;
			default:
				//TODO: catch error here. Should be caught before
				// doing BGPsec stuff, though.
				break;
			}

			uint8_t alg = attr->bgpsecpath->sigblock1->alg;

			bgpsec = rtr_mgr_bgpsec_new(alg,
						    SAFI_UNICAST, // for now...
						    afi,
						    bgp->as,
						    peer->as,
						    *pfx);

			/* Assemble all secure path segments, if there are any */
			/* First secure path */
			struct bgpsec_secpath *curr_sec =
					attr->bgpsecpath->secpaths;

			while (curr_sec) {
				struct rtr_secure_path_seg *seg =
					rtr_mgr_bgpsec_new_secure_path_seg(curr_sec->pcount,
									   curr_sec->flags,
									   curr_sec->as);
				rtr_mgr_bgpsec_append_sec_path_seg(bgpsec, seg);
				curr_sec = curr_sec->next;
			}

			/* Now prepend the own secure path segment. */
			rtr_mgr_bgpsec_prepend_sec_path_seg(bgpsec, my_sps);

			//TODO: make sure that sigblock1 is not NULL.
			struct bgpsec_sigseg *curr_sig =
						attr->bgpsecpath->sigblock1->sigsegs;

			while (curr_sig) {
				struct rtr_signature_seg *sig =
					rtr_mgr_bgpsec_new_signature_seg(curr_sig->ski,
									 curr_sig->sig_len,
									 curr_sig->signature);
				rtr_mgr_bgpsec_append_sig_seg(bgpsec, sig);
				curr_sec = curr_sec->next;
			}

			int retval = rtr_mgr_bgpsec_generate_signature(bgpsec,
								       bgp->priv_key,
								       &new_ss);
			if (retval != RTR_BGPSEC_SUCCESS) {
				//TODO: error handling if sig gen failed.
			}
			memcpy(new_ss->ski, bgp->ski, SKI_SIZE);
		}
	}
	memcpy(*signature, new_ss->signature, new_ss->sig_len);
	return 0;
}

static int attr_bgpsec_path(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	struct bgpsec_aspath *bgpsecpath = NULL;
	struct bgpsec_secpath *curr_path = NULL;
	struct bgpsec_secpath *prev_path = NULL;
	struct bgpsec_sigblock *sigblock1 = NULL;
	struct bgpsec_sigblock *sigblock2 = NULL;
	struct bgpsec_sigseg *curr_sig_path = NULL;
	struct bgpsec_sigseg *prev_sig_path = NULL;
	uint16_t sec_path_count = 0;
	uint16_t sigblock_len = 0;
	uint8_t alg = 0;
	bgp_size_t remain_len = length;

	sec_path_count = stream_getw(peer->curr) - 2;
	remain_len -= 2;

	bgpsecpath = XMALLOC(MTYPE_AS_PATH, sizeof(struct bgpsec_aspath));

	/* Build the secure path segments from the stream */
	for (int i = 0; i < sec_path_count; i++) {
		curr_path = XMALLOC(MTYPE_AS_PATH, sizeof(struct bgpsec_secpath));

		if (prev_path) {
			prev_path->next = curr_path;
		} else {
			/* If it is the head segment, add the head to the BGPsec_PATH */
			bgpsecpath->secpaths = curr_path;
		}

		curr_path->pcount = stream_getc(peer->curr);
		curr_path->flags = stream_getc(peer->curr);
		curr_path->as = stream_getl(peer->curr);
		remain_len -= 6;

		prev_path = curr_path;
	}

	/* Parse the first signature block from the stream and build the
	 * signature paths segments */
	sigblock1 = XMALLOC(MTYPE_AS_PATH, sizeof(struct bgpsec_sigblock));
	sigblock1->length = sigblock_len = stream_getw(peer->curr);
	sigblock1->alg = alg = stream_getc(peer->curr);
	while (sigblock_len > 0) {
		curr_sig_path = XMALLOC(MTYPE_AS_PATH, sizeof(struct bgpsec_secpath));

		if (prev_sig_path) {
			prev_sig_path->next = curr_sig_path;
		} else {
			/* If it is the head segment, add the head to the BGPsec_PATH */
			sigblock1->sigsegs = curr_sig_path;
		}

		stream_get(curr_sig_path->ski, peer->curr, 20);
		curr_sig_path->sig_len = stream_getw(peer->curr);
		stream_get(curr_sig_path->signature, peer->curr, curr_sig_path->sig_len);

		prev_sig_path = curr_sig_path;
		sigblock_len -= 22 + curr_sig_path->sig_len;
	}
	bgpsecpath->sigblock1 = sigblock1;
	remain_len -= sigblock1->length;

	/* The second signature block. Not currently used since the is only one
	 * algorithm suite right now. */
	if (remain_len > 0) {
		sigblock2 = XMALLOC(MTYPE_AS_PATH, sizeof(struct bgpsec_sigblock));
		sigblock2->length = sigblock_len = stream_getw(peer->curr);
		sigblock2->alg = alg = stream_getc(peer->curr);
		while (sigblock_len > 0) {
			curr_sig_path = XMALLOC(MTYPE_AS_PATH, sizeof(struct bgpsec_secpath));

			if (prev_sig_path) {
				prev_sig_path->next = curr_sig_path;
			} else {
				/* If it is the head segment, add the head to the BGPsec_PATH */
				sigblock2->sigsegs = curr_sig_path;
			}

			stream_get(curr_sig_path->ski, peer->curr, 20);
			curr_sig_path->sig_len = stream_getw(peer->curr);
			stream_get(curr_sig_path->signature, peer->curr, curr_sig_path->sig_len);

			prev_sig_path = curr_sig_path;
			sigblock_len -= 22 + curr_sig_path->sig_len;
		}
		bgpsecpath->sigblock2 = sigblock2;
	}

	attr->bgpsecpath = bgpsecpath;

	/*return BGP_ATTR_PARSE_PROCEED;*/
	return 0;
}

static int bgp_bgpsec_init(struct thread_master *master)
{
	/*rpki_debug = 0;*/
	/*rtr_is_running = 0;*/
	/*rtr_is_stopping = 0;*/

	/*cache_list = list_new();*/
	/*cache_list->del = (void (*)(void *)) & free_cache;*/

	/*polling_period = POLLING_PERIOD_DEFAULT;*/
	/*expire_interval = EXPIRE_INTERVAL_DEFAULT;*/
	/*retry_interval = RETRY_INTERVAL_DEFAULT;*/
	/*timeout = TIMEOUT_DEFAULT;*/
	/*initial_synchronisation_timeout =*/
		/*INITIAL_SYNCHRONISATION_TIMEOUT_DEFAULT;*/
	/*install_cli_commands();*/
	/*rpki_init_sync_socket();*/
	return 0;
}

static int bgp_bgpsec_module_init(void)
{
	lrtr_set_alloc_functions(malloc_wrapper, realloc_wrapper, free_wrapper);

	hook_register(frr_late_init, bgp_bgpsec_init);
	hook_register(frr_early_fini, &bgp_bgpsec_fini);

	hook_register(bgp_capability_bgpsec, capability_bgpsec);
	hook_register(bgp_put_bgpsec_cap, put_bgpsec_cap);
	hook_register(bgp_gen_bgpsec_sig, gen_bgpsec_sig);
	hook_register(bgp_attr_bgpsec_path, attr_bgpsec_path);

	return 0;
}

static int bgp_bgpsec_fini(void)
{
	/*stop();*/
	/*list_delete(&cache_list);*/

	/*close(rpki_sync_socket_rtr);*/
	/*close(rpki_sync_socket_bgpd);*/

	return 0;
}

FRR_MODULE_SETUP(.name = "bgpd_bgpsec", .version = "0.0.1",
		 .description = "Enable BGPsec support for FRR.",
		 .init = bgp_bgpsec_module_init)
