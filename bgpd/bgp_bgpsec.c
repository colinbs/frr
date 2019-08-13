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
#define RTRLIB_BGPSEC_ENABLED // TODO: This in only temporary!

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
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_errors.h"
#include "lib/network.h"
#include "lib/thread.h"
#include "lib/stream.h"
#ifndef VTYSH_EXTRACT_PL
#include "rtrlib/rtrlib.h"
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

#define BGPSEC_DEBUG(...)                                                \
	if (bgpsec_debug) {                                                  \
		zlog_debug("BGPSEC: " __VA_ARGS__);                              \
	}

#define BGPSEC_OUTPUT_STRING "Control BGPsec specific settings\n"

#define BGPSEC_SECURE_PATH_SEGMENT_SIZE 6

DEFINE_MTYPE_STATIC(BGPD, BGP_BGPSEC_VALIDATION, "BGP BGPsec AS path validation")

enum return_values { SUCCESS = 0, ERROR = -1 };

static int config_write(struct vty *vty);

static void install_cli_commands(void);

static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr);

static int put_bgpsec_cap(struct stream *s, struct peer *peer);

static int gen_bgpsec_sig(struct peer *peer, struct attr *attr,
			  struct bgp *bgp, struct prefix *p,
              struct bgpsec_secpath *own_secpath,
			  struct bgpsec_sigseg **own_sigseg);

static int attr_bgpsec_path(struct bgp_attr_parser_args *args);

static int write_bgpsec_aspath_to_stream(struct stream *s,
                                         struct bgpsec_aspath *aspath,
                                         int *bgpsec_attrlen,
                                         struct bgpsec_secpath own_secpath,
                                         struct bgpsec_sigseg *own_sigseg);

struct bgpsec_aspath *bgpsc_aspath_new(void);

struct bgpsec_sigblock *bgpsec_sigblock_new(void);

static int bgpsec_debug;

static struct cmd_node bgpsec_node = {BGPSEC_NODE, "%s(config-bgpsec)# ", 1};

static void *malloc_wrapper(size_t size)
{
	return XMALLOC(MTYPE_BGP_BGPSEC_VALIDATION, size);
}

static void *realloc_wrapper(void *ptr, size_t size)
{
	return XREALLOC(MTYPE_BGP_BGPSEC_VALIDATION, ptr, size);
}

static void free_wrapper(void *ptr)
{
	XFREE(MTYPE_BGP_BGPSEC_VALIDATION, ptr);
}

static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	uint8_t version_dir = 0;
	uint16_t afi = 0;

	version_dir = stream_getc(s);
	afi = stream_getw(s);

    BGPSEC_DEBUG("BGPsec capability received");

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
			BGPSEC_DEBUG("%s BGPSEC: Receive Capability received for AFI %d",
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
			BGPSEC_DEBUG("%s BGPSEC: Send Capability received for AFI %u",
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
			BGPSEC_DEBUG(
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
			BGPSEC_DEBUG(
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
			BGPSEC_DEBUG(
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
			BGPSEC_DEBUG(
				"%s BGPSEC: sending Receive Capability for AFI IPv6",
				peer->host);
		}
	}
	return 0;
}

static int gen_bgpsec_sig(struct peer *peer, struct attr *attr,
			  struct bgp *bgp, struct prefix *p,
              struct bgpsec_secpath *own_secpath,
			  struct bgpsec_sigseg **own_sigseg)
{
	struct rtr_bgpsec *bgpsec = NULL;
	struct rtr_bgpsec_nlri *pfx = NULL;

	struct rtr_signature_seg *ss = NULL;
	struct rtr_secure_path_seg *sps = NULL;
	struct rtr_secure_path_seg *my_sps = NULL;
	struct rtr_signature_seg *new_ss = NULL;

	uint16_t afi = 0;

	int bgpsec_origin = 0;
	int retval = 0;

    /* Begin the signing process */

    /* This is the secure path segment of the local AS */
    my_sps = rtr_mgr_bgpsec_new_secure_path_seg(
                                        own_secpath->pcount,
                                        own_secpath->flags,
                                        ntohl(own_secpath->as));

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
    pfx = XMALLOC(MTYPE_AS_PATH, sizeof(struct rtr_bgpsec_nlri));
    pfx->prefix_len = p->prefixlen;
    afi = family2afi(p->family);
    switch (afi) {
    case AFI_IP:
        pfx->prefix.ver = LRTR_IPV4;
        pfx->prefix.u.addr4.addr = p->u.prefix4.s_addr;
        break;
    case AFI_IP6:
        pfx->prefix.ver = LRTR_IPV6;
        memcpy(&pfx->prefix.u.addr6.addr, &p->u.prefix6.s6_addr32,
                sizeof(uint32_t) * 4);
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
        sps = rtr_mgr_bgpsec_new_secure_path_seg(curr_sec->pcount,
                                                 curr_sec->flags,
                                                 curr_sec->as);
        rtr_mgr_bgpsec_append_sec_path_seg(bgpsec, sps);
        curr_sec = curr_sec->next;
    }

    /* Now prepend the own secure path segment. */
    rtr_mgr_bgpsec_prepend_sec_path_seg(bgpsec, my_sps);

    //TODO: make sure that sigblock1 is not NULL.
    struct bgpsec_sigseg *curr_sig =
                attr->bgpsecpath->sigblock1->sigsegs;

    while (curr_sig) {
        ss = rtr_mgr_bgpsec_new_signature_seg(curr_sig->ski,
                                              curr_sig->sig_len,
                                              curr_sig->signature);
        rtr_mgr_bgpsec_append_sig_seg(bgpsec, ss);
        curr_sec = curr_sec->next;
    }

    retval = rtr_mgr_bgpsec_generate_signature(bgpsec,
                                               bgp->priv_key,
                                               &new_ss);
    if (retval != RTR_BGPSEC_SUCCESS) {
        //TODO: error handling if sig gen failed.
    }

    /* Init the own_sigseg struct */
    *own_sigseg = XMALLOC(MTYPE_ATTR, sizeof(struct bgpsec_sigseg));
    memset(*own_sigseg, 0, sizeof(struct bgpsec_sigseg));
    (*own_sigseg)->signature = XMALLOC(MTYPE_ATTR, new_ss->sig_len);

    /* Copy the signature and its length to the input parameters. */
    (*own_sigseg)->next = NULL;
    memcpy((*own_sigseg)->signature, new_ss->signature, new_ss->sig_len);
    (*own_sigseg)->sig_len = new_ss->sig_len;
    memcpy((*own_sigseg)->ski, new_ss->ski, SKI_LENGTH);

    rtr_mgr_bgpsec_nlri_free(pfx);
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

	sec_path_count = (stream_getw(peer->curr) / BGPSEC_SECURE_PATH_SEGMENT_SIZE) - 2;
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

    bgpsecpath->path_count = sec_path_count;

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

        sigblock1->sig_count++;
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

            sigblock1->sig_count++;
		}
		bgpsecpath->sigblock2 = sigblock2;
	}

	attr->bgpsecpath = bgpsecpath;
	return 0;
}

static int write_bgpsec_aspath_to_stream(struct stream *s,
                                         struct bgpsec_aspath *aspath,
                                         int *length,
                                         struct bgpsec_secpath own_secpath,
                                         struct bgpsec_sigseg *own_sigseg)
{
    struct bgpsec_sigblock *block = NULL;
    struct bgpsec_secpath *sec = NULL;
    struct bgpsec_sigseg *sig = NULL;
    int origin = 0;

    //TODO: origin or not?
    if (aspath->path_count == 0)
        origin = 1;

    /* Prepend own_secpath to the BGPsec path */
    if (origin) {
        block = aspath->sigblock1;
    } else {
        own_secpath.next = aspath->secpaths;
        own_sigseg->next = block->sigsegs;
    }

    /* Prepend own_sigseg to the signature segments */
    memcpy(aspath->secpaths, &own_secpath, sizeof(struct bgpsec_secpath));
    memcpy(block->sigsegs, own_sigseg, sizeof(struct bgpsec_sigseg));
    aspath->path_count++;
    block->sig_count++;

    /* Put in all secure path segments */
    sec = aspath->secpaths;
    while (sec) {
        stream_putc(s, sec->pcount);
        stream_putc(s, sec->flags);
        stream_putl(s, sec->as);

        sec = sec->next;
    }

    *length += aspath->path_count * BGPSEC_SECURE_PATH_SEGMENT_SIZE;

    /* Put in block length and algorithm ID */
    stream_putw(s, block->length);
    stream_putc(s, block->alg);

    /* Put in all signature segments */
    sig = block->sigsegs;
    while (sig) {
        stream_put(s, sig->ski, SKI_LENGTH);
        stream_putw(s, sig->sig_len);
        stream_put(s, sig->signature, sig->sig_len);

        sig = sig->next;
    }

    *length += block->length;
    memcpy(aspath->sigblock1, block, sizeof(struct bgpsec_sigblock));

    return 0;
}

static int bgp_bgpsec_init(struct thread_master *master)
{
    bgpsec_debug = 0;
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
    install_cli_commands();
	/*rpki_init_sync_socket();*/
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

static int bgp_bgpsec_module_init(void)
{
	lrtr_set_alloc_functions(malloc_wrapper, realloc_wrapper, free_wrapper);

	hook_register(frr_late_init, bgp_bgpsec_init);
	hook_register(frr_early_fini, &bgp_bgpsec_fini);

	hook_register(bgp_capability_bgpsec, capability_bgpsec);
	hook_register(bgp_put_bgpsec_cap, put_bgpsec_cap);
	hook_register(bgp_gen_bgpsec_sig, gen_bgpsec_sig);
	hook_register(bgp_attr_bgpsec_path, attr_bgpsec_path);

	hook_register(bgp_write_bgpsec_aspath_to_stream,
                  write_bgpsec_aspath_to_stream);

	return 0;
}

DEFUN_NOSH (bgpsec,
            bgpsec_cmd,
            "bgpsec",
            "Enable BGPsec and enter BGPsec configuration mode\n")
{
	vty->node = BGPSEC_NODE;
	return CMD_SUCCESS;
}

DEFUN (bgpsec_cap,
       bgpsec_cap_cmd,
       "bgpsec cap <send|receive> <ipv4|ipv6>",
       BGPSEC_OUTPUT_STRING
       "Set send and receive capabilities\n"
       "Send BGPsec updates for given AFI\n"
       "Receive BGPsec updates for given AFI\n"
       "IPv4 prefixes\n"
       "IPv6 prefixes\n")
{
    BGPSEC_DEBUG("BGPsec capabilities set: %s %s", argv[2]->arg, argv[3]->arg);
    return CMD_SUCCESS;
}

DEFUN (no_bgpsec_cap,
       no_bgpsec_cap_cmd,
       "no bgpsec cap <send|receive> <ipv4|ipv6>",
       NO_STR
       BGPSEC_OUTPUT_STRING
       "Unset send and receive capabilities\n"
       "Dont Send BGPsec updates for given AFI\n"
       "Dont Receive BGPsec updates for given AFI\n"
       "No IPv4 prefixes\n"
       "No IPv6 prefixes\n")
{
    BGPSEC_DEBUG("BGPsec capabilities unset: dont %s %s", argv[3]->arg, argv[4]->arg);
    return CMD_SUCCESS;
}

DEFUN (debug_bgpsec,
       debug_bgpsec_cmd,
       "debug bgpsec",
       DEBUG_STR
       "Enable debugging for BGPsec\n")
{
	bgpsec_debug = 1;
    BGPSEC_DEBUG("BGPsec debugging successfully enabled");
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgpsec,
       no_debug_bgpsec_cmd,
       "no debug bgpsec",
       NO_STR
       DEBUG_STR
       "Disable debugging for BGPsec\n")
{
	bgpsec_debug = 0;
    BGPSEC_DEBUG("BGPsec debugging successfully disabled");
	return CMD_SUCCESS;
}

DEFUN (bgpsec_start,
       bgpsec_start_cmd,
       "bgpsec start",
       BGPSEC_OUTPUT_STRING
       "start bgpsec support\n")
{
    BGPSEC_DEBUG("BGPsec started");
    struct bgp *bgp;
    bgp = bgp_get_default();
    if (bgp)
        BGPSEC_DEBUG("AS: %d", bgp->as);
    BGPSEC_DEBUG("No BGP set");
	return CMD_SUCCESS;
}

DEFUN (bgpsec_spass,
       bgpsec_spass_cmd,
       "bgpsec spass",
       BGPSEC_OUTPUT_STRING
       "bgpsec macht spass\n")
{
    BGPSEC_DEBUG("SO VIEL SPASS!!!");
    return CMD_SUCCESS;
}

DEFUN (bgpsec_stop,
       bgpsec_stop_cmd,
       "bgpsec stop",
       BGPSEC_OUTPUT_STRING
       "stop bgpsec support\n")
{
    BGPSEC_DEBUG("BGPsec stopped");
	return CMD_SUCCESS;
}

DEFUN_NOSH (bgpsec_exit,
            bgpsec_exit_cmd,
            "exit",
            "Exit BGPsec configuration and restart BGPsec session\n")
{
	/*reset(false);*/

	vty->node = CONFIG_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (bgpsec_quit,
            bgpsec_quit_cmd,
            "quit",
            "Exit BGPsec configuration mode\n")
{
	return bgpsec_exit(self, vty, argc, argv);
}

DEFUN_NOSH (bgpsec_end,
            bgpsec_end_cmd,
            "end",
            "End BGPsec configuration, restart BGPsec session and change to enable mode\n")
{
    int ret = SUCCESS;

	vty_config_exit(vty);
	vty->node = ENABLE_NODE;
	return ret == SUCCESS ? CMD_SUCCESS : CMD_WARNING;
}


static int config_write(struct vty *vty)
{
    return 1;
}

static void overwrite_exit_commands(void)
{
	unsigned int i;
	vector cmd_vector = bgpsec_node.cmd_vector;

	for (i = 0; i < cmd_vector->active; ++i) {
		struct cmd_element *cmd = vector_lookup(cmd_vector, i);

		if (strcmp(cmd->string, "exit") == 0
		    || strcmp(cmd->string, "quit") == 0
		    || strcmp(cmd->string, "end") == 0) {
			uninstall_element(BGPSEC_NODE, cmd);
		}
	}

	install_element(BGPSEC_NODE, &bgpsec_exit_cmd);
	install_element(BGPSEC_NODE, &bgpsec_quit_cmd);
	install_element(BGPSEC_NODE, &bgpsec_end_cmd);
}

static void install_cli_commands(void)
{
	install_node(&bgpsec_node, &config_write);
	install_default(BGPSEC_NODE);
	overwrite_exit_commands();
	install_element(CONFIG_NODE, &bgpsec_cmd);
	install_element(ENABLE_NODE, &bgpsec_cmd);

	install_element(ENABLE_NODE, &bgpsec_start_cmd);
	install_element(ENABLE_NODE, &bgpsec_stop_cmd);

	/* Install debug commands */
	install_element(CONFIG_NODE, &debug_bgpsec_cmd);
	install_element(ENABLE_NODE, &debug_bgpsec_cmd);
	install_element(CONFIG_NODE, &no_debug_bgpsec_cmd);
	install_element(ENABLE_NODE, &no_debug_bgpsec_cmd);

    /* Install capability commands */
    install_element(CONFIG_NODE, &bgpsec_cap_cmd);
    install_element(ENABLE_NODE, &bgpsec_cap_cmd);
    install_element(CONFIG_NODE, &no_bgpsec_cap_cmd);
    install_element(ENABLE_NODE, &no_bgpsec_cap_cmd);

    /* Try to append something to the AFI nodes */
    install_element(BGP_IPV4_NODE, &bgpsec_spass_cmd);
    install_element(BGP_IPV4M_NODE, &bgpsec_spass_cmd);
    install_element(BGP_IPV6_NODE, &bgpsec_spass_cmd);
    install_element(BGP_IPV6M_NODE, &bgpsec_spass_cmd);
}

FRR_MODULE_SETUP(.name = "bgpd_bgpsec", .version = "0.0.1",
		 .description = "Enable BGPsec support for FRR.",
		 .init = bgp_bgpsec_module_init)
