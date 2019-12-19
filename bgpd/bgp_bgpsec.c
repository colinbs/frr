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
#include <string.h>
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
#include "rtrlib/spki/spkitable.h"
/*#include "openssl/x509v3.h"*/
/*#include "openssl/pem.h"*/
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

#define BGPSEC_OUTPUT_STR "Control BGPsec specific settings\n"

#define BGPSEC_SECURE_PATH_SEGMENT_SIZE 6

#define PRIV_KEY_BUFFER_SIZE 500

struct cache {
	enum { TCP, SSH } type;
	struct tr_socket *tr_socket;
	union {
		struct tr_tcp_config *tcp_config;
		struct tr_ssh_config *ssh_config;
	} tr_config;
	struct rtr_socket *rtr_socket;
	uint8_t preference;
};

enum return_values { SUCCESS = 0, ERROR = -1 };

static int config_write(struct vty *vty);

static void install_cli_commands(void);

static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr);

static int put_bgpsec_cap(struct stream *s, struct peer *peer);

static int gen_bgpsec_sig(struct peer *peer, struct attr *attr,
                          struct bgp *bgp, struct prefix *p,
                          afi_t afi, safi_t safi,
                          struct bgpsec_secpath *own_secpath,
                          struct bgpsec_sigseg **own_sigseg);

static int attr_bgpsec_path(struct bgp_attr_parser_args *args);

static int build_bgpsec_aspath(struct bgp *bgp,
                               struct peer *peer,
                               struct stream *s,
                               struct attr *attr,
                               struct prefix *bgpsec_p,
                               afi_t afi,
                               safi_t safi);

static int write_bgpsec_aspath_to_stream(struct stream *s,
                                         struct bgpsec_aspath *aspath,
                                         int *bgpsec_attrlen,
                                         struct bgpsec_secpath *own_secpath,
                                         struct bgpsec_sigseg *own_sigseg);

static int val_bgpsec_aspath(struct attr *attr,
                             struct peer *peer,
                             struct bgp_nlri *mp_update);

struct private_key *bgpsec_private_key_new(void);

static int load_private_key_from_file(struct private_key *priv_key);

static void bgpsec_private_key_free(struct private_key *priv_key);

static int bgpsec_cleanup(struct bgp *bgp);

struct bgpsec_aspath *bgpsc_aspath_new(void);

struct bgpsec_sigblock *bgpsec_sigblock_new(void);

static int copy_rtr_data_to_frr(struct bgpsec_aspath *bgpsecpath,
                                struct rtr_bgpsec *data);

static int chartob16(unsigned char hex_char);

static int ski_char_to_hex(unsigned char *ski, uint8_t *buffer);

static int bgpsec_debug;

static struct rtr_mgr_config *rtr_config;
static int rtr_is_running;
static int rtr_is_starting;
static struct list *cache_list;

static struct cmd_node bgpsec_node = {BGPSEC_NODE, "%s(config-bgpsec)# ", 1};

static void *malloc_wrapper(size_t size)
{
	return XMALLOC(MTYPE_BGP_BGPSEC, size);
}

static void *realloc_wrapper(void *ptr, size_t size)
{
	return XREALLOC(MTYPE_BGP_BGPSEC, ptr, size);
}

static void free_wrapper(void *ptr)
{
	XFREE(MTYPE_BGP_BGPSEC, ptr);
}

/*
 * Parse a received BGPsec capability.
 */
static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	uint8_t version_dir = 0;
	uint16_t afi = 0;

	version_dir = stream_getc(s);
	afi = stream_getw(s);

    BGPSEC_DEBUG("BGPsec capability received. DIR: %d, AFI: %d", version_dir, afi);

	if (hdr->length != CAPABILITY_CODE_BGPSEC_LEN) {
		flog_err(EC_BGP_CAPABILITY_INVALID_LENGTH,
			 "BGPSEC: received invalid capability header length %d",
			 hdr->length);
		return 1;
	}

	/* check, if the receive capability is set for IPv4/6
	 */
	if ((version_dir | (BGPSEC_DIR_RECEIVE << 3)) == 0) {
		//TODO: The flags are set by the user via the vty for a certain peer.
        if (afi == AFI_IP) {
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV4_RCV);
        } else if (afi == AFI_IP6) {
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV6_RCV);
        } else {
            /*TODO: gives strange error code output in test.*/
            flog_err(EC_BGP_CAPABILITY_INVALID_DATA,
                 "BGPSEC: received invalid AFI %d in capability",
                 afi);
            return 1;
        }

		if (bgp_debug_neighbor_events(peer)) {
			BGPSEC_DEBUG("%s BGPSEC: Receive Capability received for AFI %d",
				   peer->host, afi);
		}
	}

	/* check, if the send capability is set set for IPv4/6
	 */
	if (version_dir & (BGPSEC_DIR_SEND << 3)) {
		//TODO: The flags are set by the user via the vty for a certain peer.
        if (afi == AFI_IP) {
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV4_RCV);
        } else if (afi == AFI_IP6) {
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV6_RCV);
        } else {
            /*TODO: gives strange error code output in test.*/
            flog_err(EC_BGP_CAPABILITY_INVALID_DATA,
                 "BGPSEC: received invalid AFI %d in capability",
                 afi);
            return 1;
        }

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
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV4_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		bgpsec_version_dir = ((BGPSEC_VERSION << 4) | (BGPSEC_DIR_SEND << 3));
		bgpsec_afi = BGPSEC_AFI_IPV4;
		stream_putc(s, bgpsec_version_dir);
		stream_putw(s, bgpsec_afi);
        BGPSEC_DEBUG(
            "%s BGPSEC: sending Send Capability for AFI IPv4",
            peer->host);
		if (bgp_debug_neighbor_events(peer)) {
			BGPSEC_DEBUG(
				"%s BGPSEC: sending Send Capability for AFI IPv4",
				peer->host);
		}
	}

	/* BGPsec IPv4 receive capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV4)) {
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV4_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		bgpsec_version_dir = ((BGPSEC_VERSION << 4) | (BGPSEC_DIR_RECEIVE << 3));
		bgpsec_afi = BGPSEC_AFI_IPV4;
		stream_putc(s, bgpsec_version_dir);
		stream_putw(s, bgpsec_afi);
        BGPSEC_DEBUG(
            "%s BGPSEC: sending Receive Capability for AFI IPv4",
            peer->host);
		if (bgp_debug_neighbor_events(peer)) {
			BGPSEC_DEBUG(
				"%s BGPSEC: sending Receive Capability for AFI IPv4",
				peer->host);
		}
	}

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
        BGPSEC_DEBUG(
            "%s BGPSEC: sending Send Capability for AFI IPv6",
            peer->host);
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
        BGPSEC_DEBUG(
            "%s BGPSEC: sending Receive Capability for AFI IPv6",
            peer->host);
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
                          afi_t afi, safi_t safi,
                          struct bgpsec_secpath *own_secpath,
                          struct bgpsec_sigseg **own_sigseg)
{
	struct rtr_bgpsec *bgpsec = NULL;
	struct rtr_bgpsec_nlri *pfx = NULL;

	struct rtr_signature_seg *ss = NULL;
	struct rtr_secure_path_seg *sps = NULL;
	struct rtr_secure_path_seg *my_sps = NULL;
	struct rtr_signature_seg *new_ss = NULL;

	int retval = 0;

    if (!p)
        return 1;

    /* Begin the signing process */

    /* This is the secure path segment of the local AS */
    my_sps = rtr_mgr_bgpsec_new_secure_path_seg(
                                        own_secpath->pcount,
                                        own_secpath->flags,
                                        own_secpath->as);

    /* If there are no signature or secure path segments
     * then this is an origin UPDATE. Hence, allocate memory. */
    if (attr->bgpsecpath->secpaths == NULL
        && attr->bgpsecpath->sigblock1 == NULL)
    {
        attr->bgpsecpath->sigblock1 = bgpsec_sigblock_new();
    }

    //TODO: only the first signature block is
    // used right now.

    /* Assign all necessary values to the data struct */

    /* Use RTRlib struct to store the prefix, AFI and length.
     * Store a IPv4/6 address according to the AFI. */
    pfx = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct rtr_bgpsec_nlri));
    pfx->prefix_len = p->prefixlen;
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

    bgpsec = rtr_mgr_bgpsec_new(alg, safi, afi, bgp->as, peer->as, *pfx);

    /* Assemble all secure path segments, if there are any */
    /* First secure path */
    struct bgpsec_secpath *curr_sec = attr->bgpsecpath->secpaths;

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

    /*bgp->priv_key = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct private_key));*/
    /*//TODO: set the path here for now. There needs to be a DEFUN to do this,*/
    /*//though.*/
    /*bgp->priv_key->filepath = "/home/colin/git/frr/bgpd/privkey.der";*/
    /*static uint8_t dummyski[] = {*/
        /*0xAB, 0x4D, 0x91, 0x0F, 0x55,*/
        /*0xCA, 0xE7, 0x1A, 0x21, 0x5E,*/
        /*0xF3, 0xCA, 0xFE, 0x3A, 0xCC,*/
        /*0x45, 0xB5, 0xEE, 0xC1, 0x54*/
    /*};*/
        /*[>0x47, 0xF2, 0x3B, 0xF1, 0xAB,<]*/
        /*[>0x2F, 0x8A, 0x9D, 0x26, 0x86,<]*/
        /*[>0x4E, 0xBB, 0xD8, 0xDF, 0x27,<]*/
        /*[>0x11, 0xC7, 0x44, 0x06, 0xEC<]*/
    /*memcpy(bgp->priv_key->ski, dummyski, SKI_SIZE);*/

    /*load_private_key_from_file(bgp->priv_key);*/

    if (!bgp->priv_key) {
        BGPSEC_DEBUG("Error: private key not loaded");
        bgpsec_secpath_free(own_secpath);
        return 1;
    }

    retval = rtr_mgr_bgpsec_generate_signature(bgpsec,
                                               bgp->priv_key->key_buffer,
                                               &new_ss);
    memcpy(new_ss->ski, bgp->priv_key->ski, SKI_SIZE);

    if (retval != RTR_BGPSEC_SUCCESS) {
        BGPSEC_DEBUG("Error while generating signature");
        bgpsec_secpath_free(own_secpath);
        return 1;
    }

    /* Init the own_sigseg struct */
    *own_sigseg = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct bgpsec_sigseg));
    memset(*own_sigseg, 0, sizeof(struct bgpsec_sigseg));
    (*own_sigseg)->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, new_ss->sig_len);

    /* Copy the signature and its length to the input parameters. */
    (*own_sigseg)->next = NULL;
    memcpy((*own_sigseg)->signature, new_ss->signature, new_ss->sig_len);
    (*own_sigseg)->sig_len = new_ss->sig_len;
    memcpy((*own_sigseg)->ski, new_ss->ski, SKI_LENGTH);

    XFREE(MTYPE_BGP_BGPSEC_PATH, pfx);
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
	struct bgpsec_sigseg *curr_sig_path = NULL;
	struct bgpsec_sigseg *prev_sig_path = NULL;
	uint16_t sec_path_count = 0;
	uint16_t sig_segs_len = 0;
	uint8_t alg = 0;
	bgp_size_t remain_len = length;

	sec_path_count = (stream_getw(peer->curr) - 2) / BGPSEC_SECURE_PATH_SEGMENT_SIZE;
	remain_len -= 2;

    bgpsecpath = bgpsec_aspath_new();

	/* Build the secure path segments from the stream */
	for (int i = 0; i < sec_path_count; i++) {
        curr_path = bgpsec_secpath_new();
		curr_path->pcount = stream_getc(peer->curr);
		curr_path->flags = stream_getc(peer->curr);
		curr_path->as = stream_getl(peer->curr);

		if (prev_path) {
			prev_path->next = curr_path;
		} else {
			/* If it is the head segment, add the head to the BGPsec_PATH */
			bgpsecpath->secpaths = curr_path;
		}

		remain_len -= 6;
		prev_path = curr_path;
	}

    bgpsecpath->path_count = sec_path_count;

	/* Parse the first signature block from the stream and build the
	 * signature paths segments */
	sigblock1 = bgpsec_sigblock_new();
    sigblock1->sig_count = 0;
	sigblock1->length = stream_getw(peer->curr);
	sigblock1->alg = alg = stream_getc(peer->curr);

    /* Subtract 3 (length and algorithm) from the total sigblock length to get
     * the length of the signature segments only. */
    sig_segs_len = sigblock1->length - 3;
	while (sig_segs_len > 0) {
		curr_sig_path = bgpsec_sigseg_new();

		if (prev_sig_path) {
			prev_sig_path->next = curr_sig_path;
		} else {
			/* If it is the head segment, add the head to the BGPsec_PATH */
			sigblock1->sigsegs = curr_sig_path;
		}

		stream_get(curr_sig_path->ski, peer->curr, 20);
		curr_sig_path->sig_len = stream_getw(peer->curr);
        curr_sig_path->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH,
                                           curr_sig_path->sig_len);
        if (!curr_sig_path->signature) {
            BGPSEC_DEBUG("Error: memory for signature cound not be allocated");
        }
		stream_get(curr_sig_path->signature, peer->curr, curr_sig_path->sig_len);

		prev_sig_path = curr_sig_path;
		sig_segs_len -= 22 + curr_sig_path->sig_len;

        sigblock1->sig_count++;
	}
	bgpsecpath->sigblock1 = sigblock1;
	remain_len -= sigblock1->length;

    // TODO: propper error handling in case some bytes are left in the end.
    if (remain_len > 0) {
        zlog_debug("Strange, there are still %d bytes left...", remain_len);
    }

	attr->bgpsecpath = bgpsecpath;
    attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_BGPSEC_PATH);

	return 0;
}

// DELETEME----
static struct spki_record *create_record(int ASN,
                                         uint8_t *ski,
                                         uint8_t *spki)
{
	struct spki_record *record = malloc(sizeof(struct spki_record));

	memset(record, 0, sizeof(*record));
	record->asn = ASN;
	memcpy(record->ski, ski, SKI_SIZE);
	memcpy(record->spki, spki, SPKI_SIZE);

	record->socket = NULL;
	return record;
}

static uint8_t ski1[]  = {
        0xAB, 0x4D, 0x91, 0x0F, 0x55,
        0xCA, 0xE7, 0x1A, 0x21, 0x5E,
        0xF3, 0xCA, 0xFE, 0x3A, 0xCC,
        0x45, 0xB5, 0xEE, 0xC1, 0x54
};

static uint8_t ski2[]  = {
		0x47, 0xF2, 0x3B, 0xF1, 0xAB,
		0x2F, 0x8A, 0x9D, 0x26, 0x86,
		0x4E, 0xBB, 0xD8, 0xDF, 0x27,
		0x11, 0xC7, 0x44, 0x06, 0xEC
};

static uint8_t spki1[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
		0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x73, 0x91, 0xBA,
        0xBB, 0x92, 0xA0, 0xCB, 0x3B, 0xE1, 0x0E, 0x59, 0xB1, 0x9E,
        0xBF, 0xFB, 0x21, 0x4E, 0x04, 0xA9, 0x1E, 0x0C, 0xBA, 0x1B,
        0x13, 0x9A, 0x7D, 0x38, 0xD9, 0x0F, 0x77, 0xE5, 0x5A, 0xA0,
        0x5B, 0x8E, 0x69, 0x56, 0x78, 0xE0, 0xFA, 0x16, 0x90, 0x4B,
        0x55, 0xD9, 0xD4, 0xF5, 0xC0, 0xDF, 0xC5, 0x88, 0x95, 0xEE,
        0x50, 0xBC, 0x4F, 0x75, 0xD2, 0x05, 0xA2, 0x5B, 0xD3, 0x6F,
        0xF5
};

static uint8_t spki2[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x28, 0xFC, 0x5F,
		0xE9, 0xAF, 0xCF, 0x5F, 0x4C, 0xAB, 0x3F, 0x5F, 0x85, 0xCB,
		0x21, 0x2F, 0xC1, 0xE9, 0xD0, 0xE0, 0xDB, 0xEA, 0xEE, 0x42,
		0x5B, 0xD2, 0xF0, 0xD3, 0x17, 0x5A, 0xA0, 0xE9, 0x89, 0xEA,
		0x9B, 0x60, 0x3E, 0x38, 0xF3, 0x5F, 0xB3, 0x29, 0xDF, 0x49,
		0x56, 0x41, 0xF2, 0xBA, 0x04, 0x0F, 0x1C, 0x3A, 0xC6, 0x13,
		0x83, 0x07, 0xF2, 0x57, 0xCB, 0xA6, 0xB8, 0xB5, 0x88, 0xF4,
		0x1F
};

static int load_private_key_from_file(struct private_key *priv_key)
{
    FILE *keyfile = fopen(priv_key->filepath, "r");
    uint8_t tmp_buff[PRIV_KEY_BUFFER_SIZE];
    uint16_t length = 0;
    //TODO: use X509_get0_subject_key_id() on an X509 cert to get the SKI.
    /*BIO *bio = BIO_new(BIO_s_file());*/
    /*X509 *cert = NULL;*/

    /*if (!keyfile) {*/
        /*BGPSEC_DEBUG("Could not read private key file %s", priv_key->filepath);*/
        /*return 1;*/
    /*}*/

    /*if (!bio) {*/
        /*BGPSEC_DEBUG("Could not create bio");*/
        /*return 1;*/
    /*}*/

    /*if (!BIO_read_filename(bio, priv_key->filepath)) {*/
        /*BGPSEC_DEBUG("Could not read file in bio");*/
        /*return 1;*/
    /*}*/

    /*PEM_read_bio_X509(bio, &cert, 0, NULL);*/

    /*if (!cert) {*/
        /*BGPSEC_DEBUG("Error loading key from bio");*/
        /*return 1;*/
    /*}*/

    /*const ASN1_OCTET_STRING *ski = X509_get0_subject_key_id(cert);*/

    length = fread(&tmp_buff, sizeof(uint8_t), PRIV_KEY_BUFFER_SIZE, keyfile);
    fclose(keyfile);

    if (length <= 0)
        return 1;

    priv_key->key_buffer = XMALLOC(MTYPE_BGP_BGPSEC_PRIV_KEY, length);
    if (!(priv_key->key_buffer))
        return 1;

    memcpy(priv_key->key_buffer, &tmp_buff, length);
    priv_key->key_len = length;

    return 0;
}

static void init_tr_socket(struct cache *cache)
{
	if (cache->type == TCP)
		tr_tcp_init(cache->tr_config.tcp_config,
			    cache->tr_socket);
}

static struct rtr_mgr_group *get_groups(void)
{
	struct listnode *cache_node;
	struct rtr_mgr_group *rtr_mgr_groups;
	struct cache *cache;

	int group_count = listcount(cache_list);

	if (group_count == 0)
		return NULL;

	rtr_mgr_groups = XMALLOC(MTYPE_BGP_RPKI_CACHE_GROUP,
				 group_count * sizeof(struct rtr_mgr_group));

	size_t i = 0;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		rtr_mgr_groups[i].sockets = &cache->rtr_socket;
		rtr_mgr_groups[i].sockets_len = 1;
		rtr_mgr_groups[i].preference = cache->preference;

		init_tr_socket(cache);

		i++;
	}

	return rtr_mgr_groups;
}

static int add_cache(struct cache *cache)
{
	uint8_t preference = cache->preference;
	struct rtr_mgr_group group;

	group.preference = preference;
	group.sockets_len = 1;
	group.sockets = &cache->rtr_socket;

	listnode_add(cache_list, cache);

	if (rtr_is_running) {
		init_tr_socket(cache);

		if (rtr_mgr_add_group(rtr_config, &group) != RTR_SUCCESS) {
            if (cache->type == TCP)
                tr_tcp_init(cache->tr_config.tcp_config,
                        cache->tr_socket);
			return ERROR;
		}
	}

	return SUCCESS;
}

static int add_tcp_cache(const char *host, const char *port,
			 const uint8_t preference)
{
	struct rtr_socket *rtr_socket;
	struct tr_tcp_config *tcp_config =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_tcp_config));
	struct tr_socket *tr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_socket));
	struct cache *cache =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct cache));

	tcp_config->host = XSTRDUP(MTYPE_BGP_RPKI_CACHE, host);
	tcp_config->port = XSTRDUP(MTYPE_BGP_RPKI_CACHE, port);
	tcp_config->bindaddr = NULL;

	rtr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct rtr_socket));
	rtr_socket->tr_socket = tr_socket;

	cache->type = TCP;
	cache->tr_socket = tr_socket;
	cache->tr_config.tcp_config = tcp_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	return add_cache(cache);
}


static int start(void)
{
	unsigned int waiting_time = 0;
    struct spki_record *record1;
    struct spki_record *record2;
	int ret;

	rtr_is_starting = 1;

    ret = add_tcp_cache("rpki-validator.realmv6.org", "8283", 1);
    if (ret == ERROR) {
        return ERROR;
    }

	if (list_isempty(cache_list)) {
		return ERROR;
	}
	int groups_len = listcount(cache_list);
	struct rtr_mgr_group *groups = get_groups();

	ret = rtr_mgr_init(&rtr_config, groups, groups_len, 3600,
			   7200, 600,
			   NULL, NULL, NULL, NULL);
	if (ret == RTR_ERROR) {
		return ERROR;
	}

	ret = rtr_mgr_start(rtr_config);
	if (ret == RTR_ERROR) {
		rtr_mgr_free(rtr_config);
		return ERROR;
	}
	rtr_is_running = 1;
	while (waiting_time++ <= 30) {
		if (rtr_mgr_conf_in_sync(rtr_config))
			break;

		sleep(1);
	}
	if (rtr_mgr_conf_in_sync(rtr_config)) {
		rtr_is_starting = 0;
	} else {
		rtr_is_starting = 0;
	}

    record1 = create_record(64496, ski1, spki1);
    rtr_mgr_bgpsec_add_spki_record(rtr_config, record1);

    record2 = create_record(65536, ski2, spki2);
    rtr_mgr_bgpsec_add_spki_record(rtr_config, record2);

	XFREE(MTYPE_BGP_RPKI_CACHE_GROUP, groups);
    free(record1);
    free(record2);

	return SUCCESS;
}
// ----DELETEME

static int copy_rtr_data_to_frr(struct bgpsec_aspath *bgpsecpath,
                                struct rtr_bgpsec *data)
{
    struct rtr_secure_path_seg *sec;
    struct rtr_signature_seg *sig;
    int result;

    for (int i = 0; i < bgpsecpath->path_count; i++) {
        sec = rtr_mgr_bgpsec_new_secure_path_seg(bgpsecpath->secpaths->pcount,
                                                 bgpsecpath->secpaths->flags,
                                                 bgpsecpath->secpaths->as);
        if (!sec)
            return 1;

        rtr_mgr_bgpsec_prepend_sec_path_seg(data, sec);
    }

    for (int i = 0; i < bgpsecpath->sigblock1->sig_count; i++) {
        sig = rtr_mgr_bgpsec_new_signature_seg(bgpsecpath->sigblock1->sigsegs->ski,
                                               bgpsecpath->sigblock1->sigsegs->sig_len,
                                               bgpsecpath->sigblock1->sigsegs->signature);
        if (!sig)
            return 1;

        result = rtr_mgr_bgpsec_prepend_sig_seg(data, sig);

        if (result == RTR_BGPSEC_ERROR) {
            BGPSEC_DEBUG("Error, signature cound not be prepended to bgpsec data");
            return 1;
        }
    }

    return 0;
}

static void handle_result(struct peer *peer, enum rtr_bgpsec_rtvals result)
{
    switch (result) {
    case RTR_BGPSEC_NOT_VALID:
        BGPSEC_DEBUG("%s At least one signature is not valid.", peer->host);
        break;
    case RTR_BGPSEC_VALID:
        BGPSEC_DEBUG("%s All signatures are valid.", peer->host);
        break;
    case RTR_BGPSEC_SUCCESS:
        BGPSEC_DEBUG("%s An operation was successful.", peer->host);
        break;
    case RTR_BGPSEC_ERROR:
        BGPSEC_DEBUG("%s An operation was not successful.", peer->host);
        break;
    case RTR_BGPSEC_LOAD_PUB_KEY_ERROR:
        BGPSEC_DEBUG("%s The public key could not be loaded.", peer->host);
        break;
    case RTR_BGPSEC_LOAD_PRIV_KEY_ERROR:
        BGPSEC_DEBUG("%s The private key could not be loaded.", peer->host);
        break;
    case RTR_BGPSEC_ROUTER_KEY_NOT_FOUND:
        BGPSEC_DEBUG("%s The SKI for a router key was not found.", peer->host);
        break;
    case RTR_BGPSEC_SIGNING_ERROR:
        BGPSEC_DEBUG("%s An error during signing occurred.", peer->host);
        break;
    case RTR_BGPSEC_UNSUPPORTED_ALGORITHM_SUITE:
        BGPSEC_DEBUG("%s The specified algorithm suite is not supported by RTRlib.", peer->host);
        break;
    case RTR_BGPSEC_UNSUPPORTED_AFI:
        BGPSEC_DEBUG("%s The specified AFI is not supported by BGPsec.", peer->host);
        break;
    case RTR_BGPSEC_WRONG_SEGMENT_AMOUNT:
        BGPSEC_DEBUG("%s The amount of signature and secure path segments are not equal.", peer->host);
        break;
    case RTR_BGPSEC_MISSING_DATA:
        BGPSEC_DEBUG("%s The data required for signing or validating is not complete.", peer->host);
        break;
    default:
        break;
    }
}

static int val_bgpsec_aspath(struct attr *attr,
                             struct peer *peer,
                             struct bgp_nlri *mp_update)
{
    enum rtr_bgpsec_rtvals result;
    int retval;
    struct rtr_bgpsec_nlri *pfx;
    struct rtr_bgpsec *data;
    struct bgpsec_aspath *bgpsecpath;
    struct bgp_nlri *mp_pfx = mp_update;
    uint8_t prefix_len_b;
    uint32_t n_ip = 0;
    uint32_t h_ip = 0;
    uint32_t h_ip6[4];

    if (!attr->bgpsecpath) {
        BGPSEC_DEBUG("Error: bgpsecpath is empty");
        return 1;
    }

    bgpsecpath = attr->bgpsecpath;

    if (!bgpsecpath->sigblock1) {
        BGPSEC_DEBUG("Error: sigblock1 is empty");
        return 1;
    }

    pfx = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct rtr_bgpsec_nlri));

    // The first byte of the NLRI is the length in bits.
    pfx->prefix_len = *mp_pfx->nlri;
    /*mp_pfx->nlri++; // Increment to skip the NLRI-length byte.*/
    prefix_len_b = (pfx->prefix_len + 7) / 8;

    switch (mp_pfx->afi) {
    case AFI_IP:
        pfx->prefix.ver = LRTR_IPV4;
        memcpy(&n_ip, (mp_pfx->nlri + 1), prefix_len_b); //inc nlri to skip len
        /*h_ip = ntohl(n_ip);*/
        h_ip = n_ip;
        memcpy(&(pfx->prefix.u.addr4.addr), &h_ip, sizeof(h_ip));
        break;
    case AFI_IP6:
        pfx->prefix.ver = LRTR_IPV6;
        memset(h_ip6, 0, sizeof(h_ip6));
        /*nip6toh(mp_pfx->nlri, h_ip6, prefix_len_b);*/
        memcpy(pfx->prefix.u.addr6.addr, (mp_pfx->nlri + 1), prefix_len_b); //inc nlri to skip len
        break;
    }

    data = rtr_mgr_bgpsec_new(bgpsecpath->sigblock1->alg,
                              mp_pfx->safi,
                              mp_pfx->afi,
                              peer->local_as,
                              peer->local_as,
                              *pfx);

    retval = copy_rtr_data_to_frr(bgpsecpath, data);

    if (retval) {
        BGPSEC_DEBUG("Error while copying RTR data to FRR");
        return 1;
    }

    result = rtr_mgr_bgpsec_validate_as_path(data, rtr_config);

    /* Prints out detailed information of the validation result. */
    handle_result(peer, result);

    if (result != RTR_BGPSEC_VALID)
        return 1;

    return 0;
}

static int build_bgpsec_aspath(struct bgp *bgp,
                               struct peer *peer,
                               struct stream *s,
                               struct attr *attr,
                               struct prefix *bgpsec_p,
                               afi_t afi,
                               safi_t safi)
{
    struct bgpsec_secpath *own_secpath = NULL;
    struct bgpsec_sigseg *own_sigseg = NULL;
    int bgpsec_attrlen = 0;
	size_t aspath_sizep;

    own_secpath = bgpsec_secpath_new();
    own_secpath->as = bgp->as;

    /* Check, if the peer can receive bgpsec updates, and we
     * can also send bgpsec updates */
    if ((CHECK_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV4_RCV) ||
        CHECK_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV4_RCV))
        && (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV4)
        || CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV6)))
    {
        //TODO: only eBGP is covered right now.
        if (peer->sort == BGP_PEER_EBGP || peer->sort == BGP_PEER_CONFED) {
            //TODO: check, if this is correct!
            /* Set the confed flag if required */
            if (peer->sort == BGP_PEER_CONFED) {
                own_secpath->flags = 0x80;
            }
            /* Set the pCount to the appropriate value */
            //TODO: AS migration and pCounts > 1 are
            // currently ignored.
            if (peer->sort != BGP_PEER_CONFED) {
                own_secpath->pcount = 1;
            }
        }
    } else {
        bgpsec_secpath_free(own_secpath);
        return 1;
    }

    //TODO: have a better way of detecting an origin message.
    /* If bgpsecpath is empty, this is an origin message */
    if (!attr->bgpsecpath) {
        attr->bgpsecpath = bgpsec_aspath_new();
    }

    /* Create the signature before writing the BGPsec path to the stream.
     * This saves stripping the path data from the stream again, in case
     * the signature could not be generated.
     */
    int foo = 0;
    foo = gen_bgpsec_sig(peer, attr, bgp, bgpsec_p, afi, safi, own_secpath, &own_sigseg);
    if (foo != 0) {
        zlog_debug("There has been an error");
        return 1;
    }

    if (own_sigseg) {
        stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTLEN);
        stream_putc(s, BGP_ATTR_BGPSEC_PATH);
        aspath_sizep = stream_get_endp(s);
        stream_putw(s, 0);
        write_bgpsec_aspath_to_stream(s, attr->bgpsecpath,
                                      &bgpsec_attrlen, own_secpath,
                                      own_sigseg);
        stream_putw_at(s, aspath_sizep, bgpsec_attrlen);
    } else {
        BGPSEC_DEBUG("Error generating signature");
        //TODO: error handling.
        return 1;
    }

    bgpsec_aspath_free(attr->bgpsecpath);
    attr->bgpsecpath = NULL;

    return 0;
}

static int write_bgpsec_aspath_to_stream(struct stream *s,
                                         struct bgpsec_aspath *aspath,
                                         int *length,
                                         struct bgpsec_secpath *own_secpath,
                                         struct bgpsec_sigseg *own_sigseg)
{
	size_t aspath_sizep;
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
        block->sigsegs = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct bgpsec_sigseg));
        aspath->secpaths = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct bgpsec_secpath));
    } else {
        //TODO: own_secpath->next pointer needs to be allocated.
        own_secpath->next = aspath->secpaths;
        own_sigseg->next = block->sigsegs;
    }

    /* Prepend own_sigseg to the signature segments */
    aspath->secpaths = own_secpath;
    block->sigsegs = own_sigseg;
    aspath->path_count++;
    block->sig_count++;

    stream_putw(s, (aspath->path_count * BGPSEC_SECURE_PATH_SEGMENT_SIZE) + 2);

    /* Put in all secure path segments */
    sec = aspath->secpaths;
    while (sec) {
        stream_putc(s, sec->pcount);
        stream_putc(s, sec->flags);
        stream_putl(s, sec->as);

        sec = sec->next;
    }

    *length += (aspath->path_count * BGPSEC_SECURE_PATH_SEGMENT_SIZE) + 2;

    /* Put in block length and algorithm ID */
    aspath_sizep = stream_get_endp(s);
    stream_putw(s, 0);
    stream_putc(s, block->alg);

    /* The length field + algo id */
    block->length += 3;

    /* Put in all signature segments */
    sig = block->sigsegs;
    while (sig) {
        stream_put(s, sig->ski, SKI_LENGTH);
        stream_putw(s, sig->sig_len);
        stream_put(s, sig->signature, sig->sig_len);
        block->length += SKI_LENGTH + sig->sig_len + sizeof(sig->sig_len);

        sig = sig->next;
    }
    stream_putw_at(s, aspath_sizep, block->length);

    *length += block->length;
    memcpy(aspath->sigblock1, block, sizeof(struct bgpsec_sigblock));

    return 0;
}

static int chartob16(unsigned char hex_char)
{
    if (hex_char > 47 && hex_char < 58)
        return hex_char - 48;

    if (hex_char > 64 && hex_char < 71)
        return hex_char - 55;
        
    if (hex_char > 96 && hex_char < 103)
        return hex_char - 87;

    return -1;
}

static int ski_char_to_hex(unsigned char *ski, uint8_t *buffer)
{
    char ch1;
    char ch2;

    for (int i = 0, j = 0; i < (SKI_STR_SIZE - 1); i += 2, j++) {
        ch1 = chartob16(ski[i]);
        ch2 = chartob16(ski[i+1]);
        if (ch1 == -1 || ch2 == -1)
            return (i + 1);
        buffer[j] = (ch1 << 4) | ch2;
    }

    return 0;
}

struct private_key *bgpsec_private_key_new(void)
{
    struct private_key *priv_key;

    priv_key = XMALLOC(MTYPE_BGP_BGPSEC_PRIV_KEY, sizeof(struct private_key));

    if (!priv_key)
        return NULL;

    memset(priv_key->ski, 0, SKI_SIZE);
    memset(priv_key->ski_str, 0, SKI_STR_SIZE);

    return priv_key;
}

static int bgpsec_cleanup(struct bgp *bgp)
{
    bgpsec_private_key_free(bgp->priv_key);
    bgp->priv_key = NULL;
    return 0;
}

static void bgpsec_private_key_free(struct private_key *priv_key)
{
    if (!priv_key)
        return;
    
    XFREE(MTYPE_BGP_BGPSEC_PRIV_KEY, priv_key->key_buffer);
    priv_key->key_buffer = NULL;
    XFREE(MTYPE_BGP_BGPSEC_PRIV_KEY, priv_key);
}

static int bgp_bgpsec_init(struct thread_master *master)
{
    int bgpsec_debug = 0;
    int rtr_is_running = 0;
    int rtr_is_stopping = 0;
    int ret = 0;

    cache_list = list_new();
    /*cache_list->del = (void (*)(void *)) & free_cache;*/

    /*polling_period = POLLING_PERIOD_DEFAULT;*/
    /*expire_interval = EXPIRE_INTERVAL_DEFAULT;*/
    /*retry_interval = RETRY_INTERVAL_DEFAULT;*/
    /*timeout = TIMEOUT_DEFAULT;*/
    /*initial_synchronisation_timeout =*/
        /*INITIAL_SYNCHRONISATION_TIMEOUT_DEFAULT;*/
    install_cli_commands();
    /*rpki_init_sync_socket();*/
    ret = start();

	return 0;
}

static int bgp_bgpsec_fini(void)
{
	rtr_mgr_stop(rtr_config);
	rtr_mgr_free(rtr_config);
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
	hook_register(bgp_attr_bgpsec_path, attr_bgpsec_path);

    hook_register(bgp_packet_build_bgpsec_aspath,
                  build_bgpsec_aspath);
    hook_register(bgp_val_bgpsec_aspath, val_bgpsec_aspath);

    hook_register(bgp_bgpsec_cleanup, bgpsec_cleanup);

	return 0;
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

DEFUN (bgpsec_private_key,
       bgpsec_private_key_cmd,
       "bgpsec privkey WORD",
       BGPSEC_OUTPUT_STR
       "Set the BGPsec private key\n"
       "Set path to BGPsec private key file\n")
{
    struct bgp *bgp;
    int result;
    int idx_path = 2;

    bgp = bgp_get_default();
    if (bgp) {
        if (bgp->priv_key) {
            bgpsec_private_key_free(bgp->priv_key);
            bgp->priv_key = NULL;
        }

        bgp->priv_key = bgpsec_private_key_new();

        if (!bgp->priv_key) {
            vty_out(vty, "Error while allocating private key memory\n");
            return CMD_WARNING_CONFIG_FAILED;
        }

        bgp->priv_key->filepath = (const char *)argv[idx_path]->arg;
        result = load_private_key_from_file(bgp->priv_key);

        if (result) {
            vty_out(vty, "Error while loading private key file\n");
            return CMD_WARNING_CONFIG_FAILED;
        }

        bgp->priv_key->loaded = true;
        bgp->priv_key->active = true;

        BGPSEC_DEBUG("Successfully loaded private key %s",
                     bgp->priv_key->filepath);
    } else {
		vty_out(vty, "%% No BGP process is configured\n");
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (bgpsec_private_key_ski,
       bgpsec_private_key_ski_cmd,
       "bgpsec privkey ski WORD",
       BGPSEC_OUTPUT_STR
       "Set the BGPsec private key\n"
       "Set the SKI\n"
       "The SKI\n")
{
    struct bgp *bgp;
    int result;
    int idx_path = 3;
    int len;

    bgp = bgp_get_default();
    if (bgp) {
        if (!bgp->priv_key) {
            vty_out(vty, "No private key is set\n");
            return CMD_WARNING_CONFIG_FAILED;
        }

        len = strlen(argv[idx_path]->arg);
        if (len != 40) { // 20 * 2
            vty_out(vty, "The SKI must be exactly 40 characters long (20 bytes)\n");
            return CMD_WARNING_CONFIG_FAILED;
        }

        memcpy(bgp->priv_key->ski_str, argv[idx_path]->arg, SKI_STR_SIZE);
        result = ski_char_to_hex(bgp->priv_key->ski_str, bgp->priv_key->ski);

        if (result != 0) {
            vty_out(vty, "Error: non-hex character found at position %d\n", result);
            return CMD_WARNING_CONFIG_FAILED;
        }

        BGPSEC_DEBUG("Successfully set SKI %s", bgp->priv_key->ski_str);
    } else {
		vty_out(vty, "%% No BGP process is configured\n");
        return CMD_WARNING;
    }

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

DEFUN_NOSH (bgpsec_exit,
            bgpsec_exit_cmd,
            "exit",
            "Exit BGPsec configuration and restart BGPsec session\n")
{
	/*reset(false);*/

	vty->node = BGP_NODE;
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
			uninstall_element(BGP_NODE, cmd);
		}
	}

	install_element(BGP_NODE, &bgpsec_exit_cmd);
	install_element(BGP_NODE, &bgpsec_quit_cmd);
	install_element(BGP_NODE, &bgpsec_end_cmd);
}

static void install_cli_commands(void)
{
    install_node(&bgpsec_node, &config_write);
    install_default(BGPSEC_NODE);
    overwrite_exit_commands();

    install_element(BGP_NODE, &bgpsec_private_key_cmd);
    install_element(BGP_NODE, &bgpsec_private_key_ski_cmd);

	/* Install debug commands */
	install_element(CONFIG_NODE, &debug_bgpsec_cmd);
	install_element(ENABLE_NODE, &debug_bgpsec_cmd);
	install_element(CONFIG_NODE, &no_debug_bgpsec_cmd);
	install_element(ENABLE_NODE, &no_debug_bgpsec_cmd);
}

FRR_MODULE_SETUP(.name = "bgpd_bgpsec", .version = "0.0.1",
		 .description = "Enable BGPsec support for FRR.",
		 .init = bgp_bgpsec_module_init)
