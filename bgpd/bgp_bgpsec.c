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
#include "bgpd/bgp_packet.h"
#include "lib/network.h"
#include "lib/thread.h"
#include "lib/stream.h"
#ifndef VTYSH_EXTRACT_PL
#include "rtrlib/rtrlib.h"
#include "rtrlib/transport/tcp/tcp_transport.h"
#include "rtrlib/spki/spkitable.h"
#include "bgpd/bgp_bgpsec_clippy.c"
#if defined(FOUND_SSH)
#include "rtrlib/transport/ssh/ssh_transport.h"
#endif
#endif
#include "hook.h"
#include "libfrr.h"
#include "version.h"

#define BGPSEC_DEBUG(...)                                                \
	if (term_bgp_debug_bgpsec) {                                         \
		zlog_debug("BGPSEC: " __VA_ARGS__);                              \
	}

#define SS_LEN(ss) SKI_LENGTH + ss->sig_len + sizeof(ss->sig_len)

#define BGPSEC_OUTPUT_STRING "Control BGPsec specific settings\n"

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

static int config_on_exit(struct vty *vty);

static void install_cli_commands(void);

static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr);

static const char *dir2str(uint8_t dir);

static int put_bgpsec_cap(struct stream *s, struct peer *peer);

static int gen_bgpsec_sig(struct peer *peer, struct bgpsec_aspath *bgpsecpath,
                          struct bgp *bgp, const struct prefix *p,
                          afi_t afi, safi_t safi,
                          struct bgpsec_secpath *own_sps,
                          struct bgpsec_sigseg **own_ss);

static int attr_bgpsec_path(struct bgp_attr_parser_args *args);

static int build_bgpsec_aspath(struct bgp *bgp,
                               struct peer *peer,
                               struct stream *s,
                               struct attr *attr,
                               const struct prefix *bgpsec_p,
                               afi_t afi,
                               safi_t safi);

static int write_bgpsec_aspath_to_stream(struct stream *s,
                                         struct bgpsec_aspath *aspath,
                                         int *bgpsec_attrlen,
                                         struct bgpsec_secpath *own_sps,
                                         struct bgpsec_sigseg *own_ss,
                                         int sig_only);

static int val_bgpsec_aspath(struct attr *attr,
                             struct peer *peer,
                             struct bgp_nlri *mp_update);

struct private_key *bgpsec_private_key_new(void);

static int load_private_key_from_file(struct private_key *priv_key);

static void bgpsec_private_key_free(struct private_key *priv_key);

static int bgpsec_cleanup(struct bgp *bgp);

static int copy_rtr_data_to_frr(struct bgpsec_aspath *bgpsecpath,
                                struct rtr_bgpsec *data);

static int chartob16(unsigned char hex_char);

static int ski_char_to_hex(unsigned char *ski, uint8_t *buffer);

static int bgpsec_path2str(struct bgpsec_aspath *aspath);

static int copy_mp_update(struct attr *attr, struct bgp_nlri *mp_update);

static struct rtr_mgr_config *rtr_config;
static int rtr_is_running;
static int rtr_is_starting;
static int rtr_is_stopping;
static _Atomic int rtr_update_overflow;
static struct list *cache_list;
static int rpki_sync_socket_rtr;
static int rpki_sync_socket_bgpd;

/*static struct cmd_node bgpsec_node = {*/
    /*.name = "bgpsec",*/
    /*.node = BGPSEC_NODE,*/
    /*.parent_node = CONFIG_NODE,*/
    /*.prompt = "%s(config-bgpsec)# ",*/
    /*.config_write = config_write,*/
    /*.node_exit = config_on_exit,*/
/*};*/

/*
 * Allocation/free wrapper
 */
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
 * Parse a received BGPsec capability
 */
static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	uint8_t version_dir = 0;
    uint8_t dir = 0;
	uint16_t afi = 0;

	version_dir = stream_getc(s);
	afi = stream_getw(s);

    dir = version_dir >> 3;

	if (hdr->length != CAPABILITY_CODE_BGPSEC_LEN) {
		flog_err(EC_BGP_CAPABILITY_INVALID_LENGTH,
			 "BGPsec Cap: Received invalid length %d, non-multiple of 3",
			 hdr->length);
		return 1;
	}

    if ((version_dir >> 4) > BGPSEC_VERSION) {
		flog_err(EC_BGP_BGPSEC_UNSUPPORTED_VERSION,
			 "BGPsec Cap: Received unsupported BGPsec version %d",
			 (version_dir >> 4));
		return 1;
    }

    if (afi != AFI_IP && afi != AFI_IP6) {
        flog_err(EC_BGP_CAPABILITY_INVALID_DATA,
             "%s: Received invalid AFI %d in BGPsec capability from peer %s",
             __func__, afi, peer->host);
        return 1;
    }

    if (dir != BGPSEC_DIR_RECEIVE && dir != BGPSEC_DIR_SEND) {
        flog_err(EC_BGP_CAPABILITY_INVALID_DATA,
             "%s: Received invalid direction %d in "
             "BGPsec capability from peer %s",
             __func__, dir, peer->host);
        return 1;
    }

    switch (dir) {
    case BGPSEC_DIR_RECEIVE:
        /* check, if the RECEIVE capability is set for IPv4/6
         */
        if (afi == AFI_IP)
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV4_RCV);
        else if (afi == AFI_IP6)
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV6_RCV);
        break;
    case BGPSEC_DIR_SEND:
        /* check, if the SEND capability is set set for IPv4/6
         */
        if (afi == AFI_IP)
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV4_RCV);
        else if (afi == AFI_IP6)
            SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV6_RCV);
        break;
    default:
        break;
    }

    if (bgp_debug_neighbor_events(peer)) {
        BGPSEC_DEBUG("%s rcvd %s capability for AFI %s, version %d",
                     peer->host, dir2str(version_dir), afi2str(afi),
                     version_dir >> 4);
    }

	return 0;
}

/*
 * Write BGPsec capabilities to a stream
 */
static int put_bgpsec_cap(struct stream *s, struct peer *peer)
{
	uint8_t bgpsec_version = 0;
    uint8_t bgpsec_send = 0;
    uint8_t bgpsec_receive = 0;

    bgpsec_version = BGPSEC_VERSION << 4;
    bgpsec_send = BGPSEC_DIR_SEND << 3;
    bgpsec_receive = BGPSEC_DIR_RECEIVE << 3;

	/* BGPsec IPv4 SEND capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV4)) {
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV4_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		stream_putc(s, (bgpsec_version | bgpsec_send));
		stream_putw(s, BGPSEC_AFI_IPV4);
		if (bgp_debug_neighbor_events(peer)) {
			BGPSEC_DEBUG(
                "%s send SEND capability for IPv4",
				peer->host);
		}
	}

	/* BGPsec IPv4 RECEIVE capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV4)) {
		SET_FLAG(peer->cap, PEER_CAP_BGPSEC_RECEIVE_IPV4_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		stream_putc(s, (bgpsec_version | bgpsec_receive));
		stream_putw(s, BGPSEC_AFI_IPV4);
		if (bgp_debug_neighbor_events(peer)) {
			BGPSEC_DEBUG(
                "%s send RECEIVE capability for IPv4",
				peer->host);
		}
	}

	/* BGPsec IPv6 SEND capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV6)) {
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		stream_putc(s, (bgpsec_version | bgpsec_send));
		stream_putw(s, BGPSEC_AFI_IPV6);
		if (bgp_debug_neighbor_events(peer)) {
			BGPSEC_DEBUG(
                "%s send SEND capability for IPv6",
				peer->host);
		}
	}

	/* BGPsec IPv6 RECEIVE capability
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_RECEIVE_IPV6)) {
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_BGPSEC);
		stream_putc(s, CAPABILITY_CODE_BGPSEC_LEN);
		stream_putc(s, (bgpsec_version | bgpsec_receive));
		stream_putw(s, BGPSEC_AFI_IPV6);
		if (bgp_debug_neighbor_events(peer)) {
			BGPSEC_DEBUG(
                "%s send RECEIVE capability for IPv6",
				peer->host);
		}
	}
	return 0;
}

/*
 * Generate a BGPsec signature and write it to own_ss
 *
 * TODO: only one signature block is processed right now.
 * New algorithm suites require the generation
 * of a signature for both signature blocks.
 */
static int gen_bgpsec_sig(struct peer *peer, struct bgpsec_aspath *bgpsecpath,
                          struct bgp *bgp, const struct prefix *p,
                          afi_t afi, safi_t safi,
                          struct bgpsec_secpath *own_sps,
                          struct bgpsec_sigseg **own_ss)
{
	struct rtr_bgpsec *bgpsec = NULL;
	struct rtr_bgpsec_nlri *pfx = NULL;

	struct rtr_signature_seg *rtr_ss = NULL;
	struct rtr_secure_path_seg *rtr_sps = NULL;
	struct rtr_secure_path_seg *rtr_my_sps = NULL;
	struct rtr_signature_seg *rtr_new_ss = NULL;

    struct bgpsec_secpath *curr_sps = NULL;
    struct bgpsec_sigseg *curr_ss = NULL;

    /* Temp pointer, will be assigned to *own_ss in the end */
	struct bgpsec_sigseg *frr_new_ss = NULL;

    uint8_t alg = 0;

	int retval = 0;

    if (!p)
        return 1;

    /* Private key must be loaded */
    if (!bgp->priv_key) {
        BGPSEC_DEBUG("Private key not loaded");
        return 1;
    }

    /* If there are no signature or secure path segments
     * then this is an origin UPDATE. Hence, allocate memory. */
    if (bgpsecpath->secpaths == NULL
        && bgpsecpath->sigblock1 == NULL)
    {
        bgpsecpath->sigblock1 = bgpsec_sigblock_new();
    }

    /* Use RTRlib struct to store the prefix, AFI and length.
     * Store an IPv4/6 address according to the AFI. */
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
        /* Validity of AFI was already checked in build_bgpsec_aspath */
        break;
    }

    alg = bgpsecpath->sigblock1->alg;

    bgpsec = rtr_mgr_bgpsec_new(alg, safi, afi, bgp->as, peer->as, *pfx);

    /* Assemble all secure path segments, if there are any */
    /* First secure path */
    curr_sps = bgpsecpath->secpaths;

    while (curr_sps) {
        rtr_sps = rtr_mgr_bgpsec_new_secure_path_seg(curr_sps->pcount,
                                                     curr_sps->flags,
                                                     curr_sps->as);
        rtr_mgr_bgpsec_append_sec_path_seg(bgpsec, rtr_sps);
        curr_sps = curr_sps->next;
    }

    /* This is the secure path segment of the local AS */
    rtr_my_sps = rtr_mgr_bgpsec_new_secure_path_seg(
                                        own_sps->pcount,
                                        own_sps->flags,
                                        own_sps->as);

    /* Now prepend the own secure path segment */
    rtr_mgr_bgpsec_prepend_sec_path_seg(bgpsec, rtr_my_sps);

    /* Repeat the procedure, this time with the signatures */
    curr_ss = bgpsecpath->sigblock1->sigsegs;

    while (curr_ss) {
        rtr_ss = rtr_mgr_bgpsec_new_signature_seg(curr_ss->ski,
                                                  curr_ss->sig_len,
                                                  curr_ss->signature);
        rtr_mgr_bgpsec_append_sig_seg(bgpsec, rtr_ss);
        curr_ss = curr_ss->next;
    }

    retval = rtr_mgr_bgpsec_generate_signature(bgpsec,
                                               bgp->priv_key->key_buffer,
                                               &rtr_new_ss);
    if (retval != RTR_BGPSEC_SUCCESS) {
        BGPSEC_DEBUG("Error while generating signature");
        bgpsec_sps_free(own_sps);
        return 1;
    }

    /* Init the frr_new_ss struct */
    frr_new_ss = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct bgpsec_sigseg));
    memset(frr_new_ss, 0, sizeof(struct bgpsec_sigseg));
    frr_new_ss->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, rtr_new_ss->sig_len);

    /* Copy the signature and its length to the input parameters */
    frr_new_ss->next = NULL;
    memcpy(frr_new_ss->signature, rtr_new_ss->signature, rtr_new_ss->sig_len);
    frr_new_ss->sig_len = rtr_new_ss->sig_len;

    /* Copy the SKI from the bgp struct to the new signature segment */
    memcpy(frr_new_ss->ski, bgp->priv_key->ski, SKI_LENGTH);

    *own_ss = frr_new_ss;

    XFREE(MTYPE_BGP_BGPSEC_PATH, pfx);
    rtr_mgr_bgpsec_free_signatures(rtr_new_ss);

	return 0;
}

static int attr_bgpsec_path(struct bgp_attr_parser_args *args)
{
	struct peer *const peer = args->peer;
	struct attr *const attr = args->attr;
	const bgp_size_t length = args->length;
	bgp_size_t remain_len = length;

	struct bgpsec_aspath *aspath = NULL;
	struct bgpsec_secpath *curr_sps = NULL;
	struct bgpsec_secpath *prev_sps = NULL;
	struct bgpsec_sigblock *sigblock1 = NULL;
	struct bgpsec_sigseg *curr_ss = NULL;
	struct bgpsec_sigseg *prev_ss = NULL;

	uint16_t sps_count = 0;
	uint16_t ss_len = 0;
	uint8_t alg = 0;

	sps_count = (stream_getw(peer->curr) - 2) / BGPSEC_SECURE_PATH_SEGMENT_SIZE;
	remain_len -= 2;

    aspath = bgpsec_aspath_new();

	/* Build the secure path segments from the stream */
	for (int i = 0; i < sps_count; i++) {
        curr_sps = bgpsec_sps_new();
		curr_sps->pcount = stream_getc(peer->curr);
		curr_sps->flags = stream_getc(peer->curr);
		curr_sps->as = stream_getl(peer->curr);

		if (prev_sps) {
            prev_sps->next = curr_sps;
		} else {
            aspath->secpaths = curr_sps;
		}

		remain_len -= 6;
		prev_sps = curr_sps;
	}

    aspath->path_count = sps_count;

	/* Parse the first signature block from the stream and build the
	 * signature paths segments */
	sigblock1 = bgpsec_sigblock_new();
    sigblock1->sig_count = 0;
	sigblock1->length = stream_getw(peer->curr);
	sigblock1->alg = alg = stream_getc(peer->curr);

    /* Subtract 3 (length and algorithm) from the total sigblock length to get
     * the length of the signature segments only. */
    ss_len = sigblock1->length - 3;

	while (ss_len > 0) {
		curr_ss = bgpsec_ss_new();

		if (prev_ss) {
            prev_ss->next = curr_ss;
		} else {
			/* If it is the head segment, add the head to the BGPsec_PATH */
			sigblock1->sigsegs = curr_ss;
		}

		stream_get(curr_ss->ski, peer->curr, 20);
		curr_ss->sig_len = stream_getw(peer->curr);
        curr_ss->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH,
                                     curr_ss->sig_len);
        if (!curr_ss->signature) {
            BGPSEC_DEBUG("Memory for signature cound not be allocated");
        }
		stream_get(curr_ss->signature, peer->curr, curr_ss->sig_len);

		prev_ss = curr_ss;
		ss_len -= 22 + curr_ss->sig_len;

        sigblock1->sig_count++;
	}
	aspath->sigblock1 = sigblock1;
	remain_len -= sigblock1->length;

    if (remain_len) {
		zlog_info(
			"BGPsec attribute length is bad: %d leftover octets",
			remain_len);
		bgp_notify_send_with_data(peer, BGP_NOTIFY_UPDATE_ERR,
					  BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
					  args->startp, args->total);
		return -1;
    }

    bgpsec_path2str(aspath);

	attr->bgpsecpath = aspath;
    attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_BGPSEC_PATH);

	return 0;
}

int bgpsec_path2str(struct bgpsec_aspath *aspath)
{
    struct bgpsec_aspath *p;
    struct bgpsec_secpath *sps;
    char separator = ' ';
    int length = 0;

    if (!aspath)
        return 0;

    p = aspath;
    sps = p->secpaths;

    /* We define the ASN length just like in aspath_make_str_count */
#define ASN_STR_LEN ((10 + 1) * 10) + 1

    /*buffer = XMALLOC(MTYPE_BGP_BGPSEC_PATH, ASN_STR_LEN);*/
    /*memset(buffer, '\0', ASN_STR_LEN);*/
    char buffer[ASN_STR_LEN] = {'\0'};
    memset(buffer, '\0', sizeof(buffer));

    while (sps) {
        sprintf(buffer + length, "%d", sps->as);
        length = strlen(buffer);
        sps = sps->next;
        /* If we are not at the end, add a separator */
        if (sps) {
            strcpy(buffer + length, &separator);
            length++;
        }
    }

#undef ASN_STR_LEN
    aspath->str = XMALLOC(MTYPE_BGP_BGPSEC_PATH, length + 1); // +1 for '\0'

    strcpy(aspath->str, buffer);
    aspath->str_len = length;

    return length;
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

    if (!keyfile) {
        BGPSEC_DEBUG("Could not read private key file %s", priv_key->filepath);
        return 1;
    }

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

	rtr_mgr_groups = XMALLOC(MTYPE_BGP_BGPSEC_PATH,
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
		XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct tr_tcp_config));
	struct tr_socket *tr_socket =
		XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct tr_socket));
	struct cache *cache =
		XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct cache));

	tcp_config->host = XSTRDUP(MTYPE_BGP_BGPSEC_PATH, host);
	tcp_config->port = XSTRDUP(MTYPE_BGP_BGPSEC_PATH, port);
	tcp_config->bindaddr = NULL;

	rtr_socket =
		XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct rtr_socket));
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
    struct spki_record *record1;
    struct spki_record *record2;
    int ret;

    rtr_is_stopping = 0;
    rtr_update_overflow = 0;

    if (list_isempty(cache_list)) {
        BGPSEC_DEBUG(
            "No caches were found in config. Prefix validation is off.");
        return ERROR;
    }
    BGPSEC_DEBUG("Init rtr_mgr.");
    int groups_len = listcount(cache_list);
    struct rtr_mgr_group *groups = get_groups();

    ret = rtr_mgr_init(&rtr_config, groups, groups_len, 3600,
               7200, 600, NULL, NULL, NULL, NULL);
    if (ret == RTR_ERROR) {
        BGPSEC_DEBUG("Init rtr_mgr failed.");
        return ERROR;
    }

    BGPSEC_DEBUG("Starting rtr_mgr.");
    ret = rtr_mgr_start(rtr_config);
    if (ret == RTR_ERROR) {
        BGPSEC_DEBUG("Starting rtr_mgr failed.");
        rtr_mgr_free(rtr_config);
        return ERROR;
    }
    rtr_is_running = 1;

    record1 = create_record(64496, ski1, spki1);
    rtr_mgr_bgpsec_add_spki_record(rtr_config, record1);

    record2 = create_record(65536, ski2, spki2);
    rtr_mgr_bgpsec_add_spki_record(rtr_config, record2);

    XFREE(MTYPE_BGP_BGPSEC_PATH, groups);
    free(record1);
    free(record2);

	return SUCCESS;
}

static void stop(void)
{
	rtr_is_stopping = 1;
	if (rtr_is_running) {
		rtr_mgr_stop(rtr_config);
		rtr_mgr_free(rtr_config);
		rtr_is_running = 0;
	}
}

static int reset(bool force)
{
	if (rtr_is_running && !force)
		return SUCCESS;

	BGPSEC_DEBUG("Resetting RPKI Session");
	stop();
	return start();
}

// ----DELETEME

static int copy_rtr_data_to_frr(struct bgpsec_aspath *aspath,
                                struct rtr_bgpsec *rtr_data)
{
    struct rtr_secure_path_seg *sps;
    struct rtr_signature_seg *ss;
    struct bgpsec_secpath *next_sps;
    struct bgpsec_sigseg *next_ss;
    int result;

    next_sps = aspath->secpaths;
    while (next_sps) {
        sps = rtr_mgr_bgpsec_new_secure_path_seg(next_sps->pcount,
                                                 next_sps->flags,
                                                 next_sps->as);
        if (!sps)
            return 1;

        rtr_mgr_bgpsec_append_sec_path_seg(rtr_data, sps);
        next_sps = next_sps->next;
    }

    next_ss = aspath->sigblock1->sigsegs;
    while (next_ss) {
        ss = rtr_mgr_bgpsec_new_signature_seg(next_ss->ski,
                                              next_ss->sig_len,
                                              next_ss->signature);
        if (!ss)
            return 1;

        result = rtr_mgr_bgpsec_append_sig_seg(rtr_data, ss);

        if (result == RTR_BGPSEC_ERROR) {
            BGPSEC_DEBUG("Signature cound not be prepended to RTR BGPsec data");
            return 1;
        }
        next_ss = next_ss->next;
    }

    return 0;
}

static void debug_result(struct peer *peer, enum rtr_bgpsec_rtvals result)
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
        BGPSEC_DEBUG(
                "%s The specified algorithm suite is not supported by RTRlib.",
                peer->host);
        break;
    case RTR_BGPSEC_UNSUPPORTED_AFI:
        BGPSEC_DEBUG("%s The specified AFI is not supported by BGPsec.",
                     peer->host);
        break;
    case RTR_BGPSEC_WRONG_SEGMENT_AMOUNT:
        BGPSEC_DEBUG(
                "%s The amount of signature and "
                "secure path segments are not equal.", peer->host);
        break;
    case RTR_BGPSEC_MISSING_DATA:
        BGPSEC_DEBUG(
                "%s The data required for signing or "
                "validating is not complete.", peer->host);
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
    struct bgpsec_aspath *aspath;
    uint8_t pfx_len_b; // prefix length in bytes

    if (!attr->bgpsecpath) {
        BGPSEC_DEBUG("BGPsec path is empty");
        return 1;
    }

    aspath = attr->bgpsecpath;

    if (!aspath->sigblock1) {
        BGPSEC_DEBUG("Signature Block is empty");
        return 1;
    }

    pfx = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct rtr_bgpsec_nlri));

    /* The first byte of the NLRI is the length in bits.
     * Convert it into bytes. */
    pfx->prefix_len = *mp_update->nlri;
    pfx_len_b = (pfx->prefix_len + 7) / 8;

    switch (mp_update->afi) {
    case AFI_IP:
        pfx->prefix.ver = LRTR_IPV4;
        memcpy(&(pfx->prefix.u.addr4.addr),
               (mp_update->nlri + 1), // +1 to skip len byte
               pfx_len_b);
        break;
    case AFI_IP6:
        pfx->prefix.ver = LRTR_IPV6;
        memcpy(pfx->prefix.u.addr6.addr,
               (mp_update->nlri + 1), // +1 to skip len byte
               pfx_len_b);
        break;
    }

    data = rtr_mgr_bgpsec_new(aspath->sigblock1->alg,
                              mp_update->safi,
                              mp_update->afi,
                              peer->local_as,
                              peer->local_as,
                              *pfx);

    retval = copy_rtr_data_to_frr(aspath, data);

    if (retval) {
        BGPSEC_DEBUG("Could not copy RTR data to FRR data");
        return 1;
    }

    result = rtr_mgr_bgpsec_validate_as_path(data, rtr_config);

    /* Print out detailed information on the validation result. */
    debug_result(peer, result);

    if (result != RTR_BGPSEC_VALID)
        return 1;

    return 0;
}

static int build_bgpsec_aspath(struct bgp *bgp,
                               struct peer *peer,
                               struct stream *s,
                               struct attr *attr,
                               const struct prefix *bgpsec_p,
                               afi_t afi,
                               safi_t safi)
{
    struct bgpsec_aspath *aspath = NULL;
    struct bgpsec_secpath *own_sps = NULL;
    struct bgpsec_sigseg *own_ss = NULL;
    int bgpsec_attrlen = 0;
	size_t aspath_sizep = 0;
    int rtval = 0;
    int sig_only = 0;

    /* Only valid AFI for BGPsec are IPv4 and IPv6 */
    if (afi != AFI_IP && afi != AFI_IP6) {
		flog_err(EC_BGP_BGPSEC_INVALID_AFI,
			 "BGPsec: Received invalid AFI %s, expected 1 (IPv4) or 2 (IPv6)",
			 afi2str(afi));
        return 1;
    }

    own_sps = bgpsec_sps_new();
    own_sps->as = bgp->as;

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
                own_sps->flags = 0x80;
            }
            /* Set the pCount to the appropriate value */
            //TODO: AS migration and pCounts > 1 are
            // currently ignored.
            if (peer->sort != BGP_PEER_CONFED) {
                own_sps->pcount = 1;
            }
        }
    } else {
        bgpsec_sps_free(own_sps);
        return 1;
    }

    /* Search for a bgpsecpath with the given AS path and given prefix */
    struct bgpsec_aspath *tmp_path = bgpsec_aspath_new();
    tmp_path->str = XMALLOC(MTYPE_BGP_BGPSEC_PATH, attr->aspath->str_len + 1);
    tmp_path->str_len = attr->aspath->str_len;
    memcpy(tmp_path->str, attr->aspath->str, attr->aspath->str_len);
    tmp_path->str[tmp_path->str_len] = '\0';

    int pfx_len_b = (bgpsec_p->prefixlen + 7) / 8;

    tmp_path->pfx = XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct bgp_nlri));
    tmp_path->pfx->nlri = XMALLOC(MTYPE_BGP_BGPSEC_PATH, pfx_len_b + 1);
    tmp_path->pfx->length = pfx_len_b + 1;
    memcpy(tmp_path->pfx->nlri, &(bgpsec_p->prefixlen), 1);
    memcpy(tmp_path->pfx->nlri + 1, bgpsec_p->u.val, pfx_len_b + 1);

    //TODO: have a better way of detecting an origin message.
    /* If aspath is empty, this is an origin message */
    if (attr->bgpsecpath) {
        aspath = bgpsec_aspath_get(tmp_path);
        if (!aspath) {
            aspath = bgpsec_aspath_new();
        }
        /*aspath = copy_bgpsecpath(attr->bgpsecpath);*/
    } else {
        aspath = bgpsec_aspath_new();
    }

    /* Create the signature before writing the BGPsec path to the stream.
     * This saves stripping the path data from the stream again, in case
     * the signature could not be generated.
     */
    rtval = gen_bgpsec_sig(peer, aspath, bgp, bgpsec_p, afi, safi,
                           own_sps, &own_ss);

    if (own_ss && rtval == 0) {
        stream_putc(s, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTLEN);
        stream_putc(s, BGP_ATTR_BGPSEC_PATH);
        aspath_sizep = stream_get_endp(s);
        stream_putw(s, 0);

        write_bgpsec_aspath_to_stream(s, aspath,
                                      &bgpsec_attrlen, own_sps,
                                      own_ss, sig_only);

        stream_putw_at(s, aspath_sizep, bgpsec_attrlen);
    } else {
        // TODO: print error code from rtrlib
        BGPSEC_DEBUG("Error generating signature");
        rtval = 1;
    }

    bgpsec_sps_free(own_sps);
    /*bgpsec_aspath_free(aspath);*/
    /*aspath = NULL;*/

    return rtval;
}

static int write_bgpsec_aspath_to_stream(struct stream *s,
                                         struct bgpsec_aspath *aspath,
                                         int *length,
                                         struct bgpsec_secpath *own_sps,
                                         struct bgpsec_sigseg *own_ss,
                                         int sig_only)
{
    struct bgpsec_sigblock *block = NULL;
    struct bgpsec_secpath *sps= NULL;
    struct bgpsec_sigseg *ss = NULL;
	size_t block_lenp = 0;
    uint16_t sp_len = 0; // secure path length

    block = aspath->sigblock1;
    block->length = 0;

    sp_len = ((aspath->path_count + 1) * BGPSEC_SECURE_PATH_SEGMENT_SIZE) + 2;
    stream_putw(s, sp_len);

    /* First put in the secure path segment of the own AS */
    stream_putc(s, own_sps->pcount);
    stream_putc(s, own_sps->flags);
    stream_putl(s, own_sps->as);

    /* Then, put in the rest of the secure path segments.
     * They are already in reversed order: AS3 AS2 AS1 */
    sps = aspath->secpaths;
    while (sps) {
        stream_putc(s, sps->pcount);
        stream_putc(s, sps->flags);
        stream_putl(s, sps->as);

        sps = sps->next;
    }

    *length += sp_len;

    /* Save the pointer to the position of the block length
     * and add it later. We do not know the total length of the
     * signatures yet */
    block_lenp = stream_get_endp(s);
    stream_putw(s, 0);

    /* Put in the algorithm suite ID */
    stream_putc(s, block->alg);

    /* The length field + algo id */
    block->length += 3;

    /* Now, put in the signature segment of the own AS */
    stream_put(s, own_ss->ski, SKI_LENGTH);
    stream_putw(s, own_ss->sig_len);
    stream_put(s, own_ss->signature, own_ss->sig_len);
    block->length += SS_LEN(own_ss);

    /* Then, put in the rest of the signature segments.
     * They also are in reversed order. */
    ss = block->sigsegs;
    while (ss) {
        stream_put(s, ss->ski, SKI_LENGTH);
        stream_putw(s, ss->sig_len);
        stream_put(s, ss->signature, ss->sig_len);
        block->length += SS_LEN(ss);

        ss = ss->next;
    }

    /* Write the total block length to the previously saved position */
    stream_putw_at(s, block_lenp, block->length);

    *length += block->length;

    memcpy(aspath->sigblock1, block, sizeof(struct bgpsec_sigblock));

    return 0;
}

static int copy_mp_update(struct attr *attr, struct bgp_nlri *mp_update) {
    if (!attr || !mp_update)
        return 1;

    if (!attr->bgpsecpath)
        return 1;

    if (attr->bgpsecpath->pfx)
        return 1;

    attr->bgpsecpath->pfx =
        XMALLOC(MTYPE_BGP_BGPSEC_PATH, sizeof(struct bgp_nlri));
    attr->bgpsecpath->pfx->nlri =
        XMALLOC(MTYPE_BGP_BGPSEC_PATH, mp_update->length);

    attr->bgpsecpath->pfx->afi = mp_update->afi;
    attr->bgpsecpath->pfx->safi = mp_update->safi;
    attr->bgpsecpath->pfx->length = mp_update->length;

    memcpy(attr->bgpsecpath->pfx->nlri, mp_update->nlri, mp_update->length);

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

static const char *dir2str(uint8_t version_dir) {
    int dir = version_dir >> 3;

    switch (dir) {
    case BGPSEC_DIR_RECEIVE:
        return "RECEIVE";
    case BGPSEC_DIR_SEND:
        return "SEND";
    default:
        break;
    }
    return NULL;
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

static int bgpd_sync_callback(struct thread *thread)
{
	return 0;
}

static void rpki_init_sync_socket(void)
{
	int fds[2];
	const char *msg;

	BGPSEC_DEBUG("initializing sync socket");
	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, fds) != 0) {
		msg = "could not open rpki sync socketpair";
		goto err;
	}
	rpki_sync_socket_rtr = fds[0];
	rpki_sync_socket_bgpd = fds[1];

	if (set_nonblocking(rpki_sync_socket_rtr) != 0) {
		msg = "could not set rpki_sync_socket_rtr to non blocking";
		goto err;
	}

	if (set_nonblocking(rpki_sync_socket_bgpd) != 0) {
		msg = "could not set rpki_sync_socket_bgpd to non blocking";
		goto err;
	}


	thread_add_read(bm->master, bgpd_sync_callback, NULL,
			rpki_sync_socket_bgpd, NULL);

	return;

err:
	zlog_err("RPKI: %s", msg);
	abort();

}

static int bgp_bgpsec_init(struct thread_master *master)
{
    /*int bgpsec_debug = 0;*/
    /*int rtr_is_running = 0;*/
    /*int rtr_is_stopping = 0;*/

    cache_list = list_new();
    /*cache_list->del = (void (*)(void *)) & free_cache;*/

    /*polling_period = POLLING_PERIOD_DEFAULT;*/
    /*expire_interval = EXPIRE_INTERVAL_DEFAULT;*/
    /*retry_interval = RETRY_INTERVAL_DEFAULT;*/
    /*timeout = TIMEOUT_DEFAULT;*/
    /*initial_synchronisation_timeout =*/
        /*INITIAL_SYNCHRONISATION_TIMEOUT_DEFAULT;*/
    install_cli_commands();
    rpki_init_sync_socket();
    start();

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
	hook_register(bgp_copy_mp_update, copy_mp_update);

    hook_register(bgp_packet_build_bgpsec_aspath,
                  build_bgpsec_aspath);
    hook_register(bgp_val_bgpsec_aspath, val_bgpsec_aspath);

    hook_register(bgp_bgpsec_cleanup, bgpsec_cleanup);

	return 0;
}

/*DEFUN (debug_bgpsec,*/
       /*debug_bgpsec_cmd,*/
       /*"debug bgpsec",*/
       /*DEBUG_STR*/
       /*"Enable debugging for BGPsec\n")*/
/*{*/
	/*bgpsec_debug = 1;*/
    /*BGPSEC_DEBUG("BGPsec debugging successfully enabled");*/
	/*return CMD_SUCCESS;*/
/*}*/

/*DEFUN (no_debug_bgpsec,*/
       /*no_debug_bgpsec_cmd,*/
       /*"no debug bgpsec",*/
       /*NO_STR*/
       /*DEBUG_STR*/
       /*"Disable debugging for BGPsec\n")*/
/*{*/
	/*bgpsec_debug = 0;*/
    /*BGPSEC_DEBUG("BGPsec debugging successfully disabled");*/
	/*return CMD_SUCCESS;*/
/*}*/

DEFUN (bgpsec_private_key,
       bgpsec_private_key_cmd,
       "bgpsec privkey WORD",
       BGPSEC_OUTPUT_STRING
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

        strcpy(bgp->priv_key->filepath, (const char *)argv[idx_path]->arg);
        result = load_private_key_from_file(bgp->priv_key);

        if (result) {
            vty_out(vty, "Error while loading private key file\n");
            bgpsec_private_key_free(bgp->priv_key);
            bgp->priv_key = NULL;
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
       BGPSEC_OUTPUT_STRING
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

DEFPY (bgpsec_cache,
       bgpsec_cache_cmd,
       "bgpsec cache <A.B.C.D|WORD>"
       "<TCPPORT>"
       "preference (1-255)",
       BGPSEC_OUTPUT_STRING
       "Install a cache server to current group\n"
       "IP address of cache server\n Hostname of cache server\n"
       "TCP port number\n"
       "Preference of the cache server\n"
       "Preference value\n")
{
	int return_value;
	struct listnode *cache_node;
	struct cache *current_cache;

    for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, current_cache)) {
        if (current_cache->preference == preference) {
            vty_out(vty,
                "Cache with preference %ld is already configured\n",
                preference);
            return CMD_WARNING;
        }
    }

    return_value = add_tcp_cache(cache, tcpport, preference);

	if (return_value == ERROR) {
		vty_out(vty, "Could not create new bgpsec cache\n");
		return CMD_WARNING;
	}

    start();

	return CMD_SUCCESS;
}

DEFUN (bgpsec_reset,
       bgpsec_reset_cmd,
       "bgpsec reset",
       BGPSEC_OUTPUT_STRING
       "reset bgpsec\n")
{
	return reset(true) == SUCCESS ? CMD_SUCCESS : CMD_WARNING;
}

/*DEFUN_NOSH (bgpsec_exit,*/
            /*bgpsec_exit_cmd,*/
            /*"exit",*/
            /*"Exit BGPsec configuration and restart BGPsec session\n")*/
/*{*/
	/*[>reset(false);<]*/

	/*vty->node = BGP_NODE;*/
	/*return CMD_SUCCESS;*/
/*}*/

/*DEFUN_NOSH (bgpsec_quit,*/
            /*bgpsec_quit_cmd,*/
            /*"quit",*/
            /*"Exit BGPsec configuration mode\n")*/
/*{*/
	/*return bgpsec_exit(self, vty, argc, argv);*/
/*}*/

/*DEFUN_NOSH (bgpsec_end,*/
            /*bgpsec_end_cmd,*/
            /*"end",*/
            /*"End BGPsec configuration, restart BGPsec session and change to enable mode\n")*/
/*{*/
    /*int ret = SUCCESS;*/

	/*vty_config_exit(vty);*/
	/*vty->node = ENABLE_NODE;*/
	/*return ret == SUCCESS ? CMD_SUCCESS : CMD_WARNING;*/
/*}*/


static int config_write(struct vty *vty)
{
    struct bgp *bgp;

    bgp = bgp_get_default();

    if (bgp->priv_key) {
        if (bgp->priv_key->filepath)
            vty_out(vty, "bgpsec privkey %s\n", bgp->priv_key->filepath);
        if (bgp->priv_key->ski_str)
            vty_out(vty, "bgpsec privkey ski %s\n", bgp->priv_key->ski_str);
        return 1;
    } else {
        return 0;
    }
}

static int config_on_exit(struct vty *vty)
{
	/*reset(false);*/
	return 1;
}

/*static void overwrite_exit_commands(void)*/
/*{*/
	/*unsigned int i;*/
	/*vector cmd_vector = bgpsec_node.cmd_vector;*/

	/*for (i = 0; i < cmd_vector->active; ++i) {*/
		/*struct cmd_element *cmd = vector_lookup(cmd_vector, i);*/

		/*if (strcmp(cmd->string, "exit") == 0*/
			/*|| strcmp(cmd->string, "quit") == 0*/
			/*|| strcmp(cmd->string, "end") == 0) {*/
			/*uninstall_element(BGP_NODE, cmd);*/
		/*}*/
	/*}*/

	/*install_element(BGP_NODE, &bgpsec_exit_cmd);*/
	/*install_element(BGP_NODE, &bgpsec_quit_cmd);*/
	/*install_element(BGP_NODE, &bgpsec_end_cmd);*/
/*}*/

static void install_cli_commands(void)
{
    /*install_node(&bgpsec_node);*/
    /*install_default(BGPSEC_NODE);*/
    /*overwrite_exit_commands();*/

    install_element(BGP_NODE, &bgpsec_private_key_cmd);
    install_element(BGP_NODE, &bgpsec_private_key_ski_cmd);
    install_element(BGP_NODE, &bgpsec_cache_cmd);
    install_element(BGP_NODE, &bgpsec_reset_cmd);

	/* Install debug commands */
	/*install_element(CONFIG_NODE, &debug_bgpsec_cmd);*/
	/*install_element(ENABLE_NODE, &debug_bgpsec_cmd);*/
	/*install_element(CONFIG_NODE, &no_debug_bgpsec_cmd);*/
	/*install_element(ENABLE_NODE, &no_debug_bgpsec_cmd);*/
}

FRR_MODULE_SETUP(.name = "bgpd_bgpsec", .version = "0.0.1",
		 .description = "Enable BGPsec support for FRR.",
		 .init = bgp_bgpsec_module_init)
