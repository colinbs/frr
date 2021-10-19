/*
 * BGP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Don Slice
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

#ifndef __BGP_ERRORS_H__
#define __BGP_ERRORS_H__

#include "lib/ferr.h"

enum bgp_log_refs {

	EC_BGP_ATTR_FLAG = BGP_FERR_START,
	EC_BGP_ATTR_LEN,
	EC_BGP_ATTR_ORIGIN,
	EC_BGP_ATTR_MAL_AS_PATH,
	EC_BGP_ATTR_FIRST_AS,
	EC_BGP_ATTR_MARTIAN_NH,
	EC_BGP_ATTR_PMSI_TYPE,
	EC_BGP_ATTR_PMSI_LEN,
	EC_BGP_ATTR_NH_SEND_LEN,
	EC_BGP_PEER_GROUP,
	EC_BGP_PEER_DELETE,
	EC_BGP_TABLE_CHUNK,
	EC_BGP_MACIP_LEN,
	EC_BGP_LM_ERROR,
	EC_BGP_JSON_MEM_ERROR,
	EC_BGP_UPDGRP_ATTR_LEN,
	EC_BGP_UPDGRP_CREATE,
	EC_BGP_UPDATE_SND,
	EC_BGP_PKT_OPEN,
	EC_BGP_SND_FAIL,
	EC_BGP_INVALID_STATUS,
	EC_BGP_UPDATE_RCV,
	EC_BGP_NO_CAP,
	EC_BGP_NOTIFY_RCV,
	EC_BGP_KEEP_RCV,
	EC_BGP_RFSH_RCV,
	EC_BGP_CAP_RCV,
	EC_BGP_NH_UPD,
	EC_BGP_LABEL,
	EC_BGP_MULTIPATH,
	EC_BGP_PKT_PROCESS,
	EC_BGP_CONNECT,
	EC_BGP_FSM,
	EC_BGP_VNI,
	EC_BGP_NO_DFLT,
	EC_BGP_VTEP_INVALID,
	EC_BGP_ES_INVALID,
	EC_BGP_EVPN_ROUTE_DELETE,
	EC_BGP_EVPN_FAIL,
	EC_BGP_EVPN_ROUTE_INVALID,
	EC_BGP_EVPN_ROUTE_CREATE,
	EC_BGP_ES_CREATE,
	EC_BGP_EVPN_AS_MISMATCH,
	EC_BGP_EVPN_INSTANCE_MISMATCH,
	EC_BGP_FLOWSPEC_PACKET,
	EC_BGP_FLOWSPEC_INSTALLATION,
	EC_BGP_ASPATH_FEWER_HOPS,
	EC_BGP_DEFUNCT_SNPA_LEN,
	EC_BGP_MISSING_ATTRIBUTE,
	EC_BGP_ATTRIBUTE_TOO_SMALL,
	EC_BGP_EXT_ATTRIBUTE_TOO_SMALL,
	EC_BGP_ATTRIBUTE_REPEATED,
	EC_BGP_ATTRIBUTE_TOO_LARGE,
	EC_BGP_ATTRIBUTE_PARSE_ERROR,
	EC_BGP_ATTRIBUTE_PARSE_WITHDRAW,
	EC_BGP_ATTRIBUTE_FETCH_ERROR,
	EC_BGP_ATTRIBUTES_MISMATCH,
	EC_BGP_DUMP,
	EC_BGP_UPDATE_PACKET_SHORT,
	EC_BGP_UPDATE_PACKET_LONG,
	EC_BGP_UNRECOGNIZED_CAPABILITY,
	EC_BGP_NO_TCP_MD5,
	EC_BGP_EVPN_PMSI_PRESENT,
	EC_BGP_EVPN_VPN_VNI,
	EC_BGP_EVPN_ESI,
	EC_BGP_INVALID_LABEL_STACK,
	EC_BGP_ZEBRA_SEND,
	EC_BGP_CAPABILITY_INVALID_LENGTH,
	EC_BGP_CAPABILITY_INVALID_DATA,
	EC_BGP_CAPABILITY_VENDOR,
	EC_BGP_CAPABILITY_UNKNOWN,
	EC_BGP_INVALID_NEXTHOP_LENGTH,
	EC_BGP_DOPPELGANGER_CONFIG,
	EC_BGP_ROUTER_ID_SAME,
	EC_BGP_INVALID_BGP_INSTANCE,
	EC_BGP_INVALID_ROUTE,
    EC_BGP_BGPSEC_INVALID_AFI,
    EC_BGP_BGPSEC_UNSUPPORTED_VERSION,
};

extern void bgp_error_init(void);

#endif
