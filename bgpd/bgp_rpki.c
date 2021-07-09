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

/* If rtrlib compiled with ssh support, don`t fail build */
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
#include "bgpd/bgp_rpki.h"
#include "northbound_cli.h"

#include "bgpd/bgp_open.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_packet.h"
#include "lib/network.h"
#include "lib/thread.h"
#ifndef VTYSH_EXTRACT_PL
#include "rtrlib/rtrlib.h"
#include "rtrlib/transport/tcp/tcp_transport.h"
#include "rtrlib/spki/spkitable.h"
#if defined(FOUND_SSH)
#include "rtrlib/transport/ssh/ssh_transport.h"
#endif
#endif
#include "hook.h"
#include "libfrr.h"
#include "lib/version.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_rpki_clippy.c"
#endif

#define RPKI_VALID      1
#define RPKI_NOTFOUND   2
#define RPKI_INVALID    3

#define POLLING_PERIOD_DEFAULT      3600
#define EXPIRE_INTERVAL_DEFAULT     7200
#define RETRY_INTERVAL_DEFAULT      600

#define BGPSEC_SECURE_PATH_SEGMENT_SIZE     6
#define PRIV_KEY_BUFFER_SIZE                500

#define RPKI_DEBUG(...)                                                \
	if (rpki_debug) {                                                  \
		zlog_debug("RPKI: " __VA_ARGS__);                              \
	}

#define BGPSEC_DEBUG(...)                                              \
	if (term_bgp_debug_bgpsec) {                                       \
		zlog_debug("BGPSEC: " __VA_ARGS__);                            \
	}

#define SS_LEN(ss) SKI_LENGTH + ss->sig_len + sizeof(ss->sig_len)

#define RPKI_OUTPUT_STRING "Control rpki specific settings\n"
#define BGPSEC_OUTPUT_STRING "Control BGPsec specific settings\n"

static double total_cpu_ticks_rpki_start = 0;
static double total_cpu_ticks_attr_parse = 0;
static int total_count_attr_parse = 0;

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

struct rpki_for_each_record_arg {
	struct vty *vty;
	unsigned int *prefix_amount;
	as_t as;
};

static int start(void);
static void stop(void);
static int reset(bool force);
static struct rtr_mgr_group *get_connected_group(void);
static void print_prefix_table(struct vty *vty);
static void install_cli_commands(void);
static int config_write(struct vty *vty);
static int config_on_exit(struct vty *vty);
static void free_cache(struct cache *cache);
static struct rtr_mgr_group *get_groups(void);
#if defined(FOUND_SSH)
static int add_ssh_cache(const char *host, const unsigned int port,
			 const char *username, const char *client_privkey_path,
			 const char *client_pubkey_path,
			 const char *server_pubkey_path,
			 const uint8_t preference);
#endif
static struct rtr_socket *create_rtr_socket(struct tr_socket *tr_socket);
static struct cache *find_cache(const uint8_t preference);
static int add_tcp_cache(const char *host, const char *port,
			 const uint8_t preference);
static void print_record(const struct pfx_record *record, struct vty *vty);
static int is_synchronized(void);
static int is_running(void);
static void route_match_free(void *rule);
static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,

					       void *object);
static void *route_match_compile(const char *arg);
static void revalidate_bgp_node(struct bgp_dest *dest, afi_t afi, safi_t safi);
static void revalidate_all_routes(void);

/* BGPsec specific functions */
static int capability_bgpsec(struct peer *peer,
			     struct capability_header *hdr);
static const char *dir2str(uint8_t dir);
static int put_bgpsec_cap(struct stream *s, struct peer *peer);
static int gen_bgpsec_sig(struct peer *peer, struct bgpsec_aspath *bgpsecpath,
                          struct bgp *bgp, const struct prefix *p,
                          afi_t afi, safi_t safi,
                          struct bgpsec_secpath *own_sps,
                          struct bgpsec_sigseg **own_ss);
static int attr_bgpsec_path(struct bgp_attr_parser_args *args,
                            struct bgp_nlri *mp_update);
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
static int copy_frr_data_to_rtr(struct bgpsec_aspath *bgpsecpath,
                                struct rtr_bgpsec *data);
static int chartob16(unsigned char hex_char);
static int ski_char_to_hex(unsigned char *ski, uint8_t *buffer);
static int bgpsec_path2str(struct bgpsec_aspath *aspath);
static int copy_mp_update(struct attr *attr, struct bgp_nlri *mp_update);

static struct rtr_mgr_config *rtr_config;
static struct list *cache_list;
static int rtr_is_running;
static int rtr_is_stopping;
static _Atomic int rtr_update_overflow;
static int rpki_debug;
static unsigned int polling_period;
static unsigned int expire_interval;
static unsigned int retry_interval;
static int rpki_sync_socket_rtr;
static int rpki_sync_socket_bgpd;

static struct cmd_node rpki_node = {
	.name = "rpki",
	.node = RPKI_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-rpki)# ",
	.config_write = config_write,
	.node_exit = config_on_exit,
};
static const struct route_map_rule_cmd route_match_rpki_cmd = {
	"rpki", route_match, route_match_compile, route_match_free};

static void *malloc_wrapper(size_t size)
{
	return XMALLOC(MTYPE_BGP_RPKI_CACHE, size);
}

static void *realloc_wrapper(void *ptr, size_t size)
{
	return XREALLOC(MTYPE_BGP_RPKI_CACHE, ptr, size);
}

static void free_wrapper(void *ptr)
{
	XFREE(MTYPE_BGP_RPKI_CACHE, ptr);
}

static void init_tr_socket(struct cache *cache)
{
	if (cache->type == TCP)
		tr_tcp_init(cache->tr_config.tcp_config,
			    cache->tr_socket);
#if defined(FOUND_SSH)
	else
		tr_ssh_init(cache->tr_config.ssh_config,
			    cache->tr_socket);
#endif
}

static void free_tr_socket(struct cache *cache)
{
	if (cache->type == TCP)
		tr_tcp_init(cache->tr_config.tcp_config,
			    cache->tr_socket);
#if defined(FOUND_SSH)
	else
		tr_ssh_init(cache->tr_config.ssh_config,
			    cache->tr_socket);
#endif
}

static int rpki_validate_prefix(struct peer *peer, struct attr *attr,
				const struct prefix *prefix);

static void ipv6_addr_to_network_byte_order(const uint32_t *src, uint32_t *dest)
{
	int i;

	for (i = 0; i < 4; i++)
		dest[i] = htonl(src[i]);
}

static void ipv6_addr_to_host_byte_order(const uint32_t *src, uint32_t *dest)
{
	int i;

	for (i = 0; i < 4; i++)
		dest[i] = ntohl(src[i]);
}

static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,
					       void *object)
{
	int *rpki_status = rule;
	struct bgp_path_info *path;

	path = object;

	if (rpki_validate_prefix(path->peer, path->attr, prefix)
	    == *rpki_status) {
		return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

static void *route_match_compile(const char *arg)
{
	int *rpki_status;

	rpki_status = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(int));

	if (strcmp(arg, "valid") == 0)
		*rpki_status = RPKI_VALID;
	else if (strcmp(arg, "invalid") == 0)
		*rpki_status = RPKI_INVALID;
	else
		*rpki_status = RPKI_NOTFOUND;

	return rpki_status;
}

static void route_match_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct rtr_socket *create_rtr_socket(struct tr_socket *tr_socket)
{
	struct rtr_socket *rtr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct rtr_socket));
	rtr_socket->tr_socket = tr_socket;
	return rtr_socket;
}

static struct cache *find_cache(const uint8_t preference)
{
	struct listnode *cache_node;
	struct cache *cache;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		if (cache->preference == preference)
			return cache;
	}
	return NULL;
}

static void print_record(const struct pfx_record *record, struct vty *vty)
{
	char ip[INET6_ADDRSTRLEN];

	lrtr_ip_addr_to_str(&record->prefix, ip, sizeof(ip));
	vty_out(vty, "%-40s   %3u - %3u   %10u\n", ip, record->min_len,
		record->max_len, record->asn);
}

static void print_record_by_asn(const struct pfx_record *record, void *data)
{
	struct rpki_for_each_record_arg *arg = data;
	struct vty *vty = arg->vty;

	if (record->asn == arg->as) {
		(*arg->prefix_amount)++;
		print_record(record, vty);
	}
}

static void print_record_cb(const struct pfx_record *record, void *data)
{
	struct rpki_for_each_record_arg *arg = data;
	struct vty *vty = arg->vty;

	(*arg->prefix_amount)++;

	print_record(record, vty);
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

inline int is_synchronized(void)
{
	return rtr_is_running && rtr_mgr_conf_in_sync(rtr_config);
}

inline int is_running(void)
{
	return rtr_is_running;
}

static struct prefix *pfx_record_to_prefix(struct pfx_record *record)
{
	struct prefix *prefix = prefix_new();

	prefix->prefixlen = record->min_len;

	if (record->prefix.ver == LRTR_IPV4) {
		prefix->family = AF_INET;
		prefix->u.prefix4.s_addr = htonl(record->prefix.u.addr4.addr);
	} else {
		prefix->family = AF_INET6;
		ipv6_addr_to_network_byte_order(record->prefix.u.addr6.addr,
						prefix->u.prefix6.s6_addr32);
	}

	return prefix;
}

static int bgpd_sync_callback(struct thread *thread)
{
	struct bgp *bgp;
	struct listnode *node;
	struct prefix *prefix;
	struct pfx_record rec;

	thread_add_read(bm->master, bgpd_sync_callback, NULL,
			rpki_sync_socket_bgpd, NULL);

	if (atomic_load_explicit(&rtr_update_overflow, memory_order_seq_cst)) {
		while (read(rpki_sync_socket_bgpd, &rec,
			    sizeof(struct pfx_record))
		       != -1)
			;

		atomic_store_explicit(&rtr_update_overflow, 0,
				      memory_order_seq_cst);
		revalidate_all_routes();
		return 0;
	}

	int retval =
		read(rpki_sync_socket_bgpd, &rec, sizeof(struct pfx_record));
	if (retval != sizeof(struct pfx_record)) {
		RPKI_DEBUG("Could not read from rpki_sync_socket_bgpd");
		return retval;
	}
	prefix = pfx_record_to_prefix(&rec);

	afi_t afi = (rec.prefix.ver == LRTR_IPV4) ? AFI_IP : AFI_IP6;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct peer *peer;
		struct listnode *peer_listnode;

		for (ALL_LIST_ELEMENTS_RO(bgp->peer, peer_listnode, peer)) {
			safi_t safi;

			for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
				if (!peer->bgp->rib[afi][safi])
					continue;

				struct bgp_dest *match;
				struct bgp_dest *node;

				match = bgp_table_subtree_lookup(
					peer->bgp->rib[afi][safi], prefix);
				node = match;

				while (node) {
					if (bgp_dest_has_bgp_path_info_data(
						    node)) {
						revalidate_bgp_node(node, afi,
								    safi);
					}

					node = bgp_route_next_until(node,
								    match);
				}
			}
		}
	}

	prefix_free(&prefix);
	return 0;
}

static void revalidate_bgp_node(struct bgp_dest *bgp_dest, afi_t afi,
				safi_t safi)
{
	struct bgp_adj_in *ain;

	for (ain = bgp_dest->adj_in; ain; ain = ain->next) {
		int ret;
		struct bgp_path_info *path =
			bgp_dest_get_bgp_path_info(bgp_dest);
		mpls_label_t *label = NULL;
		uint32_t num_labels = 0;

		if (path && path->extra) {
			label = path->extra->label;
			num_labels = path->extra->num_labels;
		}
		ret = bgp_update(ain->peer, bgp_dest_get_prefix(bgp_dest),
				 ain->addpath_rx_id, ain->attr, afi, safi,
				 ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, label,
				 num_labels, 1, NULL);

		if (ret < 0)
			return;
	}
}

static void revalidate_all_routes(void)
{
	struct bgp *bgp;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct peer *peer;
		struct listnode *peer_listnode;

		for (ALL_LIST_ELEMENTS_RO(bgp->peer, peer_listnode, peer)) {

			for (size_t i = 0; i < 2; i++) {
				safi_t safi;
				afi_t afi = (i == 0) ? AFI_IP : AFI_IP6;

				for (safi = SAFI_UNICAST; safi < SAFI_MAX;
				     safi++) {
					if (!peer->bgp->rib[afi][safi])
						continue;

					bgp_soft_reconfig_in(peer, afi, safi);
				}
			}
		}
	}
}

static void rpki_update_cb_sync_rtr(struct pfx_table *p __attribute__((unused)),
				    const struct pfx_record rec,
				    const bool added __attribute__((unused)))
{
	if (rtr_is_stopping
	    || atomic_load_explicit(&rtr_update_overflow, memory_order_seq_cst))
		return;

	int retval =
		write(rpki_sync_socket_rtr, &rec, sizeof(struct pfx_record));
	if (retval == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		atomic_store_explicit(&rtr_update_overflow, 1,
				      memory_order_seq_cst);

	else if (retval != sizeof(struct pfx_record))
		RPKI_DEBUG("Could not write to rpki_sync_socket_rtr");
}

static void rpki_init_sync_socket(void)
{
	int fds[2];
	const char *msg;

	RPKI_DEBUG("initializing sync socket");
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

static int bgp_rpki_init(struct thread_master *master)
{
	rpki_debug = 0;
	rtr_is_running = 0;
	rtr_is_stopping = 0;

	cache_list = list_new();
	cache_list->del = (void (*)(void *)) & free_cache;

	polling_period = POLLING_PERIOD_DEFAULT;
	expire_interval = EXPIRE_INTERVAL_DEFAULT;
	retry_interval = RETRY_INTERVAL_DEFAULT;
	install_cli_commands();
	rpki_init_sync_socket();
	return 0;
}

static int bgp_rpki_fini(void)
{
	stop();
	list_delete(&cache_list);

	close(rpki_sync_socket_rtr);
	close(rpki_sync_socket_bgpd);

	return 0;
}

static int bgp_rpki_module_init(void)
{
	lrtr_set_alloc_functions(malloc_wrapper, realloc_wrapper, free_wrapper);

	hook_register(bgp_rpki_prefix_status, rpki_validate_prefix);
	hook_register(frr_late_init, bgp_rpki_init);
	hook_register(frr_early_fini, &bgp_rpki_fini);

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

// DELETEME----
/*static struct spki_record *create_record(int ASN,*/
                                         /*uint8_t *ski,*/
                                         /*uint8_t *spki)*/
/*{*/
	/*struct spki_record *record = XMALLOC(MTYPE_BGP_BGPSEC_PATH, (sizeof(struct spki_record)));*/

	/*memset(record, 0, sizeof(*record));*/
	/*record->asn = ASN;*/
	/*memcpy(record->ski, ski, SKI_SIZE);*/
	/*memcpy(record->spki, spki, SPKI_SIZE);*/

	/*record->socket = NULL;*/
	/*return record;*/
/*}*/

/*static uint8_t ski1[]  = {*/
        /*0xAB, 0x4D, 0x91, 0x0F, 0x55,*/
        /*0xCA, 0xE7, 0x1A, 0x21, 0x5E,*/
        /*0xF3, 0xCA, 0xFE, 0x3A, 0xCC,*/
        /*0x45, 0xB5, 0xEE, 0xC1, 0x54*/
/*};*/

/*static uint8_t ski2[]  = {*/
		/*0x47, 0xF2, 0x3B, 0xF1, 0xAB,*/
		/*0x2F, 0x8A, 0x9D, 0x26, 0x86,*/
		/*0x4E, 0xBB, 0xD8, 0xDF, 0x27,*/
		/*0x11, 0xC7, 0x44, 0x06, 0xEC*/
/*};*/

/*static uint8_t spki1[] = {*/
		/*0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,*/
		/*0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,*/
		/*0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x73, 0x91, 0xBA,*/
        /*0xBB, 0x92, 0xA0, 0xCB, 0x3B, 0xE1, 0x0E, 0x59, 0xB1, 0x9E,*/
        /*0xBF, 0xFB, 0x21, 0x4E, 0x04, 0xA9, 0x1E, 0x0C, 0xBA, 0x1B,*/
        /*0x13, 0x9A, 0x7D, 0x38, 0xD9, 0x0F, 0x77, 0xE5, 0x5A, 0xA0,*/
        /*0x5B, 0x8E, 0x69, 0x56, 0x78, 0xE0, 0xFA, 0x16, 0x90, 0x4B,*/
        /*0x55, 0xD9, 0xD4, 0xF5, 0xC0, 0xDF, 0xC5, 0x88, 0x95, 0xEE,*/
        /*0x50, 0xBC, 0x4F, 0x75, 0xD2, 0x05, 0xA2, 0x5B, 0xD3, 0x6F,*/
        /*0xF5*/
/*};*/

/*static uint8_t spki2[] = {*/
		/*0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,*/
		/*0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,*/
		/*0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x28, 0xFC, 0x5F,*/
		/*0xE9, 0xAF, 0xCF, 0x5F, 0x4C, 0xAB, 0x3F, 0x5F, 0x85, 0xCB,*/
		/*0x21, 0x2F, 0xC1, 0xE9, 0xD0, 0xE0, 0xDB, 0xEA, 0xEE, 0x42,*/
		/*0x5B, 0xD2, 0xF0, 0xD3, 0x17, 0x5A, 0xA0, 0xE9, 0x89, 0xEA,*/
		/*0x9B, 0x60, 0x3E, 0x38, 0xF3, 0x5F, 0xB3, 0x29, 0xDF, 0x49,*/
		/*0x56, 0x41, 0xF2, 0xBA, 0x04, 0x0F, 0x1C, 0x3A, 0xC6, 0x13,*/
		/*0x83, 0x07, 0xF2, 0x57, 0xCB, 0xA6, 0xB8, 0xB5, 0x88, 0xF4,*/
		/*0x1F*/
/*};*/
//----DELETEME

static int start(void)
{
	int ret;

	rtr_is_stopping = 0;
	rtr_update_overflow = 0;

	if (list_isempty(cache_list)) {
		RPKI_DEBUG(
			"No caches were found in config. Prefix validation is off.");
		return ERROR;
	}
	RPKI_DEBUG("Init rtr_mgr.");
	int groups_len = listcount(cache_list);
	struct rtr_mgr_group *groups = get_groups();

	RPKI_DEBUG("Polling period: %d", polling_period);
	ret = rtr_mgr_init(&rtr_config, groups, groups_len, polling_period,
			   expire_interval, retry_interval,
			   rpki_update_cb_sync_rtr, NULL, NULL, NULL);
	if (ret == RTR_ERROR) {
		RPKI_DEBUG("Init rtr_mgr failed.");
		return ERROR;
	}

	RPKI_DEBUG("Starting rtr_mgr.");
	ret = rtr_mgr_start(rtr_config);
	if (ret == RTR_ERROR) {
		RPKI_DEBUG("Starting rtr_mgr failed.");
		rtr_mgr_free(rtr_config);
		return ERROR;
	}
	rtr_is_running = 1;

	XFREE(MTYPE_BGP_RPKI_CACHE_GROUP, groups);

	return SUCCESS;
}

static int copy_frr_data_to_rtr(struct bgpsec_aspath *aspath,
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

    if (!rtr_is_running) {
        BGPSEC_DEBUG("RPKI is not running");
        return 1;
    }

    if (!attr->bgpsecpath) {
        BGPSEC_DEBUG("BGPsec path is empty");
        return 1;
    }

    aspath = attr->bgpsecpath;

    if (!aspath->sigblock1) {
        BGPSEC_DEBUG("Signature Block is empty");
        return 1;
    }

    /* The first byte of the NLRI is the length in bits.
     * Convert it into bytes. */
    pfx_len_b = (*mp_update->nlri + 7) / 8;
    pfx = rtr_mgr_bgpsec_nlri_new(pfx_len_b);
    pfx->nlri_len = *mp_update->nlri;

    pfx->afi = mp_update->afi;
    memcpy(pfx->nlri,
           (mp_update->nlri + 1), // +1 to skip len byte
           pfx_len_b);

    data = rtr_mgr_bgpsec_new(aspath->sigblock1->alg,
                              mp_update->safi,
                              mp_update->afi,
                              peer->local_as,
                              peer->local_as,
                              pfx);

    retval = copy_frr_data_to_rtr(aspath, data);

    if (retval) {
        BGPSEC_DEBUG("Could not copy RTR data to FRR data");
        return 1;
    }

    result = rtr_mgr_bgpsec_validate_as_path(data, rtr_config);

    rtr_mgr_bgpsec_free(data);

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
    int origin = 0;

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

    //TODO: have a better way of detecting an origin message.
    /* If aspath is empty, this is an origin message */
    if (attr->bgpsecpath) {
        /* Search for a bgpsecpath with the given AS path and given prefix */
        struct bgpsec_aspath *tmp_path = bgpsec_aspath_new();
        tmp_path->str = XCALLOC(MTYPE_BGP_BGPSEC_PATH_STR, attr->aspath->str_len + 1);
        tmp_path->str_len = attr->aspath->str_len;
        /*memcpy(tmp_path->str, attr->aspath->str, attr->aspath->str_len);*/
        strcpy(tmp_path->str, attr->aspath->str);

        int pfx_len_b = (bgpsec_p->prefixlen + 7) / 8;
        uint8_t cidr = (uint8_t)bgpsec_p->prefixlen;

        tmp_path->pfx = XCALLOC(MTYPE_BGP_BGPSEC_NLRI, sizeof(struct bgp_nlri));
        tmp_path->pfx->nlri = XCALLOC(MTYPE_BGP_BGPSEC_NLRI, pfx_len_b + 1);
        tmp_path->pfx->length = pfx_len_b + 1;
        memcpy(tmp_path->pfx->nlri, &cidr, sizeof(uint8_t));
        memcpy(tmp_path->pfx->nlri + 1, bgpsec_p->u.val, pfx_len_b);

        aspath = bgpsec_aspath_get(tmp_path);
        if (!aspath) {
            aspath = bgpsec_aspath_new();
        }
        bgpsec_aspath_free(tmp_path);
        /*aspath = copy_bgpsecpath(attr->bgpsecpath);*/
    } else {
        origin = 1;
        aspath = bgpsec_aspath_new();
    }

    /* Create the signature before writing the BGPsec path to the stream.
     * This saves stripping the path data from the stream again, in case
     * the signature could not be generated.
     */
    RUSAGE_T before, after;
    _Atomic unsigned long cputime;
    unsigned long helper;
    GETRUSAGE(&before);
    rtval = gen_bgpsec_sig(peer, aspath, bgp, bgpsec_p, afi, safi,
                           own_sps, &own_ss);
    GETRUSAGE(&after);
    thread_consumed_time(&after, &before, &helper);
    cputime = helper;
    total_count_attr_parse += 1;
    total_cpu_ticks_attr_parse += cputime;
    if (total_count_attr_parse == 1 ||
        total_count_attr_parse == 500 ||
        total_count_attr_parse == 1000 ||
        total_count_attr_parse == 1500 ||
        total_count_attr_parse == 2000 ||
        total_count_attr_parse == 2500 ||
        total_count_attr_parse == 3000 ||
        total_count_attr_parse == 3500 ||
        total_count_attr_parse == 4000 ||
        total_count_attr_parse == 3500 ||
        total_count_attr_parse == 4000 ||
        total_count_attr_parse == 4500 ||
        total_count_attr_parse == 5000) {
        zlog_debug("sign - count: %d,\
                    duration (rusage): %luus,\
                    total: %f,\
                    average: %f",
                   total_count_attr_parse, cputime,
                   total_cpu_ticks_attr_parse,
                   total_cpu_ticks_attr_parse / total_count_attr_parse);
    }

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
    bgpsec_ss_free(own_ss);
    if (origin) {
        bgpsec_aspath_free(aspath);
        aspath = NULL;
    }

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
        XMALLOC(MTYPE_BGP_BGPSEC_NLRI, sizeof(struct bgp_nlri));
    attr->bgpsecpath->pfx->nlri =
        XMALLOC(MTYPE_BGP_BGPSEC_NLRI, mp_update->length);

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
    XFREE(MTYPE_BGP_BGPSEC_PRIV_KEY, priv_key->filepath);
    priv_key->filepath = NULL;
    XFREE(MTYPE_BGP_BGPSEC_PRIV_KEY, priv_key);
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

	RPKI_DEBUG("Resetting RPKI Session");
	stop();
	return start();
}

static struct rtr_mgr_group *get_connected_group(void)
{
	if (!cache_list || list_isempty(cache_list))
		return NULL;

	return rtr_mgr_get_first_group(rtr_config);
}

static void print_prefix_table_by_asn(struct vty *vty, as_t as)
{
	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group = get_connected_group();
	struct rpki_for_each_record_arg arg;

	arg.vty = vty;
	arg.as = as;

	if (!group) {
		vty_out(vty, "Cannot find a connected group.\n");
		return;
	}

	struct pfx_table *pfx_table = group->sockets[0]->pfx_table;

	vty_out(vty, "RPKI/RTR prefix table\n");
	vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length", "Origin-AS");

	arg.prefix_amount = &number_of_ipv4_prefixes;
	pfx_table_for_each_ipv4_record(pfx_table, print_record_by_asn, &arg);

	arg.prefix_amount = &number_of_ipv6_prefixes;
	pfx_table_for_each_ipv6_record(pfx_table, print_record_by_asn, &arg);

	vty_out(vty, "Number of IPv4 Prefixes: %u\n", number_of_ipv4_prefixes);
	vty_out(vty, "Number of IPv6 Prefixes: %u\n", number_of_ipv6_prefixes);
}

static void print_prefix_table(struct vty *vty)
{
	struct rpki_for_each_record_arg arg;

	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group = get_connected_group();

	arg.vty = vty;

	if (!group)
		return;

	struct pfx_table *pfx_table = group->sockets[0]->pfx_table;

	vty_out(vty, "RPKI/RTR prefix table\n");
	vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length", "Origin-AS");

	arg.prefix_amount = &number_of_ipv4_prefixes;
	pfx_table_for_each_ipv4_record(pfx_table, print_record_cb, &arg);

	arg.prefix_amount = &number_of_ipv6_prefixes;
	pfx_table_for_each_ipv6_record(pfx_table, print_record_cb, &arg);

	vty_out(vty, "Number of IPv4 Prefixes: %u\n", number_of_ipv4_prefixes);
	vty_out(vty, "Number of IPv6 Prefixes: %u\n", number_of_ipv6_prefixes);
}

static int rpki_validate_prefix(struct peer *peer, struct attr *attr,
				const struct prefix *prefix)
{
	struct assegment *as_segment;
	as_t as_number = 0;
	struct lrtr_ip_addr ip_addr_prefix;
	enum pfxv_state result;

	if (!is_synchronized())
		return 0;

	// No aspath means route comes from iBGP
	if (!attr->aspath || !attr->aspath->segments) {
		// Set own as number
		as_number = peer->bgp->as;
	} else {
		as_segment = attr->aspath->segments;
		// Find last AsSegment
		while (as_segment->next)
			as_segment = as_segment->next;

		if (as_segment->type == AS_SEQUENCE) {
			// Get rightmost asn
			as_number = as_segment->as[as_segment->length - 1];
		} else if (as_segment->type == AS_CONFED_SEQUENCE
			   || as_segment->type == AS_CONFED_SET) {
			// Set own as number
			as_number = peer->bgp->as;
		} else {
			// RFC says: "Take distinguished value NONE as asn"
			// which means state is unknown
			return RPKI_NOTFOUND;
		}
	}

	// Get the prefix in requested format
	switch (prefix->family) {
	case AF_INET:
		ip_addr_prefix.ver = LRTR_IPV4;
		ip_addr_prefix.u.addr4.addr = ntohl(prefix->u.prefix4.s_addr);
		break;

	case AF_INET6:
		ip_addr_prefix.ver = LRTR_IPV6;
		ipv6_addr_to_host_byte_order(prefix->u.prefix6.s6_addr32,
					     ip_addr_prefix.u.addr6.addr);
		break;

	default:
		return 0;
	}

	// Do the actual validation
	rtr_mgr_validate(rtr_config, as_number, &ip_addr_prefix,
			 prefix->prefixlen, &result);

	// Print Debug output
	switch (result) {
	case BGP_PFXV_STATE_VALID:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: VALID",
			prefix, as_number);
		return RPKI_VALID;
	case BGP_PFXV_STATE_NOT_FOUND:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: NOT FOUND",
			prefix, as_number);
		return RPKI_NOTFOUND;
	case BGP_PFXV_STATE_INVALID:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: INVALID",
			prefix, as_number);
		return RPKI_INVALID;
	default:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: CANNOT VALIDATE",
			prefix, as_number);
		break;
	}
	return 0;
}

static int add_cache(struct cache *cache)
{
	uint8_t preference = cache->preference;
	struct rtr_mgr_group group;

	group.preference = preference;
	group.sockets_len = 1;
	group.sockets = &cache->rtr_socket;

	if (rtr_is_running) {
		init_tr_socket(cache);

		if (rtr_mgr_add_group(rtr_config, &group) != RTR_SUCCESS) {
			free_tr_socket(cache);
			return ERROR;
		}
	}

	listnode_add(cache_list, cache);

	return SUCCESS;
}

static int add_tcp_cache(const char *host, const char *port,
			 const uint8_t preference)
{
	struct rtr_socket *rtr_socket;
	struct tr_tcp_config *tcp_config =
		XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_tcp_config));
	struct tr_socket *tr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_socket));
	struct cache *cache =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct cache));

	tcp_config->host = XSTRDUP(MTYPE_BGP_RPKI_CACHE, host);
	tcp_config->port = XSTRDUP(MTYPE_BGP_RPKI_CACHE, port);
	tcp_config->bindaddr = NULL;
	tcp_config->data = NULL;
	tcp_config->new_socket = NULL;
	tcp_config->connect_timeout = 0;

	rtr_socket = create_rtr_socket(tr_socket);

	cache->type = TCP;
	cache->tr_socket = tr_socket;
	cache->tr_config.tcp_config = tcp_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	int ret = add_cache(cache);
	if (ret != SUCCESS) {
		free_cache(cache);
	}

	return ret;
}

#if defined(FOUND_SSH)
static int add_ssh_cache(const char *host, const unsigned int port,
			 const char *username, const char *client_privkey_path,
			 const char *client_pubkey_path,
			 const char *server_pubkey_path,
			 const uint8_t preference)
{
	struct tr_ssh_config *ssh_config =
		XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_ssh_config));
	struct cache *cache =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct cache));
	struct tr_socket *tr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_socket));
	struct rtr_socket *rtr_socket;

	ssh_config->port = port;
	ssh_config->host = XSTRDUP(MTYPE_BGP_RPKI_CACHE, host);
	ssh_config->bindaddr = NULL;
	ssh_config->data = NULL;
	ssh_config->new_socket = NULL;
	ssh_config->connect_timeout = 0;

	ssh_config->username = XSTRDUP(MTYPE_BGP_RPKI_CACHE, username);
	ssh_config->client_privkey_path =
		XSTRDUP(MTYPE_BGP_RPKI_CACHE, client_privkey_path);
	ssh_config->server_hostkey_path =
		XSTRDUP(MTYPE_BGP_RPKI_CACHE, server_pubkey_path);

	rtr_socket = create_rtr_socket(tr_socket);

	cache->type = SSH;
	cache->tr_socket = tr_socket;
	cache->tr_config.ssh_config = ssh_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	int ret = add_cache(cache);
	if (ret != SUCCESS) {
		free_cache(cache);
	}

	return ret;
}
#endif

static void free_cache(struct cache *cache)
{
	if (cache->type == TCP) {
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.tcp_config->host);
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.tcp_config->port);
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.tcp_config);
	}
#if defined(FOUND_SSH)
	else {
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.ssh_config->host);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.ssh_config->username);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.ssh_config->client_privkey_path);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.ssh_config->server_hostkey_path);
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.ssh_config);
	}
#endif
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->rtr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache);
}

static int config_write(struct vty *vty)
{
	struct listnode *cache_node;
	struct cache *cache;
    struct bgp *bgp;

	if (listcount(cache_list)) {
		if (rpki_debug)
			vty_out(vty, "debug rpki\n");

		vty_out(vty, "!\n");
		vty_out(vty, "rpki\n");
		vty_out(vty, "  rpki polling_period %d\n", polling_period);
		for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
			switch (cache->type) {
				struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
				struct tr_ssh_config *ssh_config;
#endif
			case TCP:
				tcp_config = cache->tr_config.tcp_config;
				vty_out(vty, "  rpki cache %s %s ",
					tcp_config->host, tcp_config->port);
				break;
#if defined(FOUND_SSH)
			case SSH:
				ssh_config = cache->tr_config.ssh_config;
				vty_out(vty, "  rpki cache %s %u %s %s %s ",
					ssh_config->host, ssh_config->port,
					ssh_config->username,
					ssh_config->client_privkey_path,
					ssh_config->server_hostkey_path != NULL
						? ssh_config
							  ->server_hostkey_path
						: " ");
				break;
#endif
			default:
				break;
			}

			vty_out(vty, "preference %hhu\n", cache->preference);
		}
		vty_out(vty, "  exit\n");

        bgp = bgp_get_default();

        if (bgp->priv_key) {
            if (bgp->priv_key->filepath)
                vty_out(vty, "bgpsec privkey %s\n", bgp->priv_key->filepath);
            if (bgp->priv_key->ski_str)
                vty_out(vty, "bgpsec privkey ski %s\n", bgp->priv_key->ski_str);
        }

		return 1;
	} else {
		return 0;
	}
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
    int pfx_len_b = 0;

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
    pfx_len_b = (p->prefixlen + 7) / 8;
    pfx = rtr_mgr_bgpsec_nlri_new(pfx_len_b);
    pfx->nlri_len = p->prefixlen;
    pfx->afi = afi;
    memcpy(pfx->nlri, &p->u.prefix, pfx_len_b);

    alg = bgpsecpath->sigblock1->alg;

    bgpsec = rtr_mgr_bgpsec_new(alg, safi, afi, bgp->as, peer->as, pfx);

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
    frr_new_ss = XMALLOC(MTYPE_BGP_BGPSEC_PATH_SS, sizeof(struct bgpsec_sigseg));
    memset(frr_new_ss, 0, sizeof(struct bgpsec_sigseg));
    frr_new_ss->signature = XMALLOC(MTYPE_BGP_BGPSEC_SIG, rtr_new_ss->sig_len);

    /* Copy the signature and its length to the input parameters */
    frr_new_ss->next = NULL;
    memcpy(frr_new_ss->signature, rtr_new_ss->signature, rtr_new_ss->sig_len);
    frr_new_ss->sig_len = rtr_new_ss->sig_len;

    /* Copy the SKI from the bgp struct to the new signature segment */
    memcpy(frr_new_ss->ski, bgp->priv_key->ski, SKI_LENGTH);

    *own_ss = frr_new_ss;

    rtr_mgr_bgpsec_free_signatures(rtr_new_ss);
    rtr_mgr_bgpsec_free(bgpsec);

	return 0;
}

static int attr_bgpsec_path(struct bgp_attr_parser_args *args,
                            struct bgp_nlri *mp_update)
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

    if (mp_update->afi == AFI_IP) {
        if (!CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV4)
            || !CHECK_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV4_RCV)) {
            flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
                      "%s sent BGPsec UPDATE, but capabilities are not set for AFI %s",
                      peer->host, afi2str(mp_update->afi));
            return -1;
        }
    }
    if (mp_update->afi == AFI_IP6) {
	    if (!CHECK_FLAG(peer->flags, PEER_FLAG_BGPSEC_SEND_IPV6)
            || !CHECK_FLAG(peer->cap, PEER_CAP_BGPSEC_SEND_IPV6_RCV)) {
            flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
                      "%s sent BGPsec UPDATE, but capabilities are not set for AFI %s",
                      peer->host, afi2str(mp_update->afi));
            return -1;
        }
    }
    if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH))) {
        flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
                  "%s sent invalid BGPsec UPDATE (contains AS_PATH and BGPsec_PATH)",
                  peer->host);
        return -1;
    }

	sps_count = (stream_getw(peer->curr) - 2) / BGPSEC_SECURE_PATH_SEGMENT_SIZE;
	remain_len -= 2;

    aspath = bgpsec_aspath_new();

	/* Build the secure path segments from the stream */
	for (int i = 0; i < sps_count; i++) {
        curr_sps = bgpsec_sps_new();
		curr_sps->pcount = stream_getc(peer->curr);
		curr_sps->flags = stream_getc(peer->curr);
		curr_sps->as = stream_getl(peer->curr);

        if (curr_sps->pcount == 0) {
            flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
                      "%s sent invalid BGPsec UPDATE (encountered pCount value 0)",
                      peer->host);
            return -1;
        }

		if (prev_sps) {
            prev_sps->next = curr_sps;
		} else {
            aspath->secpaths = curr_sps;
		}

		remain_len -= 6;
		prev_sps = curr_sps;
	}

    if (peer->as != aspath->secpaths->as) {
        flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
                  "%s sent invalid BGPsec UPDATE (last AS (%d) does not match peer AS (%d))",
                  peer->host, aspath->secpaths->as, peer->as);
        return -1;
    }

    aspath->path_count = sps_count;

	/* Parse the first signature block from the stream and build the
	 * signature paths segments */
	sigblock1 = bgpsec_sigblock_new();
    sigblock1->sig_count = 0;
	sigblock1->length = stream_getw(peer->curr);
	sigblock1->alg = alg = stream_getc(peer->curr);

    if (alg != 1) {
        flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
                  "%s sent invalid BGPsec UPDATE (invalid algorithm ID %d)",
                  peer->host, alg);
        return -1;
    }

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
        curr_ss->signature = XMALLOC(MTYPE_BGP_BGPSEC_SIG,
                                     curr_ss->sig_len);
        if (!curr_ss->signature) {
            BGPSEC_DEBUG("Memory for signature cound not be allocated");
        }
		stream_get(curr_ss->signature, peer->curr, curr_ss->sig_len);

		prev_ss = curr_ss;
		ss_len -= 22 + curr_ss->sig_len;

        sigblock1->sig_count++;
	}

    if (sps_count != sigblock1->sig_count) {
        flog_warn(EC_BGP_ATTRIBUTE_PARSE_ERROR,
                  "%s sent invalid BGPsec UPDATE (uneven amount of segments)",
                  peer->host);
        return -1;
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
    attr->aspath = bgpsec_aspath_parse(attr);
    attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AS_PATH);

	return 0;
}

/* This function creates an AS path string considering
 * the pcount values. Meaning that the path
 * 1 2 2 2 3
 * will NOT be transformed to
 * 1 2 3
 * This is important when fetching AS paths from the bgpsec
 * hash bucket in bgpsec_aspath_get().
 */
int bgpsec_path2str(struct bgpsec_aspath *aspath)
{
    struct bgpsec_aspath *p;
    struct bgpsec_secpath *sps;
    int length = 0;

    if (!aspath)
        return 0;

    p = aspath;
    sps = p->secpaths;

    /* We define the ASN length just like in aspath_make_str_count */
#define ASN_STR_LEN ((10 + 1) * 40) + 1

    /*buffer = XMALLOC(MTYPE_BGP_BGPSEC_PATH, ASN_STR_LEN);*/
    /*memset(buffer, '\0', ASN_STR_LEN);*/
    char buffer[ASN_STR_LEN] = {'\0'};
    memset(buffer, 0, sizeof(buffer));

    while (sps) {
        for (int i = 0; i < sps->pcount; i++) {
            sprintf(buffer + length, "%d ", sps->as);
            length = strlen(buffer);
        }
        sps = sps->next;
    }

    /* Hacky workaround if the AS path is empty.
     * Setting length to 1 prevents the rest of the function from crashing.
     */
    if (length == 0) {
        length = 1;
    }

#undef ASN_STR_LEN
    /* Space for \0 is included in length */
    aspath->str = XCALLOC(MTYPE_BGP_BGPSEC_PATH_STR, length);

    /* Remove the last separator space */
    length -= 1;
    buffer[length] = '\0';

    strcpy(aspath->str, buffer);
    aspath->str_len = length;

    return length;
}

static int load_private_key_from_file(struct private_key *priv_key)
{
    FILE *keyfile = fopen(priv_key->filepath, "r");
    uint8_t tmp_buff[PRIV_KEY_BUFFER_SIZE];
    uint16_t length = 0;
    //TODO: use X509_get0_subject_key_id() on an X509 cert to get the SKI.
    /*BIO *bio = BIO_new(BIO_s_file());*/
    /*X509 *cert = NULL;*/

    if (!keyfile) {
        BGPSEC_DEBUG("Could not read private key file %s: %s", priv_key->filepath, strerror(errno));
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

DEFUN_NOSH (rpki,
	    rpki_cmd,
	    "rpki",
	    "Enable rpki and enter rpki configuration mode\n")
{
	vty->node = RPKI_NODE;
	return CMD_SUCCESS;
}

DEFUN (bgp_rpki_start,
       bgp_rpki_start_cmd,
       "rpki start",
       RPKI_OUTPUT_STRING
       "start rpki support\n")
{
	if (listcount(cache_list) == 0)
		vty_out(vty,
			"Could not start rpki because no caches are configured\n");

	if (!is_running()) {
		if (start() == ERROR) {
			RPKI_DEBUG("RPKI failed to start");
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

DEFUN (bgp_rpki_stop,
       bgp_rpki_stop_cmd,
       "rpki stop",
       RPKI_OUTPUT_STRING
       "start rpki support\n")
{
	if (is_running())
		stop();

	return CMD_SUCCESS;
}

DEFPY (rpki_polling_period,
       rpki_polling_period_cmd,
       "rpki polling_period (1-86400)$pp",
       RPKI_OUTPUT_STRING
       "Set polling period\n"
       "Polling period value\n")
{
	polling_period = pp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_polling_period,
       no_rpki_polling_period_cmd,
       "no rpki polling_period",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set polling period back to default\n")
{
	polling_period = POLLING_PERIOD_DEFAULT;
	return CMD_SUCCESS;
}

DEFPY (rpki_expire_interval,
       rpki_expire_interval_cmd,
       "rpki expire_interval (600-172800)$tmp",
       RPKI_OUTPUT_STRING
       "Set expire interval\n"
       "Expire interval value\n")
{
	if ((unsigned int)tmp >= polling_period) {
		expire_interval = tmp;
		return CMD_SUCCESS;
	}

	vty_out(vty, "%% Expiry interval must be polling period or larger\n");
	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_rpki_expire_interval,
       no_rpki_expire_interval_cmd,
       "no rpki expire_interval",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set expire interval back to default\n")
{
	expire_interval = polling_period * 2;
	return CMD_SUCCESS;
}

DEFPY (rpki_retry_interval,
       rpki_retry_interval_cmd,
       "rpki retry_interval (1-7200)$tmp",
       RPKI_OUTPUT_STRING
       "Set retry interval\n"
       "retry interval value\n")
{
	retry_interval = tmp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_retry_interval,
       no_rpki_retry_interval_cmd,
       "no rpki retry_interval",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set retry interval back to default\n")
{
	retry_interval = RETRY_INTERVAL_DEFAULT;
	return CMD_SUCCESS;
}

DEFPY (rpki_cache,
       rpki_cache_cmd,
       "rpki cache <A.B.C.D|WORD><TCPPORT|(1-65535)$sshport SSH_UNAME SSH_PRIVKEY SSH_PUBKEY [SERVER_PUBKEY]> preference (1-255)",
       RPKI_OUTPUT_STRING
       "Install a cache server to current group\n"
       "IP address of cache server\n Hostname of cache server\n"
       "TCP port number\n"
       "SSH port number\n"
       "SSH user name\n"
       "Path to own SSH private key\n"
       "Path to own SSH public key\n"
       "Path to Public key of cache server\n"
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


	// use ssh connection
	if (ssh_uname) {
#if defined(FOUND_SSH)
		return_value =
			add_ssh_cache(cache, sshport, ssh_uname, ssh_privkey,
				      ssh_pubkey, server_pubkey, preference);
#else
		return_value = SUCCESS;
		vty_out(vty,
			"ssh sockets are not supported. Please recompile rtrlib and frr with ssh support. If you want to use it\n");
#endif
	} else { // use tcp connection
		return_value = add_tcp_cache(cache, tcpport, preference);
	}

	if (return_value == ERROR) {
		vty_out(vty, "Could not create new rpki cache\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFPY (no_rpki_cache,
       no_rpki_cache_cmd,
       "no rpki cache <A.B.C.D|WORD> <TCPPORT|(1-65535)$sshport> preference (1-255)$preference",
       NO_STR
       RPKI_OUTPUT_STRING
       "Remove a cache server\n"
       "IP address of cache server\n Hostname of cache server\n"
       "TCP port number\n"
       "SSH port number\n"
       "Preference of the cache server\n"
       "Preference value\n")
{
	struct cache *cache_p = find_cache(preference);

	if (!cache_p) {
		vty_out(vty, "Could not find cache %ld\n", preference);
		return CMD_WARNING;
	}

	if (rtr_is_running && listcount(cache_list) == 1) {
		stop();
	} else if (rtr_is_running) {
		if (rtr_mgr_remove_group(rtr_config, preference) == RTR_ERROR) {
			vty_out(vty, "Could not remove cache %ld", preference);

			vty_out(vty, "\n");
			return CMD_WARNING;
		}
	}

	listnode_delete(cache_list, cache_p);
	free_cache(cache_p);

	return CMD_SUCCESS;
}

DEFUN (show_rpki_prefix_table,
       show_rpki_prefix_table_cmd,
       "show rpki prefix-table",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show validated prefixes which were received from RPKI Cache\n")
{
	struct listnode *cache_node;
	struct cache *cache;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		vty_out(vty, "host: %s port: %s\n",
			cache->tr_config.tcp_config->host,
			cache->tr_config.tcp_config->port);
	}
	if (is_synchronized())
		print_prefix_table(vty);
	else
		vty_out(vty, "No connection to RPKI cache server.\n");

	return CMD_SUCCESS;
}

DEFPY (show_rpki_as_number, show_rpki_as_number_cmd,
      "show rpki as-number (1-4294967295)$by_asn",
      SHOW_STR RPKI_OUTPUT_STRING
      "Lookup by ASN in prefix table\n"
      "AS Number\n")
{
	if (!is_synchronized()) {
		vty_out(vty, "No Connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	print_prefix_table_by_asn(vty, by_asn);
	return CMD_SUCCESS;
}

DEFPY (show_rpki_prefix,
       show_rpki_prefix_cmd,
       "show rpki prefix <A.B.C.D/M|X:X::X:X/M> [(1-4294967295)$asn]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Lookup IP prefix and optionally ASN in prefix table\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "AS Number\n")
{

	if (!is_synchronized()) {
		vty_out(vty, "No Connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	struct lrtr_ip_addr addr;
	char addr_str[INET6_ADDRSTRLEN];
	size_t addr_len = strchr(prefix_str, '/') - prefix_str;

	memset(addr_str, 0, sizeof(addr_str));
	memcpy(addr_str, prefix_str, addr_len);

	if (lrtr_ip_str_to_addr(addr_str, &addr) != 0) {
		vty_out(vty, "Invalid IP prefix\n");
		return CMD_WARNING;
	}

	struct pfx_record *matches = NULL;
	unsigned int match_count = 0;
	enum pfxv_state result;

	if (pfx_table_validate_r(rtr_config->pfx_table, &matches, &match_count,
				 asn, &addr, prefix->prefixlen, &result)
	    != PFX_SUCCESS) {
		vty_out(vty, "Prefix lookup failed");
		return CMD_WARNING;
	}

	vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length", "Origin-AS");
	for (size_t i = 0; i < match_count; ++i) {
		const struct pfx_record *record = &matches[i];

		if (record->max_len >= prefix->prefixlen
		    && ((asn != 0 && (uint32_t)asn == record->asn)
			|| asn == 0)) {
			print_record(&matches[i], vty);
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_rpki_cache_server,
       show_rpki_cache_server_cmd,
       "show rpki cache-server",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "SHOW configured cache server\n")
{
	struct listnode *cache_node;
	struct cache *cache;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		if (cache->type == TCP) {
			vty_out(vty, "host: %s port: %s\n",
				cache->tr_config.tcp_config->host,
				cache->tr_config.tcp_config->port);

#if defined(FOUND_SSH)
		} else if (cache->type == SSH) {
			vty_out(vty,
				"host: %s port: %d username: %s server_hostkey_path: %s client_privkey_path: %s\n",
				cache->tr_config.ssh_config->host,
				cache->tr_config.ssh_config->port,
				cache->tr_config.ssh_config->username,
				cache->tr_config.ssh_config
					->server_hostkey_path,
				cache->tr_config.ssh_config
					->client_privkey_path);
#endif
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_rpki_cache_connection,
       show_rpki_cache_connection_cmd,
       "show rpki cache-connection",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show to which RPKI Cache Servers we have a connection\n")
{
	if (!is_synchronized()) {
		vty_out(vty, "No connection to RPKI cache server.\n");

		return CMD_SUCCESS;
	}

	struct listnode *cache_node;
	struct cache *cache;
	struct rtr_mgr_group *group = get_connected_group();

	if (!group) {
		vty_out(vty, "Cannot find a connected group.\n");
		return CMD_SUCCESS;
	}
	vty_out(vty, "Connected to group %d\n", group->preference);
	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		if (cache->preference == group->preference) {
			struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
			struct tr_ssh_config *ssh_config;
#endif

			switch (cache->type) {
			case TCP:
				tcp_config = cache->tr_config.tcp_config;
				vty_out(vty, "rpki tcp cache %s %s pref %hhu\n",
					tcp_config->host, tcp_config->port,
					cache->preference);
				break;

#if defined(FOUND_SSH)
			case SSH:
				ssh_config = cache->tr_config.ssh_config;
				vty_out(vty, "rpki ssh cache %s %u pref %hhu\n",
					ssh_config->host, ssh_config->port,
					cache->preference);
				break;
#endif

			default:
				break;
			}
		}
	}

	return CMD_SUCCESS;
}

static int config_on_exit(struct vty *vty)
{
	reset(false);
	return 1;
}

DEFUN (rpki_reset,
       rpki_reset_cmd,
       "rpki reset",
       RPKI_OUTPUT_STRING
       "reset rpki\n")
{
	return reset(true) == SUCCESS ? CMD_SUCCESS : CMD_WARNING;
}

DEFUN (debug_rpki,
       debug_rpki_cmd,
       "debug rpki",
       DEBUG_STR
       "Enable debugging for rpki\n")
{
	rpki_debug = 1;
	return CMD_SUCCESS;
}

DEFUN (no_debug_rpki,
       no_debug_rpki_cmd,
       "no debug rpki",
       NO_STR
       DEBUG_STR
       "Disable debugging for rpki\n")
{
	rpki_debug = 0;
	return CMD_SUCCESS;
}

DEFUN_YANG (match_rpki,
       match_rpki_cmd,
       "match rpki <valid|invalid|notfound>",
       MATCH_STR
       RPKI_OUTPUT_STRING
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:rpki']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:rpki", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[2]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_rpki,
       no_match_rpki_cmd,
       "no match rpki <valid|invalid|notfound>",
       NO_STR
       MATCH_STR
       RPKI_OUTPUT_STRING
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:rpki']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

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

        bgp->priv_key->filepath_len = strlen((const char *)argv[idx_path]->arg) + 1;
        bgp->priv_key->filepath = XMALLOC(MTYPE_BGP_BGPSEC_PRIV_KEY,
                                          bgp->priv_key->filepath_len);
        strcpy((char *)bgp->priv_key->filepath, (const char *)argv[idx_path]->arg);
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


static void install_cli_commands(void)
{
	// TODO: make config write work
	install_node(&rpki_node);
	install_default(RPKI_NODE);
	install_element(CONFIG_NODE, &rpki_cmd);
	install_element(ENABLE_NODE, &rpki_cmd);

	install_element(ENABLE_NODE, &bgp_rpki_start_cmd);
	install_element(ENABLE_NODE, &bgp_rpki_stop_cmd);

	/* Install rpki reset command */
	install_element(RPKI_NODE, &rpki_reset_cmd);

	/* Install rpki polling period commands */
	install_element(RPKI_NODE, &rpki_polling_period_cmd);
	install_element(RPKI_NODE, &no_rpki_polling_period_cmd);

	/* Install rpki expire interval commands */
	install_element(RPKI_NODE, &rpki_expire_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_expire_interval_cmd);

	/* Install rpki retry interval commands */
	install_element(RPKI_NODE, &rpki_retry_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_retry_interval_cmd);

	/* Install rpki cache commands */
	install_element(RPKI_NODE, &rpki_cache_cmd);
	install_element(RPKI_NODE, &no_rpki_cache_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_rpki_prefix_table_cmd);
	install_element(VIEW_NODE, &show_rpki_cache_connection_cmd);
	install_element(VIEW_NODE, &show_rpki_cache_server_cmd);
	install_element(VIEW_NODE, &show_rpki_prefix_cmd);
	install_element(VIEW_NODE, &show_rpki_as_number_cmd);

	/* Install debug commands */
	install_element(CONFIG_NODE, &debug_rpki_cmd);
	install_element(ENABLE_NODE, &debug_rpki_cmd);
	install_element(CONFIG_NODE, &no_debug_rpki_cmd);
	install_element(ENABLE_NODE, &no_debug_rpki_cmd);

	/* Install route match */
	route_map_install_match(&route_match_rpki_cmd);
	install_element(RMAP_NODE, &match_rpki_cmd);
	install_element(RMAP_NODE, &no_match_rpki_cmd);

    /* Install BGPsec key commands */
    install_element(BGP_NODE, &bgpsec_private_key_cmd);
    install_element(BGP_NODE, &bgpsec_private_key_ski_cmd);
}

FRR_MODULE_SETUP(.name = "bgpd_rpki", .version = "0.3.6",
		 .description = "Enable RPKI support for FRR.",
		 .init = bgp_rpki_module_init,
);
