/*
 * Copyright (C) 2017 Cumulus Networks Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"

struct zebra_privs_t *bgpd_privs = NULL;
struct thread_master *master = NULL;

static uint8_t ski1[]  = {
    0x47, 0xF2, 0x3B, 0xF1, 0xAB,
    0x2F, 0x8A, 0x9D, 0x26, 0x86,
    0x4E, 0xBB, 0xD8, 0xDF, 0x27,
    0x11, 0xC7, 0x44, 0x06, 0xEC
};

static uint8_t ski2[]  = {
    0xAB, 0x4D, 0x91, 0x0F, 0x55,
    0xCA, 0xE7, 0x1A, 0x21, 0x5E,
    0xF3, 0xCA, 0xFE, 0x3A, 0xCC,
    0x45, 0xB5, 0xEE, 0xC1, 0x54
};

static uint8_t ski3[]  = {
    0xCD, 0x4D, 0x91, 0x0F, 0x55,
    0xCA, 0xE7, 0x1A, 0x21, 0x5E,
    0xF3, 0xCA, 0xFE, 0x3A, 0xCC,
    0x45, 0xB5, 0xEE, 0xC1, 0x68
};

static uint8_t sig1[] = {
    0x12, 0x23, 0x34, 0x45, 0x56
};

static uint8_t sig2[] = {
    0x67, 0x78, 0x89, 0x9A, 0xA0
};

static uint8_t sig3[] = {
    0xBC, 0xCD, 0xDE, 0xEF, 0xF0
};

/*
 * These tests are for there to make sure that BGPsec AS path operations
 * are valid, such as allocating and freeing.
 */

static void test_bgpsec_aspath(void)
{
    struct bgpsec_aspath *path = bgpsec_aspath_new();

    assert(path);
    assert(path->secpaths == NULL);
    assert(path->path_count == 0);
    assert(path->sigblock1 == NULL);
    assert(path->sigblock2 == NULL);
    assert(path->str == NULL);
    assert(path->str_len == 0);

    bgpsec_aspath_free(path);
}

static void test_bgpsec_sigblock(void)
{
    struct bgpsec_aspath *path = bgpsec_aspath_new();
    path->sigblock1 = bgpsec_sigblock_new();

    assert(path->sigblock1);
    assert(path->sigblock1->sigsegs == NULL);
    assert(path->sigblock1->length == 0);
    assert(path->sigblock1->alg == 1);
    assert(path->sigblock1->sig_count == 0);

    bgpsec_aspath_free(path);
}

static void test_bgpsec_secpath_new(void)
{
    struct bgpsec_aspath *path = bgpsec_aspath_new();
    struct bgpsec_secpath *first = NULL;

    path->secpaths = bgpsec_secpath_new();
    first = path->secpaths;

    for (int i = 0; i < 10; i++) {
        path->secpaths->next = bgpsec_secpath_new();
        path->secpaths = path->secpaths->next;
    }

    path->secpaths = first;
    bgpsec_aspath_free(path);
}

static void test_bgpsec_sigsegs_new(void)
{
    struct bgpsec_aspath *path = bgpsec_aspath_new();
    struct bgpsec_sigseg *first = NULL;

    path->sigblock1 = bgpsec_sigblock_new();
    path->sigblock1->sigsegs = bgpsec_sigseg_new();
    first = path->sigblock1->sigsegs;

    for (int i = 0; i < 10; i++) {
        path->sigblock1->sigsegs->next = bgpsec_sigseg_new();
        path->sigblock1->sigsegs = path->sigblock1->sigsegs->next;
    }

    path->sigblock1->sigsegs = first;
    bgpsec_aspath_free(path);
}

static void test_bgpsec_copy_secpath(void)
{
    struct bgpsec_secpath *first = bgpsec_secpath_new();
    struct bgpsec_secpath *second = bgpsec_secpath_new();
    struct bgpsec_secpath *third = bgpsec_secpath_new();

    struct bgpsec_secpath *copy;

    first->pcount = 1;
    first->flags = 1;
    first->as = 111;
    first->next = second;

    second->pcount = 2;
    second->flags = 2;
    second->as = 222;
    second->next = third;

    third->pcount = 3;
    third->flags = 3;
    third->as = 333;
    third->next = NULL;

    copy = copy_secpath(first);

    assert(copy);

    assert(copy->pcount == 1);
    assert(copy->flags == 1);
    assert(copy->as == 111);

    assert(copy->next->pcount == 2);
    assert(copy->next->flags == 2);
    assert(copy->next->as == 222);

    assert(copy->next->next->pcount == 3);
    assert(copy->next->next->flags == 3);
    assert(copy->next->next->as == 333);

    bgpsec_secpath_free_all(first);
    bgpsec_secpath_free_all(copy);
}

static void test_bgpsec_copy_sigseg(void)
{
    struct bgpsec_sigseg *first = bgpsec_sigseg_new();
    struct bgpsec_sigseg *second = bgpsec_sigseg_new();
    struct bgpsec_sigseg *third = bgpsec_sigseg_new();

    struct bgpsec_sigseg *copy;

    assert(first);
    assert(second);
    assert(third);

    first->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);
    second->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);
    third->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);

    memcpy(first->ski, ski1, SKI_SIZE);
    first->sig_len = 5;
    memcpy(first->signature, sig1, 5);
    first->next = second;

    memcpy(second->ski, ski2, SKI_SIZE);
    second->sig_len = 5;
    memcpy(second->signature, sig2, 5);
    second->next = third;

    memcpy(third->ski, ski3, SKI_SIZE);
    third->sig_len = 5;
    memcpy(third->signature, sig3, 5);
    third->next = NULL;

    copy = copy_sigseg(first);

    assert(copy);

    assert(copy->ski[0] == 0x47);
    assert(copy->ski[19] == 0xEC);
    assert(copy->sig_len == 5);
    assert(copy->signature[0] == 0x12);
    assert(copy->signature[4] == 0x56);

    assert(copy->next->ski[0] == 0xAB);
    assert(copy->next->ski[19] == 0x54);
    assert(copy->next->sig_len == 5);
    assert(copy->next->signature[0] == 0x67);
    assert(copy->next->signature[4] == 0xA0);

    assert(copy->next->next->ski[0] == 0xCD);
    assert(copy->next->next->ski[19] == 0x68);
    assert(copy->next->next->sig_len == 5);
    assert(copy->next->next->signature[0] == 0xBC);
    assert(copy->next->next->signature[4] == 0xF0);

    bgpsec_sigseg_free_all(first);
    bgpsec_sigseg_free_all(copy);
}

static void test_bgpsec_copy_bgpsecpath()
{
    struct bgpsec_aspath *path = bgpsec_aspath_new();
    struct bgpsec_aspath *copy;

    struct bgpsec_sigseg *first_sig = bgpsec_sigseg_new();
    struct bgpsec_sigseg *second_sig = bgpsec_sigseg_new();
    struct bgpsec_sigseg *third_sig = bgpsec_sigseg_new();

    struct bgpsec_secpath *first_sec = bgpsec_secpath_new();
    struct bgpsec_secpath *second_sec = bgpsec_secpath_new();
    struct bgpsec_secpath *third_sec = bgpsec_secpath_new();

    path->sigblock1 = bgpsec_sigblock_new();

    path->sigblock1->sigsegs = first_sig;
    path->secpaths = first_sec;

    path->sigblock1->length = 100;
    path->sigblock1->alg = 1;
    path->sigblock1->sig_count = 3;

    path->path_count = 3;

    first_sig->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);
    second_sig->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);
    third_sig->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);

    memcpy(first_sig->ski, ski1, SKI_SIZE);
    first_sig->sig_len = 5;
    memcpy(first_sig->signature, sig1, 5);
    first_sig->next = second_sig;

    memcpy(second_sig->ski, ski2, SKI_SIZE);
    second_sig->sig_len = 5;
    memcpy(second_sig->signature, sig2, 5);
    second_sig->next = third_sig;

    memcpy(third_sig->ski, ski3, SKI_SIZE);
    third_sig->sig_len = 5;
    memcpy(third_sig->signature, sig3, 5);
    third_sig->next = NULL;

    first_sec->pcount = 1;
    first_sec->flags = 1;
    first_sec->as = 111;
    first_sec->next = second_sec;

    second_sec->pcount = 2;
    second_sec->flags = 2;
    second_sec->as = 222;
    second_sec->next = third_sec;

    third_sec->pcount = 3;
    third_sec->flags = 3;
    third_sec->as = 333;
    third_sec->next = NULL;

    copy = copy_bgpsecpath(path);

    assert(copy);

    assert(copy->sigblock1->length == 100);
    assert(copy->sigblock1->alg == 1);
    assert(copy->sigblock1->sig_count == 3);

    assert(copy->path_count == 3);

    assert(copy->sigblock1->sigsegs->ski[0] == 0x47);
    assert(copy->sigblock1->sigsegs->ski[19] == 0xEC);
    assert(copy->sigblock1->sigsegs->sig_len == 5);
    assert(copy->sigblock1->sigsegs->signature[0] == 0x12);
    assert(copy->sigblock1->sigsegs->signature[4] == 0x56);

    assert(copy->sigblock1->sigsegs->next->ski[0] == 0xAB);
    assert(copy->sigblock1->sigsegs->next->ski[19] == 0x54);
    assert(copy->sigblock1->sigsegs->next->sig_len == 5);
    assert(copy->sigblock1->sigsegs->next->signature[0] == 0x67);
    assert(copy->sigblock1->sigsegs->next->signature[4] == 0xA0);

    assert(copy->sigblock1->sigsegs->next->next->ski[0] == 0xCD);
    assert(copy->sigblock1->sigsegs->next->next->ski[19] == 0x68);
    assert(copy->sigblock1->sigsegs->next->next->sig_len == 5);
    assert(copy->sigblock1->sigsegs->next->next->signature[0] == 0xBC);
    assert(copy->sigblock1->sigsegs->next->next->signature[4] == 0xF0);

    assert(copy->secpaths->pcount == 1);
    assert(copy->secpaths->flags == 1);
    assert(copy->secpaths->as == 111);

    assert(copy->secpaths->next->pcount == 2);
    assert(copy->secpaths->next->flags == 2);
    assert(copy->secpaths->next->as == 222);

    assert(copy->secpaths->next->next->pcount == 3);
    assert(copy->secpaths->next->next->flags == 3);
    assert(copy->secpaths->next->next->as == 333);

    bgpsec_aspath_free(path);
    bgpsec_aspath_free(copy);
}

static void test_bgpsec_reverse_order()
{
    struct bgpsec_aspath *path = bgpsec_aspath_new();

    struct bgpsec_sigseg *first_sig = bgpsec_sigseg_new();
    struct bgpsec_sigseg *second_sig = bgpsec_sigseg_new();
    struct bgpsec_sigseg *third_sig = bgpsec_sigseg_new();

    struct bgpsec_sigseg *sig_reversed = NULL;
    struct bgpsec_sigseg *sig_normal = NULL;

    struct bgpsec_secpath *first_sec = bgpsec_secpath_new();
    struct bgpsec_secpath *second_sec = bgpsec_secpath_new();
    struct bgpsec_secpath *third_sec = bgpsec_secpath_new();

    struct bgpsec_secpath *sec_reversed = NULL;
    struct bgpsec_secpath *sec_normal = NULL;

    path->sigblock1 = bgpsec_sigblock_new();

    path->sigblock1->sigsegs = first_sig;
    path->secpaths = first_sec;

    path->sigblock1->length = 100;
    path->sigblock1->alg = 1;
    path->sigblock1->sig_count = 3;

    path->path_count = 3;

    first_sig->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);
    second_sig->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);
    third_sig->signature = XMALLOC(MTYPE_BGP_BGPSEC_PATH, 5);

    memcpy(first_sig->ski, ski1, SKI_SIZE);
    first_sig->sig_len = 5;
    memcpy(first_sig->signature, sig1, 5);
    first_sig->next = second_sig;

    memcpy(second_sig->ski, ski2, SKI_SIZE);
    second_sig->sig_len = 5;
    memcpy(second_sig->signature, sig2, 5);
    second_sig->next = third_sig;

    memcpy(third_sig->ski, ski3, SKI_SIZE);
    third_sig->sig_len = 5;
    memcpy(third_sig->signature, sig3, 5);
    third_sig->next = NULL;

    first_sec->pcount = 1;
    first_sec->flags = 1;
    first_sec->as = 111;
    first_sec->next = second_sec;

    second_sec->pcount = 2;
    second_sec->flags = 2;
    second_sec->as = 222;
    second_sec->next = third_sec;

    third_sec->pcount = 3;
    third_sec->flags = 3;
    third_sec->as = 333;
    third_sec->next = NULL;

    sig_reversed = reverse_sigseg_order(first_sig);

    assert(sig_reversed->ski[0] == 0xCD);
    assert(sig_reversed->ski[19] == 0x68);
    assert(sig_reversed->sig_len == 5);
    assert(sig_reversed->signature[0] == 0xBC);
    assert(sig_reversed->signature[4] == 0xF0);

    assert(sig_reversed->next->ski[0] == 0xAB);
    assert(sig_reversed->next->ski[19] == 0x54);
    assert(sig_reversed->next->sig_len == 5);
    assert(sig_reversed->next->signature[0] == 0x67);
    assert(sig_reversed->next->signature[4] == 0xA0);

    assert(sig_reversed->next->next->ski[0] == 0x47);
    assert(sig_reversed->next->next->ski[19] == 0xEC);
    assert(sig_reversed->next->next->sig_len == 5);
    assert(sig_reversed->next->next->signature[0] == 0x12);
    assert(sig_reversed->next->next->signature[4] == 0x56);

    sig_normal = reverse_sigseg_order(sig_reversed);

    assert(sig_normal->ski[0] == 0x47);
    assert(sig_normal->ski[19] == 0xEC);
    assert(sig_normal->sig_len == 5);
    assert(sig_normal->signature[0] == 0x12);
    assert(sig_normal->signature[4] == 0x56);

    assert(sig_normal->next->ski[0] == 0xAB);
    assert(sig_normal->next->ski[19] == 0x54);
    assert(sig_normal->next->sig_len == 5);
    assert(sig_normal->next->signature[0] == 0x67);
    assert(sig_normal->next->signature[4] == 0xA0);

    assert(sig_normal->next->next->ski[0] == 0xCD);
    assert(sig_normal->next->next->ski[19] == 0x68);
    assert(sig_normal->next->next->sig_len == 5);
    assert(sig_normal->next->next->signature[0] == 0xBC);
    assert(sig_normal->next->next->signature[4] == 0xF0);

    sec_reversed = reverse_secpath_order(first_sec);

    assert(sec_reversed->pcount == 3);
    assert(sec_reversed->flags == 3);
    assert(sec_reversed->as == 333);

    assert(sec_reversed->next->pcount == 2);
    assert(sec_reversed->next->flags == 2);
    assert(sec_reversed->next->as == 222);

    assert(sec_reversed->next->next->pcount == 1);
    assert(sec_reversed->next->next->flags == 1);
    assert(sec_reversed->next->next->as == 111);

    sec_normal = reverse_secpath_order(sec_reversed);

    assert(sec_normal->pcount == 1);
    assert(sec_normal->flags == 1);
    assert(sec_normal->as == 111);

    assert(sec_normal->next->pcount == 2);
    assert(sec_normal->next->flags == 2);
    assert(sec_normal->next->as == 222);

    assert(sec_normal->next->next->pcount == 3);
    assert(sec_normal->next->next->flags == 3);
    assert(sec_normal->next->next->as == 333);

    bgpsec_sigseg_free_all(sig_reversed);
    bgpsec_sigseg_free_all(sig_normal);
    bgpsec_secpath_free_all(sec_reversed);
    bgpsec_secpath_free_all(sec_normal);
}

int main(int argc, char *argv[])
{
    test_bgpsec_aspath();
    test_bgpsec_sigblock();
    test_bgpsec_secpath_new();
    test_bgpsec_sigsegs_new();
    test_bgpsec_copy_secpath();
    test_bgpsec_copy_sigseg();
    test_bgpsec_copy_bgpsecpath();
    test_bgpsec_reverse_order();
}
