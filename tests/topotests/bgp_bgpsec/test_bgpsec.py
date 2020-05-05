#!/usr/bin/env python

#
# test_bgp_as_wide_bgp_identifier.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
rfc6286: Autonomous-System-Wide Unique BGP Identifier for BGP-4
Test if 'Bad BGP Identifier' notification is sent only to
internal peers (autonomous-system-wide). eBGP peers are not
affected and should work.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo


class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        for routern in range(1, 3):
            tgen.add_router("r{}".format(routern))

        tgen.gears["r1"].add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology("debug")

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.iteritems(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            # TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname)), "-M rpki", os.path.join(CWD, "{}/privkey.der".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_as_wide_bgp_identifier():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router, ip):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor %s json" % ip))
        expected = {ip: {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, tgen.gears["r1"], "10.0.0.3")
    success, result = topotest.run_and_expect(test_func, None, count=5, wait=0.5)

    assert result is None, 'Failed to converge: "{}"'.format(tgen.gears["r1"])

    test_func = functools.partial(_bgp_converge, tgen.gears["r2"], "10.0.0.2")
    success, result = topotest.run_and_expect(test_func, None, count=5, wait=0.5)

    assert result is None, 'Failed to converge: "{}"'.format(tgen.gears["r2"])

    def _bgp_prefix_counter(router, ip, updates):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor %s json" % ip))
        expected = {
            ip: {
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": updates}},
            }
        }
        return topotest.json_cmp(output, expected)

    router = tgen.gears["r1"]

    # print router.vtysh_cmd("show ip bgp neighbor %s" % "10.0.0.2")
    # print router.vtysh_cmd("show running-config")

    test_func = functools.partial(_bgp_prefix_counter, router, "10.0.0.3", 2)
    success, result = topotest.run_and_expect(test_func, None, count=5, wait=0.5)

    assert result is None, 'Failed to see right amount of prefixes in "{}"'.format(router)

    router = tgen.gears["r2"]

    # print router.vtysh_cmd("show ip bgp neighbor %s" % "10.0.0.2")

    test_func = functools.partial(_bgp_prefix_counter, router, "10.0.0.2", 4)
    success, result = topotest.run_and_expect(test_func, None, count=5, wait=0.5)

    assert result is None, 'Failed to see right amount of prefixes in "{}"'.format(router)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
