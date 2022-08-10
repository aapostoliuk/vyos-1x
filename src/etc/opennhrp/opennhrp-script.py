#!/usr/bin/env python3
#
# Copyright (C) 2021 VyOS maintainers and contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import re
import sys
import vici
import logging

from systemd.journal import JournalHandler
from json import loads

from vyos.util import cmd
from vyos.util import process_named_running
from collections import OrderedDict

NHRP_CONFIG = "/run/opennhrp/opennhrp.conf"

def vici_get_ipsec_uniqueid(conn, src_nbma, dst_nbma):
    try:
        session = vici.Session()
        sases = session.list_sas({'ike': conn})
        print('OK')
        for sas in sases:
            if sas[conn]["local-host"].decode('ascii') == src_nbma  \
                    and sas[conn]["remote-host"].decode('ascii') == dst_nbma:
                logger.info('Terminating tunnel id: %s', sas[conn]["uniqueid"].decode('ascii'))
                return sas[conn]["uniqueid"].decode('ascii')
        logger.info('Cannot find dmvpn ipsec tunnel src_nbma %s dst_nbma %s', src_nbma, dst_nbma)
        return '0'
    except:
        print('Terminated')
        return None

def vici_ike_terminate(ikeid):
    try:
        session = vici.Session()
        logs = session.terminate({'ike-id': ikeid, 'timeout': '-1'})
        logger.info("Tunnel id %s was terminated", ikeid)
        for log in logs:
            message = log['msg'].decode('ascii')
            print('INIT LOG:', message)
        return True
    except:
        logger.info("Tunnel id %s not terminated", ikeid)
        return None

def parse_type_ipsec(interface):
    with open(NHRP_CONFIG, 'r') as f:
        lines = f.readlines()
        match = rf'^interface {interface} #(hub|spoke)(?:\s([\w-]+))?$'
        for line in lines:
            m = re.match(match, line)
            if m:
                return m[1], m[2]
    return None, None


def add_peer_route(nbma_src: str, nbma_dst: str, mtu: str) -> None:
    """Add a route to a NBMA peer

    Args:
        nmba_src (str): a local IP address
        nbma_dst (str): a remote IP address
        mtu (str): a MTU for a route
    """
    # Find routes to a peer
    route_get_cmd = f'sudo ip -j route get {nbma_dst} from {nbma_src}'
    try:
        route_info_data = loads(cmd(route_get_cmd))
    except Exception as err:
        print(f'Unable to find a route to {nbma_dst}: {err}')

    # Check if an output has an expected format
    if not isinstance(route_info_data, list):
        print(f'Garbage returned from the "{route_get_cmd}" command: \
            {route_info_data}')
        return

    # Add static routes to a peer
    for route_item in route_info_data:
        route_dev = route_item.get('dev')
        route_dst = route_item.get('dst')
        route_gateway = route_item.get('gateway')
        # Prepare a command to add a route
        route_add_cmd = 'sudo ip route add'
        if route_dst:
            route_add_cmd = f'{route_add_cmd} {route_dst}'
        if route_gateway:
            route_add_cmd = f'{route_add_cmd} via {route_gateway}'
        if route_dev:
            route_add_cmd = f'{route_add_cmd} dev {route_dev}'
        route_add_cmd = f'{route_add_cmd} proto 42 mtu {mtu}'
        # Add a route
        try:
            cmd(route_add_cmd)
        except Exception as err:
            print(f'Unable to add a route using command "{route_add_cmd}": \
                    {err}')


def vici_initiate(conn, child_sa, src_addr, dest_addr):
    try:
        session = vici.Session()
        logs = session.initiate({
            'ike': conn,
            'child': child_sa,
            'timeout': '-1',
            'my-host': src_addr,
            'other-host': dest_addr
        })
        for log in logs:
            message = log['msg'].decode('ascii')
            print('INIT LOG:', message)
        return True
    except:
        return None


def vici_terminate(conn, child_sa, src_addr, dest_addr):
    ikeid = vici_get_ipsec_uniqueid(conn,src_addr,dest_addr)
    if ikeid is None:
        return None
    elif ikeid == '0':
        logger.info('Nothing terminate')
        return False
    else:
        return vici_ike_terminate(ikeid)

def iface_up(interface):
    logger.info('iface_up %s', interface)

    cmd(f'sudo ip route flush proto 42 dev {interface}')
    cmd(f'sudo ip neigh flush dev {interface}')


def peer_up(dmvpn_type, conn):
    # src_addr = os.getenv('NHRP_SRCADDR')
    src_nbma = os.getenv('NHRP_SRCNBMA')
    # dest_addr = os.getenv('NHRP_DESTADDR')
    dest_nbma = os.getenv('NHRP_DESTNBMA')
    dest_mtu = os.getenv('NHRP_DESTMTU')
    logger.info('peer_up dmvpn_type=%s conn=%s src_nbma=%s dest_nbma=%s', dmvpn_type, conn, src_nbma, dest_nbma)

    if dest_mtu:
        add_peer_route(src_nbma, dest_nbma, dest_mtu)

    if conn and dmvpn_type == 'spoke' and process_named_running('charon'):
        logger.info('Start terminate tunnel')
        vici_terminate(conn, 'dmvpn', src_nbma, dest_nbma)
        logger.info('Start initiate new tunnel')
        vici_initiate(conn, 'dmvpn', src_nbma, dest_nbma)
    


def peer_down(dmvpn_type, conn):
    src_nbma = os.getenv('NHRP_SRCNBMA')
    dest_nbma = os.getenv('NHRP_DESTNBMA')
    logger.info('peer_down type=%s conn=%s src_nbma=%s dest_nbma=%s', dmvpn_type, conn, src_sbma, dest_nbma)

    if conn and dmvpn_type == 'spoke' and process_named_running('charon'):
        vici_terminate(conn, 'dmvpn', src_nbma, dest_nbma)

    cmd(f'sudo ip route del {dest_nbma} src {src_nbma} proto 42')


def route_up(interface):
    dest_addr = os.getenv('NHRP_DESTADDR')
    dest_prefix = os.getenv('NHRP_DESTPREFIX')
    next_hop = os.getenv('NHRP_NEXTHOP')
    logger.info('route_up dest_prefix=%s dest_addr=%s next_hop=%s interface=%s', dest_prefix, dest_addr, next_hop, interface)

    cmd(f'sudo ip route replace {dest_addr}/{dest_prefix} proto 42 \
        via {next_hop} dev {interface}')
    cmd('sudo ip route flush cache')


def route_down(interface):
    dest_addr = os.getenv('NHRP_DESTADDR')
    dest_prefix = os.getenv('NHRP_DESTPREFIX')
    logging.info('route_down dest_prefix=%s dest_addr=%s interface=%s', dest_prefix, dest_addr, interface)

    cmd(f'sudo ip route del {dest_addr}/{dest_prefix} proto 42')
    cmd('sudo ip route flush cache')

if __name__ == '__main__':
    action = sys.argv[1]
    interface = os.getenv('NHRP_INTERFACE')
    dmvpn_type, profile_name = parse_type_ipsec(interface)

    dmvpn_conn = None


    logger = logging.getLogger('opennhrp_script')
    logger.addHandler(JournalHandler())
    logger.setLevel(logging.INFO)

    if profile_name:
        dmvpn_conn = f'dmvpn-{profile_name}-{interface}'

    if action == 'interface-up':
        iface_up(interface)
    elif action == 'peer-register':
        pass
    elif action == 'peer-up':
        peer_up(dmvpn_type, dmvpn_conn)
    elif action == 'peer-down':
        peer_down(dmvpn_type, dmvpn_conn)
    elif action == 'route-up':
        route_up(interface)
    elif action == 'route-down':
        route_down(interface)
