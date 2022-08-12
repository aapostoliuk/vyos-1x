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
# import logging

# from systemd.journal import JournalHandler
from json import loads
from vyos.logger import getLogger

from vyos.util import cmd
from vyos.util import process_named_running

NHRP_CONFIG = "/run/opennhrp/opennhrp.conf"


def vici_get_ipsec_uniqueid(conn: str, src_nbma: str, dst_nbma: str) -> list:
    """ Find and return IKE SAs by src nbma and dst nbma

    Args:
        conn (str):
        src_nbma (str):
        dst_nbma (str):

    Returns: list

    """
    if conn and src_nbma and dst_nbma:
        try:
            session = vici.Session()
            list_ikeid = []
            list_sa = session.list_sas({'ike': conn})
            print('OK')
            for sa in list_sa:
                if sa[conn]["local-host"].decode('ascii') == src_nbma \
                        and sa[conn]["remote-host"].decode('ascii') == dst_nbma:
                    list_ikeid.append(sa[conn]["uniqueid"].decode('ascii'))
            return list_ikeid
        except Exception as e:
            print(f'Terminated {e}')
            return []
    else:
        print('Terminated')
        return []


def vici_ike_terminate(list_ikeid: list) -> bool:
    """ Terminating IKE SAs by list of IKE IDs

    Args:
        list_ikeid (list):

    Returns: bool

    """
    if list:
        try:
            session = vici.Session()
            for ikeid in list_ikeid:
                logs = session.terminate({'ike-id': ikeid, 'timeout': '-1'})
                logger.info("Tunnel id %s was terminated", ikeid)
                for log in logs:
                    message = log['msg'].decode('ascii')
                    print('INIT LOG:', message)
            return True
        except Exception as err:
            logger.info("Tunnel id %s not terminated", list_ikeid)
            print(f'{err}')
            return False
    else:
        logger.info("Nothing to terminate", list_ikeid)
        return False


def parse_type_ipsec(interface: str) -> tuple[str, str]:
    """ Get DMVPN Type and NHRP Profile

    Args:
        interface (str):

    Returns: tuple[str,str]

    """
    if interface:
        with open(NHRP_CONFIG, 'r') as f:
            lines = f.readlines()
            match = rf'^interface {interface} #(hub|spoke)(?:\s([\w-]+))?$'
            for line in lines:
                m = re.match(match, line)
                if m:
                    return m[1], m[2]
        return '', ''
    else:
        return '', ''


def add_peer_route(nbma_src: str, nbma_dst: str, mtu: str) -> None:
    """Add a route to a NBMA peer

    Args:
        nbma_src (str): a local IP address
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


def vici_initiate(conn: str, child_sa: str, src_addr: str, dest_addr: str) -> bool:
    """ Create IKE and IPSEC SAs

    Args:
        conn (str):
        child_sa (str):
        src_addr (str):
        dest_addr (str):

    Returns: bool

    """
    logger.info('Try to initiate connection %s with child sas %s src_addr:%s dst_addr:%s', conn, child_sa, src_addr,
                dest_addr)
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
    except Exception as err:
        print(f'Unable to initiate connection {err}')
        return False


def vici_terminate(conn: str, src_addr: str, dest_addr: str) -> None:
    """ Find and terminate Ike SAs by src nbma and dst nbma.

    Args:
        conn (str): _description_
        src_addr (str): _description_
        dest_addr (str): _description_
    """
    ikeid_list = vici_get_ipsec_uniqueid(conn, src_addr, dest_addr)

    if not ikeid_list:
        logger.info('Nothing terminate')
    else:
        vici_ike_terminate(ikeid_list)


def iface_up(interface: str) -> None:
    """ Interface UP

    Args:
        interface (str):
    """
    logger.info('iface_up %s', interface)
    if interface:
        try:
            cmd(f'sudo ip route flush proto 42 dev {interface}')
            cmd(f'sudo ip neigh flush dev {interface}')
        except Exception as err:
            print(f'Unable to flush route on interface "{interface}": \
                    {err}')


def peer_up(dmvpn_type: str, conn: str) -> None:
    """ NHRP peer UP functions

    Args:
        dmvpn_type (str):
        conn (str):
    """
    src_nbma = os.getenv('NHRP_SRCNBMA')
    dest_nbma = os.getenv('NHRP_DESTNBMA')
    dest_mtu = os.getenv('NHRP_DESTMTU')
    if (src_nbma is not None) and (dest_nbma is not None):
        logger.info('peer_up dmvpn_type=%s conn=%s src_nbma=%s dest_nbma=%s', dmvpn_type, conn, src_nbma, dest_nbma)
        if dest_mtu:
            add_peer_route(src_nbma, dest_nbma, dest_mtu)
        if conn and dmvpn_type == 'spoke' and process_named_running('charon'):
            logger.info('Start terminate tunnel')
            vici_terminate(conn, src_nbma, dest_nbma)
            logger.info('Start initiate new tunnel')
            vici_initiate(conn, 'dmvpn', src_nbma, dest_nbma)
    else:
        logger.info('Can not get NHRP NBMA addresses')


def peer_down(dmvpn_type: str, conn: str) -> None:
    """ NHRP Peer Down functions

    Args:
        dmvpn_type (str):
        conn (str):
    """
    src_nbma = os.getenv('NHRP_SRCNBMA')
    dest_nbma = os.getenv('NHRP_DESTNBMA')
    if (src_nbma is not None) and (dest_nbma is not None):
        logger.info('peer_down type=%s conn=%s src_nbma=%s dest_nbma=%s', dmvpn_type, conn, src_nbma, dest_nbma)
        if conn and dmvpn_type == 'spoke' and process_named_running('charon'):
            vici_terminate(conn, src_nbma, dest_nbma)
        try:
            cmd(f'sudo ip route del {dest_nbma} src {src_nbma} proto 42')
        except Exception as err:
            print(f'Unable to del route {err}')
    else:
        logger.info('Can not get NHRP NBMA addresses')


def route_up(interface: str) -> None:
    """ Route UP

    Args:
        interface (str):
    """
    dest_addr = os.getenv('NHRP_DESTADDR')
    dest_prefix = os.getenv('NHRP_DESTPREFIX')
    next_hop = os.getenv('NHRP_NEXTHOP')
    if (dest_addr is not None) and (dest_prefix is not None) and (next_hop is not None):
        logger.info('route_up dest_prefix=%s dest_addr=%s next_hop=%s interface=%s', dest_prefix, dest_addr, next_hop,
                    interface)
        try:
            cmd(f'sudo ip route replace {dest_addr}/{dest_prefix} proto 42 \
                    via {next_hop} dev {interface}')
            cmd('sudo ip route flush cache')
        except Exception as err:
            print(f'Unable replace or flush route {err}')
    else:
        logger.info('Can not get NHRP NBMA addresses or next_hop')


def route_down(interface: str) -> None:
    """Route Down

    Args:
        interface (str):
    """
    dest_addr = os.getenv('NHRP_DESTADDR')
    dest_prefix = os.getenv('NHRP_DESTPREFIX')
    if (dest_addr is not None) and (dest_prefix is not None):
        logger.info('route_down dest_prefix=%s dest_addr=%s interface=%s', dest_prefix, dest_addr, interface)
        try:
            cmd(f'sudo ip route del {dest_addr}/{dest_prefix} proto 42')
            cmd('sudo ip route flush cache')
        except Exception as err:
            print(f'Unable delete or flush route {err}')
    else:
        logger.info('Can not get NHRP NBMA address or prefix')


if __name__ == '__main__':
    action = sys.argv[1]
    logger = getLogger('opennhrp-script', syslog=True)
    interface = os.getenv('NHRP_INTERFACE')
    logger.info('ARGS: %s, OS ENV: %s', sys.argv, os.environ)
    if interface is not None:
        dmvpn_type, profile_name = parse_type_ipsec(interface)
        dmvpn_conn = None
        if dmvpn_type:
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
        else:
            logger.info('Can not get DMVPN TYPE')
    else:
        logger.info('Can not get NHRP interface')
