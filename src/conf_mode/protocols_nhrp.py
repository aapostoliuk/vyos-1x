#!/usr/bin/env python3
#
# Copyright (C) 2021-2024 VyOS maintainers and contributors
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

from vyos.config import Config
from vyos.configdict import node_changed
from vyos.template import render_to_string
from vyos.template import render
from vyos.utils.process import run
from vyos.utils.dict import dict_search
from vyos import ConfigError
from vyos import airbag
from vyos import frr
airbag.enable()

nflog_redirect = 1
nflog_multicast = 2
nhrp_nftables_conf = '/run/nftables_nhrp.conf'


def get_config(config=None):
    if config:
        conf = config
    else:
        conf = Config()
    base = ['protocols', 'nhrp']

    nhrp = conf.get_config_dict(base, key_mangling=('-', '_'),
                                get_first_key=True, no_tag_node_value_mangle=True)
    interfaces_removed = node_changed(conf, base + ['tunnel'])
    if interfaces_removed:
        nhrp['interface_removed'] = list(interfaces_removed)

    if not conf.exists(base):
        # If nhrp instance is deleted then mark it
        nhrp.update({'deleted' : ''})
        return nhrp
    nhrp = conf.merge_defaults(nhrp, recursive=True)

    for intf, intf_config in nhrp['tunnel'].items():
        if 'multicast' in intf_config:
            nhrp['multicast'] = nflog_multicast
        if 'redirect' in intf_config:
            nhrp['redirect'] = nflog_redirect

    nhrp['if_tunnel'] = conf.get_config_dict(['interfaces', 'tunnel'], key_mangling=('-', '_'),
                                get_first_key=True, no_tag_node_value_mangle=True)

    nhrp['profile_map'] = {}
    profile = conf.get_config_dict(['vpn', 'ipsec', 'profile'], key_mangling=('-', '_'),
                                get_first_key=True, no_tag_node_value_mangle=True)

    for name, profile_conf in profile.items():
        if 'bind' in profile_conf and 'tunnel' in profile_conf['bind']:
            interfaces = profile_conf['bind']['tunnel']
            if isinstance(interfaces, str):
                interfaces = [interfaces]
            for interface in interfaces:
                if dict_search(f'tunnel.{interface}',nhrp):
                    nhrp['tunnel'][interface]['security_profile'] = name
    return nhrp


def verify(nhrp):
    if not nhrp or 'deleted' in nhrp:
        return None
    if 'tunnel' in nhrp:
        for name, nhrp_conf in nhrp['tunnel'].items():
            if not nhrp['if_tunnel'] or name not in nhrp['if_tunnel']:
                raise ConfigError(f'Tunnel interface "{name}" does not exist')

            tunnel_conf = nhrp['if_tunnel'][name]

            if 'encapsulation' not in tunnel_conf or tunnel_conf['encapsulation'] != 'gre':
                raise ConfigError(f'Tunnel "{name}" is not an mGRE tunnel')

            if 'remote' in tunnel_conf:
                raise ConfigError(f'Tunnel "{name}" cannot have a remote address defined')

            map_tunnelip = dict_search('map.tunnel_ip', nhrp_conf)
            if map_tunnelip:
                for map_name, map_conf in map_tunnelip.items():
                    if 'nbma' not in map_conf:
                        raise ConfigError(f'nbma-address missing on map {map_name} on tunnel {name}')
            map_tunnelip = dict_search('nhs.tunnel_ip', nhrp_conf)
            if map_tunnelip:
                for map_name, map_conf in map_tunnelip.items():
                    if 'nbma' not in map_conf:
                        raise ConfigError(f'nbma-address missing on map nhs {map_name} on tunnel {name}')
    return None


def generate(nhrp):
    if not nhrp or 'deleted' in nhrp:
        return None
    render(nhrp_nftables_conf, 'frr/nhrpd_nftables.conf.j2', nhrp)
    nhrp['frr_nhrpd_config'] = render_to_string('frr/nhrpd.frr.j2', nhrp)
    return None


def apply(nhrp):
    nhrp_daemon = 'nhrpd'

    nft_rc = run(f'nft --file {nhrp_nftables_conf}')
    if nft_rc != 0:
        raise ConfigError('Failed to apply NHRP tunnel firewall rules')

    # Save original configuration prior to starting any commit actions
    frr_cfg = frr.FRRConfig()

    frr_cfg.load_configuration(nhrp_daemon)

    frr_cfg.modify_section(r'^nhrp .*')

    for key in ['tunnel', 'interface_removed']:
        if key not in nhrp:
            continue
        for interface in nhrp[key]:
            frr_cfg.modify_section(f'^interface {interface}', stop_pattern='^exit', remove_stop_mark=True)

    if 'frr_nhrpd_config' in nhrp:
        frr_cfg.add_before(frr.default_add_before, nhrp['frr_nhrpd_config'])

    frr_cfg.commit_configuration(nhrp_daemon)

    return None


if __name__ == '__main__':
    try:
        c = get_config()
        verify(c)
        generate(c)
        apply(c)
    except ConfigError as e:
        print(e)
        exit(1)
