#! /usr/bin/env python3
'''
    TLS-Compliance-Check
    Copyright (C) 2023 Universitaetsklinikum Bonn AoeR

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import argparse
import logging
import sys
import ssl

from typing import cast
from ipaddress import ip_address, IPv4Network, IPv6Network, AddressValueError
from cryptography import x509
from cryptography.x509 import ExtensionOID, DNSName, ExtensionNotFound, NameOID
from helper.logging import setup_logging
from cryptography.x509.extensions import DuplicateExtension


PROGRAM_NAME = 'TLS-Compliance-Check'
PROGRAM_VERSION = '0.0.1'
PROGRAM_DESCRIPTION = 'Identify corporate domains and check if TLS parameters are compliant to BSI TR-02102'


def _setup_argparser():
    parser = argparse.ArgumentParser(description='{} - {}'.format(PROGRAM_NAME, PROGRAM_DESCRIPTION))
    parser.add_argument('-ip', '--ip_address', help='server IPv4 or IPv6 address', default=None)
    parser.add_argument('-n', '--IPv4_network', help='IPv4 Network e.g. "192.168.0.0/24"', default=None)
    parser.add_argument('-n6', '--IPv6_network', help='IPv6 Network e.g. "2001:db00::0/120"', default=None)
    parser.add_argument('-R', '--store_report_to', help='store report file to this location', default=None)
    parser.add_argument('-V', '--version', action='version', version='{} {}'.format(PROGRAM_NAME, PROGRAM_VERSION))
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
    parser.add_argument('-s', '--silent', action='store_true', default=False, help='disable console output')
    return parser.parse_args()


def get_common_names(certificate: x509.Certificate) -> list [str]:
    return [cn.value for cn in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]

def get_dns_alternative_names(certificate: x509.Certificate) -> list[str]:
    try:
        dns_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_ext_value = cast(x509.SubjectAlternativeName, dns_ext.value)
        return dns_ext_value.get_values_for_type(DNSName)
    except ExtensionNotFound:
        logging.warning('no dns alt names found')
    except DuplicateExtension:
        logging.error('more than on alternative name extension -> certificate is invalid')
    return []

def _check_server(server_address, default_port=443):
    logging.debug('checking server: {}'.format(server_address))
    port = default_port
    try:
        raw_cert = ssl.get_server_certificate((str(server_address), 443), timeout=5)
    except OSError:
        logging.debug('{} is not reachable'.format(server_address))
    except TimeoutError:
        logging.error('{} could not retrieve certificate on port {}'.format(server_address, port))
    server_cert = x509.load_pem_x509_certificate(raw_cert.encode('utf-8'))
    common_names = get_common_names(server_cert)
    dns_alt_names = get_dns_alternative_names(server_cert)
    logging.info('certificate found: CN={}; ALT_NAMES={}'.format(common_names, dns_alt_names))


if __name__ == '__main__':
    args = _setup_argparser()
    setup_logging(args.debug)

    if args.ip_address:
        try:
            server = ip_address(args.ip_address)
        except ValueError:
            logging.error('"{}" is not a valid ip address'.format(args.ip_address))
            sys.exit(1)
        _check_server(server)
    elif args.IPv4_network:
        try:
            subnet = IPv4Network(args.IPv4_network)
        except AddressValueError:
            logging.error('"{}" is not a valid network definition'.format(args.IPv4_network))
            sys.exit(1)
        logging.info('checking {} ip-addresses in subnet {}'.format(subnet.num_addresses-2, subnet.exploded))
        for server in subnet.hosts():
            _check_server(server)
    elif args.IPv6_network:
        try:
            subnet = IPv6Network(args.IPv6_network)
        except AddressValueError:
            logging.error('"{}" is not a valid network definition'.format(args.IPv6_network))
            sys.exit(1)
        logging.info('checking {} ip-addresses in subnet {}'.format(subnet.num_addresses-2, subnet.exploded))
        for server in subnet.hosts():
            _check_server(server)
    else:
        logging.error('No input given. You need to set "-ip", "-n" or "-n6" parameter. Use "-h" to get more details.')
        sys.exit(2)

    sys.exit()
