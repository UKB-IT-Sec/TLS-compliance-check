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

import logging

from typing import cast
from cryptography import x509
from cryptography.x509 import ExtensionOID, DNSName, ExtensionNotFound, NameOID
from cryptography.x509.extensions import DuplicateExtension


def get_common_names(certificate: x509.Certificate) -> list [str]:
    return [cn.value for cn in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]


def get_dns_alternative_names(certificate: x509.Certificate) -> list[str]:
    try:
        dns_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_ext_value = cast(x509.SubjectAlternativeName, dns_ext.value)
        return dns_ext_value.get_values_for_type(DNSName)
    except ExtensionNotFound:
        logging.debug('no dns alt names found')
    except DuplicateExtension:
        logging.error('more than on alternative name extension -> certificate is invalid')
    return []
