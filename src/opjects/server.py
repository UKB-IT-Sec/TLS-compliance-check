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

from helper.certificate import get_common_names, get_dns_alternative_names

class Server(object):

    common_name = str()
    dns_alt_names = list()

    def __init__(self, ip_address, x509_certificate):
        self.ip_address = ip_address
        self.certificate = x509_certificate
        self.common_name = get_common_names(self.certificate)
        self.dns_alt_names = get_dns_alternative_names(self.certificate)


    def get_all_dns_names(self):
        return set(self.common_name) | set(self.dns_alt_names)

    def get_key_size(self):
        logging.debug(self.certificate.public_key().public_numbers())
        return self.certificate.public_key().key_size


    def __repr__(self):
        return 'IP:{}; CN:{}; DNS_ALTNAMES:{}; key_size: {}'.format(self.ip_address, self.common_name, self.dns_alt_names, self.get_key_size())

    
    def __str__(self):
        return self.__repr__()
        