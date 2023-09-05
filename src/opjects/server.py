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

from datetime import datetime

from helper.certificate import get_common_names, get_dns_alternative_names,\
    get_key_size, get_key_type


class Server(object):

    problems = {'certificate': dict(), 'tls_parameter': dict()}

    def __init__(self, ip_address, x509_certificate):
        self.ip_address = ip_address
        self.certificate = x509_certificate
        self.common_name = get_common_names(self.certificate)
        self.dns_alt_names = get_dns_alternative_names(self.certificate)
        self.key_type = get_key_type(self.certificate)
        self.key_size = get_key_size(self.certificate)


    def check_dates(self):
        current_time = datetime.now()
        if self.certificate.not_valid_before > current_time:
            logging.error('Certificate is not valid before: {}'.format(self.certificate.not_valid_before))
            self.problems['certificate']['not_valid'] = 'not valid yet: {}'.format(self.certificate.not_valid_before)
        if self.certificate.not_valid_after < current_time:
            logging.error('Certificate is no longer valid: {}'.format(self.certificate.not_valid_after))
            self.problems['certificate']['not_valid'] = 'expired: {}'.format(self.certificate.not_valid_after)
    
    
    def check_key_compliance(self, compliance_db):
        try:
            if self.key_size <= compliance_db['Certificate']['KeyComplexity'][self.key_type]:
                logging.error('key size not compliant: {}'.format(self.key_size))
                self.problems['certificate']['key_length'] = '{} bit < {} bit (mandatory)'.format(self.key_size, compliance_db['Certificate']['KeyComplexity'][self.key_type])
        except KeyError:
            logging.error('key type not supported')
        

    def get_all_dns_names(self):
        return set(self.common_name) | set(self.dns_alt_names)


    def __repr__(self):
        return 'IP:{}; CN:{}; DNS_ALTNAMES:{}; key: {} {} bit; expire: {}'.format(self.ip_address, self.common_name, self.dns_alt_names, self.key_type, self.key_size, self.certificate.not_valid_after)

    
    def __str__(self):
        return self.__repr__()
        