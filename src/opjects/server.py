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
    get_key_size, get_key_type, get_curve


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
            self.problems['certificate']['not_valid'] = 'certificate not valid yet: {}'.format(self.certificate.not_valid_before)
        if self.certificate.not_valid_after < current_time:
            self.problems['certificate']['not_valid'] = 'certificate expired: {}'.format(self.certificate.not_valid_after)
    
    
    def check_key_compliance(self, compliance_db):
        try:
            if self.key_size <= compliance_db['Certificate']['KeyComplexity'][self.key_type]:
                self.problems['certificate']['key_length'] = 'key length to small: {} bit < {} bit (mandatory)'.format(self.key_size, compliance_db['Certificate']['KeyComplexity'][self.key_type])
        except KeyError:
            logging.error('key type not supported')

    def check_curve(self, compliance_db):
        if self.key_type == 'EC':
            curve = get_curve(self.certificate)
            if not curve in compliance_db['Certificate']['AllowedCurves']:
                self.problems['certificate']['curve'] = 'curve is not allowed: {}'.format(curve)


    def is_compliant(self):
        return len(self.problems['certificate']) == 0 and len(self.problems['tls_parameter']) == 0


    def generate_txt_report(self):
        header = 'Results for {} - {}\n'.format(self.ip_address, self.common_name)
        dns_alt_names = 'DNS alternative names: {}\n'.format('; '.join(self.dns_alt_names))
        if self.is_compliant():
            compliant = 'Server is compliant'
        else:
            problems = 'Certificate: \n'
            for problem in self.problems['certificate']:
                problems += '- {}\n'.format(self.problems['certificate'][problem])
            compliant = 'Server is not compliant because of the following problems: \n{}'.format(problems)
            
        return header + dns_alt_names + compliant


    def __repr__(self):
        return 'IP:{}; CN:{}; DNS_ALTNAMES:{}; key: {} {} bit; expire: {}'.format(self.ip_address, self.common_name, self.dns_alt_names, self.key_type, self.key_size, self.certificate.not_valid_after)

    
    def __str__(self):
        return self.__repr__()
        