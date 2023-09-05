# TLS-compliance-check
Identify corporate domains and check if TLS parameters are compliant to BSI TR-02102

## Checks
The following checks are implemented at the moment

Certificate:
* certificate is expired or not valid jet
* RSA key length is compliant
* EC key length is compliant
* EC curve is compliant

## Install

In `src` directory execute the following commands

```sh
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Usage
do not forget to enter venv before running the tool:

```sh
cd src
source venv/bin/activate
```

check a single server:
`python3 tls_compliance_check.py -ip 192.168.0.1`

check an IPv4 network segment:
`python3 tls_compliance_check.py -n 192.168.0.0/24`

check an IPv6 network segment:
`python3 tls_compliance_check.py -n6 2001:db00::0/120`

use `--help` to view all parameter options.