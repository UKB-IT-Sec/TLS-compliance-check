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
import json

from pathlib import Path


def get_compliance_ruleset_folder():
    src_folder = Path(__file__).parent.parent.resolve()
    return src_folder / Path('rulesets')


def load_compliance_database(compliance_file_path: Path) -> dict:
    with open(compliance_file_path, 'r') as compliance_file:
        compliance_db = json.load(compliance_file)
    return compliance_db
        