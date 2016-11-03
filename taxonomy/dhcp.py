#!/usr/bin/python
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# pylint: disable=line-too-long

"""Routines for handling DHCP signature information.
"""

# Unit tests can override these.
DHCP_LEASES_FILE = '/config/dhcp.leases'
DHCP_SIGNATURE_FILE = '/config/dhcp.fingerprints'


# There is an enormous database of DHCP fingerprints at fingerbank.org.
# It is a 15 MByte SQLite DB. Thus far we're only using the DHCP
# signature as an additive when wifi signatures are indistinct, so
# we're only including the DHCP signatures which we will actually use.
database = {
    '1,33,3,6,15,26,28,51,58,59': ['android'],
    '1,33,3,6,15,28,51,58,59': ['android'],
    '1,3,6,28,33,51,58,59,121': ['android'],
    '1,121,33,3,6,15,28,51,58,59,119': ['android'],
    '1,3,6,15,26,28,51,58,59,43': ['android'],

    '1,3,6,15,112,113,78,79,95,252': ['appletv1'],

    '6,3,1,15,66,67,13,44,2,42,12': ['brotherprinter'],

    '1,3,6,15,44,47': ['canonprinter'],

    '1,121,33,3,6,12,15,26,28,51,54,58,59,119,252': ['chromeos'],
    '1,121,33,3,6,12,15,26,28,51,54,58,59,119': ['chromeos'],

    '1,3,6': ['dashbutton', 'canonprinter'],

    '1,3,6,28': ['ecobee', 'canonprinter'],

    '1,3,6,12,15,17,28,40,41,42': ['epsonprinter'],

    '6,3,1,15,66,67,13,44': ['hpprinter'],
    '6,3,1,15,66,67,13,44,12': ['hpprinter'],
    '6,3,1,15,66,67,13,44,12,81': ['hpprinter'],
    '6,3,1,15,66,67,13,44,119,12,81,252': ['hpprinter'],
    '6,3,1,15,66,67,13,44,12,81,252': ['hpprinter'],

    '1,3,6,15,119,252': ['ios'],
    '1,121,3,6,15,119,252': ['ios'],

    '1,3,6,15,119,95,252,44,46,47': ['ipodtouch1'],

    '252,3,42,15,6,1,12': ['lgtv', 'tizen'],
    '252,3,42,6,1,12': ['tizen'],

    '1,3,6,15,119,95,252,44,46,101': ['macos'],
    '1,3,6,15,119,95,252,44,46': ['macos'],
    '1,121,3,6,15,119,252,95,44,46': ['macos'],

    '58,59,6,15,51,54,1,3': ['panasonictv'],

    '1,3,15,6': ['playstation'],

    '1,3,6,15,12': ['roku'],

    '1,3,6,12,15,28,42,125': ['samsungtv'],

    '1,28,2,3,15,6,12': ['tivo'],

    '1,3,6,12,15,28,42': ['viziotv', 'wemo', 'directv', 'samsungtv'],
    '1,3,6,12,15,28,40,41,42': ['viziotv', 'kindle'],
    '1,3,6,12,15,17,23,28,29,31,33,40,41,42': ['viziotv'],

    '1,3,6,15,28,33': ['wii'],
    '1,3,6,15': ['wii', 'xbox'],

    '1,15,3,6,44,46,47,31,33,121,249,252,43': ['windows-phone', 'windows'],
    '1,3,6,15,31,33,43,44,46,47,121,249,252': ['windows'],
}


def LookupOperatingSystem(mac):
  """Lookup the operating system using a DHCP signature."""
  mac = mac.lower()
  try:
    with open(DHCP_SIGNATURE_FILE) as f:
      for line in f:
        try:
          (physaddr, signature) = line.split()
        except ValueError:
          continue
        if physaddr.lower() == mac:
          return database.get(signature, [])
  except IOError:
    pass
  return []


def LookupHostname(mac):
  """Lookup the hostname for a MAC address."""
  mac = mac.lower()
  try:
    with open(DHCP_LEASES_FILE) as f:
      for line in f:
        try:
          (_, physaddr, _, name, _) = line.split()
        except ValueError:
          # There are other formats of lines in dhcp.leases, like DUID.
          continue
        if physaddr.lower() == mac:
          return None if name == '*' else name
  except IOError:
    pass
  return None
