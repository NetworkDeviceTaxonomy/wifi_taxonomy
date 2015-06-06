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
    '1,33,3,6,15,26,28,51,58,59': 'android',
    '1,33,3,6,15,28,51,58,59': 'android',

    '1,121,33,3,6,12,15,26,28,51,54,58,59,119,252': 'chromeos',
    '1,121,33,3,6,12,15,26,28,51,54,58,59,119': 'chromeos',

    '1,3,6,15,119,252': 'ios',

    '1,3,6,15,119,95,252,44,46,101': 'macos',
    '1,3,6,15,119,95,252,44,46': 'macos',
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
          return database.get(signature, None)
  except IOError:
    pass
  return None


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
