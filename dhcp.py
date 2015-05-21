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


def LookupHostname(mac):
  """Lookup the hostname for a MAC address."""
  mac = mac.lower()
  name = None
  with open(DHCP_LEASES_FILE) as f:
    for line in f:
      try:
        (unused_ts, physaddr, unused_ip, name, _) = line.split()
      except ValueError:
        # there are other formats of lines in dhcp.leases, like DUID.
        continue
      if physaddr.lower() == mac:
        return None if name == '*' else name
  return None
