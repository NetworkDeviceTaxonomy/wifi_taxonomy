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

"""Routines for handling Ethernet OUI information.
"""

# The IEEE publishes an enormous list of registered Ethernet OUIs,
# but we don't benefit from having that entire list here. Instead
# we track the OUIs which let us distinguish devices which are
# otherwise very similar, such as distinguishing LG G2 from Samsung
# Galaxy S4.
database = {
    'f8:a9:d0': 'lg',

    '18:b4:30': 'nest',

    '10:a5:d0': 'samsung',
    '14:7d:c5': 'samsung',
    '5c:0a:5b': 'samsung',
    'c0:bd:d1': 'samsung',
    'c4:42:02': 'samsung',
    'cc:3a:61': 'samsung',
}


def LookupOUI(mac):
  """Lookup manufacturer from a MAC address."""
  mac = mac.lower().split(':')
  oui = ':'.join(mac[0:3])
  return database.get(oui, None)
