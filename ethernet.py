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
    '30:85:a9': 'asus',
    'ac:22:0b': 'asus',

    '9c:d9:17': 'motorola',
    'f8:e0:79': 'motorola',

    '10:68:3f': 'lg',
    '40:b0:fa': 'lg',
    'c4:43:8f': 'lg',
    'c4:9a:02': 'lg',
    'f8:a9:d0': 'lg',

    '18:b4:30': 'nest',

    '10:a5:d0': 'samsung',
    '14:7d:c5': 'samsung',
    '38:aa:3c': 'samsung',
    '40:0e:85': 'samsung',
    '5c:0a:5b': 'samsung',
    '90:e7:c4': 'samsung',
    'c0:bd:d1': 'samsung',
    'c4:42:02': 'samsung',
    'cc:3a:61': 'samsung',
    'd0:22:be': 'samsung',
    'e8:50:8b': 'samsung',
    'f0:25:b7': 'samsung',
    'f4:09:d8': 'samsung',
}


def LookupOUI(mac):
  """Lookup manufacturer from a MAC address."""
  mac = mac.lower().split(':')
  oui = ':'.join(mac[0:3])
  return database.get(oui, None)
