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
    'f0:a2:25': 'amazon',

    '30:85:a9': 'asus',
    '5c:ff:35': 'asus',
    'ac:22:0b': 'asus',

    '00:23:76': 'htc',
    '1c:b0:94': 'htc',
    '38:e7:d8': 'htc',
    '50:2e:5c': 'htc',
    '7c:61:93': 'htc',
    '90:e7:c4': 'htc',
    'e8:99:c4': 'htc',

    '10:68:3f': 'lg',
    '40:b0:fa': 'lg',
    'c4:43:8f': 'lg',
    'c4:9a:02': 'lg',
    'f8:a9:d0': 'lg',

    '60:45:bd': 'microsoft',

    '98:4b:4a': 'motorola',
    '9c:d9:17': 'motorola',
    'f8:7b:7a': 'motorola',
    'f8:cf:c5': 'motorola',
    'f8:e0:79': 'motorola',

    '18:b4:30': 'nest',

    '10:a5:d0': 'samsung',
    '14:7d:c5': 'samsung',
    '38:aa:3c': 'samsung',
    '40:0e:85': 'samsung',
    '5c:0a:5b': 'samsung',
    '6c:2f:2c': 'samsung',
    '8c:77:12': 'samsung',
    '90:b6:86': 'samsung',
    '90:e7:c4': 'samsung',
    'a0:0b:ba': 'samsung',
    'c0:bd:d1': 'samsung',
    'c4:42:02': 'samsung',
    'cc:3a:61': 'samsung',
    'd0:22:be': 'samsung',
    'e8:50:8b': 'samsung',
    'f0:25:b7': 'samsung',
    'f4:09:d8': 'samsung',

    '30:17:c8': 'sony',
    '40:b8:37': 'sony',
    'b4:52:7e': 'sony',
}


def LookupOUI(mac):
  """Lookup manufacturer from a MAC address."""
  mac = mac.lower().split(':')
  oui = ':'.join(mac[0:3])
  return database.get(oui, None)
