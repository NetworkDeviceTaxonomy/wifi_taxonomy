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

"""Routines for handling SSDP information.
"""

import hashlib


database = {
    'OpenRG/6.0.7.1.4 UPnP/1.0': 'Google Fiber GFRG1x0',
    'HDHomeRun/1.0 UPnP/1.0': 'HDHomeRun',
    'Linux UPnP/1.0 Sonos/28.1-83040 (ZP90)': 'Sonos ZP90',
    'Linux UPnP/1.0 Sonos/28.1-83040 (ZP120)': 'Sonos ZP120',
    'WNDR3700v2 UPnP/1.0 miniupnpd/1.0': 'Netgear WNDR3700',
    'Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0': 'Windows XP',
}


def describe_ssdp_device(signature):
  """Lookup device type from an SSDP server string.

  Returns:
    the string model name of the device if known, or an SHA256
    checksum of the signature if not known.
  """
  if not signature:
    return ''
  return database.get(signature, 'SHA:' + hashlib.sha256(signature).hexdigest())
