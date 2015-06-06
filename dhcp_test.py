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

"""Tests for taxonomy/dhcp.py."""

__author__ = 'dgentry@google.com (Denton Gentry)'


import unittest
import dhcp


class DhcpTaxonomyTest(unittest.TestCase):

  def setUp(self):
    dhcp.DHCP_LEASES_FILE = 'testdata/dhcp.leases'
    dhcp.DHCP_SIGNATURE_FILE = 'testdata/dhcp.signatures'

  def testLookupName(self):
    self.assertEqual(dhcp.LookupHostname('28:18:78:ff:ff:01'), 'Xbox-SystemOS')
    self.assertEqual(dhcp.LookupHostname('28:18:78:FF:FF:01'), 'Xbox-SystemOS')
    self.assertEqual(dhcp.LookupHostname('00:00:00:00:00:01'), None)
    self.assertEqual(dhcp.LookupHostname('d8:50:e6:ff:ff:02'), None)

  def testLookupOperatingSystem(self):
    self.assertEqual(dhcp.LookupOperatingSystem('28:18:78:ff:ff:01'), 'android')
    self.assertEqual(dhcp.LookupOperatingSystem('00:00:00:00:00:01'), None)


if __name__ == '__main__':
  unittest.main()
