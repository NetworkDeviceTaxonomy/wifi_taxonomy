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

"""Tests for taxonomy/wifi.py."""

__author__ = 'dgentry@google.com (Denton Gentry)'


import unittest
import wifi


class WifiTaxonomyTest(unittest.TestCase):

  def testLookup(self):
    signature = ('wifi|probe:0,1,50,45,htcap:186e|'
                 'assoc:0,1,50,48,221(0050f2,2),45,127,htcap:086c')
    taxonomy = wifi.identify_wifi_device(signature)
    self.assertEqual(taxonomy, 'RTL8192CU;')

    signature = (
        'wifi|probe:0,1,50,3,45,127,221(00904c,51),htcap:59ad|'
        'assoc:0,1,33,36,48,50,45,127,221(00904c,51),221(0050f2,2),htcap:59ad')
    taxonomy = wifi.identify_wifi_device(signature)
    self.assertEqual(taxonomy, 'BCM4360;MacBook Air or Pro - 2014')

  def testChecksumWhenNoIdentification(self):
    taxonomy = wifi.identify_wifi_device('wifi|probe:1,2,3,4,htcap:0|assoc:1')
    h = ('SHA:27b78dbb1bc795961ddad0686137eb9fddbbc7f8766bd8947b4deca563b830be'
         ';Unknown')
    self.assertEqual(taxonomy, h)

  def test80211abg(self):
    taxonomy = wifi.identify_wifi_device('wifi|probe:1|assoc:1')
    self.assertEqual(taxonomy, 'Unknown;802.11a/b/g device')

  def testWpsRemoval(self):
    signature = 'wifi|probe:1,2,3,4,wps:Model_Name|assoc:1,2,3,wps:Foo,4'
    expected = 'wifi|probe:1,2,3,4|assoc:1,2,3,4'
    self.assertEqual(wifi.remove_wps(signature), expected)

  def testSimilarDevice(self):
    signature = ('wifi|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),'
                 'htcap:012c,wps:FooBar|assoc:0,1,48,45,221(0050f2,2),'
                 'htcap:012c')
    taxonomy = wifi.identify_wifi_device(signature)
    self.assertEqual(taxonomy, 'QCA_WCN3360;Unknown')


if __name__ == '__main__':
  unittest.main()
