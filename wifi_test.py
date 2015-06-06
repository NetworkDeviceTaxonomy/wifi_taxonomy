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
import dhcp
import wifi


class WifiTaxonomyTest(unittest.TestCase):

  def setUp(self):
    dhcp.DHCP_LEASES_FILE = 'testdata/dhcp.leases'
    dhcp.DHCP_SIGNATURE_FILE = 'testdata/dhcp.signatures'

  def testLookup(self):
    signature = ('wifi|probe:0,1,50,45,htcap:186e|'
                 'assoc:0,1,50,48,221(0050f2,2),45,127,htcap:086c')
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertEqual(taxonomy, 'RTL8192CU;;802.11n n:1,w:20')

    signature = (
        'wifi|probe:0,1,50,3,45,127,221(00904c,51),htcap:59ad|'
        'assoc:0,1,33,36,48,50,45,127,221(00904c,51),221(0050f2,2),htcap:59ad')
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    expected = 'BCM4360;MacBook Air or Pro - 2014;802.11n n:2,w:20'
    self.assertEqual(taxonomy, expected)

  def testNameLookup(self):
    signature = 'wifi|probe:0,1,3,50|assoc:0,1,48,50'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertIn(';Unknown;', taxonomy)
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertIn(';Unknown;', taxonomy)
    taxonomy = wifi.identify_wifi_device(signature, '2c:1f:23:ff:ff:01')
    self.assertIn(';iPod Touch 1st gen;', taxonomy)

  def testChecksumWhenNoIdentification(self):
    taxonomy = wifi.identify_wifi_device('wifi|probe:1,2,3,4,htcap:0|assoc:1',
                                         '00:00:01:00:00:01')
    h = 'SHA:27b78dbb1bc795961ddad0686137eb9fddbbc7f8766bd8947b4deca563b830be'
    self.assertIn(h, taxonomy)

  def testWpsRemoval(self):
    signature = 'wifi|probe:1,2,3,4,wps:Model_Name|assoc:1,2,3,wps:Foo,4'
    expected = 'wifi|probe:1,2,3,4|assoc:1,2,3,4'
    self.assertEqual(wifi.remove_wps(signature), expected)

  def testSimilarDevice(self):
    signature = ('wifi|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),'
                 'htcap:012c,wps:FooBar|assoc:0,1,48,45,221(0050f2,2),'
                 'htcap:012c')
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertEqual(taxonomy, 'QCA_WCN3360;Unknown;802.11n n:2,w:20')

  def testOUI(self):
    # Devices with the same Wifi signature, distinguished via MAC OUI
    signature = ('wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),'
                 '221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,'
                 '48,50,45,221(001018,2),221(0050f2,2),htcap:102d')
    taxonomy = wifi.identify_wifi_device(signature, 'f8:a9:d0:00:00:01')
    self.assertIn(';LG G2;', taxonomy)
    self.assertNotIn(';Samsung Galaxy S4;', taxonomy)
    taxonomy = wifi.identify_wifi_device(signature, 'cc:3a:61:00:00:01')
    self.assertNotIn(';LG G2;', taxonomy)
    self.assertIn(';Samsung Galaxy S4;', taxonomy)
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertIn(';Samsung Galaxy S4 or LG G2;', taxonomy)

  def testUnknown(self):
    signature = 'wifi|probe:0,1,2,vhtcap:0033|assoc:3,4,vhtcap:0033'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11ac' in taxonomy)
    self.assertFalse('802.11n' in taxonomy)
    self.assertFalse('802.11a/b/g' in taxonomy)
    signature = 'wifi|probe:0,1,2,htcap:0033|assoc:3,4,htcap:0033'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertFalse('802.11ac' in taxonomy)
    self.assertTrue('802.11n' in taxonomy)
    self.assertFalse('802.11a/b/g' in taxonomy)
    signature = 'wifi|probe:0,1,2|assoc:3,4'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertFalse('802.11ac' in taxonomy)
    self.assertFalse('802.11n' in taxonomy)
    self.assertTrue('802.11a/b/g' in taxonomy)

  def test802_11n_NssWidth(self):
    signature = 'wifi|probe:0|assoc:1,htcap:0000'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11n n:1,w:20' in taxonomy)
    signature = 'wifi|probe:0|assoc:1,htcap:0102'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11n n:2,w:40' in taxonomy)
    signature = 'wifi|probe:0|assoc:1,htcap:0200'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11n n:3,w:20' in taxonomy)
    signature = 'wifi|probe:0|assoc:1,htcap:0302'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11n n:4,w:40' in taxonomy)
    signature = 'wifi|probe:0|assoc:1'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11a/b/g' in taxonomy)

  def test802_11ac_Width(self):
    signature = 'wifi|probe:0|assoc:1,htcap:0302,vhtcap:00000000'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11ac n:4,w:80' in taxonomy)
    signature = 'wifi|probe:0|assoc:1,htcap:0200,vhtcap:00000004'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11ac n:3,w:160' in taxonomy)
    signature = 'wifi|probe:0|assoc:1,vhtcap:00000008'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11ac n:?,w:80+80' in taxonomy)
    signature = 'wifi|probe:0|assoc:1,vhtcap:0000000c'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11ac n:?,w:??' in taxonomy)

  def testBrokenNssWidth(self):
    """Test for broken client behavior.

    A few clients, notably Nexus 4 with Android 4.2,
    include a VHT Capabilities in their Probe even
    though they are not 802.11ac devices. Presumably
    the driver supports other chipsets which are.
    To work around this, taxonomy is only supposed to
    look at the Association for determining client
    performance characteristics.
    """
    signature = 'wifi|probe:0,htcap:0200,vhtcap:00000700|assoc:1,htcap:0200'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11n n:3,w:20' in taxonomy)

  def testCorruptFiles(self):
    signature = 'wifi|probe:0|assoc:1,htcap:this_is_not_a_number'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11n' in taxonomy)
    signature = 'wifi|probe:0|assoc:1,vhtcap:this_is_not_a_number'
    taxonomy = wifi.identify_wifi_device(signature, '00:00:01:00:00:01')
    self.assertTrue('802.11ac' in taxonomy)


if __name__ == '__main__':
  unittest.main()
