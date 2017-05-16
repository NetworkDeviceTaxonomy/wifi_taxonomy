#!/usr/bin/python
# Copyright 2016 Google Inc. All Rights Reserved.
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

import dhcp
import glob
import os.path
import subprocess
import sys
import wifi

regression = [
  # devices for which we have a pcap but have decided not to add
  # to the database
  ('', './testdata/pcaps/ASUS Transformer TF300 2.4GHz.pcap'),
  ('', './testdata/pcaps/Blackberry Bold 9930 2.4GHz GFRG210 Specific Probe.pcap'),
  ('', './testdata/pcaps/Blackberry Bold 9930 5GHz GFRG210 Specific Probe.pcap'),
  ('', './testdata/pcaps/HTC Evo 2.4GHz.pcap'),
  ('', './testdata/pcaps/HTC Incredible 2.4GHz.pcap'),
  ('', './testdata/pcaps/HTC Inspire 2.4GHz.pcap'),
  ('', './testdata/pcaps/HTC Sensation 2.4GHz.pcap'),
  ('', './testdata/pcaps/HTC Thunderbolt 2.4GHz.pcap'),
  ('', './testdata/pcaps/HTC Titan 2.4GHz.pcap'),
  ('', './testdata/pcaps/iPad Mini 4th gen 5GHz MK6L2LL Broadcast Probe.pcap'),
  ('', './testdata/pcaps/iPad Mini 4th gen 5GHz MK6L2LL Specific Probe.pcap'),
  ('', './testdata/pcaps/Lenovo_T440_80211ac_2x2_Windows8_2_4_GHz.pcap'),
  ('', './testdata/pcaps/LG E900 2.4GHz.pcap'),
  ('', './testdata/pcaps/LG G2X 2.4GHz.pcap'),
  ('', './testdata/pcaps/LG Revolution 2.4GHz.pcap'),
  ('', './testdata/pcaps/MediaTek MT7610U 2.4GHz.pcap'),
  ('', './testdata/pcaps/MacBook Air late 2014 (A1466) 5GHz.pcap'),
  ('', './testdata/pcaps/MacBook Pro early 2014 (A1502) 2.4GHz.pcap'),
  ('', './testdata/pcaps/MacBook Air late 2014 (A1466) 2.4GHz.pcap'),
  ('', './testdata/pcaps/MacBook Air late 2010 (A1369) 2.4GHz.pcap'),
  ('', './testdata/pcaps/MacBook Pro early 2014 (A1502) 5GHz.pcap'),
  ('', './testdata/pcaps/MacBook Air late 2010 (A1369) 5GHz.pcap'),
  ('', './testdata/pcaps/Motorola Droid 2 2.4GHz.pcap'),
  ('', './testdata/pcaps/Motorola Droid 3 2.4GHz.pcap'),
  ('', './testdata/pcaps/Motorola Droid Razr 2.4GHz XT910 Broadcast Probe.pcap'),
  ('', './testdata/pcaps/Motorola Droid Razr 2.4GHz XT910 Specific Probe.pcap'),
  ('', './testdata/pcaps/Motorola Droid Razr 2.4GHz XT910.pcap'),
  ('', './testdata/pcaps/Motorola Droid Razr 5GHz XT910.pcap'),
  ('', './testdata/pcaps/Motorola Droid Razr Maxx 2.4GHz.pcap'),
  ('', './testdata/pcaps/Nexus One 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Charge 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Captivate 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Continuum 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Epic 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Exhibit 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Fascinate 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Galaxy Tab 2 2.4GHz.pcap'),
  ('', './testdata/pcaps/Samsung Galaxy 4G 2.4GHz SGH-T959V.pcap'),
  ('', './testdata/pcaps/Samsung Infuse 5GHz.pcap'),
  ('', './testdata/pcaps/Samsung Vibrant 2.4GHz.pcap'),
  ('', './testdata/pcaps/Sony Ericsson Xperia X10 2.4GHz.pcap'),
  ('', './testdata/pcaps/Sony NSX-48GT1 2.4GHz Broadcast Probe.pcap'),
  ('', './testdata/pcaps/Sony NSX-48GT1 2.4GHz Specific Probe.pcap'),

  # Names where the identified species doesn't exactly match the filename,
  # usually because multiple devices are too similar to distinguish. We name
  # the file for the specific device which was captured, and add an entry
  # here for the best identification which we can manage.
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Paperwhite 2012 2.4GHz B024.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Voyage 2.4GHz B013.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Voyage 2.4GHz B054.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz Google Wifi OS 4.1.3 SN 9203 Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz Google Wifi OS 4.1.3 SN 9203 Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz Google Wifi OS 4.1.3 SN B00E Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz Google Wifi OS 4.1.3 SN B00E Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz GFRG210 OS 4.1.3 SN 9203.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz GFRG210 OS 4.1.3 SN B00E.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz OnHub OS 4.1.3 SN B00E Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz OnHub OS 4.1.3 SN B00E Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz OnHub OS 4.1.3 SN B00E Broadcast Probe #2.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz OnHub OS 4.1.3 SN B00E Specific Probe #2.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz OnHub OS 4.1.3 SN 9203 Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz OnHub OS 4.1.3 SN 9203 Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz WNDR3800 OS 4.1.3 SN 9203 Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz WNDR3800 OS 4.1.3 SN 9203 Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz WNDR3800 OS 4.1.3 SN B00E Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle 4 2.4GHz WNDR3800 OS 4.1.3 SN B00E Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz OnHub OS 5.3.7.3 SN B011 Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz OnHub OS 5.3.7.3 SN B011 Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz WNDR3800 OS 5.3.7.3 SN B011 Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz WNDR3800 OS 5.3.7.3 SN B011 Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz GFRG210 OS 5.3.7.3 SN B011 Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz GFRG210 OS 5.3.7.3 SN B011 Specific Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz Google Wifi OS 5.3.7.3 SN B011 Broadcast Probe.pcap'),
  ('Amazon Kindle', './testdata/pcaps/Amazon Kindle Touch 2.4GHz Google Wifi OS 5.3.7.3 SN B011 Specific Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 1st gen 5GHz GFRG210 iOS5.1.1 MB292LL Specific Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 2nd gen 5GHz GFRG210 iOS9.3.5 FC979LL Specific Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 2nd gen 5GHz Google Wifi iOS9.3.5 FC979LL Specific Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 1st gen 5GHz OnHub iOS5.1.1 MB292LL Broadcast Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 1st gen 5GHz Google Wifi iOS5.1.1 MB292LL Broadcast Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 2nd gen 5GHz OnHub iOS9.3.5 FC979LL Broadcast Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 2nd gen 5GHz OnHub iOS9.3.5 FC979LL Specific Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 2nd gen 5GHz GFRG210 iOS9.3.5 FC979LL Broadcast Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 1st gen 5GHz GFRG210 iOS5.1.1 MB292LL Broadcast Probe.pcap'),
  ('iPad 1st or 2nd gen', './testdata/pcaps/iPad 2nd gen 5GHz Google Wifi iOS9.3.5 FC979LL Broadcast Probe.pcap'),
  ('iPhone 6/6+', './testdata/pcaps/iPhone 6 5GHz GFRG210 iOS 9 MG552LL.pcap'),
  ('iPhone 6/6+', './testdata/pcaps/iPhone 6+ 5GHz iOS 9.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 5GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz RRM.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz MKRD2LL iOS 10.0.2 Specific Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz iOS 10.0.2 Broadcast Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz iOS 10.0.2 Specific Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 5GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 5GHz RRM.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz GFRG210 iOS10.2 MKRD2LL Broadcast Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz GFRG210 iOS10.2 MKRD2LL Specific Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz OnHub iOS10.2 MKRD2LL Broadcast Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz Google Wifi iOS10.2 MKRD2LL Broadcast Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz OnHub iOS10.2 MKRD2LL Specific Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz Google Wifi iOS10.2 MKRD2LL Specific Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz Google Wifi iOS10.2 MKV22LL Broadcast Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz OnHub iOS10.2 MKV22LL Broadcast Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz OnHub iOS10.2 MKV22LL Specific Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz Google Wifi iOS10.2 MKV22LL Specific Probe.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz GFRG210 iOS10.2 MKV22LL Broadcast Probe.pcap'),
  ('iPhone 7/7+', './testdata/pcaps/iPhone 7 2.4GHz GFRG210 iOS10.2 MN8H2LL Broadcast Probe.pcap'),
  ('iPhone 7/7+', './testdata/pcaps/iPhone 7+ 2.4GHz.pcap'),
  ('iPhone 7/7+', './testdata/pcaps/iPhone 7 2.4GHz GFRG210 iOS10.2 MN8H2LL Specific Probe.pcap'),
  ('iPhone 7/7+', './testdata/pcaps/iPhone 7 2.4GHz Google Wifi iOS10.2 MN8H2LL Broadcast Probe.pcap'),
  ('iPhone 7/7+', './testdata/pcaps/iPhone 7 2.4GHz OnHub iOS10.2 MN8H2LL Specific Probe.pcap'),
  ('iPhone 7/7+', './testdata/pcaps/iPhone 7 2.4GHz OnHub iOS10.2 MN8H2LL Broadcast Probe.pcap'),
  ('iPhone 7/7+', './testdata/pcaps/iPhone 7 2.4GHz Google Wifi iOS10.2 MN8H2LL Specific Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz GFRG210 sw 4.2.1 hw MC086LL Broadcast Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz GFRG210 sw 4.2.1 hw MC086LL Specific Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz WNDR3800 sw 4.2.1 hw MC086LL Broadcast Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz WNDR3800 sw 4.2.1 hw MC086LL Specific Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz Google Wifi sw 4.2.1 hw MC086LL Broadcast Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz Google Wifi sw 4.2.1 hw MC086LL Specific Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz OnHub sw 4.2.1 hw MC086LL Broadcast Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPod Touch 2nd gen 2.4GHz OnHub sw 4.2.1 hw MC086LL Specific Probe.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPhone 3GS 2.4GHz.pcap'),
  ('iPod Touch 2nd gen or iPhone 3GS', './testdata/pcaps/iPhone 3GS 2.4GHz M137LL.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz OnHub An5.0 LG-D855 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG K7 2.4GHz Google Wifi Android 5.1.1 LG-AS330 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz GFRG210 An5.0 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz Google Wifi An5.0 LG-D855 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz OnHub An5.0 LG-D855 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz OnHub An5.0 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG K7 2.4GHz GFRG210 Android 5.1.1 LG-AS330 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG K7 2.4GHz Google Wifi Android 5.1.1 LG-AS330 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz OnHub An5.0 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG K7 2.4GHz GFRG210 Android 5.1.1 LG-AS330 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz GFRG210 An5.0 LG-D855 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG K7 2.4GHz OnHub Android 5.1.1 LG-AS330 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz GFRG210 An5.0 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz Google Wifi An5.0 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz Google Wifi An5.0 LG-D855 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG K7 2.4GHz OnHub Android 5.1.1 LG-AS330 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz GFRG210 An5.0 LG-D855 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz GFRG210 An5.0 LG-D855 #2 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz Google Wifi An5.0 LG-D855 #2 Broadcast Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz Google Wifi An5.0 LG-D855 #2 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz GFRG210 An5.0 LG-D855 #2 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz OnHub An5.0 LG-D855 #2 Specific Probe.pcap'),
  ('LG G3 or K7', './testdata/pcaps/LG G3 2.4GHz OnHub An5.0 LG-D855 #2 Broadcast Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/LG G4 5GHz OnHub Android 5.1 LG-H815 Broadcast Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/Nexus 5 5GHz Google Wifi Android 6.0.1 Specific Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/LG G4 5GHz Google Wifi Android 5.1 LG-H815 Specific Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/LG G4 5GHz Google Wifi Android 5.1 LG-H815 Broadcast Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/Nexus 5 5GHz GFRG210 Android 6.0.1 Specific Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/Nexus 5 5GHz.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/LG G4 5GHz GFRG210 Android 5.1 LG-H815 Specific Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/Nexus 5 5GHz GFRG210 Android 6.0.1 Broadcast Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/Nexus 5 5GHz Google Wifi Android 6.0.1 Broadcast Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/Nexus 5 5GHz OnHub Android 6.0.1 Broadcast Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/LG G4 5GHz OnHub Android 5.1 LG-H815 Specific Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/Nexus 5 5GHz OnHub Android 6.0.1 Specific Probe.pcap'),
  ('LG G4 or Nexus 5', './testdata/pcaps/LG G4 5GHz GFRG210 Android 5.1 LG-H815 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2.4GHz Specific.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2.4GHz.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2nd gen 2.4GHz Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2nd gen 2.4GHz.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz GFRG210 An5.1 XT1032 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz WNDR3800 An5.1 XT1032 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz WNDR3800 An5.1 XT1032 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz Google Wifi An5.1 XT1032 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz GFRG210 An5.1 XT1032 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz Google Wifi An5.1 XT1032 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz OnHub An5.1 XT1032 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz OnHub An5.1 XT1032 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 3rd gen 2.4GHz OnHub Android 6.0 SKU XT1540 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz GFRG210 An6.0 XT1063 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2nd gen 2.4GHz Google Wifi An6.0 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz GFRG210 An6.0 XT1063 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz Google Wifi An6.0 XT1063 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 3rd gen 2.4GHz OnHub Android 6.0 SKU XT1540 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 3rd gen 2.4GHz Google Wifi Android 6.0 SKU XT1540 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2nd gen 2.4GHz OnHub An6.0 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 3rd gen 2.4GHz Google Wifi Android 6.0 SKU XT1540 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2nd gen 2.4GHz OnHub An6.0 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz OnHub An6.0 XT1063 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2nd gen 2.4GHz Google Wifi An6.0 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz OnHub An6.0 XT1063 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz Google Wifi An6.0 XT1063 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz WNDR3800 An6.0 XT1063 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz WNDR3800 An6.0 XT1063 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 1st gen 2.4GHz OnHub An5.1 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 1st gen 2.4GHz Google Wifi An5.1 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 1st gen 2.4GHz GFRG210 An5.1 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz Google Wifi An4.4.4 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz GFRG210 An5.0.2 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz OnHub An4.4.4 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz GFRG210 An4.4.4 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz OnHub An4.4.4 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz GFRG210 An4.4.4 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz OnHub An5.0.2 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz Google Wifi An5.0.2 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz WNDR3800 An5.0.2 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz WNDR3800 An5.0.2 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 1st gen 2.4GHz Google Wifi An4.4.4 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz GFRG210 An5.0.2 Specific Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz OnHub An5.0.2 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto G 2nd gen 2.4GHz Google Wifi An5.0.2 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2nd gen 2.4GHz Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 1st gen 2.4GHz GFRG210 An5.1 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 1st gen 2.4GHz Google Wifi An5.1 Broadcast Probe.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 1st gen 2.4GHz OnHub An5.1 Broadcast Probe.pcap'),
  ('Nest Thermostat v1 or v2', './testdata/pcaps/Nest Thermostat 2.4GHz.pcap'),
  ('Playstation 3 or 4', './testdata/pcaps/Playstation 3 2.4GHz Google Wifi OS 4.8 model CECH-4301A Specific Probe.pcap'),
  ('Roku 2 or 3 or Streaming Stick', './testdata/pcaps/Roku 3 2.4GHz 4230.pcap'),
  ('Roku 2 or 3 or Streaming Stick', './testdata/pcaps/Roku 3 5GHz 4230.pcap'),
  ('Roku 4 or TV', './testdata/pcaps/Roku 4 2.4GHz.pcap'),
  ('Roku 4 or TV', './testdata/pcaps/Roku 4 5GHz.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz GFRG210 An4.0.4 SGH-T879 Broadcast Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz GFRG210 An4.0.4 SGH-T879 Specific Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz OnHub An4.0.4 SGH-T879 Broadcast Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz OnHub An4.0.4 SGH-T879 Specific Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz Google Wifi An4.0.4 SGH-T879 Specific Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz Google Wifi An4.0.4 SGH-T879 Broadcast Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz WNDR3800 An4.1.2 GT-I9105 Broadcast Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz Google Wifi An4.1.2 GT-I9105 Broadcast Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz GFRG210 An4.1.2 GT-I9105 Specific Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz OnHub An4.1.2 GT-I9105 Specific Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz WNDR3800 An4.1.2 GT-I9105 Specific Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz Google Wifi An4.1.2 GT-I9105 Specific Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz OnHub An4.1.2 GT-I9105 Broadcast Probe.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz GFRG210 An4.1.2 GT-I9105 Broadcast Probe.pcap'),
  ('Samsung Galaxy Note 5 or S7 Edge', './testdata/pcaps/Samsung Galaxy S7 Edge 5GHz GFRG210 An6.0.1 SM-G935F Specific Probe.pcap'),
  ('Samsung Galaxy Note 5 or S7 Edge', './testdata/pcaps/Samsung Galaxy S7 Edge 5GHz GFRG210 An6.0.1 SM-G935F Broadcast Probe.pcap'),
  ('Samsung Galaxy Note 5 or S7 Edge', './testdata/pcaps/Samsung Galaxy Note 5 5GHz GFRG210 An6.0.1 SM-N920C Broadcast Probe.pcap'),
  ('Samsung Galaxy Note 5 or S7 Edge', './testdata/pcaps/Samsung Galaxy Note 5 5GHz GFRG210 An6.0.1 SM-N920C Specific Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Infuse 2.4GHz.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz WNDR3800 An4.0.3 GF-I9100 Broadcast Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz WNDR3800 An4.0.3 GF-I9100 Specific Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz GFRG210 An4.0.3 GF-I9100 Specific Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz Google Wifi An4.0.3 GF-I9100 Specific Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz Google Wifi An4.0.3 GF-I9100 Broadcast Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz GFRG210 An4.0.3 GF-I9100 Broadcast Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz OnHub An4.0.3 GF-I9100 Broadcast Probe.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz OnHub An4.0.3 GF-I9100 Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz WNDR3800 Android 5.0.2 SM-T800 Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz GFRG210 Android 6.0.1 SM-G900H Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz OnHub Android 5.0.2 SM-T800 Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz OnHub Android 5.0 SM-G900F Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz WNDR3800 Android 5.0.2 SM-T800 Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz GFRG210 Android 5.0 SM-G900F Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz OnHub Android 5.0.2 SM-T800 Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz Probe 1.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz Google Wifi Android 6.0.1 SM-G900H Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz Google Wifi Android 5.0 SM-G900F Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz GFRG210 Android 5.0.2 SM-T800 Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz OnHub Android 5.0 SM-G900F Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz GFRG210 Android 5.0 SM-G900F Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz Probe 3.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz OnHub Android 6.0.1 SM-G900H Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz Google Wifi Android 5.0 SM-G900F Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz Google Wifi Android 6.0.1 SM-G900H Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz GFRG210 Android 5.0.2 SM-T800 Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz Google Wifi Android 5.0.2 SM-T800 Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy Tab S 2.4GHz Google Wifi Android 5.0.2 SM-T800 Specific Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz GFRG210 Android 6.0.1 SM-G900H Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz OnHub Android 6.0.1 SM-G900H Broadcast Probe.pcap'),
  ('Samsung Galaxy S5 or Tab S', './testdata/pcaps/Samsung Galaxy S5 2.4GHz Probe 2.pcap'),
  ('Sony Xperia Z4 or Z5', './testdata/pcaps/Sony Xperia Z5 5GHz.pcap'),
  ('Sony Xperia Z4 or Z5', './testdata/pcaps/Sony Xperia Z5 2.4GHz.pcap'),
  ('Sony Xperia Z4 or Z5', './testdata/pcaps/Sony Xperia Z4 Tablet 5GHz.pcap'),
  ('Sony Xperia Z4 or Z5', './testdata/pcaps/Sony Xperia Z4 Tablet 2.4GHz.pcap'),
]


def get_taxonomy_from_pcap(filename):
  (mac, sig) = subprocess.check_output(['./wifi_signature', '-f', filename]).split()
  return (mac, sig)


def get_model(filename):
  offset = filename.find('2.4GHz')
  if offset < 0:
    offset = filename.find('5GHz')
  if offset < 0:
    print 'Invalid filename: %s' % filename
    return ''
  return filename[0:offset].strip()


def check_pcap(expected_model, pcap):
  mac, sig = get_taxonomy_from_pcap(pcap)
  genus, species, _ = wifi.identify_wifi_device(sig, mac)
  actual_model = genus + " " + species if species else genus
  if expected_model and expected_model != actual_model:
    print 'Mismatch in %s: %s %s != %s' % (pcap, mac, expected_model,
                                           actual_model)
    return True
  if not expected_model and 'Unknown' not in actual_model:
    print 'Mismatch in %s: %s %s != Unknown' % (pcap, mac, actual_model)
    return True


if __name__ == '__main__':
  dhcp.DHCP_LEASES_FILE = 'testdata/dhcp.leases'
  dhcp.DHCP_SIGNATURE_FILE = 'testdata/dhcp.signatures'
  pcaps = glob.glob('./testdata/pcaps/*.pcap')
  rc = 0

  for (expected_model, pcap) in regression:
    pcaps.remove(pcap)
    if check_pcap(expected_model, pcap):
      rc = 1

  for pcap in pcaps:
    expected_model = get_model(os.path.basename(pcap))
    if not expected_model or check_pcap(expected_model, pcap):
      rc = 1

  sys.exit(rc)
