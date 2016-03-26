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

"""Database of signatures for known Wifi devices."""


import hashlib
import dhcp
import ethernet


database = {
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|os:dashbutton':
        ('BCM43362', 'Amazon Dash Button', '2.4GHz'),

    'wifi4|probe:0,1,50|assoc:0,1,50,48,221(0050f2,2)|os:kindle':
        ('', 'Amazon Kindle', '2.4GHz'),
    'wifi|probe:0,1,50,45,htcap:01ac,htagg:02,htmcs:0000ffff|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:01ac,htagg:02,htmcs:0000ffff|os:kindle':
        ('', 'Amazon Kindle', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:1130,htagg:18,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),htcap:1130,htagg:18,htmcs:000000ff|oui:amazon':
        ('TI_WL1271', 'Amazon Kindle Fire 7" (2011 edition)', '2.4GHz'),
    'wifi|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:KFASWI|assoc:0,1,50,45,127,221(0050f2,2),48,htcap:1172,htagg:03,htmcs:000000ff':
        ('', 'Amazon Kindle Fire 7" (2014 edition)', '2.4GHz'),
    'wifi|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:KFFOWI|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff':
        ('', 'Amazon Kindle Fire 7" (2015 edition)', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:007e,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(001018,2),221(0050f2,2),htcap:007e,htagg:1b,htmcs:0000ffff,txpow:e50d|oui:amazon':
        ('', 'Amazon Fire TV Stick', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:003c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:003c,htagg:1b,htmcs:0000ffff,txpow:170c|oui:amazon':
        ('', 'Amazon Fire TV Stick', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:081e,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:081e,htagg:1b,htmcs:0000ffff,txpow:0008|os:appletv1':
        ('BCM94321', 'Apple TV (1st gen)', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:181c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:181c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:581c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:581c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:181c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:581c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:581c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:181c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:080c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:080c,htagg:1b,htmcs:000000ff,txpow:1208|os:ios':
        ('BCM4329', 'Apple TV (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff,txpow:1308|os:ios':
        ('BCM4329', 'Apple TV (2nd gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|name:appletv':
        ('BCM4330', 'Apple TV (3rd gen)', '2.4GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|name:appletv':
        ('BCM4330', 'Apple TV (3rd gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1907|os:ios':
        ('BCM4334', 'Apple TV (3rd gen rev A)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1907|os:ios':
        ('BCM4334', 'Apple TV (3rd gen rev A)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1a07|os:ios':
        ('BCM4334', 'Apple TV (3rd gen rev A)', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1a07|os:ios':
        ('BCM4334', 'Apple TV (3rd gen rev A)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:appletv':
        ('', 'Apple TV (4th gen)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1502,extcap:0000000000000040|name:appletv':
        ('', 'Apple TV (4th gen)', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:112c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:112c,htagg:19,htmcs:000000ff|os:brotherprinter':
        ('', 'Brother Printer', '2.4GHz'),

    'wifi4|probe:0,1,45,191,htcap:11e2,htagg:17,htmcs:0000ffff,vhtcap:038071a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,48,45,127,191,221(0050f2,2),htcap:11e6,htagg:17,htmcs:0000ffff,vhtcap:038001a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000000000000040|os:chromeos':
        ('Intel_7260', 'Chromebook Pixel 2', '5GHz'),
    'wifi4|probe:0,1,45,191,htcap:11e2,htagg:17,htmcs:0000ffff,vhtcap:038071a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,48,45,127,191,221(0050f2,2),htcap:11ee,htagg:17,htmcs:0000ffff,vhtcap:038001a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000000000000040|os:chromeos':
        ('Intel_7260', 'Chromebook Pixel 2', '5GHz'),
    'wifi4|probe:0,1,45,191,htcap:11e2,htagg:17,htmcs:0000ffff,vhtcap:038071a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,127,191,221(0050f2,2),htcap:11e6,htagg:17,htmcs:0000ffff,vhtcap:038001a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1600,extcap:0000000000000040|os:chromeos':
        ('Intel_7260', 'Chromebook Pixel 2', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:11e2,htagg:17,htmcs:0000ffff|assoc:0,1,50,48,45,127,221(0050f2,2),htcap:11a4,htagg:17,htmcs:0000ffff,extcap:0000000000000040|os:chromeos':
        ('Intel_7260', 'Chromebook Pixel 2', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:11e2,htagg:17,htmcs:0000ffff|assoc:0,1,50,48,45,127,221(0050f2,2),htcap:11ac,htagg:17,htmcs:0000ffff,extcap:0000000000000040|os:chromeos':
        ('Intel_7260', 'Chromebook Pixel 2', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:11ef,htagg:1b,htmcs:0000ffff|assoc:0,1,48,45,221(0050f2,2),htcap:11ef,htagg:1b,htmcs:0000ffff|os:chromeos':
        ('AR5822', 'Chromebook 14" HP', '5GHz'),
    'wifi4|probe:0,1,50,3,45,htcap:11ef,htagg:1b,htmcs:0000ffff|assoc:0,1,50,48,45,221(0050f2,2),htcap:11ef,htagg:1b,htmcs:0000ffff|os:chromeos':
        ('AR5822', 'Chromebook 14" HP', '2.4GHz'),

    'wifi|probe:0,1,3,45,50,htcap:01ff|assoc:0,1,50,127,221(0050f2,1),221(0050f2,2),45,htcap:01ff|os:chromeos':
        ('Marvell_88W8897', 'Chromebook 14" HP (Tegra)', '2.4GHz'),

    'wifi4|probe:0,1,45,50,htcap:016e,htagg:03,htmcs:0000ffff|assoc:0,1,48,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:0000ffff,extcap:00':
        ('AR9382', 'Chromebook 11" Samsung', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:016e,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:0000ffff,extcap:00':
        ('AR9382', 'Chromebook 11" Samsung', '2.4GHz'),

    'wifi4|probe:0,1,3,45,50,htcap:0120,htagg:03,htmcs:00000000|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:000000ff,extcap:0000000000000140|oui:google':
        ('Marvell_88W8797', 'Chromecast', '2.4GHz'),
    'wifi4|probe:0,1,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,48,127,221(0050f2,2),45,191,htcap:006e,htagg:03,htmcs:000000ff,vhtcap:33c07030,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,extcap:0400000000000140|oui:google':
        ('Marvell_88W8887', 'Chromecast v2', '5GHz'),
    'wifi4|probe:0,1,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,33,36,48,127,221(0050f2,2),45,191,htcap:006e,htagg:03,htmcs:000000ff,vhtcap:33c07030,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,extcap:0400000000000140|oui:google':
        ('Marvell_88W8887', 'Chromecast v2', '5GHz'),
    'wifi4|probe:0,1,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,33,36,48,127,221(0050f2,2),45,191,htcap:006e,htagg:03,htmcs:000000ff,vhtcap:33c07030,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,txpow:1308,extcap:0400000000000140|oui:google':
        ('Marvell_88W8887', 'Chromecast v2', '5GHz'),
    'wifi4|probe:0,1,3,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:002c,htagg:03,htmcs:000000ff,extcap:0000000000000140|oui:google':
        ('Marvell_88W8887', 'Chromecast v2', '2.4GHz'),

    'wifi|probe:0,1,50,45,htcap:002c,htagg:01,htmcs:000000ff|assoc:0,1,50,45,48,221(0050f2,2),htcap:002c,htagg:01,htmcs:000000ff|oui:dropcam':
        ('', 'Dropcam', '2.4GHz'),

    'wifi|probe:0,1,3,45,50,htcap:0162,htagg:00,htmcs:000000ff|assoc:0,1,45,48,127,50,221(0050f2,2),htcap:016e,htagg:1b,htmcs:000000ff|os:epsonprinter':
        ('', 'Epson Printer', '2.4GHz'),

    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff|os:hpprinter':
        ('', 'HP Printer', '2.4GHz'),
    'wifi|probe:0,1,3,45,50,htcap:0160,htagg:03,htmcs:000000ff|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:016c,htagg:03,htmcs:000000ff|os:hpprinter':
        ('', 'HP Printer', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(0050f2,2),221(506f9a,9),htcap:0020,htagg:1a,htmcs:000000ff|os:hpprinter':
        ('', 'HP Printer', '2.4GHz'),
    'wifi|probe:0,1,3,45,50,htcap:0060,htagg:03,htmcs:000000ff|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:006c,htagg:03,htmcs:000000ff|os:hpprinter':
        ('', 'HP Printer', '2.4GHz'),
    'wifi4|probe:0,1,3,45,50,127,htcap:010c,htagg:1b,htmcs:0000ffff,extcap:00|assoc:0,1,45,48,127,50,221(0050f2,2),htcap:016c,htagg:1b,htmcs:000000ff,extcap:00|os:hpprinter':
        ('', 'HP Printer', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:htc':
        ('BCM4335', 'HTC One', '5GHz'),
    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:htc':
        ('BCM4335', 'HTC One', '5GHz'),
    'wifi4|probe:0,1,50,45,127,221(001018,2),221(00904c,51),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1408|oui:htc':
        ('BCM4335', 'HTC One', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1408|oui:htc':
        ('BCM4335', 'HTC One', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:HTC_VLE_U|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('', 'HTC One S', '2.4GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:HTC_VLE_U|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('', 'HTC One S', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),191,127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a820040,wps:HTC_One_M8|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a8201400040':
        ('WCN3680', 'HTC One M8', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a820040,wps:HTC_One_M8|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a8201400040':
        ('WCN3680', 'HTC One M8', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a820040,wps:HTC_One_M8|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a8201400000':
        ('WCN3680', 'HTC One M8', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a8201400000|oui:htc':
        ('WCN3680', 'HTC One M8', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,107,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e009,extcap:0000088001400040|oui:htc':
        ('BCM4356', 'HTC One M9', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:1063,htagg:17,htmcs:000000ff,extcap:0000088001400040|assoc:0,1,50,33,36,45,127,107,221(001018,2),221(0050f2,2),htcap:1063,htagg:17,htmcs:000000ff,txpow:1309,extcap:000008800140|oui:htc':
        ('BCM4356', 'HTC One M9', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:1063,htagg:17,htmcs:000000ff,extcap:0000088001400040|assoc:0,1,50,33,36,45,127,107,221(001018,2),221(0050f2,2),htcap:1063,htagg:17,htmcs:000000ff,txpow:1309,extcap:000008800140|oui:htc':
        ('BCM4356', 'HTC One M9', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:080c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:080c,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('BCM4329', 'iPad (1st/2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0800,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0800,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('BCM4329', 'iPad (1st/2nd gen)', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('BCM4329', 'iPad (1st gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:1800,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1800,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('BCM4329', 'iPad (1st gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff,txpow:1108|os:ios':
        ('BCM4329', 'iPad (2nd gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:1800,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1800,htagg:1b,htmcs:000000ff,txpow:1108|os:ios':
        ('BCM4329', 'iPad (2nd gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|os:ios':
        ('BCM4330', 'iPad (3rd gen)', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|os:ios':
        ('BCM4330', 'iPad (3rd gen)', '5GHz'),
    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100|os:ios':
        ('BCM4330', 'iPad (3rd gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e708|os:ios':
        ('BCM4334', 'iPad (4th gen or Air)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e708|os:ios':
        ('BCM4334', 'iPad (4th gen or Air)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1805|os:ios':
        ('BCM4334', 'iPad (4th gen or Air)', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1805|os:ios':
        ('BCM4334', 'iPad (4th gen or Air)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('BCM4350', 'iPad Air (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('BCM4350', 'iPad Air (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('BCM4350', 'iPad Air (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('BCM4350', 'iPad Air (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('BCM4350', 'iPad Air (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('BCM4350', 'iPad Air (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('BCM4350', 'iPad Air (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1502,extcap:0000000000000040|os:ios':
        ('BCM4335', 'iPad Air (2nd gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1502,extcap:0000000000000040|os:ios':
        ('BCM4335', 'iPad Air (2nd gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1807|os:ios':
        ('BCM4334', 'iPad Mini (1st gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1807|os:ios':
        ('BCM4334', 'iPad Mini (1st gen)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1605|os:ios':
        ('BCM4334', 'iPad Mini (1st gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1605|os:ios':
        ('BCM4334', 'iPad Mini (1st gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e606|os:ios':
        ('BCM4324', 'iPad Mini (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e606|os:ios':
        ('BCM4324', 'iPad Mini (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1603|os:ios':
        ('BCM4324', 'iPad Mini (2nd gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1603|os:ios':
        ('BCM4324', 'iPad Mini (2nd gen)', '2.4GHz'),

    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:1800,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1800,htagg:1b,htmcs:000000ff|os:ios':
        ('BCM4329', 'iPhone 4', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff|os:ios':
        ('BCM4330', 'iPhone 4s', '2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff|os:ios':
        ('BCM4330', 'iPhone 4s', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1504|os:ios':
        ('BCM4334', 'iPhone 5', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1504|os:ios':
        ('BCM4334', 'iPhone 5', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1403|os:ios':
        ('BCM4334', 'iPhone 5', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1403|os:ios':
        ('BCM4334', 'iPhone 5', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('BCM4334', 'iPhone 5c', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1704|os:ios':
        ('BCM4334', 'iPhone 5c', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1704|os:ios':
        ('BCM4334', 'iPhone 5c', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1603|os:ios':
        ('BCM4334', 'iPhone 5s', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1603|os:ios':
        ('BCM4334', 'iPhone 5s', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('BCM4334', 'iPhone 5s', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('BCM4334', 'iPhone 5s', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4339', 'iPhone 6/6+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4339', 'iPhone 6/6+', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1302,extcap:0000000000000040|os:ios':
        ('BCM4339', 'iPhone 6', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1302,extcap:0000000000000040|os:ios':
        ('BCM4339', 'iPhone 6', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1402,extcap:0000000000000040|os:ios':
        ('BCM4339', 'iPhone 6+', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1402,extcap:0000000000000040|os:ios':
        ('BCM4339', 'iPhone 6+', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('BCM4350', 'iPhone 6s/6s+', '2.4GHz'),

    'wifi4|probe:0,1,3,50|assoc:0,1,48,50|os:ipodtouch1':
        ('Marvell_W8686B22', 'iPod Touch 1st/2nd gen', '2.4GHz'),

    'wifi4|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2),221(0050f2,2)|name:ipod':
        ('BCM4329', 'iPod Touch 3rd gen', '2.4GHz'),

    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff|os:ios':
        ('BCM4329', 'iPod Touch 4th gen', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1504|os:ios':
        ('BCM4334', 'iPod Touch 5th gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1706|os:ios':
        ('BCM4334', 'iPod Touch 5th gen', '2.4GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1706|os:ios':
        ('BCM4334', 'iPod Touch 5th gen', '2.4GHz'),

    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000000040|oui:lg':
        ('BCM4335', 'LG G2', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:11ff|oui:lg':
        ('BCM4335', 'LG G2', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:11ff|oui:lg':
        ('BCM4335', 'LG G2', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),191,127,107,221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:000000800040|assoc:0,1,33,36,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:170d,extcap:00000a8201400040|oui:lg':
        ('BCM4339', 'LG G3', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(506f9a,16),htcap:012c,htagg:03,htmcs:000000ff,extcap:000000800040|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a8201400000|oui:lg':
        ('BCM4339', 'LG G3', '2.4GHz'),

    'wifi4|probe:0,1,3,45,127,107,191,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:1d01,extcap:0000008001400040|oui:lg':
        ('BCM4339', 'LG G4', '5GHz'),
    'wifi4|probe:0,1,50,45,127,107,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000088001400040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1001,extcap:000000800140|oui:lg':
        ('BCM4339', 'LG G4', '2.4GHz'),

    'wifi|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:LGMS323|assoc:0,1,50,48,45,221(0050f2,2),221(004096,3),htcap:012c':
        ('QCA_WCN3360', 'LG Optimus L70', '2.4GHz'),

    'wifi|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:LGLS660|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('', 'LG Tribute', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:087e,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:087e,htagg:1b,htmcs:0000ffff,txpow:0f07|os:macos':
        ('BCM43224', 'MacBook Air late 2010 (A1369)', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:187c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:187c,htagg:1b,htmcs:0000ffff,txpow:1207|os:macos':
        ('BCM43224', 'MacBook Air late 2010 (A1369)', '2.4GHz'),

    'wifi4|probe:0,1,45,221(00904c,51),htcap:086e,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(00904c,51),221(0050f2,2),htcap:086e,htagg:1b,htmcs:0000ffff,txpow:0f07|os:macos':
        ('BCM4322', 'MacBook Air late 2011', '5GHz'),

    'wifi4|probe:0,1,45,221(00904c,51),htcap:09ef,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(00904c,51),221(0050f2,2),htcap:09ef,htagg:1b,htmcs:0000ffff,txpow:0005|os:macos':
        ('BCM4331', 'MacBook Pro 17" late 2011 (A1297)', '5GHz'),
    'wifi4|probe:0,1,3,45,221(00904c,51),htcap:09ef,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(00904c,51),221(0050f2,2),htcap:09ef,htagg:1b,htmcs:0000ffff,txpow:0005|os:macos':
        ('BCM4331', 'MacBook Pro 17" late 2011 (A1297)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(00904c,51),htcap:19ad,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(00904c,51),221(0050f2,2),htcap:19ad,htagg:1b,htmcs:0000ffff,txpow:1305|os:macos':
        ('BCM4331', 'MacBook Pro 17" late 2011 (A1297)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,htcap:09ef,htagg:17,htmcs:0000ffff,extcap:0400000000000040|assoc:0,1,33,36,48,45,127,221(0050f2,2),htcap:09ef,htagg:17,htmcs:0000ffff,txpow:e007,extcap:0400000000000040|os:macos':
        ('BCM4331', 'MacBook Pro 15" late 2013 (A1398)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,htcap:49ad,htagg:17,htmcs:0000ffff,extcap:0400000000000040|assoc:0,1,50,33,36,48,45,127,221(0050f2,2),htcap:49ad,htagg:17,htmcs:0000ffff,txpow:1307,extcap:0000000000000040|os:macos':
        ('BCM4331', 'MacBook Pro 15" late 2013 (A1398)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,htcap:09ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400000000000040|assoc:0,1,33,36,48,45,127,191,221(0050f2,2),htcap:09ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0400000000000040|os:macos':
        ('BCM4360', 'MacBook Air late 2014 (A1466)', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,htcap:49ad,htagg:17,htmcs:0000ffff,extcap:0400000000000040|assoc:0,1,50,33,36,48,45,127,221(0050f2,2),htcap:49ad,htagg:17,htmcs:0000ffff,txpow:1407,extcap:0000000000000040|os:macos':
        ('BCM4360', 'MacBook Air late 2014 (A1466)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(00904c,51),htcap:09ef,htagg:17,htmcs:0000ffff,vhtcap:0f8259b2,vhtrxmcs:0000ffea,vhttxmcs:0000ffea,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(00904c,51),221(0050f2,2),htcap:09ef,htagg:17,htmcs:0000ffff,vhtcap:0f8259b2,vhtrxmcs:0000ffea,vhttxmcs:0000ffea,txpow:e808,extcap:0000000000000040|os:macos':
        ('BCM4360', 'MacBook Pro early 2014 (A1502)', '5GHz'),
    'wifi4|probe:0,1,50,45,127,221(00904c,51),htcap:59ad,htagg:17,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,127,221(00904c,51),221(0050f2,2),htcap:59ad,htagg:17,htmcs:0000ffff,txpow:1906,extcap:0000000000000040|os:macos':
        ('BCM4360', 'MacBook Pro early 2014 (A1502)', '2.4GHz'),

    'wifi4|probe:0,1,45,50,htcap:0102,htagg:03,htmcs:0000ffff|assoc:0,1,48,221(0050f2,2),45,htcap:010e,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Marvell_88W8797', 'Microsoft Surface RT', '5GHz'),
    'wifi4|probe:0,1,45,50,htcap:0102,htagg:03,htmcs:0000ffff|assoc:0,1,33,36,48,221(0050f2,2),45,htcap:010e,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Marvell_88W8797', 'Microsoft Surface RT', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:0102,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Marvell_88W8797', 'Microsoft Surface RT', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a0200000000|oui:motorola':
        ('QCA_WCN3620', 'Moto E (2nd gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000|oui:motorola':
        ('QCA_WCN3620', 'Moto E (2nd gen)', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:motorola':
        ('QCA_WCN3620', 'Moto G or Moto X', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,48,45,221(0050f2,2),191,127,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a02|oui:motorola':
        ('QCA_WCN3680', 'Moto X', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,48,45,221(0050f2,2),191,127,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a02|oui:motorola':
        ('QCA_WCN3680', 'Moto X', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),191,htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:motorola':
        ('QCA_WCN3680', 'Moto X', '2.4GHz'),

    'wifi4|probe:0,1,127,45,htcap:01ef,htagg:03,htmcs:0000ffff,extcap:00000a0201|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004040|oui:motorola':
        ('', 'Moto X Style', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004040|oui:motorola':
        ('', 'Moto X Style', '5GHz'),
    'wifi4|probe:0,1,50,127,45,htcap:01ef,htagg:03,htmcs:0000ffff,extcap:00000a0201|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:00000a020100000040|oui:motorola':
        ('', 'Moto X Style', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:00000a0201|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:00000a020100000040|oui:motorola':
        ('', 'Moto X Style', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:082c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:082c,htagg:1b,htmcs:000000ff,txpow:0a08|oui:motorola':
        ('BCM4329', 'Motorola Xoom', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:182c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:182c,htagg:1b,htmcs:000000ff,txpow:0e08|oui:motorola':
        ('BCM4329', 'Motorola Xoom', '2.4GHz'),

    'wifi4|probe:0,1,50,45,htcap:0130,htagg:18,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),htcap:013c,htagg:18,htmcs:000000ff|oui:nest':
        ('TI_WL1270', 'Nest Thermostat v1/v2', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,33,36,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff,txpow:130d':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a02':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a02|oui:lg':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:lg':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:lg':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:lg':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e003,extcap:0000000000000040|oui:lg':
        ('BCM4339', 'Nexus 5', '5GHz'),
    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e003,extcap:0000000000000040|oui:lg':
        ('BCM4339', 'Nexus 5', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1303|oui:lg':
        ('BCM4339', 'Nexus 5', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(001018,2),221(00904c,51),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1303|oui:lg':
        ('BCM4339', 'Nexus 5', '2.4GHz'),

    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a0201000040|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:0000000000000040|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,127,extcap:00000a020100004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,127,extcap:00000a020100004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '5GHz'),
    'wifi4|probe:0,1,50,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a0201000040|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:0000000000000000|oui:lg':
        ('QCA6174', 'Nexus 5X', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|oui:lg':
        ('QCA6174', 'Nexus 5X', '2.4GHz'),
    'wifi4|probe:0,1,50,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|oui:lg':
        ('QCA6174', 'Nexus 5X', '2.4GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('QCA6174', 'Nexus 5X', '2.4GHz'),
    'wifi4|probe:0,1,50,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,txpow:1e08,extcap:000000000000000080|oui:lg':
        ('QCA6174', 'Nexus 5X', '2.4GHz'),
    'wifi4|probe:0,1,50,127,extcap:00000a020100004080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,txpow:1e08,extcap:000000000000000080|oui:lg':
        ('QCA6174', 'Nexus 5X', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,txpow:1e08,extcap:000000000000000080|oui:lg':
        ('QCA6174', 'Nexus 5X', '2.4GHz'),

    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140,wps:Nexus_6|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:000008800140':
        ('BCM4356', 'Nexus 6', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140,wps:Nexus_6|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:000008800140':
        ('BCM4356', 'Nexus 6', '5GHz'),
    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,wps:Nexus_6|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009':
        ('BCM4356', 'Nexus 6', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_6|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('BCM4356', 'Nexus 6', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_6|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('BCM4356', 'Nexus 6', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_6|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('BCM4356', 'Nexus 6', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,wps:Nexus_6|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209':
        ('BCM4356', 'Nexus 6', '2.4GHz'),

    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,wps:Nexus_6P|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002':
        ('BCM4358', 'Nexus 6P', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040,wps:Nexus_6P|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0000088001400040':
        ('BCM4358', 'Nexus 6P', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_6P|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1402,extcap:0000088001400040':
        ('BCM4358', 'Nexus 6P', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|oui:asus':
        ('BCM4330', 'Nexus 7 (2012)', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02|oui:asus':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02|oui:asus':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:asus':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:asus':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140,wps:Nexus_9|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:000008800140':
        ('BCM4354', 'Nexus 9', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_9|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1309,extcap:000008800140':
        ('BCM4354', 'Nexus 9', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_9|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:150b,extcap:000008800140':
        ('BCM4354', 'Nexus 9', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:01fe,htagg:1b,htmcs:0000ffff|assoc:0,1,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff|oui:samsung':
        ('', 'Nexus 10', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:01bc,htagg:1b,htmcs:0000ffff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff|oui:samsung':
        ('', 'Nexus 10', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040,wps:Nexus_Player|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040':
        ('BCM4356', 'Nexus Player', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_Player|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('BCM4356', 'Nexus Player', '2.4GHz'),

    'wifi4|probe:0,1,50,45,51,127,htcap:012c,htagg:1b,htmcs:000000ff,extcap:0100000000000040|assoc:0,1,48,50,221(0050f2,2),45,51,127,htcap:012c,htagg:1b,htmcs:000000ff,extcap:0100000000000040|os:windows-phone':
        ('', 'Nokia Lumia 635', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:012c,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,221(0050f2,2),45,51,127,htcap:012c,htagg:1b,htmcs:000000ff,extcap:0100000000000040|os:windows-phone':
        ('', 'Nokia Lumia 635', '2.4GHz'),

    'wifi4|probe:0,1,50|assoc:0,1,50,48,221(005043,1)|os:playstation':
        ('', 'Playstation 3 or 4', '2.4GHz'),

    'wifi|probe:0,1,3,50|assoc:0,1,48,50,221(0050f2,2),45,htcap:112c,htagg:03,htmcs:0000ffff|os:playstation':
        ('Marvell_88W8797', 'Playstation 4', '2.4GHz'),
    'wifi4|probe:0,1,3,50|assoc:0,1,33,48,50,221(0050f2,2),45,htcap:112c,htagg:03,htmcs:0000ffff,txpow:0f06|os:playstation':
        ('Marvell_88W8797', 'Playstation 4', '2.4GHz'),

    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|os:roku':
        ('BCM43362', 'Roku HD', '2.4GHz'),

    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff|os:roku':
        ('BCM4336', 'Roku 2 XD', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:19bc,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:19bc,htagg:16,htmcs:0000ffff,txpow:140a,extcap:0000000000000040|os:roku':
        ('BCM43236', 'Roku 3', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:193c,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:193c,htagg:16,htmcs:0000ffff,txpow:140a,extcap:0000000000000040|os:roku':
        ('BCM43236', 'Roku 3', '2.4GHz'),

    'wifi4|probe:0,1,45,191,221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,191,199,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1109|os:roku':
        ('', 'Roku 4', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1209|os:roku':
        ('', 'Roku 4', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,htcap:0020,htagg:01,htmcs:000000ff|assoc:0,1,50,45,61,48,221(0050f2,2),htcap:0020,htagg:01,htmcs:000000ff|oui:samsung':
        ('', 'Samsung Galaxy Mini', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:010c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:010c,htagg:19,htmcs:000000ff,txpow:0f09':
        ('BCM4330', 'Samsung Galaxy Nexus', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:010c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:010c,htagg:19,htmcs:000000ff,txpow:0f09':
        ('BCM4330', 'Samsung Galaxy Nexus', '5GHz'),
    'wifi4|probe:0,1,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Nexus', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff,txpow:1209':
        ('BCM4330', 'Samsung Galaxy Nexus', '2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff,txpow:1209':
        ('BCM4330', 'Samsung Galaxy Nexus', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:120a|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Nexus', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f09|oui:samsung':
        ('', 'Samsung Galaxy Note or S2+', '5GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:1409|oui:samsung':
        ('', 'Samsung Galaxy Note', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Note 2', '5GHz'),
    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Note 2', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Note 2', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Note 2', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020,htagg:1a,htmcs:000000ff,txpow:1209|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Note 2', '2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020,htagg:1a,htmcs:000000ff,txpow:1209|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Note 2', '2.4GHz'),

    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy Note 3', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy Note 3', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1208|oui:samsung':
        ('BCM4335', 'Samsung Galaxy Note 3', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1208|oui:samsung':
        ('BCM4335', 'Samsung Galaxy Note 3', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,107,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy Note 4', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,70,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy Note 4', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1509,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy Note 4', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1509,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy Note 4', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:00080f8401400040|assoc:0,1,33,36,48,45,127,191,199,221(00904c,4),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1102,extcap:0000000000000040|oui:samsung':
        ('BCM4359', 'Samsung Galaxy Note 5', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:00080f8401400040|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1202|oui:samsung':
        ('BCM4359', 'Samsung Galaxy Note 5', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('', 'Samsung Galaxy S2', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('', 'Samsung Galaxy S2', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:120a|oui:samsung':
        ('', 'Samsung Galaxy S2 or Infuse','2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:120a|oui:samsung':
        ('', 'Samsung Galaxy S2 or Infuse','2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:1209|oui:samsung':
        ('', 'Samsung Galaxy S2+', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1409|oui:samsung':
        ('BCM4334', 'Samsung Galaxy S3', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1409|oui:samsung':
        ('BCM4334', 'Samsung Galaxy S3', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020,htagg:1a,htmcs:000000ff,txpow:1409|oui:samsung':
        ('BCM4334', 'Samsung Galaxy S3', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000000040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '5GHz'),
    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000000040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088000400040|assoc:0,1,33,36,48,45,127,107,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000008000400040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '5GHz'),
    'wifi4|probe:0,1,3,45,127,107,191,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088000400040|assoc:0,1,33,36,48,45,127,107,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000008000400040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000400040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000400040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000088000400040|assoc:0,1,33,36,48,50,45,127,107,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1201,extcap:000000800040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1201|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,107,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000088000400040|assoc:0,1,33,36,48,50,45,127,107,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1201,extcap:000000800040|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,107,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e20b,extcap:0000088001400040|oui:samsung':
        ('BCM4354', 'Samsung Galaxy S5', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140|assoc:0,1,50,33,36,48,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140|oui:samsung':
        ('BCM4354', 'Samsung Galaxy S5', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140|oui:samsung':
        ('BCM4354', 'Samsung Galaxy S5', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy S6', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy S6', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1402,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy S6', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1402,extcap:0000088001400040|oui:samsung':
        ('BCM4358', 'Samsung Galaxy S6', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:082c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:082c,htagg:1b,htmcs:000000ff,txpow:0f08|oui:samsung':
        ('BCM4329', 'Samsung Galaxy Tab', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:182c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:182c,htagg:1b,htmcs:000000ff,txpow:1208|oui:samsung':
        ('BCM4329', 'Samsung Galaxy Tab', '2.4GHz'),

    'wifi4|probe:0,1,45,50,htcap:0162,htagg:03,htmcs:00000000|assoc:0,1,48,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:000000ff,extcap:0400000000000140|oui:samsung':
        ('Marvell_88W8787', 'Samsung Galaxy Tab 3', '5GHz'),
    'wifi4|probe:0,1,45,50,htcap:0162,htagg:03,htmcs:00000000|assoc:0,1,33,36,48,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:000000ff,txpow:1208,extcap:0400000000000140|oui:samsung':
        ('Marvell_88W8787', 'Samsung Galaxy Tab 3', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:0162,htagg:03,htmcs:00000000|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:000000ff,extcap:0000000000000140|oui:samsung':
        ('Marvell_88W8787', 'Samsung Galaxy Tab 3', '2.4GHz'),

    'wifi|probe:0,1,45,221(0050f2,8),htcap:016e|assoc:0,1,33,36,48,45,221(0050f2,2),221(004096,3),htcap:016e|oui:samsung':
        ('APQ8026', 'Samsung Galaxy Tab 4', '5GHz'),
    'wifi|probe:0,1,50,3,45,221(0050f2,8),htcap:012c|assoc:0,1,50,48,45,221(0050f2,2),221(004096,3),htcap:012c|oui:samsung':
        ('APQ8026', 'Samsung Galaxy Tab 4', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0c0a|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Tab 10.1', '5GHz'),
    'wifi4|probe:0,1,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0c0a|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Tab 10.1', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('BCM4330', 'Samsung Galaxy Tab 10.1', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:11ee,htagg:02,htmcs:0000ffff|assoc:0,1,45,127,33,36,48,221(0050f2,2),htcap:11ee,htagg:02,htmcs:0000ffff,txpow:1100,extcap:01|os:samsungtv':
        ('', 'Samsung Smart TV', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:01ac,htagg:02,htmcs:0000ffff|assoc:0,1,50,45,127,48,221(0050f2,2),htcap:01ac,htagg:02,htmcs:0000ffff,extcap:01|os:samsungtv':
        ('', 'Samsung Smart TV', '2.4GHz'),

    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffc,vhttxmcs:0000fffc|assoc:0,1,33,36,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff|oui:sony':
        ('WCN3680', 'Sony Xperia Z Ultra', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffc,vhttxmcs:0000fffc|assoc:0,1,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff|oui:sony':
        ('WCN3680', 'Sony Xperia Z Ultra', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000|oui:sony':
        ('WCN3680', 'Sony Xperia Z Ultra', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000|oui:sony':
        ('WCN3680', 'Sony Xperia Z Ultra', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,70,45,127,107,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0000088001400040|oui:sony':
        ('', 'Sony Xperia Z4 Tablet', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,70,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1307,extcap:0000088001400040|oui:sony':
        ('', 'Sony Xperia Z4 Tablet', '2.4GHz'),

    'wifi4|probe:0,1,50,221(0050f2,4),wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:12,htmcs:000000ff,extcap:01000000|os:visiotv':
        ('', 'Vizio Smart TV', '2.4GHz'),
    'wifi|probe:0,1,50,45,127,221(0050f2,4),htcap:106e,htagg:12,htmcs:000000ff,wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:12,htmcs:000000ff,extcap:00000001|os:visiotv':
        ('', 'Vizio Smart TV', '2.4GHz'),
    'wifi|probe:0,1,50,48|assoc:0,1,50,221(0050f2,2),45,51,127,48,htcap:012c,htagg:1b,htmcs:000000ff|os:visiotv':
        ('', 'Vizio Smart TV', '2.4GHz'),

    'wifi|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2)|os:wii':
        ('BCM4318', 'Wii', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff|os:wii':
        ('BCM43362', 'Wii-U', '2.4GHz'),

    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|oui:withings':
        ('', 'Withings Scale', '2.4GHz'),

    'wifi|probe:0,1,3,45,50,127,htcap:010c,htagg:1b,htmcs:0000ffff|assoc:0,1,45,48,50,221(0050f2,2),htcap:010c,htagg:1b,htmcs:000000ff|oui:microsoft':
        ('', 'Xbox', '5GHz'),
    'wifi|probe:0,1,3,45,50,htcap:016e,htagg:03,htmcs:0000ffff|assoc:0,1,33,48,50,127,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:0000ffff,extcap:00000000|oui:microsoft':
        ('', 'Xbox', '5GHz'),

    'wifi4|probe:0,1,3,45,50,htcap:058f,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,221(0050f2,2),45,htcap:058d,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Marvell_88W8897', 'Xbox One', '2.4GHz'),
    'wifi4|probe:0,1,45,50,htcap:058f,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,221(0050f2,2),45,htcap:058d,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Marvell_88W8897', 'Xbox One', '2.4GHz'),
}


def make_v2_signature(sig):
  """Degrade a v3 / v4 signature to match the equivalent v2 signature.

  v3/v4 signatures include additional information from the Wifi MLME
  frames, based on experience of working with v1 and v2. Return a string
  which matches what the v2 signature would have been, by removing
  the additional information.

  This allows us to retain the base of v2 signatures.

  Args:
    sig: the text signature.

  Returns:
    a v2 signature.
  """
  new_sig = []
  for s in sig.split('|'):
    fields = s.split(',')
    new_fields = []
    for x in fields:
      if x.startswith('extcap:'):
        val = x[7:]
        # v2 sig includes only the first 4 bytes, swapped.
        swapped = ''
        if len(val) >= 8:
          swapped = swapped + val[6:8]
        if len(val) >= 6:
          swapped = swapped + val[4:6]
        if len(val) >= 4:
          swapped = swapped + val[2:4]
        if len(val) >= 2:
          swapped = swapped + val[0:2]
        x = 'extcap:' + swapped
      if x.startswith('cap') or x.startswith('txpow'):
        # new fields in v3, omit from v2 sig
        continue
      new_fields.append(x)
    new_sig.append(','.join(new_fields))
  new_sig[0] = 'wifi'
  return '|'.join(new_sig)


def v2only(field):
  """Return true if field only occurs in a v2 signature."""
  labels = set(['htagg', 'htmcs', 'vhtrxmcs', 'vhttxmcs', 'intwrk', 'extcap'])
  for l in labels:
    if l in field:
      return True
  return False


def make_v1_signature(sig):
  """Degrade a v2 signature to match the equivalent v1 signature.

  v2 signatures include additional information from the Wifi MLME
  frames, based on experience of working with v1. Return a string
  which matches what the v1 signature would have been, by removing
  the additional information.

  This allows us to retain the base of v1 signatures.

  Args:
    sig: the text signature.

  Returns:
    a v1 signature.
  """
  new_sig = []
  for s in sig.split('|'):
    fields = s.split(',')
    new_fields = [x for x in fields if not v2only(x)]
    new_sig.append(','.join(new_fields))
  return '|'.join(new_sig)


def performance_characteristics(signature):
  """Parse 802.11n/ac capabilities bitmasks from sig.

  Args:
    signature: the Wifi signature string.

  Returns:
    (standard, nss, width) where:
    standard: 802.11 standard like 'a/b/g', 'n', 'ac', etc.
    nss: number of spatial streams as an int, 0 for unknown.
    width: channel width as a string: '20', '40', '80', '160', '80+80', '??'
  """
  segments = signature.split('|')
  assoc = ''
  for segment in segments:
    # There are a few kindof broken devices which
    # include a vhtcap in their Probe even though
    # they are not 802.11ac devices. They didn't
    # notice because its the Association which
    # really counts. So only look at the Association.
    if segment.startswith('assoc:'):
      assoc = segment
  if not assoc:
    return ''
  fields = assoc.split(',')
  vht_nss = ht_nss = 0
  vht_width = ht_width = ''
  for field in fields:
    if field.startswith('vhtcap:'):
      try:
        bitmap = int(field[len('vhtcap:'):], base=16)
      except ValueError:
        vht_width = '??'
      else:
        scw = (bitmap >> 2) & 0x3
        widths = {0: '80', 1: '160', 2: '80+80'}
        vht_width = widths.get(scw, '??')
    elif field.startswith('htcap:'):
      try:
        bitmap = int(field[len('htcap:'):], base=16)
      except ValueError:
        ht_width = '??'
      else:
        ht_width = '40' if bitmap & 0x2 else '20'
    elif field.startswith('htmcs:'):
      try:
        mcs = int(field[len('htmcs:'):], base=16)
      except ValueError:
        pass
      else:
        ht_nss = ((mcs & 0x000000ff != 0) + (mcs & 0x0000ff00 != 0) +
                  (mcs & 0x00ff0000 != 0) + (mcs & 0xff000000 != 0))
    elif field.startswith('vhtrxmcs:'):
      try:
        mcs = int(field[len('vhtrxmcs:'):], base=16)
      except ValueError:
        pass
      else:
        vht_nss = ((mcs & 0x0003 != 0x0003) + (mcs & 0x000c != 0x000c) +
                   (mcs & 0x0030 != 0x0030) + (mcs & 0x00c0 != 0x00c0) +
                   (mcs & 0x0300 != 0x0300) + (mcs & 0x0c00 != 0x0c00) +
                   (mcs & 0x3000 != 0x3000) + (mcs & 0xc000 != 0xc000))
  if vht_width:
    return ('802.11ac', vht_nss, vht_width)
  if ht_width:
    return ('802.11n', ht_nss, ht_width)
  return ('802.11a/b/g', 1, '20')


def performance_info(standard, nss, width):
  """Return a readable string from output of performance_characteristics.

  Arguments:
    standard: 802.11 standard like 'a/b/g', 'n', 'ac', etc.
    nss: number of spatial streams as an int, 0 for unknown.
    width: channel width as a string: '20', '40', '80', '160', '80+80', '??'

  Returns:
    A string combining the arguments passed in.
  """
  return '%s n:%s,w:%s' % (standard, nss or '?', width)


def depersonalize_hostname(hostname):
  """Remove autopersonalization like 'Dentons-iPad', just return 'ipad'."""
  h = hostname.lower()
  if h.startswith('android'):
    return 'android'
  if 'appletv' in h or 'apple-tv' in h:
    return 'appletv'
  if 'ipad' in h:
    return 'ipad'
  if 'iphone' in h:
    return 'iphone'
  if 'ipod' in h:
    return 'ipod'
  return hostname


def identify_wifi_device(signature, mac):
  """Look up a wifi device by signature.

  Arguments:
    signature: a string of the form 'wifi4:probe:X,Y,Z|assoc:Q,R,S'
    mac: MAC address of the client, a string of the form 'qq:rr:ss:tt:uu:vv'

  Returns:
    A tuple describing the Wifi chipset and the type of device.

    If we know what it is, this will be (ChipName, ModelName, PerformanceInfo)

    If the signature is not known, calculate a SHA256 of the signature and
    return (SHA256, 'Unknown', PerformanceInfo)
  """

  v4_sig = signature.strip()
  v2_sig = make_v2_signature(v4_sig)
  v1_sig = make_v1_signature(v2_sig)
  perf = performance_info(*performance_characteristics(v4_sig))
  name = dhcp.LookupHostname(mac)
  opersys = dhcp.LookupOperatingSystem(mac)
  oui = ethernet.LookupOUI(mac)
  suffixes = []
  if name:
    suffixes.append('|name:' + depersonalize_hostname(name))
  for o in opersys:
    suffixes.append('|os:' + o)
  for o in oui:
    suffixes.append('|oui:' + o)
  suffixes.append('')
  for sig in [v4_sig, v2_sig, v1_sig]:
    for suffix in suffixes:
      result = database.get(sig + suffix, None)
      if result is not None:
        return (result[0], result[1], perf)

  # We have no idea what the client is.
  slug = 'SHA:' + hashlib.sha256(signature).hexdigest()
  return (slug, 'Unknown', perf)


if __name__ == '__main__':
  for k, v in database.iteritems():
    print 'SHA:' + hashlib.sha256(k).hexdigest() + ' ' + v[1]
    # Remove os, oui, etc qualifiers if present.
    a = k.split('|')
    if len(a) > 3:
      v4_sig = '|'.join(a[0:3])
      print 'SHA:' + hashlib.sha256(v4_sig).hexdigest() + ' ' + v[1] + ' (unqualified)'

      v2_sig = make_v2_signature(v4_sig)
      if v2_sig != v4_sig:
        print 'SHA:' + hashlib.sha256(v2_sig).hexdigest() + ' ' + v[1] + ' (unqualified, v2)'

      v1_sig = make_v1_signature(v2_sig)
      if v1_sig != v2_sig:
        print 'SHA:' + hashlib.sha256(v1_sig).hexdigest() + ' ' + v[1] + ' (unqualified, v1)'
