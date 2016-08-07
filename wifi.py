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


# Associated with each signature is a tuple:
# Field #1 = Genus = a human-recognizeable name for the device. If the device
#   has branding silkscreened on it (ex: "Samsung Galaxy S4" on the back), that
#   should probably be the Genus though this isn't rigidly adhered to.
#   We want someone reading the Genus to recognize it without thinking to
#   themselves "Wow, that is comically detailed."
# Field #2 = Species = the most specific designation we know of, such as the
#   version or model number or vintage. Not all entries will have a Species,
#   if the Genus is very specific we may not have any additional information
#   to put in the species.
#   We want someone reading the Species to think to themselves "Wow, that is
#   comically detailed."
# Field #3 = Frequency = band of this signature, '2.4GHz' or '5GHz'.

database = {
    'wifi4|probe:0,1,50,127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),extcap:00000080,wps:5042T|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('Alcatel OneTouch', 'Pop Astro', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|os:dashbutton':
        ('Amazon Dash Button', '', '2.4GHz'),

    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a0200000040|oui:amazon':
        ('Amazon Fire Phone', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a0200000040|oui:amazon':
        ('Amazon Fire Phone', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a0200000000|oui:amazon':
        ('Amazon Fire Phone', '', '2.4GHz'),

    'wifi4|probe:0,1,221(0050f2,4),221(506f9a,9),wps:AFTS|assoc:0,1,45,191,127,221(000c43,6),221(0050f2,2),htcap:008e,htagg:1f,htmcs:0000ffff,vhtcap:31c139b0,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:0000000000000040':
        ('Amazon Fire TV', '2015 (2nd gen)', '5GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),221(506f9a,9),htcap:01ed,htagg:1f,htmcs:0000ffff,extcap:00,wps:AFTS|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:008c,htagg:1f,htmcs:0000ffff,extcap:00000a02':
        ('Amazon Fire TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),221(506f9a,9),htcap:01ef,htagg:1f,htmcs:0000ffff,extcap:00,wps:AFTS|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:008c,htagg:1f,htmcs:0000ffff,extcap:00000a02':
        ('Amazon Fire TV', '2015 (2nd gen)', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:AFTS|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:008c,htagg:1f,htmcs:0000ffff,extcap:00000a02':
        ('Amazon Fire TV', '2015 (2nd gen)', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:007e,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(001018,2),221(0050f2,2),htcap:007e,htagg:1b,htmcs:0000ffff,txpow:e50d|oui:amazon':
        ('Amazon Fire TV Stick', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:003c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:003c,htagg:1b,htmcs:0000ffff,txpow:170c|oui:amazon':
        ('Amazon Fire TV Stick', '', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:11ee,htagg:02,htmcs:0000ffff|assoc:0,1,33,36,48,221(0050f2,2),45,127,htcap:11ee,htagg:02,htmcs:0000ffff,txpow:0e00,extcap:01|oui:amazon':
        ('Amazon Echo', '', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:01ac,htagg:02,htmcs:0000ffff|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:01ac,htagg:02,htmcs:0000ffff,extcap:01|oui:amazon':
        ('Amazon Echo', '', '2.4GHz'),

    'wifi4|probe:0,1,50|assoc:0,1,50,48,221(0050f2,2)|oui:amazon':
        ('Amazon Kindle', '', '2.4GHz'),
    'wifi4|probe:0,1,50|assoc:0,1,50,221(0050f2,2)|oui:amazon':
        ('Amazon Kindle', 'Keyboard 3', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:002c,htagg:01,htmcs:000000ff|assoc:0,1,50,45,48,221(0050f2,2),htcap:002c,htagg:01,htmcs:000000ff|oui:amazon':
        ('Amazon Kindle', '', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:1130,htagg:18,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),htcap:1130,htagg:18,htmcs:000000ff|oui:amazon':
        ('Amazon Kindle', 'Fire 7" (2011 edition)', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:KFFOWI|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('Amazon Kindle', 'Fire 7" (2015 edition)', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:081e,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:081e,htagg:1b,htmcs:0000ffff,txpow:0008|os:appletv1':
        ('Apple TV', '1st gen', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:181c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:181c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('Apple TV', '1st gen', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:581c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:581c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('Apple TV', '1st gen', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:181c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:581c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('Apple TV', '1st gen', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:581c,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:181c,htagg:1b,htmcs:0000ffff,txpow:1308|os:appletv1':
        ('Apple TV', '1st gen', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:080c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:080c,htagg:1b,htmcs:000000ff,txpow:1208|os:ios':
        ('Apple TV', '2nd gen', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff,txpow:1308|os:ios':
        ('Apple TV', '2nd gen', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|name:appletv':
        ('Apple TV', '3rd gen', '2.4GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|name:appletv':
        ('Apple TV', '3rd gen', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1907|os:ios':
        ('Apple TV', '3rd gen rev A', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1907|os:ios':
        ('Apple TV', '3rd gen rev A', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1a07|os:ios':
        ('Apple TV', '3rd gen rev A', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1a07|os:ios':
        ('Apple TV', '3rd gen rev A', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:appletv':
        ('Apple TV', '4th gen', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1502,extcap:0000000000000040|name:appletv':
        ('Apple TV', '4th gen', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff|os:ios':
        ('Apple Watch', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff|os:ios':
        ('Apple Watch', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,htcap:1030,htagg:18,htmcs:000000ff|assoc:0,1,50,46,48,45,221(0050f2,2),htcap:1030,htagg:18,htmcs:000000ff|oui:barnes&noble':
        ('Barnes & Noble Nook', 'Color', '2.4GHz'),

    'wifi4|probe:0,1,50,221(0050f2,4)|assoc:0,1,50,45,221(0050f2,2),48,htcap:000c,htagg:1b,htmcs:000000ff|os:wemo':
        ('Belkin WeMo', 'Switch', '2.4GHz'),

    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:BLU_DASH_M|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('BLU Dash', 'M', '2.4GHz'),

    'wifi4|probe:0,1,50,127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),extcap:00000080,wps:BLU_STUDIO_5_0_C_HD|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:0100008000c6':
        ('BLU Studio', '5.0.C HD', '2.4GHz'),

    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:BLU_STUDIO_C_SUPER_CAMERA|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('BLU Studio', 'C Super Camera', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:112c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:112c,htagg:19,htmcs:000000ff|os:brotherprinter':
        ('Brother Printer', '', '2.4GHz'),

    # MX410, probably others
    'wifi4|probe:0,1,3,45,50,htcap:007e,htagg:00,htmcs:000000ff|assoc:0,1,45,48,50,221(0050f2,2),htcap:000c,htagg:1b,htmcs:000000ff|os:canonprinter':
        ('Canon Printer', '', '2.4GHz'),
    # MX492, probably others
    'wifi4|probe:0,1,3,45,50,htcap:007e,htagg:00,htmcs:000000ff|assoc:0,1,48,50,221(0050f2,2),45,htcap:000c,htagg:1b,htmcs:000000ff|os:canonprinter':
        ('Canon Printer', '', '2.4GHz'),
    # MX492 has been seen to send these massive Probe packets. Likely other models, too.
    'wifi4|probe:64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,127,11,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,extcap:|assoc:0,1,48,50,221(0050f2,2),45,htcap:000c,htagg:1b,htmcs:000000ff|os:canonprinter':
        ('Canon Printer', '', '2.4GHz'),
    'wifi4|probe:0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0|assoc:0,1,48,50,221(0050f2,2),45,htcap:000c,htagg:1b,htmcs:000000ff|os:canonprinter':
        ('Canon Printer', '', '2.4GHz'),

    'wifi4|probe:0,1,45,191,htcap:11e2,htagg:17,htmcs:0000ffff,vhtcap:038071a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,48,45,127,191,221(0050f2,2),htcap:11e6,htagg:17,htmcs:0000ffff,vhtcap:038001a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000000000000040|os:chromeos':
        ('Chromebook', 'Pixel 2', '5GHz'),
    'wifi4|probe:0,1,45,191,htcap:11e2,htagg:17,htmcs:0000ffff,vhtcap:038071a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,48,45,127,191,221(0050f2,2),htcap:11ee,htagg:17,htmcs:0000ffff,vhtcap:038001a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000000000000040|os:chromeos':
        ('Chromebook', 'Pixel 2', '5GHz'),
    'wifi4|probe:0,1,45,191,htcap:11e2,htagg:17,htmcs:0000ffff,vhtcap:038071a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,127,191,221(0050f2,2),htcap:11e6,htagg:17,htmcs:0000ffff,vhtcap:038001a0,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1600,extcap:0000000000000040|os:chromeos':
        ('Chromebook', 'Pixel 2', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:11e2,htagg:17,htmcs:0000ffff|assoc:0,1,50,48,45,127,221(0050f2,2),htcap:11a4,htagg:17,htmcs:0000ffff,extcap:0000000000000040|os:chromeos':
        ('Chromebook', 'Pixel 2', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:11e2,htagg:17,htmcs:0000ffff|assoc:0,1,50,48,45,127,221(0050f2,2),htcap:11ac,htagg:17,htmcs:0000ffff,extcap:0000000000000040|os:chromeos':
        ('Chromebook', 'Pixel 2', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:11ef,htagg:1b,htmcs:0000ffff|assoc:0,1,48,45,221(0050f2,2),htcap:11ef,htagg:1b,htmcs:0000ffff|os:chromeos':
        ('Chromebook', 'HP 14', '5GHz'),
    'wifi4|probe:0,1,50,3,45,htcap:11ef,htagg:1b,htmcs:0000ffff|assoc:0,1,50,48,45,221(0050f2,2),htcap:11ef,htagg:1b,htmcs:0000ffff|os:chromeos':
        ('Chromebook', 'HP 14', '2.4GHz'),

    'wifi4|probe:0,1,45,50,htcap:016e,htagg:03,htmcs:0000ffff|assoc:0,1,48,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:0000ffff,extcap:00':
        ('Chromebook', 'Samsung 11.6"', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:016e,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:0000ffff,extcap:00':
        ('Chromebook', 'Samsung 11.6"', '2.4GHz'),

    'wifi4|probe:0,1,3,45,50,htcap:0120,htagg:03,htmcs:00000000|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:000000ff,extcap:0000000000000140|oui:google':
        ('Chromecast', 'v1', '2.4GHz'),
    'wifi4|probe:0,1,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,48,127,221(0050f2,2),45,191,htcap:006e,htagg:03,htmcs:000000ff,vhtcap:33c07030,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,extcap:0400000000000140|oui:google':
        ('Chromecast', 'v2', '5GHz'),
    'wifi4|probe:0,1,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,33,36,48,127,221(0050f2,2),45,191,htcap:006e,htagg:03,htmcs:000000ff,vhtcap:33c07030,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,extcap:0400000000000140|oui:google':
        ('Chromecast', 'v2', '5GHz'),
    'wifi4|probe:0,1,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,33,36,48,127,221(0050f2,2),45,191,htcap:006e,htagg:03,htmcs:000000ff,vhtcap:33c07030,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,txpow:1308,extcap:0400000000000140|oui:google':
        ('Chromecast', 'v2', '5GHz'),
    'wifi4|probe:0,1,3,45,50,127,191,htcap:0062,htagg:03,htmcs:00000000,vhtcap:33c07030,vhtrxmcs:0124fffc,vhttxmcs:0124fffc,extcap:0000000000000040|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:002c,htagg:03,htmcs:000000ff,extcap:0000000000000140|oui:google':
        ('Chromecast', 'v2', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:007c,htagg:1a,htmcs:0000ffff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:007c,htagg:1a,htmcs:0000ffff,txpow:1408|os:directv':
        ('DirecTV', 'HR44 or HD54', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:107c,htagg:1a,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:107c,htagg:1a,htmcs:0000ffff,txpow:1608|os:directv':
        ('DirecTV', 'HR44 or HF54', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:106e,htagg:01,htmcs:000000ff|assoc:0,1,45,33,36,48,221(0050f2,2),htcap:106e,htagg:01,htmcs:000000ff,txpow:0e00|oui:dropcam':
        ('Dropcam', '', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:002c,htagg:01,htmcs:000000ff|assoc:0,1,50,45,48,221(0050f2,2),htcap:002c,htagg:01,htmcs:000000ff|oui:dropcam':
        ('Dropcam', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,htcap:002c,htagg:01,htmcs:000000ff|assoc:0,1,50,45,48,221(0050f2,2),htcap:002c,htagg:01,htmcs:000000ff|oui:ecobee':
        ('ecobee thermostat', '', '2.4GHz'),

    'wifi4|probe:0,1,3,45,50,htcap:0162,htagg:00,htmcs:000000ff|assoc:0,1,45,48,127,50,221(0050f2,2),htcap:016e,htagg:1b,htmcs:000000ff,extcap:00|os:epsonprinter':
        ('Epson Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:182c,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:182c,htagg:1b,htmcs:000000ff|os:epsonprinter':
        ('Epson Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2)|os:epsonprinter':
        ('Epson Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff|os:epsonprinter':
        ('Epson Printer', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:102c,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:102c,htagg:1b,htmcs:000000ff|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:0160,htagg:03,htmcs:000000ff|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:016c,htagg:03,htmcs:000000ff,extcap:00|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:0160,htagg:03,htmcs:000000ff|assoc:0,1,45,48,127,50,221(0050f2,2),htcap:016c,htagg:03,htmcs:000000ff,extcap:00000000|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(0050f2,2),221(506f9a,9),htcap:0020,htagg:1a,htmcs:000000ff|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:0060,htagg:03,htmcs:000000ff|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:006c,htagg:03,htmcs:000000ff,extcap:00|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,3,45,50,127,htcap:010c,htagg:1b,htmcs:0000ffff,extcap:00|assoc:0,1,45,48,127,50,221(0050f2,2),htcap:016c,htagg:1b,htmcs:000000ff,extcap:00|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2)|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),
    'wifi4|probe:0,1,3,45,50,127,htcap:010c,htagg:1b,htmcs:0000ffff,extcap:00|assoc:0,1,48,50,221(0050f2,2)|os:hpprinter':
        ('HP Printer', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:htc':
        ('HTC One', '', '5GHz'),
    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:03800032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:htc':
        ('HTC One', '', '5GHz'),
    'wifi4|probe:0,1,50,45,127,221(001018,2),221(00904c,51),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1408|oui:htc':
        ('HTC One', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1408|oui:htc':
        ('HTC One', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:HTC_VLE_U|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('HTC One', 'S', '2.4GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:HTC_VLE_U|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('HTC One', 'S', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),191,127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a820040,wps:HTC_One_M8|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a8201400040':
        ('HTC One', 'M8', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a820040,wps:HTC_One_M8|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a8201400040':
        ('HTC One', 'M8', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,127,107,221(0050f2,4),221(506f9a,10),221(506f9a,9),221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:000000800040,wps:HTC_One_M8|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:1e0d,extcap:0000008001400040':
        ('HTC One', 'M8', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a820040,wps:HTC_One_M8|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a8201400000':
        ('HTC One', 'M8', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a8201400000|oui:htc':
        ('HTC One', 'M8', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(0050f2,4),221(506f9a,10),221(506f9a,9),221(506f9a,16),htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a820040,wps:831C|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a8201400000':
        ('HTC One', 'M8, Sprint edition', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a820040,wps:HTC6525LVW|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:160d,extcap:00000a8201400000':
        ('HTC One', 'M8, Verizon edition', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,107,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e009,extcap:0000088001400040|oui:htc':
        ('HTC One', 'M9', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:1063,htagg:17,htmcs:000000ff,extcap:0000088001400040|assoc:0,1,50,33,36,45,127,107,221(001018,2),221(0050f2,2),htcap:1063,htagg:17,htmcs:000000ff,txpow:1309,extcap:000008800140|oui:htc':
        ('HTC One', 'M9', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:1063,htagg:17,htmcs:000000ff,extcap:0000088001400040|assoc:0,1,50,33,36,45,127,107,221(001018,2),221(0050f2,2),htcap:1063,htagg:17,htmcs:000000ff,txpow:1309,extcap:000008800140|oui:htc':
        ('HTC One', 'M9', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,10),221(506f9a,9),221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:000008800140,wps:0PJA2|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e009,extcap:000008800140':
        ('HTC One', 'M9, Sprint edition', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(506f9a,16),221(0050f2,8),221(001018,2),htcap:1063,htagg:17,htmcs:000000ff,extcap:000008800140,wps:0PJA2|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:1063,htagg:17,htmcs:000000ff,txpow:1309,extcap:000008800140':
        ('HTC One', 'M9, Sprint edition', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff|oui:htc':
        ('HTC One', 'V', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:0130,htagg:18,htmcs:000000ff|assoc:0,1,48,45,221(0050f2,2),htcap:013c,htagg:18,htmcs:000000ff|oui:htc':
        ('HTC One', 'X', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:0130,htagg:18,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),htcap:013c,htagg:18,htmcs:000000ff|oui:htc':
        ('HTC One', 'X', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:080c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:080c,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('iPad', '1st or 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,221(001018,2),htcap:080c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),htcap:080c,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('iPad', '1st or 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0800,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0800,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('iPad', '1st or 2nd gen', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('iPad', '1st gen', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:1800,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1800,htagg:1b,htmcs:000000ff,txpow:1008|os:ios':
        ('iPad', '1st gen', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff,txpow:1108|os:ios':
        ('iPad', '2nd gen', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:1800,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1800,htagg:1b,htmcs:000000ff,txpow:1108|os:ios':
        ('iPad', '2nd gen', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|os:ios':
        ('iPad', '3rd gen', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:180f|os:ios':
        ('iPad', '3rd gen', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff,txpow:150c|os:ios':
        ('iPad', '3rd gen', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e708|os:ios':
        ('iPad', '4th gen or Air 1st gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e708|os:ios':
        ('iPad', '4th gen or Air 1st gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e708|os:ios':
        ('iPad', '4th gen or Air 1st gen', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1805|os:ios':
        ('iPad', '4th gen or Air 1st gen', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1805|os:ios':
        ('iPad', '4th gen or Air 1st gen', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad', 'Air 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad', 'Air 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad', 'Air 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad', 'Air 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad', 'Air 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad', 'Air 2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad', 'Air 2nd gen', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1502,extcap:0000000000000040|os:ios':
        ('iPad', 'Air 2nd gen', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1502,extcap:0000000000000040|os:ios':
        ('iPad', 'Air 2nd gen', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1807|os:ios':
        ('iPad Mini', '1st gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1807|os:ios':
        ('iPad Mini', '1st gen', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1605|os:ios':
        ('iPad Mini', '1st gen', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1605|os:ios':
        ('iPad Mini', '1st gen', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e606|os:ios':
        ('iPad Mini', '2nd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e606|os:ios':
        ('iPad Mini', '2nd gen', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1603|os:ios':
        ('iPad Mini', '2nd gen', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1603|os:ios':
        ('iPad Mini', '2nd gen', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e001|os:ios':
        ('iPad Mini', '3rd gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff,txpow:e001|os:ios':
        ('iPad Mini', '3rd gen', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1201|os:ios':
        ('iPad Mini', '3rd gen', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc,htagg:1b,htmcs:0000ffff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff,txpow:1201|os:ios':
        ('iPad Mini', '3rd gen', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad Mini', '4th gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|name:ipad':
        ('iPad Mini', '4th gen', '5GHz'),

    'wifi4|probe:0,1,3,50|assoc:0,1,48,50|os:ios':
        ('iPhone 2', '', '2.4GHz'),

    'wifi4|probe:0,1,3,50|assoc:0,1,48,50,221(0050f2,2)|os:ios':
        ('iPhone 3', '', '2.4GHz'),

    'wifi4|probe:0,1,50,3,221(001018,2)|assoc:0,1,48,50,221(001018,2),221(0050f2,2)|os:ios':
        ('iPhone 3GS', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:1800,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1800,htagg:1b,htmcs:000000ff|os:ios':
        ('iPhone 4', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff|os:ios':
        ('iPhone 4s', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100,htagg:19,htmcs:000000ff|os:ios':
        ('iPhone 4s', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1504|os:ios':
        ('iPhone 5', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1504|os:ios':
        ('iPhone 5', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1403|os:ios':
        ('iPhone 5', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1403|os:ios':
        ('iPhone 5', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('iPhone 5c', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('iPhone 5c', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('iPhone 5c', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1704|os:ios':
        ('iPhone 5c', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1704|os:ios':
        ('iPhone 5c', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1704|os:ios':
        ('iPhone 5c', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1603|os:ios':
        ('iPhone 5s', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1603|os:ios':
        ('iPhone 5s', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1603|os:ios':
        ('iPhone 5s', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('iPhone 5s', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000804|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1805|os:ios':
        ('iPhone 5s', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6/6+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6/6+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(00904c,51),221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6/6+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(00904c,51),221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6/6+', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1302,extcap:0000000000000040|os:ios':
        ('iPhone 6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1302,extcap:0000000000000040|os:ios':
        ('iPhone 6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(00904c,51),221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1302,extcap:0000000000000040|os:ios':
        ('iPhone 6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0400000000000040|os:ios':
        ('iPhone 6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1402,extcap:0000000000000040|os:ios':
        ('iPhone 6+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1402,extcap:0000000000000040|os:ios':
        ('iPhone 6+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(00904c,51),221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1402,extcap:0000000000000040|os:ios':
        ('iPhone 6+', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0400088400000040|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f815832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e002,extcap:0400000000000040|os:ios':
        ('iPhone 6s/6s+', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:000000ff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(00904c,51),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(00904c,51),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0400088400000040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:000000ff,txpow:1202,extcap:0000000000000040|os:ios':
        ('iPhone 6s/6s+', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:0063,htagg:17,htmcs:000000ff,vhtcap:0f805032,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0400088400000040|assoc:0,1,33,36,45,127,221(001018,2),221(0050f2,2),htcap:0063,htagg:17,htmcs:000000ff,txpow:e002,extcap:000008|os:ios':
        ('iPhone SE', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021,htagg:17,htmcs:000000ff,extcap:0400088400000040|assoc:0,1,50,33,36,45,127,221(001018,2),221(0050f2,2),htcap:0021,htagg:17,htmcs:000000ff,txpow:1402,extcap:0000000000000040|os:ios':
        ('iPhone SE', '', '2.4GHz'),

    'wifi4|probe:0,1,3,50|assoc:0,1,48,50|os:ipodtouch1':
        ('iPod Touch', '1st or 2nd gen', '2.4GHz'),

    'wifi4|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2),221(0050f2,2)|name:ipod':
        ('iPod Touch', '3rd gen', '2.4GHz'),

    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c,htagg:1b,htmcs:000000ff|os:ios':
        ('iPod Touch', '4th gen', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1504|os:ios':
        ('iPod Touch', '5th gen', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:1504|os:ios':
        ('iPod Touch', '5th gen', '5GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1706|os:ios':
        ('iPod Touch', '5th gen', '2.4GHz'),
    'wifi4|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062,htagg:1a,htmcs:000000ff,extcap:00000004|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1706|os:ios':
        ('iPod Touch', '5th gen', '2.4GHz'),

    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000000040|oui:lg':
        ('LG G2', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:11ff|oui:lg':
        ('LG G2', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:11ff|oui:lg':
        ('LG G2', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),191,127,107,221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:000000800040|assoc:0,1,33,36,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:170d,extcap:00000a8201400040|oui:lg':
        ('LG G3', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,127,107,221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:000000800040|assoc:0,1,33,36,48,45,221(0050f2,2),191,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:170d,extcap:00000a8201400040|oui:lg':
        ('LG G3', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(506f9a,16),htcap:012c,htagg:03,htmcs:000000ff,extcap:000000800040|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a8201400000|oui:lg':
        ('LG G3', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(506f9a,16),htcap:012c,htagg:03,htmcs:000000ff,extcap:000000800040|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a8201400000|oui:lg':
        ('LG G3', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,107,221(506f9a,16),htcap:016e,htagg:03,htmcs:000000ff,extcap:000000800040|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a8201400000|oui:lg':
        ('LG G3', '', '2.4GHz'),

    'wifi4|probe:0,1,3,45,127,107,191,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:1d01,extcap:0000008001400040|oui:lg':
        ('LG G4', '', '5GHz'),
    'wifi4|probe:0,1,50,45,127,107,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000088001400040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1001,extcap:000000800140|oui:lg':
        ('LG G4', '', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:LGL16C|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('LG Lucky', '', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:LGMS323|assoc:0,1,50,48,45,221(0050f2,2),221(004096,3),htcap:012c,htagg:03,htmcs:000000ff':
        ('LG Optimus', 'L70', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:LG_D415|assoc:0,1,50,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a0200000000':
        ('LG Optimus', 'L90', '2.4GHz'),

    'wifi4|probe:0,1,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:LG_V400|assoc:0,1,33,36,48,70,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000':
        ('LG Pad', 'v400', '5GHz'),

    'wifi4|probe:0,1,45,191,221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009|os:lgtv':
        ('LG Smart TV', '', '5GHz'),
    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,wps:_|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009|os:lgtv':
        ('LG Smart TV', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000000000000040,wps:_|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209|os:lgtv':
        ('LG Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:11ac,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:11ac,htagg:16,htmcs:0000ffff,txpow:140a,extcap:0000000000000040|os:lgtv':
        ('LG Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,wps:_|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209|os:lgtv':
        ('LG Smart TV', '', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:LGLS660|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('LG Tribute', '', '2.4GHz'),

    'wifi4|probe:0,1,50|assoc:0,1,50,48,221(0050f2,2)|oui:lifx':
        ('LIFX LED light bulb', '', '2.4GHz'),

    'wifi4|probe:0,1,45,50,htcap:0102,htagg:03,htmcs:0000ffff|assoc:0,1,48,221(0050f2,2),45,htcap:010e,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Microsoft Surface', 'RT', '5GHz'),
    'wifi4|probe:0,1,45,50,htcap:0102,htagg:03,htmcs:0000ffff|assoc:0,1,33,36,48,221(0050f2,2),45,htcap:010e,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Microsoft Surface', 'RT', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:0102,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Microsoft Surface', 'RT', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a0200000000|oui:motorola':
        ('Moto E', '2nd gen', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000|oui:motorola':
        ('Moto E', '2nd gen', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:motorola':
        ('Moto G or Moto X', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,48,45,221(0050f2,2),191,127,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a02|oui:motorola':
        ('Moto X', '', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,48,45,221(0050f2,2),191,127,127,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31805120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:00000a02|oui:motorola':
        ('Moto X', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),191,htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffe,vhttxmcs:0000fffe|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:motorola':
        ('Moto X', '', '2.4GHz'),

    'wifi4|probe:0,1,127,45,htcap:01ef,htagg:03,htmcs:0000ffff,extcap:00000a0201|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004040|oui:motorola':
        ('Moto X', 'Style', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004040|oui:motorola':
        ('Moto X', 'Style', '5GHz'),
    'wifi4|probe:0,1,50,127,45,htcap:01ef,htagg:03,htmcs:0000ffff,extcap:00000a0201|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:00000a020100000040|oui:motorola':
        ('Moto X', 'Style', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:00000a0201|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:00000a020100000040|oui:motorola':
        ('Moto X', 'Style', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:082c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:082c,htagg:1b,htmcs:000000ff,txpow:0a08|oui:motorola':
        ('Motorola Xoom', '', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:182c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:182c,htagg:1b,htmcs:000000ff,txpow:0e08|oui:motorola':
        ('Motorola Xoom', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,htcap:0130,htagg:18,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),htcap:013c,htagg:18,htmcs:000000ff|oui:nest':
        ('Nest Thermostat', 'v1 or v2', '2.4GHz'),
    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0f09|oui:nest':
        ('Nest Thermostat', 'v3', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff,txpow:150b|oui:nest':
        ('Nest Thermostat', 'v3', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('Nexus 4', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('Nexus 4', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,33,36,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff,txpow:130d':
        ('Nexus 4', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 4', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('Nexus 4', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a02':
        ('Nexus 4', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a02|oui:lg':
        ('Nexus 4', '', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,vhtcap:31811120,vhtrxmcs:01b2fffc,vhttxmcs:01b2fffc,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('Nexus 4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('Nexus 4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:lg':
        ('Nexus 4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:lg':
        ('Nexus 4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:lg':
        ('Nexus 4', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e003,extcap:0000000000000040|oui:lg':
        ('Nexus 5', '', '5GHz'),
    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e003,extcap:0000000000000040|oui:lg':
        ('Nexus 5', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000000000000040|assoc:0,1,33,36,45,127,191,221(001018,2),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e003,extcap:0000000000000040|oui:lg':
        ('Nexus 5', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,70,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e003,extcap:0000008001400040|oui:lg':
        ('Nexus 5', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1303|oui:lg':
        ('Nexus 5', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(001018,2),221(00904c,51),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1303|oui:lg':
        ('Nexus 5', '', '2.4GHz'),

    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a0201000040|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:0000000000000040|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,127,extcap:00000a020100004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338001b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,48,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,127,45,191,htcap:01ad,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,127,extcap:00000a020100004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:000000000000004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:339071b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,txpow:1e08,extcap:000000000000004080|oui:lg':
        ('Nexus 5X', '', '5GHz'),
    'wifi4|probe:0,1,50,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a0201000040|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:0000000000000000|oui:lg':
        ('Nexus 5X', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|oui:lg':
        ('Nexus 5X', '', '2.4GHz'),
    'wifi4|probe:0,1,50,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|oui:lg':
        ('Nexus 5X', '', '2.4GHz'),
    'wifi4|probe:0,1,50,127,45,191,htcap:01ef,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,txpow:1e08,extcap:000000000000000080|oui:lg':
        ('Nexus 5X', '', '2.4GHz'),
    'wifi4|probe:0,1,50,127,45,191,htcap:01ad,htagg:03,htmcs:0000ffff,vhtcap:338061b2,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a020100004080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,txpow:1e08,extcap:000000000000000080|oui:lg':
        ('Nexus 5X', '', '2.4GHz'),
    'wifi4|probe:0,1,50,127,extcap:00000a020100004080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,txpow:1e08,extcap:000000000000000080|oui:lg':
        ('Nexus 5X', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,htcap:01ad,htagg:03,htmcs:0000ffff,extcap:000000000000000080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:01ad,htagg:03,htmcs:0000ffff,txpow:1e08,extcap:000000000000000080|oui:lg':
        ('Nexus 5X', '', '2.4GHz'),

    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140,wps:Nexus_6|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:000008800140':
        ('Nexus 6', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140,wps:Nexus_6|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:000008800140':
        ('Nexus 6', '', '5GHz'),
    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,wps:Nexus_6|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009':
        ('Nexus 6', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040,wps:Nexus_6|assoc:0,1,33,36,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040':
        ('Nexus 6', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140,wps:Nexus_6|assoc:0,1,33,36,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:000008800140':
        ('Nexus 6', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040,wps:Nexus_6|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040':
        ('Nexus 6', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_6|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('Nexus 6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_6|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('Nexus 6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_6|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('Nexus 6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,wps:Nexus_6|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209':
        ('Nexus 6', '', '2.4GHz'),

    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,wps:Nexus_6P|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002':
        ('Nexus 6P', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040,wps:Nexus_6P|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0000088001400040':
        ('Nexus 6P', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_6P|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1402,extcap:0000088001400040':
        ('Nexus 6P', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|oui:asus':
        ('Nexus 7', '2012 edition', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02|oui:asus':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:016e,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,8),htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02|oui:asus':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,45,htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),127,htcap:016e,htagg:03,htmcs:000000ff,txpow:1e0d,extcap:00000a02|oui:asus':
        ('Nexus 7', '2013 edition', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),127,221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02':
        ('Nexus 7', '2013 edition', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:asus':
        ('Nexus 7', '2013 edition', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:asus':
        ('Nexus 7', '2013 edition', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,extcap:00000a02|oui:asus':
        ('Nexus 7', '2013 edition', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,htagg:03,htmcs:000000ff,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff':
        ('Nexus 7', '2013 edition', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140,wps:Nexus_9|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:000008800140':
        ('Nexus 9', '', '5GHz'),
    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,wps:Nexus_9|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009':
        ('Nexus 9', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_9|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1309,extcap:000008800140':
        ('Nexus 9', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_9|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:150b,extcap:000008800140':
        ('Nexus 9', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_9|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1309,extcap:000008800140':
        ('Nexus 9', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,wps:Nexus_9|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1309':
        ('Nexus 9', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:01fe,htagg:1b,htmcs:0000ffff|assoc:0,1,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe,htagg:1b,htmcs:0000ffff|oui:samsung':
        ('Nexus 10', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:01bc,htagg:1b,htmcs:0000ffff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc,htagg:1b,htmcs:0000ffff|oui:samsung':
        ('Nexus 10', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040,wps:Nexus_Player|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040':
        ('Nexus Player', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140,wps:Nexus_Player|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('Nexus Player', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:Nexus_Player|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140':
        ('Nexus Player', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,51,127,htcap:012c,htagg:1b,htmcs:000000ff,extcap:0100000000000040|assoc:0,1,48,50,221(0050f2,2),45,51,127,htcap:012c,htagg:1b,htmcs:000000ff,extcap:0100000000000040|os:windows-phone':
        ('Nokia Lumia', '635', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:012c,htagg:1b,htmcs:000000ff|assoc:0,1,48,50,221(0050f2,2),45,51,127,htcap:012c,htagg:1b,htmcs:000000ff,extcap:0100000000000040|os:windows-phone':
        ('Nokia Lumia', '635', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,48,45,221(0050f2,2),htcap:016e,htagg:03,htmcs:000000ff|os:windows-phone':
        ('Nokia Lumia', '920', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff|os:windows-phone':
        ('Nokia Lumia', '920', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000008001000040,wps:SHIELD_Android_TV|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0000008001000040':
        ('NVidia SHIELD', 'Android TV', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040,wps:SHIELD_Android_TV|assoc:0,1,33,36,48,70,45,127,191,221(00904c,51),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0000088001400040':
        ('NVidia SHIELD', 'Android TV', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000008001000040,wps:SHIELD_Android_TV|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1207,extcap:0000008001000040':
        ('NVidia SHIELD', 'Android TV', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040,wps:SHIELD_Android_TV|assoc:0,1,50,33,36,48,70,45,127,221(00904c,51),221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1207,extcap:0000088001400040':
        ('NVidia SHIELD', 'Android TV', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000|oui:oneplus':
        ('Oneplus', 'X', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,4),htcap:11ee,htagg:02,htmcs:0000ffff,wps:WPS_STA|assoc:0,1,33,36,48,221(0050f2,2),45,127,htcap:11ee,htagg:02,htmcs:0000ffff,txpow:0b00,extcap:01|os:panasonictv':
        ('Panasonic TV', '', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),htcap:01ac,htagg:02,htmcs:0000ffff,wps:WPS_STA|assoc:0,1,50,221(0050f2,2),45,127,htcap:01ac,htagg:02,htmcs:0000ffff,extcap:01|os:panasonictv':
        ('Panasonic TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,48|assoc:0,1,33,36,50,221(0050f2,2),45,221(00037f,1),221(00037f,4),48,htcap:1004,htagg:1b,htmcs:0000ffff,txpow:0f0f|os:panasonictv':
        ('Panasonic TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),htcap:01ad,htagg:02,htmcs:0000ffff,wps:WPS_SUPPLICANT_STATION|assoc:0,1,50,45,48,221(0050f2,2),htcap:01ad,htagg:02,htmcs:0000ffff|os:panasonictv':
        ('Panasonic TV', '', '2.4GHz'),

    'wifi4|probe:0,1,50|assoc:0,1,50,48,221(005043,1)|os:playstation':
        ('Playstation', '3 or 4', '2.4GHz'),

    'wifi4|probe:0,1,3,50|assoc:0,1,33,48,50,221(0050f2,2),45,htcap:010c,htagg:03,htmcs:0000ffff,txpow:1209|os:playstation':
        ('Playstation', '4', '2.4GHz'),
    'wifi4|probe:0,1,3,50|assoc:0,1,48,50,221(0050f2,2),45,htcap:112c,htagg:03,htmcs:0000ffff,txpow:0f06|os:playstation':
        ('Playstation', '4', '2.4GHz'),
    'wifi4|probe:0,1,3,50|assoc:0,1,33,48,50,221(0050f2,2),45,htcap:112c,htagg:03,htmcs:0000ffff,txpow:0f06|os:playstation':
        ('Playstation', '4', '2.4GHz'),
    'wifi4|probe:0,1,3,50|assoc:0,1,33,48,50,221(0050f2,2),45,htcap:010c,htagg:03,htmcs:0000ffff,txpow:0f06|os:playstation':
        ('Playstation', '4', '2.4GHz'),
    'wifi4|probe:0,1,3,50|assoc:0,1,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:0000ffff|os:playstation':
        ('Playstation', '4', '2.4GHz'),

    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:RCT6303W87DK|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('RCA Viking Tablet', 'RCA 10 Viking Pro', '2.4GHz'),

    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:RCT6773W42B|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('RCA Voyager Tablet', 'v1', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:RCT6773W42B|assoc:0,1,50,45,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('RCA Voyager Tablet', 'v1', '2.4GHz'),

    # RCA Voyager-II
    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:RCT6773W22B|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('RCA Voyager Tablet', 'v2', '2.4GHz'),

    # Roku model 1100, 2500 and LT model 2450
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|os:roku':
        ('Roku', 'HD or LT', '2.4GHz'),

    # Roku model 1101
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:186e,htagg:1a,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:186e,htagg:1a,htmcs:0000ffff,txpow:1208|os:roku':
        ('Roku', 'HD-XR', '2.4GHz'),

    # Roku Streaming Stick model 3400X
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:187c,htagg:1a,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:187c,htagg:1a,htmcs:0000ffff,txpow:1208|os:roku':
        ('Roku', 'Streaming Stick 3400X', '2.4GHz'),

    # Roku Streaming Stick model 3600
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:19bc,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,50,45,127,221(001018,2),221(0050f2,2),htcap:19bc,htagg:16,htmcs:0000ffff,txpow:140a,extcap:0000000000000040|os:roku':
        ('Roku', 'Streaming Stick 3600', '2.4GHz'),

    # Roku 1 models 2000, 2050, 2100, and XD
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:186e,htagg:1a,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:186e,htagg:1a,htmcs:0000ffff,txpow:1308|os:roku':
        ('Roku', '1', '2.4GHz'),

    # Roku 1 model 2710 and Roku LT model 2700
    'wifi4|probe:0,1,50,3,45,221(001018,2),221(00904c,51),htcap:0020,htagg:1a,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020,htagg:1a,htmcs:000000ff|os:roku':
        ('Roku', '1 or LT', '2.4GHz'),

    # Roku 2 models 3000, 3050, 3100, and Roku LT model 2400
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff|os:roku':
        ('Roku', '2 or LT', '2.4GHz'),

    # Roku 2 model 2720
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:187c,htagg:1a,htmcs:0000ffff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:187c,htagg:1a,htmcs:0000ffff|os:roku':
        ('Roku', '2', '2.4GHz'),

    # Roku 3 model 4230, 4200, 4200X, 4230X, Roku Streaming Stick model 3500, Roku 2 model 4210X
    'wifi4|probe:0,1,45,127,221(001018,2),221(00904c,51),htcap:09bc,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:09bc,htagg:16,htmcs:0000ffff,txpow:100a,extcap:0000000000000040|os:roku':
        ('Roku', '2 or 3 or Streaming Stick', '5GHz'),
    'wifi4|probe:0,1,3,45,127,221(001018,2),221(00904c,51),htcap:09bc,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:09bc,htagg:16,htmcs:0000ffff,txpow:100a,extcap:0000000000000040|os:roku':
        ('Roku', '2 or 3 or Streaming Stick', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:19bc,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:19bc,htagg:16,htmcs:0000ffff,txpow:140a,extcap:0000000000000040|os:roku':
        ('Roku', '2 or 3 or Streaming Stick', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:193c,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:193c,htagg:16,htmcs:0000ffff,txpow:140a,extcap:0000000000000040|os:roku':
        ('Roku', '2 or 3 or Streaming Stick', '2.4GHz'),

    # Roku 3 model 4230RW
    'wifi4|probe:0,1,45,127,221(001018,2),221(00904c,51),htcap:093c,htagg:16,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:093c,htagg:16,htmcs:0000ffff,txpow:110a,extcap:0000000000000040|os:roku':
        ('Roku', '3', '5GHz'),

    # Roku 4 model 4400 or Roku TV NP-YW
    'wifi4|probe:0,1,45,127,191,221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,199,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1109,extcap:0000000000000040|os:roku':
        ('Roku', '4 or TV', '5GHz'),
    'wifi4|probe:0,1,45,191,221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,191,199,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1109|os:roku':
        ('Roku', '4 or TV', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1209|os:roku':
        ('Roku', '4 or TV', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1209|os:roku':
        ('Roku', '4 or TV', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,htcap:0020,htagg:01,htmcs:000000ff|assoc:0,1,50,45,61,48,221(0050f2,2),htcap:0020,htagg:01,htmcs:000000ff|oui:samsung':
        ('Samsung Galaxy', 'Mini', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:010c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:010c,htagg:19,htmcs:000000ff,txpow:0f09':
        ('Samsung Galaxy Nexus', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:010c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:010c,htagg:19,htmcs:000000ff,txpow:0f09':
        ('Samsung Galaxy Nexus', '', '5GHz'),
    'wifi4|probe:0,1,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('Samsung Galaxy Nexus', '', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff,txpow:1209':
        ('Samsung Galaxy Nexus', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff,wps:Galaxy_Nexus|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff,txpow:1209':
        ('Samsung Galaxy Nexus', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:120a|oui:samsung':
        ('Samsung Galaxy Nexus', '', '2.4GHz'),

    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f09|oui:samsung':
        ('Samsung Galaxy Note or S2+', '', '5GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:1409|oui:samsung':
        ('Samsung Galaxy Note', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('Samsung Galaxy Note II', '', '5GHz'),
    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('Samsung Galaxy Note II', '', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('Samsung Galaxy Note II', '', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:0e09|oui:samsung':
        ('Samsung Galaxy Note II', '', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020,htagg:1a,htmcs:000000ff,txpow:1209|oui:samsung':
        ('Samsung Galaxy Note II', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020,htagg:1a,htmcs:000000ff,txpow:1209|oui:samsung':
        ('Samsung Galaxy Note II', '', '2.4GHz'),

    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:samsung':
        ('Samsung Galaxy Note 3', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,htagg:17,htmcs:000000ff,vhtcap:0f805932,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e008,extcap:0000000000000040|oui:samsung':
        ('Samsung Galaxy Note 3', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1208|oui:samsung':
        ('Samsung Galaxy Note 3', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:112d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:112d,htagg:17,htmcs:000000ff,txpow:1208|oui:samsung':
        ('Samsung Galaxy Note 3', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,107,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy Note 4', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,70,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy Note 4', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1509,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy Note 4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1509,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy Note 4', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:00080f8401400040|assoc:0,1,33,36,48,45,127,191,199,221(00904c,4),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1102,extcap:0000000000000040|oui:samsung':
        ('Samsung Galaxy Note 5', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:00080f8401400040|assoc:0,1,33,36,48,70,45,127,191,199,221(00904c,4),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1202,extcap:0000000000000040|oui:samsung':
        ('Samsung Galaxy Note 5', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:00080f840140|assoc:0,1,33,36,48,70,45,191,199,221(00904c,4),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1202|oui:samsung':
        ('Samsung Galaxy Note 5', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:00080f8401400040|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1202|oui:samsung':
        ('Samsung Galaxy Note 5', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('Samsung Galaxy S2', '', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('Samsung Galaxy S2', '', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:120a|oui:samsung':
        ('Samsung Galaxy S2 or Infuse', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:120a|oui:samsung':
        ('Samsung Galaxy S2 or Infuse', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:1209|oui:samsung':
        ('Samsung Galaxy S2+', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1409|oui:samsung':
        ('Samsung Galaxy S3', '', '5GHz'),
    'wifi4|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0062,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062,htagg:1a,htmcs:000000ff,txpow:1409|oui:samsung':
        ('Samsung Galaxy S3', '', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020,htagg:1a,htmcs:000000ff,txpow:1409|oui:samsung':
        ('Samsung Galaxy S3', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000000040|oui:samsung':
        ('Samsung Galaxy S4', '', '5GHz'),
    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000000040|oui:samsung':
        ('Samsung Galaxy S4', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088000400040|assoc:0,1,33,36,48,45,127,107,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000008000400040|oui:samsung':
        ('Samsung Galaxy S4', '', '5GHz'),
    'wifi4|probe:0,1,3,45,127,107,191,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000088000400040|assoc:0,1,33,36,48,45,127,107,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000008000400040|oui:samsung':
        ('Samsung Galaxy S4', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000400040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000400040|oui:samsung':
        ('Samsung Galaxy S4', '', '5GHz'),
    'wifi4|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,extcap:0000080000400040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,htagg:17,htmcs:000000ff,vhtcap:0f805832,vhtrxmcs:0000fffe,vhttxmcs:0000fffe,txpow:e001,extcap:0000000000400040|oui:samsung':
        ('Samsung Galaxy S4', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000088000400040|assoc:0,1,33,36,48,50,45,127,107,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1201,extcap:000000800040|oui:samsung':
        ('Samsung Galaxy S4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000080000000040|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1201|oui:samsung':
        ('Samsung Galaxy S4', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,107,221(506f9a,16),221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d,htagg:17,htmcs:000000ff,extcap:0000088000400040|assoc:0,1,33,36,48,50,45,127,107,221(001018,2),221(0050f2,2),htcap:102d,htagg:17,htmcs:000000ff,txpow:1201,extcap:000000800040|oui:samsung':
        ('Samsung Galaxy S4', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,107,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e20b,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy S5', '', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140|assoc:0,1,33,36,48,45,127,107,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e20b,extcap:000008800140|oui:samsung':
        ('Samsung Galaxy S5', '', '5GHz'),
    'wifi4|probe:0,1,45,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e20b|oui:samsung':
        ('Samsung Galaxy S5', '', '5GHz'),
    'wifi4|probe:0,1,45,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:9b40fffa,vhttxmcs:18dafffa|assoc:0,1,33,36,48,45,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:9b40fffa,vhttxmcs:18dafffa,txpow:e20b|oui:samsung':
        ('Samsung Galaxy S5', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:000008800140|assoc:0,1,33,36,48,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e20b,extcap:000008800140|oui:samsung':
        ('Samsung Galaxy S5', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140|assoc:0,1,50,33,36,48,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140|oui:samsung':
        ('Samsung Galaxy S5', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140|oui:samsung':
        ('Samsung Galaxy S5', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:000008800140|assoc:0,1,50,33,36,48,70,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209,extcap:000008800140|oui:samsung':
        ('Samsung Galaxy S5', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy S6', '', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy S6', '', '5GHz'),
    'wifi4|probe:0,1,45,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002|oui:samsung':
        ('Samsung Galaxy S6', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1402,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy S6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1402,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy S6', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1402,extcap:0000088001400040|oui:samsung':
        ('Samsung Galaxy S6', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:0163,htagg:17,htmcs:0000ffff,vhtcap:0f907032,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:00080f8401400040|assoc:0,1,33,36,48,70,45,127,191,199,221(00904c,4),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1102,extcap:0000000000000040|oui:samsung':
        ('Samsung Galaxy S7', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:00080f8401400040|assoc:0,1,50,33,36,48,70,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1402|oui:samsung':
        ('Samsung Galaxy S7', '', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:00080f840140|assoc:0,1,50,33,36,48,70,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1402|oui:samsung':
        ('Samsung Galaxy S7', '', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9178b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:00080f840140|assoc:0,1,33,36,48,70,45,191,199,221(00904c,4),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f9118b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:1102|oui:samsung':
        ('Samsung Galaxy S7 Edge', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(00904c,4),221(0050f2,8),221(001018,2),htcap:1163,htagg:17,htmcs:0000ffff,extcap:00080f8401400040|assoc:0,1,50,33,36,48,70,45,221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1302|oui:samsung':
        ('Samsung Galaxy S7 Edge', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(001018,2),221(00904c,51),htcap:082c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:082c,htagg:1b,htmcs:000000ff,txpow:0f08|oui:samsung':
        ('Samsung Galaxy Tab', '', '5GHz'),
    'wifi4|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:182c,htagg:1b,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:182c,htagg:1b,htmcs:000000ff,txpow:1208|oui:samsung':
        ('Samsung Galaxy Tab', '', '2.4GHz'),

    'wifi4|probe:0,1,45,50,htcap:0162,htagg:03,htmcs:00000000|assoc:0,1,48,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:000000ff,extcap:0400000000000140|oui:samsung':
        ('Samsung Galaxy Tab 3', '', '5GHz'),
    'wifi4|probe:0,1,45,50,htcap:0162,htagg:03,htmcs:00000000|assoc:0,1,33,36,48,127,221(0050f2,2),45,htcap:016e,htagg:03,htmcs:000000ff,txpow:1208,extcap:0400000000000140|oui:samsung':
        ('Samsung Galaxy Tab 3', '', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:0162,htagg:03,htmcs:00000000|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:000000ff,extcap:0000000000000140|oui:samsung':
        ('Samsung Galaxy Tab 3', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,33,36,48,45,221(0050f2,2),221(004096,3),htcap:016e,htagg:03,htmcs:000000ff,txpow:170d|oui:samsung':
        ('Samsung Galaxy Tab 4', '', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),221(004096,3),htcap:012c,htagg:03,htmcs:000000ff|oui:samsung':
        ('Samsung Galaxy Tab 4', '', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0c0a|oui:samsung':
        ('Samsung Galaxy Tab 10.1', '', '5GHz'),
    'wifi4|probe:0,1,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:000c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c,htagg:19,htmcs:000000ff,txpow:0c0a|oui:samsung':
        ('Samsung Galaxy Tab 10.1', '', '5GHz'),
    'wifi4|probe:0,1,50,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff,wps:_|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff,txpow:0f0a|oui:samsung':
        ('Samsung Galaxy Tab 10.1', '', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(001018,2),htcap:0020,htagg:1f,htmcs:000000ff|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:0020,htagg:1f,htmcs:000000ff,txpow:1203|os:tizen':
        ('Samsung Watch', 'Gear S2', '2.4GHz'),

    'wifi4|probe:0,1,45,htcap:11ee,htagg:02,htmcs:0000ffff|assoc:0,1,45,127,33,36,48,221(0050f2,2),htcap:11ee,htagg:02,htmcs:0000ffff,txpow:1100,extcap:01|os:samsungtv':
        ('Samsung Smart TV', '', '5GHz'),
    # UN55JS9000, probably more
    'wifi4|probe:0,1,45,127,191,221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000000000000040|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000000000000040|os:tizen':
        ('Samsung Smart TV', '', '5GHz'),
    # LED75
    'wifi4|probe:0,1,45,221(002d25,32),htcap:11ee,htagg:02,htmcs:0000ffff|assoc:0,1,33,36,221(0050f2,2),45,127,htcap:11ee,htagg:02,htmcs:0000ffff,txpow:0e00,extcap:01|os:samsungtv':
        ('Samsung Smart TV', '', '5GHz'),
    # UN46ES7100F
    'wifi4|probe:0,1,45,221(002d25,32),htcap:11ee,htagg:02,htmcs:0000ffff|assoc:0,1,33,36,48,221(0050f2,2),45,127,htcap:11ee,htagg:02,htmcs:0000ffff,txpow:0e00,extcap:01|os:samsungtv':
        ('Samsung Smart TV', '', '5GHz'),
    # UN40JU6500
    'wifi4|probe:0,1,45,191,221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009|os:tizen':
        ('Samsung Smart TV', '', '5GHz'),
    'wifi4|probe:0,1,50,45,htcap:01ac,htagg:02,htmcs:0000ffff|assoc:0,1,50,45,127,48,221(0050f2,2),htcap:01ac,htagg:02,htmcs:0000ffff,extcap:01|os:samsungtv':
        ('Samsung Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(002d25,32),htcap:01ac,htagg:02,htmcs:0000ffff|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:01ac,htagg:02,htmcs:0000ffff,extcap:01|os:samsungtv':
        ('Samsung Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:0120,htagg:02,htmcs:000000ff|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:0120,htagg:02,htmcs:000000ff,extcap:01|os:samsungtv':
        ('Samsung Smart TV', '', '2.4GHz'),
    # UN40JU6500, probably more
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000000000000040|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209|os:tizen':
        ('Samsung Smart TV', '', '2.4GHz'),
    # UN40JU6500, probably more
    'wifi4|probe:0,1,50,3,45,221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1209|os:tizen':
        ('Samsung Smart TV', '', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,htcap:11ef,htagg:1b,htmcs:0000ffff|assoc:0,1,50,48,45,221(0050f2,2),htcap:11ef,htagg:1b,htmcs:0000ffff|oui:sling':
        ('Slingbox', '500', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,4),htcap:11ee,htagg:02,htmcs:0000ffff,wps:Sony_BRAVIA|assoc:0,1,33,36,48,221(0050f2,2),45,127,htcap:11ee,htagg:02,htmcs:0000ffff,txpow:0500,extcap:01':
        ('Sony Bravia TV', '', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:11ef,htagg:13,htmcs:0000ffff,wps:BRAVIA_2015|assoc:0,1,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:01ef,htagg:13,htmcs:0000ffff,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '5GHz'),
    'wifi4|probe:0,1,221(0050f2,4),221(506f9a,10),221(506f9a,9),wps:BRAVIA_2015|assoc:0,1,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:01ef,htagg:13,htmcs:0000ffff,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '5GHz'),
    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:11ef,htagg:13,htmcs:0000ffff,vhtcap:31c139b0,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,wps:BRAVIA_4K_2015|assoc:0,1,45,191,127,221(000c43,6),221(0050f2,2),48,127,htcap:006f,htagg:13,htmcs:0000ffff,vhtcap:31c001b0,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '5GHz'),
    'wifi4|probe:0,1,45,221(0050f2,4),htcap:11ee,htagg:02,htmcs:0000ffff,wps:Sony_BRAVIA|assoc:0,1,33,36,48,221(0050f2,2),45,127,htcap:11ee,htagg:02,htmcs:0000ffff,txpow:0c00,extcap:01':
        ('Sony Bravia TV', '', '5GHz'),
    'wifi4|probe:0,1,221(0050f2,4),221(506f9a,10),221(506f9a,9),wps:BRAVIA_4K_2015|assoc:0,1,45,191,127,221(000c43,6),221(0050f2,2),48,127,htcap:006f,htagg:13,htmcs:0000ffff,vhtcap:31c001b0,vhtrxmcs:030cfffa,vhttxmcs:030cfffa,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '5GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:01ad,htagg:02,htmcs:0000ffff,wps:Sony_BRAVIA|assoc:0,1,50,45,127,48,221(0050f2,2),htcap:01ad,htagg:02,htmcs:0000ffff,extcap:01':
        ('Sony Bravia TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,221(0050f2,4),htcap:01ac,htagg:02,htmcs:0000ffff,wps:Sony_BRAVIA|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:01ac,htagg:02,htmcs:0000ffff,extcap:01':
        ('Sony Bravia TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:01ed,htagg:13,htmcs:0000ffff,extcap:00,wps:BRAVIA_2015|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:008c,htagg:13,htmcs:0000ffff,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:11ef,htagg:13,htmcs:0000ffff,extcap:00,wps:BRAVIA_2015|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:01ad,htagg:13,htmcs:0000ffff,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,10),221(506f9a,9),wps:BRAVIA_4K_2015|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:008c,htagg:13,htmcs:0000ffff,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,10),221(506f9a,9),wps:BRAVIA_2015|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:01ad,htagg:13,htmcs:0000ffff,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:11ef,htagg:13,htmcs:0000ffff,extcap:00,wps:BRAVIA_4K_2015|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,127,htcap:008c,htagg:13,htmcs:0000ffff,extcap:00000a02':
        ('Sony Bravia TV', '2015 model', '2.4GHz'),

    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffc,vhttxmcs:0000fffc|assoc:0,1,33,36,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff|oui:sony':
        ('Sony Xperia', 'Z Ultra', '5GHz'),
    'wifi4|probe:0,1,3,45,221(0050f2,8),191,htcap:016e,htagg:03,htmcs:000000ff,vhtcap:31800120,vhtrxmcs:0000fffc,vhttxmcs:0000fffc|assoc:0,1,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff|oui:sony':
        ('Sony Xperia', 'Z Ultra', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000|oui:sony':
        ('Sony Xperia', 'Z Ultra', '2.4GHz'),
    'wifi4|probe:0,1,50,45,htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c,htagg:03,htmcs:000000ff,txpow:170d,extcap:00000a0200000000|oui:sony':
        ('Sony Xperia', 'Z Ultra', '2.4GHz'),

    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815032,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,70,45,127,107,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815032,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0000088001400040|oui:sony':
        ('Sony Xperia', 'Z4 or Z5', '5GHz'),
    'wifi4|probe:0,1,45,127,107,191,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000088001400040|assoc:0,1,33,36,48,70,45,127,107,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0000088001400040|oui:sony':
        ('Sony Xperia', 'Z4 or Z5', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,107,221(506f9a,16),221(0050f2,8),221(001018,2),htcap:002d,htagg:17,htmcs:0000ffff,extcap:0000088001400040|assoc:0,1,50,33,36,48,70,45,127,107,221(001018,2),221(0050f2,2),htcap:002d,htagg:17,htmcs:0000ffff,txpow:1307,extcap:0000088001400040|oui:sony':
        ('Sony Xperia', 'Z4 or Z5', '2.4GHz'),

    # TIVO-849
    'wifi4|probe:0,1,45,127,191,221(001018,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000008001|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,htagg:17,htmcs:0000ffff,vhtcap:0f815832,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e009,extcap:0000008001|os:tivo':
        ('TiVo', 'BOLT', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(00904c,51),221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000008001000040|assoc:0,1,33,36,48,45,127,191,221(00904c,51),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0000008001000040|os:tivo':
        ('TiVo', 'BOLT', '5GHz'),
    'wifi4|probe:0,1,45,127,191,221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,extcap:0000008001000040|assoc:0,1,33,36,48,45,127,191,221(00904c,51),221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e007,extcap:0000008001000040|os:tivo':
        ('TiVo', 'BOLT', '5GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(00904c,51),221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:0000008001000040|assoc:0,1,50,33,36,48,45,127,221(00904c,51),221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1207,extcap:0000008001000040|os:tivo':
        ('TiVo', 'BOLT', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,127,221(001018,2),htcap:01ad,htagg:17,htmcs:0000ffff,extcap:0000008001000040|assoc:0,1,50,33,36,48,45,127,221(00904c,51),221(001018,2),221(0050f2,2),htcap:01ad,htagg:17,htmcs:0000ffff,txpow:1207,extcap:0000008001000040|os:tivo':
        ('TiVo', 'BOLT', '2.4GHz'),

    # TIVO-746
    'wifi4|probe:0,1,50,221(00904c,51),45,48,htcap:13ce,htagg:1b,htmcs:0000ffff|assoc:0,1,33,36,50,221(0050f2,2),221(00904c,51),45,221(002163,1),221(002163,4),48,htcap:13ce,htagg:1b,htmcs:0000ffff,txpow:0f0f|os:tivo':
        ('TiVo', 'Premiere Series 4', '2.4GHz'),
    # TIVO-846
    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:107c,htagg:19,htmcs:0000ffff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:107c,htagg:19,htmcs:0000ffff,txpow:1208|os:tivo':
        ('TiVo', 'Roamio', '2.4GHz'),
    # TIVO-848
    'wifi4|probe:0,1,50|assoc:0,1,50,221(0050f2,2),45,51,48,htcap:01ac,htagg:1b,htmcs:0000ffff|os:tivo':
        ('TiVo', 'Roamio Plus', '2.4GHz'),
    # TiVo-652 HD and HD XL, TIVO-648, and TIVO-750 have the same signature
    'wifi4|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2)|os:tivo':
        ('TiVo', 'Series3 or Series4', '2.4GHz'),

    'wifi4|probe:0,1,50,45,221(0050f2,4),htcap:106e,htagg:13,htmcs:0000ffff,wps:Ralink_Wireless_Linux_Client|assoc:0,1,45,127,221(000c43,6),221(0050f2,2),48,htcap:000e,htagg:13,htmcs:0000ffff,extcap:00|oui:toshiba':
        ('Toshiba Smart TV', '', '5GHz'),
    'wifi4|probe:0,1,221(0050f2,4),wps:Ralink_Wireless_Linux_Client|assoc:0,1,45,127,221(000c43,6),221(0050f2,2),48,htcap:000e,htagg:13,htmcs:0000ffff,extcap:00|oui:toshiba':
        ('Toshiba Smart TV', '', '5GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:13,htmcs:0000ffff,extcap:01|oui:toshiba':
        ('Toshiba Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),htcap:106e,htagg:13,htmcs:0000ffff,extcap:00,wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:13,htmcs:0000ffff,extcap:01|oui:toshiba':
        ('Toshiba Smart TV', '', '2.4GHz'),

    # P602ui-B3
    'wifi4|probe:0,1,50,221(0050f2,4),wps:_|assoc:0,33,36,1,48,221(0050f2,2),45,127,htcap:106e,htagg:1f,htmcs:0000ffff,txpow:150d,extcap:0000000000000000|os:viziotv':
        ('Vizio Smart TV', '', '5GHz'),
    # P602ui-B3
    'wifi4|probe:0,1,50|assoc:0,33,36,1,48,221(0050f2,2),45,127,htcap:106e,htagg:1f,htmcs:0000ffff,txpow:150d,extcap:0000000000000000|os:viziotv':
        ('Vizio Smart TV', '', '5GHz'),
    'wifi4|probe:0,1,45,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,wps:_|assoc:0,1,33,36,48,45,191,221(001018,2),221(0050f2,2),htcap:01ef,htagg:17,htmcs:0000ffff,vhtcap:0f8159b2,vhtrxmcs:0000fffa,vhttxmcs:0000fffa,txpow:e002|oui:vizio':
        ('Vizio SmartCast TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:12,htmcs:000000ff,extcap:01000000|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:13,htmcs:000000ff,extcap:01|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),htcap:106e,htagg:12,htmcs:000000ff,extcap:00,wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:12,htmcs:000000ff,extcap:01000000|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,45,127,221(0050f2,4),htcap:106e,htagg:13,htmcs:000000ff,extcap:00,wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,127,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:13,htmcs:000000ff,extcap:01|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,221(0050f2,4),wps:Ralink_Wireless_Linux_Client|assoc:0,1,50,45,221(000c43,6),221(0050f2,2),48,htcap:000c,htagg:13,htmcs:000000ff|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),
    'wifi4|probe:0,1,50,48|assoc:0,1,50,221(0050f2,2),45,51,127,48,htcap:012c,htagg:1b,htmcs:000000ff,extcap:01|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),
    # P602ui-B3
    'wifi4|probe:0,1,50,221(0050f2,4),wps:_|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:122c,htagg:1f,htmcs:0000ffff,extcap:0000000000000000|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),
    # P602ui-B3
    'wifi4|probe:0,1,50|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:122c,htagg:1f,htmcs:0000ffff,extcap:0000000000000000|os:viziotv':
        ('Vizio Smart TV', '', '2.4GHz'),

    'wifi4|probe:0,1,3,45,221(0050f2,8),htcap:016e,htagg:03,htmcs:000000ff|assoc:0,1,33,36,45,221(0050f2,2),htcap:016e,htagg:03,htmcs:000000ff,txpow:110d|oui:vizio':
        ('Vizio Tablet', 'XR6P', '5GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff|oui:vizio':
        ('Vizio Tablet', 'XR6P', '2.4GHz'),

    'wifi4|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2)|os:wii':
        ('Wii', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(00904c,51),htcap:100c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(00904c,51),221(0050f2,2),htcap:100c,htagg:19,htmcs:000000ff|os:wii':
        ('Wii-U', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020,htagg:1a,htmcs:000000ff|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020,htagg:1a,htmcs:000000ff,txpow:1009|oui:wink':
        ('Wink Hub', '', '2.4GHz'),

    'wifi4|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c,htagg:19,htmcs:000000ff|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c,htagg:19,htmcs:000000ff|oui:withings':
        ('Withings Scale', '', '2.4GHz'),

    'wifi4|probe:0,1,3,45,50,127,htcap:010c,htagg:1b,htmcs:0000ffff,extcap:00|assoc:0,1,45,48,50,221(0050f2,2),htcap:010c,htagg:1b,htmcs:000000ff|oui:microsoft':
        ('Xbox', '', '5GHz'),
    'wifi4|probe:0,1,3|assoc:0,1,48,33,36,221(0050f2,2),txpow:1405|oui:microsoft':
        ('Xbox', '', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:016e,htagg:03,htmcs:0000ffff|assoc:0,1,33,48,50,127,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:0000ffff,txpow:1208,extcap:0000000000000140|oui:microsoft':
        ('Xbox', '', '5GHz'),
    'wifi4|probe:0,1,50|assoc:0,1,3,33,36,50,221(0050f2,2),45,221(00037f,1),221(00037f,4),48,htcap:104c,htagg:00,htmcs:000000ff,txpow:0f0f|oui:microsoft':
        ('Xbox', '', '2.4GHz'),
    'wifi4|probe:0,1,50,48|assoc:0,1,3,33,36,50,221(0050f2,2),45,221(00037f,1),221(00037f,4),48,htcap:104c,htagg:00,htmcs:0000ffff,txpow:0f0f|oui:microsoft':
        ('Xbox', '', '2.4GHz'),
    'wifi4|probe:0,1,45,50,htcap:058f,htagg:03,htmcs:0000ffff|assoc:0,1,33,36,48,221(0050f2,2),45,htcap:058f,htagg:03,htmcs:0000ffff,txpow:1208|oui:microsoft':
        ('Xbox', '', '2.4GHz'),
    'wifi4|probe:0,1,3,50|assoc:0,1,33,48,50,127,127,221(0050f2,2),45,htcap:012c,htagg:03,htmcs:0000ffff,txpow:1208,extcap:0000000000000140|oui:microsoft':
        ('Xbox', '', '2.4GHz'),

    'wifi4|probe:0,1,45,50,htcap:058f,htagg:03,htmcs:0000ffff|assoc:0,1,33,36,221(0050f2,2),45,htcap:058f,htagg:03,htmcs:0000ffff,txpow:1208|oui:microsoft':
        ('Xbox', 'One', '5GHz'),
    'wifi4|probe:0,1,3,45,50,htcap:058f,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,221(0050f2,2),45,htcap:058d,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Xbox', 'One', '2.4GHz'),
    'wifi4|probe:0,1,45,50,htcap:058f,htagg:03,htmcs:0000ffff|assoc:0,1,48,50,221(0050f2,2),45,htcap:058d,htagg:03,htmcs:0000ffff|oui:microsoft':
        ('Xbox', 'One', '2.4GHz'),
    'wifi4|probe:0,1|assoc:0,1,50,45,127,221(000c43,0),221(0050f2,2),33,48,htcap:008d,htagg:02,htmcs:0000ffff,txpow:0805,extcap:0100000000000000|oui:microsoft':
        ('Xbox', 'One', '2.4GHz'),
    'wifi4|probe:0,1,50|assoc:0,1,50,45,127,221(000c43,0),221(0050f2,2),33,48,htcap:008d,htagg:02,htmcs:0000ffff,txpow:0805,extcap:0100000000000000|oui:microsoft':
        ('Xbox', 'One', '2.4GHz'),

    'wifi4|probe:0,1,50,3,45,221(0050f2,8),htcap:012c,htagg:03,htmcs:000000ff|assoc:0,1,50,33,48,70,45,221(0050f2,2),htcap:012c,htagg:03,htmcs:000000ff,txpow:170d|oui:xiaomi':
        ('Xiaomi Redmi', '3', '2.4GHz'),

    'wifi4|probe:0,1,45,221(0050f2,8),191,127,htcap:016f,htagg:1f,htmcs:000000ff,vhtcap:33907132,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,extcap:040000000000004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:016f,htagg:1f,htmcs:000000ff,vhtcap:33907132,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,txpow:1408,extcap:040000000000004080|oui:xiaomi':
        ('Xiaomi Mi', '5', '5GHz'),
    'wifi4|probe:0,1,45,191,3,127,htcap:016f,htagg:df,htmcs:000000ff,vhtcap:33800132,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,extcap:04000a020100004080|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:016f,htagg:1f,htmcs:000000ff,vhtcap:33907132,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,txpow:1408,extcap:040000000000004080|oui:xiaomi':
        ('Xiaomi Mi', '5', '5GHz'),
    'wifi4|probe:0,1,50,45,191,3,127,htcap:016f,htagg:df,htmcs:000000ff,vhtcap:33800132,vhtrxmcs:0186fffe,vhttxmcs:0186fffe,extcap:04000a020100004080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012d,htagg:1f,htmcs:000000ff,txpow:1408,extcap:040000000000000080|oui:xiaomi':
        ('Xiaomi Mi', '5', '2.4GHz'),
    'wifi4|probe:0,1,50,3,45,221(0050f2,8),127,htcap:012d,htagg:1f,htmcs:000000ff,extcap:040000000000000080|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012d,htagg:1f,htmcs:000000ff,txpow:1408,extcap:040000000000000080|oui:xiaomi':
        ('Xiaomi Mi', '5', '2.4GHz'),

    'wifi4|probe:0,1,50,221(0050f2,4),221(506f9a,9),wps:Z820|assoc:0,1,50,45,48,127,221(0050f2,2),htcap:1172,htagg:03,htmcs:000000ff,extcap:01':
        ('ZTE Obsidian', '', '2.4GHz'),
}


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
    A tuple describing the model of the device.

    If we know what it is, this will be (Genus, Species, PerformanceInfo)

    If the signature is not known, calculate a SHA256 of the signature and
    return (SHA256, 'Unknown', PerformanceInfo)
  """

  sig = signature.strip()
  perf = performance_info(*performance_characteristics(sig))
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
  for suffix in suffixes:
    result = database.get(sig + suffix, None)
    if result is not None:
      return (result[0], result[1], perf)

  # We have no idea what the client is.
  slug = 'SHA:' + hashlib.sha256(signature).hexdigest()
  return (slug, 'Unknown', perf)


if __name__ == '__main__':
  for k, v in database.iteritems():
    name = v[0] + ' ' + v[1]
    print 'SHA:' + hashlib.sha256(k).hexdigest() + ' ' + name
    # Remove os, oui, etc qualifiers if present.
    a = k.split('|')
    if len(a) > 3:
      sig = '|'.join(a[0:3])
      print 'SHA:' + hashlib.sha256(sig).hexdigest() + ' ' + name + ' (unqualified)'
