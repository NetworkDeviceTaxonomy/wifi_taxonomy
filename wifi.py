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


import dhcp
import ethernet
import hashlib


initialized = {}


database = {
    'wifi|probe:0,1,45,221(001018,2),221(00904c,51),htcap:081e|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:081e':
        ('BCM94321', 'Apple TV (1st gen)', '5GHz'),
    'wifi|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:581c|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:581c':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:181c|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:581c':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:581c|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:181c':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:181c|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:181c':
        ('BCM94321', 'Apple TV (1st gen)', '2.4GHz'),

    'wifi|probe:0,1,45,221(001018,2),221(00904c,51),htcap:080c|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:080c|name:Apple-TV':
        ('BCM4329', 'Apple TV (2nd gen)', '5GHz'),
    'wifi|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c|name:Apple-TV':
        ('BCM4329', 'Apple TV (2nd gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062|name:Apple-TV':
        ('BCM4330', 'Apple TV (3rd gen)', '5GHz'),
    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062|name:Apple-TV':
        ('BCM4330', 'Apple TV (3rd gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020|name:Apple-TV':
        ('BCM4330', 'Apple TV (3rd gen)', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020|name:Apple-TV':
        ('BCM4330', 'Apple TV (3rd gen)', '2.4GHz'),

    'wifi|probe:0,1,45,htcap:11ef|assoc:0,1,48,45,221(0050f2,2),htcap:11ef|os:chromeos':
        ('AR5822', 'Chromebook 14" HP', '5GHz'),
    'wifi|probe:0,1,50,3,45,htcap:11ef|assoc:0,1,50,48,45,221(0050f2,2),htcap:11ef|os:chromeos':
        ('AR5822', 'Chromebook 14" HP', '2.4GHz'),

    'wifi|probe:0,1,45,50,htcap:016e|assoc:0,1,48,127,221(0050f2,2),45,htcap:016e|os:chromeos':
        ('AR9382', 'Chromebook 11" Samsung', '5GHz'),
    'wifi|probe:0,1,3,45,50,htcap:016e|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:016e|os:chromeos':
        ('AR9382', 'Chromebook 11" Samsung', '2.4GHz'),

    'wifi|probe:0,1,3,45,50,htcap:0120|assoc:0,1,48,50,127,221(0050f2,2),45,htcap:012c|name:Chromecast':
        ('Marvell_88W8797', 'Chromecast', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(506f9a,16),221(001018,2),221(00904c,51),htcap:006f,vhtcap:03800032|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,vhtcap:03800032':
        ('BCM4335', 'HTC One', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(506f9a,16),221(001018,2),221(00904c,51),htcap:102d|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d':
        ('BCM4335', 'HTC One', '2.4GHz'),

    'wifi|probe:0,1,3,45,221(0050f2,8),191,127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:016e,vhtcap:31800120,wps:HTC_One_M8|assoc:0,1,33,36,48,70,45,221(0050f2,2),191,127,htcap:016e,vhtcap:31800120':
        ('WCN3680', 'HTC One M8', '5GHz'),
    'wifi|probe:0,1,50,3,45,221(0050f2,8),127,107,221(0050f2,4),221(506f9a,9),221(506f9a,16),htcap:012c,wps:HTC_One_M8|assoc:0,1,50,33,48,70,45,221(0050f2,2),127,htcap:012c':
        ('WCN3680', 'HTC One M8', '2.4GHz'),

    'wifi|probe:0,1,45,221(001018,2),221(00904c,51),htcap:080c|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:080c':
        ('BCM4329', 'iPad (1st/2nd gen)', '5GHz'),
    'wifi|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:180c':
        ('BCM4329', 'iPad (1st/2nd gen)', '2.4GHz'),

    'wifi|probe:0,1,45,3,221(001018,2),221(00904c,51),htcap:0100|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100':
        ('BCM4330', 'iPad (3rd gen)', '5GHz'),
    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100':
        ('BCM4330', 'iPad (3rd gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe':
        ('BCM4334', 'iPad (4th gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc':
        ('BCM4334', 'iPad (4th gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062|name:ipad':
        ('BCM4334', 'iPad Mini (1st gen)', '5GHz'),
    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062|name:ipad':
        ('BCM4334', 'iPad Mini (1st gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020|name:ipad':
        ('BCM4334', 'iPad Mini (1st gen)', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020|name:ipad':
        ('BCM4334', 'iPad Mini (1st gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe':
        ('BCM43241', 'iPad Air (1st gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc':
        ('BCM43241', 'iPad Air (1st gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,vhtcap:0f815832|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,vhtcap:0f815832':
        ('BCM4335', 'iPad Air (2nd gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4335', 'iPad Air (2nd gen)', '2.4GHz'),

    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:0100|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0100':
        ('BCM4330', 'iPhone 4S', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062|name:iphone':
        ('BCM4334', 'iPhone 5/5S', '5GHz'),
    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062|name:iphone':
        ('BCM4334', 'iPhone 5/5S', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020|name:iphone':
        ('BCM4334', 'iPhone 5/5S', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020|name:iphone':
        ('BCM4334', 'iPhone 5/5S', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062':
        ('BCM4334', 'iPhone 5/5S or iPad Mini (1st gen)', '5GHz'),
    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0062|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062':
        ('BCM4334', 'iPhone 5/5S or iPad Mini (1st gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,70,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020':
        ('BCM4334', 'iPhone 5/5S or iPad Mini (1st gen)', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:0020|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0020':
        ('BCM4334', 'iPhone 5/5S or iPad Mini (1st gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:0063,vhtcap:0f805032|assoc:0,1,33,36,48,70,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,vhtcap:0f805032':
        ('BCM4339', 'iPhone 6/6+', '5GHz'),
    'wifi|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:0063,vhtcap:0f805032|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:0063,vhtcap:0f805032':
        ('BCM4339', 'iPhone 6/6+', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:0021':
        ('BCM4339', 'iPhone 6/6+', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:0021|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:0021':
        ('BCM4339', 'iPhone 6/6+', '2.4GHz'),

    'wifi|probe:0,1,3,50|assoc:0,1,48,50|name:iPod':
        ('Marvell_W8686B22', 'iPod Touch 1st gen', '2.4GHz'),

    'wifi|probe:0,1,50,221(001018,2)|assoc:0,1,48,50,221(001018,2),221(0050f2,2)|name:iPod-touch':
        ('BCM4329', 'iPod Touch 3rd gen', '2.4GHz'),

    'wifi|probe:0,1,50,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:102d|oui:lg':
        ('BCM4335', 'LG G2', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:102d|oui:lg':
        ('BCM4335', 'LG G2', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d|oui:lg':
        ('BCM4335', 'LG G2', '2.4GHz'),

    'wifi|probe:0,1,50,45,221(00904c,51),htcap:182c|assoc:0,1,33,36,48,50,45,221(00904c,51),221(0050f2,2),htcap:182c':
        ('BCM4322', 'MacBook - late 2008 (A1278)', '5GHz'),
    'wifi|probe:0,1,50,3,45,221(00904c,51),htcap:182c|assoc:0,1,33,36,48,50,45,221(00904c,51),221(0050f2,2),htcap:182c':
        ('BCM4322', 'MacBook - late 2008 (A1278)', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,htcap:09ef,vhtcap:0f8159b2|assoc:0,1,33,36,48,45,127,191,221(0050f2,2),htcap:09ef,vhtcap:0f8159b2':
        ('BCM4360', 'MacBook Air - late 2014 (A1466)', '5GHz'),
    'wifi|probe:0,1,50,45,127,221(00904c,51),htcap:59ad|assoc:0,1,33,36,48,50,45,127,221(00904c,51),221(0050f2,2),htcap:59ad':
        ('BCM4360', 'MacBook Air - late 2014 (A1466)', '5GHz'),
    'wifi|probe:0,1,45,127,191,221(00904c,51),htcap:09ef,vhtcap:0f8159b2|assoc:0,1,33,36,48,45,127,191,221(00904c,51),221(0050f2,2),htcap:09ef,vhtcap:0f8159b2':
        ('BCM4360', 'MacBook Air - late 2014 (A1466)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,htcap:49ad|assoc:0,1,50,33,36,48,45,127,221(0050f2,2),htcap:49ad':
        ('BCM4360', 'MacBook Air - late 2014 (A1466)', '2.4GHz'),

    'wifi|probe:0,1,50,3,45,127,221(00904c,51),htcap:59ad|assoc:0,1,33,36,48,50,45,127,221(00904c,51),221(0050f2,2),htcap:59ad':
        ('BCM4360', 'MacBook Air or Pro - 2014', '2.4GHz'),

    'wifi|probe:0,1,45,221(00904c,51),htcap:09ef|assoc:0,1,33,36,48,45,221(00904c,51),221(0050f2,2),htcap:09ef':
        ('BCM4331', 'MacBook Pro - late 2013 (A1398)', '5GHz'),
    'wifi|probe:0,1,3,45,221(00904c,51),htcap:09ef|assoc:0,1,33,36,48,45,221(00904c,51),221(0050f2,2),htcap:09ef':
        ('BCM4331', 'MacBook Pro - late 2013 (A1398)', '5GHz'),
    'wifi|probe:0,1,45,127,htcap:09ef|assoc:0,1,33,36,48,45,127,221(0050f2,2),htcap:09ef|os:macos':
        ('BCM4331', 'MacBook Pro - late 2013 (A1398)', '5GHz'),
    'wifi|probe:0,1,50,3,45,221(00904c,51),htcap:19ad|assoc:0,1,33,36,48,50,45,221(00904c,51),221(0050f2,2),htcap:19ad':
        ('BCM4331', 'MacBook Pro - late 2013 (A1398)', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(00904c,51),htcap:09ef,vhtcap:0f8259b2|assoc:0,1,33,36,48,45,127,191,221(00904c,51),221(0050f2,2),htcap:09ef,vhtcap:0f8259b2':
        ('BCM4360', 'MacBook Pro - early 2014 (A1502)', '5GHz'),
    # 2.4 GHz signature for this device is listed above as 'MacBook Air or Pro - 2014'

    'wifi|probe:0,1,45,221(0050f2,8),191,htcap:016e,vhtcap:31800120|assoc:0,1,33,36,48,45,221(0050f2,2),191,127,htcap:016e,vhtcap:31800120':
        ('QCA_WCN3680', 'MOTO-X 2013 version', '5GHz'),
    'wifi|probe:0,1,50,3,45,221(0050f2,8),191,htcap:012c,vhtcap:31800120|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3680', 'MOTO-X 2013 version', '2.4GHz'),

    'wifi|probe:0,1,50,45,htcap:0130|assoc:0,1,50,48,45,221(0050f2,2),htcap:013c|oui:nest':
        ('TI_WL1270', 'Nest Thermostat v1', '2.4GHz'),

    'wifi|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,vhtcap:31811120,wps:Nexus_4|assoc:0,1,33,36,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi|probe:0,1,45,221(0050f2,8),191,htcap:012c,vhtcap:31811120|assoc:0,1,33,36,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:Nexus_4|assoc:0,1,33,36,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi|probe:0,1,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,vhtcap:31811120,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,vhtcap:31811120,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),191,221(0050f2,4),221(506f9a,9),htcap:012c,vhtcap:31811120|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:016f,vhtcap:0f805932|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:016f,vhtcap:0f805932':
        ('BCM4339', 'Nexus 5', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:112d|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:112d':
        ('BCM4339', 'Nexus 5', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,vhtcap:0f815832,wps:Nexus_6|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,vhtcap:0f815832':
        ('BCM4356', 'Nexus 6', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,wps:Nexus_6|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4356', 'Nexus 6', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,wps:Nexus_6|assoc:0,1,50,33,36,48,45,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4356', 'Nexus 6', '2.4GHz'),

    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c':
        ('BCM4330', 'Nexus 7 (2012)', '2.4GHz'),

    'wifi|probe:0,1,45,221(0050f2,8),htcap:016e|assoc:0,1,48,45,221(0050f2,2),htcap:016e':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,wps:Nexus_7|assoc:0,1,48,45,221(0050f2,2),htcap:016e':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),htcap:012c|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,10),221(506f9a,9),htcap:012c,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),

    'wifi|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,wps:Nexus_9|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4354', 'Nexus 9', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,wps:Nexus_9|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4354', 'Nexus 9', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:006f,vhtcap:0f815832,wps:Nexus_Player|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,vhtcap:0f815832':
        ('BCM4356', 'Nexus Player', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(0050f2,4),221(506f9a,9),221(001018,2),htcap:002d,wps:Nexus_Player|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4356', 'Nexus Player', '2.4GHz'),

    'wifi|probe:0,1,3,50|assoc:0,1,48,50,221(0050f2,2),45,htcap:112c':
        ('Marvell_88W8797', 'Playstation 4', '2.4GHz'),

    'wifi|probe:0,1,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:010c,wps:Galaxy_Nexus|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:010c':
        ('BCM4330', 'Samsung Galaxy Nexus', '5GHz'),
    'wifi|probe:0,1,50,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:110c,wps:Galaxy_Nexus|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c':
        ('BCM4330', 'Samsung Galaxy Nexus', '2.4GHz'),

    'wifi|probe:0,1,3,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:016f,vhtcap:0f805932|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:016f,vhtcap:0f805932':
        ('BCM4335', 'Samsung Galaxy Note 3', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:112d|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:112d':
        ('BCM4335', 'Samsung Galaxy Note 3', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(00904c,4),221(0050f2,8),221(001018,2),htcap:006f,vhtcap:0f815832|assoc:0,1,33,36,48,70,45,127,191,221(00904c,4),221(001018,2),221(0050f2,2),htcap:006f,vhtcap:0f815832':
        ('BCM4358', 'Samsung Galaxy Note 4', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(00904c,4),221(0050f2,8),221(001018,2),htcap:002d|assoc:0,1,50,33,36,48,70,45,127,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4358', 'Samsung Galaxy Note 4', '2.4GHz'),

    'wifi|probe:0,1,45,221(001018,2),221(00904c,51),htcap:000c|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:000c':
        ('BCM4330', 'Samsung Galaxy S2', ''),

    'wifi|probe:0,1,45,221(001018,2),221(00904c,51),htcap:0062|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:0062':
        ('BCM4334', 'Samsung Galaxy S3', '5GHz'),
    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:1020|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:1020':
        ('BCM4334', 'Samsung Galaxy S3', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,vhtcap:0f805832|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,vhtcap:0f805832':
        ('BCM4335', 'Samsung Galaxy S4 or LG G2', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d':
        ('BCM4335', 'Samsung Galaxy S4 or LG G2', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:102d':
        ('BCM4335', 'Samsung Galaxy S4 or LG G2', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,vhtcap:0f805832|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,vhtcap:0f805832|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '2.4GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(0050f2,2),htcap:102d|oui:samsung':
        ('BCM4335', 'Samsung Galaxy S4', '2.4GHz'),

    'wifi|probe:0,1,45,221(0050f2,8),htcap:016e|assoc:0,1,33,36,48,45,221(0050f2,2),221(004096,3),htcap:016e':
        ('APQ8026', 'Samsung Galaxy Tab 4', '5GHz'),
    'wifi|probe:0,1,50,3,45,221(0050f2,8),htcap:012c|assoc:0,1,50,48,45,221(0050f2,2),221(004096,3),htcap:012c':
        ('APQ8026', 'Samsung Galaxy Tab 4', '2.4GHz'),

    'wifi|probe:0,1,3,45,50,htcap:058f|assoc:0,1,48,50,221(0050f2,2),45,htcap:058d|name:Xbox-SystemOS':
        ('Marvell_88W8897', 'Xbox One', '5GHz'),
    'wifi|probe:0,1,45,50,htcap:058f|assoc:0,1,48,221(0050f2,2),45,htcap:058f|name:Xbox-SystemOS':
        ('Marvell_88W8897', 'Xbox One', '2.4GHz'),

    'wifi|probe:0,1,50|assoc:0,1,33,36,50,48,221(0050f2,2),221(00904c,51),45,htcap:104c':
        ('AR9170', '', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:086f,vhtcap:0f815032|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,51),221(0050f2,2),htcap:086f,vhtcap:0f815032':
        ('BCM43526', '', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:186f|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(00904c,51),221(0050f2,2),htcap:186f':
        ('BCM43526', '', '2.4GHz'),

    'wifi|probe:0,1,45,191,htcap:0966,vhtcap:03837122|assoc:0,1,45,48,127,191,221(0050f2,2),htcap:0962,vhtcap:03800122':
        ('Intel_7260', '', '5GHz'),
    'wifi|probe:0,1,45,50,191,htcap:0924,vhtcap:03837122|assoc:0,1,45,48,50,127,221(0050f2,2),htcap:0920':
        ('Intel_7260', '', '2.4GHz'),

    'wifi|probe:0,1,50|assoc:0,1,50,48,221(0050f2,2),45,htcap:18ee':
        ('Realtek?', '', '2.4GHz'),

    'wifi|probe:0,1,50,45,htcap:086c|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:086c':
        ('RTL8188EU', '', '2.4GHz'),

    'wifi|probe:0,1,50,45,htcap:186e|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:086c':
        ('RTL8192CU', '', '2.4GHz'),
}


def remove_wps(signature):
  """Remove a 'wps:Model_Name' from a signature.

  Many devices include their model in the signature, but there are likely
  a number of different devices using the same Wifi chipset. If we have the
  signature for a different model which matches except for the WPS ID,
  then we should conclude it is the same chipset.
  """
  fields = signature.split('|')
  new_fields = []
  for field in fields:
    attributes = field.split(',')
    attributes = [x for x in attributes if 'wps:' not in x]
    new_fields.append(','.join(attributes))
  return '|'.join(new_fields)


def init_database():
  """Initialize the signature database.

  A number of the signatures contain WPS model names.
  We want to also match similar devices using the same chipset.
  We iterate through the database and add a non-WPS version of
  any signature which includes one.
  """
  for (k, v) in database.items():
    if 'wps:' in k:
      new_k = remove_wps(k)
      if new_k not in database:
        database[new_k] = v
  initialized['database'] = True


def performance_info(signature):
  """Parse 802.11n/ac capabilities bitmasks from sig.

  Args:
    signature: the Wifi signature string.

  Returns:
    a text string suitable for logging.
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
  nss = '?'
  vht_width = ht_width = ''
  for field in fields:
    if field.startswith('vhtcap:'):
      try:
        bitmap = int(field[len('vhtcap:'):], base=16)
      except ValueError:
        vht_width = '??'
      else:
        scw = (bitmap >> 2) & 0x3
        widths = {0: '80', 1: '160', 2:'80+80'}
        vht_width = widths.get(scw, '??')
    elif field.startswith('htcap:'):
      try:
        bitmap = int(field[len('htcap:'):], base=16)
      except ValueError:
        ht_width = '??'
      else:
        nss = str(((bitmap >> 8) & 0x3) + 1)
        ht_width = '40' if bitmap & 0x2 else '20'
  if vht_width:
    return '802.11ac n:%s,w:%s' % (nss, vht_width)
  if ht_width:
    return '802.11n n:%s,w:%s' % (nss, ht_width)
  return '802.11a/b/g'


def depersonalize_hostname(hostname):
  """Remove autopersonalization like 'Dentons-iPad', just return 'ipad'."""
  h = hostname.lower()
  if h.startswith('android-'):
    return 'android'
  if 'ipad' in h:
    return 'ipad'
  if 'iphone' in h:
    return 'iphone'
  return hostname


def identify_wifi_device(signature, mac):
  """Look up a wifi device by signature.

  Arguments:
    signature: a string of the form 'wifi:probe:X,Y,Z|assoc:Q,R,S'
    mac: MAC address of the client, a string of the form 'qq:rr:ss:tt:uu:vv'

  Returns:
    A string describing the Wifi chipset and the type of device.

    If we know what it is, this will be 'ChipName;ModelName;PerformanceInfo'

    If we don't know what the device is but we can identify the chipset
    as being the same as some other device we know about, this will be
    'ChipName;Unknown;PerformanceInfo'

    If the signature is not known, return a SHA256 of the signature
    followed by 'Unknown;PerformanceInfo'
  """
  if 'database' not in initialized:
    init_database()

  signature = signature.strip()
  perf = performance_info(signature)
  name = dhcp.LookupHostname(mac)
  opersys = dhcp.LookupOperatingSystem(mac)
  oui = ethernet.LookupOUI(mac)
  keys = []
  if name:
    keys.append(signature + '|name:' + depersonalize_hostname(name))
  if opersys:
    keys.append(signature + '|os:' + opersys)
  if oui:
    keys.append(signature + '|oui:' + oui)
  keys.append(signature)
  for key in keys:
    result = database.get(key, None)
    if result is not None:
      return '%s;%s;%s' % (result[0], result[1], perf)

  # Try again with no WPS identifier, identify chipset only.
  new_key = remove_wps(key)
  result = database.get(new_key, None)
  if result is not None:
    return '%s;Unknown;%s' % (result[0], perf)

  # We have no idea what the client is.

  slug = 'SHA:' + hashlib.sha256(signature).hexdigest()
  return slug + ';Unknown;' + perf


if __name__ == '__main__':
  for k, v in database.iteritems():
    print 'SHA:' + hashlib.sha256(k).hexdigest() + ' ' + v[1]
