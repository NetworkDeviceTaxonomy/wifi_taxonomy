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


initialized = {}


database = {
    'wifi|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:Nexus_4|assoc:0,1,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '5GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:Nexus_4|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3360', 'Nexus 4', '2.4GHz'),

    'wifi|probe:0,1,50,45,3,221(001018,2),221(00904c,51),htcap:110c|assoc:0,1,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c':
        ('BCM4330', 'Nexus 7 (2012)', '2.4GHz'),

    'wifi|probe:0,1,45,221(0050f2,8),htcap:016e|assoc:0,1,48,45,221(0050f2,2),htcap:016e':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi|probe:0,1,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:016e,wps:Nexus_7|assoc:0,1,48,45,221(0050f2,2),htcap:016e':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '5GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),htcap:012c|assoc:':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),
    'wifi|probe:0,1,50,45,221(0050f2,8),221(0050f2,4),221(506f9a,9),htcap:012c,wps:Nexus_7|assoc:0,1,50,48,45,221(0050f2,2),htcap:012c':
        ('QCA_WCN3660', 'Nexus 7 (2013)', '2.4GHz'),

    'wifi|probe:0,1,45,221(001018,2),221(00904c,51),htcap:080c|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:080c':
        ('BCM4329', 'iPad (2nd gen)', '5GHz'),
    'wifi|probe:0,1,50,45,221(001018,2),221(00904c,51),htcap:180c|assoc:':
        ('BCM4329', 'iPad (2nd gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01fe|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01fe':
        ('BCM4334', 'iPad (4th gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(001018,2),221(00904c,51),221(0050f2,8),htcap:01bc|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:01bc':
        ('BCM4334', 'iPad (4th gen)', '2.4GHz'),

    'wifi|probe:0,1,45,127,107,191,221(0050f2,8),221(001018,2),htcap:006f,vhtcap:0f815832|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(0050f2,2),htcap:006f,vhtcap:0f815832':
        ('BCM4339', 'iPad Air (2nd gen)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,107,221(0050f2,8),221(001018,2),htcap:002d|assoc:0,1,50,33,36,48,45,127,221(001018,2),221(0050f2,2),htcap:002d':
        ('BCM4339', 'iPad Air (2nd gen)', '2.4GHz'),

    'wifi|probe:0,1,45,221(00904c,51),htcap:09ef|assoc:0,1,33,36,48,45,221(00904c,51),221(0050f2,2),htcap:09ef':
        ('BCM4331', 'MacBook Pro - late 2013 (A1398)', '5GHz'),
    'wifi|probe:0,1,50,3,45,221(00904c,51),htcap:19ad|assoc:0,1,33,36,48,50,45,221(00904c,51),221(0050f2,2),htcap:19ad':
        ('BCM4331', 'MacBook Pro - late 2013 (A1398)', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,htcap:09ef,vhtcap:0f8159b2|assoc:0,1,33,36,48,45,127,191,221(0050f2,2),htcap:09ef,vhtcap:0f8159b2':
        ('BCM4360', 'MacBook Air - late 2014 (A1466)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,htcap:49ad|assoc:0,1,50,33,36,48,45,127,221(0050f2,2),htcap:49ad':
        ('BCM4360', 'MacBook Air - late 2014 (A1466)', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(00904c,51),htcap:09ef,vhtcap:0f8259b2|assoc:0,1,33,36,48,45,127,191,221(00904c,51),221(0050f2,2),htcap:09ef,vhtcap:0f8259b2':
        ('BCM4360', 'MacBook Pro - early 2014 (A1502)', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(00904c,51),htcap:59ad|assoc:0,1,33,36,48,50,45,127,221(00904c,51),221(0050f2,2),htcap:59ad':
        ('BCM4360', 'MacBook Pro - early 2014 (A1502)', '2.4GHz'),

    'wifi|probe:0,1,50|assoc:0,1,50,48,221(0050f2,2),45,htcap:18ee':
        ('Realtek?', '', '2.4GHz'),

    'wifi|probe:0,1,45,191,htcap:0966,vhtcap:03837122|assoc:0,1,45,48,127,191,221(0050f2,2),htcap:0962,vhtcap:03800122':
        ('Intel_7260', '', '5GHz'),
    'wifi|probe:0,1,45,50,191,htcap:0924,vhtcap:03837122|assoc:0,1,45,48,50,127,221(0050f2,2),htcap:0920':
        ('Intel_7260', '', '2.4GHz'),

    'wifi|probe:0,1,50,45,htcap:086c|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:086c':
        ('RTL8188EU', '', '2.4GHz'),

    'wifi|probe:0,1,50,45,htcap:186e|assoc:0,1,50,48,221(0050f2,2),45,127,htcap:086c':
        ('RTL8192CU', '', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(001018,2),221(00904c,51),htcap:086f,vhtcap:0f815032|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,51),221(0050f2,2),htcap:086f,vhtcap:0f815032':
        ('BCM43526', '', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),htcap:186f|assoc:0,1,33,36,48,50,45,127,221(001018,2),221(00904c,51),221(0050f2,2),htcap:186f':
        ('BCM43526', '', '2.4GHz'),

    'wifi|probe:0,1,50|assoc:0,1,33,36,50,48,221(0050f2,2),221(00904c,51),45,htcap:104c':
        ('AR9170', '', '2.4GHz'),

    'wifi|probe:0,1,50,45,htcap:0130|assoc:0,1,50,48,45,221(0050f2,2),htcap:013c':
        ('TI_WL1270', 'Nest Thermostat v1', '2.4GHz'),

    'wifi|probe:0,1,45,127,191,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:006f,vhtcap:0f805832|assoc:0,1,33,36,48,45,127,191,221(001018,2),221(00904c,4),221(0050f2,2),htcap:006f,vhtcap:0f805832':
        ('BCM4335', 'Samsung Galaxy S4', '5GHz'),
    'wifi|probe:0,1,50,3,45,127,221(001018,2),221(00904c,51),221(00904c,4),221(0050f2,8),htcap:102d|assoc:0,1,33,36,48,50,45,221(001018,2),221(0050f2,2),htcap:102d':
        ('BCM4335', 'Samsung Galaxy S4', '2.4GHz'),

    'wifi|probe:0,1,45,221(0050f2,4),221(001018,2),221(00904c,51),htcap:010c,wps:Galaxy_Nexus|assoc:0,1,33,36,48,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:010c':
        ('BCM4330', 'Samsung Galaxy Nexus', '5GHz'),
    'wifi|probe:0,1,50,45,3,221(0050f2,4),221(001018,2),221(00904c,51),htcap:110c,wps:Galaxy_Nexus|assoc:0,1,33,36,48,50,45,221(001018,2),221(00904c,51),221(0050f2,2),htcap:110c':
        ('BCM4330', 'Samsung Galaxy Nexus', '2.4GHz'),
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

def identify_wifi_chipset(signature):
  """Look up a wifi device by signature.

  Arguments:
    signature: a string of the form 'wifi:probe:X,Y,Z|assoc:Q,R,S'

  Returns:
    A string describing the Wifi chipset like 'BCM4360'
    If the signature is not known, returns a SHA256 of the signature.
  """
  if 'database' not in initialized:
    init_database()

  key = signature.strip().lower()
  result = database.get(key, None)
  if result is not None and result[0]:
    return result[0]

  new_key = remove_wps(key)
  result = database.get(new_key, None)
  if result is not None and result[0]:
    return result[0]

  return hashlib.sha256(key).hexdigest()
