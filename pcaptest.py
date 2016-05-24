#!/usr/bin/python

import dhcp
import glob
import os.path
import subprocess
import sys
import wifi

regression = [
  # devices for which we have a pcap but have decided not to add
  # to the database
  ('Unknown', './testdata/pcaps/ASUS Transformer TF300 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Blackberry Bold 9930 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Blackberry Bold 9930 5GHz.pcap'),
  ('Unknown', './testdata/pcaps/HTC Evo 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/HTC Incredible 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/HTC Inspire 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/HTC Sensation 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/HTC Thunderbolt 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/HTC Titan 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Lenovo_T440_80211ac_2x2_Windows8_2_4_GHz.pcap'),
  ('Unknown', './testdata/pcaps/LG E900 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/LG G2X 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/LG Revolution 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/MediaTek MT7610U 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid 2 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid 3 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid Razr 2.4GHz XT910 Broadcast Probe.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid Razr 2.4GHz XT910 Specific Probe.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid Razr 2.4GHz XT910.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid Razr 5GHz XT910.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid Razr Maxx 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Nexus One 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Charge 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Captivate 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Continuum 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Epic 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Exhibit 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Fascinate 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Galaxy Tab 2 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Infuse 5GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Vibrant 2.4GHz.pcap'),

  # Names where the identified species doesn't exactly match the filename,
  # usually because multiple devices are too similar to distinguish. We name
  # the file for the specific device which was captured, and add an entry
  # here for the best identification which we can manage.
  ('iPad (1st/2nd gen)', './testdata/pcaps/iPad 1st gen 5GHz.pcap'),
  ('iPad (1st/2nd gen)', './testdata/pcaps/iPad 2nd gen 5GHz.pcap'),
  ('iPad (4th gen or Air)', './testdata/pcaps/iPad (4th gen) 5GHz.pcap'),
  ('iPad (4th gen or Air)', './testdata/pcaps/iPad (4th gen) 2.4GHz.pcap'),
  ('iPad (4th gen or Air)', './testdata/pcaps/iPad Air 5GHz.pcap'),
  ('iPad (4th gen or Air)', './testdata/pcaps/iPad Air 2.4GHz.pcap'),
  ('iPhone 6/6+', './testdata/pcaps/iPhone 6 5GHz.pcap'),
  ('iPhone 6/6+', './testdata/pcaps/iPhone 6+ 5GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 5GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 5GHz.pcap'),
  ('iPod Touch 1st/2nd gen', './testdata/pcaps/iPod Touch 1st gen 2.4GHz.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2.4GHz Specific.pcap'),
  ('Moto G or Moto X', './testdata/pcaps/Moto X 2.4GHz.pcap'),
  ('Nest Thermostat v1/v2', './testdata/pcaps/Nest Thermostat 2.4GHz.pcap'),
  ('Roku 3 or Streaming Stick', './testdata/pcaps/Roku 3 2.4GHz 4230.pcap'),
  ('Roku 3 or Streaming Stick', './testdata/pcaps/Roku 3 5GHz 4230.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy S2+ 5GHz.pcap'),
  ('Samsung Galaxy Note or S2+', './testdata/pcaps/Samsung Galaxy Note 5GHz.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Galaxy S2 2.4GHz.pcap'),
  ('Samsung Galaxy S2 or Infuse', './testdata/pcaps/Samsung Infuse 2.4GHz.pcap'),
  ('Sony Xperia Z4/Z5', './testdata/pcaps/Sony Xperia Z5 5GHz.pcap'),
  ('Sony Xperia Z4/Z5', './testdata/pcaps/Sony Xperia Z5 2.4GHz.pcap'),
  ('Sony Xperia Z4/Z5', './testdata/pcaps/Sony Xperia Z4 Tablet 5GHz.pcap'),
  ('Sony Xperia Z4/Z5', './testdata/pcaps/Sony Xperia Z4 Tablet 2.4GHz.pcap'),
]


def get_taxonomy_from_pcap(filename):
  (mac, sig) = subprocess.check_output(['./tax_signature', '-f', filename]).split()
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
  _, actual_model, _ = wifi.identify_wifi_device(sig, mac)
  if expected_model != actual_model:
    print 'Mismatch in %s: %s %s != %s' % (pcap, mac, expected_model,
                                           actual_model)
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
