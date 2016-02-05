#!/usr/bin/python

import dhcp
import glob
import os.path
import subprocess
import sys
import wifi

regression = [
  # devices for which we have a pcap but have decided not to add
  # to the database, generally because the device is not common
  # enough.
  ('Unknown', './testdata/pcaps/iPhone 2 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/iPhone 3 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/iPhone 3GS 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/iPhone 3GS 2.4GHz M137LL.pcap'),
  ('Unknown', './testdata/pcaps/HTC Evo 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/HTC Thunderbolt 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Lenovo_T440_80211ac_2x2_Windows8_2_4_GHz.pcap'),
  ('Unknown', './testdata/pcaps/MediaTek MT7610U 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid 2 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Motorola Droid 3 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Nexus One 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Charge 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Captivate 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Continuum 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Epic 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Fascinate 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Galaxy Tab 2 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Samsung Vibrant 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Sony Xperia Z5 2.4GHz.pcap'),
  ('Unknown', './testdata/pcaps/Sony Xperia Z5 5GHz.pcap'),

  # Names which contain a slash ('/'), which Linux filenames do not
  # tolerate. Inferring the expected result from the filename doesn't
  # work for these, instead we add them explicitly.
  ('iPad (1st/2nd gen)', './testdata/pcaps/iPad 1st gen 5GHz.pcap'),
  ('iPad (1st/2nd gen)', './testdata/pcaps/iPad 2nd gen 5GHz.pcap'),
  ('iPhone 6/6+', './testdata/pcaps/iPhone 6+ 5GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 2.4GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 2.4GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s 5GHz.pcap'),
  ('iPhone 6s/6s+', './testdata/pcaps/iPhone 6s+ 5GHz.pcap'),
  ('iPod Touch 1st/2nd gen', './testdata/pcaps/iPod Touch 1st gen 2.4GHz.pcap'),
  ('Nest Thermostat v1/v2', './testdata/pcaps/Nest Thermostat 2.4GHz.pcap'),
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
