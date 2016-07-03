#!/bin/sh

. ./wvtest/wvtest.sh

export LC_ALL=C

ORIGFILE="./testdata/anonymize_pcap/chromebook_unanonymized.pcap"
ANONFILE="/tmp/anonpcaptest.$$.pcap"

WVSTART "anonymize_pcap test"

rm -f "$ANONFILE"
cp "$ORIGFILE" "$ANONFILE"

WVPASS ./anonymize_pcap -f "$ANONFILE"

orig=$(./wifi_signature -f "$ORIGFILE" | cut -d' ' -f2- )
anon=$(./wifi_signature -f "$ANONFILE" | cut -d' ' -f2- )
WVPASSEQ "$orig" "$anon"

# Obfuscate SSID
WVPASSNE "$(strings "$ORIGFILE" | grep GEEKHOLD)" ""
WVPASSEQ "$(strings "$ANONFILE" | grep GEEKHOLD)" ""

# Obfuscate MAC address
WVPASS grep -qP "\\x6c\\x29\\x95\\x7c\\x25\\xfe" "$ORIGFILE"
WVFAIL grep -qP "\\x6c\\x29\\x95\\x7c\\x25\\xfe" "$ANONFILE"
