#!/bin/bash
# ============================================================
#  capture.sh  --  run on the capture-sensor (.200)
#  Captures ALL mirrored victim-LAN traffic on the SPAN iface.
#
#  USAGE:  sudo ./capture.sh
#  STOP:   Ctrl+C  (when the 1-hour run is over)
# ============================================================

IFACE="enp9s0"        # the SPAN/mirror interface (no IP, receives the copy)
OUT="/tmp/thursday_morning_$(date +%Y%m%d_%H%M%S).pcap"

echo "capturing on $IFACE -> $OUT"
echo "start this BEFORE benign+attacks, stop with Ctrl+C AFTER the hour."
echo "----------------------------------------------------------"
# -s 0 = full packets; no filter = capture everything the mirror sees
sudo tcpdump -i "$IFACE" -s 0 -w "$OUT"
