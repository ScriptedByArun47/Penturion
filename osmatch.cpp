#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>
#include <map>

// TCP pseudo header for checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Checksum calculation function
unsigned short checksum(unsigned short* ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

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

// IP validation function
bool validate_ip(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

// Craft and send SYN packet
void craft_and_send(const std::string& target_ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr* iph = (struct iphdr*) datagram;
    struct tcphdr* tcph = (struct tcphdr*) (datagram + sizeof(struct iphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

    std::string spoofed_src_ip = "192.168.1.100";

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(spoofed_src_ip.c_str());
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = checksum((unsigned short*)datagram, sizeof(struct iphdr));

    tcph->source = htons(12345);
    tcph->dest = htons(80);
    srand(time(NULL));
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5 + 5;
    tcph->syn = 1;
    tcph->window = htons(29200);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    unsigned char* options = (unsigned char*)(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
    int opt_len = 0;
    options[opt_len++] = 2; options[opt_len++] = 4; options[opt_len++] = 0x05; options[opt_len++] = 0xb4;
    options[opt_len++] = 4; options[opt_len++] = 2;
    options[opt_len++] = 8; options[opt_len++] = 10;
    uint32_t ts_val = htonl(time(NULL)), ts_ecr = 0;
    memcpy(options + opt_len, &ts_val, 4); opt_len += 4;
    memcpy(options + opt_len, &ts_ecr, 4); opt_len += 4;
    options[opt_len++] = 1;
    options[opt_len++] = 3; options[opt_len++] = 3; options[opt_len++] = 7;

    int tcp_len = sizeof(struct tcphdr) + opt_len;
    char pseudo_packet[4096];
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);

    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    memcpy(pseudo_packet + sizeof(struct pseudo_header) + sizeof(struct tcphdr), options, opt_len);

    tcph->check = checksum((unsigned short*)pseudo_packet, sizeof(struct pseudo_header) + tcp_len);

    std::cout << "=== Packet Details ===\n";
    std::cout << "Target IP: " << target_ip << "\n";
    std::cout << "Source IP (spoofed): " << spoofed_src_ip << "\n";
    std::cout << "Source Port: 12345\n";
    std::cout << "Destination Port: 80\n";
    std::cout << "Sequence Number: " << ntohl(tcph->seq) << "\n";
    std::cout << "TCP Flags: SYN set\n";
    std::cout << "Window Size: " << ntohs(tcph->window) << "\n";
    std::cout << "TCP Options: MSS=1460, SACK Permitted, Timestamp, Window Scale=7\n";
    std::cout << "======================\n";

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(sock);
        exit(1);
    }

    if (sendto(sock, datagram, ntohs(iph->tot_len), 0, (sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
        close(sock);
        exit(1);
    } else {
        std::cout << "Packet successfully sent to " << target_ip << std::endl;
    }

    close(sock);
}

// Fingerprint structure
struct Fingerprint {
    int ttl;
    int window_size;
    std::vector<int> tcp_options; // For simplicity, store option kinds only
    std::string os_name;
};

// Check if TCP options match ignoring order (simple check)
bool tcp_options_match(const std::vector<int>& a, const std::vector<int>& b) {
    if (a.size() != b.size()) return false;
    std::map<int,int> count_a, count_b;
    for (int v : a) count_a[v]++;
    for (int v : b) count_b[v]++;
    return count_a == count_b;
}

// Simple fingerprint matching function
std::string match_fingerprint(int ttl, int window_size, const std::vector<int>& tcp_opts,
                              const std::vector<Fingerprint>& db) {
    for (const auto& fp : db) {
        // Match TTL with some tolerance (+-5)
        if (abs(fp.ttl - ttl) <= 5 &&
            fp.window_size == window_size &&
            tcp_options_match(fp.tcp_options, tcp_opts)) {
            return fp.os_name;
        }
    }
    return "Unknown OS";
}

// Simulated function to capture response (replace with actual capture)
void simulate_response(int& ttl, int& window_size, std::vector<int>& tcp_options) {
    ttl = 64;
    window_size = 29200;
    tcp_options = {2,4,8,1,3}; // MSS, SACK, Timestamp, NOP, Window scale
}

int main() {
    std::string target_ip;
    std::cout << "Enter target IP address: ";
    std::getline(std::cin, target_ip);

    if (!validate_ip(target_ip)) {
        std::cerr << "Invalid IP address format. Exiting." << std::endl;
        return 1;
    }

    craft_and_send(target_ip);

    // --- Fingerprint DB (example) ---
    std::vector<Fingerprint> fingerprint_db = {
        {64, 29200, {2,4,8,1,3}, "Linux Kernel 3.x"},
        {128, 65535, {2,4,1}, "Windows 10"},
        {255, 8192, {2,1,3}, "Cisco Router IOS"}
    };

    // Simulate capture of TTL, window size, TCP options from response
    int captured_ttl;
    int captured_window;
    std::vector<int> captured_opts;
    simulate_response(captured_ttl, captured_window, captured_opts);

    std::cout << "Captured response:" << std::endl;
    std::cout << "TTL: " << captured_ttl << std::endl;
    std::cout << "Window Size: " << captured_window << std::endl;
    std::cout << "TCP Options (kinds): ";
    for (int opt : captured_opts) std::cout << opt << " ";
    std::cout << std::endl;

    // Match fingerprint
    std::string os = match_fingerprint(captured_ttl, captured_window, captured_opts, fingerprint_db);
    std::cout << "Fingerprint matched OS: " << os << std::endl;

    return 0;
}
