#include "../include/scanner.h"

int get_ifdetails(const char *iface, int *ifindex, uint8_t *mac) { // retrieves interface index and mac address
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return -1;
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

int get_default_iface(char *iface) { // identifies default network interface name
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char iface_tmp[64];
        unsigned long dest, gw, mask;
        if (sscanf(line, "%s %lx %lx %*x %*d %*d %*d %lx %*d %*d %*d", iface_tmp, &dest, &gw, &mask) >= 3) {
            if (dest == 0) { 
                strcpy(iface, iface_tmp);
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

int get_default_gateway(char *gateway_ip) { // determines default gateway ip
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        unsigned long dest, gw, mask;
        if (sscanf(line, "%s %lx %lx %*d %*d %*d %lx %lx", iface, &dest, &gw, &mask, &mask) >= 3) {
            if (dest == 0) { 
                struct in_addr addr;
                addr.s_addr = gw;
                strcpy(gateway_ip, inet_ntoa(addr));
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

void force_arp(const char *dst_ip) { //  arp resolution
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(666);
    addr.sin_addr.s_addr = inet_addr(dst_ip);
    char dummy = 'x';
    sendto(sock, &dummy, 1, 0, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    usleep(10000); 
}

int get_gateway_mac(uint8_t *mac) { // resolves the hardware address
    char gateway_ip[32];
    if (get_default_gateway(gateway_ip) == 0) {
        if (!quiet_mode) printf("[DEBUG] Gateway IP: %s\n", gateway_ip);
        force_arp(gateway_ip);
    } else {
        // failed to determine gateway
    }
    
    usleep(200000);
    
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[256];
    if (fgets(line, sizeof(line), f)) { } 
    while (fgets(line, sizeof(line), f)) {
        char ip[64], hw[64], device[64];
        int type, flags;
        if (sscanf(line, "%s %x %x %s %*s %s", ip, &type, &flags, hw, device) >= 4) {
            if (strcmp(ip, gateway_ip) == 0 && (flags & 0x2)) { 
                int m[6];
                if (sscanf(hw, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i=0; i<6; i++) mac[i] = (uint8_t)m[i];
                    fclose(f);
                    return 0;
                }
            }
        }
    }
    fclose(f);
    return -1;
}

uint32_t get_local_ip(const char *interface) { // finds the local ip
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0;
    }
    
    uint32_t ip = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (interface && strcmp(ifa->ifa_name, interface) != 0) continue;
            uint32_t addr = sa->sin_addr.s_addr;
            uint8_t first_octet = (addr >> 24) & 0xFF;
            if (first_octet == 127) continue;
            ip = addr;
            if (first_octet != 169 || (addr >> 16) != 0xA9FE) break;
        }
    }
    freeifaddrs(ifaddr);
    return ip;
}

unsigned short calculate_ip_checksum(struct iphdr *iph) { // computes checksum for an ip header
    unsigned short *buf = (unsigned short *)iph;
    unsigned int sum = 0;
    iph->check = 0;
    
    for (int i = 0; i < iph->ihl * 2; i++) {
        sum += buf[i];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

unsigned short calculate_tcp_checksum(struct tcphdr *tcp, uint32_t src_ip, uint32_t dst_ip) { // computes the tcp checksum 
    uint32_t sum = 0;
    
    uint16_t tcp_len_bytes = tcp->doff * 4;
    
    unsigned short *src_ptr = (unsigned short *)&src_ip;
    sum += src_ptr[0];
    sum += src_ptr[1];
    
    unsigned short *dst_ptr = (unsigned short *)&dst_ip;
    sum += dst_ptr[0];
    sum += dst_ptr[1];
    
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len_bytes);
    
    unsigned short *tcp_ptr = (unsigned short *)tcp;
    for (int i = 0; i < tcp_len_bytes / 2; i++) {
        sum += tcp_ptr[i];
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

void create_tcp_packet_flags(packet_t *packet, uint32_t src_ip, uint32_t dst_ip,
                            unsigned short src_port, unsigned short dst_port,
                            uint8_t *src_mac, uint8_t *dst_mac, uint8_t flags) {
    memset(packet->buffer, 0, PACKET_SIZE);
    
    struct ethhdr *eth = (struct ethhdr *)packet->buffer;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);
    
    struct iphdr *iph = (struct iphdr *)(packet->buffer + sizeof(struct ethhdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    
    struct tcphdr *tcph = (struct tcphdr *)(packet->buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(100);
    tcph->ack_seq = 0;
    
    tcph->doff = 5; // Default 20 bytes if no options
    
    // Flags
    tcph->fin = (flags & 0x01) ? 1 : 0;
    tcph->syn = (flags & 0x02) ? 1 : 0;
    tcph->rst = (flags & 0x04) ? 1 : 0;
    tcph->psh = (flags & 0x08) ? 1 : 0;
    tcph->ack = (flags & 0x10) ? 1 : 0;
    tcph->urg = (flags & 0x20) ? 1 : 0;
    
    tcph->window = htons(64240); 
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Optional MSS for SYN
    if (flags & 0x02) {
         tcph->doff = 6; // +4 bytes option
         unsigned char *opt_ptr = (unsigned char *)tcph + sizeof(struct tcphdr);
         opt_ptr[0] = 2; opt_ptr[1] = 4;
         *(uint16_t *)(opt_ptr + 2) = htons(1460);
         iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 4);
    }
    
    iph->check = calculate_ip_checksum(iph);
    tcph->check = calculate_tcp_checksum(tcph, src_ip, dst_ip);
    
    packet->length = ntohs(iph->tot_len) + sizeof(struct ethhdr);
    if (packet->length < 60) packet->length = 60;
}

void create_syn_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip,
                      unsigned short src_port, unsigned short dst_port,
                      uint8_t *src_mac, uint8_t *dst_mac) { // constructs raw tcp syn packet 
    create_tcp_packet_flags(packet, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, 0x02);
}

void create_udp_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip,
                       unsigned short src_port, unsigned short dst_port,
                       uint8_t *src_mac, uint8_t *dst_mac, uint8_t *payload, size_t payload_len) {
    memset(packet->buffer, 0, PACKET_SIZE);
    
    struct ethhdr *eth = (struct ethhdr *)packet->buffer;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);
    
    struct iphdr *iph = (struct iphdr *)(packet->buffer + sizeof(struct ethhdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    
    struct udphdr *udph = (struct udphdr *)(packet->buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udph->source = htons(src_port);
    udph->dest = htons(dst_port);
    udph->len = htons(sizeof(struct udphdr) + payload_len);
    udph->check = 0; 
    
    if (payload && payload_len > 0) {
        if (payload_len > (PACKET_SIZE - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)))) {
            payload_len = PACKET_SIZE - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
        }
        memcpy(packet->buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr), payload, payload_len);
    }
    
    iph->check = calculate_ip_checksum(iph);
    
    packet->length = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
    if (packet->length < 60) packet->length = 60;
}

unsigned short calculate_icmp_checksum(struct icmphdr *icmp, int len) {
    unsigned short *buf = (unsigned short *)icmp;
    unsigned int sum = 0;
    icmp->checksum = 0;
    for (int i = 0; i < len / 2; i++) {
        sum += buf[i];
    }
    if (len % 2) {
        sum += *(unsigned char *)&buf[len/2];
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

void create_icmp_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip, uint8_t *src_mac, uint8_t *dst_mac) {
    memset(packet->buffer, 0, PACKET_SIZE);
    
    struct ethhdr *eth = (struct ethhdr *)packet->buffer;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);
    
    struct iphdr *iph = (struct iphdr *)(packet->buffer + sizeof(struct ethhdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr)); 
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    
    struct icmphdr *icmph = (struct icmphdr *)(packet->buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(1234);
    icmph->un.echo.sequence = 0;
    icmph->checksum = 0;
    icmph->checksum = calculate_icmp_checksum(icmph, sizeof(struct icmphdr));
    
    iph->check = calculate_ip_checksum(iph);

    packet->length = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    if (packet->length < 60) packet->length = 60;
}
