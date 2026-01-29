#include "../include/scanner.h"


writer_context_t writer_ctx;
pthread_t writer_thread_id; 

void init_writer(const char *filename) { 
    writer_ctx.head = 0;
    writer_ctx.tail = 0;
    writer_ctx.stop = 0;
    pthread_mutex_init(&writer_ctx.mutex, NULL);
    pthread_cond_init(&writer_ctx.cond, NULL);
    
    if (filename) {
        writer_ctx.file = fopen(filename, "a");
        if (!writer_ctx.file) { /* handle error */ }
    } else {
        writer_ctx.file = NULL;
    }
}

void push_to_writer(const char *str) { 
    pthread_mutex_lock(&writer_ctx.mutex);
    int next_head = (writer_ctx.head + 1) % WRITER_QUEUE_SIZE;
    if (next_head != writer_ctx.tail) {
        strncpy(writer_ctx.queue[writer_ctx.head], str, 31);
        writer_ctx.queue[writer_ctx.head][31] = '\0';
        writer_ctx.head = next_head;
        pthread_cond_signal(&writer_ctx.cond);
    } 

    pthread_mutex_unlock(&writer_ctx.mutex);
}

void *writer_thread_func(void *arg) { 
    char buffer[65536]; 
    
    while (1) {
        pthread_mutex_lock(&writer_ctx.mutex);
        while (writer_ctx.head == writer_ctx.tail && !writer_ctx.stop) {
            pthread_cond_wait(&writer_ctx.cond, &writer_ctx.mutex);
        }
        
        if (writer_ctx.stop && writer_ctx.head == writer_ctx.tail) {
            pthread_mutex_unlock(&writer_ctx.mutex);
            break;
        }

        int bytes = 0;

        while (writer_ctx.head != writer_ctx.tail && bytes < 65000) {
            int len = strlen(writer_ctx.queue[writer_ctx.tail]);
            memcpy(buffer + bytes, writer_ctx.queue[writer_ctx.tail], len);
            buffer[bytes + len] = '\n';
            bytes += len + 1;
            writer_ctx.tail = (writer_ctx.tail + 1) % WRITER_QUEUE_SIZE;
        }
        pthread_mutex_unlock(&writer_ctx.mutex);
        
        if (bytes > 0) {
            if (writer_ctx.file) {
                fwrite(buffer, 1, bytes, writer_ctx.file);

            } else {
                fwrite(buffer, 1, bytes, stdout);
                fflush(stdout);
            }
        }
    }
    if (writer_ctx.file && writer_ctx.file != stdout) {
        fflush(writer_ctx.file);
        fclose(writer_ctx.file);
    }
    return NULL;
}

static inline uint32_t hash_ip_port(uint32_t ip, uint16_t port) {
    uint32_t h = ip ^ port;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

void process_packet(const uint8_t *packet, int length, stats_t *stats,
                   scanner_config_t *config, uint32_t src_ip) { 
    if (length < ETH_HDRLEN) return;
    
    struct ethhdr *eth = (struct ethhdr *)packet;
    uint16_t eth_type = ntohs(eth->h_proto);
    int offset = ETH_HDRLEN;


    if (eth_type == 0x8100) {
        if (length < ETH_HDRLEN + 4) return;
        eth_type = ntohs(*(uint16_t *)(packet + offset + 2));
        offset += 4;
    }

    if (eth_type != ETH_P_IP) return;
    if (length < offset + IP4_HDRLEN) return;

    struct iphdr *iph = (struct iphdr *)(packet + offset);
    

    if (iph->daddr != src_ip) return;

    
    if (iph->protocol == IPPROTO_TCP && length >= offset + (iph->ihl * 4) + TCP_HDRLEN) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + offset + (iph->ihl * 4));
        
        if (tcph->syn && tcph->ack) {
            atomic_fetch_add(&stats->packets_received, 1);
            atomic_fetch_add(&stats->syn_acks, 1);
            atomic_fetch_add(&stats->hosts_up, 1);
            atomic_fetch_add(&stats->ports_open, 1);
            
            uint32_t ip_hbo = ntohl(iph->saddr);
            uint16_t port_hbo = ntohs(tcph->source);
            char out_str[32];
            
            if (config->is_multiport) {
                uint32_t h = hash_ip_port(ip_hbo, port_hbo);
                uint8_t bit = 1 << (h & 7);
                uint8_t *byte_ptr = &seen_ips[h >> 3];
                
                if (!(atomic_fetch_or((_Atomic uint8_t *)byte_ptr, bit) & bit)) {
                    char ip_str[16];
                    int_to_ip(iph->saddr, ip_str);
                    snprintf(out_str, sizeof(out_str), "%s:%u", ip_str, port_hbo);
                    push_to_writer(out_str);
                }
            } else {
                /* Atomic check-and-set in bitset */
                uint8_t bit = 1 << (ip_hbo & 7);
                uint8_t *byte_ptr = &seen_ips[ip_hbo >> 3];
                
                if (!(atomic_fetch_or((_Atomic uint8_t *)byte_ptr, bit) & bit)) {
                    int_to_ip(iph->saddr, out_str);
                    push_to_writer(out_str);
                }
            }
            
        } else if (tcph->rst) {
            atomic_fetch_add(&stats->rst_replies, 1);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + offset + (iph->ihl * 4));
        atomic_fetch_add(&stats->packets_received, 1);
        atomic_fetch_add(&stats->hosts_up, 1); 
        atomic_fetch_add(&stats->ports_open, 1);
        
        uint32_t ip_hbo = ntohl(iph->saddr);
        uint16_t port_hbo = ntohs(udph->source);
        char out_str[32];

        if (config->is_multiport) {
            uint32_t h = hash_ip_port(ip_hbo, port_hbo);
            uint8_t bit = 1 << (h & 7);
            uint8_t *byte_ptr = &seen_ips[h >> 3];
            
            if (!(atomic_fetch_or((_Atomic uint8_t *)byte_ptr, bit) & bit)) {
                char ip_str[16];
                int_to_ip(iph->saddr, ip_str);
                snprintf(out_str, sizeof(out_str), "%s:%u", ip_str, port_hbo);
                push_to_writer(out_str);
            }
        } else {
            uint8_t bit = 1 << (ip_hbo & 7);
            uint8_t *byte_ptr = &seen_ips[ip_hbo >> 3];
            
            if (!(atomic_fetch_or((_Atomic uint8_t *)byte_ptr, bit) & bit)) {
                int_to_ip(iph->saddr, out_str);
                push_to_writer(out_str);
            }
        }
        
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)(packet + offset + (iph->ihl * 4));
        if (icmph->type == ICMP_DEST_UNREACH) {
            atomic_fetch_add(&stats->icmp_unreach, 1);
        }
    }

}

void *receiver_thread(void *arg) { 
    thread_context_t *ctx = (thread_context_t *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((ctx->thread_id + ctx->config->senders) % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        return NULL;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ctx->config->ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        // failed bind
    }

    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ctx->config->ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        // failed promisc
    }

    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = 4096 * 128; 
    req.tp_block_nr = 64;           
    req.tp_frame_size = 2048;      
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req)) < 0) {
        close(sock);
        return NULL;
    }

    size_t ring_size = req.tp_block_size * req.tp_block_nr;
    unsigned char *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if (ring == MAP_FAILED) {
        close(sock);
        return NULL;
    }

    struct iovec *rd = malloc(req.tp_frame_nr * sizeof(struct iovec));
    for (int i = 0; i < req.tp_frame_nr; ++i) {
        rd[i].iov_base = ring + (i * req.tp_frame_size);
        rd[i].iov_len = req.tp_frame_size;
    }

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = sock;
    pfd.events = POLLIN | POLLERR;

    int one = 1;
    setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
    
    int fanout_arg = (1 | (PACKET_FANOUT_HASH << 16));
    if (setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) < 0) {
        if (!quiet_mode) fprintf(stderr, "[!] Warning: setsockopt(PACKET_FANOUT) failed (errno %d: %s). Duplicate reception may occur at OS level.\n", errno, strerror(errno));
    }

    unsigned int frame_idx = 0;
    while (ctx->running && !stop_signal) {
        struct tpacket_hdr *t_hdr = (struct tpacket_hdr *)rd[frame_idx].iov_base;
        
        if (t_hdr->tp_status == TP_STATUS_KERNEL) {
            if (poll(&pfd, 1, 10) <= 0) continue;
        }

        while (ctx->running && !stop_signal && (t_hdr->tp_status & TP_STATUS_USER)) {
            unsigned char *pkt = (unsigned char *)t_hdr + t_hdr->tp_mac;
            process_packet(pkt, t_hdr->tp_len, ctx->stats, ctx->config, ctx->src_ip);
            
            t_hdr->tp_status = TP_STATUS_KERNEL;
            frame_idx = (frame_idx + 1) % req.tp_frame_nr;
            t_hdr = (struct tpacket_hdr *)rd[frame_idx].iov_base;
        }
    }
    
    munmap(ring, ring_size);
    free(rd);
    close(sock);
    return NULL;
}
