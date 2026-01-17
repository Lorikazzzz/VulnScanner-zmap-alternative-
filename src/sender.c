#include "../include/scanner.h"

void ip_per_thread(ip_range_t *ip_ranges, int num_ip_ranges, port_range_t *port_ranges, int num_port_ranges, thread_context_t *contexts, int num_threads) { 
    uint64_t total_ips = calculate_total_ips(ip_ranges, num_ip_ranges);
    uint64_t total_ports = 0;
    for (int i = 0; i < num_port_ranges; i++) {
        total_ports += port_ranges[i].end - port_ranges[i].start + 1;
    }
    uint64_t total_packets = total_ips * total_ports;
    if (total_packets == 0) return;

    for (int t = 0; t < num_threads; t++) {
        uint64_t pkts_per_thread = total_packets / num_threads;
        uint64_t start_idx = t * pkts_per_thread;
        uint64_t end_idx = (t == num_threads - 1) ? total_packets : (t + 1) * pkts_per_thread;
        
        contexts[t].work.global_start_idx = start_idx;
        contexts[t].work.global_end_idx = end_idx;
        contexts[t].work.current_global_idx = start_idx;
        
        contexts[t].work.all_ip_ranges = ip_ranges;
        contexts[t].work.total_ip_ranges = num_ip_ranges;
        contexts[t].work.total_ips = total_ips;
        contexts[t].work.total_packets = total_packets;
        
        contexts[t].work.port_ranges = port_ranges;
        contexts[t].work.num_port_ranges = num_port_ranges;
        contexts[t].work.port_range_idx = 0;
    }
}

void rate_limit_batch(thread_context_t *ctx, int batch_size) { 
    if (ctx->config->rate_limit == 0) return;
    
    static __thread int calls = 0;
    if (++calls < 32) return;
    calls = 0;

    struct timeval now;
    gettimeofday(&now, NULL);
    
    double elapsed = (now.tv_sec - ctx->last_send_time.tv_sec) + (now.tv_usec - ctx->last_send_time.tv_usec) / 1000000.0;
    double target_time = (double)(batch_size * 32) / ctx->config->rate_limit;
    
    if (elapsed < target_time) {
        double sleep_us = (target_time - elapsed) * 1000000;
        if (sleep_us > 1500) {
            usleep((useconds_t)sleep_us - 200); 
        } else {
            while (elapsed < target_time) {
                gettimeofday(&now, NULL);
                elapsed = (now.tv_sec - ctx->last_send_time.tv_sec) + (now.tv_usec - ctx->last_send_time.tv_usec) / 1000000.0;
            }
        }
    }
    gettimeofday(&ctx->last_send_time, NULL);
}

void *sender_thread(void *arg) { 
    thread_context_t *ctx = (thread_context_t *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ctx->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    uint32_t xor_state = ctx->current_state;


    unsigned int frame_idx = 0;

    int version = TPACKET_V2;
    if (setsockopt(ctx->socket_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        // failed version
    }

    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = 4096 * 256;
    req.tp_block_nr = 64;
    req.tp_frame_size = 512; 
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    int val = 1;
    if (setsockopt(ctx->socket_fd, SOL_PACKET, PACKET_TX_HAS_OFF, &val, sizeof(val)) < 0) {
        // failed offset opt
    }

    int qbypass = 1;
    if (setsockopt(ctx->socket_fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qbypass, sizeof(qbypass)) < 0) {
        if (errno != ENOPROTOOPT) perror("setsockopt PACKET_QDISC_BYPASS");
    }

    if (setsockopt(ctx->socket_fd, SOL_PACKET, PACKET_TX_RING, (void *)&req, sizeof(req)) < 0) {
        return NULL;
    }

    size_t ring_size = req.tp_block_size * req.tp_block_nr;
    unsigned char *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->socket_fd, 0);
    if (ring == MAP_FAILED) {
        return NULL;
    }

    packet_t scan_pkt;
    if (ctx->config->scan_method == SCAN_METHOD_UDP) {
        create_udp_packet(&scan_pkt, ctx->src_ip, 0, ctx->src_port, ctx->work.port_ranges[0].start,
                         ctx->config->src_mac, ctx->config->dst_mac, ctx->config->probe_payload, ctx->config->probe_payload_len);
    } else {
        // Default to SYN
        create_syn_packet(&scan_pkt, ctx->src_ip, 0, 
                         ctx->src_port, ctx->work.port_ranges[0].start,
                         ctx->config->src_mac, ctx->config->dst_mac);
    }

    uint32_t tp_mac = TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
    for (int i = 0; i < req.tp_frame_nr; i++) {
        struct tpacket2_hdr *t_hdr = (struct tpacket2_hdr *)(ring + (i * req.tp_frame_size));
        t_hdr->tp_mac = tp_mac;
        t_hdr->tp_net = tp_mac + sizeof(struct ethhdr);
        unsigned char *pkt_ptr = (unsigned char *)t_hdr + tp_mac;
        memcpy(pkt_ptr, scan_pkt.buffer, scan_pkt.length);
    }
                     
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    ctx->last_send_time = start_time;
    ctx->packets_sent = 0;
    
    while (ctx->running && !stop_signal && ctx->work.current_global_idx < ctx->work.global_end_idx) {
        int batch_count = 0;
        int ring_batch = 0;

        while (ring_batch < BATCH_SIZE && ctx->work.current_global_idx < ctx->work.global_end_idx && !stop_signal) {
            struct tpacket2_hdr *t_hdr = (struct tpacket2_hdr *)(ring + (frame_idx * req.tp_frame_size));
            
            if (t_hdr->tp_status != TP_STATUS_AVAILABLE) {
                if (batch_count > 0) break; 
                send(ctx->socket_fd, NULL, 0, MSG_DONTWAIT);
                continue;
            }

            uint64_t index = blackrock_shuffle(&ctx->config->blackrock, ctx->work.current_global_idx);
            
            uint64_t ip_idx = index % ctx->work.total_ips;
            uint64_t port_total_idx = index / ctx->work.total_ips;

            uint32_t current_ip_nbo = get_ip_from_index(ip_idx, ctx->work.all_ip_ranges, ctx->work.total_ip_ranges);
            uint32_t current_ip_hbo = ntohl(current_ip_nbo);

            ctx->work.current_global_idx++;

            // Port selection
            uint16_t current_port = 0;
            uint64_t p_acc = 0;
            for (int p = 0; p < ctx->work.num_port_ranges; p++) {
                uint64_t p_count = ctx->work.port_ranges[p].end - ctx->work.port_ranges[p].start + 1;
                if (port_total_idx < p_acc + p_count) {
                    current_port = ctx->work.port_ranges[p].start + (port_total_idx - p_acc);
                    break;
                }
                p_acc += p_count;
            }

            if (is_blacklisted(current_ip_hbo)) continue;

            unsigned char *pkt_ptr = (unsigned char *)t_hdr + t_hdr->tp_mac;
            
            t_hdr->tp_len = scan_pkt.length;

            struct iphdr *iph = (struct iphdr *)(pkt_ptr + sizeof(struct ethhdr));
            
            iph->daddr = current_ip_nbo;
            iph->id = (uint16_t)xorshift32(&xor_state);
            iph->check = 0; 
            iph->check = calculate_ip_checksum(iph);

            if (ctx->config->scan_method == SCAN_METHOD_UDP) {
                struct udphdr *udph = (struct udphdr *)(pkt_ptr + sizeof(struct ethhdr) + sizeof(struct iphdr));
                udph->dest = htons(current_port);
                udph->check = 0;
            } else {
                struct tcphdr *tcph = (struct tcphdr *)(pkt_ptr + sizeof(struct ethhdr) + sizeof(struct iphdr));
                tcph->dest = htons(current_port);
                tcph->seq = htonl(xorshift32(&xor_state));
                tcph->check = 0; 
                tcph->check = calculate_tcp_checksum(tcph, ctx->src_ip, current_ip_nbo);
            }
            
            t_hdr->tp_status = TP_STATUS_SEND_REQUEST;
            frame_idx = (frame_idx + 1) % req.tp_frame_nr;
            ring_batch++; 
            batch_count++;
        }

        if (batch_count > 0) {
            int sent = send(ctx->socket_fd, NULL, 0, MSG_DONTWAIT);
             if (sent >= 0 || errno == ENOBUFS || errno == EAGAIN) {
                atomic_fetch_add(&ctx->stats->packets_sent, batch_count);
                ctx->packets_sent += batch_count;
            }
        }
        
        rate_limit_batch(ctx, batch_count);
    }
    
    munmap(ring, ring_size);
    return NULL;
}
