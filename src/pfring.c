#ifdef USE_PFRING
#include "../include/scanner.h"
#include <pfring.h>
#include <errno.h>

void *pfring_sender_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ctx->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    uint32_t xor_state = ctx->current_state;

    printf("[*] Thread %d: Using PF_RING\n", ctx->thread_id);
    


    ctx->ring = pfring_open(ctx->config->interface, 1500, PF_RING_PROMISC);
    if (ctx->ring == NULL) {

        printf("pfring_open error [%s] (is pf_ring loaded?)\n", strerror(errno));
        return NULL;
    }
    
    pfring_set_socket_mode(ctx->ring, 0); 
    
    if (pfring_enable_ring(ctx->ring) != 0) {
        printf("pfring_enable_ring error\n");
        pfring_close(ctx->ring);
        return NULL;
    }

    packet_t template_pkt;
    create_syn_packet(&template_pkt, ctx->src_ip, 0, 
                     ctx->src_port, ctx->work.port_ranges[0].start,
                     ctx->config->src_mac, ctx->config->dst_mac);
                     
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    ctx->last_send_time = start_time;
    ctx->packets_sent = 0;
    
    uint64_t total_range_size = calculate_total_ips(ctx->work.all_ip_ranges, ctx->work.total_ip_ranges);
    
    unsigned char *pkt_ptr = template_pkt.buffer;
    
    while (ctx->running && !stop_signal && ctx->work.current_global_idx < ctx->work.global_end_idx) {
        int batch_count = 0;
        
        while (batch_count < BATCH_SIZE && ctx->work.current_global_idx < ctx->work.global_end_idx && !stop_signal) {
             uint64_t real_idx = encrypt_index(ctx->work.current_global_idx, total_range_size);
             uint32_t current_ip_nbo = get_ip_from_index(real_idx, ctx->work.all_ip_ranges, ctx->work.total_ip_ranges);
             uint32_t current_ip_hbo = ntohl(current_ip_nbo);
             
             ctx->work.current_global_idx++;

             int r_port_idx = xorshift32(&xor_state) % ctx->work.num_port_ranges;
             uint16_t current_port = ctx->work.port_ranges[r_port_idx].start + 
                                    (xorshift32(&xor_state) % (ctx->work.port_ranges[r_port_idx].end - ctx->work.port_ranges[r_port_idx].start + 1));

             if (is_blacklisted(current_ip_hbo)) continue;

             struct iphdr *iph = (struct iphdr *)(pkt_ptr + sizeof(struct ethhdr));
             struct tcphdr *tcph = (struct tcphdr *)(pkt_ptr + sizeof(struct ethhdr) + sizeof(struct iphdr));
             
             iph->daddr = current_ip_nbo;
             tcph->dest = htons(current_port);
             tcph->seq = htonl(xorshift32(&xor_state));
             
             iph->check = 0; 
             iph->check = calculate_ip_checksum(iph);
             tcph->check = 0; 
             tcph->check = calculate_tcp_checksum(tcph, ctx->src_ip, current_ip_nbo);
             
             int sent_bytes = pfring_send(ctx->ring, (char *)pkt_ptr, template_pkt.length, 0);
             
             if (sent_bytes >= 0) {
                 batch_count++;
             }
        }
        
        if (batch_count > 0) {
            atomic_fetch_add(&ctx->stats->packets_sent, batch_count);
            ctx->packets_sent += batch_count;
        }
        rate_limit_batch(ctx, batch_count);
    }
    
    pfring_close(ctx->ring);
    return NULL;
}
#endif
