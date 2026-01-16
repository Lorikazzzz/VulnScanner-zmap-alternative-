#ifdef USE_PFRING_ZC
#include "../include/scanner.h"

void *pfring_zc_sender_thread(void *arg) { 
    thread_context_t *ctx = (thread_context_t *)arg;
    uint32_t xor_state = ctx->current_state;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ctx->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    if (!quiet_mode) printf("[*] Thread %d: Using PF_RING ZC Sender\n", ctx->thread_id);

    packet_t template_pkt;
    create_syn_packet(&template_pkt, ctx->src_ip, 0, 
                     ctx->src_port, ctx->work.port_ranges[0].start,
                     ctx->config->src_mac, ctx->config->dst_mac);

    pfring_zc_pkt_buff *zc_buf;
    uint64_t total_range_size = calculate_total_ips(ctx->work.all_ip_ranges, ctx->work.total_ip_ranges);

    while (ctx->running && !stop_signal && ctx->work.current_global_idx < ctx->work.global_end_idx) {
        int batch_count = 0;

        while (batch_count < BATCH_SIZE && ctx->work.current_global_idx < ctx->work.global_end_idx && !stop_signal) {
            zc_buf = pfring_zc_get_packet_handle(ctx->config->zc_pool);
            if (zc_buf == NULL) {
                // Out of buffers, flush and wait   
                pfring_zc_sync_queue(ctx->zc_queue, tx_only);
                usleep(1);
                continue;
            }

            uint64_t real_idx = encrypt_index(ctx->work.current_global_idx, total_range_size);
            uint32_t current_ip_nbo = get_ip_from_index(real_idx, ctx->work.all_ip_ranges, ctx->work.total_ip_ranges);
            uint32_t current_ip_hbo = ntohl(current_ip_nbo);
            
            ctx->work.current_global_idx++;

            int r_port_idx = xorshift32(&xor_state) % ctx->work.num_port_ranges;
            uint16_t current_port = ctx->work.port_ranges[r_port_idx].start + 
                                   (xorshift32(&xor_state) % (ctx->work.port_ranges[r_port_idx].end - ctx->work.port_ranges[r_port_idx].start + 1));

            if (is_blacklisted(current_ip_hbo)) {
                continue;
            }

            unsigned char *data = pfring_zc_pkt_buff_data(zc_buf, ctx->zc_queue);
            memcpy(data, template_pkt.buffer, template_pkt.length);
            zc_buf->len = template_pkt.length;

            struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
            struct tcphdr *tcph = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
            
            iph->daddr = current_ip_nbo;
            iph->id = (uint16_t)xorshift32(&xor_state);
            tcph->dest = htons(current_port);
            tcph->seq = htonl(xorshift32(&xor_state));
            
            iph->check = 0; 
            iph->check = calculate_ip_checksum(iph);
            tcph->check = 0; 
            tcph->check = calculate_tcp_checksum(tcph, ctx->src_ip, current_ip_nbo);

            if (pfring_zc_send_pkt(ctx->zc_queue, &zc_buf, 0) >= 0) {
                batch_count++;
            }
        }

        if (batch_count > 0) {
            pfring_zc_sync_queue(ctx->zc_queue, tx_only);
            atomic_fetch_add(&ctx->stats->packets_sent, batch_count);
            ctx->packets_sent += batch_count;
        }

        rate_limit_batch(ctx, batch_count);
    }

    return NULL;
}
#endif
