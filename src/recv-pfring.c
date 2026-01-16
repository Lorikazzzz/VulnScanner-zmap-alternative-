#ifdef USE_PFRING_ZC
#include "../include/scanner.h"

void *pfring_zc_receiver_thread(void *arg) { 
    thread_context_t *ctx = (thread_context_t *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((ctx->thread_id + ctx->config->senders) % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    if (!quiet_mode) printf("[*] Thread %d: Using PF_RING ZC Receiver\n", ctx->thread_id);

    pfring_zc_pkt_buff *zc_buf = pfring_zc_get_packet_handle(ctx->config->zc_pool);
    if (zc_buf == NULL) {
        fprintf(stderr, "[-] Failed to get ZC buffer handle for receiver\n");
        return NULL;
    }

    while (ctx->running && !stop_signal) {
        if (pfring_zc_recv_pkt(ctx->zc_queue, &zc_buf, 0) > 0) {
            unsigned char *pkt = pfring_zc_pkt_buff_data(zc_buf, ctx->zc_queue);
            process_packet(pkt, zc_buf->len, ctx->stats, ctx->config, ctx->src_ip);
            
            // Re-use or get new handle if needed. ZC recv swaps pointers.
        } else {
            // Optional: short sleep or poll if idle
            usleep(1);
        }
    }

    return NULL;
}
#endif
