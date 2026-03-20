#include "../include/scanner.h"
#include <signal.h>
#include <sys/mman.h>

extern volatile int stop_signal;
extern stats_t stats;
extern uint8_t *seen_ips;
extern uint8_t *alive_ips;
extern int quiet_mode;

static void sighandler(int sig) {
    if (stop_signal) exit(1);
    stop_signal = 1;
}

void *status_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    unsigned long long last_sent = 0;
    unsigned long long last_recv = 0;
    struct timeval last_time;
    gettimeofday(&last_time, NULL);
    sleep(1);
    while (ctx->running && !stop_signal) {
        sleep(1);
        struct timeval now;
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start_time.tv_sec) + (now.tv_usec - start_time.tv_usec) / 1000000.0;
        double since_last = (now.tv_sec - last_time.tv_sec) + (now.tv_usec - last_time.tv_usec) / 1000000.0;
        unsigned long long current_sent = atomic_load(&ctx->stats->packets_sent);
        unsigned long long current_recv = atomic_load(&ctx->stats->packets_received);
        unsigned long long hits = atomic_load(&ctx->stats->ports_open);
        
        double pps_sent = since_last > 0 ? (double)(current_sent - last_sent) / since_last : 0;
        double pps_recv = since_last > 0 ? (double)(current_recv - last_recv) / since_last : 0;
        last_sent = current_sent;
        last_recv = current_recv;
        last_time = now;
        double percent = (ctx->stats->total_packets > 0) ? (double)current_sent / ctx->stats->total_packets * 100.0 : 0;
        double avg_pps_sent = elapsed > 0 ? (double)current_sent / elapsed : 0;
        
        double hitrate = 0;
        if (current_sent > 0) {
            hitrate = (double)hits / current_sent * 100.0;
        }
        char s_pps_sent[32], s_avg_pps_sent[32], s_pps_recv[32];
        format_zmap_rate(pps_sent, s_pps_sent);
        format_zmap_rate(avg_pps_sent, s_avg_pps_sent);
        format_zmap_rate(pps_recv, s_pps_recv);
        if (!quiet_mode) {
            fprintf(stderr, "\r%02d:%02d %d%%; send: %llu %s (%s avg); recv: %llu %s; hitrate: %.4f%%", 
                    (int)elapsed/60, (int)elapsed%60, (int)percent, current_sent, s_pps_sent, s_avg_pps_sent, current_recv, s_pps_recv, hitrate);
            fflush(stderr);
        }
    }
    return NULL;
}

void setup_scan(scanner_config_t *config) {
    signal(SIGINT, sighandler);
    if (!config->interface) {
        config->interface = malloc(64);
        get_default_iface(config->interface);
    }
    get_ifdetails(config->interface, &config->ifindex, config->src_mac);
    if (!config->source_ip) {
        config->source_ip_int = get_local_ip(config->interface);
    } else {
        config->source_ip_int = ip_to_int(config->source_ip);
    }
    if (!config->gateway_set) {
        if (get_gateway_mac(config->dst_mac) < 0) memset(config->dst_mac, 0xFF, 6);
    }

    if (config->whitelist_file) {
        if (!load_whitelist(config->whitelist_file)) {
            fprintf(stderr, "[-] Failed to load whitelist from %s\n", config->whitelist_file);
            exit(1);
        }
    }
    if (config->blacklist_file) {
        if (!load_blacklist(config->blacklist_file)) {
            fprintf(stderr, "[-] Failed to load blacklist from %s\n", config->blacklist_file);
            exit(1);
        }
    }

    if (!quiet_mode) {
        struct in_addr addr;
        addr.s_addr = config->source_ip_int;
        printf("[*] Source IP: %s\n", inet_ntoa(addr));
        printf("[*] Interface: %s (Index: %d)\n", config->interface, config->ifindex);
        printf("[*] Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               config->src_mac[0], config->src_mac[1], config->src_mac[2],
               config->src_mac[3], config->src_mac[4], config->src_mac[5]);
        printf("[*] Destination (Gateway) MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               config->dst_mac[0], config->dst_mac[1], config->dst_mac[2],
               config->dst_mac[3], config->dst_mac[4], config->dst_mac[5]);
    }
}

void run_scan(scanner_config_t *config) {
    init_writer(config->output_file);
    pthread_t writer_tid;
    pthread_create(&writer_tid, NULL, writer_thread_func, NULL);
    if (stop_signal) goto cleanup;

    seen_ips = calloc(1ULL << 29, 1);
    if (config->icmp_prescan) alive_ips = calloc(1ULL << 29, 1);
    if (stop_signal) goto cleanup;

    ip_range_t *active_ranges = whitelist ? whitelist : NULL;
    int num_ranges = whitelist_count;
    if (!active_ranges) {
        num_ranges = parse_ip_range(config->target_range && config->target_range[0] ? config->target_range : "0.0.0.0/0", &active_ranges);
    }
    uint64_t total_ips = calculate_total_ips(active_ranges, num_ranges);
    uint64_t total_ports = 0;
    for (int i = 0; i < config->num_port_ranges; i++) {
        total_ports += config->port_ranges[i].end - config->port_ranges[i].start + 1;
    }
    uint64_t total_packets = total_ips * total_ports;
    uint64_t full_start = 0, full_end = total_packets;
    if (config->shards > 1) {
        uint64_t per_shard = total_packets / config->shards;
        full_start = config->shard * per_shard;
        full_end = (config->shard == config->shards - 1) ? total_packets : (config->shard + 1) * per_shard;
        total_packets = full_end - full_start;
    }
    blackrock_init(&config->blackrock, total_ips * total_ports, rand(), 4);
    
    if (config->icmp_prescan) {
        alive_ips = calloc(1ULL << 29, 1);
        alive_queue = calloc(ALIVE_QUEUE_SIZE, sizeof(_Atomic uint32_t));
        atomic_init(&alive_queue_head, 0);
        atomic_init(&alive_queue_tail, 0);
        atomic_init(&icmp_sender_done, 0);
    }

    config->original_scan_method = config->scan_method;
    if (config->icmp_prescan) {
        config->scan_method = SCAN_METHOD_ICMP_ECHO;
    }

    memset(&stats, 0, sizeof(stats_t));
    stats.total_packets = total_packets;
    thread_context_t scan_ctx[MAX_THREADS];
    ip_per_thread(active_ranges, num_ranges, config->port_ranges, config->num_port_ranges, scan_ctx, config->senders, full_start, full_end);
    
    pthread_t senders[MAX_THREADS], receivers[MAX_THREADS], alivers[8], status_tid;
    
    for (int i = 0; i < config->senders; i++) {
        scan_ctx[i].thread_id = i;
        scan_ctx[i].config = config;
        scan_ctx[i].stats = &stats;
        scan_ctx[i].running = 1;
        scan_ctx[i].src_ip = config->source_ip_int;
        scan_ctx[i].src_port = 50000 + i;
        scan_ctx[i].socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_ifindex = config->ifindex, .sll_halen = ETH_ALEN };
        memcpy(sll.sll_addr, config->dst_mac, ETH_ALEN);
        bind(scan_ctx[i].socket_fd, (struct sockaddr *)&sll, sizeof(sll));
        pthread_create(&senders[i], NULL, sender_thread, &scan_ctx[i]);
    }

    int num_alivers = config->icmp_prescan ? 4 : 0;
    thread_context_t alive_ctx[8];
    for (int i = 0; i < num_alivers; i++) {
        alive_ctx[i] = scan_ctx[0];
        alive_ctx[i].thread_id = i + 100;
        alive_ctx[i].src_port = 60000 + i;
        alive_ctx[i].socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        pthread_create(&alivers[i], NULL, alive_sender_thread, &alive_ctx[i]);
    }

    thread_context_t r_ctx[MAX_THREADS];
    for (int i = 0; i < config->receivers; i++) {
        r_ctx[i] = scan_ctx[0];
        r_ctx[i].thread_id = i;
        r_ctx[i].running = 1;
        pthread_create(&receivers[i], NULL, receiver_thread, &r_ctx[i]);
    }

    thread_context_t s_ctx = { .stats = &stats, .running = 1 };
    pthread_create(&status_tid, NULL, status_thread, &s_ctx);

    for (int i = 0; i < config->senders; i++) pthread_join(senders[i], NULL);
    atomic_store(&icmp_sender_done, 1);
    
    for (int i = 0; i < num_alivers; i++) pthread_join(alivers[i], NULL);
    
    for (int i = 0; i < config->cooldown_secs && !stop_signal; i++) sleep(1);
    for (int i = 0; i < config->receivers; i++) { r_ctx[i].running = 0; pthread_join(receivers[i], NULL); }
    s_ctx.running = 0; pthread_join(status_tid, NULL);

    if (config->icmp_prescan) {
        free(alive_queue); alive_queue = NULL;
        config->scan_method = config->original_scan_method;
    }

cleanup:
    writer_ctx.stop = 1;
    pthread_cond_broadcast(&writer_ctx.cond);
    pthread_join(writer_tid, NULL);
    if (seen_ips) { free(seen_ips); seen_ips = NULL; }
    if (alive_ips) { free(alive_ips); alive_ips = NULL; }
}
