#include "../include/scanner.h"


volatile int stop_signal = 0;
pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *output_file_ptr = NULL;
int quiet_mode = 0;


extern pthread_t writer_thread_id; 

void help() { 
    printf("Basic Options:\n");
    printf("  -p, --target-port=port      Port(s) to scan (default: 80)\n");
    printf("  -o, --output-file=name      Output file (results will be appended)\n");
    printf("  -b, --blacklist-file=path   File of subnets to exclude\n");
    printf("  -w, --whitelist-file=path   File of subnets to include\n");
    printf("  -r, --rate=pps              Set the send rate in packets/sec (default: %d)\n", DEFAULT_RATE);
    printf("  -B, --bandwidth=bps         Set the send rate in bits/second\n");
    printf("  -i, --interface=name        Network interface to use\n");
    printf("  -S, --source-ip=ip          Source IP address (default: auto)\n");
    printf("  -T, --sender-threads=n      Number of sender threads (default: 4)\n");
    printf("  -R, --receivers=n           Number of receiver threads (default: 1)\n");
    printf("  -c, --cooldown-time=secs    How long to wait for responses (default: 5)\n");
    printf("  -G, --gateway-mac=addr      Manual gateway MAC (e.g. 00:11:22:33:44:55)\n");
    printf("  -v, --verbose               More verbose output\n");
    printf("  -d, --dryrun                Don't actually send packets\n");
    printf("  -q  --quiet                 Runs the scanner at quiet mode\n");
    printf("  -h, --help                  Print this help and exit\n");
}

void parse_arguments(int argc, char *argv[], scanner_config_t *config) { 
    int opt;
    int help_requested = 0;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"source-ip", required_argument, 0, 'S'},
        {"target-ip", required_argument, 0, 't'},
        {"target-port", required_argument, 0, 'p'},
        {"rate", required_argument, 0, 'r'},
        {"bandwidth", required_argument, 0, 'B'},
        {"blacklist-file", required_argument, 0, 'b'},
        {"whitelist-file", required_argument, 0, 'w'},
        {"output-file", required_argument, 0, 'o'},
        {"sender-threads", required_argument, 0, 'T'},
        {"receivers", required_argument, 0, 'R'},
        {"cooldown-time", required_argument, 0, 'c'},
        {"gateway-mac", required_argument, 0, 'G'},
        {"verbose", no_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"dryrun", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "i:s:t:p:r:b:w:o:B:S:T:R:G:q:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i': config->interface = strdup(optarg); break;
            case 's':
            case 'S': config->source_ip = strdup(optarg); break;
            case 'T': 
                config->senders = atoi(optarg);
                if (config->senders < 1) config->senders = 1;
                if (config->senders > MAX_THREADS) config->senders = MAX_THREADS;
                break;
            case 'R':
                config->receivers = atoi(optarg);
                if (config->receivers < 1) config->receivers = 1;
                break;
            case 't': config->target_range = strdup(optarg); break;
            case 'p': config->port_range = strdup(optarg); break;
            case 'r':
                config->rate_limit = parse_scaled_value(optarg);
                if (config->rate_limit == 0) config->rate_limit = DEFAULT_RATE;
                break;
            case 'b': config->blacklist_file = strdup(optarg); break;
            case 'w': config->whitelist_file = strdup(optarg); break;
            case 'o': config->output_file = strdup(optarg); break;
            case 'B': config->bandwidth_limit = parse_scaled_value(optarg); break;
            case 'v': config->verbose = 1; break;
            case 'd': config->dry_run = 1; break;
            case 'c': config->cooldown_secs = atoi(optarg); break;
            case 'G': {
                int m[6];
                if (sscanf(optarg, "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i=0; i<6; i++) config->dst_mac[i] = (uint8_t)m[i];
                    config->gateway_set = 1;
                } else {
                    // invalid mac
                    exit(1);
                }
                break;
            }
            case 'q': {
                config->quiet = 1; 
                quiet_mode = 1;
                break;
            }
            case 'h': help_requested = 1; break;
            default: exit(1);
        }
    }
    
    if (optind < argc && !config->target_range) {
        config->target_range = strdup(argv[optind]);
    }
    
    if (help_requested) {
        help();
        exit(0);
    }
    
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
        
        double percent = 0;
        if (ctx->stats->total_packets > 0) {
            percent = (double)current_sent / ctx->stats->total_packets * 100.0;
        }
        
        double avg_pps_sent = elapsed > 0 ? (double)current_sent / elapsed : 0;
        double avg_pps_recv = elapsed > 0 ? (double)current_recv / elapsed : 0;
        double hitrate = current_sent > 0 ? (double)hits / current_sent * 100.0 : 0;
        
        int hrs = (int)elapsed / 3600;
        int mins = ((int)elapsed % 3600) / 60;
        int secs = (int)elapsed % 60;
        
        char s_pps_sent[32], s_avg_pps_sent[32];
        char s_pps_recv[32], s_avg_pps_recv[32];
        
        format_zmap_rate(pps_sent, s_pps_sent);
        format_zmap_rate(avg_pps_sent, s_avg_pps_sent);
        format_zmap_rate(pps_recv, s_pps_recv);
        format_zmap_rate(avg_pps_recv, s_avg_pps_recv);

        if (!quiet_mode) {
            if (hrs > 0) {
                fprintf(stderr, "\r%d:%02d:%02d %d%%; send: %llu %s (%s avg); recv: %llu %s (%s avg); hitrate: %.2f%%", 
                        hrs, mins, secs, (int)percent, current_sent, s_pps_sent, s_avg_pps_sent, 
                        current_recv, s_pps_recv, s_avg_pps_recv, hitrate);
            } else {
                fprintf(stderr, "\r%02d:%02d %d%%; send: %llu %s (%s avg); recv: %llu %s (%s avg); hitrate: %.2f%%", 
                        mins, secs, (int)percent, current_sent, s_pps_sent, s_avg_pps_sent, 
                        current_recv, s_pps_recv, s_avg_pps_recv, hitrate);
            }
            fflush(stderr);
        }
    }
    if (!quiet_mode) fprintf(stderr, "\n");
    return NULL;
}

void sighandler(int sig) { 
    stop_signal = 1;
}

int main(int argc, char *argv[]) { 
    if (geteuid() != 0) {
        fprintf(stderr, "[-] This program must be run as root\n");
        return 1;
    }
    
    signal(SIGINT, sighandler);

    scanner_config_t config = {
        .interface = NULL,
        .source_ip = NULL,
        .target_range = strdup("0.0.0.0/0"),
        .port_range = NULL,
        .blacklist_file = NULL,
        .whitelist_file = NULL,
        .output_file = NULL,
        .rate_limit = DEFAULT_RATE,
        .bandwidth_limit = DEFAULT_BANDWIDTH,
        .senders = 4,
        .receivers = 1,
        .verbose = 0,
        .dry_run = 0,
        .cooldown_secs = 5,
        .scan_type = 0,
        .quiet = 0,
        .output_format = 3
    };
    
    stats_t stats = {0};
    struct timeval tv;
    gettimeofday(&tv, NULL);
    stats.start_time = tv.tv_sec + tv.tv_usec / 1000000.0;
    
    parse_arguments(argc, argv, &config);
    

    init_writer(config.output_file);
    pthread_t writer_tid;
    pthread_create(&writer_tid, NULL, writer_thread_func, NULL);
    writer_thread_id = writer_tid;

    if (config.blacklist_file) {
        if (!quiet_mode) printf("[*] Loading blacklist from %s...\n", config.blacklist_file);
        if (load_blacklist(config.blacklist_file)) {
            if (!quiet_mode) printf("[*] Loaded %d exclusion ranges\n", blacklist_count);
        }
    }
    
    if (config.whitelist_file) {
        if (!quiet_mode) printf("[*] Loading whitelist from %s...\n", config.whitelist_file);
        if (load_whitelist(config.whitelist_file)) {
            if (!quiet_mode) printf("[*] Loaded %d inclusion ranges\n", whitelist_count);
        }
    }
    

    srand(time(NULL) ^ getpid());
    
    init_feistel_cipher();


    if (config.dry_run) {
        if (!quiet_mode) printf("[*] Dry run mode - no packets will be sent\n");
        return 0;
    }
    
    port_range_t *port_ranges = NULL;
    int num_port_ranges = parse_port_range(config.port_range, &port_ranges);
    if (num_port_ranges <= 0) {
        fprintf(stderr, "[-] Invalid port range\n");
        return 1;
    }
    
    ip_range_t *active_ip_ranges = NULL;
    int num_active_ranges = 0;

    if (config.whitelist_file && whitelist_count > 0) {
        if (!quiet_mode) printf("[*] Using whitelist as primary scan targets\n");
        active_ip_ranges = whitelist;
        num_active_ranges = whitelist_count;
    } else {
        int res = parse_ip_range(config.target_range, &active_ip_ranges);
        if (res <= 0) {
            fprintf(stderr, "[-] Invalid IP range\n");
            return 1;
        }
        num_active_ranges = res;
    }

    uint64_t total_ips = calculate_total_ips(active_ip_ranges, num_active_ranges);
    uint64_t total_ports = 0;
    for (int i = 0; i < num_port_ranges; i++) {
        total_ports += port_ranges[i].end - port_ranges[i].start + 1;
    }
    uint64_t total_packets = total_ips * total_ports;
    stats.total_packets = total_packets;
    
    if (total_packets == 0) {
        fprintf(stderr, "[-] Nothing to scan\n");
        return 1;
    }
    
    uint32_t src_ip = 0;
    if (config.source_ip) {
        src_ip = ip_to_int(config.source_ip);
    } else {
        src_ip = get_local_ip(config.interface);
    }
    
    if (src_ip == 0) {
        fprintf(stderr, "[-] Could not determine source IP\n");
        return 1;
    }
    
    if (config.bandwidth_limit > 0) {
        config.rate_limit = (unsigned long)(config.bandwidth_limit / (84 * 8));
        if (config.rate_limit == 0) config.rate_limit = 1;
    }
    
    thread_context_t contexts[MAX_THREADS];
    memset(contexts, 0, sizeof(contexts));
    
    ip_per_thread(active_ip_ranges, num_active_ranges, port_ranges, num_port_ranges, 
                   contexts, config.senders);
    
    pthread_t sender_threads[MAX_THREADS];
    srand(time(NULL));
    
    if (!config.interface) {
        char auto_iface[64];
        if (get_default_iface(auto_iface) == 0) {
            config.interface = strdup(auto_iface);
        } else {
            config.interface = strdup("eth0");
        }
    }
    if (get_ifdetails(config.interface, &config.ifindex, config.src_mac) < 0) {
        fprintf(stderr, "[-] Could not get details for interface %s\n", config.interface);
        return 1;
    }

#ifdef USE_PFRING_ZC
    int cluster_id = 10;
    config.zc_cluster = pfring_zc_create_cluster(cluster_id, 1500, 0, 1024 + (config.senders + config.receivers) * BATCH_SIZE, 0, NULL, 0);
    if (config.zc_cluster == NULL) {
        return 1;
    }
    config.zc_pool = pfring_zc_create_buffer_pool(config.zc_cluster, 1024 + (config.senders + config.receivers) * BATCH_SIZE);
    if (config.zc_pool == NULL) {
        return 1;
    }
#endif
    
    char src_ip_str[32];
    int_to_ip(src_ip, src_ip_str);

    if (!quiet_mode) {
        printf("[*] Source IP: %s\n", src_ip_str);
        printf("[*] Interface: %s (Index: %d)\n", config.interface, config.ifindex);
        printf("[*] Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               config.src_mac[0], config.src_mac[1], config.src_mac[2],
               config.src_mac[3], config.src_mac[4], config.src_mac[5]);
        
        if (!config.gateway_set) {
            if (get_gateway_mac(config.dst_mac) < 0) {
                printf("[!] Gateway MAC not found, using broadcast (This is usually BAD for WAN scanning)\n");
                memset(config.dst_mac, 0xFF, 6);
            }
        }
        
        printf("[*] Destination (Gateway) MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               config.dst_mac[0], config.dst_mac[1], config.dst_mac[2],
               config.dst_mac[3], config.dst_mac[4], config.dst_mac[5]);
    } else {
        if (!config.gateway_set) {
            if (get_gateway_mac(config.dst_mac) < 0) {
                memset(config.dst_mac, 0xFF, 6);
            }
        }
    }
    

    for (int i = 0; i < config.senders; i++) {
        contexts[i].thread_id = i;
        contexts[i].config = &config;
        contexts[i].stats = &stats;
        contexts[i].running = 1;
        contexts[i].src_ip = src_ip;
        contexts[i].src_port = 50000 + i;
        contexts[i].packets_sent = 0;
        gettimeofday(&contexts[i].last_send_time, NULL);
        contexts[i].current_state = (i + 1) * 1234567 + (uint32_t)time(NULL);
        
        contexts[i].socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (contexts[i].socket_fd < 0) {
            return 1;
        }
        
        memset(&contexts[i].sll, 0, sizeof(struct sockaddr_ll));
        contexts[i].sll.sll_family = AF_PACKET;
        contexts[i].sll.sll_ifindex = config.ifindex;
        contexts[i].sll.sll_halen = ETH_ALEN;
        memcpy(contexts[i].sll.sll_addr, config.dst_mac, ETH_ALEN);
        
        if (bind(contexts[i].socket_fd, (struct sockaddr *)&contexts[i].sll, sizeof(struct sockaddr_ll)) < 0) {
            return 1;
        }

#ifdef USE_PFRING_ZC
        char zc_dev_name[128];
        snprintf(zc_dev_name, sizeof(zc_dev_name), "zc:%s", config.interface);
        contexts[i].zc_queue = pfring_zc_open_device(config.zc_cluster, zc_dev_name, tx_only, 0);
        if (contexts[i].zc_queue == NULL) {
            fprintf(stderr, "[-] pfring_zc_open_device error for thread (PFRING ZEROCOPY LOADED?)%d (errno: %d, %s)\n", i, errno, strerror(errno));
            return 1;
        }
        pthread_create(&sender_threads[i], NULL, pfring_zc_sender_thread, &contexts[i]);
#else
        pthread_create(&sender_threads[i], NULL, sender_thread, &contexts[i]);
#endif
    }


    pthread_t status_tid;
    thread_context_t status_ctx;
    status_ctx.stats = &stats;
    status_ctx.running = 1;
    pthread_create(&status_tid, NULL, status_thread, &status_ctx);
    

    pthread_t receiver_threads[MAX_THREADS];
    thread_context_t receiver_contexts[MAX_THREADS];
    
    for (int i = 0; i < config.receivers; i++) {
        receiver_contexts[i].thread_id = i;
        receiver_contexts[i].config = &config;
        receiver_contexts[i].stats = &stats;
        receiver_contexts[i].running = 1;
        receiver_contexts[i].src_ip = src_ip;
#ifdef USE_PFRING_ZC
        char zc_dev_name[128];
        snprintf(zc_dev_name, sizeof(zc_dev_name), "zc:%s", config.interface);
        receiver_contexts[i].zc_queue = pfring_zc_open_device(config.zc_cluster, zc_dev_name, rx_only, 0);
        if (receiver_contexts[i].zc_queue == NULL) {
            fprintf(stderr, "[-] pfring_zc_open_device error for receiver (PFRING ZEROCOPY LOADED?)%d (errno: %d, %s)\n", i, errno, strerror(errno));
            return 1;
        }
        pthread_create(&receiver_threads[i], NULL, pfring_zc_receiver_thread, &receiver_contexts[i]);
#else
        pthread_create(&receiver_threads[i], NULL, receiver_thread, &receiver_contexts[i]);
#endif
    }
    

    for (int i = 0; i < config.senders; i++) {
        pthread_join(sender_threads[i], NULL);
        close(contexts[i].socket_fd);
    }
    

    for (int i = 0; i < config.cooldown_secs; i++) {
        if (stop_signal) break;
        if (!quiet_mode) {
            printf("\r[*] Cooldown: %d/%d seconds", i + 1, config.cooldown_secs);
            fflush(stdout);
        }
        sleep(1);
    }
    if (!quiet_mode) printf("\n");
    

    for (int i = 0; i < config.receivers; i++) {
        receiver_contexts[i].running = 0;
        pthread_join(receiver_threads[i], NULL);
    }
    

    status_ctx.running = 0;
    pthread_join(status_tid, NULL);
    

    pthread_mutex_lock(&writer_ctx.mutex);
    writer_ctx.stop = 1;
    pthread_cond_signal(&writer_ctx.cond);
    pthread_mutex_unlock(&writer_ctx.mutex);
    pthread_join(writer_tid, NULL);
    
#ifdef USE_PFRING_ZC
    pfring_zc_destroy_cluster(config.zc_cluster);
#endif
    if (!quiet_mode) printf("[*] Scan completed.\n");
    return 0;
}

