#include "../include/scanner.h"
#include <getopt.h>

static void usage() {
    printf("Usage: ./scanner [options]\n");
    printf("  -h, --help                Print this help message\n");
    printf("  -p, --port=port           Port ranges to scan (e.g. 80, 443, 1-1024)\n");
    printf("  -t, --target-range=range   Target IP address or CIDR range\n");
    printf("  -r, --rate=pps            Set the send rate in packets per second\n");
    printf("  -B, --bandwidth=bps       Set the send rate in bits per second (e.g. 10M, 1G)\n");
    printf("  -i, --interface=name      Network interface to use\n");
    printf("  -S, --source-ip=ip        Source IP address\n");
    printf("  -G, --gateway-mac=mac     Gateway MAC address\n");
    printf("  -M, --probe-module=name   Scan method (tcp, udp)\n");
    printf("  -T, --sender-threads=num  Number of sender threads (default: 1)\n");
    printf("  -R, --receivers=num       Number of receiver threads (default: 1)\n");
    printf("  -c, --cooldown-time=sec   Cooldown time (default: 5s)\n");
    printf("  -s, --shards=N/M          Sharding (e.g. 1/6)\n");
    printf("  --icmp                    ICMP prescan\n");
    printf("  -w, --whitelist-file=path Whitelist file for target IPs\n");
    printf("  -b, --blacklist-file=path Blacklist file for target IPs\n");
    printf("  -o, --output-file=path    Output file (defaults to stdout)\n");
    printf("  -q, --quiet               Quiet mode, don't print progress\n");
    printf("\n");
    exit(0);
}

void parse_arguments(int argc, char **argv, scanner_config_t *config) {
    memset(config, 0, sizeof(scanner_config_t));
    config->senders = 1;
    config->receivers = 1;
    config->cooldown_secs = 5;
    config->rate_limit = DEFAULT_RATE;
    config->scan_method = SCAN_METHOD_SYN;
    config->target_range = "0.0.0.0/0";

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"rate", required_argument, 0, 'r'},
        {"bandwidth", required_argument, 0, 'B'},
        {"interface", required_argument, 0, 'i'},
        {"source-ip", required_argument, 0, 'S'},
        {"probe-module", required_argument, 0, 'M'},
        {"sender-threads", required_argument, 0, 'T'},
        {"receivers", required_argument, 0, 'R'},
        {"cooldown-time", required_argument, 0, 'c'},
        {"gateway-mac", required_argument, 0, 'G'},
        {"whitelist-file", required_argument, 0, 'w'},
        {"blacklist-file", required_argument, 0, 'b'},
        {"output-file", required_argument, 0, 'o'},
        {"quiet", no_argument, 0, 'q'},
        {"shards", required_argument, 0, 's'},
        {"target-range", required_argument, 0, 't'},
        {"icmp", no_argument, 0, 1003},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "qhp:t:r:B:i:S:M:T:R:c:G:w:b:o:s:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h': usage(); break;
            case 'p': config->num_port_ranges = parse_port_range(optarg, &config->port_ranges); break;
            case 't': config->target_range = strdup(optarg); break;
            case 'r': config->rate_limit = parse_scaled_value(optarg); break;
            case 'B': config->bandwidth_limit = parse_scaled_value(optarg); break;
            case 'i': config->interface = strdup(optarg); break;
            case 'S': config->source_ip = strdup(optarg); break;
            case 'M':
                if (strcmp(optarg, "tcp") == 0 || strcmp(optarg, "syn") == 0 || strcmp(optarg, "synscan") == 0) config->scan_method = SCAN_METHOD_SYN;
                else if (strcmp(optarg, "udp") == 0) config->scan_method = SCAN_METHOD_UDP;
                break;
            case 'T': config->senders = atoi(optarg); break;
            case 'R': config->receivers = atoi(optarg); break;
            case 'c': config->cooldown_secs = atoi(optarg); break;
            case 'G': {
                int m[6];
                if (sscanf(optarg, "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int j=0; j<6; j++) config->dst_mac[j] = (uint8_t)m[j];
                    config->gateway_set = 1;
                }
                break;
            }
            case 'w': config->whitelist_file = strdup(optarg); break;
            case 'b': config->blacklist_file = strdup(optarg); break;
            case 'o': config->output_file = strdup(optarg); break;
            case 'q': quiet_mode = 1; break;
            case 's': {
                char *slash = strchr(optarg, '/');
                if (slash) {
                    *slash = '\0';
                    config->shard = atoi(optarg) - 1;
                    config->shards = atoi(slash + 1);
                }
                break;
            }
            case 1003: config->icmp_prescan = 1; break;
        }
    }
    if (optind < argc) {
        config->target_range = strdup(argv[optind]);
    }

    if (config->num_port_ranges == 0 && config->scan_method != SCAN_METHOD_ICMP_ECHO) {
        printf("[-] Invalid port range\n");
        exit(1);
    }
}
