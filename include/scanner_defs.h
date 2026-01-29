#ifndef SCANNER_DEFS_H
#define SCANNER_DEFS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <stdatomic.h>

#ifdef USE_PFRING
#include <pfring.h>
#endif
#ifdef USE_PFRING_ZC
#include <pfring_zc.h>
#endif
#include "crypto-blackrock.h"

#define MAX_PORTS 65535
#define MAX_THREADS 256
#define PACKET_SIZE 1514
#define DEFAULT_RATE 10000000
#define DEFAULT_BANDWIDTH 0
#define MAX_IPS_PER_THREAD 16777216

// Scan Methods
#define SCAN_METHOD_SYN 0
#define SCAN_METHOD_ACK 1
#define SCAN_METHOD_FIN 2
#define SCAN_METHOD_NULL 3
#define SCAN_METHOD_XMAS 4
#define SCAN_METHOD_UDP 5
#define SCAN_METHOD_ICMP_ECHO 6

#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define TCP_HDRLEN 20
#define BATCH_SIZE 10 //more is better for recv + peak pps but unstable
#define WRITER_QUEUE_SIZE 1000000

typedef struct { //def arg
    char *interface;
    char *source_ip;
    char *target_range;
    char *port_range;
    char *blacklist_file;
    char *whitelist_file;
    char *output_file;
    unsigned long rate_limit;
    unsigned long bandwidth_limit;
    int senders;
    int receivers;
    int verbose;
    int dry_run;
    int cooldown_secs;
    int scan_type;
    int output_format;
    int quiet;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    int ifindex;
    int gateway_set;
    int scan_method;
#ifdef USE_PFRING_ZC
    pfring_zc_cluster *zc_cluster;
    pfring_zc_buffer_pool *zc_pool;
#endif
    char *probe_args;
    uint8_t *probe_payload;
    size_t probe_payload_len;
    struct BlackRock blackrock;
    int is_multiport;
} scanner_config_t;

typedef struct { //scan
    _Atomic unsigned long long packets_sent;
    _Atomic unsigned long long packets_received;
    _Atomic unsigned long long hosts_up;
    _Atomic unsigned long long ports_open;
    _Atomic unsigned long long syn_acks;
    _Atomic unsigned long long rst_replies;
    _Atomic unsigned long long icmp_unreach;
    double start_time;
    double end_time;
    uint64_t total_packets;
} stats_t;

typedef struct { //port
    unsigned short start;
    unsigned short end;
} port_range_t;

typedef struct { //range 
    uint32_t start;
    uint32_t end;
    uint64_t total_ips;
} ip_range_t;

typedef struct { //thread worker
    port_range_t *port_ranges;
    int num_port_ranges;
    int port_range_idx;
    uint16_t current_port;
    ip_range_t *ranges;     
    int num_ranges;
    int current_range_idx;
    uint32_t current_ip;
    uint64_t global_start_idx;
    uint64_t global_end_idx;
    uint64_t current_global_idx;
    ip_range_t *all_ip_ranges;
    int total_ip_ranges;
    uint64_t total_ips;
    uint64_t total_packets;
} thread_work_t;

typedef struct { //packet struct
    unsigned char buffer[PACKET_SIZE];
    size_t length;
    struct sockaddr_in dest_addr;
} packet_t;



typedef struct { //thread context
    int thread_id;
    int socket_fd;
#ifdef USE_PFRING
    pfring *ring;
#endif
#ifdef USE_PFRING_ZC
    pfring_zc_queue *zc_queue;
#endif
    scanner_config_t *config;
    stats_t *stats;
    thread_work_t work;
    int running;
    uint32_t src_ip;
    unsigned short src_port;
    struct timeval last_send_time;
    uint64_t packets_sent;
    uint32_t current_state;
    struct sockaddr_ll sll;
} thread_context_t;


typedef struct { //process queue
    char queue[WRITER_QUEUE_SIZE][32]; 
    int head;
    int tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int stop;
    FILE *file;
} writer_context_t;


extern writer_context_t writer_ctx;
extern volatile int stop_signal;
extern pthread_mutex_t output_mutex;
extern FILE *output_file_ptr;
extern int quiet_mode;
extern uint8_t *seen_ips;

#define IS_IP_SEEN(ip) (seen_ips[(uint32_t)(ip) >> 3] & (1 << ((uint32_t)(ip) & 7)))
#define MARK_IP_SEEN(ip) (seen_ips[(uint32_t)(ip) >> 3] |= (1 << ((uint32_t)(ip) & 7)))

#endif

