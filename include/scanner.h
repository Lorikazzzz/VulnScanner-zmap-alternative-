#ifndef SCANNER_H
#define SCANNER_H

#include "scanner_defs.h"


void ip_per_thread(ip_range_t *ip_ranges, int num_ip_ranges, port_range_t *port_ranges, int num_port_ranges,thread_context_t *contexts, int num_threads);
void *sender_thread(void *arg);
#ifdef USE_PFRING_ZC
void *pfring_zc_sender_thread(void *arg);
void *pfring_zc_receiver_thread(void *arg);
#endif
void rate_limit_batch(thread_context_t *ctx, int batch_size);


void *receiver_thread(void *arg);
void process_packet(const uint8_t *packet, int length, stats_t *stats, scanner_config_t *config, uint32_t src_ip);
void init_writer(const char *filename);
void push_to_writer(const char *str);
void *writer_thread_func(void *arg);


int parse_port_range(char *range, port_range_t **ranges);
int parse_ip_range(char *range, ip_range_t **ranges);
int load_blacklist(const char *filename);
int load_whitelist(const char *filename);
int load_exclusion_list(const char *filename, ip_range_t **list, int *count);
int is_blacklisted(uint32_t ip_hbo);
int is_whitelisted(uint32_t ip_hbo);


int get_default_iface(char *iface);
int get_ifdetails(const char *iface, int *ifindex, uint8_t *mac);
int get_default_gateway(char *gateway_ip);
int get_gateway_mac(uint8_t *mac);
uint32_t get_local_ip(const char *interface);
unsigned short calculate_ip_checksum(struct iphdr *iph);
unsigned short calculate_tcp_checksum(struct tcphdr *tcp, uint32_t src_ip, uint32_t dst_ip);
void create_syn_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip,unsigned short src_port, unsigned short dst_port,uint8_t *src_mac, uint8_t *dst_mac);
void create_udp_packet(packet_t *packet, uint32_t src_ip, uint32_t dst_ip,unsigned short src_port, unsigned short dst_port,uint8_t *src_mac, uint8_t *dst_mac);


uint32_t xorshift32(uint32_t *state);
uint64_t parse_scaled_value(const char *str);
void format_count(double count, char *buf);
void format_zmap_rate(double rate, char *buf);
void int_to_ip(uint32_t ip_int, char *buffer);
uint32_t ip_to_int(const char *ip);
uint32_t get_ip_from_index(uint64_t index, ip_range_t *ip_ranges, int num_ip_ranges);
uint64_t calculate_total_ips(ip_range_t *ip_ranges, int num_ip_ranges);


extern ip_range_t *blacklist;
extern int blacklist_count;
extern ip_range_t *whitelist;
extern int whitelist_count;

#endif
