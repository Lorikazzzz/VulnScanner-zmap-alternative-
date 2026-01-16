#include "../include/scanner.h"
#include <math.h>

uint32_t xorshift32(uint32_t *state) { 
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

uint64_t parse_scaled_value(const char *str) { 
    char *endptr;
    double val = strtod(str, &endptr);
    if (*endptr == 'k' || *endptr == 'K') val *= 1000;
    else if (*endptr == 'm' || *endptr == 'M') val *= 1000000;
    else if (*endptr == 'g' || *endptr == 'G') val *= 1000000000;
    return (uint64_t)val;
}

void format_count(double count, char *buf) { 
    if (count >= 1000000000) sprintf(buf, "%.2fB", count / 1000000000);
    else if (count >= 1000000) sprintf(buf, "%.2fM", count / 1000000);
    else if (count >= 1000) sprintf(buf, "%.2fK", count / 1000);
    else sprintf(buf, "%.0f", count);
}

void format_zmap_rate(double rate, char *buf) { 
    if (rate >= 1000000.0) sprintf(buf, "%.2f Mp/s", rate / 1000000.0);
    else if (rate >= 1000.0) sprintf(buf, "%.1f Kp/s", rate / 1000.0);
    else sprintf(buf, "%.0f p/s", rate);
}

void int_to_ip(uint32_t ip_int, char *buffer) { 
    struct in_addr addr;
    addr.s_addr = ip_int;
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
}

uint32_t ip_to_int(const char *ip) { 
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) <= 0) return 0;
    return addr.s_addr;
}


static uint32_t feistel_keys[4];

void init_feistel_cipher() { 
    for (int i = 0; i < 4; i++) {
         feistel_keys[i] = (rand() & 0xFFFF) | ((rand() & 0xFFFF) << 16);
    }
}

static uint32_t feistel_round(uint32_t val, uint32_t key) {
    uint32_t x = val ^ key;
    x ^= x >> 16;
    x *= 0x85ebca6b;
    x ^= x >> 13;
    x *= 0xc2b2ae35;
    x ^= x >> 16;
    return x;
}

uint64_t encrypt_index(uint64_t index, uint64_t range_size) {
    if (range_size <= 1) return 0;
    
    uint64_t next_pow2 = 1;
    while (next_pow2 < range_size) next_pow2 <<= 1;
    

    int bits = 0;
    uint64_t temp = next_pow2 - 1;
    while (temp) { bits++; temp >>= 1; }
    
    int half_bits = (bits + 1) / 2;
    uint64_t mask = (1ULL << half_bits) - 1;
    uint64_t r_mask = (1ULL << (bits - half_bits)) - 1;

    uint64_t permuted = index;
    do {
        uint64_t L_blk = permuted >> (bits - half_bits);
        uint64_t R_blk = permuted & r_mask;
        
        for(int r = 0; r < 4; r++) {
            uint64_t f = feistel_round((uint32_t)R_blk, feistel_keys[r]);
            uint64_t next_L = R_blk;
            uint64_t next_R = L_blk ^ (f & ( (1ULL << (bits - half_bits)) - 1 ));
            
            L_blk = next_L;
            R_blk = next_R;
        }
        
        permuted = (L_blk << (bits - half_bits)) | R_blk;
        
    } while (permuted >= range_size);
    
    return permuted;
}

uint64_t calculate_total_ips(ip_range_t *ip_ranges, int num_ip_ranges) { 
    uint64_t total = 0;
    for (int i = 0; i < num_ip_ranges; i++) {
        uint32_t start = ip_ranges[i].start;
        uint32_t end = ip_ranges[i].end;
        if (start == 0 && end == 0xFFFFFFFF) return 4294967296ULL;
        uint32_t start_host = ntohl(start);
        uint32_t end_host = ntohl(end);
        total += (uint64_t)(end_host - start_host + 1);
    }
    return total;
}

uint32_t get_ip_from_index(uint64_t index, ip_range_t *ip_ranges, int num_ip_ranges) { 
    for (int i = 0; i < num_ip_ranges; i++) {
        uint32_t start = ntohl(ip_ranges[i].start);
        uint32_t end = ntohl(ip_ranges[i].end);
        uint64_t count = (uint64_t)end - start + 1;
        
        if (index < count) {
            return htonl(start + index);
        }
        index -= count;
    }
    return 0;
}
