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

uint64_t calculate_total_ips(ip_range_t *ip_ranges, int num_ip_ranges) { 
    uint64_t total = 0;
    for (int i = 0; i < num_ip_ranges; i++) {
        uint64_t start_host = (uint64_t)ntohl(ip_ranges[i].start);
        uint64_t end_host = (uint64_t)ntohl(ip_ranges[i].end);
        total += (end_host - start_host + 1);
    }
    return total;
}

uint32_t get_ip_from_index(uint64_t index, ip_range_t *ip_ranges, int num_ip_ranges) { 
    for (int i = 0; i < num_ip_ranges; i++) {
        uint64_t start_host = (uint64_t)ntohl(ip_ranges[i].start);
        uint64_t end_host = (uint64_t)ntohl(ip_ranges[i].end);
        uint64_t count = end_host - start_host + 1;
        
        if (index < count) {
            uint64_t target_ip = start_host + index;
            return htonl((uint32_t)target_ip);
        }
        index -= count;
    }
    return 0;
}
