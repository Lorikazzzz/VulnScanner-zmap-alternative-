#include "../include/scanner.h"

ip_range_t *blacklist = NULL;
int blacklist_count = 0;
ip_range_t *whitelist = NULL;
int whitelist_count = 0;

int is_blacklisted(uint32_t ip_hbo) { 
    if (!blacklist) return 0;
    for (int i = 0; i < blacklist_count; i++) {
        if (ip_hbo >= ntohl(blacklist[i].start) && ip_hbo <= ntohl(blacklist[i].end)) {
            return 1;
        }
    }
    return 0;
}

int is_whitelisted(uint32_t ip_hbo) { 
    if (!whitelist) return 1;
    for (int i = 0; i < whitelist_count; i++) {
        if (ip_hbo >= ntohl(whitelist[i].start) && ip_hbo <= ntohl(whitelist[i].end)) {
            return 1;
        }
    }
    return 0;
}

int load_exclusion_list(const char *filename, ip_range_t **list, int *count) { 
    FILE *f = fopen(filename, "r");
    if (!f) return 0;

    char line[64];
    while (fgets(line, sizeof(line), f)) {

        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        
        char *slash = strchr(line, '/');
        uint32_t ip, mask;
        if (slash) {
            *slash = '\0';
            ip = ntohl(ip_to_int(line));
            int bits = atoi(slash + 1);
            mask = (bits == 0 ? 0 : (~0U << (32 - bits)));
        } else {
            ip = ntohl(ip_to_int(line));
            mask = 0xFFFFFFFF;
        }
        
        if (ip != 0 || (line[0] != 0 && strcmp(line, "0.0.0.0") == 0)) {
            *list = realloc(*list, (*count + 1) * sizeof(ip_range_t));
            (*list)[*count].start = htonl(ip & mask);
            (*list)[*count].end = htonl(ip | ~mask);
            (*list)[*count].total_ips = (uint64_t)ntohl((*list)[*count].end) - ntohl((*list)[*count].start) + 1;
            (*count)++;
        }
    }
    fclose(f);
    return 1;
}

int load_blacklist(const char *filename) { 
    return load_exclusion_list(filename, &blacklist, &blacklist_count);
}

int load_whitelist(const char *filename) { 
    return load_exclusion_list(filename, &whitelist, &whitelist_count);
}

int parse_port_range(char *range, port_range_t **ranges) { 
    char *token, *saveptr;
    int count = 0;
    
    if (!range) return -1;
    
    char *temp = strdup(range);
    token = strtok_r(temp, ",", &saveptr);
    while (token) {
        count++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(temp);
    
    if (count == 0) return -1;
    
    *ranges = malloc(count * sizeof(port_range_t));
    if (!*ranges) return -1;
    
    temp = strdup(range);
    token = strtok_r(temp, ",", &saveptr);
    count = 0;
    
    while (token) {
        char *dash = strchr(token, '-');
        int start, end;
        if (dash) {
            *dash = '\0';
            start = atoi(token);
            end = atoi(dash + 1);
        } else {
            start = atoi(token);
            end = atoi(token);
        }
        
        if (start < 1 || end > 65535 || start > end) {
            free(*ranges);
            free(temp);
            return -1;
        }

        int is_dup = 0;
        for (int i = 0; i < count; i++) {
            if ((*ranges)[i].start == start && (*ranges)[i].end == end) {
                is_dup = 1;
                break;
            }
        }
        
        if (!is_dup) {
            (*ranges)[count].start = start;
            (*ranges)[count].end = end;
            count++;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(temp);
    return count;
}

int parse_ip_range(char *range, ip_range_t **ranges) { 
    if (!range) return -1;
    
    char *slash = strchr(range, '/');
    if (slash) {
        *ranges = malloc(sizeof(ip_range_t));
        if (!*ranges) return -1;
        
        char *range_copy = strdup(range);
        slash = strchr(range_copy, '/');
        *slash = '\0';
        uint32_t ip = ip_to_int(range_copy);
        int bits = atoi(slash + 1);
        
        if (bits == 0) {
            (*ranges)[0].start = 0;
            (*ranges)[0].end = 0xFFFFFFFF;
            free(range_copy);
            return 1;
        }
        
        if (bits < 0 || bits > 32) {
            free(*ranges);
            free(range_copy);
            return -1;
        }
        
        uint32_t ip_hbo = ntohl(ip);
        uint32_t mask = (bits == 0 ? 0 : (~0U << (32 - bits)));
        uint32_t network = ip_hbo & mask;
        uint32_t broadcast = network | ~mask;
        
        (*ranges)[0].start = htonl(network);
        (*ranges)[0].end = htonl(broadcast);
        
        free(range_copy);
        return 1;
    }
    
    char *dash = strchr(range, '-');
    if (dash) {
        char *start_ip = strndup(range, dash - range);
        char *end_ip = strdup(dash + 1);
        
        *ranges = malloc(sizeof(ip_range_t));
        if (!*ranges) {
            free(start_ip);
            free(end_ip);
            return -1;
        }
        
        (*ranges)[0].start = ip_to_int(start_ip);
        (*ranges)[0].end = ip_to_int(end_ip);
        
        free(start_ip);
        free(end_ip);
        
        if ((*ranges)[0].start == 0 || (*ranges)[0].end == 0) {
            free(*ranges);
            return -1;
        }
        return 1;
    }
    
    *ranges = malloc(sizeof(ip_range_t));
    if (!*ranges) return -1;
    
    (*ranges)[0].start = ip_to_int(range);
    (*ranges)[0].end = (*ranges)[0].start;
    
    if ((*ranges)[0].start == 0) {
        free(*ranges);
        return -1;
    }
    return 1;
}
