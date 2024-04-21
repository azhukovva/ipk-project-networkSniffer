#ifndef ARGS_H
#define ARGS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_BUFF 1000

struct args_t {
    // interface to sniff
    char interface[MAX_BUFF];
    // port filters
    int src_port;
    int dest_port;
    // protocol filters
    int is_tcp;
    int is_udp;
    int is_arp;
    int is_ndp;
    int is_icmp4;
    int is_icmp6;
    int is_igmp;
    int is_mld;
    // number of packets to sniff
    int n;
};

void reset_args(struct args_t *args);

#endif