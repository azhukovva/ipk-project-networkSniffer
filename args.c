#include "args.h"

void reset_args(struct args_t *args) {
    memset(args->interface, 0, sizeof(args->interface));
    args->src_port = 0;
    args->dest_port = 0;
    args->is_tcp = 0;
    args->is_udp = 0;
    args->is_arp = 0;
    args->is_ndp = 0;
    args->is_icmp4 = 0;
    args->is_icmp6 = 0;
    args->is_igmp = 0;
    args->is_mld = 0;
    args->n = 0;
}
