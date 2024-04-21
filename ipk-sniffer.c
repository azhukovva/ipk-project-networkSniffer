#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <pcap.h>
#include <signal.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#define MAX_BUFF 1024
#define FILTER_SIZE MAX_BUFF*4
#define ERRBUF_SIZE MAX_BUFF/4

#define MAC_LENGTH 18
#define ETHER_SIZE 14
#define HEX_SIZE 6

#define FILTER_LENGTH 8

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

struct globals_t {
    pcap_if_t* alldevsp;    //list of all network interfaces
    pcap_t* handle;
};

struct globals_t globals;

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
    args->n = 1;
}

void error(const char* message, ...) {
    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

void cleanup() {
    pcap_freealldevs(globals.alldevsp);
    pcap_close(globals.handle);
}

void handle_signal() {
    cleanup();
    exit(EXIT_SUCCESS);
}

void print_packet(const unsigned char* packet, int len) {
    int i, j, cols;
    for (i = 0; i < len; i += 16) {
        printf("\n0x%04x:", i);

        cols = i + 16;

        for (j = i; j < cols; j++) {
            if (j < len)
                printf(" %02x", packet[j]);
            else
                printf("   ");
        }
        printf(" ");
        for (j = i; cols < len ? j < cols : j < len; j++)
            printf("%c", isprint(packet[j]) ? packet[j] : '.');
    }
    printf("\n");
}

void handle_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet) {

    
}

pcap_if_t* get_network_interfaces() {
    pcap_if_t* list = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&list, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    return list;
}

void print_network_interfaces() {
    pcap_if_t* item = get_network_interfaces();

    printf("Interface\tDescription\n");
    while (item) {
        printf("%s\t%s\n", item->name, item->description);
        item = item->next;
    }

    pcap_freealldevs(item);
    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    
    signal(SIGINT, handle_signal);

    struct args_t args;
    reset_args(&args);

    if (argc == 1) {
        print_network_interfaces();
        return 0;
    }


    for(int i = 1; i < argc; i++){
        char* opt = argv[i];                            // Current option (E.g. -p or -i)
        char* arg = (i + 1) < argc ? argv[i+1] : NULL;  // Possible argument

        if(strcmp(opt, "-i") == 0 || strcmp(opt, "--interface") == 0){
            if (argc == 2) {
                print_network_interfaces();
                return 0;
            }
            // TODO check if arg is valid

            strcpy(args.interface, arg);
            i++;
        } else if (strcmp(opt, "-p") == 0) {
            if(arg == NULL){
                error("Port is missing");
            }

            args.dest_port = atoi(arg);
            args.src_port = atoi(arg);
            // go to the next option
            i++;
        } else if (strcmp(opt, "--port-source") == 0) {
            if(arg == NULL){
                error("Port is missing");
            }

            args.src_port = atoi(arg);
            // go to the next option
            i++;
        } else if (strcmp(opt, "--port-destination") == 0) {
            if(arg == NULL){
                error("Port is missing");
            }

            args.dest_port = atoi(arg);
            // go to the next option
            i++;
        } else if (strcmp(opt, "-n") == 0) {
            if(arg == NULL){
                error("Number of packets is missing");
            }

            args.n = atoi(arg);
            // go to the next option
            i++;
        } else if (strcmp(opt, "--tcp") == 0) {
            args.is_tcp = 1;
        } else if (strcmp(opt, "--udp") == 0) {
            args.is_udp = 1;
        } else if (strcmp(opt, "--arp") == 0) {
            args.is_arp = 1;
        } else if (strcmp(opt, "--ndp") == 0) {
            args.is_ndp = 1;
        } else if (strcmp(opt, "--icmp4") == 0) {
            args.is_icmp4 = 1;
        } else if (strcmp(opt, "--icmp6") == 0) {
            args.is_icmp6 = 1;
        } else if (strcmp(opt, "--igmp") == 0) {
            args.is_igmp = 1;
        } else if (strcmp(opt, "--mld") == 0) {
            args.is_mld = 1;
        } else {
            error("Option \"%s\" is unknown", opt);
        }
    }

    
    return 0;
}