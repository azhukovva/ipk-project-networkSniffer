/**
 * @author xzhuka01
 */

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

enum protocol_t {
    TCP, UDP,
    ARP, NDP, 
    IGMP, MLD,
    ICMP4, ICMP6,
};

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

/**
 * @brief Reset args
 */
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

/**
 * @brief Error print
 */
void error(const char* message, ...) {
    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

/**
 * @brief clenup for global variables
 */
void cleanup() {
    pcap_freealldevs(globals.alldevsp);
    pcap_close(globals.handle);
}

/**
 * @brief CTRL + C handler
 */
void handle_signal() {
    cleanup();
    exit(EXIT_SUCCESS);
}

/**
 * @brief Generates a filter expression based on the provided arguments.
 *
 * @param expr Pointer to the destination buffer where the filter expression will be stored.
 * @param args Pointer to the arguments containing protocol type flags and optional port numbers.
 * 
 * @return void
 */
void generate_filter_expr(char* expr, struct args_t* args) {
    char result[MAX_BUFF] = { 0 };

    const char* apply_filter[] = {
        [TCP] = "tcp",
        [UDP] = "udp",
        [ICMP4] = "icmp",
        [ICMP6] = "icmp6",
        [ARP] = "arp",
        [NDP] = "(icmp6 and icmp6[0] >= 133 and icmp6 and icmp6[0] <= 136)",
        [IGMP] = "igmp",
        [MLD] = "(icmp6 and icmp6[0] >= 130 and icmp6[0] <= 132)"
    };

    int filters_enabled[FILTER_LENGTH] = {
        args->is_tcp,
        args->is_udp,
        args->is_icmp4,
        args->is_icmp6,
        args->is_arp,
        args->is_ndp,
        args->is_igmp,
        args->is_mld
    };

    int has_filters = 0;
    for(int i = 0; i < FILTER_LENGTH; i++){
        has_filters = filters_enabled[i];

        if(has_filters){
            break;
        }  
    }

    for (int i = 0; i < FILTER_LENGTH; i++) {
        char buff[FILTER_SIZE] = { 0 };
        if (filters_enabled[i]) {

            switch (i) {
            case TCP: 
            case UDP:
                if (args->src_port == 0 && args->dest_port == 0) {
                    sprintf(buff, (strlen(result) > 0 ? " or %s" : "%s"), apply_filter[i]);
                }
                else if(args->src_port && args->dest_port == 0){
                    sprintf(buff, (strlen(result) > 0 ? " or (%s src port %d)" : "(%s src port %d)"), apply_filter[i], args->src_port);
                } else if (args->dest_port && args->src_port == 0){
                    sprintf(buff, (strlen(result) > 0 ? " or (%s dst port %d)" : "(%s dst port %d)"), apply_filter[i], args->dest_port);
                } else {
                    sprintf(buff, (strlen(result) > 0 ? " or (%s (src port %d and dst port %d))" : "(%s (src port %d and dst port %d))"), apply_filter[i], args->src_port, args->dest_port);
                }
                break;
            case ICMP4: case ICMP6:
            case ARP: case IGMP:
            case NDP: case MLD:
                sprintf(buff, (strlen(result) > 0 ? " or %s" : "%s"), apply_filter[i]);
                break;
            }
            strcat(result, buff);
        }
    }
    if(!has_filters && (args->src_port || args->dest_port)){
        char buff[FILTER_SIZE] = { 0 };
        if(args->src_port && args->dest_port == 0){
            sprintf(buff, "src port %d", args->src_port);
        } else if (args->dest_port && args->src_port == 0){
            sprintf(buff, "dst port %d", args->dest_port);
        } else {
            sprintf(buff, "(src port %d and dst port %d)", args->src_port, args->dest_port);
        }
        strcat(result, buff);
    }

    sprintf(expr, strlen(result) > 0 ? "(%s)" : "", result);
}

/**
 * @brief Sets the timestamp string based on the packet header information.
 *
 * @param dest Pointer to the destination buffer where the timestamp string will be stored.
 * @param header Pointer to the packet header containing timestamp information.
 * 
 * @return void
 */
void set_timestamp(char* dest, const struct pcap_pkthdr* header) {
    char buffer[MAX_BUFF] = {0};
    char timestamp[40] = {0};
    struct tm* time = localtime(&header->ts.tv_sec);
    strftime(timestamp, 30, "%Y-%m-%dT%H:%M:%S", time);
    sprintf(buffer, "%s.%03ld%+03ld:%02ld", timestamp, header->ts.tv_usec / 1000, time->tm_gmtoff / 3600,
            labs(time->tm_gmtoff % 3600) / 60);
    strcpy(dest, buffer);
}

/**
 * @brief Converts an array of bytes into a hexadecimal string representation.
 *
 * @param dest Pointer to the destination buffer where the hexadecimal string will be stored.
 * @param bytes Pointer to the array of bytes to be converted.
 * 
 * @return void
 */
void print_hex(char* dest, uint8_t* bytes) {
    char hex[MAC_LENGTH] = { 0 };
    for (int i = 0; i < HEX_SIZE; i++) {
        char hh[4] = { 0 };

        sprintf(hh, (i < HEX_SIZE - 1 ? "%02x:" : "%02x"), bytes[i]);
        strcat(hex, hh);
    }
    strcpy(dest, hex); //
}

/**
 * @brief Prints the content of a packet in hexadecimal and ASCII format.
 *
 * @param packet Pointer to the packet data.
 * @param len Length of the packet data, in bytes.
 * 
 * @return void
 */
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

/**
 * @brief Handles a captured network packet.
 * 
 * @param args Unused argument. Can be NULL.
 * @param header Pointer to the packet header containing metadata like timestamp and packet length.
 * @param packet Pointer to the captured packet data.
 * 
 * @return void
 */
void handle_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet) {

    struct ether_header* eth_header = (struct ether_header*)packet;

    char src_dst_addr[MAC_LENGTH] = { 0 };   
    char timestamp[MAX_BUFF] = { 0 };         
    char src_ip[MAX_BUFF] = { 0 };             
    char dst_ip[MAX_BUFF] = { 0 };            

    set_timestamp(timestamp, header);
    printf("timestamp: %s\n", timestamp);
    print_hex(src_dst_addr, eth_header->ether_shost);
    printf("src MAC: %s\n", src_dst_addr);
    print_hex(src_dst_addr, eth_header->ether_dhost);
    printf("dst MAC: %s\n", src_dst_addr);
    printf("frame length: %d bytes\n", header->caplen);

    switch (ntohs(eth_header->ether_type)) {
    case ETHERTYPE_IP: {        

        struct ip* ip_header = (struct ip*)(packet + ETHER_SIZE);      

        inet_ntop(AF_INET, &ip_header->ip_src.s_addr, src_ip, MAX_BUFF);
        inet_ntop(AF_INET, &ip_header->ip_dst.s_addr, dst_ip, MAX_BUFF);

        printf("src IP: %s\ndst IP: %s\n", src_ip, dst_ip);

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + ETHER_SIZE + sizeof(struct ip));      //tcp header
            printf("src PORT: %d\ndst PORT: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr* udp_header = (struct udphdr*)(packet + ETHER_SIZE + sizeof(struct ip));      //udp header
            printf("src PORT: %d\ndst PORT: %d\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
        }

        // Other protocols do not have any port number
        break;
    }
    case ETHERTYPE_ARP: {
        struct ether_arp* arp_header = (struct ether_arp*)(packet + ETHER_SIZE);        //arp header

        inet_ntop(AF_INET, &arp_header->arp_spa, src_ip, MAX_BUFF);
        inet_ntop(AF_INET, &arp_header->arp_tpa, dst_ip, MAX_BUFF);

        printf("src IP: %s\ndst IP: %s\n", src_ip, dst_ip);
        break;
    }
    case ETHERTYPE_IPV6: {
        struct ip6_hdr* ip6_header = (struct ip6_hdr*)(packet + ETHER_SIZE);        //ipv6 header

        inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

        printf("src IP: %s\ndst IP: %s\n", src_ip, dst_ip);
        break;
    }
    }
    print_packet(packet, header->caplen);
    printf("\n");
}

/**
 * @brief Retrieves a list of network interfaces available on the system.
 *
 * @return A pointer to the first element of the list of network interfaces
 */
pcap_if_t* get_network_interfaces() {
    pcap_if_t* list = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&list, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    return list;
}

/**
 * @brief Prints information about network interfaces available on the system.
 *
 * @return void
 */
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

    globals.alldevsp = get_network_interfaces();

    char filter_expr[FILTER_SIZE] = { 0 };  // filter expr buffer
    char errbuf[ERRBUF_SIZE] = { 0 };       // error buffer

    generate_filter_expr(filter_expr, &args);

    struct bpf_program filter;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(args.interface, &net, &mask, errbuf)) {
        cleanup();
        error("Can't get netmask for device: %s", errbuf);
    }

    globals.handle = pcap_open_live(args.interface, BUFSIZ, 1, 1, errbuf);
    if (globals.handle == NULL) {
        cleanup();
        error("Unable to open device: %s", errbuf);
    }

    if (pcap_compile(globals.handle, &filter, filter_expr, 0, net) == -1) {
        cleanup();
        error("Unable to compile filter expression: %s", pcap_geterr(globals.handle));
    }

    if (pcap_setfilter(globals.handle, &filter) == -1) {
        cleanup();
        error("Unable to set filters: %s", pcap_geterr(globals.handle));
    }

    int loop = pcap_loop(globals.handle, args.n, handle_packet, (unsigned char*)NULL);
    if (loop < 0) {
        cleanup();
        error("Pcap loop failed: %s", pcap_geterr(globals.handle));
    }

    cleanup();
    return 0;
}