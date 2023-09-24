#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ethhdr* eth_header = (struct ethhdr*)packet;

    if (ntohs(eth_header->h_proto) == ETH_P_IP) { // Check if it's an IP packet
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ethhdr));
        int ip_header_len = ip_header->ip_hl << 2; // Calculate IP header length in bytes

        switch (ip_header->ip_p) { // Check the protocol field in IP header
        case IPPROTO_TCP: {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);
            printf("Protocol: TCP\n");
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);
            printf("Protocol: UDP\n");
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr* icmp_header = (struct icmphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);
            printf("Protocol: ICMP\n");
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Type: %d\n", icmp_header->type);
            break;
        }
        default:
            printf("Protocol: Unknown\n");
            break;
        }
    }
}

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Step 1: Open live pcap session on NIC with name "enp0s3" (Change this to your network interface name)
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // Step 2: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Close the handle
    pcap_close(handle);
    return 0;
}
