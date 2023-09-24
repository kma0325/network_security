#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <pcap.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};


void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ethhdr* eth_header = (struct ethhdr*)packet;
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header->h_source[0], eth_header->h_source[1],eth_header->h_source[2], eth_header->h_source[3],eth_header->h_source[4], eth_header->h_source[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header->h_dest[0], eth_header->h_dest[1],eth_header->h_dest[2], eth_header->h_dest[3],eth_header->h_dest[4], eth_header->h_dest[5]);
        
    if (ntohs(eth_header->h_proto) == ETH_P_IP) { // Check if it's an IP packet
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ethhdr));
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
      
        int ip_header_len = ip_header->ip_hl << 2;
        
        switch(ip_header->ip_p ) { // Check the protocol field in IP header
          case IPPROTO_TCP:
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len);
            printf("Protocol: TCP\n");
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
            break;
      
          default:
            printf("ignore\n");
          }
       
        }
    }
}

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

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
