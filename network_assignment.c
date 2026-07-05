#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void print_mac(u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));

    int ip_header_len = ip->iph_ihl * 4;

    printf("=====================================\n");
    printf("Src MAC: ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("Dst MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    printf("Protocol: TCP\n");

    struct tcpheader *tcp = (struct tcpheader *)
                             ((u_char *)ip + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;

    printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    if (payload_len > 0) {
        const u_char *payload = (u_char *)tcp + tcp_header_len;
        printf("HTTP Message (%d bytes):\n", payload_len);
        for (int i = 0; i < payload_len; i++) {
            putchar(isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    } else {
        printf("HTTP Message: 없음\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;
}