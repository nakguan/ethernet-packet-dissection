#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet{
	uint8_t ether_dhost[ETHER_ADDR_LEN];
	uint8_t ether_shost[ETHER_ADDR_LEN];
	uint16_t ether_type;
};

struct sniff_ip{
	uint8_t ip_buf[9];
	uint8_t proctocol;
	uint8_t ip_buf2[2];
	uint8_t src_ip[4];
	uint8_t dst_ip[4];
};

#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

struct sniff_tcp{
	uint16_t th_sport;
	uint16_t th_dport;
};
 

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;

    struct sniff_ethernet *ethernet;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;

    const u_char* packet;

    int size_ip;
    int size_tcp;

    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

   	ethernet = (struct sniff_ethernet*)(packet);
   	ip = (struct sniff_ip*)(packet+SIZE_ETHERNET);
   	tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+20);
   	if (ethernet->ether_type != 8) continue;
   	
   	printf("Ethernet destination MAC address is ");

   	for(int i=0;i<ETHER_ADDR_LEN;i++)
   	{
   		printf("%x",ethernet->ether_dhost[i]);
   		if(i!=ETHER_ADDR_LEN-1)
   			printf(":");
   	}
   	printf("\n");
   	printf("Ethernet source MAC address is ");
   	for(int i=0;i<ETHER_ADDR_LEN;i++)
   	{
   		printf("%x",ethernet->ether_shost[i]);
   		if(i!=ETHER_ADDR_LEN-1)
   			printf(":");
   	}
   	printf("\n");
   	printf("Source IP address is ");
   	for(int i=0;i<4;i++)
   	{
   		printf("%d",ip->src_ip[i]);
   		if(i!=3)
   			printf(".");
   	}
   	printf("\n");
   	printf("Destination IP address is ");
   	for(int i=0;i<4;i++)
   	{
   		printf("%d",ip->dst_ip[i]);
   		if(i!=3)
   			printf(".");
   	}
   	printf("\n");
   	printf("Source Port is %d\n",tcp->th_sport);
   	printf("Destination Port is %d\n",tcp->th_dport);
   	printf("-----------------------------------------------------------\n");

  }

  pcap_close(handle);
  return 0;
}
