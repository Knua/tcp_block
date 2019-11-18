#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>

using namespace std;

#define max(a,b) (a > b ? a : b) 
#define min(a,b) (a < b ? a : b) 

uint32_t pow(uint32_t a, uint32_t n){ // return a^n
  uint32_t result = 1;
  while(n--){
    result *= a;
  }
  return result;
}

void usage() {
  printf("tcp_block <interface> <host>\n");
  printf("tcp_block wlan0 test.gilgil.net\n");
}

char * host_name;
int host_name_len;

// Layer 7
bool Data_checking(u_char * packet, uint32_t start, uint32_t end){
	if(start >= end) return true;

	if(strncmp((const char *)(packet + start), "GET", 3) == 0 ||
	strncmp((const char *)(packet + start), "POST", 4) == 0 ||
	strncmp((const char *)(packet + start), "HEAD", 4) == 0 ||
	strncmp((const char *)(packet + start), "PUT", 3) == 0 ||
	strncmp((const char *)(packet + start), "DELETE", 6) == 0 ||
	strncmp((const char *)(packet + start), "OPTIONS", 7) == 0) {
		// \x0d \x0a -> end of string
		const char * ptr = strstr((const char *)(packet + start), "Host:");
		if(ptr != NULL){
			char save_string[101] = "";
			for(int i = 6;; i++){
				if(strncmp((ptr + i), "\x0d", 1) == 0) break;
				strncat(save_string, (ptr + i), 1);
			}
			printf("[Work] Packet Hostname: %s\n", save_string);
			int cmp_len = strlen(save_string);

			if(strncmp((const char *)save_string, host_name, max(host_name_len, cmp_len)) == 0){
				printf("[Success] Correct HostName\n");
				return false;
			}
			else printf("[Work] Different HostName\n");
		}
		else printf("[Work] No HostName..\n");
	}
	return true;
}

void Data_check(u_char * packet, uint32_t start, uint32_t max_size){
	uint32_t end = start + 32;
	end = min(end, max_size);
  if(!Data_checking(packet, start, end)){ // false means find input hostname
    block_packet(packet);
  }
	printf("\n");
}

void block_packet(u_char * packet){
  
}

// Layer 4
uint32_t TCP_check(u_char * packet, uint32_t start){
	uint32_t tcp_start = start;
	uint32_t tcp_header_length = (packet[tcp_start + 12] & 0xf0) >> 2;
	return tcp_start + tcp_header_length;
}

// Layer 3
uint8_t ipv4_protocol_id;
uint32_t IPv4_check(u_char * packet, uint32_t start){
	uint32_t ipv4_start = start;
	uint32_t ipv4_header_length = (packet[ipv4_start] & 0x0f) * 4;
	ipv4_protocol_id = packet[ipv4_start + 9];
	return ipv4_start + ipv4_header_length;
}

int main(int argc, char* argv[]) 
{
  if (argc != 3) {
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

	host_name = argv[2];
	host_name_len = strlen(host_name);

  while (true) {
    struct pcap_pkthdr* header;
    u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    uint32_t ipv4_header_end = 0;
	  uint32_t tcp_header_end = 0;

    ipv4_header_end = IPv4_check(packet, 0);
    if(ipv4_protocol_id == 0x6){ // IPv4 -> TCP
    	tcp_header_end = TCP_check(packet, ipv4_header_end);
    }
    Data_check(packet, max(ipv4_header_end, tcp_header_end), header->caplen);
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
