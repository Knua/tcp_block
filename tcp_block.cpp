#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <memory.h>
#include <netdb.h>
#include <sys/types.h>

#define max(a,b) (a > b ? a : b) 
#define min(a,b) (a < b ? a : b) 

#define ETHERNET_header_end 14
#define ETHERTYPE 12
#define ETHERNET_DESTINATION_MAC_ADDR 0
#define ETHERNET_SOURCE_MAC_ADDR 6
#define MAC_address_length 6
#define IPv4_address_length 4
#define IPv4_SOURCE_IP_ADDR 12
#define IPv4_DESTINATION_IP_ADDR 16
#define IPv4_checksum 10
#define TCP_SOURCE_PORT_NUM 0
#define TCP_DESTINATION_PORT_NUM 2
#define TCP_port_length 4
#define TCP_SEQ_NUM 4
#define TCP_ACK_NUM 8
#define TCP_Flag 13
#define TCP_FIN_Flag 7
#define TCP_RST_Flag 5
#define TCP_checksum 16

#define Forward_FIN_flag 0
#define Backward_FIN_flag 0
// 0 -> RST

uint32_t pow(uint32_t a, uint32_t n){ // return a^n
	uint32_t result = 1;
	while(n--){
		result *= a;
	}
	return result;
}

void copy_6byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 6; i++){
        dst[i] = src[i];
    }
}
void copy_4byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 4; i++){
        dst[i] = src[i];
    }
}

void usage() {
	printf("tcp_block <interface> <host>\n");
	printf("tcp_block wlan0 test.gilgil.net\n");
}

char * host_name;
int host_name_len;

uint8_t ipv4_protocol_id;
uint16_t ethernet_protocol_type;

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
				printf("[Success] Correct HostName\n\n");
				return false;
			}
			else printf("[Work] Different HostName\n\n");
		}
		else printf("[Work] No HostName..\n\n");
	}
	return true;
}

typedef struct _tcp_pseudo_checksum {
    uint8_t src_ip_addr[4];
	uint8_t dst_ip_addr[4];
	uint8_t reserved;
	uint8_t protocol_id;
	uint16_t tcp_length;
} tcp_pseudo_checksum;

uint16_t CheckSum(uint16_t * buffer, uint32_t size){
    uint32_t checksum = 0;
    while(size > 1){
        checksum += *buffer++;
        size -= sizeof(uint16_t);
    }
    if(size) checksum += *(uint16_t *)buffer;

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    return (uint16_t)(~checksum);
}

void Forward_RST(uint8_t * packet, uint32_t packet_size, uint32_t ipv4_header_end, uint32_t tcp_header_end, pcap_t * handle){
	
	uint32_t new_SEQ_NUM = *(packet + TCP_SEQ_NUM + ipv4_header_end) + (packet_size - tcp_header_end);
	new_SEQ_NUM = htonl(new_SEQ_NUM);
	for(int i = 0; i < 4; i++){
		*(packet + TCP_SEQ_NUM + ipv4_header_end + 3 - i) = new_SEQ_NUM % 256;
		new_SEQ_NUM /= 256;
	}

	uint8_t save_tcp_flag = *(packet + TCP_Flag + ipv4_header_end);
	save_tcp_flag = htonl(save_tcp_flag);
	save_tcp_flag |= 0b00000100;
	*(packet + TCP_Flag + ipv4_header_end) = save_tcp_flag;	

	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = CheckSum((uint16_t *)(packet + ETHERNET_header_end), ipv4_header_end - ETHERNET_header_end);

	tcp_pseudo_checksum tcp_pseudo_check;
	
	// must be implemented

	tcp_pseudo_check.protocol_id = 0x6;

	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = 0x0000;
	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = CheckSum((uint16_t *)(packet + tcp_header_end), sizeof(tcp_pseudo_checksum));
	
	if(pcap_sendpacket(handle, packet, packet_size) != 0) printf("[Error] Failed to send Block Packet..\n");
}

void Forward_FIN(uint8_t * packet, uint32_t packet_size, uint32_t ipv4_header_end, uint32_t tcp_header_end, pcap_t * handle){

	// if(pcap_sendpacket(handle, packet, packet_size) != 0) printf("[Error] Failed to send Block Packet..\n");
}
void Backward_RST(uint8_t * packet, uint32_t packet_size, uint32_t ipv4_header_end, uint32_t tcp_header_end, pcap_t * handle){

	// if(pcap_sendpacket(handle, packet, packet_size) != 0) printf("[Error] Failed to send Block Packet..\n");
}
void Backward_FIN(uint8_t * packet, uint32_t packet_size, uint32_t ipv4_header_end, uint32_t tcp_header_end, pcap_t * handle){

	// if(pcap_sendpacket(handle, packet, packet_size) != 0) printf("[Error] Failed to send Block Packet..\n");
}

void block_packet(uint8_t * packet, uint32_t packet_size, uint32_t ipv4_header_end, uint32_t tcp_header_end, pcap_t * handle){

	uint8_t src_mac_addr[MAC_address_length];
	uint8_t dst_mac_addr[MAC_address_length];
	uint8_t src_ip_addr[IPv4_address_length];
	uint8_t dst_ip_addr[IPv4_address_length];
	uint8_t src_port_num[TCP_port_length];
	uint8_t dst_port_num[TCP_port_length];

	copy_6byte(packet + ETHERNET_SOURCE_MAC_ADDR, src_mac_addr);
	copy_6byte(packet + ETHERNET_DESTINATION_MAC_ADDR, dst_mac_addr);
	copy_4byte(packet + IPv4_SOURCE_IP_ADDR + ETHERNET_header_end, src_ip_addr);
	copy_4byte(packet + IPv4_DESTINATION_IP_ADDR + ETHERNET_header_end, dst_ip_addr);
	copy_4byte(packet + TCP_SOURCE_PORT_NUM + ipv4_header_end, src_port_num);
	copy_4byte(packet + TCP_DESTINATION_PORT_NUM + ipv4_header_end, dst_port_num);

	u_char * forward_packet = new uint8_t[packet_size];
	for(int i = 0; i < packet_size; i++) forward_packet[i] = packet[i];
	u_char * backward_packet = new uint8_t[packet_size];
	for(int i = 0; i < packet_size; i++) backward_packet[i] = packet[i];
	
	if(Forward_FIN_flag) Forward_FIN(forward_packet, packet_size, ipv4_header_end, tcp_header_end, handle);
	else Forward_RST(forward_packet, packet_size, ipv4_header_end, tcp_header_end, handle);

	copy_6byte(dst_mac_addr, backward_packet + ETHERNET_SOURCE_MAC_ADDR);
	copy_6byte(src_mac_addr, backward_packet + ETHERNET_DESTINATION_MAC_ADDR);
	copy_4byte(dst_ip_addr, backward_packet + IPv4_SOURCE_IP_ADDR + ETHERNET_header_end);
	copy_4byte(src_ip_addr, backward_packet + IPv4_DESTINATION_IP_ADDR + ETHERNET_header_end);
	copy_4byte(dst_port_num, backward_packet + TCP_SOURCE_PORT_NUM);
	copy_4byte(src_port_num, backward_packet + TCP_DESTINATION_PORT_NUM);
	if(Backward_FIN_flag) Backward_FIN(backward_packet, packet_size, ipv4_header_end, tcp_header_end, handle);
	else Backward_RST(backward_packet, packet_size, ipv4_header_end, tcp_header_end, handle);
}

void Data_check(u_char * packet, uint32_t start, uint32_t max_size, uint32_t ipv4_header_end, uint32_t tcp_header_end, pcap_t * handle){
	uint32_t end = start + 32;
	end = min(end, max_size);
	if(!Data_checking(packet, start, end)){ // false means find input hostname
		block_packet(packet, max_size, ipv4_header_end, tcp_header_end, handle);
	}
}

// Layer 4
uint32_t TCP_check(u_char * packet, uint32_t start){
	uint32_t tcp_start = start;
	uint32_t tcp_header_length = (packet[tcp_start + 12] & 0xf0) >> 2;
	return tcp_start + tcp_header_length;
}

// Layer 3
uint32_t IPv4_check(u_char * packet, uint32_t start){
	uint32_t ipv4_start = start;
	uint32_t ipv4_header_length = (packet[ipv4_start] & 0x0f) * 4;
	ipv4_protocol_id = packet[ipv4_start + 9];
	return ipv4_start + ipv4_header_length;
}

// Layer 2
uint32_t Ethernet_print(u_char * packet){
    uint16_t protocol_type = 0;
    for(int i = 12; i < 14; i++){
      protocol_type += packet[i] * pow(256, 13-i);
    }
    ethernet_protocol_type = protocol_type;
    return 14; // ethernet header end
}

int main(int argc, char* argv[]){
	if (argc != 3){
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
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		uint32_t ethernet_header_end = 0;
		uint32_t ipv4_header_end = 0;
		uint32_t tcp_header_end = 0;

		ethernet_header_end = Ethernet_print((u_char *)packet);
		if(ethernet_protocol_type == 0x0800){ // IPv4
			ipv4_header_end = IPv4_check((u_char *)packet, ethernet_header_end);
		}
		if(ipv4_protocol_id == 0x6){ // IPv4 -> TCP
			tcp_header_end = TCP_check((u_char *)packet, ipv4_header_end);
		}
		Data_check((u_char *)packet, max(ipv4_header_end, tcp_header_end), header->caplen, ipv4_header_end, tcp_header_end, handle);
	}

	pcap_close(handle);
	return 0;
}
