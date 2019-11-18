#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define max(a,b) (a > b ? a : b) 
#define min(a,b) (a < b ? a : b) 

uint16_t ethernet_protocol_type;
uint8_t ipv4_protocol_id;

uint32_t pow(uint32_t a, uint32_t n){ // return a^n
  uint32_t result = 1;
  while(n--){
    result *= a;
  }
  return result;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

// Layer 7 (또는 IPv4, TCP 를 제외한 다른 프로토콜 이용 시 식별되지 않은 이후 32바이트만을 출력)
void Data_print(const u_char * packet, uint32_t start, uint32_t max_size){
  printf("\t (Layer 5-7) Data (~ 32 bytes)      :");
  uint32_t end = start + 32;
  end = min(end, max_size); // data 의 길이가 32바이트를 넘어갈 경우에도 최대 패킷 크기를 넘지 못하게 함
  for(int i = start; i < end; i++){
    if((i - start) % 8 == 0) printf("\n\t\t");
    printf("0x%02x ", packet[i]);
  }
  printf("\n");
}

// Layer 4
uint32_t TCP_print(const u_char * packet, uint32_t start){
  uint32_t tcp_start = start;

  uint32_t tcp_src_port_start = tcp_start, tcp_src_port_end = tcp_start + 1;
  uint16_t tcp_src_port_num = packet[tcp_src_port_start] * 256 + packet[tcp_src_port_end];
  printf("\t (TCP) Source port                  : %d\n", tcp_src_port_num);

  uint32_t tcp_dst_port_start = tcp_src_port_end + 1, tcp_dst_port_end = tcp_dst_port_start + 1;
  uint16_t tcp_dst_port_num = packet[tcp_dst_port_start] * 256 + packet[tcp_dst_port_end];
  printf("\t (TCP) Destination port             : %d\n", tcp_dst_port_num);

  uint32_t tcp_header_length = (packet[tcp_start + 12] & 0xf0) >> 2;
  printf("\t (TCP) Header Length                : %d bytes\n", tcp_header_length);

  return tcp_start + tcp_header_length;
}

// Layer 3
uint32_t IPv4_print(const u_char * packet, uint32_t start){
  uint32_t ipv4_start = start;
  
  uint32_t ipv4_header_length = (packet[ipv4_start] & 0x0f) * 4;
  printf("\t (IPv4) Header Length               : %d bytes\n", ipv4_header_length);

  uint32_t ipv4_protocol_ID = packet[ipv4_start + 9];
  ipv4_protocol_id = ipv4_protocol_ID;
  printf("\t (IPv4) Protocol ID                 : %d\n", ipv4_protocol_ID);

  printf("\t (IPv4) IP source address           : ");
  uint32_t ipv4_src_addr_start = ipv4_start + 12;
  uint32_t ipv4_src_addr_end = ipv4_src_addr_start + 4;
  for(int i = ipv4_src_addr_start; i < ipv4_src_addr_end; i++){
    printf("%d", packet[i]);
    if(i == ipv4_src_addr_end - 1) break;
    printf(".");
  }
  printf("\n");

  printf("\t (IPv4) IP destination address      : ");
  uint32_t ipv4_dst_addr_start = ipv4_start + 16;
  uint32_t ipv4_dst_addr_end = ipv4_dst_addr_start + 4;
  for(int i = ipv4_dst_addr_start; i < ipv4_dst_addr_end; i++){
    printf("%d", packet[i]);
    if(i == ipv4_dst_addr_end - 1) break;
    printf(".");
  }
  printf("\n");

  return ipv4_start + ipv4_header_length;
}
 
// Layer 2 (only Ethernet checking)
uint32_t Ethernet_print(const u_char * packet){
  printf("\t (Ethernet) MAC source address      : ");
    for(int i = 6; i < 12; i++){
      printf("%02x", packet[i]);
      if(i == 11) break; 
      printf(":");
    }
    printf("\n");
    printf("\t (Ethernet) MAC destination address : ");
    for(int i = 0; i < 6; i++){
      printf("%02x", packet[i]);
      if(i == 5) break;
      printf(":");
    }
    printf("\n");
    uint16_t protocol_type = 0;
    printf("\t (Ethernet) Protocol Type           : ");
    for(int i = 12; i < 14; i++){
      protocol_type += packet[i] * pow(256, 13-i);
    }
    printf("0x%04x \n", protocol_type);
    ethernet_protocol_type = protocol_type;

    return 14; // ethernet header end
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

  int packetNum = 0;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    printf("[Packet %d]\n", ++packetNum);
    printf("\t Packet size                        : %u bytes\n", header->caplen);
    uint32_t ethernet_header_end = Ethernet_print(packet);

    // Ethernet -> IPv4 -> TCP -> (Data)
    uint32_t ipv4_header_end = 0;
    uint32_t tcp_header_end = 0;

    if(ethernet_protocol_type == 0x0800){ // IPv4
      ipv4_header_end = IPv4_print(packet, ethernet_header_end);
    }
    if(ipv4_protocol_id == 0x6){ // IPv4 -> TCP
      tcp_header_end = TCP_print(packet, ipv4_header_end);
    }
    Data_print(packet, max(max(ethernet_header_end, ipv4_header_end), tcp_header_end), header->caplen);
    // 만약 2계층에서는 ethernet protocol 을 이용하였으나 상위 계층에서 ipv4, tcp protocol 을 이용하지 않은 경우, 이후 (최대) 32bytes 만을 출력합니다.
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
