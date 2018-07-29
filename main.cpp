#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void printPacket(const u_char* _packet,long int len);

int main(int argc, char* argv[]) {
  //if (argc != 2) {
  //  usage();
  //  return -1;
  //}
  char dst_mac[6] = "";
  int i;

  char* dev = "ens33";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    printPacket(packet, header->caplen);	//function for print packet (packet content and header length is argument)
  }

  pcap_close(handle);
  return 0;
}

void printPacket(const u_char* _packet, long int len){
	int i;				//for loop 
	long long int src_port = 0;	//for print src_port
	long long int dst_port = 0;	//for print dst_prot
	long long int headerLength = 0;	//for calculate tcp_headerLength
	long long int totalHLEN = 0;	//for print content 16 bytes
	
	printf("dst_mac :\t");
	for(i = 0; i < 6; i++){
		if(i == 5){
			if(_packet[i] < 16){
				printf("0");	//if value is smaller than 10 print 0
			}
			printf("%X",_packet[i]);
			break;
		}
		if(_packet[i] < 16){
			printf("0");		//if value is smaller than 10 print 0
		}
		printf("%X:",_packet[i]);
	}
	printf("\n");
	
	printf("src_mac :\t");
        for(i = 6; i < 12; i++){
                if(i == 11){
			if(_packet[i] < 16){
				printf("0");	//if value is smaller than 10 print 0
			}
                        printf("%X",_packet[i]);
                        break;
                }
		if(_packet[i] < 16){
			printf("0");		//if value is smaller than 10 print 0
		}
                printf("%X:",_packet[i]);
        }
        printf("\n");

	totalHLEN += 14;			//add 14bytes(ethernet Total Length)

	if(_packet[12] == 0x08 && _packet[13] == 0x00){
		//printf("%0X %0X %0X %0X\n",_packet[26],_packet[27],_packet[28],_packet[29]);
		printf("src_ip :\t");
		for(i = 26; i < 30; i++){
			if(i == 29){
				printf("%lld",_packet[i]);
				break;
			}
			printf("%lld.", _packet[i]);
		}
		printf("\ndst_ip :\t");
		for(i = 30; i < 34; i++){
			if(i == 33){
				printf("%lld",_packet[i]);
				break;
			}
			printf("%lld.", _packet[i]);
		}
		printf("\n");

		totalHLEN += 20;			//add ip layer length
			
		src_port += _packet[34]<<8;		//calculate src_port value
		src_port += _packet[35];
		
		printf("src_port :\t%lld\n",src_port);

		dst_port += _packet[36]<<8;		//calculate dst_prot value
		dst_port += _packet[37];

		printf("dst_port :\t%lld\n",dst_port);
		
		
		headerLength = (long long int)_packet[46];
		printf("HLEN :\t\t%lld\n", headerLength);

		totalHLEN += headerLength;		//add tcp header length

		headerLength += 34;

		if( (len - totalHLEN) >= 16){		// if total header length is bigger than totalHLEN print data content
			printf("data content 16 bytes : ");
			for(i = headerLength ; i < (headerLength+16) ; i++){
                        	printf("%X ",_packet[i]);
			}
                }
                printf("\n");

	}




	//printf("------------packet contents------------\n");
	//for(i = 0; i < len; i++){
	//	printf("%3X",_packet[i]);
		
	//}

	//printf("------------end   --------------------\n");

}

